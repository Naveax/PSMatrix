from __future__ import annotations
import argparse, http.client, json, threading, hashlib, shutil
from pathlib import Path
from urllib.parse import quote
from psmatrix.http_auth import HTTPAuthConfig
from psmatrix.http_mcp import HTTPMCPConfig, build_http_server
from psmatrix.http_sessions import SessionLimits

ACCEPT='application/json, text/event-stream'

def main():
    parser=argparse.ArgumentParser(description='Run the real PSMatrix Streamable HTTP delivery flow.')
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--runtime-archive', type=Path, required=True)
    parser.add_argument('--hashes-file', type=Path, required=True)
    parser.add_argument('--mirror-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    home=args.home.resolve()
    if home.exists(): shutil.rmtree(home)
    config=HTTPMCPConfig(
        host='127.0.0.1', port=0, public_url='http://127.0.0.1/mcp',
        allowed_hosts=('127.0.0.1','localhost'),
        auth_config=HTTPAuthConfig('none-localhost','http://127.0.0.1/mcp'),
        rate_per_minute=1000, burst=100, max_concurrent_per_session=2,
        session_limits=SessionLimits(
            max_files=128,max_project_bytes=512*1024*1024,max_upload_bytes=128*1024*1024,
            max_artifact_bytes=256*1024*1024,max_text_bytes=2*1024*1024,
            ttl_seconds=3600,artifact_ttl_seconds=300,
        ),
    )
    server=build_http_server(config,home)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    host,port=server.server_address

    def request(method,path,body=None,headers=None,timeout=300):
        conn=http.client.HTTPConnection(host,port,timeout=timeout)
        values=dict(headers or {})
        if isinstance(body,(dict,list)):
            raw=json.dumps(body,separators=(',',':')).encode(); values.setdefault('Content-Type','application/json')
        else: raw=body
        conn.request(method,path,body=raw,headers=values)
        res=conn.getresponse(); data=res.read(); hdr=dict(res.getheaders()); conn.close()
        if res.status >= 400:
            raise RuntimeError(f'{method} {path} -> {res.status}: {data[:2000]!r}')
        return res.status,hdr,data

    try:
        _,headers,data=request('POST','/mcp',{
            'jsonrpc':'2.0','id':1,'method':'initialize','params':{
                'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'psmatrix-1.8-e2e','version':'1'}
            }}, {'Accept':ACCEPT})
        session=headers['MCP-Session-Id']
        common={'Accept':ACCEPT,'MCP-Session-Id':session,'MCP-Protocol-Version':'2025-11-25'}
        request('POST','/mcp',{'jsonrpc':'2.0','method':'notifications/initialized','params':{}},common)

        def upload(name,path,key,content_type='application/octet-stream'):
            data=Path(path).read_bytes()
            status,_,raw=request('PUT','/projects/files/'+quote(name,safe='/'),data,{
                'MCP-Session-Id':session,'Idempotency-Key':key,'Content-Type':content_type
            },timeout=600)
            result=json.loads(raw)
            assert result['sha256']==hashlib.sha256(data).hexdigest()
            return result
        upload('runtime/powershell-7.6.4-linux-x64.tar.gz',args.runtime_archive.resolve(),'runtime-archive')
        upload('runtime/hashes.sha256',args.hashes_file.resolve(),'runtime-hashes','text/plain')
        upload('mirror/psmatrix-module-mirror.zip',args.mirror_archive.resolve(),'module-mirror')

        source="Set-StrictMode -Version Latest\n[pscustomobject]@{ Status = 'web-ok'; Value = 42 } | ConvertTo-Json -Compress\n"
        compatibility={
          'schema':1,'kind':'psmatrix.compatibility-matrix','name':'web-e2e-compatibility',
          'sources':['tool.ps1'],
          'targets':[{'id':'core-7.6.4','runtime':'7.6.4','required':True,'modules':[]}]
        }
        full={
          'schema':1,'kind':'psmatrix.full-matrix-spec','name':'web-e2e-full',
          'targets':[{'id':'linux-7.6.4','kind':'local','version':'7.6.4','arch':'x64','libc':'glibc','backend':'native','required':True}],
          'differential':{'mode':'off'},'requirements':{'require_complete':True}
        }
        for name,value,key in [
            ('tool.ps1',source.encode(),'source'),
            ('compatibility.json',json.dumps(compatibility).encode(),'compat'),
            ('full-matrix.json',json.dumps(full).encode(),'full'),
        ]:
            request('PUT','/projects/files/'+name,value,{
                'MCP-Session-Id':session,'Idempotency-Key':key,'Content-Type':'application/json' if name.endswith('.json') else 'text/plain'
            })

        next_id=2
        def tool(name,args):
            nonlocal next_id
            request_id=next_id; next_id+=1
            _,_,raw=request('POST','/mcp',{
              'jsonrpc':'2.0','id':request_id,'method':'tools/call','params':{'name':name,'arguments':args}
            },common,timeout=1200)
            result=json.loads(raw)['result']
            if result.get('isError'):
                raise RuntimeError(result['structuredContent'])
            return result['structuredContent']

        boot=tool('psmatrix_bootstrap',{
          'runtime':'7.6.4','runtimeArchivePath':'runtime/powershell-7.6.4-linux-x64.tar.gz',
          'hashesPath':'runtime/hashes.sha256','mirrorArchivePath':'mirror/psmatrix-module-mirror.zip'
        })
        blocked=tool('psmatrix_delivery_status',{})
        assert blocked['ready'] is False and blocked['webValidation']['valid'] is False

        submitted=tool('psmatrix_web_validate',{
          'paths':['tool.ps1'],'runtimes':['7.6.4'],
          'compatibilitySpecPath':'compatibility.json','fullMatrixSpecPath':'full-matrix.json',
          'localArgs':['--psscriptanalyzer','off','--pester','off','--coverage','off','--dependencies','off','--cache','off'],
          'timeout':300,'jobs':1,'differential':'off'
        })
        assert submitted['status']=='RUNNING' and submitted['jobId']
        import time
        for _ in range(600):
            validated=tool('psmatrix_web_validation_status',{'jobId':submitted['jobId']})
            if validated['status']!='RUNNING': break
            time.sleep(1)
        assert validated['status']=='PASS' and validated['deliveryReady'] is True, validated
        delivery=tool('psmatrix_delivery_status',{})
        assert delivery['ready'] is True and delivery['webValidation']['valid'] is True
        artifact=tool('psmatrix_artifact_prepare',{'path':'tool.ps1','purpose':'delivery'})
        _,download_headers,downloaded=request('GET',artifact['downloadPath'],timeout=60)
        assert downloaded==source.encode()
        result={
          'status':'PASS','session':session,'runtime':boot['runtime']['runtimeId'],
          'mirror_packages':boot['mirror']['packages'],'pre_validation_delivery_blocked':not blocked['ready'],
          'web_validation':validated,'delivery':delivery,'artifact_sha256':hashlib.sha256(downloaded).hexdigest(),
          'digest_header':download_headers.get('Digest'),
        }
        args.output.resolve().write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        print(json.dumps({'status':'PASS','runtime':result['runtime'],'mirror':result['mirror_packages'],'delivery':delivery['ready']},sort_keys=True))
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=10)


if __name__ == "__main__":
    main()
