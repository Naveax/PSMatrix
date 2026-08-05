import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.module_compat import (
    CompatibilityError,
    CompatibilitySpec,
    OfflineModuleMirror,
    plan_compatibility_matrix,
    resolve_mirror_lock,
    scan_project_dependencies,
    version_satisfies,
    write_compatibility_template,
)
from psmatrix.module_manager import ModuleManager


def package(path: Path, name='Example', version='1.0.0', dependencies=()):
    deps=''.join(f'<dependency id="{n}" version="{v}" />' for n,v in dependencies)
    nuspec=f'''<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
<id>{name}</id><version>{version}</version><dependencies><group targetFramework="PowerShell">{deps}</group></dependencies>
</metadata></package>'''
    manifest=f"@{{RootModule='{name}.psm1';ModuleVersion='{version}';GUID='11111111-1111-1111-1111-111111111111'}}"
    with zipfile.ZipFile(path,'w') as z:
        z.writestr(f'{name}.nuspec',nuspec)
        z.writestr(f'tools/{name}/{name}.psd1',manifest)
        z.writestr(f'tools/{name}/{name}.psm1',f"function Get-{name} {{ '{version}' }}")


class ModuleCompatibilityTests(unittest.TestCase):
    def test_mirror_add_verify_export_and_install(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); p=root/'Example.nupkg'
            package(p,dependencies=(('Dependency','[2.0.0]'),))
            digest=hashlib.sha256(p.read_bytes()).hexdigest()
            mirror=OfflineModuleMirror(root/'mirror')
            result=mirror.add(p,expected_sha256=digest,source='fixture')
            self.assertEqual(result.dependencies[0].name,'Dependency')
            self.assertTrue(mirror.verify()['valid'])
            export1=root/'one.zip'; export2=root/'two.zip'
            self.assertEqual(mirror.export(export1)['sha256'],mirror.export(export2)['sha256'])
            manager=ModuleManager(root/'home')
            installed=mirror.install_into(manager,'Example','1.0.0')
            self.assertEqual(installed['sha256'],digest)

    def test_mirror_rejects_hash_tamper_and_duplicate_identity_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); one=root/'one.nupkg'; two=root/'two.nupkg'
            package(one); package(two)
            with zipfile.ZipFile(two,'a') as z: z.writestr('extra.txt','changed')
            mirror=OfflineModuleMirror(root/'mirror')
            d1=hashlib.sha256(one.read_bytes()).hexdigest(); d2=hashlib.sha256(two.read_bytes()).hexdigest()
            mirror.add(one,expected_sha256=d1)
            with self.assertRaises(CompatibilityError): mirror.add(two,expected_sha256=d2)
            with self.assertRaises(CompatibilityError): mirror.add(one,expected_sha256='0'*64)


    def test_nuget_ranges_and_transitive_graph_lock(self):
        self.assertTrue(version_satisfies('2.0.0','[2.0.0]'))
        self.assertTrue(version_satisfies('2.5.0','[2.0.0,3.0.0)'))
        self.assertFalse(version_satisfies('3.0.0','[2.0.0,3.0.0)'))
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); mirror=OfflineModuleMirror(root/'mirror')
            dep=root/'Dependency.nupkg'; app=root/'Application.nupkg'
            package(dep,name='Dependency',version='2.5.0')
            package(app,name='Application',version='1.0.0',dependencies=(('Dependency','[2.0.0,3.0.0)'),))
            for item in (dep,app): mirror.add(item,expected_sha256=hashlib.sha256(item.read_bytes()).hexdigest())
            lock=resolve_mirror_lock(mirror,{'Application':'1.0.0'})
            self.assertEqual({x['name'] for x in lock['powershell_modules']},{'Application','Dependency'})
            self.assertEqual(len(lock['psmatrix_graph']['edges']),1)

    def test_dependency_conflict_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); mirror=OfflineModuleMirror(root/'mirror')
            dep=root/'Dependency.nupkg'; a=root/'A.nupkg'; b=root/'B.nupkg'
            package(dep,name='Dependency',version='2.0.0')
            package(a,name='A',version='1.0.0',dependencies=(('Dependency','[2.0.0]'),))
            package(b,name='B',version='1.0.0',dependencies=(('Dependency','[3.0.0]'),))
            for item in (dep,a,b): mirror.add(item,expected_sha256=hashlib.sha256(item.read_bytes()).hexdigest())
            with self.assertRaises(CompatibilityError): resolve_mirror_lock(mirror,{'A':'1.0.0','B':'1.0.0'})

    def test_project_scan_finds_import_requires_and_manifest_modules(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'a.ps1').write_text("#requires -Modules 'Pester', Az.Accounts\nImport-Module PSScriptAnalyzer",encoding='utf-8')
            (root/'m.psd1').write_text("@{ RequiredModules = @('Example') }",encoding='utf-8')
            scan=scan_project_dependencies(root)
            names={item['name'] for item in scan['modules']}
            self.assertEqual(names,{'Pester','Az.Accounts','PSScriptAnalyzer','Example'})

    def test_template_and_plan_fail_closed_until_runtime_and_modules_exist(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'tool.ps1').write_text("'ok'",encoding='utf-8')
            spec=root/'compat.json'
            spec.write_text(json.dumps({
                'schema':1,'kind':'psmatrix.compatibility-matrix','name':'lab','sources':['tool.ps1'],
                'targets':[{'id':'target','runtime':'7.6.4','required':True,'pester':'5.7.1','psscriptanalyzer':'1.24.0','modules':[]}]
            }),encoding='utf-8')
            loaded=CompatibilitySpec.load(spec); self.assertEqual(len(loaded.targets),1)
            plan=plan_compatibility_matrix(spec,mirror_root=root/'mirror',runtime_home=root/'home')
            self.assertEqual(plan['status'],'INCOMPLETE')
            self.assertIn('target',plan['coverage']['missing_required'])

    def test_template_creation_is_non_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'compat.json'
            result=write_compatibility_template(path)
            self.assertEqual(result['targets'],2)
            with self.assertRaises(CompatibilityError): write_compatibility_template(path)


if __name__ == '__main__': unittest.main()
