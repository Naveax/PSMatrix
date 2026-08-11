from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parents[2]
LEDGER_VALIDATOR=ROOT/"scripts"/"ga"/"validate_final_lock_input_ledger.py"

class FinalLockVerificationError(RuntimeError): pass

def _load_validator():
    spec=importlib.util.spec_from_file_location("final_lock_ledger_for_verifier",LEDGER_VALIDATOR)
    if spec is None or spec.loader is None: raise FinalLockVerificationError("unable to load final-lock ledger validator")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

def _one_artifact(items:list[dict[str,Any]],name:str,label:str)->dict[str,Any]:
    matches=[item for item in items if isinstance(item,dict) and item.get("name")==name and item.get("expired") is False]
    if len(matches)!=1: raise FinalLockVerificationError(f"{label}: expected exactly one nonexpired {name} artifact; observed {len(matches)}")
    if type(matches[0].get("id")) is not int or matches[0]["id"]<=0: raise FinalLockVerificationError(f"{label}: invalid artifact ID")
    return matches[0]

def verify_records(ledger:dict[str,Any],contract:dict[str,Any],runs:dict[str,dict[str,Any]],artifacts:dict[str,list[dict[str,Any]]],repository_targets_present:dict[str,bool])->dict[str,Any]:
    validator=_load_validator()
    try: state=validator.validate(ledger,contract)
    except Exception as exc: raise FinalLockVerificationError(f"final-lock ledger validation failed: {exc}") from exc
    if state.get("inputs_complete") is not True: raise FinalLockVerificationError("final-lock ledger must be input-complete before provenance verification")
    specs={
        "rc4_enrollment":(ledger["rc4_enrollment_run_id"],contract["rc4_authority_continuity"]["workflow"],contract["rc4_authority_continuity"]["artifact"],contract["rc4_authority_continuity"]["enrollment_control_head"]),
        "staging":(ledger["staging_run_id"],contract["final_staging"]["workflow"],contract["final_staging"]["artifact"],contract["final_release_commit"]),
        "review":(ledger["review_run_id"],"production-ga-windows-authority-final-release-lock-review","psmatrix-2.0.0-final-release-lock-review",None),
        "promotion":(ledger["promotion_run_id"],"production-ga-windows-authority-final-release-lock-promotion","psmatrix-2.0.0-final-release-lock-promotion-candidate",None),
    }
    rows=[]; shared_control_heads=[]
    for label,(run_id,workflow,artifact_name,expected_head) in specs.items():
        run=runs.get(label)
        if not isinstance(run,dict) or run.get("id")!=run_id: raise FinalLockVerificationError(f"{label}: missing or mismatched run record")
        if run.get("name")!=workflow or run.get("event")!="workflow_dispatch" or run.get("status")!="completed" or run.get("conclusion")!="success": raise FinalLockVerificationError(f"{label}: run is not the expected successful workflow_dispatch")
        head=str(run.get("head_sha") or "").lower()
        if expected_head is not None and head!=expected_head: raise FinalLockVerificationError(f"{label}: exact head mismatch")
        if label in {"review","promotion"}: shared_control_heads.append(head)
        artifact=_one_artifact(artifacts.get(label,[]),artifact_name,label)
        rows.append({"stage":label,"run_id":run_id,"workflow":workflow,"head_sha":head,"artifact":artifact_name,"artifact_id":artifact["id"],"verified":True})
    if len(set(shared_control_heads))!=1 or not shared_control_heads[0]: raise FinalLockVerificationError("review and promotion runs must share one exact control head")
    targets=contract.get("repository_targets")
    if not isinstance(targets,dict) or set(targets)!={"lock","public_key"}: raise FinalLockVerificationError("final lock repository target contract mismatch")
    if repository_targets_present.get("lock") is not True or repository_targets_present.get("public_key") is not True: raise FinalLockVerificationError("exact lock-control repository commit does not expose both required targets")
    return {"schema":1,"kind":"psmatrix.final-release-lock-api-verification","version":"2.0.0","status":"PASS","final_release_commit":contract["final_release_commit"],"shared_review_promotion_control_head":shared_control_heads[0],"verified_run_count":4,"runs":rows,"reviewed_digest_formats_valid":True,"repository_commit":ledger["lock_control_repository_commit"],"repository_lock_target_present":True,"repository_public_key_target_present":True,"run_and_artifact_provenance_verified":True,"repository_target_presence_verified":True,"repository_target_content_verified":False,"release_signing_executed":False,"final_ga_evaluator_invoked":False,"ga_eligible":False}

def _gh_json(gh:str,endpoint:str)->Any:
    completed=subprocess.run([gh,"api",endpoint],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
    if completed.returncode!=0: raise FinalLockVerificationError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try: return json.loads(completed.stdout)
    except json.JSONDecodeError as exc: raise FinalLockVerificationError(f"gh api returned invalid JSON for {endpoint}") from exc

def collect_live(ledger:dict[str,Any],contract:dict[str,Any],*,repository:str,gh:str):
    run_ids={"rc4_enrollment":ledger["rc4_enrollment_run_id"],"staging":ledger["staging_run_id"],"review":ledger["review_run_id"],"promotion":ledger["promotion_run_id"]}; runs={}; artifacts={}
    for label,run_id in run_ids.items():
        runs[label]=_gh_json(gh,f"repos/{repository}/actions/runs/{run_id}"); value=_gh_json(gh,f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100")
        if not isinstance(value,dict) or not isinstance(value.get("artifacts"),list): raise FinalLockVerificationError(f"{label}: invalid artifact listing")
        artifacts[label]=value["artifacts"]
    commit=ledger["lock_control_repository_commit"]; presence={}
    for label,path in contract["repository_targets"].items():
        try: _gh_json(gh,f"repos/{repository}/contents/{path}?ref={commit}"); presence[label]=True
        except FinalLockVerificationError: presence[label]=False
    return runs,artifacts,presence

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--ledger",type=Path,required=True); p.add_argument("--contract",type=Path,default=Path("ga-packs/03-authoritative-windows/final-release-lock-signing-control-contract.json")); p.add_argument("--repository",default="Naveax/PSMatrix"); p.add_argument("--gh",default="gh"); p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    try:
        ledger=json.loads(a.ledger.read_text(encoding="utf-8")); contract=json.loads(a.contract.read_text(encoding="utf-8")); runs,artifacts,presence=collect_live(ledger,contract,repository=a.repository,gh=a.gh); value=verify_records(ledger,contract,runs,artifacts,presence); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8"); print("final_lock_api_verification=PASS runs=4/4 repository_targets=2/2"); print("release_signing_executed=false"); return 0
    except (OSError,json.JSONDecodeError,FinalLockVerificationError,subprocess.SubprocessError,TypeError,ValueError) as exc: print(f"final lock API verification failed: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
