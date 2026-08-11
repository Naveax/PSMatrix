from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA40=re.compile(r"^[0-9a-f]{40}$")

class EvidenceLedgerError(RuntimeError): pass

def validate(ledger:dict[str,Any],contract:dict[str,Any])->dict[str,Any]:
    if ledger.get("schema")!=1 or ledger.get("kind")!="psmatrix.final-ga-evidence-run-ledger" or ledger.get("version")!="2.0.0": raise EvidenceLedgerError("evidence ledger identity mismatch")
    if contract.get("schema")!=1 or contract.get("kind")!="psmatrix.final-ga-evaluator-control-contract" or contract.get("version")!="2.0.0": raise EvidenceLedgerError("final evaluator contract identity mismatch")
    gates=contract.get("required_gates"); sources=contract.get("evidence_sources")
    if not isinstance(gates,list) or len(gates)!=11 or not isinstance(sources,dict) or list(sources)!=gates: raise EvidenceLedgerError("final evaluator contract gate closure mismatch")
    head=ledger.get("execution_head")
    if head not in (None,"") and (not isinstance(head,str) or SHA40.fullmatch(head) is None): raise EvidenceLedgerError("execution_head must be 40 lowercase hex or null")
    entries=ledger.get("gates")
    if not isinstance(entries,dict) or set(entries)!=set(gates): raise EvidenceLedgerError("ledger must contain exactly the eleven evaluator gates")
    present=[]; rows=[]
    for gate in gates:
        expected=sources[gate]; row=entries[gate]
        if not isinstance(row,dict): raise EvidenceLedgerError(f"{gate} ledger entry must be an object")
        for field in ("workflow","artifact","authority"):
            if row.get(field)!=expected.get(field): raise EvidenceLedgerError(f"{gate} {field} does not match evaluator contract")
        run_id=row.get("run_id")
        if run_id in (None,""): present_flag=False
        elif type(run_id) is int and run_id>0: present_flag=True; present.append(run_id)
        else: raise EvidenceLedgerError(f"{gate} run_id must be a positive integer or null")
        rows.append({"gate":gate,"run_id_present":present_flag,"workflow":row["workflow"],"artifact":row["artifact"],"authority":row["authority"]})
    if len(present)!=len(set(present)): raise EvidenceLedgerError("evidence run IDs must be distinct")
    complete=isinstance(head,str) and SHA40.fullmatch(head) is not None and len(present)==11
    return {"schema":1,"kind":"psmatrix.final-ga-evidence-run-ledger-validation","version":"2.0.0","status":"INPUTS_COMPLETE_NOT_EVALUATED" if complete else "INCOMPLETE","execution_head":head,"required_gate_count":11,"present_run_id_count":len(present),"missing_gates":[row["gate"] for row in rows if not row["run_id_present"]],"gates":rows,"inputs_complete":complete,"workflow_dispatch_verified":False,"workflow_success_verified":False,"artifact_identity_verified":False,"shared_execution_head_verified":False,"final_ga_evaluator_invoked":False,"ga_eligible":False}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--ledger",type=Path,required=True); p.add_argument("--contract",type=Path,default=Path("ga-packs/03-authoritative-windows/final-ga-evaluator-control-contract.json")); p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    try:
        value=validate(json.loads(a.ledger.read_text(encoding="utf-8")),json.loads(a.contract.read_text(encoding="utf-8"))); a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8"); print(f"final_ga_evidence_run_ledger={value['status']} runs={value['present_run_id_count']}/11"); return 0 if value["inputs_complete"] else 2
    except (OSError,json.JSONDecodeError,EvidenceLedgerError,TypeError,ValueError) as exc: print(f"final GA evidence run ledger validation failed: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
