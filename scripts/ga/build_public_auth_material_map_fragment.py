from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "ga" / "validate_public_auth_provisioning.py"

class PublicAuthFragmentError(RuntimeError): pass

def _load_validator():
    spec = importlib.util.spec_from_file_location("public_auth_validator_for_fragment", VALIDATOR)
    if spec is None or spec.loader is None: raise PublicAuthFragmentError("unable to load public-auth validator")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

def _external(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try: resolved.relative_to(ROOT.resolve())
    except ValueError: return resolved
    raise PublicAuthFragmentError(f"{label} must stay outside repository")

def build_fragment(material_root: Path, value_root: Path) -> dict[str, Any]:
    material = _external(material_root, "public-auth material root")
    validator = _load_validator()
    try: validation = validator.validate_material(material)
    except Exception as exc: raise PublicAuthFragmentError(f"public-auth material validation failed: {exc}") from exc
    if validation.get("status") != "PASS" or validation.get("required_check_count") != 19:
        raise PublicAuthFragmentError("public-auth validation did not prove exact 19-check closure")
    secrets_root = material / "secrets"
    secret_names = list(validator.TOKEN_NAMES) + [f"{prefix}_CERT" for prefix in validator.PAIR_PREFIXES] + [f"{prefix}_KEY" for prefix in validator.PAIR_PREFIXES]
    secret_map: dict[str, str] = {}
    for name in secret_names:
        suffix = ".txt" if name in validator.TOKEN_NAMES else ".pem"
        path = secrets_root / f"{name}{suffix}"
        if not path.is_file() or path.is_symlink(): raise PublicAuthFragmentError(f"missing public-auth secret material: {name}")
        secret_map[name] = str(path.resolve())
    variables = json.loads((material / "vars.json").read_text(encoding="utf-8"))
    output = _external(value_root, "public-auth value root"); output.mkdir(parents=True, exist_ok=True)
    var_map: dict[str, str] = {}
    for name in validator.VAR_NAMES:
        value_file = output / f"{name}.txt"
        value_file.write_text(str(variables[name]).strip() + "\n", encoding="utf-8")
        var_map[name] = str(value_file)
    if len(secret_map) != 14 or len(var_map) != 5:
        raise PublicAuthFragmentError("public-auth material-map cardinality mismatch")
    return {"schema":1,"kind":"psmatrix.production-ga-environment-material-map","version":"2.0.0","fragment":"public-auth","environment_count":1,"check_count":19,"environments":{"production-ga-public-auth-probe":{"secrets":secret_map,"vars":var_map}},"safety":{"values_in_map":False,"hashes_in_map":False,"lengths_in_map":False}}

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--material-root",type=Path,required=True); p.add_argument("--value-root",type=Path,required=True); p.add_argument("--output-map",type=Path,required=True); a=p.parse_args()
    try:
        value=build_fragment(a.material_root,a.value_root); output=_external(a.output_map,"output map"); output.parent.mkdir(parents=True,exist_ok=True); output.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8"); print("production_ga_public_auth_material_map=PASS checks=19 secrets=14 vars=5"); return 0
    except (OSError,ValueError,TypeError,PublicAuthFragmentError) as exc: print(f"public-auth material-map fragment failed: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
