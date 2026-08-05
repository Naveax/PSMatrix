from __future__ import annotations

import base64
import json
import sys

from .scheduler import run_target_payload


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        options = payload.get("options", {})
        encoded_stdin = options.pop("stdin_data_base64", None)
        options["stdin_data"] = base64.b64decode(encoded_stdin) if encoded_stdin is not None else None
        result = run_target_payload(payload)
        json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except BaseException as exc:
        json.dump(
            {"worker_error": {"type": type(exc).__name__, "message": str(exc)}},
            sys.stderr,
            ensure_ascii=False,
        )
        sys.stderr.write("\n")
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
