from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "scripts" / "ga" / "verification-hardening-action-lock.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class VerificationHardeningActionLockTests(unittest.TestCase):
    def test_lock_has_exact_expected_actions_and_commits(self) -> None:
        value = json.loads(LOCK.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.verification-hardening-action-lock")
        self.assertEqual(value["version"], "2.0.0")
        actions = value["actions"]
        self.assertEqual(
            set(actions),
            {"actions/checkout", "actions/setup-python", "actions/upload-artifact"},
        )
        for name, entry in actions.items():
            with self.subTest(name=name):
                self.assertRegex(entry["commit"], SHA40)
                self.assertRegex(entry["major_family"], r"^v[0-9]+$")
        self.assertEqual(
            actions["actions/checkout"]["commit"],
            "11d5960a326750d5838078e36cf38b85af677262",
        )
        self.assertEqual(
            actions["actions/setup-python"]["commit"],
            "a26af69be951a213d495a4c3e4e4022e16d87065",
        )
        self.assertEqual(
            actions["actions/upload-artifact"]["commit"],
            "ea165f8d65b6e75b540449e92b4886f43607fa02",
        )


if __name__ == "__main__":
    unittest.main()
