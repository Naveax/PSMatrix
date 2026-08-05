from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-full-runtime-matrix.yml"
SCRIPT = ROOT / "scripts" / "ga" / "Invoke-PSMatrixFullRuntimeMatrixGA.ps1"
DOC = ROOT / "docs" / "PRODUCTION_GA_FULL_MATRIX.md"
LAYOUT = ROOT / "ops" / "full-matrix-ga" / "full-matrix-ga-layout.template.json"


class GAFullMatrixOperationTests(unittest.TestCase):
    def test_workflow_is_manual_protected_self_hosted_and_sha_pinned(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("push:", text)
        self.assertIn("environment: production-ga-full-matrix", text)
        self.assertIn("runs-on: [self-hosted, Linux, X64, psmatrix-full-matrix]", text)
        self.assertIn("persist-credentials: false", text)
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
        self.assertGreaterEqual(len(uses), 3)
        for value in uses:
            self.assertRegex(value, r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$")

    def test_operator_requires_25_ready_strict_release_bound_matrix(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("'full', 'release-binding'", text)
        self.assertIn("'full', 'plan'", text)
        self.assertIn("'full', 'test'", text)
        self.assertIn("'full', 'attest'", text)
        self.assertIn("full verify-attestation", text)
        self.assertIn("25/25 ready targets", text)
        self.assertIn("'strict'", text)
        self.assertIn("Output directory must be empty", text)
        self.assertNotIn("CiPrivateKey = (Join-Path $output", text)

    def test_layout_declares_exact_25_lanes_and_is_secret_free(self):
        value = json.loads(LAYOUT.read_text(encoding="utf-8"))
        self.assertEqual(value["kind"], "psmatrix.full-matrix-ga-runner-layout")
        self.assertEqual(len(value["required"]["local_lanes"]), 12)
        self.assertEqual(len(value["required"]["remote_endpoint_files"]), 13)
        combined = LAYOUT.read_text(encoding="utf-8") + DOC.read_text(encoding="utf-8")
        self.assertNotIn("BEGIN PRIVATE KEY", combined)
        self.assertIn("25", combined)

    def test_schemas_exist_and_are_machine_readable(self):
        for name in ("full-matrix-release-binding.schema.json", "full-runtime-matrix-predicate.schema.json"):
            value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(value["$schema"], "https://json-schema.org/draft/2020-12/schema")


if __name__ == "__main__":
    unittest.main()
