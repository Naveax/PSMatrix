from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "certify_verification_hardening_source.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verification_tree_binding", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerificationHardeningTreeBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def init_repo(self, root: Path) -> tuple[str, str]:
        self.git(root, "init")
        self.git(root, "config", "user.email", "ci@example.invalid")
        self.git(root, "config", "user.name", "PSMatrix CI")
        (root / "safe.txt").write_text("safe\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "baseline")
        head = self.git(root, "rev-parse", "HEAD").strip().lower()
        tree = self.git(root, "rev-parse", f"{head}^{{tree}}").strip().lower()
        return head, tree

    def scan_receipt(self, head: str, tree: str) -> dict[str, object]:
        return {
            "repository_head": head,
            "repository_tree": tree,
            "tracked_blob_authority_verified": True,
            "working_tree_clean_verified": True,
            "repository_head_stable_during_scan": True,
            "repository_tree_stable_during_scan": True,
        }

    def test_wrong_or_missing_tree_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            head, tree = self.init_repo(root)
            for mode in ("missing", "wrong", "unstable"):
                with self.subTest(mode=mode):
                    scan = self.scan_receipt(head, tree)
                    if mode == "missing":
                        scan.pop("repository_tree")
                    elif mode == "wrong":
                        scan["repository_tree"] = "0" * 40
                    else:
                        scan["repository_tree_stable_during_scan"] = False
                    with self.assertRaises(self.module.HardeningSourceCertificationError):
                        self.module.certify(root, head, scan)

    def test_source_propagates_tree_binding_proof(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("scanner.repository_tree", text)
        self.assertIn("private_material_scan_repository_tree", text)
        self.assertIn("private_material_scan_repository_tree_bound", text)
        self.assertIn("private_material_scan_repository_tree_stable_during_scan", text)

    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr)
        return completed.stdout


if __name__ == "__main__":
    unittest.main()
