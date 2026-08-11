from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GA = ROOT / "scripts" / "ga"

INTERNAL_TO_PUBLIC = {
    "_publish_final_immutable_release_impl.py": "publish_final_immutable_release.py",
    "_verify_final_immutable_release_impl.py": "verify_final_immutable_release.py",
    "_verify_final_release_closure_impl.py": "verify_final_release_closure.py",
}
LIBRARY_ONLY_MESSAGE = "internal GA implementation is library-only; use the public entrypoint"


class InternalGAImplementationCLIBoundaryTests(unittest.TestCase):
    def test_internal_implementations_refuse_direct_execution(self) -> None:
        for internal in INTERNAL_TO_PUBLIC:
            with self.subTest(internal=internal):
                completed = subprocess.run(
                    [sys.executable, str(GA / internal)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    LIBRARY_ONLY_MESSAGE,
                    completed.stdout + completed.stderr,
                )

    def test_library_only_guard_precedes_any_internal_main(self) -> None:
        for internal in INTERNAL_TO_PUBLIC:
            with self.subTest(internal=internal):
                text = (GA / internal).read_text(encoding="utf-8")
                guard = text.index("LIBRARY_ONLY_MESSAGE")
                main = text.find("def main()")
                self.assertGreaterEqual(guard, 0)
                if main >= 0:
                    self.assertLess(guard, main)
                self.assertIn('if __name__ == "__main__":', text[: max(main, 1_000)])

    def test_public_entrypoints_remain_executable_clis(self) -> None:
        for public in INTERNAL_TO_PUBLIC.values():
            with self.subTest(public=public):
                completed = subprocess.run(
                    [sys.executable, str(GA / public), "--help"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=completed.stdout + completed.stderr,
                )
                self.assertIn("usage:", completed.stdout.lower())


if __name__ == "__main__":
    unittest.main()
