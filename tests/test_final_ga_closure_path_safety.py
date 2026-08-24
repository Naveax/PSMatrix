from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
SCRIPT = ROOT / "scripts" / "ga" / "final_ga_closure.py"


def _load_module():
    name = "psmatrix_test_final_ga_closure_path_safety"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load final GA closure script")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


class FinalGAClosurePathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def _symlink(self, link: Path, target: Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable on this runner: {exc}")

    @staticmethod
    def _write(path: Path, text: str = "test\n") -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _sign_args(self, root: Path) -> SimpleNamespace:
        source_root = root / "source"
        source_root.mkdir(parents=True)
        return SimpleNamespace(
            policy=self._write(root / "ga-policy.json", "{}\n"),
            source_root=source_root,
            expected_commit="0" * 40,
            private_key=self._write(root / "private.pem"),
            public_key=self._write(root / "public.pem"),
            output_dir=root / "closure-output",
        )

    def _verify_args(self, root: Path) -> SimpleNamespace:
        source_root = root / "source"
        source_root.mkdir(parents=True)
        evidence = root / "evidence"
        evidence.mkdir()
        return SimpleNamespace(
            policy=self._write(root / "ga-policy.json", "{}\n"),
            source_root=source_root,
            expected_commit="0" * 40,
            evaluation=self._write(evidence / "production-ga-evaluation.json", "{}\n"),
            ga_attestation=self._write(evidence / "production-ga.dsse.json", "{}\n"),
            closure_attestation=self._write(evidence / "final-closure.dsse.json", "{}\n"),
            public_key=self._write(root / "public.pem"),
            output=root / "verification.json",
        )

    def test_legacy_policy_resolver_is_replaced_with_fail_closed_resolver(self) -> None:
        self.assertIs(self.module._legacy._resolve, self.module._safe_policy_resolve)

    def test_policy_resolver_rejects_direct_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = self._write(root / "target.json", "{}\n")
            link = root / "evidence.json"
            self._symlink(link, target)
            with self.assertRaises(self.module.ClosureError):
                self.module._safe_policy_resolve(root, "evidence.json", "evidence")

    def test_policy_resolver_rejects_parent_symlink_component(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            self._write(real / "evidence.json", "{}\n")
            linked = root / "linked"
            self._symlink(linked, real, directory=True)
            with self.assertRaises(self.module.ClosureError):
                self.module._safe_policy_resolve(root, "linked/evidence.json", "evidence")

    def test_sign_prepare_rejects_symlink_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self._sign_args(root)
            target = args.private_key
            link = root / "linked-private.pem"
            self._symlink(link, target)
            args.private_key = link
            with self.assertRaises(self.module.ClosureError):
                self.module._prepare_sign_args(args)

    def test_sign_prepare_rejects_symlink_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self._sign_args(root)
            real_output = root / "real-output"
            real_output.mkdir()
            linked_output = root / "linked-output"
            self._symlink(linked_output, real_output, directory=True)
            args.output_dir = linked_output
            with self.assertRaises(self.module.ClosureError):
                self.module._prepare_sign_args(args)

    def test_verify_prepare_rejects_symlink_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self._verify_args(root)
            target = args.ga_attestation
            link = target.with_name("linked-ga.dsse.json")
            self._symlink(link, target)
            args.ga_attestation = link
            with self.assertRaises(self.module.ClosureError):
                self.module._prepare_verify_args(args)

    def test_verify_prepare_rejects_symlink_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args = self._verify_args(root)
            target = self._write(root / "real-verification.json", "{}\n")
            link = root / "linked-verification.json"
            self._symlink(link, target)
            args.output = link
            with self.assertRaises(self.module.ClosureError):
                self.module._prepare_verify_args(args)

    def test_regular_sign_and_verify_paths_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sign_args = self._sign_args(root / "sign")
            safe_sign = self.module._prepare_sign_args(sign_args)
            self.assertEqual(safe_sign.policy, sign_args.policy.resolve())
            self.assertEqual(safe_sign.source_root, sign_args.source_root.resolve())
            self.assertEqual(safe_sign.private_key, sign_args.private_key.resolve())
            self.assertEqual(safe_sign.public_key, sign_args.public_key.resolve())
            self.assertEqual(safe_sign.output_dir, sign_args.output_dir.resolve())

            verify_args = self._verify_args(root / "verify")
            safe_verify = self.module._prepare_verify_args(verify_args)
            self.assertEqual(safe_verify.evaluation, verify_args.evaluation.resolve())
            self.assertEqual(safe_verify.ga_attestation, verify_args.ga_attestation.resolve())
            self.assertEqual(safe_verify.closure_attestation, verify_args.closure_attestation.resolve())
            self.assertEqual(safe_verify.output, verify_args.output.resolve())


if __name__ == "__main__":
    unittest.main()
