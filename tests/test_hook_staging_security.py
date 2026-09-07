import os
import tempfile
import unittest
from pathlib import Path

from psmatrix.run_config import (
    RunConfigurationError,
    resolve_execution_profile,
    stage_hooks,
)


class HookStagingSecurityTests(unittest.TestCase):
    def _profile_with_hook(self, root: Path):
        source = root / "script.ps1"
        source.write_text("'ok'", encoding="utf-8")
        hook = root / "setup.ps1"
        hook.write_text("'setup'", encoding="utf-8")
        profile = resolve_execution_profile(source, cli_setup=(str(hook),))
        return hook, profile

    def test_rejects_symlinked_intermediate_hooks_directory(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, profile = self._profile_with_hook(root)
            workspace = root / "workspace"
            internal = workspace / ".psmatrix-internal"
            internal.mkdir(parents=True)
            external = root / "external-hooks"
            external.mkdir()
            (internal / "hooks").symlink_to(external, target_is_directory=True)

            with self.assertRaisesRegex(RunConfigurationError, "symlink or reparse point"):
                stage_hooks(workspace, profile.setup, "setup")

            self.assertFalse((external / "setup").exists())

    def test_rejects_symlinked_final_hook_destination_without_overwriting_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, profile = self._profile_with_hook(root)
            hook = profile.setup[0]
            workspace = root / "workspace"
            destination_root = workspace / ".psmatrix-internal" / "hooks" / "setup"
            destination_root.mkdir(parents=True)
            outside = root / "outside.ps1"
            outside.write_text("'outside'", encoding="utf-8")
            destination = destination_root / f"000-{hook.sha256[:12]}-{hook.source.name}"
            destination.symlink_to(outside)

            with self.assertRaisesRegex(RunConfigurationError, "symlink or reparse point"):
                stage_hooks(workspace, profile.setup, "setup")

            self.assertEqual(outside.read_text(encoding="utf-8"), "'outside'")

    def test_rejects_hook_source_changed_after_profile_resolution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            hook, profile = self._profile_with_hook(root)
            hook.write_text("'mutated'", encoding="utf-8")
            workspace = root / "workspace"
            workspace.mkdir()

            with self.assertRaisesRegex(RunConfigurationError, "changed after validation"):
                stage_hooks(workspace, profile.setup, "setup")

            destination_root = workspace / ".psmatrix-internal" / "hooks" / "setup"
            self.assertEqual(list(destination_root.glob("*")), [])


if __name__ == "__main__":
    unittest.main()
