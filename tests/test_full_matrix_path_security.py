import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.full_matrix import FullMatrixError, FullMatrixSpec, execute_full_matrix, write_full_matrix_template


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _local_spec(root: Path) -> Path:
    path = root / "full.json"
    path.write_text(
        json.dumps({
            "schema": 1,
            "kind": "psmatrix.full-matrix-spec",
            "name": "full",
            "targets": [{"id": "linux", "kind": "local", "version": "7.6.5"}],
        }),
        encoding="utf-8",
    )
    return path


class FullMatrixPathSecurityTests(unittest.TestCase):
    def test_rejects_reparse_matrix_spec(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            spec = _local_spec(root)
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {spec})):
                with self.assertRaisesRegex(FullMatrixError, "symlink or reparse point"):
                    FullMatrixSpec.load(spec)

    def test_rejects_reparse_endpoint_parent_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            endpoints = root / "endpoints"
            endpoints.mkdir()
            (endpoints / "win.json").write_text("{}", encoding="utf-8")
            spec = root / "full.json"
            spec.write_text(
                json.dumps({
                    "schema": 1,
                    "kind": "psmatrix.full-matrix-spec",
                    "name": "full",
                    "targets": [{
                        "id": "win",
                        "kind": "remote",
                        "runtime_id": "windows-powershell-5.1",
                        "endpoint": "endpoints/win.json",
                    }],
                }),
                encoding="utf-8",
            )
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {endpoints})):
                with self.assertRaisesRegex(FullMatrixError, "symlink or reparse point"):
                    FullMatrixSpec.load(spec)

    def test_rejects_reparse_allowance_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            allowance = root / "differences.json"
            allowance.write_text(
                json.dumps({
                    "schema": 1,
                    "kind": "psmatrix.differential-allowances",
                    "name": "empty",
                    "rules": [],
                }),
                encoding="utf-8",
            )
            spec = root / "full.json"
            spec.write_text(
                json.dumps({
                    "schema": 1,
                    "kind": "psmatrix.full-matrix-spec",
                    "name": "full",
                    "targets": [{"id": "linux", "kind": "local", "version": "7.6.5"}],
                    "differential": {"allowance_file": "differences.json"},
                }),
                encoding="utf-8",
            )
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {allowance})):
                with self.assertRaisesRegex(FullMatrixError, "symlink or reparse point"):
                    FullMatrixSpec.load(spec)

    def test_execute_rejects_reparse_entrypoint_before_runtime_work(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entrypoint = root / "tool.ps1"
            entrypoint.write_text("'ok'", encoding="utf-8")
            spec = _local_spec(root)
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {entrypoint})):
                with self.assertRaisesRegex(FullMatrixError, "symlink or reparse point"):
                    execute_full_matrix(
                        home=root / "home",
                        root=root,
                        entrypoint=entrypoint,
                        spec_path=spec,
                        include=[],
                        local_args=[],
                        remote_options={},
                        timeout=30,
                    )

    def test_execute_rejects_reparse_include_before_runtime_work(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entrypoint = root / "tool.ps1"
            entrypoint.write_text("'ok'", encoding="utf-8")
            include = root / "helper.ps1"
            include.write_text("'helper'", encoding="utf-8")
            spec = _local_spec(root)
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {include})):
                with self.assertRaisesRegex(FullMatrixError, "symlink or reparse point"):
                    execute_full_matrix(
                        home=root / "home",
                        root=root,
                        entrypoint=entrypoint,
                        spec_path=spec,
                        include=[include],
                        local_args=[],
                        remote_options={},
                        timeout=30,
                    )

    def test_template_rejects_reparse_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output_dir = root / "output"
            output_dir.mkdir()
            output = output_dir / "full.json"
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {output_dir})):
                with self.assertRaisesRegex(FullMatrixError, "symlink or reparse point"):
                    write_full_matrix_template(output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
