import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.cache import ResultCache, _direct_directory_stat, _regular_file_stat
from psmatrix.models import TargetReport


class CacheReparseIndirectionTests(unittest.TestCase):
    @staticmethod
    def _report(marker: str = "safe") -> TargetReport:
        return TargetReport(
            runtime_id="powershell-7.6.4-linux-x64",
            runtime_version="7.6.4",
            source="sample.ps1",
            source_sha256=marker,
            status="PASS",
            parse_ok=True,
        )

    def _directory_symlink(self, target: Path, link: Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")

    def test_reparse_attribute_is_not_a_direct_directory_or_regular_file(self):
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        directory_info = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_file_attributes=reparse,
        )
        file_info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_file_attributes=reparse,
        )

        with patch.object(Path, "lstat", return_value=directory_info):
            self.assertIsNone(_direct_directory_stat(Path("reparse-directory")))
        with patch.object(Path, "lstat", return_value=file_info):
            self.assertIsNone(_regular_file_stat(Path("reparse-file.json")))

    def test_symlinked_shard_cannot_read_write_or_prune_external_record(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = ResultCache(root / "cache")
            safe = ResultCache(root / "safe-cache")
            external = root / "external"
            external.mkdir()
            key = "a" * 64

            self.assertTrue(safe.store(key, self._report(), {}, material_digest=key))
            external_record = external / f"{key}.json"
            shutil.copy2(safe.record_path(key), external_record)

            shard = cache.records / key[:2]
            self._directory_symlink(external, shard)

            self.assertIsNone(cache.load(key))
            self.assertFalse(cache.store(key, self._report("new"), {}, material_digest=key))
            self.assertEqual(cache.stats(), {"records": 0, "bytes": 0})
            self.assertEqual(cache.prune(max_records=0)["removed"], 0)
            self.assertTrue(external_record.is_file())

    def test_replaced_targets_directory_is_never_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = ResultCache(root / "cache")
            external = root / "external"
            external.mkdir()
            shutil.rmtree(cache.records)
            self._directory_symlink(external, cache.records)
            key = "b" * 64

            self.assertIsNone(cache.load(key))
            self.assertFalse(cache.store(key, self._report(), {}, material_digest=key))
            self.assertEqual(cache.stats(), {"records": 0, "bytes": 0})
            self.assertEqual(cache.prune(max_records=0)["removed"], 0)
            with self.assertRaises(OSError):
                cache.clear()
            self.assertTrue(external.is_dir())


if __name__ == "__main__":
    unittest.main()
