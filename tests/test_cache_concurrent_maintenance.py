import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.cache import ResultCache


class CacheConcurrentMaintenanceTests(unittest.TestCase):
    def _record(self, cache: ResultCache, key: str, content: str = "{}") -> Path:
        path = cache.record_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_stats_ignores_record_that_disappears_during_stat(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            record = self._record(cache, "a" * 64)
            original_stat = Path.stat

            def missing_stat(path: Path, *args, **kwargs):
                if path == record:
                    raise FileNotFoundError(str(path))
                return original_stat(path, *args, **kwargs)

            with patch.object(Path, "stat", new=missing_stat):
                stats = cache.stats()

            self.assertEqual(stats, {"records": 0, "bytes": 0})

    def test_age_prune_tolerates_record_disappearing_before_fallback_stat(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            record = self._record(cache, "b" * 64, "{")
            original_stat = Path.stat
            calls = 0

            def flaky_stat(path: Path, *args, **kwargs):
                nonlocal calls
                if path == record:
                    calls += 1
                    if calls == 2:
                        raise FileNotFoundError(str(path))
                return original_stat(path, *args, **kwargs)

            with patch.object(Path, "stat", new=flaky_stat):
                result = cache.prune(max_age_days=0)

            self.assertEqual(result["removed"], 0)
            self.assertEqual(result["records"], 1)

    def test_max_record_prune_tolerates_record_disappearing_before_ranking(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            disappearing = self._record(cache, "c" * 64)
            self._record(cache, "d" * 64)
            original_stat = Path.stat
            calls = 0

            def disappearing_stat(path: Path, *args, **kwargs):
                nonlocal calls
                if path == disappearing:
                    calls += 1
                    if calls == 2:
                        path.unlink(missing_ok=True)
                        raise FileNotFoundError(str(path))
                return original_stat(path, *args, **kwargs)

            with patch.object(Path, "stat", new=disappearing_stat):
                result = cache.prune(max_records=1)

            self.assertEqual(result["removed"], 0)
            self.assertEqual(result["records"], 1)

    def test_clear_recreates_records_root_if_it_disappears_before_rmtree(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            self._record(cache, "e" * 64)
            original_rmtree = shutil.rmtree

            def disappearing_rmtree(path: Path, *args, **kwargs):
                original_rmtree(path, *args, **kwargs)
                raise FileNotFoundError(str(path))

            with patch("psmatrix.cache.shutil.rmtree", side_effect=disappearing_rmtree):
                before = cache.clear()

            self.assertEqual(before["records"], 1)
            self.assertTrue(cache.records.is_dir())

    def test_prune_tolerates_records_root_disappearing_before_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            self._record(cache, "f" * 64)
            original_iterdir = Path.iterdir

            def missing_iterdir(path: Path):
                if path == cache.records:
                    raise FileNotFoundError(str(path))
                return original_iterdir(path)

            with patch.object(Path, "iterdir", new=missing_iterdir):
                result = cache.prune()

            self.assertEqual(result["removed"], 0)
            self.assertEqual(result["records"], 1)


if __name__ == "__main__":
    unittest.main()
