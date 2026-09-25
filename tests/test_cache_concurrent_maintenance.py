import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.cache import ResultCache
from psmatrix.util import exclusive_lock


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
            original_lstat = Path.lstat

            def missing_lstat(path: Path, *args, **kwargs):
                if path == record:
                    raise FileNotFoundError(str(path))
                return original_lstat(path, *args, **kwargs)

            with patch.object(Path, "lstat", new=missing_lstat):
                stats = cache.stats()

            self.assertEqual(stats, {"records": 0, "bytes": 0})

    def test_age_prune_tolerates_record_disappearing_before_fallback_stat(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            record = self._record(cache, "b" * 64, "{")
            original_lstat = Path.lstat
            calls = 0

            def flaky_lstat(path: Path, *args, **kwargs):
                nonlocal calls
                if path == record:
                    calls += 1
                    if calls == 2:
                        raise FileNotFoundError(str(path))
                return original_lstat(path, *args, **kwargs)

            with patch.object(Path, "lstat", new=flaky_lstat):
                result = cache.prune(max_age_days=0)

            self.assertEqual(result["removed"], 0)
            self.assertEqual(result["records"], 1)

    def test_max_record_prune_tolerates_record_disappearing_before_ranking(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            disappearing = self._record(cache, "c" * 64)
            self._record(cache, "d" * 64)
            original_lstat = Path.lstat
            calls = 0

            def disappearing_lstat(path: Path, *args, **kwargs):
                nonlocal calls
                if path == disappearing:
                    calls += 1
                    if calls == 2:
                        path.unlink(missing_ok=True)
                        raise FileNotFoundError(str(path))
                return original_lstat(path, *args, **kwargs)

            with patch.object(Path, "lstat", new=disappearing_lstat):
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
            # An unreadable/disappearing records root is not trustworthy enough
            # to report records that maintenance cannot enumerate directly.
            self.assertEqual(result["records"], 0)

    def test_cross_process_store_waits_for_cache_mutation_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache_root = root / "cache"
            ready = root / "ready-store"
            cache = ResultCache(cache_root)
            lock_path = cache.root / ".result-cache.lock"
            child = r"""
import sys
from pathlib import Path
from psmatrix.cache import ResultCache, cache_key
from psmatrix.models import TargetReport

cache_root = Path(sys.argv[1])
ready = Path(sys.argv[2])
cache = ResultCache(cache_root)
source = cache_root.parent / "child.ps1"
source.write_text("'ok'", encoding="utf-8")
report = TargetReport(
    runtime_id="powershell-7.6.4-linux-x64",
    runtime_version="7.6.4",
    source=str(source),
    source_sha256="c" * 64,
    status="PASS",
    parse_ok=True,
)
material = {"key": "value"}
key = cache_key(material)
ready.write_text("ready", encoding="utf-8")
if not cache.store(key, report, material):
    raise SystemExit(2)
print("done", flush=True)
"""
            process = None
            try:
                with exclusive_lock(lock_path):
                    process = subprocess.Popen(
                        [sys.executable, "-c", child, str(cache_root), str(ready)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=dict(os.environ),
                    )
                    deadline = time.monotonic() + 10.0
                    while not ready.exists() and process.poll() is None:
                        if time.monotonic() >= deadline:
                            self.fail("child did not reach cache store boundary")
                        time.sleep(0.01)
                    self.assertTrue(ready.exists())
                    time.sleep(0.25)
                    self.assertIsNone(process.poll(), "child store bypassed cache mutation lock")

                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), "done")
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)

    def test_cross_process_clear_waits_for_cache_mutation_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache_root = root / "cache"
            ready = root / "ready-clear"
            cache = ResultCache(cache_root)
            self._record(cache, "a" * 64)
            lock_path = cache.root / ".result-cache.lock"
            child = r"""
import sys
from pathlib import Path
from psmatrix.cache import ResultCache

cache_root = Path(sys.argv[1])
ready = Path(sys.argv[2])
cache = ResultCache(cache_root)
ready.write_text("ready", encoding="utf-8")
cache.clear()
print("done", flush=True)
"""
            process = None
            try:
                with exclusive_lock(lock_path):
                    process = subprocess.Popen(
                        [sys.executable, "-c", child, str(cache_root), str(ready)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=dict(os.environ),
                    )
                    deadline = time.monotonic() + 10.0
                    while not ready.exists() and process.poll() is None:
                        if time.monotonic() >= deadline:
                            self.fail("child did not reach cache clear boundary")
                        time.sleep(0.01)
                    self.assertTrue(ready.exists())
                    time.sleep(0.25)
                    self.assertIsNone(process.poll(), "child clear bypassed cache mutation lock")

                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), "done")
                self.assertEqual(cache.stats(), {"records": 0, "bytes": 0})
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
