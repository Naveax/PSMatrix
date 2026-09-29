import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_result_cache_hardening as hardening
from psmatrix import remote_worker as rw


class RemoteResultCacheHardeningTests(unittest.TestCase):
    def _cache(self, root: Path):
        cache = root / "cache"
        cache.mkdir()
        direct, identity = rw._pin_direct_directory(cache, label="Worker result cache")
        return direct, identity

    def test_install_replaces_cache_read_and_write_helpers(self):
        self.assertIs(rw._read_pinned_json, hardening._hardened_read_pinned_json)
        self.assertIs(rw._write_pinned_json, hardening._hardened_write_pinned_json)
        self.assertTrue(getattr(rw, "_result_cache_io_identity_hardened", False))

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_posix_cache_round_trip_uses_pinned_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            cache, identity = self._cache(Path(temp))
            target = cache / "job.json"
            value = {"schema": 1, "request_sha256": "a" * 64, "nested": {"x": 1}}
            hardening._hardened_write_pinned_json(
                target,
                value,
                directory=cache,
                directory_identity=identity,
                label="Worker result cache entry",
            )
            loaded = hardening._hardened_read_pinned_json(
                target,
                directory=cache,
                directory_identity=identity,
                label="Worker result cache entry",
            )
            self.assertEqual(loaded, value)
            expected = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            self.assertEqual(target.read_text(encoding="utf-8"), expected)

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_parent_swap_during_publish_cannot_redirect_cache_entry(self):
        if os.link not in getattr(os, "supports_dir_fd", set()):
            self.skipTest("dir_fd link unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache, identity = self._cache(root)
            target = cache / "job.json"
            renamed = root / "cache.original"
            real_link = os.link
            swapped = {"done": False}

            def swapping_link(*args, **kwargs):
                if not swapped["done"]:
                    swapped["done"] = True
                    cache.rename(renamed)
                    cache.mkdir()
                return real_link(*args, **kwargs)

            with patch.object(hardening.os, "link", side_effect=swapping_link):
                with self.assertRaises(rw.WorkerError):
                    hardening._hardened_write_pinned_json(
                        target,
                        {"schema": 1},
                        directory=cache,
                        directory_identity=identity,
                        label="Worker result cache entry",
                    )

            self.assertTrue(swapped["done"])
            self.assertFalse((cache / "job.json").exists())
            self.assertFalse((renamed / "job.json").exists())

    @unittest.skipIf(os.name == "nt", "descriptor-relative POSIX regression")
    def test_parent_swap_before_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache, identity = self._cache(root)
            target = cache / "job.json"
            target.write_text('{"schema": 1}\n', encoding="utf-8")
            renamed = root / "cache.original"
            cache.rename(renamed)
            cache.mkdir()
            (cache / "job.json").write_text('{"schema": 999}\n', encoding="utf-8")
            with self.assertRaises(rw.WorkerError):
                hardening._hardened_read_pinned_json(
                    cache / "job.json",
                    directory=cache,
                    directory_identity=identity,
                    label="Worker result cache entry",
                )

    def test_target_outside_cache_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache, identity = self._cache(root)
            with self.assertRaises(rw.WorkerError):
                hardening._hardened_read_pinned_json(
                    root / "outside.json",
                    directory=cache,
                    directory_identity=identity,
                    label="Worker result cache entry",
                )


if __name__ == "__main__":
    unittest.main()
