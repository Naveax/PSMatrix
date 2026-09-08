import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.fleet import FleetError, FleetRegistry


_REPARSE_POINT = 0x400


def _reparse_lstat(target: Path):
    original = Path.lstat
    wanted = Path(os.path.abspath(os.fspath(target)))

    def fake(path: Path):
        current = Path(os.path.abspath(os.fspath(path)))
        if current == wanted:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR if current.is_dir() else stat.S_IFREG,
                st_file_attributes=_REPARSE_POINT,
            )
        return original(path)

    return fake


class FleetRegistryPathBoundaryTests(unittest.TestCase):
    def test_constructor_rejects_reparse_home(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            home.mkdir()
            with patch("pathlib.Path.lstat", new=_reparse_lstat(home)):
                with self.assertRaises(FleetError):
                    FleetRegistry(home)

    def test_list_revalidates_registry_index_before_read(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            fleet = FleetRegistry(home)
            fleet._save({"schema": 1, "generation": 0, "workers": []})
            with patch("pathlib.Path.lstat", new=_reparse_lstat(fleet.index)):
                with self.assertRaises(FleetError):
                    fleet.list()

    def test_transition_revalidates_registry_lock_before_use(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            fleet = FleetRegistry(home)
            fleet._save(
                {
                    "schema": 1,
                    "generation": 0,
                    "workers": [{"worker_id": "worker-a", "state": "ACTIVE"}],
                }
            )
            fleet.lock.touch()
            with patch("pathlib.Path.lstat", new=_reparse_lstat(fleet.lock)):
                with self.assertRaises(FleetError):
                    fleet.transition("worker-a", "QUARANTINED", reason="test")

    def test_enroll_rejects_reparse_endpoint_before_loading(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            endpoint = root / "endpoint.json"
            endpoint.write_text("{}", encoding="utf-8")
            fleet = FleetRegistry(home)
            with patch("pathlib.Path.lstat", new=_reparse_lstat(endpoint)):
                with patch("psmatrix.fleet.RemoteEndpoint.load") as load:
                    with self.assertRaises(FleetError):
                        fleet.enroll(endpoint)
                    load.assert_not_called()

    def test_managed_reset_files_are_revalidated_before_enrollment(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            endpoint = root / "endpoint.json"
            snapshot = root / "snapshot.json"
            private = root / "reset.pem"
            public = root / "reset.pub"
            for path in (endpoint, snapshot, private, public):
                path.write_text("fixture", encoding="utf-8")
            fleet = FleetRegistry(home)
            endpoint_model = SimpleNamespace(worker_id="worker-a", expected_runtime_id="windows-powershell-5.1")
            with patch("psmatrix.fleet.RemoteEndpoint.load", return_value=endpoint_model):
                with patch("pathlib.Path.lstat", new=_reparse_lstat(private)):
                    with self.assertRaises(FleetError):
                        fleet.enroll(
                            endpoint,
                            snapshot_config=snapshot,
                            reset_private_key=private,
                            reset_public_key=public,
                        )

    def test_select_revalidates_stored_endpoint_before_returning_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            endpoint = root / "endpoint.json"
            endpoint.write_text("{}", encoding="utf-8")
            fleet = FleetRegistry(home)
            fleet._save(
                {
                    "schema": 1,
                    "generation": 0,
                    "workers": [
                        {
                            "worker_id": "worker-a",
                            "runtime_id": "windows-powershell-5.1",
                            "endpoint": str(endpoint),
                            "state": "ACTIVE",
                            "priority": 100,
                            "labels": {},
                            "last_health": {
                                "passed": True,
                                "authoritative": True,
                            },
                        }
                    ],
                }
            )
            with patch("pathlib.Path.lstat", new=_reparse_lstat(endpoint)):
                with self.assertRaises(FleetError):
                    fleet.select("windows-powershell-5.1")


if __name__ == "__main__":
    unittest.main()
