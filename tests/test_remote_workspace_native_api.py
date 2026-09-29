import os
import tempfile
import unittest
import uuid
from pathlib import Path

from psmatrix import remote_worker as rw
from psmatrix import remote_workspace_create_hardening as workspace_hardening
from psmatrix import remote_workspace_native_api_hardening as hardening


class RemoteWorkspaceNativeApiTests(unittest.TestCase):
    def test_native_contract_wrapper_is_installed(self):
        self.assertIs(
            workspace_hardening._create_windows_directory_handle,
            hardening._hardened_create_windows_directory_handle,
        )
        self.assertTrue(
            getattr(workspace_hardening, "_native_api_contract_hardened", False)
        )

    def test_invalid_handle_values_are_rejected(self):
        class FakeCtypes:
            class c_void_p:
                def __init__(self, value=None):
                    self.value = (1 << 64) - 1 if value == -1 else value

        class Handle:
            def __init__(self, value):
                self.value = value

        self.assertFalse(hardening._valid_handle_value(FakeCtypes, Handle(None)))
        self.assertFalse(hardening._valid_handle_value(FakeCtypes, Handle(0)))
        self.assertTrue(hardening._valid_handle_value(FakeCtypes, Handle(123)))

    @unittest.skipUnless(os.name == "nt", "Windows native API regression")
    def test_windows_native_api_declares_full_function_contracts(self):
        api = hardening._windows_native_api()
        nt_create_file = api[5]
        rtl_status_to_dos_error = api[6]
        self.assertEqual(len(nt_create_file.argtypes), 11)
        self.assertEqual(len(rtl_status_to_dos_error.argtypes), 1)
        self.assertIsNotNone(nt_create_file.restype)
        self.assertIsNotNone(rtl_status_to_dos_error.restype)

    @unittest.skipUnless(os.name == "nt", "Windows native create regression")
    def test_native_create_returns_live_nonreplaceable_directory_handle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / str(uuid.uuid4())
            handle, identity = hardening._hardened_create_windows_directory_handle(
                rw,
                target,
            )
            try:
                self.assertTrue(target.is_dir())
                self.assertEqual(len(identity), 2)
                with self.assertRaises(OSError):
                    target.rename(target.with_suffix(".moved"))
            finally:
                from psmatrix import remote_zip_hardening as zip_hardening

                zip_hardening._close_windows_handle(handle)


if __name__ == "__main__":
    unittest.main()
