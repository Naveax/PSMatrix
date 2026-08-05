import tempfile
import unittest
from pathlib import Path

from psmatrix.oci import OciRuntimeManager


class OciMountContractTests(unittest.TestCase):
    def test_generated_wrapper_uses_valid_long_mount_syntax(self):
        with tempfile.TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / "pwsh"
            OciRuntimeManager._write_wrapper(
                wrapper,
                engine_name="docker",
                engine_path="/usr/bin/docker",
                image="example.invalid/psmatrix:test",
                version="6.0.5",
                platform="linux/amd64",
            )
            payload = wrapper.read_text(encoding="utf-8")

        self.assertIn("type=bind,src={host_root},dst=/workspace", payload)
        self.assertNotIn("dst=/workspace,rw", payload)
        self.assertIn("--read-only", payload)
        self.assertIn("--cap-drop=ALL", payload)
        self.assertIn("no-new-privileges", payload)
        self.assertIn("/tmp:rw,nosuid,nodev,noexec,size=64m", payload)


if __name__ == "__main__":
    unittest.main()
