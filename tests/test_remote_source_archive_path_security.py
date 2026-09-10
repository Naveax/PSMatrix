import tempfile
import unittest
from pathlib import Path

from psmatrix.remote_worker import create_source_archive


class RemoteSourceArchivePathSecurityTests(unittest.TestCase):
    def test_archive_reads_direct_single_link_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "entry.ps1"
            source.write_text("'ok'", encoding="utf-8")

            payload = create_source_archive(root, [source])

            self.assertGreater(len(payload), 10)


if __name__ == "__main__":
    unittest.main()
