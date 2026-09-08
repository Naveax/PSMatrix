import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from psmatrix.evidence import write_evidence_bundle
from psmatrix.models import MatrixReport, TargetReport


def _report(source: Path, digest: str) -> MatrixReport:
    return MatrixReport(
        schema=1,
        tool_version="test",
        started_at="2026-09-08T00:00:00+00:00",
        finished_at="2026-09-08T00:00:01+00:00",
        status="PASS",
        targets=[
            TargetReport(
                runtime_id="powershell-7.6.5-linux-x64",
                runtime_version="7.6.5",
                source=str(source),
                source_sha256=digest,
                status="PASS",
                parse_ok=True,
            )
        ],
    )


class EvidenceSourceByteIntegrityTests(unittest.TestCase):
    def test_bundle_rejects_bytes_that_do_not_match_validated_source_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            original = b"Write-Output 'validated'\n"
            replacement = b"Write-Output 'changed'\n"
            source.write_bytes(original)
            digest = hashlib.sha256(original).hexdigest()
            output = root / "evidence.zip"
            original_read_bytes = Path.read_bytes

            def swapped_read_bytes(path: Path) -> bytes:
                if path == source:
                    return replacement
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", autospec=True, side_effect=swapped_read_bytes):
                with self.assertRaisesRegex(ValueError, "Source changed after validation"):
                    write_evidence_bundle(_report(source, digest), output, project_root=root)

            self.assertFalse(output.exists())

    def test_bundled_source_bytes_match_manifest_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tool.ps1"
            raw = b"Write-Output 'stable'\n"
            source.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            output = root / "evidence.zip"

            write_evidence_bundle(_report(source, digest), output, project_root=root)

            with zipfile.ZipFile(output) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                source_entry = next(item for item in manifest["entries"] if item["path"].startswith("sources/"))
                bundled = archive.read(source_entry["path"])

            self.assertEqual(hashlib.sha256(bundled).hexdigest(), digest)
            self.assertEqual(source_entry["sha256"], digest)


if __name__ == "__main__":
    unittest.main()
