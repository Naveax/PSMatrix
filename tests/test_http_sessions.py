import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.http_sessions import ProjectSessionAPI, ProjectSessionStore, SessionError, SessionLimits
from psmatrix.module_compat import OfflineModuleMirror


def package(path: Path, name="Example", version="1.0.0"):
    nuspec = f'''<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
<id>{name}</id><version>{version}</version><dependencies><group targetFramework="PowerShell"></group></dependencies>
</metadata></package>'''
    manifest = f"@{{RootModule='{name}.psm1';ModuleVersion='{version}';GUID='11111111-1111-1111-1111-111111111111'}}"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{name}.nuspec", nuspec)
        archive.writestr(f"tools/{name}/{name}.psd1", manifest)
        archive.writestr(f"tools/{name}/{name}.psm1", f"function Get-{name} {{ '{version}' }}")


class HTTPSessionTests(unittest.TestCase):
    def test_path_quota_principal_and_termination_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home", SessionLimits(
                max_files=2, max_project_bytes=2048, max_upload_bytes=1024, max_text_bytes=1024,
                max_artifact_bytes=2048, ttl_seconds=120, artifact_ttl_seconds=30,
            ))
            record = store.create("principal-a")
            store.upload_text(record, "a.ps1", "'a'")
            with self.assertRaises(SessionError): store.upload_text(record, "../escape.ps1", "x")
            with self.assertRaises(SessionError): store.upload(record, "large.bin", b"X" * 1025)
            with self.assertRaises(SessionError): store.get(record.session_id, "principal-b")
            store.terminate(record.session_id, "principal-a")
            with self.assertRaises(SessionError): store.get(record.session_id, "principal-a")

    def test_mirror_bootstrap_imports_only_verified_packages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_package = root / "Example.nupkg"
            package(source_package)
            mirror = OfflineModuleMirror(root / "source-mirror")
            mirror.add(source_package, expected_sha256=hashlib.sha256(source_package.read_bytes()).hexdigest())
            export = root / "mirror.zip"
            mirror.export(export)

            store = ProjectSessionStore(root / "home")
            record = store.create("principal")
            uploaded = record.root / "mirror.zip"
            uploaded.write_bytes(export.read_bytes())
            api = ProjectSessionAPI(store, record)
            result = api.bootstrap(runtime=None, runtime_archive=None, hashes_file=None, mirror_archive="mirror.zip")
            self.assertTrue(result["mirror"]["valid"])
            self.assertEqual(result["mirror"]["packages"], 1)
            imported = OfflineModuleMirror(record.home / "module-mirror")
            self.assertEqual(imported.exact("Example", "1.0.0")["sha256"], hashlib.sha256(source_package.read_bytes()).hexdigest())


    def test_audit_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            store.upload_text(record, "tool.ps1", "'ok'")
            status = store.status(record)
            self.assertTrue(status["audit"]["valid"])
            audit = store._record_path(record.session_id).parent / "audit.jsonl"
            lines = audit.read_text(encoding="utf-8").splitlines()
            value = __import__("json").loads(lines[-1])
            value["action"] = "tampered"
            lines[-1] = __import__("json").dumps(value, sort_keys=True, separators=(",", ":"))
            audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(store.status(record)["audit"]["valid"])

    def test_artifact_capability_is_bound_to_principal(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal-a")
            store.upload(record, ".psmatrix/mcp/report.json", b"{}")
            prepared = store.prepare_artifact(record, ".psmatrix/mcp/report.json", purpose="diagnostic")
            token = prepared["downloadPath"].split("/artifacts/", 1)[1]
            _, path, payload = store.resolve_artifact(token, "principal-a")
            self.assertEqual(path.read_bytes(), b"{}")
            self.assertEqual(payload["purpose"], "diagnostic")
            with self.assertRaises(SessionError): store.resolve_artifact(token, "principal-b")


if __name__ == "__main__": unittest.main()
