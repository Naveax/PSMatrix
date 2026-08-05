import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.module_manager import ModuleInstallError, ModuleManager


def make_module_package(
    path: Path,
    *,
    name: str = "PSScriptAnalyzer",
    version: str = "1.25.0",
    traversal: bool = False,
) -> None:
    nuspec = f"""<?xml version='1.0'?>
<package xmlns='http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'>
  <metadata><id>{name}</id><version>{version}</version></metadata>
</package>
"""
    manifest = f"""@{{
    RootModule = '{name}.psm1'
    ModuleVersion = '{version}'
    GUID = 'f6fb5c0e-c759-4c77-9a98-9908c1b60f52'
    FunctionsToExport = @('Invoke-ScriptAnalyzer')
}}
"""
    module = """function Invoke-ScriptAnalyzer {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string] $Path)
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match 'ANALYZER_ERROR') {
        [pscustomobject]@{
            RuleName = 'PSMatrix.FakeRule'
            Severity = 'Error'
            Message = 'Synthetic analyzer error'
            ScriptName = [IO.Path]::GetFileName($Path)
            Line = 1
            Column = 1
            Extent = 'ANALYZER_ERROR'
            SuppressionID = $null
            SuggestedCorrections = @()
        }
    }
}
Export-ModuleMember -Function Invoke-ScriptAnalyzer
"""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{name}.nuspec", nuspec)
        archive.writestr(f"tools/{name}/{name}.psd1", manifest)
        archive.writestr(f"tools/{name}/{name}.psm1", module)
        if traversal:
            archive.writestr("../escape.txt", "escape")


class ModuleManagerTests(unittest.TestCase):
    def test_installs_hash_verified_package_and_stages_versioned_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "module.nupkg"
            make_module_package(package)
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            manager = ModuleManager(root / "home")
            installation = manager.install_nupkg(
                package,
                expected_name="PSScriptAnalyzer",
                expected_version="1.25.0",
                sha256=digest,
            )
            self.assertTrue(installation.verified)
            self.assertTrue((installation.root / "PSScriptAnalyzer.psd1").is_file())
            self.assertEqual(manager.latest("PSScriptAnalyzer"), installation.root)

            staged = root / "staged"
            entries = manager.stage_all(staged)
            self.assertEqual(len(entries), 1)
            self.assertTrue(
                (staged / "PSScriptAnalyzer" / "1.25.0" / "PSScriptAnalyzer.psd1").is_file()
            )

    def test_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "module.nupkg"
            make_module_package(package)
            manager = ModuleManager(root / "home")
            with self.assertRaises(ModuleInstallError):
                manager.install_nupkg(package, sha256="0" * 64)

    def test_rejects_package_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "module.nupkg"
            make_module_package(package, traversal=True)
            manager = ModuleManager(root / "home")
            with self.assertRaises(ModuleInstallError):
                manager.install_nupkg(package, trust_local=True)
            self.assertFalse((root / "escape.txt").exists())

    def test_rejects_unsafe_module_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "module.nupkg"
            make_module_package(package, name="../Escape")
            manager = ModuleManager(root / "home")
            with self.assertRaises(ModuleInstallError):
                manager.install_nupkg(package, trust_local=True)

    def test_offline_cache_restores_locked_module_and_stages_only_selection(self):
        from psmatrix.dependencies import ModuleLock

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.nupkg"
            second = root / "second.nupkg"
            make_module_package(first, name="Example", version="1.0.0")
            make_module_package(second, name="Other", version="2.0.0")
            manager = ModuleManager(root / "home")
            first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
            second_hash = hashlib.sha256(second.read_bytes()).hexdigest()
            manager.install_nupkg(first, sha256=first_hash)
            manager.install_nupkg(second, sha256=second_hash)

            # Remove the expanded module but retain the immutable package cache.
            import shutil
            shutil.rmtree(manager.module_root("Example", "1.0.0"))
            locks = (ModuleLock("Example", "1.0.0", first_hash, True),)
            resolved = manager.ensure_locked(locks, restore=True)
            self.assertEqual(resolved[0]["name"], "Example")

            staged = root / "staged-locked"
            entries = manager.stage_for_run(staged, locks, tool_names=())
            self.assertEqual([item["name"] for item in entries], ["Example"])
            self.assertFalse((staged / "Other").exists())

    def test_build_lock_records_exact_hash_and_verification_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "module.nupkg"
            make_module_package(package, name="Example", version="1.2.3")
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            manager = ModuleManager(root / "home")
            manager.install_nupkg(package, sha256=digest)
            lock = manager.build_lock(["Example"], require_verified=True)
            self.assertEqual(lock["schema"], 1)
            self.assertEqual(lock["powershell_modules"][0]["version"], "1.2.3")
            self.assertEqual(lock["powershell_modules"][0]["sha256"], digest)
            self.assertTrue(lock["powershell_modules"][0]["require_verified"])


if __name__ == "__main__":
    unittest.main()
