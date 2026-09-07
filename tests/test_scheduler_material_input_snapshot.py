import tempfile
import unittest
from pathlib import Path

from psmatrix.cache import cache_and_shard_keys
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions
from psmatrix.scheduler import build_jobs


class _RuntimeManagerStub:
    def __init__(self, root: Path) -> None:
        self.root = root

    def metadata_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "runtime-metadata.json"

    def executable_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "pwsh"


class _OciManagerStub:
    def __init__(self, root: Path) -> None:
        self.root = root

    def metadata_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "oci-metadata.json"

    def wrapper_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "oci-wrapper"


class SchedulerMaterialInputSnapshotTests(unittest.TestCase):
    def test_tool_modules_and_engine_are_snapshotted_before_keying(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            specs = [
                RuntimeSpec(version="7.6.4", arch="x64"),
                RuntimeSpec(version="7.6.4", arch="arm64"),
            ]
            tool_modules = {
                "digest": "modules-before",
                "modules": [{"name": "Example", "metadata": {"version": "1.0"}}],
            }
            engine = {
                "digest": "engine-before",
                "files": [{"name": "runner.py", "metadata": {"size": 1}}],
            }

            jobs = build_jobs(
                [source],
                specs,
                RunOptions(),
                tool_version="test",
                runtime_manager=_RuntimeManagerStub(root / "runtime"),
                oci_manager=_OciManagerStub(root / "oci"),
                tool_modules=tool_modules,
                engine=engine,
            )

            self.assertEqual(len(jobs), 2)
            original_keys = [job.key for job in jobs]

            tool_modules["digest"] = "modules-after"
            tool_modules["modules"][0]["name"] = "Mutated"
            tool_modules["modules"][0]["metadata"]["version"] = "9.9"
            engine["digest"] = "engine-after"
            engine["files"][0]["name"] = "mutated.py"
            engine["files"][0]["metadata"]["size"] = 999

            for index, job in enumerate(jobs):
                self.assertEqual(job.material["tool_modules"]["digest"], "modules-before")
                self.assertEqual(job.material["tool_modules"]["modules"][0]["name"], "Example")
                self.assertEqual(
                    job.material["tool_modules"]["modules"][0]["metadata"]["version"],
                    "1.0",
                )
                self.assertEqual(job.material["engine"]["digest"], "engine-before")
                self.assertEqual(job.material["engine"]["files"][0]["name"], "runner.py")
                self.assertEqual(job.material["engine"]["files"][0]["metadata"]["size"], 1)
                self.assertEqual(cache_and_shard_keys(job.material)[0], original_keys[index])

            self.assertIsNot(jobs[0].material["tool_modules"], tool_modules)
            self.assertIsNot(jobs[0].material["engine"], engine)
            self.assertIsNot(jobs[0].material["tool_modules"], jobs[1].material["tool_modules"])
            self.assertIsNot(jobs[0].material["engine"], jobs[1].material["engine"])


if __name__ == "__main__":
    unittest.main()
