import tempfile
import unittest
from pathlib import Path

from psmatrix.models import RuntimeSpec, TargetReport
from psmatrix.scheduler import CheckpointStore, TargetJob, execute_jobs


class RecordingCache:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def store(self, key, report, material, *, material_digest=None):
        self.calls.append(
            {
                "key": key,
                "report": report,
                "material": material,
                "material_digest": material_digest,
            }
        )
        return True


class SchedulerCacheMaterialDigestTests(unittest.TestCase):
    def test_execute_jobs_reuses_job_key_as_cache_material_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "sample.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            spec = RuntimeSpec(version="7.6.4")
            key = "a" * 64
            material = {"source": {"path": str(source), "sha256": "source-hash"}}
            job = TargetJob(
                index=0,
                source=source,
                spec=spec,
                key=key,
                shard_key="b" * 64,
                material=material,
            )
            cache = RecordingCache()

            def run_one(path, runtime):
                return TargetReport(
                    runtime_id=runtime.runtime_id,
                    runtime_version=runtime.version,
                    source=str(path.resolve()),
                    source_sha256="source-hash",
                    status="PASS",
                    parse_ok=True,
                )

            result = execute_jobs(
                [job],
                run_one,
                cache=cache,
                cache_mode="refresh",
                checkpoint=CheckpointStore(None),
                resume=False,
                jobs_count=1,
                fail_fast=False,
            )

            self.assertEqual(len(cache.calls), 1)
            self.assertEqual(cache.calls[0]["key"], key)
            self.assertIs(cache.calls[0]["material"], material)
            self.assertEqual(cache.calls[0]["material_digest"], key)
            self.assertEqual(result.metadata["executed"], 1)
            self.assertEqual(result.metadata["cache_stored"], 1)


if __name__ == "__main__":
    unittest.main()
