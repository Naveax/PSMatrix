import json
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from xml.etree import ElementTree as ET

from psmatrix.cache import ResultCache
from psmatrix.cli import main
from psmatrix.evidence import write_evidence_bundle
from psmatrix.exporters import write_html, write_junit, write_sarif
from psmatrix.sbom import write_sbom
from psmatrix.models import MatrixReport, ParseDiagnostic, RuntimeSpec, TargetReport
from psmatrix.module_manager import ModuleManager
from psmatrix.oci import OciRuntimeManager
from psmatrix.runner import RunOptions
from psmatrix.runtime import RuntimeManager
from psmatrix.scheduler import CheckpointStore, build_jobs, execute_jobs


class IncrementalSchedulerTests(unittest.TestCase):
    def _target(self, source: Path, spec: RuntimeSpec, status: str = "PASS") -> TargetReport:
        return TargetReport(
            runtime_id=spec.runtime_id,
            runtime_version=spec.version,
            source=str(source.resolve()),
            source_sha256="a" * 64,
            status=status,
            parse_ok=True,
        )

    def test_cache_hit_and_checkpoint_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'ok'", encoding="utf-8")
            home = root / "home"
            manager = RuntimeManager(home)
            oci = OciRuntimeManager(home)
            options = RunOptions(psscriptanalyzer="off", pester="off")
            spec = RuntimeSpec(version="7.6.4")
            jobs = build_jobs(
                [source], [spec], options,
                tool_version="test",
                runtime_manager=manager,
                oci_manager=oci,
                tool_modules=[],
            )
            calls = []
            cache = ResultCache(root / "cache")
            checkpoint_path = root / "checkpoint.json"
            first = execute_jobs(
                jobs,
                lambda path, runtime: calls.append((path, runtime)) or self._target(path, runtime),
                cache=cache,
                cache_mode="auto",
                checkpoint=CheckpointStore(checkpoint_path),
                resume=False,
                jobs_count=2,
                fail_fast=False,
            )
            self.assertEqual(len(calls), 1)
            self.assertEqual(first.metadata["cache_stored"], 1)

            second = execute_jobs(
                jobs,
                lambda path, runtime: self.fail("cache should prevent execution"),
                cache=cache,
                cache_mode="auto",
                checkpoint=CheckpointStore(None),
                resume=False,
                jobs_count=1,
                fail_fast=False,
            )
            self.assertEqual(second.metadata["cache_hits"], 1)
            self.assertEqual(second.targets[0].cache["status"], "hit")

            resumed = execute_jobs(
                jobs,
                lambda path, runtime: self.fail("resume should prevent execution"),
                cache=None,
                cache_mode="off",
                checkpoint=CheckpointStore(checkpoint_path),
                resume=True,
                jobs_count=1,
                fail_fast=False,
            )
            self.assertEqual(resumed.metadata["resumed"], 1)
            self.assertEqual(resumed.targets[0].cache["status"], "resume")




    def test_checkpoint_writers_merge_stale_views(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'ok'", encoding="utf-8")
            spec = RuntimeSpec(version="7.6.4")
            path = root / "checkpoint.json"
            first = CheckpointStore(path)
            second = CheckpointStore(path)
            first.save("1" * 64, self._target(source, spec))
            second.save("2" * 64, self._target(source, spec))
            payload = json.loads(path.read_text())
            self.assertEqual(set(payload["records"]), {"1" * 64, "2" * 64})

    def test_cache_and_checkpoint_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'ok'", encoding="utf-8")
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4")
            jobs = build_jobs(
                [source], [spec], RunOptions(), tool_version="test",
                runtime_manager=manager, oci_manager=oci, tool_modules={}
            )
            report = self._target(source, spec)
            cache = ResultCache(root / "cache")
            cache.store(jobs[0].key, report, jobs[0].material)
            record_path = cache.record_path(jobs[0].key)
            payload = json.loads(record_path.read_text())
            payload["report"]["status"] = "FAIL_EXECUTION"
            record_path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertIsNone(cache.load(jobs[0].key))

            checkpoint_path = root / "checkpoint.json"
            checkpoint = CheckpointStore(checkpoint_path)
            checkpoint.save(jobs[0].key, report)
            payload = json.loads(checkpoint_path.read_text())
            payload["records"][jobs[0].key]["report"]["status"] = "FAIL_EXECUTION"
            checkpoint_path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertIsNone(CheckpointStore(checkpoint_path).load(jobs[0].key))

    def test_shard_identity_is_independent_of_checkout_and_runtime_install_state(self):
        with tempfile.TemporaryDirectory() as left_temp, tempfile.TemporaryDirectory() as right_temp:
            left = Path(left_temp)
            right = Path(right_temp)
            left_source = left / "sample.ps1"
            right_source = right / "sample.ps1"
            left_source.write_text("'same'", encoding="utf-8")
            right_source.write_text("'same'", encoding="utf-8")
            spec = RuntimeSpec(version="7.6.4")
            left_manager = RuntimeManager(left / "home")
            right_manager = RuntimeManager(right / "home")
            runtime_root = right_manager.runtime_root(spec)
            runtime_root.mkdir(parents=True)
            right_manager.executable_path(spec).write_text("binary", encoding="utf-8")
            right_manager.executable_path(spec).chmod(0o755)
            right_manager.metadata_path(spec).write_text(json.dumps({
                "runtime_id": spec.runtime_id, "version": spec.version,
                "sha256": "d" * 64, "installed_at": "different"
            }), encoding="utf-8")
            left_job = build_jobs(
                [left_source], [spec], RunOptions(), tool_version="test",
                runtime_manager=left_manager, oci_manager=OciRuntimeManager(left / "home"), tool_modules={}
            )[0]
            right_job = build_jobs(
                [right_source], [spec], RunOptions(), tool_version="test",
                runtime_manager=right_manager, oci_manager=OciRuntimeManager(right / "home"), tool_modules={}
            )[0]
            self.assertEqual(left_job.shard_key, right_job.shard_key)
            self.assertNotEqual(left_job.key, right_job.key)

    def test_failed_results_are_not_cached(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("throw 'x'", encoding="utf-8")
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4")
            jobs = build_jobs(
                [source], [spec], RunOptions(), tool_version="test",
                runtime_manager=manager, oci_manager=oci, tool_modules={}
            )
            cache = ResultCache(root / "cache")
            result = execute_jobs(
                jobs, lambda path, runtime: self._target(path, runtime, "FAIL_EXECUTION"),
                cache=cache, cache_mode="auto", checkpoint=CheckpointStore(None),
                resume=False, jobs_count=1, fail_fast=False,
            )
            self.assertEqual(result.metadata["cache_stored"], 0)
            self.assertEqual(cache.stats()["records"], 0)

    def test_resource_aware_worker_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = []
            for index in range(4):
                path = root / f"{index}.ps1"
                path.write_text(str(index), encoding="utf-8")
                files.append(path)
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4")
            jobs = build_jobs(
                files, [spec], RunOptions(), tool_version="test",
                runtime_manager=manager, oci_manager=oci, tool_modules={}
            )
            with patch("psmatrix.scheduler.available_memory_bytes", return_value=2048), patch("psmatrix.scheduler.os.cpu_count", return_value=8):
                result = execute_jobs(
                    jobs, lambda path, runtime: self._target(path, runtime),
                    cache=None, cache_mode="off", checkpoint=CheckpointStore(None),
                    resume=False, jobs_count=0, fail_fast=False, per_worker_memory_bytes=1024,
                )
            self.assertEqual(result.metadata["workers"], 2)
            self.assertEqual(result.metadata["memory_worker_limit"], 2)

    def test_shards_are_disjoint_and_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = []
            for index in range(7):
                path = root / f"{index}.ps1"
                path.write_text(str(index), encoding="utf-8")
                files.append(path)
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            specs = [RuntimeSpec(version="7.4.18"), RuntimeSpec(version="7.6.4")]
            options = RunOptions()
            all_keys = set()
            shard_keys = []
            for shard in range(3):
                jobs = build_jobs(
                    files, specs, options,
                    tool_version="test",
                    runtime_manager=manager,
                    oci_manager=oci,
                    tool_modules=[],
                    shard_index=shard,
                    shard_count=3,
                )
                keys = {job.key for job in jobs}
                self.assertFalse(all_keys & keys)
                all_keys |= keys
                shard_keys.append(keys)
            self.assertEqual(len(all_keys), len(files) * len(specs))

    def test_fail_fast_stops_queued_work(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = []
            for index in range(8):
                path = root / f"{index}.ps1"
                path.write_text(str(index), encoding="utf-8")
                files.append(path)
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4")
            jobs = build_jobs(
                files, [spec], RunOptions(), tool_version="test",
                runtime_manager=manager, oci_manager=oci, tool_modules=[]
            )
            count = 0
            def run(path, runtime):
                nonlocal count
                count += 1
                return self._target(path, runtime, "FAIL_EXECUTION" if count == 1 else "PASS")
            result = execute_jobs(
                jobs, run, cache=None, cache_mode="off",
                checkpoint=CheckpointStore(None), resume=False,
                jobs_count=1, fail_fast=True,
            )
            self.assertEqual(result.targets[0].status, "FAIL_EXECUTION")
            self.assertGreater(result.metadata["skipped_fail_fast"], 0)


class ExporterTests(unittest.TestCase):
    def _report(self, root: Path) -> MatrixReport:
        source = root / "sample.ps1"
        source.write_text("'ok'", encoding="utf-8")
        import hashlib
        target = TargetReport(
            runtime_id="powershell-7.6.4-linux-x64",
            runtime_version="7.6.4",
            source=str(source.resolve()),
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            status="PASS",
            parse_ok=True,
            cache={"status": "hit"},
        )
        return MatrixReport(
            schema=5,
            tool_version="0.test",
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
            status="PASS",
            targets=[target],
        )


    def test_evidence_rejects_source_changed_after_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = self._report(root)
            Path(report.targets[0].source).write_text("'changed'", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_evidence_bundle(report, root / "evidence.zip", project_root=root)

    def test_stable_diagnostics_are_not_duplicated_across_exporters(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "broken.ps1"
            source.write_text("function Broken {\n", encoding="utf-8")
            import hashlib
            target = TargetReport(
                runtime_id="powershell-7.6.4-linux-x64",
                runtime_version="7.6.4",
                source=str(source.resolve()),
                source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                status="FAIL_PARSE",
                parse_ok=False,
                parse_diagnostics=[ParseDiagnostic(message="missing brace", line=1, column=17)],
            )
            diagnostic = {
                "code": "PSMX1101", "stage": "parser", "severity": "error",
                "message": "missing brace", "runtime_id": target.runtime_id,
                "source": target.source, "line": 1, "column": 17,
                "repairability": "candidate",
            }
            report = MatrixReport(
                schema=6, tool_version="0.8.0",
                started_at="2026-01-01T00:00:00Z",
                finished_at="2026-01-01T00:00:01Z",
                status="FAIL", targets=[target], diagnostics=[diagnostic],
            )
            junit = root / "report.xml"
            sarif = root / "report.sarif"
            html = root / "report.html"
            write_junit(report, junit)
            write_sarif(report, sarif)
            write_html(report, html)
            results = json.loads(sarif.read_text())["runs"][0]["results"]
            self.assertEqual([item["ruleId"] for item in results], ["PSMX1101"])
            failure = ET.parse(junit).getroot().find(".//failure")
            self.assertIn("PSMX1101", failure.attrib["message"])
            self.assertIn("PSMX1101", html.read_text(encoding="utf-8"))

    def test_junit_sarif_html_and_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = self._report(root)
            junit = root / "report.xml"
            sarif = root / "report.sarif"
            html = root / "report.html"
            evidence = root / "evidence.zip"
            evidence_second = root / "evidence-second.zip"
            sbom = root / "sbom.json"
            write_junit(report, junit)
            write_sarif(report, sarif)
            write_html(report, html)
            write_sbom(report, sbom)
            write_evidence_bundle(report, evidence, project_root=root)
            write_evidence_bundle(report, evidence_second, project_root=root)
            self.assertEqual(ET.parse(junit).getroot().tag, "testsuite")
            self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
            self.assertIn("PSMatrix Report", html.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(sbom.read_text())["bomFormat"], "CycloneDX")
            self.assertEqual(evidence.read_bytes(), evidence_second.read_bytes())
            with zipfile.ZipFile(evidence) as archive:
                names = set(archive.namelist())
                self.assertIn("matrix-report.json", names)
                self.assertIn("provenance.json", names)
                self.assertIn("manifest.json", names)
                self.assertIn("sbom.cdx.json", names)
                self.assertTrue(any(name.startswith("sources/") for name in names))


class CacheCliTests(unittest.TestCase):
    def test_stats_prune_and_clear_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = ResultCache(root / "home" / "result-cache")
            source = root / "sample.ps1"
            source.write_text("'ok'", encoding="utf-8")
            report = TargetReport(
                runtime_id="powershell-7.6.4-linux-x64", runtime_version="7.6.4",
                source=str(source), source_sha256="c" * 64, status="PASS", parse_ok=True
            )
            cache.store("a" * 64, report, {"key": "value"})
            out = StringIO()
            with redirect_stdout(out):
                code = main(["--home", str(root / "home"), "cache", "stats"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["records"], 1)
            out = StringIO()
            with redirect_stdout(out):
                code = main(["--home", str(root / "home"), "cache", "prune", "--max-records", "0"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())["records"], 0)
            out = StringIO()
            with redirect_stdout(out):
                code = main(["--home", str(root / "home"), "cache", "clear"])
            self.assertEqual(code, 0)

class WorkerEnvironmentIsolationTests(unittest.TestCase):
    def test_worker_environment_excludes_parent_secrets_and_instrumentation(self):
        import os
        from psmatrix.scheduler import _worker_environment
        poisoned = {
            "CAAS_ARTIFACTORY_READER_PASSWORD": "secret",
            "PSMATRIX_OAUTH_CLIENT_SECRET": "oauth-secret",
            "PSMATRIX_LAB_PASSWORD_51": "lab-secret",
            "CUA_DD_INIT_ARTIFACT_TOOL_V2": "true",
            "PYTHONPATH": "src",
            "PSMATRIX_TEST_PWSH": "/safe/pwsh",
        }
        with patch.dict(os.environ, poisoned, clear=False):
            env = _worker_environment()
        self.assertNotIn("CAAS_ARTIFACTORY_READER_PASSWORD", env)
        self.assertNotIn("PSMATRIX_OAUTH_CLIENT_SECRET", env)
        self.assertNotIn("PSMATRIX_LAB_PASSWORD_51", env)
        self.assertNotIn("CUA_DD_INIT_ARTIFACT_TOOL_V2", env)
        self.assertEqual(env["PYTHONPATH"], "src")
        self.assertEqual(env["PSMATRIX_TEST_PWSH"], "/safe/pwsh")
        self.assertEqual(env["PYTHONUNBUFFERED"], "1")
