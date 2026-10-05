from pathlib import Path
import json
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
NEW_FINAL = "43922a5544745c64165df4aedd9c57391bfe6c51"
NEW_SOURCE = "final/2.0.0-release-candidate-anchor-v2"
NEW_CONTROL = "release/2.0.0-final-lock-control-v2"
NEW_ACTIVE = "release/2.0.0-final-active-lock-v2"
OLD_FINAL = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


class FinalV2ReleaseControlMigrationTests(unittest.TestCase):
    def test_lock_signing_contract_targets_v2_final_source(self):
        value = json.loads((ROOT / "ga-packs/03-authoritative-windows/final-release-lock-signing-control-contract.json").read_text(encoding="utf-8"))
        self.assertEqual(value["final_release_commit"], NEW_FINAL)
        self.assertEqual(value["final_release_source_branch"], NEW_SOURCE)
        safety = value["safety"]
        self.assertTrue(safety["fresh_final_windows_certification_required_after_signing"])
        self.assertFalse(safety["legacy_rc4_campaign_rebind_allowed"])

    def test_human_and_lock_routes_use_v2_candidate_and_control_branches(self):
        paths = (
            ".github/workflows/ops-final-human-approval-promotion-dispatch.yml",
            ".github/workflows/ops-final-lock-review-human-gate.yml",
            ".github/workflows/ops-final-promotion-to-reviewed-pr.yml",
            ".github/workflows/ops-final-reviewed-lock-merge-to-signing.yml",
            ".github/workflows/ops-rc4-closure-to-final-lock-review.yml",
        )
        for relative in paths:
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn(OLD_FINAL, text, relative)
            self.assertIn(NEW_FINAL, text, relative)
            self.assertIn(NEW_CONTROL, text, relative)
        closure = (ROOT / ".github/workflows/ops-rc4-closure-to-final-lock-review.yml").read_text(encoding="utf-8")
        self.assertIn(NEW_SOURCE, closure)
        merge = (ROOT / ".github/workflows/ops-final-reviewed-lock-merge-to-signing.yml").read_text(encoding="utf-8")
        self.assertIn(NEW_ACTIVE, merge)

    def test_post_signing_is_fail_closed_until_fresh_windows_certification_controls_exist(self):
        text = (ROOT / ".github/workflows/ops-final-signing-to-rebind-and-security-review.yml").read_text(encoding="utf-8")
        self.assertIn(NEW_ACTIVE, text)
        self.assertIn("fresh_final_windows_certification_required=true", text)
        self.assertIn("legacy_rc4_campaign_rebind_allowed=false", text)
        self.assertIn("legacy_final_windows_rebind_dispatched=false", text)
        self.assertIn("downstream_v2_evidence_controls_ready=false", text)
        self.assertNotIn("gh workflow run ga-windows-authority-final-windows-evidence-rebind.yml", text)
        self.assertNotIn("gh workflow run ga-final-security-review-packet.yml", text)

    def test_control_source_changed_path_closure_is_exact(self):
        contract = json.loads(
            (ROOT / "ga-packs/03-authoritative-windows/final-release-lock-signing-control-contract.json").read_text(
                encoding="utf-8"
            )
        )
        changed = sorted(
            line.strip().replace("\\", "/")
            for line in subprocess.check_output(
                ["git", "diff", "--name-only", NEW_FINAL],
                cwd=ROOT,
                text=True,
            ).splitlines()
            if line.strip()
        )
        allowed = sorted(contract["control_source"]["changed_path_allowlist"])
        self.assertEqual(changed, allowed)
        self.assertEqual(len(changed), 49)
        self.assertIn(".github/workflows/ci.yml", allowed)
        self.assertIn(".github/workflows/ga-final-production-bootstrap-source-preflight.yml", allowed)
        self.assertIn(".github/workflows/ga-windows-authority-final-release-source-preflight.yml", allowed)
        self.assertIn("ga-packs/03-authoritative-windows/final-production-bootstrap-contract.json", allowed)
        self.assertIn("tests/test_ci_exact_event_sha_checkout.py", allowed)
        self.assertIn("tests/test_final_production_bootstrap_contract.py", allowed)
        self.assertIn(".github/workflows/ops-windows-lab-prereq-audit.yml", allowed)
        self.assertIn("scripts/ga/Invoke-WindowsLabOperationalEnvironmentProvisioning.ps1", allowed)
        self.assertIn("tests/test_windows_lab_operational_provisioning.py", allowed)
        self.assertIn(".github/workflows/ga-windows-authority-rc4-release-lock-promotion.yml", allowed)
        self.assertIn(".github/workflows/ga-windows-authority-rc4-release-intake-selfhosted.yml", allowed)
        self.assertIn(".github/workflows/ops-rc4-promotion-to-reviewed-pr.yml", allowed)
        self.assertIn(".github/workflows/ops-rc4-reviewed-lock-merge-to-signing.yml", allowed)
        self.assertIn(".github/workflows/ops-external22-ready-to-fresh-readiness.yml", allowed)
        self.assertIn(".github/workflows/ops-fresh-readiness-to-external-evidence.yml", allowed)
        self.assertIn(".github/workflows/ops-rc4-signing-to-intake.yml", allowed)
        self.assertIn(".github/workflows/ops-rc4-intake-to-media-readiness.yml", allowed)
        self.assertIn(".github/workflows/ops-rc4-post-intake-canonical-chain.yml", allowed)
        self.assertIn(".github/workflows/ga-windows-authority-rc4-media-readiness-selfhosted.yml", allowed)
        self.assertIn("scripts/ga/Get-PSMatrixWindowsAuthorityMediaInventory.ps1", allowed)
        self.assertIn("tests/test_windows_authority_media_inventory.py", allowed)
        self.assertIn("ga-packs/03-authoritative-windows/rc4-release-lock.json", allowed)
        self.assertIn("release-assets/2.0.0rc4/psmatrix-2.0.0rc4-release-public.pem", allowed)
        self.assertIn("tests/test_windows_authority_rc4_lock_promotion_signing.py", allowed)
        self.assertFalse(any(path.startswith("src/psmatrix/") for path in changed))

    def test_rc4_intake_bundle_inventory_excludes_its_own_manifest(self):
        text = (ROOT / ".github/workflows/ga-windows-authority-rc4-release-intake-selfhosted.yml").read_text(encoding="utf-8")
        self.assertIn("path.name != inventory_path.name", text)
        self.assertIn("path.name == inventory_path.name", text)
        self.assertIn("if set(expected) != actual_names:", text)
        self.assertIn("digest, size = expected[path.name]", text)

    def test_rc4_suppressed_router_recovery_chain_is_explicit_and_fail_closed(self):
        paths = {
            ".github/workflows/ops-rc4-signing-to-intake.yml": ("recover_signing_run_id", "repaired_workflow=$RECOVERY_MODE"),
            ".github/workflows/ops-rc4-intake-to-media-readiness.yml": ("recover_intake_run_id", "rc4_repaired_intake_recovery=PASS"),
            ".github/workflows/ops-rc4-post-intake-canonical-chain.yml": ("recover_completed_run_id", "rc4_stage_workflow_run_recovery=PASS"),
            ".github/workflows/ops-rc4-closure-to-final-lock-review.yml": ("recover_completed_run_id", "rc4_to_final_workflow_run_recovery=PASS"),
        }
        for relative, markers in paths.items():
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("workflow_dispatch:", text, relative)
            self.assertIn("github.actor == 'Naveax'", text, relative)
            self.assertIn("github.triggering_actor == 'Naveax'", text, relative)
            self.assertIn("RECOVERY_MODE", text, relative)
            self.assertIn("github-actions[bot]", text, relative)
            for marker in markers:
                self.assertIn(marker, text, relative)
        signing = (ROOT / ".github/workflows/ops-rc4-signing-to-intake.yml").read_text(encoding="utf-8")
        self.assertIn("dispatch_ref='main'", signing)
        self.assertIn('.conclusion == \\"success\\"', signing)
        intake = (ROOT / ".github/workflows/ops-rc4-intake-to-media-readiness.yml").read_text(encoding="utf-8")
        self.assertIn("windows-authority-rc4-protected-release-intake", intake)
        self.assertIn("signing_control_head", intake)
        self.assertIn("path.name != inventory_path.name", intake)
        self.assertIn("path.name == inventory_path.name", intake)
        post_intake = (ROOT / ".github/workflows/ops-rc4-post-intake-canonical-chain.yml").read_text(encoding="utf-8")
        self.assertIn('if has("authoritative") then .authoritative else true end', post_intake)
        self.assertIn('if has("ga_eligible") then .ga_eligible else true end', post_intake)
        self.assertNotIn(".authoritative // true", post_intake)
        self.assertNotIn(".ga_eligible // true", post_intake)

    def test_rc4_media_blocked_state_can_be_superseded_by_a_new_successful_run(self):
        text = (ROOT / ".github/workflows/ops-rc4-post-intake-canonical-chain.yml").read_text(encoding="utf-8")
        self.assertIn("if stage_exists media_readiness; then", text)
        self.assertIn("rc4_chain_previous_blocked_state_supersedable=true", text)
        self.assertNotIn("stage_exists media_readiness || stage_exists media_readiness_blocked", text)
        self.assertIn("record_state_once media_readiness_blocked", text)
        self.assertIn("record_state_once media_readiness", text)

    def test_rc4_media_iso_inventory_repair_is_explicit_and_frozen_control_bound(self):
        inventory = (ROOT / "scripts/ga/Get-PSMatrixWindowsAuthorityMediaInventory.ps1").read_text(encoding="utf-8")
        self.assertIn("function Get-DismWimField", inventory)
        self.assertIn("& dism.exe", inventory)
        self.assertIn("/English", inventory)
        self.assertIn("('/Index:{0}' -f $index)", inventory)
        self.assertIn("Out-Null", inventory)
        self.assertNotIn("version = [string]$_.Version", inventory)

        media = (ROOT / ".github/workflows/ga-windows-authority-rc4-media-readiness-selfhosted.yml").read_text(encoding="utf-8")
        for marker in (
            "repair_from_main:",
            "REPAIR_FROM_MAIN:",
            "FROZEN_CONTROL_BRANCH: release/2.0.0rc4-active-lock",
            "repaired_rc4_media_control_binding=PASS",
            "workflow_code_recovery",
            "workflow_code_head",
        ):
            self.assertIn(marker, media)
        self.assertIn(
            'contents/${relative}?ref=$env:CONTROL_HEAD',
            media,
        )
        self.assertNotIn('contents/$relative?ref=$env:CONTROL_HEAD', media)

        intake_router = (ROOT / ".github/workflows/ops-rc4-intake-to-media-readiness.yml").read_text(encoding="utf-8")
        for marker in (
            "recover_media_control_head:",
            "dispatch-repaired-media:",
            "repaired_media_dispatch_guard=PASS",
            "-f repair_from_main=true",
        ):
            self.assertIn(marker, intake_router)
        self.assertIn("CONTROL_HEAD: ${{ inputs.recover_media_control_head }}", intake_router)
        self.assertIn("GH_TOKEN: ${{ github.token }}", intake_router)
        self.assertNotIn("\\${{", intake_router)

        post_router = (ROOT / ".github/workflows/ops-rc4-post-intake-canonical-chain.yml").read_text(encoding="utf-8")
        for marker in (
            "REPAIRED_MEDIA_MODE",
            "repaired_rc4_media_stage_recovery=PASS",
            "workflow_code_recovery",
            "workflow_code_head",
        ):
            self.assertIn(marker, post_router)

    def test_critical_paginated_gh_api_calls_are_cli_compatible(self):
        paths = (
            ".github/workflows/ops-rc4-promotion-to-reviewed-pr.yml",
            ".github/workflows/ops-rc4-reviewed-lock-merge-to-signing.yml",
            ".github/workflows/ops-final-promotion-to-reviewed-pr.yml",
            ".github/workflows/ops-final-reviewed-lock-merge-to-signing.yml",
            ".github/workflows/ops-external22-ready-to-fresh-readiness.yml",
            ".github/workflows/ops-fresh-readiness-to-external-evidence.yml",
        )
        for relative in paths:
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"gh api --paginate --slurp [^\\n]* --jq", relative)
            self.assertIn("| jq -c 'add'", text, relative)

    def test_source_preflight_targets_v2_source_branch(self):
        text = (ROOT / ".github/workflows/ga-windows-authority-final-release-lock-signing-source-preflight.yml").read_text(encoding="utf-8")
        self.assertIn('branches: ["final/2.0.0-release-candidate-anchor-v2"]', text)
        self.assertIn('.github/workflows/ga-final-production-bootstrap-source-preflight.yml', text)
        self.assertIn("v2 control closure", text)


if __name__ == "__main__":
    unittest.main()
