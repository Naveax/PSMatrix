from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_BASE_PATH = Path(__file__).with_name(
    "_final_immutable_release_publication_operator_base.py"
)


def _load_base():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_immutable_release_publication_operator_test_base",
        _BASE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load immutable publication operator test base")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_base = _load_base()


class FinalImmutableReleasePublicationOperatorTests(
    _base.FinalImmutableReleasePublicationOperatorTests
):
    def test_source_forbids_clobber_and_freezes_current_api_repository_and_contract(self) -> None:
        public = _base.SCRIPT
        impl = public.with_name("_publish_final_immutable_release_impl.py")
        text = public.read_text(encoding="utf-8") + "\n" + impl.read_text(encoding="utf-8")
        self.assertIn('API_VERSION = "2026-03-10"', text)
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn("final-immutable-release-publication-contract.json", text)
        self.assertIn("verify_protected_final_release_bundle.py", text)
        self.assertIn("immutable-releases", text)
        self.assertIn('method="DELETE"', text)
        self.assertIn("--draft=false", text)
        self.assertIn("_verify_remote_assets", text)
        self.assertIn("_rollback_pre_publish", text)
        self.assertIn("_verify_published_remote", text)
        self.assertIn("publication_receipt_output_reserved_before_mutation", text)
        self.assertNotIn("--clobber", text)
        self.assertNotIn("shell=True", text)


if __name__ == "__main__":
    unittest.main()
