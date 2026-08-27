import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
VALIDATION = ROOT / "VALIDATION.md"
ROADMAP = ROOT / "ROADMAP.md"
PYPROJECT = ROOT / "pyproject.toml"


class CurrentDocumentationBoundaryTests(unittest.TestCase):
    def test_active_documentation_tracks_source_version_without_claiming_ga(self) -> None:
        pyproject = PYPROJECT.read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
        self.assertIsNotNone(match)
        version = match.group(1)

        readme = README.read_text(encoding="utf-8")
        validation = VALIDATION.read_text(encoding="utf-8")
        normalized_readme = " ".join(readme.split())
        normalized_validation = " ".join(validation.split())
        self.assertIn(f"Current milestone: {version} Production GA closure", readme)
        self.assertIn(f"psmatrix-{version}-py3-none-any.whl", readme)
        self.assertIn(f"PSMatrix {version} Production GA gate validation", validation)
        self.assertNotIn("psmatrix-2.0.0rc2", readme)
        self.assertIn(
            "version string alone is not a Production GA declaration",
            normalized_readme,
        )
        self.assertIn("It does not declare Production GA", normalized_validation)

    def test_live_boundary_points_to_canonical_machine_and_human_gates(self) -> None:
        readme = README.read_text(encoding="utf-8")
        roadmap = ROADMAP.read_text(encoding="utf-8")
        self.assertIn("issue #260", readme)
        self.assertIn("GA_PACKS.md", readme)
        self.assertIn("authoritative Windows", readme)
        self.assertIn("complete 25-target", readme)
        self.assertIn("independent review", readme)
        self.assertIn("final signing", readme)
        self.assertIn("M2.0 — Production GA gate — active closure", roadmap)
        self.assertIn("explicit owner approval in issue #260", roadmap)
        self.assertNotIn("M2.0 — Production GA gate — next", roadmap)


if __name__ == "__main__":
    unittest.main()
