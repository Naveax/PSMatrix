import unittest

from psmatrix.runner import ScriptRunner


class AnalyzerPolicyTests(unittest.TestCase):
    def test_required_mode_fails_when_unavailable(self):
        message = ScriptRunner._analyzer_failure(
            {"status": "unavailable"}, mode="required", fail_on="error"
        )
        self.assertIn("required", message)

    def test_auto_mode_allows_unavailable_analyzer(self):
        self.assertIsNone(
            ScriptRunner._analyzer_failure(
                {"status": "unavailable"}, mode="auto", fail_on="error"
            )
        )

    def test_severity_threshold(self):
        analyzer = {
            "status": "completed",
            "diagnostics": [
                {"severity": "Warning"},
                {"severity": "Error"},
            ],
        }
        self.assertIn(
            "error=1",
            ScriptRunner._analyzer_failure(analyzer, mode="auto", fail_on="error"),
        )
        warning_message = ScriptRunner._analyzer_failure(
            analyzer, mode="auto", fail_on="warning"
        )
        self.assertIn("warning=1", warning_message)
        self.assertIsNone(
            ScriptRunner._analyzer_failure(analyzer, mode="auto", fail_on="none")
        )


if __name__ == "__main__":
    unittest.main()
