import base64
import unittest

from psmatrix.models import ExecutionResult
from psmatrix.redaction import SecretRedactor


class RedactionTests(unittest.TestCase):
    def test_raw_base64_hex_and_nested_values_are_redacted(self):
        secret = "PSMATRIX-SECRET-123456"
        redactor = SecretRedactor([secret])
        payload = {
            "raw": f"before:{secret}:after",
            "base64": base64.b64encode(secret.encode()).decode(),
            "hex": secret.encode().hex(),
            "nested": [secret],
        }
        sanitized = redactor.value(payload)
        self.assertFalse(redactor.contains_secret(sanitized))
        self.assertIn("<PSMATRIX_REDACTED>", str(sanitized))

    def test_execution_streams_are_redacted(self):
        secret = "sensitive-value"
        result = ExecutionResult(["x"], ".", 0, False, 1, secret, secret)
        sanitized = SecretRedactor([secret]).execution(result)
        self.assertNotIn(secret, sanitized.stdout + sanitized.stderr)


if __name__ == "__main__":
    unittest.main()
