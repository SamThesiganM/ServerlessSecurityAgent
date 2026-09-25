"""
tests/test_secrets.py
Unit tests for SecretScanner detection accuracy and false-positive suppression.
"""

import tempfile
import unittest
from pathlib import Path

from models.finding import Severity
from scanners.secret_scanner import SecretScanner


class TestSecretScanner(unittest.TestCase):
    """Test suite for SecretScanner."""

    def setUp(self):
        self.scanner = SecretScanner()

    def _create_temp_file(self, content: str, suffix: str = ".py") -> Path:
        """Helper to create a temporary test file."""
        tmp = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return Path(tmp.name)

    def test_detect_hardcoded_api_key(self):
        code = 'API_KEY = "test123secretkey"'
        path = self._create_temp_file(code)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].line, 1)
        self.assertIn("API Key", findings[0].title)

    def test_detect_hardcoded_password(self):
        code = 'PASSWORD = "mypassword123"'
        path = self._create_temp_file(code)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].line, 1)

    def test_detect_aws_credentials(self):
        code = (
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        )
        path = self._create_temp_file(code)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 2)
        severities = {f.severity for f in findings}
        self.assertEqual(severities, {Severity.CRITICAL})

    def test_detect_bearer_token(self):
        code = 'header = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}'
        path = self._create_temp_file(code)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_safe_env_variable_not_flagged(self):
        code = (
            'import os\n'
            'api_key = os.environ.get("API_KEY")\n'
            'password = os.getenv("DB_PASSWORD")\n'
            'has_password = True\n'
            'def verify_password(password, input_hash):\n'
            '    return True\n'
        )
        path = self._create_temp_file(code)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 0)

    def test_placeholder_suppression(self):
        code = (
            'API_KEY = "your_key_here"\n'
            'PASSWORD = "change_me"\n'
        )
        path = self._create_temp_file(code)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 0)

    def test_unsupported_extension_skipped(self):
        path = self._create_temp_file('API_KEY = "test123secret"', suffix=".png")
        self.assertFalse(self.scanner.is_supported_file(path))

    def test_nonexistent_file_returns_empty(self):
        path = Path("non_existent_file_12345.py")
        findings = self.scanner.scan_file(path)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
