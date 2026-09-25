"""
tests/test_iam.py
Unit tests for IAMScanner wildcard detection, least-privilege checks, and error handling.
"""

import json
import tempfile
import unittest
from pathlib import Path

from models.finding import Severity
from scanners.iam_scanner import IAMScanner


class TestIAMScanner(unittest.TestCase):
    """Test suite for IAMScanner."""

    def setUp(self):
        self.scanner = IAMScanner()

    def _create_temp_policy(self, data: dict) -> Path:
        """Helper to create a temporary JSON policy file."""
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, tmp)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return Path(tmp.name)

    def test_detect_full_admin_wildcard(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AdminAccess",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        path = self._create_temp_policy(policy)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("Full Administrator Access", findings[0].title)

    def test_detect_iam_privilege_escalation(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ManageIAM",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "arn:aws:iam::123456789012:role/*"
                }
            ]
        }
        path = self._create_temp_policy(policy)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("iam:*", findings[0].title)

    def test_detect_s3_and_dynamodb_wildcards(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "StorageAccess",
                    "Effect": "Allow",
                    "Action": ["s3:*", "dynamodb:*"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }
        path = self._create_temp_policy(policy)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 2)
        severities = [f.severity for f in findings]
        self.assertEqual(severities, [Severity.HIGH, Severity.HIGH])

    def test_safe_least_privilege_policy(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOnlyS3",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }
        path = self._create_temp_policy(policy)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 0)

    def test_deny_statements_not_flagged(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyAllExceptSpecific",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        path = self._create_temp_policy(policy)
        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 0)

    def test_invalid_json_handled_gracefully(self):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        tmp.write("{ invalid_json: true, ")
        tmp.close()
        path = Path(tmp.name)
        self.addCleanup(lambda: path.unlink(missing_ok=True))

        findings = self.scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "POLICY_SYNTAX_ERROR")
        self.assertEqual(findings[0].severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()
