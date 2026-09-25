"""
tests/test_event.py
Unit tests for event source detection (Phase 2.2).
"""

import tempfile
import unittest
from pathlib import Path

from analyzers.ast_analyzer import ASTCodeAnalyzer
from scanners.event_scanner import EventScanner
from models.finding import Severity


class TestEventScanner(unittest.TestCase):
    """Test suite for serverless event input detection."""

    def setUp(self):
        self.scanner = EventScanner()

    def _analyze_snippet(self, code: str) -> list:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
        tmp.write(code)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))

        analyzer = ASTCodeAnalyzer(tmp.name)
        self.assertTrue(analyzer.analyze())
        return self.scanner.scan_analyzer(analyzer)

    def test_detect_subscript_event(self):
        code = """
def handler(event, context):
    user = event["username"]
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "SERVERLESS_EVENT_INPUT")
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertEqual(findings[0].line, 3)
        self.assertIn("username", findings[0].description)

    def test_detect_get_method_event(self):
        code = """
def handler(event, context):
    cmd = event.get("command")
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertIn("command", findings[0].description)

    def test_detect_request_object(self):
        code = """
def handler(request):
    val = request.args["filter"]
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertIn("request", findings[0].description)

    def test_harmless_dict_not_flagged(self):
        code = """
def handler():
    config = {"timeout": 30}
    val = config["timeout"]
    calc = 10 + 20
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
