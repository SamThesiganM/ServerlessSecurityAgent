"""
tests/test_injection.py
Unit tests for SQL injection, command injection, and unsafe input handling (Phase 2.3 - 2.7).
"""

import tempfile
import unittest
from pathlib import Path

from analyzers.ast_analyzer import ASTCodeAnalyzer
from scanners.injection_scanner import InjectionScanner
from models.finding import Severity


class TestInjectionScanner(unittest.TestCase):
    """Test suite for injection vulnerability detection and taint tracking."""

    def setUp(self):
        self.scanner = InjectionScanner()

    def _analyze_snippet(self, code: str) -> list:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
        tmp.write(code)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))

        analyzer = ASTCodeAnalyzer(tmp.name)
        if not analyzer.analyze():
            return []
        return self.scanner.scan_analyzer(analyzer)

    def test_sql_injection_string_concat(self):
        code = """
def handler(event, context):
    user_id = event["id"]
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "SQL_INJECTION")
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].line, 5)

    def test_sql_injection_fstring(self):
        code = """
def handler(event, context):
    username = event.get("username")
    query = f"SELECT * FROM users WHERE name='{username}'"
    cursor.execute(query)
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "SQL_INJECTION")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_safe_parameterized_sql_query(self):
        code = """
def handler(event, context):
    user_id = event["id"]
    # Parameterized query: safely handled by database driver
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 0)

    def test_command_injection_os_system(self):
        code = """
import os
def handler(event, context):
    host = event["host"]
    command = "ping " + host
    os.system(command)
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "COMMAND_INJECTION")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].line, 6)

    def test_command_injection_subprocess(self):
        code = """
import subprocess
def handler(event, context):
    target = event.get("target")
    subprocess.run("nslookup " + target, shell=True)
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "COMMAND_INJECTION")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_safe_subprocess_without_shell(self):
        code = """
import subprocess
def handler(event, context):
    subprocess.run(["ping", "-c", "1", "127.0.0.1"])
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 0)

    def test_unsafe_file_handling(self):
        code = """
def handler(event, context):
    filename = event["file"]
    open("/tmp/" + filename)
"""
        findings = self._analyze_snippet(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "UNSAFE_INPUT")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_invalid_syntax_handled_gracefully(self):
        analyzer = ASTCodeAnalyzer("broken.py")
        success = analyzer.analyze("def broken_syntax( {")
        self.assertFalse(success)
        self.assertIsNotNone(analyzer.syntax_error)
        self.assertIn("Invalid Python syntax", analyzer.syntax_error)


if __name__ == "__main__":
    unittest.main()
