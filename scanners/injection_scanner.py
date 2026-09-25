"""
scanners/injection_scanner.py
Scanner for detecting potential Command Injection, SQL Injection, and
Unsafe Input Handling in Python serverless functions using AST taint tracking.
"""

from pathlib import Path
from typing import List
from models.finding import Finding, Severity
from analyzers.ast_analyzer import ASTCodeAnalyzer, SinkCall


class InjectionScanner:
    """
    Evaluates discovered sinks against tainted data flow.
    Flags potential vulnerabilities where external event inputs reach sensitive operations.
    """

    def __init__(self, start_id: int = 1):
        self.finding_counter = start_id

    def scan_analyzer(self, analyzer: ASTCodeAnalyzer) -> List[Finding]:
        """
        Evaluate sink calls from an ASTCodeAnalyzer and emit structured findings.
        """
        findings: List[Finding] = []

        for sink in analyzer.sinks:
            finding_id = f"INJ-{self.finding_counter:03d}"
            self.finding_counter += 1

            tainted_summary = ", ".join(f"'{arg}'" for arg in sink.tainted_args)

            if sink.sink_type == "COMMAND":
                findings.append(
                    Finding(
                        id=finding_id,
                        type="COMMAND_INJECTION",
                        severity=Severity.CRITICAL,
                        file=sink.file,
                        line=sink.line,
                        title="Potential command injection",
                        description=(
                            f"Externally controlled input ({tainted_summary}) appears to reach "
                            f"an operating-system command execution sink '{sink.sink_name}()'. "
                            "An attacker providing malicious input could execute arbitrary shell commands."
                        ),
                        recommendation=(
                            "Avoid constructing shell commands from external input. Use safe APIs "
                            "(e.g., subprocess.run with arguments passed as a list and shell=False), "
                            "and validate input strictly against an allowlist."
                        )
                    )
                )

            elif sink.sink_type == "SQL":
                findings.append(
                    Finding(
                        id=finding_id,
                        type="SQL_INJECTION",
                        severity=Severity.HIGH,
                        file=sink.file,
                        line=sink.line,
                        title="Potential SQL injection",
                        description=(
                            f"Externally controlled input ({tainted_summary}) appears to reach "
                            f"a SQL query executed by '{sink.sink_name}()' through dynamic string construction. "
                            "This may allow an attacker to bypass authentication or access unauthorized data."
                        ),
                        recommendation=(
                            "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) "
                            "rather than string formatting. Validate input and perform manual review."
                        )
                    )
                )

            elif sink.sink_type == "FILE":
                findings.append(
                    Finding(
                        id=finding_id,
                        type="UNSAFE_INPUT",
                        severity=Severity.MEDIUM,
                        file=sink.file,
                        line=sink.line,
                        title="Potential unsafe external input handling",
                        description=(
                            f"Externally controlled input ({tainted_summary}) reaches a filesystem "
                            f"operation '{sink.sink_name}()'. An attacker might manipulate paths to access "
                            "unauthorized files (Path Traversal)."
                        ),
                        recommendation=(
                            "Validate and constrain externally controlled input before using it in file, "
                            "database, command, or other sensitive operations. Use os.path.basename or "
                            "pathlib to ensure files remain in an intended directory."
                        )
                    )
                )

        return findings

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a Python file directly for injection vulnerabilities."""
        analyzer = ASTCodeAnalyzer(file_path)
        if not analyzer.analyze():
            return []
        return self.scan_analyzer(analyzer)
