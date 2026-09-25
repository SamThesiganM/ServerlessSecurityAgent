"""
scanners/event_scanner.py
Scanner that identifies external serverless event inputs and entry points.
Uses ASTCodeAnalyzer to discover where untrusted data enters the function.
"""

from pathlib import Path
from typing import List
from models.finding import Finding, Severity
from analyzers.ast_analyzer import ASTCodeAnalyzer


class EventScanner:
    """
    Scans Python serverless functions for external input sources
    such as event dictionaries, request objects, and parameter lookups.
    """

    def __init__(self, start_id: int = 1):
        self.finding_counter = start_id

    def scan_analyzer(self, analyzer: ASTCodeAnalyzer) -> List[Finding]:
        """
        Generate informational findings for external input sources
        discovered by the ASTCodeAnalyzer.
        """
        findings: List[Finding] = []

        for source in analyzer.sources:
            finding_id = f"EVT-{self.finding_counter:03d}"
            self.finding_counter += 1

            var_desc = f"stored in variable '{source.variable_name}'" if source.variable_name else "accessed directly"
            findings.append(
                Finding(
                    id=finding_id,
                    type="SERVERLESS_EVENT_INPUT",
                    severity=Severity.LOW,
                    file=source.file,
                    line=source.line,
                    title="External serverless event input",
                    description=(
                        f"Data is obtained directly from the serverless event ({source.expression_text}) "
                        f"and {var_desc}. Externally controlled data must be treated as untrusted."
                    ),
                    recommendation=(
                        "Validate and sanitize externally controlled input against an allowlist "
                        "before using it in sensitive operations (e.g., database queries, system commands)."
                    )
                )
            )

        return findings

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a Python file directly for event input sources."""
        analyzer = ASTCodeAnalyzer(file_path)
        if not analyzer.analyze():
            return []
        return self.scan_analyzer(analyzer)
