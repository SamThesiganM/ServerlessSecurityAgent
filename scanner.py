"""
scanner.py
Command-line interface (CLI) entry point for Serverless Function Security Auditor.
Coordinates Phase 1 (Secrets, IAM) and Phase 2 (AST Analysis, Events, Injections).
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Tuple

from models.finding import Finding, Severity
from scanners.secret_scanner import SecretScanner
from scanners.iam_scanner import IAMScanner
from scanners.event_scanner import EventScanner
from scanners.injection_scanner import InjectionScanner
from analyzers.ast_analyzer import ASTCodeAnalyzer


class AuditorCLI:
    """Orchestrates scanning across project files and generates unified security reports."""

    def __init__(self, target_path: Path):
        self.target_path = target_path
        self.secret_scanner = SecretScanner(start_id=1)
        self.iam_scanner = IAMScanner(start_id=1)
        self.event_scanner = EventScanner(start_id=1)
        self.injection_scanner = InjectionScanner(start_id=1)

    def collect_files(self) -> List[Path]:
        """Collect all relevant files to scan within the specified target path."""
        if not self.target_path.exists():
            print(f"[!] Error: Target path '{self.target_path}' does not exist.", file=sys.stderr)
            sys.exit(2)

        if self.target_path.is_file():
            return [self.target_path]

        collected: List[Path] = []
        for p in self.target_path.rglob("*"):
            if p.is_file() and not any(part.startswith(".") or part == "__pycache__" for part in p.parts):
                collected.append(p)
        return sorted(collected)

    def run_scan(self) -> List[Finding]:
        """Run all Phase 1 and Phase 2 scanners across collected files."""
        files = self.collect_files()
        raw_findings: List[Finding] = []

        for file_path in files:
            # 1. AWS IAM Policy JSON Scanner (Phase 1)
            if self.iam_scanner.is_policy_file(file_path):
                iam_findings = self.iam_scanner.scan_file(file_path)
                raw_findings.extend(iam_findings)

            # 2. Hardcoded Secret Scanner for supported source files (Phase 1)
            if self.secret_scanner.is_supported_file(file_path):
                if not (file_path.suffix.lower() == ".json" and self.iam_scanner.is_policy_file(file_path)):
                    secret_findings = self.secret_scanner.scan_file(file_path)
                    raw_findings.extend(secret_findings)

            # 3. Python AST Analysis: Events & Injections (Phase 2)
            if file_path.suffix.lower() == ".py":
                analyzer = ASTCodeAnalyzer(file_path)
                parsed = analyzer.analyze()

                if not parsed:
                    err_desc = analyzer.syntax_error or "Unknown parsing error."
                    raw_findings.append(
                        Finding(
                            id="ERR-000",
                            type="PARSING_ERROR",
                            severity=Severity.LOW,
                            file=str(file_path),
                            line=analyzer.error_line,
                            title="Python AST Parsing Error",
                            description=f"Could not parse Python source file: {err_desc}",
                            recommendation="Check the Python file for syntax errors or unsupported encoding."
                        )
                    )
                else:
                    event_findings = self.event_scanner.scan_analyzer(analyzer)
                    raw_findings.extend(event_findings)

                    inj_findings = self.injection_scanner.scan_analyzer(analyzer)
                    raw_findings.extend(inj_findings)

        # Sort findings by severity (CRITICAL first, then HIGH, MEDIUM, LOW)
        severity_rank = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3
        }
        raw_findings.sort(key=lambda f: (severity_rank.get(f.severity, 4), f.file, f.line or 0))

        # Renumber findings sequentially as [SEC-001], [SEC-002], etc. for uniform presentation
        unified_findings: List[Finding] = []
        for idx, finding in enumerate(raw_findings, start=1):
            finding.id = f"SEC-{idx:03d}"
            unified_findings.append(finding)

        return unified_findings

    @staticmethod
    def count_severities(findings: List[Finding]) -> Tuple[int, int, int, int]:
        """Compute summary counts for each severity tier."""
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        return crit, high, med, low

    def print_text_report(self, findings: List[Finding]):
        """Render a clean, human-readable terminal report."""
        crit, high, med, low = self.count_severities(findings)
        total = len(findings)

        print("=" * 60)
        print("SERVERLESS SECURITY AUDITOR")
        print("=" * 60)
        print()
        print(f"Project: {self.target_path.as_posix()}")
        print()
        print("Summary")
        print("-------")
        print(f"Critical: {crit}")
        print(f"High:     {high}")
        print(f"Medium:   {med}")
        print(f"Low:      {low}")
        print(f"Total:    {total}")
        print()

        if not findings:
            print("-" * 60)
            print("[+] Scan completed. No security issues detected!")
            print("-" * 60)
            return

        print("Findings")
        print("--------")

        for finding in findings:
            rel_file = Path(finding.file).as_posix()
            try:
                rel_file = Path(finding.file).resolve().relative_to(Path.cwd().resolve()).as_posix()
            except ValueError:
                pass

            print("-" * 60)
            print(f"[{finding.id}] {finding.severity.value} - {finding.title}")
            print(f"Type: {finding.type}")
            print(f"File: {rel_file}")

            if finding.line is not None:
                print(f"Line: {finding.line}")
            if finding.statement_id is not None:
                print(f"Statement: {finding.statement_id}")

            print()
            print("Description:")
            print(finding.description)
            print()
            print("Recommendation:")
            print(finding.recommendation)

        print("-" * 60)

    def print_json_report(self, findings: List[Finding]):
        """Export findings and summary in JSON format."""
        crit, high, med, low = self.count_severities(findings)
        output = {
            "project": str(self.target_path),
            "summary": {
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "total": len(findings)
            },
            "findings": [f.to_dict() for f in findings]
        }
        print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Serverless Function Security Auditor - Static Analysis CLI Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py demo
  python scanner.py path/to/serverless-project
  python scanner.py demo --format json
  python scanner.py demo --strict
        """
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="demo",
        help="Directory or file to audit (defaults to 'demo')"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output report format (default: text)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail with exit code 1 if critical or high vulnerabilities are detected (useful for blocking CI gates on production code)"
    )

    args = parser.parse_args()

    target_path = Path(args.target)
    cli = AuditorCLI(target_path=target_path)
    findings = cli.run_scan()

    if args.format == "json":
        cli.print_json_report(findings)
    else:
        cli.print_text_report(findings)

    # In strict mode, fail the process if critical or high vulnerabilities are detected.
    # In default reporting/advisory mode, exit 0 to indicate the audit executed successfully.
    if args.strict:
        crit, high, _, _ = cli.count_severities(findings)
        if crit > 0 or high > 0:
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
