"""
scanners/secret_scanner.py
Scanner for detecting possible hardcoded secrets, credentials, and tokens.
"""

import re
from pathlib import Path
from typing import List, Tuple
from models.finding import Finding, Severity


class SecretScanner:
    """
    Analyzes source code files for hardcoded secrets, API keys, passwords,
    and cloud provider credentials.
    """

    # Supported source file extensions for code review
    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".env", ".json", ".yaml", ".yml"
    }

    # Files or directories to ignore
    IGNORE_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", "venv", ".env_dir"}

    # Sensitive patterns: (Pattern, Title, Severity, Recommendation)
    PATTERNS: List[Tuple[re.Pattern, str, Severity, str]] = [
        # AWS Access Key ID
        (
            re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
            "Possible hardcoded secret: AWS Access Key ID",
            Severity.CRITICAL,
            "Revoke this AWS Access Key ID immediately. Use AWS IAM Roles or AWS Secrets Manager instead."
        ),
        # AWS Secret Access Key assignment
        (
            re.compile(
                r"""(?i)["']?(?:aws_secret_access_key|aws_secret_key)["']?\s*(?<![=!<>])[:=](?!=)\s*["']([^"'\s]{6,})["']"""
            ),
            "Possible hardcoded secret: AWS Secret Access Key",
            Severity.CRITICAL,
            "Never store AWS Secret Access Keys in source code. Inject credentials via IAM execution roles or AWS Secrets Manager."
        ),
        # Password assignments
        (
            re.compile(
                r"""(?i)["']?(?:password|passwd|pwd|db_password|database_password)["']?\s*(?<![=!<>])[:=](?!=)\s*["']([^"'\s]{4,})["']"""
            ),
            "Possible hardcoded secret: Password",
            Severity.CRITICAL,
            "Remove hardcoded password. Load sensitive passwords at runtime via environment variables or a secret vault."
        ),
        # API Keys and Secret Keys
        (
            re.compile(
                r"""(?i)["']?(?:api_key|apikey|secret_key|private_key|client_secret)["']?\s*(?<![=!<>])[:=](?!=)\s*["']([^"'\s]{6,})["']"""
            ),
            "Possible hardcoded secret: API Key / Private Key",
            Severity.HIGH,
            "Move API keys and private keys to environment variables or a key management service (KMS)."
        ),
        # Tokens (Authorization, Bearer, Access tokens)
        (
            re.compile(
                r"""(?i)["']?(?:access_token|auth_token|bearer_token|session_token|secret_token|refresh_token)["']?\s*(?<![=!<>])[:=](?!=)\s*["']([^"'\s]{6,})["']"""
            ),
            "Possible hardcoded secret: Authorization Token",
            Severity.HIGH,
            "Avoid static tokens in source code. Use token exchange mechanisms or dynamic runtime retrieval."
        ),
        # Bearer token strings
        (
            re.compile(r"""(?i)["']Bearer\s+([A-Za-z0-9_\-\.]{10,})["']"""),
            "Possible hardcoded secret: Bearer Token",
            Severity.HIGH,
            "Bearer tokens should be obtained dynamically at runtime, not hardcoded into source files."
        ),
    ]

    # Common placeholders to exclude to reduce false positives
    PLACEHOLDER_SUBSTRINGS = [
        "your_key_here",
        "your_password_here",
        "insert_token_here",
        "change_me",
        "<todo>",
        "placeholder",
        "dummy_key_to_replace",
    ]

    def __init__(self, start_id: int = 1):
        self.finding_counter = start_id

    def is_supported_file(self, file_path: Path) -> bool:
        """Check if file should be scanned based on extension and path."""
        # Skip ignored directories
        if any(part in self.IGNORE_DIRS for part in file_path.parts):
            return False
        return file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _is_placeholder(self, matched_value: str) -> bool:
        """Check if the matched secret is a harmless placeholder template."""
        lowered = matched_value.lower()
        return any(placeholder in lowered for placeholder in self.PLACEHOLDER_SUBSTRINGS)

    def scan_file(self, file_path: Path) -> List[Finding]:
        """
        Scan a single file line-by-line for secret patterns.
        Handles decoding errors and unreadable files safely.
        """
        findings: List[Finding] = []

        if not file_path.is_file():
            return findings

        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            # Report file read error as a finding
            findings.append(
                Finding(
                    id=f"ERR-{self.finding_counter:03d}",
                    type="SCANNER_ERROR",
                    severity=Severity.LOW,
                    file=str(file_path),
                    line=None,
                    title="File Read Error",
                    description=f"Could not read file {file_path.name}: {str(e)}",
                    recommendation="Ensure the file is readable and has proper permissions."
                )
            )
            self.finding_counter += 1
            return findings

        for line_num, line_content in enumerate(lines, start=1):
            stripped_line = line_content.strip()

            # Ignore pure comment lines that don't look like credentials
            if stripped_line.startswith(("#", "//", "/*", "*")):
                # Only check for high-confidence AWS keys in comments
                if not re.search(r"\bAKIA[0-9A-Z]{16}\b", stripped_line):
                    continue

            for pattern, title, severity, recommendation in self.PATTERNS:
                match = pattern.search(line_content)
                if match:
                    matched_value = match.group(1) if match.lastindex else match.group(0)

                    # Suppress known placeholder strings
                    if self._is_placeholder(matched_value):
                        continue

                    finding_id = f"SEC-{self.finding_counter:03d}"
                    self.finding_counter += 1

                    findings.append(
                        Finding(
                            id=finding_id,
                            type="HARDCODED_SECRET",
                            severity=severity,
                            file=str(file_path),
                            line=line_num,
                            title=title,
                            description=(
                                f"A possible hardcoded credential was detected on line {line_num}. "
                                "Hardcoded secrets in serverless functions pose a critical security risk "
                                "if the repository is exposed or packaged insecurely."
                            ),
                            recommendation=recommendation
                        )
                    )
                    # Match one finding per pattern per line to avoid duplicate noise
                    break

        return findings

