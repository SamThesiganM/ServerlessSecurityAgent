"""
scanners/iam_scanner.py
Scanner for analyzing AWS IAM JSON policy files and detecting excessive permissions.
"""

import json
from pathlib import Path
from typing import List, Any, Dict, Union
from models.finding import Finding, Severity


class IAMScanner:
    """
    Analyzes AWS IAM JSON policies for excessive permissions, wildcard actions,
    and missing least-privilege scoping.
    """

    CRITICAL_WILDCARD_SERVICES = {"iam", "sts"}
    HIGH_WILDCARD_SERVICES = {"s3", "dynamodb", "lambda", "kms", "secretsmanager"}

    def __init__(self, start_id: int = 1):
        self.finding_counter = start_id

    def is_policy_file(self, file_path: Path) -> bool:
        """
        Check if file is likely an IAM policy based on extension and filename.
        Also scans any JSON file that contains a Statement block.
        """
        if file_path.suffix.lower() != ".json":
            return False
        # If explicitly named with policy or iam, definitely inspect
        name_lower = file_path.name.lower()
        if "policy" in name_lower or "iam" in name_lower:
            return True
        # Otherwise peek inside for 'Statement' keyword
        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                content = f.read(500)
                return "Statement" in content or "statement" in content
        except Exception:
            return False

    def scan_file(self, file_path: Path) -> List[Finding]:
        """
        Parse and evaluate an IAM policy JSON file.
        Detects excessive wildcards in Actions and Resources.
        """
        findings: List[Finding] = []

        if not file_path.is_file():
            return findings

        # Attempt to load and parse JSON
        try:
            with open(file_path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except json.JSONDecodeError as err:
            finding_id = f"IAM-{self.finding_counter:03d}"
            self.finding_counter += 1
            findings.append(
                Finding(
                    id=finding_id,
                    type="POLICY_SYNTAX_ERROR",
                    severity=Severity.LOW,
                    file=str(file_path),
                    line=err.lineno,
                    title="Invalid IAM Policy JSON Syntax",
                    description=(
                        f"Failed to parse JSON file due to syntax error at line {err.lineno}, "
                        f"column {err.colno}: {err.msg}"
                    ),
                    recommendation="Ensure the policy is valid JSON before deployment."
                )
            )
            return findings
        except Exception as err:
            finding_id = f"IAM-{self.finding_counter:03d}"
            self.finding_counter += 1
            findings.append(
                Finding(
                    id=finding_id,
                    type="SCANNER_ERROR",
                    severity=Severity.LOW,
                    file=str(file_path),
                    line=None,
                    title="Error Reading Policy File",
                    description=f"Could not read policy file: {str(err)}",
                    recommendation="Verify file readability and system permissions."
                )
            )
            return findings

        # Check if the document contains a Statement
        if not isinstance(data, dict):
            return findings

        statement_entry = data.get("Statement") or data.get("statement")
        if not statement_entry:
            return findings

        # Statements can be a single dict or a list of dicts
        statements: List[Dict[str, Any]] = (
            statement_entry if isinstance(statement_entry, list) else [statement_entry]
        )

        for idx, statement in enumerate(statements, start=1):
            if not isinstance(statement, dict):
                continue

            statement_id = statement.get("Sid") or f"Statement #{idx}"
            findings.extend(self._evaluate_statement(statement, statement_id, idx, file_path))

        return findings

    def _normalize_list(self, value: Union[str, List[Any], None]) -> List[str]:
        """Convert a string or list of items into a clean list of strings."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        return []

    def _evaluate_statement(
        self,
        statement: Dict[str, Any],
        statement_id: str,
        stmt_num: int,
        file_path: Path
    ) -> List[Finding]:
        """Inspect an individual statement block for excessive permissions."""
        findings: List[Finding] = []

        # Only evaluate Allow statements; Deny statements restrict access
        effect = statement.get("Effect", "")
        if str(effect).lower() != "allow":
            return findings

        actions = self._normalize_list(statement.get("Action"))
        resources = self._normalize_list(statement.get("Resource"))

        has_star_action = any(act == "*" for act in actions)
        has_star_resource = any(res == "*" for res in resources)

        # 1. Full Admin Wildcard: Action: "*" AND Resource: "*"
        if has_star_action and has_star_resource:
            finding_id = f"IAM-{self.finding_counter:03d}"
            self.finding_counter += 1
            findings.append(
                Finding(
                    id=finding_id,
                    type="EXCESSIVE_IAM_PERMISSION",
                    severity=Severity.CRITICAL,
                    file=str(file_path),
                    line=None,
                    statement_id=statement_id,
                    title="IAM Policy: Full Administrator Access",
                    description=(
                        f"In {statement_id}, both Action and Resource are set to '*'. "
                        "This grants unrestricted administrative access over the entire AWS account. "
                        "A compromise of this serverless function allows complete account takeover."
                    ),
                    recommendation=(
                        "Apply the principle of least privilege. Explicitly specify only the required "
                        "actions (e.g., 's3:GetObject') and scope resources to specific target ARNs."
                    )
                )
            )
            # Full admin supersedes individual service checks for this statement
            return findings

        # 2. Action: "*" on specific resources
        if has_star_action:
            finding_id = f"IAM-{self.finding_counter:03d}"
            self.finding_counter += 1
            findings.append(
                Finding(
                    id=finding_id,
                    type="EXCESSIVE_IAM_PERMISSION",
                    severity=Severity.HIGH,
                    file=str(file_path),
                    line=None,
                    statement_id=statement_id,
                    title="IAM Policy: Unrestricted Actions on Resource",
                    description=(
                        f"In {statement_id}, Action is set to '*' across target resources. "
                        "This allows any operation (delete, read, update, create) on the specified resource."
                    ),
                    recommendation="Limit actions to specific API operations required by the function logic."
                )
            )

        # 3. Check for broad service-level wildcards: service:*
        for action in actions:
            action_clean = action.strip()
            if action_clean.endswith(":*"):
                service = action_clean.split(":")[0].lower()

                if service in self.CRITICAL_WILDCARD_SERVICES:
                    finding_id = f"IAM-{self.finding_counter:03d}"
                    self.finding_counter += 1
                    findings.append(
                        Finding(
                            id=finding_id,
                            type="EXCESSIVE_IAM_PERMISSION",
                            severity=Severity.CRITICAL,
                            file=str(file_path),
                            line=None,
                            statement_id=statement_id,
                            title=f"IAM Policy: Critical Privilege Escalation Risk ({action_clean})",
                            description=(
                                f"In {statement_id}, broad permissions for '{action_clean}' are granted. "
                                "Granting IAM control to a serverless function creates a critical privilege "
                                "escalation path where an attacker can modify policies and grant themselves full admin."
                            ),
                            recommendation=(
                                f"Remove '{action_clean}'. Serverless execution roles should not manage IAM policies. "
                                "Define execution roles statically in deployment templates."
                            )
                        )
                    )
                elif service in self.HIGH_WILDCARD_SERVICES:
                    finding_id = f"IAM-{self.finding_counter:03d}"
                    self.finding_counter += 1
                    findings.append(
                        Finding(
                            id=finding_id,
                            type="EXCESSIVE_IAM_PERMISSION",
                            severity=Severity.HIGH,
                            file=str(file_path),
                            line=None,
                            statement_id=statement_id,
                            title=f"IAM Policy: Excessive Service Permission ({action_clean})",
                            description=(
                                f"In {statement_id}, broad service wildcard '{action_clean}' was detected. "
                                f"This allows all actions within the '{service}' service, including administrative "
                                "and destructive calls (e.g., delete table, delete bucket)."
                            ),
                            recommendation=(
                                f"Scope '{action_clean}' to explicit operations (e.g., '{service}:Get*', "
                                f"'{service}:Put*') and restrict target Resource ARNs."
                            )
                        )
                    )
                elif service != "*":
                    finding_id = f"IAM-{self.finding_counter:03d}"
                    self.finding_counter += 1
                    findings.append(
                        Finding(
                            id=finding_id,
                            type="EXCESSIVE_IAM_PERMISSION",
                            severity=Severity.MEDIUM,
                            file=str(file_path),
                            line=None,
                            statement_id=statement_id,
                            title=f"IAM Policy: Broad Service Wildcard ({action_clean})",
                            description=(
                                f"In {statement_id}, service wildcard '{action_clean}' was detected. "
                                "While common in early development, service-level wildcards allow excessive access."
                            ),
                            recommendation=f"Replace '{action_clean}' with specific required API actions."
                        )
                    )

        # 4. Resource: "*" with non-wildcard actions
        if has_star_resource and not has_star_action:
            # Check if any action is not a service that requires * (like ec2:Describe*)
            finding_id = f"IAM-{self.finding_counter:03d}"
            self.finding_counter += 1
            findings.append(
                Finding(
                    id=finding_id,
                    type="EXCESSIVE_IAM_PERMISSION",
                    severity=Severity.MEDIUM,
                    file=str(file_path),
                    line=None,
                    statement_id=statement_id,
                    title="IAM Policy: Unscoped Resource Wildcard ('*')",
                    description=(
                        f"In {statement_id}, Resource is set to '*' while actions are specified. "
                        "This applies actions across all existing and future resources in the AWS account."
                    ),
                    recommendation="Restrict Resource to specific resource ARNs rather than '*'."
                )
            )

        return findings

