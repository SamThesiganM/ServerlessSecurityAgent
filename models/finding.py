"""
models/finding.py
Defines data structures for security findings and severity levels.
"""

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, Any, Dict


class Severity(str, Enum):
    """Vulnerability severity levels adhering to industry standards."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    """Represents an individual security finding discovered during an audit."""
    id: str
    type: str
    severity: Severity
    file: str
    line: Optional[int]
    title: str
    description: str
    recommendation: str
    statement_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding instance to a dictionary for reporting."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
