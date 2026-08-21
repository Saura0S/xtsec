"""
Base Auditor & Finding Data Models
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFORMATIONAL"


class Finding:
    """Represents a discrete security finding or vulnerability."""
    def __init__(
        self,
        id: str,
        title: str,
        severity: Severity,
        cwe: str,
        owasp: str,
        target_url: str,
        description: str,
        vulnerability_mechanism: str,
        business_impact: str,
        remediation: str,
        evidence: Optional[str] = None,
        config_patch: Optional[str] = None
    ):
        self.id = id
        self.title = title
        self.severity = severity
        self.cwe = cwe
        self.owasp = owasp
        self.target_url = target_url
        self.description = description
        self.vulnerability_mechanism = vulnerability_mechanism
        self.business_impact = business_impact
        self.remediation = remediation
        self.evidence = evidence or "Discovered during automated security audit."
        self.config_patch = config_patch or ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "target_url": self.target_url,
            "description": self.description,
            "vulnerability_mechanism": self.vulnerability_mechanism,
            "business_impact": self.business_impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "config_patch": self.config_patch
        }


class BaseAuditor(ABC):
    """Abstract base class for all XTSec vulnerability auditor modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the auditor module."""
        pass

    @abstractmethod
    def audit(self, target_url: str, session: Any, context: Dict[str, Any]) -> List[Finding]:
        """Execute non-destructive security checks and return list of findings."""
        pass