"""
Frontend Secret & API Key Leakage Auditor
"""

import re
from typing import List, Dict, Any
from urllib.parse import urljoin
import requests
from xtsec.auditors.base import BaseAuditor, Finding, Severity


class SecretAuditor(BaseAuditor):
    """Scans frontend HTML and loaded JavaScript files for hardcoded secrets and API keys."""

    @property
    def name(self) -> str:
        return "Secret & API Key Leakage Auditor"

    PATTERNS = [
        {"name": "AWS Access Key ID", "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "sev": Severity.CRITICAL, "cwe": "CWE-798"},
        {"name": "Google API Key", "regex": r"AIza[0-9A-Za-z\\-_]{35}", "sev": Severity.HIGH, "cwe": "CWE-798"},
        {"name": "Stripe Live Secret Key", "regex": r"sk_live_[0-9a-zA-Z]{24}", "sev": Severity.CRITICAL, "cwe": "CWE-798"},
        {"name": "GitHub Personal Access Token", "regex": r"ghp_[0-9a-zA-Z]{36}", "sev": Severity.CRITICAL, "cwe": "CWE-798"},
        {"name": "Slack Bot Token", "regex": r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}", "sev": Severity.CRITICAL, "cwe": "CWE-798"},
        {"name": "Private RSA / SSH Key Block", "regex": r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "sev": Severity.CRITICAL, "cwe": "CWE-312"},
        {"name": "Hardcoded JWT Token", "regex": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "sev": Severity.MEDIUM, "cwe": "CWE-798"}
    ]

    def audit(self, target_url: str, session: requests.Session, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        crawled_scripts = context.get("scripts", [])

        # Fetch main HTML
        sources = []
        try:
            resp = session.get(target_url, timeout=5, verify=False)
            sources.append((target_url, resp.text))
        except Exception:
            pass

        # Fetch up to 5 JavaScript files
        for s_url in crawled_scripts[:5]:
            try:
                s_resp = session.get(s_url, timeout=5, verify=False)
                sources.append((s_url, s_resp.text))
            except Exception:
                continue

        for source_url, content in sources:
            for pat in self.PATTERNS:
                matches = re.findall(pat["regex"], content)
                if matches:
                    snippet = matches[0]
                    # Mask sensitive key
                    masked = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 10 else "***"
                    findings.append(Finding(
                        id=f"XT-SECRET-{pat['name'].replace(' ', '_').upper()}",
                        title=f"Hardcoded Secret Detected: {pat['name']}",
                        severity=pat["sev"],
                        cwe=pat["cwe"] + " (Use of Hard-coded Credentials)",
                        owasp="A07:2021 - Identification and Authentication Failures",
                        target_url=source_url,
                        description=f"A hardcoded {pat['name']} was detected in the client-accessible source code.",
                        vulnerability_mechanism="The secret is embedded directly into frontend code or scripts delivered to any browser. Anyone inspecting page sources or running automated scrapers can extract this credential.",
                        business_impact="Unauthorized access to underlying cloud infrastructure, billing APIs, or backend databases.",
                        remediation="Immediately revoke and rotate the exposed token. Move all sensitive keys to server-side environment variables and proxy requests through your backend.",
                        evidence=f"Matched token: {masked} at {source_url}"
                    ))

        return findings