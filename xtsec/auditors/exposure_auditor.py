"""
Public Sensitive File Exposure & Administrative Gateway Auditor
"""

from typing import List, Dict, Any
from urllib.parse import urljoin
import requests
from xtsec.auditors.base import BaseAuditor, Finding, Severity


class ExposureAuditor(BaseAuditor):
    """Audits targets for publicly reachable configuration files, source code leaks, and admin portals."""

    @property
    def name(self) -> str:
        return "Sensitive File Exposure & Admin Gateway Auditor"

    SENSITIVE_TARGETS = [
        {"path": "/.env", "name": "Environment Configuration File (.env)", "sev": Severity.CRITICAL, "cwe": "CWE-552", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Contains database passwords, AWS credentials, and API secrets."},
        {"path": "/.git/HEAD", "name": "Exposed Git Version Control Repository (/.git)", "sev": Severity.CRITICAL, "cwe": "CWE-552", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Allows complete recovery and download of the application source code and commit history."},
        {"path": "/config.json", "name": "Server Configuration (config.json)", "sev": Severity.HIGH, "cwe": "CWE-200", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Contains application settings and backend URLs."},
        {"path": "/wp-config.php.bak", "name": "WordPress Backup Configuration", "sev": Severity.CRITICAL, "cwe": "CWE-552", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Plaintext database credentials exposed in backup file."},
        {"path": "/database.sql", "name": "Plaintext Database Dump (database.sql)", "sev": Severity.CRITICAL, "cwe": "CWE-200", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Contains raw SQL table dumps, user records, and password hashes."},
        {"path": "/.DS_Store", "name": "Apple macOS Directory Index (.DS_Store)", "sev": Severity.LOW, "cwe": "CWE-548", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Leaks directory structures and hidden filename paths."},
        {"path": "/phpinfo.php", "name": "PHP Diagnostic Info Page (phpinfo.php)", "sev": Severity.MEDIUM, "cwe": "CWE-200", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Reveals server configuration, active modules, and environment variables."},
        {"path": "/actuator/env", "name": "Spring Boot Actuator /env Endpoint", "sev": Severity.CRITICAL, "cwe": "CWE-200", "owasp": "A05:2021 - Security Misconfiguration", "desc": "Dumps runtime environment variables and secret tokens."},
        {"path": "/swagger.json", "name": "OpenAPI / Swagger Definition File", "sev": Severity.LOW, "cwe": "CWE-200", "owasp": "A01:2021 - Broken Access Control", "desc": "Maps out all internal API endpoints and parameters."},
        {"path": "/admin", "name": "Administrative Control Panel (/admin)", "sev": Severity.MEDIUM, "cwe": "CWE-284", "owasp": "A01:2021 - Broken Access Control", "desc": "Admin portal publicly accessible to internet traffic."},
        {"path": "/phpmyadmin", "name": "phpMyAdmin Database Management Gateway", "sev": Severity.HIGH, "cwe": "CWE-284", "owasp": "A01:2021 - Broken Access Control", "desc": "Direct database management portal accessible from public internet."}
    ]

    def audit(self, target_url: str, session: requests.Session, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        base = target_url.rstrip("/")

        for item in self.SENSITIVE_TARGETS:
            test_url = f"{base}{item['path']}"
            try:
                resp = session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                # Check for genuine HTTP 200 OK (not custom 404 pages)
                if resp.status_code == 200 and len(resp.content) > 10:
                    content_text = resp.text.lower()
                    # Filter out generic SPA 404 HTML redirects
                    if "<!doctype html>" in content_text and "not found" in content_text:
                        continue
                    if item["path"] == "/.git/HEAD" and "ref: refs/" not in resp.text:
                        continue

                    findings.append(Finding(
                        id=f"XT-EXP-{item['path'].replace('/', '_').replace('.', '').strip('_').upper()}",
                        title=f"Public Exposure: {item['name']}",
                        severity=item["sev"],
                        cwe=item["cwe"],
                        owasp=item["owasp"],
                        target_url=test_url,
                        description=f"The sensitive resource '{item['path']}' is publicly accessible without authentication. {item['desc']}",
                        vulnerability_mechanism="Web server allows public GET requests to sensitive directories. An attacker can download configuration secrets, reconstruct source code, or target exposed administration login panels for credential attacks.",
                        business_impact="Critical risk of full server compromise, database exfiltration, and supply chain exposure.",
                        remediation=f"Block public HTTP access to '{item['path']}' in your web server configuration, or move sensitive files outside the web root directory.",
                        evidence=f"HTTP 200 OK received at {test_url} ({len(resp.content)} bytes).",
                        config_patch=f"location ~* {item['path']} {{\n    deny all;\n    return 404;\n}}"
                    ))
            except requests.RequestException:
                continue

        return findings