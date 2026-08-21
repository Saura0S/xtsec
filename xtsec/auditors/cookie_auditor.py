"""
Session Cookie Security & Flag Auditor
"""

from typing import List, Dict, Any
import requests
from xtsec.auditors.base import BaseAuditor, Finding, Severity


class CookieAuditor(BaseAuditor):
    """Audits HTTP Set-Cookie headers for secure session flags."""

    @property
    def name(self) -> str:
        return "Session Cookie Flag & Attribute Auditor"

    def audit(self, target_url: str, session: requests.Session, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            resp = session.get(target_url, timeout=6, verify=False, allow_redirects=True)
            raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        except Exception:
            return findings

        if not raw_cookies:
            # Check response.cookies
            for c in resp.cookies:
                raw_cookies.append(f"{c.name}={c.value}; secure={c.secure}")

        for cookie_str in raw_cookies:
            parts = [p.strip().lower() for p in cookie_str.split(";")]
            cookie_name = cookie_str.split("=")[0].strip()

            has_httponly = any("httponly" == p for p in parts)
            has_secure = any("secure" == p for p in parts)
            has_samesite = any("samesite" in p for p in parts)

            # 1. Missing HttpOnly
            if not has_httponly:
                findings.append(Finding(
                    id="XT-COOKIE-NO-HTTPONLY",
                    title=f"Session Cookie Missing 'HttpOnly' Flag ({cookie_name})",
                    severity=Severity.HIGH,
                    cwe="CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)",
                    owasp="A05:2021 - Security Misconfiguration",
                    target_url=target_url,
                    description=f"The cookie '{cookie_name}' is set without the 'HttpOnly' directive.",
                    vulnerability_mechanism="Without HttpOnly, the cookie can be accessed and read by JavaScript running in the browser via `document.cookie`. If the application suffers from any Cross-Site Scripting (XSS) flaw, an attacker can steal the active user's session token and impersonate their account.",
                    business_impact="Account takeover and identity impersonation via client-side script execution.",
                    remediation="Add the 'HttpOnly' flag when setting session cookies in the application backend or web server.",
                    evidence=f"Set-Cookie: {cookie_str}",
                    config_patch="Set-Cookie: <name>=<value>; HttpOnly; Secure; SameSite=Lax;"
                ))

            # 2. Missing Secure
            if not has_secure and target_url.startswith("https://"):
                findings.append(Finding(
                    id="XT-COOKIE-NO-SECURE",
                    title=f"Session Cookie Missing 'Secure' Flag ({cookie_name})",
                    severity=Severity.MEDIUM,
                    cwe="CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)",
                    owasp="A02:2021 - Cryptographic Failures",
                    target_url=target_url,
                    description=f"The cookie '{cookie_name}' was set over HTTPS but lacks the 'Secure' flag.",
                    vulnerability_mechanism="The browser will happily send this cookie over unencrypted HTTP connections if the user clicks an unencrypted link or is subject to an SSL-stripping attack, exposing the session token in cleartext.",
                    business_impact="Interception of session credentials across untrusted networks.",
                    remediation="Always append '; Secure' to all cookies set over HTTPS.",
                    evidence=f"Set-Cookie: {cookie_str}"
                ))

            # 3. Missing SameSite
            if not has_samesite:
                findings.append(Finding(
                    id="XT-COOKIE-NO-SAMESITE",
                    title=f"Cookie Missing 'SameSite' Attribute ({cookie_name})",
                    severity=Severity.MEDIUM,
                    cwe="CWE-1275 (Sensitive Cookie with Improper SameSite Attribute)",
                    owasp="A01:2021 - Broken Access Control",
                    target_url=target_url,
                    description=f"The cookie '{cookie_name}' does not specify a SameSite policy (Lax or Strict).",
                    vulnerability_mechanism="Without a SameSite attribute, the browser will automatically include the session cookie in cross-site requests initiated by third-party websites, leaving the application vulnerable to Cross-Site Request Forgery (CSRF) attacks.",
                    business_impact="Attackers can force authenticated users to execute unintended actions (e.g. transfer funds or change email) on vulnerable forms.",
                    remediation="Set 'SameSite=Lax' or 'SameSite=Strict' on all state-managing cookies.",
                    evidence=f"Set-Cookie: {cookie_str}"
                ))

        return findings