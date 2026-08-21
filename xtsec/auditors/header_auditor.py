"""
HTTP Defensive Headers & CORS Misconfiguration Auditor
"""

from typing import List, Dict, Any
import requests
from xtsec.auditors.base import BaseAuditor, Finding, Severity


class HeaderAuditor(BaseAuditor):
    """Audits HTTP defensive headers, security posture, and CORS policies."""

    @property
    def name(self) -> str:
        return "HTTP Defensive Headers & CORS Policy Auditor"

    def audit(self, target_url: str, session: requests.Session, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        try:
            resp = session.get(target_url, timeout=6, verify=False, allow_redirects=True)
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception as e:
            return findings

        # 1. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers:
            findings.append(Finding(
                id="XT-HDR-CSP",
                title="Missing Content-Security-Policy (CSP) Header",
                severity=Severity.HIGH,
                cwe="CWE-79 (Improper Neutralization of Input During Web Page Generation)",
                owasp="A03:2021 - Injection",
                target_url=target_url,
                description="The web server does not send a Content-Security-Policy (CSP) response header.",
                vulnerability_mechanism="Without a CSP header, the browser trusts and executes any script loaded on the page. If an attacker injects malicious JavaScript via Cross-Site Scripting (XSS), the browser will execute it unrestricted, allowing session token theft or keystroke logging.",
                business_impact="High risk of client-side credential theft, session hijacking, defacement, and unauthorized transaction authorization.",
                remediation="Deploy a strict Content-Security-Policy header restricting script execution to authorized domains and nonces.",
                evidence="HTTP Response Headers missing 'Content-Security-Policy'.",
                config_patch="add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\";"
            ))

        # 2. Strict-Transport-Security (HSTS)
        if target_url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(Finding(
                id="XT-HDR-HSTS",
                title="Missing HTTP Strict-Transport-Security (HSTS)",
                severity=Severity.HIGH,
                cwe="CWE-319 (Cleartext Transmission of Sensitive Information)",
                owasp="A02:2021 - Cryptographic Failures",
                target_url=target_url,
                description="The application does not enforce HTTPS connections via the HSTS header.",
                vulnerability_mechanism="An attacker on the same local network (e.g. public Wi-Fi) can perform an SSL Stripping Man-in-the-Middle (MitM) attack by intercepting the user's initial HTTP request and preventing them from upgrading to HTTPS.",
                business_impact="Attacker can intercept plaintext session cookies, passwords, and sensitive financial data in transit.",
                remediation="Configure the Strict-Transport-Security header with a long max-age (at least 1 year) and includeSubDomains.",
                evidence="HTTP Response Headers missing 'Strict-Transport-Security'.",
                config_patch="add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
            ))

        # 3. X-Frame-Options (Clickjacking Protection)
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(Finding(
                id="XT-HDR-XFO",
                title="Missing Clickjacking Defense (X-Frame-Options)",
                severity=Severity.MEDIUM,
                cwe="CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)",
                owasp="A05:2021 - Security Misconfiguration",
                target_url=target_url,
                description="The web page can be embedded inside an <iframe> on external third-party domains.",
                vulnerability_mechanism="An attacker can embed your application inside an invisible <iframe> on a phishing site (UI Redressing / Clickjacking). When the victim clicks elements on the attacker's page, they unknowingly trigger actions on your application (such as transferring money or changing passwords).",
                business_impact="Unauthorized state-changing user actions executed on behalf of authenticated users without their consent.",
                remediation="Send 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' on all HTML responses.",
                evidence="HTTP Response Headers missing 'X-Frame-Options'.",
                config_patch="add_header X-Frame-Options \"SAMEORIGIN\" always;"
            ))

        # 4. X-Content-Type-Options
        if "x-content-type-options" not in headers or headers["x-content-type-options"].lower() != "nosniff":
            findings.append(Finding(
                id="XT-HDR-XCTO",
                title="Missing X-Content-Type-Options (MIME-Sniffing Defense)",
                severity=Severity.LOW,
                cwe="CWE-79 (Cross-Site Scripting via MIME Confusion)",
                owasp="A05:2021 - Security Misconfiguration",
                target_url=target_url,
                description="The server does not prevent browsers from MIME-sniffing the response content type.",
                vulnerability_mechanism="If a user uploads a text or image file containing malicious HTML/JavaScript, older browsers may ignore the declared content-type and execute the file as JavaScript (MIME confusion attack).",
                business_impact="Potential cross-site scripting (XSS) via user-uploaded file attachments.",
                remediation="Configure 'X-Content-Type-Options: nosniff' header across all responses.",
                evidence=f"Current X-Content-Type-Options: {headers.get('x-content-type-options', 'None')}",
                config_patch="add_header X-Content-Type-Options \"nosniff\" always;"
            ))

        # 5. Server Information Disclosure
        server_hdr = headers.get("server") or headers.get("x-powered-by")
        if server_hdr:
            findings.append(Finding(
                id="XT-HDR-SRV-INFO",
                title="Server Software & Version Information Disclosure",
                severity=Severity.LOW,
                cwe="CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)",
                owasp="A05:2021 - Security Misconfiguration",
                target_url=target_url,
                description=f"The web server broadcasts its exact backend technology: '{server_hdr}'.",
                vulnerability_mechanism="Broadcasting exact web server software versions helps attackers instantly look up unpatched CVEs and known exploits specifically targeting that version.",
                business_impact="Assists attackers in profiling the infrastructure for targeted exploit campaigns.",
                remediation="Disable server tokens in your web server configuration (e.g., 'server_tokens off;' in Nginx or 'ServerSignature Off' in Apache).",
                evidence=f"Disclosed Server Header: '{server_hdr}'",
                config_patch="server_tokens off;"
            ))

        # 6. CORS Misconfiguration Check
        try:
            cors_resp = session.get(target_url, headers={"Origin": "https://evil-attacker.com"}, timeout=5, verify=False)
            cors_allow_origin = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            cors_allow_creds = cors_resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

            if cors_allow_origin == "*" and cors_allow_creds:
                findings.append(Finding(
                    id="XT-CORS-WILDCARD-CREDS",
                    title="Critical CORS Misconfiguration: Wildcard with Credentials",
                    severity=Severity.CRITICAL,
                    cwe="CWE-942 (Permissive Cross-Domain Policy with Untrusted Domains)",
                    owasp="A01:2021 - Broken Access Control",
                    target_url=target_url,
                    description="The server allows cross-origin requests from any origin while transmitting authenticated credentials.",
                    vulnerability_mechanism="An attacker's website can make authenticated XMLHttpRequests/fetch requests to your backend on behalf of a logged-in victim and read the response data directly into the attacker's script.",
                    business_impact="Complete unauthorized access to private customer account data and authenticated API responses.",
                    remediation="Never combine 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'. Explicitly validate Origin against a strict whitelist.",
                    evidence="Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true"
                ))
            elif "evil-attacker.com" in cors_allow_origin and cors_allow_creds:
                findings.append(Finding(
                    id="XT-CORS-ORIGIN-REFLECTION",
                    title="Critical CORS Misconfiguration: Arbitrary Origin Reflection",
                    severity=Severity.CRITICAL,
                    cwe="CWE-942 (Permissive Cross-Domain Policy with Untrusted Domains)",
                    owasp="A01:2021 - Broken Access Control",
                    target_url=target_url,
                    description="The server blindly reflects any incoming Origin header into Access-Control-Allow-Origin with credentials enabled.",
                    vulnerability_mechanism="The application reflects the attacker's origin without validation, bypassing browser Same-Origin Policy (SOP). The attacker can steal confidential user data via client-side fetch requests.",
                    business_impact="Cross-origin data exfiltration of private user data and CSRF-like data theft.",
                    remediation="Validate the Origin header strictly against a server-side whitelist of trusted domains before reflecting it.",
                    evidence=f"Reflected Origin Header: {cors_allow_origin} with Access-Control-Allow-Credentials: true"
                ))
        except Exception:
            pass

        return findings