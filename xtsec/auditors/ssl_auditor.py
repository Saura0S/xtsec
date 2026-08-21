"""
SSL/TLS Cryptographic & Certificate Posture Auditor
"""

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from typing import List, Dict, Any
from xtsec.auditors.base import BaseAuditor, Finding, Severity


class SSLAuditor(BaseAuditor):
    """Audits TLS certificate validation, expiration, and deprecated cipher protocols."""

    @property
    def name(self) -> str:
        return "SSL/TLS Cryptographic & Transport Auditor"

    def audit(self, target_url: str, session: Any, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(":")[0]

        if not target_url.startswith("https://"):
            findings.append(Finding(
                id="XT-SSL-PLAINTEXT-HTTP",
                title="Unencrypted HTTP Connection (No SSL/TLS)",
                severity=Severity.CRITICAL,
                cwe="CWE-319 (Cleartext Transmission of Sensitive Information)",
                owasp="A02:2021 - Cryptographic Failures",
                target_url=target_url,
                description="The target website serves content over unencrypted plaintext HTTP.",
                vulnerability_mechanism="All traffic, passwords, cookies, and sensitive data are sent in plaintext over the wire. Anyone on the local network or ISP routing path can sniff and tamper with the data.",
                business_impact="Total interception and modification of user communications and credentials.",
                remediation="Deploy an SSL/TLS certificate (e.g. via Let's Encrypt) and force automatic redirection to HTTPS."
            ))
            return findings

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

                    # Check Expiry
                    expire_date_str = cert.get("notAfter")
                    if expire_date_str:
                        expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expire_date - datetime.utcnow()).days

                        if days_left < 0:
                            findings.append(Finding(
                                id="XT-SSL-CERT-EXPIRED",
                                title="Expired SSL/TLS Certificate",
                                severity=Severity.HIGH,
                                cwe="CWE-298 (Improper Validation of Certificate Expiration)",
                                owasp="A02:2021 - Cryptographic Failures",
                                target_url=target_url,
                                description=f"The SSL certificate for {domain} expired {abs(days_left)} days ago.",
                                vulnerability_mechanism="Browsers display prominent security warning blocks to all visitors, and automated clients fail to verify identity.",
                                business_impact="Loss of customer trust, broken API integrations, and warning blocks.",
                                remediation="Renew the SSL/TLS certificate immediately."
                            ))
                        elif days_left < 14:
                            findings.append(Finding(
                                id="XT-SSL-CERT-EXPIRING-SOON",
                                title=f"SSL Certificate Expiring in {days_left} Days",
                                severity=Severity.MEDIUM,
                                cwe="CWE-298",
                                owasp="A02:2021 - Cryptographic Failures",
                                target_url=target_url,
                                description=f"The SSL certificate expires in {days_left} days ({expire_date_str}).",
                                vulnerability_mechanism="Imminent service disruption if automated certificate renewal fails.",
                                business_impact="Potential downtime and browser warning screens upon expiration.",
                                remediation="Verify automated renewal (certbot/ACME) is running."
                            ))

                    # Check for Deprecated TLS Versions
                    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3"]:
                        findings.append(Finding(
                            id="XT-SSL-DEPRECATED-PROTOCOL",
                            title=f"Deprecated TLS Protocol in Use ({tls_version})",
                            severity=Severity.HIGH,
                            cwe="CWE-326 (Inadequate Encryption Strength)",
                            owasp="A02:2021 - Cryptographic Failures",
                            target_url=target_url,
                            description=f"Server negotiates legacy {tls_version}.",
                            vulnerability_mechanism="Legacy TLS 1.0/1.1 protocols lack modern cipher protection and are vulnerable to known downgrade and padding oracle attacks.",
                            business_impact="Non-compliance with PCI-DSS v4.0 and vulnerability to cryptographic eavesdropping.",
                            remediation="Disable TLS 1.0 and TLS 1.1 in web server; support only TLS 1.2 and TLS 1.3.",
                            config_patch="ssl_protocols TLSv1.2 TLSv1.3;"
                        ))

        except ssl.SSLError as e:
            findings.append(Finding(
                id="XT-SSL-INVALID-CERT",
                title="Invalid or Self-Signed SSL Certificate",
                severity=Severity.HIGH,
                cwe="CWE-295 (Improper Certificate Validation)",
                owasp="A02:2021 - Cryptographic Failures",
                target_url=target_url,
                description=f"SSL certificate validation failed: {e}",
                vulnerability_mechanism="Users receive security warning dialogs, rendering the site vulnerable to trivial Man-in-the-Middle certificate spoofing.",
                business_impact="Critical degradation of user trust and vulnerability to traffic interception.",
                remediation="Install a valid certificate issued by a recognized Certificate Authority (CA)."
            ))
        except Exception:
            pass

        return findings