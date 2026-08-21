"""
Unit tests for XTSec vulnerability auditor engine
"""

import os
import shutil
import tempfile
from xtsec.auditors.base import Finding, Severity
from xtsec.auditors.header_auditor import HeaderAuditor
from xtsec.auditors.cookie_auditor import CookieAuditor
from xtsec.reports.generator import XTSecReportGenerator


def test_finding_data_model():
    f = Finding(
        id="XT-TEST-001",
        title="Test Finding",
        severity=Severity.HIGH,
        cwe="CWE-79",
        owasp="A03:2021",
        target_url="https://example.com",
        description="Sample description",
        vulnerability_mechanism="Sample mechanism",
        business_impact="Sample impact",
        remediation="Sample remediation"
    )
    d = f.to_dict()
    assert d["id"] == "XT-TEST-001"
    assert d["severity"] == "HIGH"
    assert d["cwe"] == "CWE-79"


def test_report_generator_folder_isolation():
    test_dir = tempfile.mkdtemp()
    target_dir = os.path.join(test_dir, "reports", "example.com")

    f = Finding(
        id="XT-TEST-002",
        title="Missing Header",
        severity=Severity.MEDIUM,
        cwe="CWE-1021",
        owasp="A05:2021",
        target_url="https://example.com",
        description="Missing header",
        vulnerability_mechanism="Clickjacking risk",
        business_impact="UI redressing",
        remediation="Add X-Frame-Options",
        config_patch="add_header X-Frame-Options SAMEORIGIN;"
    )

    gen = XTSecReportGenerator("example.com", "https://example.com", [f], {"scan_time": 1.2, "crawled_count": 1})
    gen.export_all(target_dir)

    assert os.path.isdir(target_dir)
    assert os.path.exists(os.path.join(target_dir, "xtsec_audit_report.html"))
    assert os.path.exists(os.path.join(target_dir, "xtsec_executive_report.md"))
    assert os.path.exists(os.path.join(target_dir, "xtsec_scan_data.json"))
    assert os.path.exists(os.path.join(target_dir, "remediation_patches.conf"))

    shutil.rmtree(test_dir)