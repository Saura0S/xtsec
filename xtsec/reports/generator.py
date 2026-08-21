"""
XTSec Report Orchestrator & Multi-Format Exporter
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any
from xtsec.auditors.base import Finding, Severity

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class XTSecReportGenerator:
    """Handles terminal dashboard rendering and exports to HTML, Markdown, JSON, and Patches."""

    def __init__(self, target_domain: str, target_url: str, findings: List[Finding], scan_metadata: Dict[str, Any]):
        self.target_domain = target_domain
        self.target_url = target_url
        self.findings = findings
        self.scan_metadata = scan_metadata
        self.console = Console(legacy_windows=False) if RICH_AVAILABLE else None

    def _resolve_target_dir(self, dest: str) -> str:
        safe_domain = self.target_domain.replace(":", "_").replace("/", "_").replace("\\", "_")
        safe_domain_underscore = safe_domain.replace(".", "_")

        if not dest or dest.strip() in ["reports", "reports/", ".", "./", ""]:
            return os.path.join("reports", safe_domain)

        if os.path.splitext(dest)[1]:
            dest = os.path.dirname(dest) or os.path.join("reports", safe_domain)

        norm = os.path.normpath(dest)
        base = os.path.basename(norm)
        if base == safe_domain or base == safe_domain_underscore:
            return norm

        return os.path.join(norm, safe_domain)

    def print_terminal_dashboard(self):
        """Render color-coded terminal dashboard of vulnerability posture."""
        crit_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in self.findings if f.severity in [Severity.LOW, Severity.INFO])

        score = max(0, 100 - (crit_count * 25 + high_count * 15 + med_count * 8 + low_count * 3))
        grade = "A+" if score >= 95 else ("A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 55 else ("D" if score >= 40 else "F"))))

        if not self.console:
            print(f"\n--- XTSec Security Audit: {self.target_domain} ---")
            print(f"Total Vulnerabilities: {len(self.findings)} (Grade: {grade}, Score: {score}%)")
            return

        summary_text = (
            f"[bold cyan]Audited Target:[/] [white]{self.target_domain}[/] ({self.target_url})\n"
            f"[bold white]Overall Security Posture:[/] [bold {'green' if grade in ['A+', 'A'] else ('yellow' if grade in ['B', 'C'] else 'red')}]{grade} ({score}% Defense Score)[/]\n"
            f"[bold red]Critical Vulnerabilities:[/] {crit_count} | [bold yellow]High:[/] {high_count} | [bold cyan]Medium:[/] {med_count} | [dim]Low/Info:[/] {low_count}\n"
            f"[bold white]Endpoints Crawled:[/] {self.scan_metadata.get('crawled_count', 1)} | [bold white]Scan Duration:[/] {self.scan_metadata.get('scan_time', 0)}s"
        )
        self.console.print(Panel(summary_text, title="[bold cyan]🛡️ XTSec Vulnerability Assessment Summary[/]", border_style="cyan"))

        if self.findings:
            table = Table(title="[bold yellow]🔍 Discovered Vulnerabilities & Attack Vectors[/]", show_header=True, header_style="bold cyan")
            table.add_column("Severity", justify="center", width=12)
            table.add_column("Vulnerability Title", style="bold white")
            table.add_column("CWE & OWASP Category", style="dim")
            table.add_column("How It Works & Attack Risk", style="cyan")

            for f in self.findings:
                sev_style = "bold red" if f.severity == Severity.CRITICAL else ("yellow" if f.severity == Severity.HIGH else ("blue" if f.severity == Severity.MEDIUM else "dim"))
                mech = f.vulnerability_mechanism
                if len(mech) > 65:
                    mech = mech[:62] + "..."
                table.add_row(f"[{sev_style}]{f.severity.value}[/]", f.title, f"{f.cwe[:12]} | {f.owasp.split('-')[0].strip()}", mech)

            self.console.print(table)
        else:
            self.console.print(Panel("[bold green]✔ No critical vulnerabilities or defensive misconfigurations discovered![/]", border_style="green"))

    def export_all(self, target_dir: str):
        """Save HTML, Markdown, JSON, and Patches into dedicated reports/<domain>/ folder."""
        dest_dir = self._resolve_target_dir(target_dir)
        os.makedirs(dest_dir, exist_ok=True)

        html_path = os.path.join(dest_dir, "xtsec_audit_report.html")
        md_path = os.path.join(dest_dir, "xtsec_executive_report.md")
        json_path = os.path.join(dest_dir, "xtsec_scan_data.json")
        patch_path = os.path.join(dest_dir, "remediation_patches.conf")

        self.export_html(html_path)
        self.export_markdown(md_path)
        self.export_json(json_path)
        self.export_patches(patch_path)

        if self.console:
            tree_text = (
                f"[bold green]✔ All XTSec reports cleanly saved to:[/] [bold cyan]{dest_dir}[/]\n"
                f"  ├── 📄 [white]xtsec_audit_report.html[/] [dim](Interactive SPA Report with PDF Print)[/]\n"
                f"  ├── 👔 [white]xtsec_executive_report.md[/] [dim](Pentester Findings & Exploit Mechanisms)[/]\n"
                f"  ├── 💻 [white]xtsec_scan_data.json[/] [dim](Structured CI/CD Vulnerability Dataset)[/]\n"
                f"  └── 🛠️ [white]remediation_patches.conf[/] [dim](Server Hardening & Remediation Config)[/]"
            )
            self.console.print(Panel(tree_text, title="[bold cyan]📁 XTSec Dossier Generated[/]", border_style="green"))
        else:
            print(f"[+] Saved all reports to: {dest_dir}")

    def export_json(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        data = {
            "tool": "XTSec Vulnerability Scanner",
            "version": "1.0.0",
            "author": "Saurabh (@Saura0S)",
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": self.target_domain,
            "target_url": self.target_url,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings]
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def export_markdown(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        lines = [
            f"# 🛡️ XTSec Vulnerability Assessment Report — {self.target_domain}",
            f"**Target URL:** `{self.target_url}` | **Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Lead Security Auditor:** Saurabh ([@Saura0S](https://github.com/Saura0S))\n",
            "---",
            "## 📌 Assessment Overview",
            f"During the automated penetration testing assessment of `{self.target_domain}`, a total of **{len(self.findings)} security issues / attack vectors** were identified.\n",
            "---",
            "## 🔍 In-Depth Vulnerability Analysis\n"
        ]

        for idx, f in enumerate(self.findings, 1):
            lines.append(f"### {idx}. [{f.severity.value}] {f.title}")
            lines.append(f"- **Standard Classification:** `{f.cwe}` | `{f.owasp}`")
            lines.append(f"- **Affected Location:** `{f.target_url}`")
            lines.append(f"- **Description:** {f.description}")
            lines.append(f"- **⚔️ How It Works & Vulnerability Mechanism:**\n  > {f.vulnerability_mechanism}")
            lines.append(f"- **💼 Business & Security Impact:** {f.business_impact}")
            lines.append(f"- **🛠️ Remediation Guidance:** {f.remediation}")
            if f.config_patch:
                lines.append(f"```nginx\n{f.config_patch}\n```")
            lines.append("")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def export_patches(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        patches = [f.config_patch for f in self.findings if f.config_patch]
        content = "# XTSec Auto-Generated Web Server Hardening Patch\n# Apply to your Nginx or Apache server configuration\n\n"
        content += "\n\n".join(patches) if patches else "# No server configuration patches required.\n"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    def export_html(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        html_cards = ""
        for f in self.findings:
            sev_color = "#ef4444" if f.severity == Severity.CRITICAL else ("#f59e0b" if f.severity == Severity.HIGH else ("#3b82f6" if f.severity == Severity.MEDIUM else "#10b981"))
            html_cards += f"""
            <div class="vuln-card">
              <div class="vuln-header">
                <span class="badge" style="background-color: {sev_color};">{f.severity.value}</span>
                <span class="vuln-title">{f.title}</span>
              </div>
              <p class="vuln-desc"><b>Overview:</b> {f.description}</p>
              <div class="mechanism-box">
                <b>⚔️ How this is Vulnerable / Attack Mechanism:</b>
                <p>{f.vulnerability_mechanism}</p>
              </div>
              <p><b>💼 Impact:</b> {f.business_impact}</p>
              <div class="remediation-box">
                <b>💡 How to Fix:</b> {f.remediation}
                {f'<pre><code>{f.config_patch}</code></pre>' if f.config_patch else ''}
              </div>
            </div>
            """

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XTSec Vulnerability Report - {self.target_domain}</title>
  <style>
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 24px; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .header-box {{ background: linear-gradient(135deg, #1e1b4b, #0f172a); border: 1px solid #312e81; padding: 28px; border-radius: 12px; margin-bottom: 24px; }}
    .header-title {{ font-size: 28px; font-weight: bold; color: #38bdf8; margin: 0 0 10px 0; }}
    .vuln-card {{ background: #131b2e; border: 1px solid #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 18px; }}
    .badge {{ color: white; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold; }}
    .vuln-title {{ font-size: 18px; font-weight: bold; margin-left: 12px; }}
    .mechanism-box {{ background: #1e1e38; border-left: 4px solid #f43f5e; padding: 12px; border-radius: 4px; margin: 12px 0; }}
    .remediation-box {{ background: #064e3b; border-left: 4px solid #10b981; padding: 12px; border-radius: 4px; margin: 12px 0; }}
    pre {{ background: #000; padding: 10px; border-radius: 6px; overflow-x: auto; color: #4ade80; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-box">
      <div class="header-title">🛡️ XTSec Vulnerability & Posture Report</div>
      <div>Target: <b>{self.target_domain}</b> ({self.target_url})</div>
      <div>Audit Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | Lead Auditor: <b>Saurabh (@Saura0S)</b></div>
    </div>
    <h2>Vulnerability Findings ({len(self.findings)})</h2>
    {html_cards if html_cards else '<p style="color: #4ade80;">No vulnerabilities discovered. Target is hardened.</p>'}
  </div>
</body>
</html>"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_doc)