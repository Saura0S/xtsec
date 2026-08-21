<div align="center">

# 🛡️ XTSec — Enterprise Web Vulnerability & Penetration Testing Suite

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Vulnerability Audit](https://img.shields.io/badge/Audit-OWASP_Top_10-red?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Target Isolation](https://img.shields.io/badge/Dossier-Target_Isolated-blue?style=for-the-badge)](reports/)

<p align="center">
  <b>High-precision, multi-vector web vulnerability and penetration testing posture auditor in Python.</b><br/>
  <i>Explains what is vulnerable, the underlying attack mechanism, business impact, and delivers auto-generated server hardening patches.</i>
</p>

</div>

---

## 📌 What is XTSec?

**XTSec** is an automated web vulnerability assessment suite designed for security engineers, penetration testers, and DevSecOps teams. It conducts non-destructive multi-vector heuristic auditing across web applications to discover misconfigurations, weak cryptography, leaked credentials, and missing defensive headers.

For every finding, XTSec details:
1. **The Vulnerability**: Precise CWE and OWASP Top 10 classification.
2. **⚔️ How It Works / Attack Mechanism**: Explains *why* the issue is exploitable and what an attacker can achieve.
3. **💼 Business Impact**: The real-world consequence (e.g. session takeover, credential interception).
4. **💡 Remediation & Config Patches**: Ready-to-apply Nginx and Apache server hardening snippets.

---

## 🚀 Key Modules & Capabilities

| Engine Module | Vulnerability Vectors Audited | Standard |
| :--- | :--- | :--- |
| **Defensive Headers & CORS** | Missing CSP, HSTS, X-Frame-Options, MIME sniffing, and Arbitrary CORS origin reflection | OWASP A03 / A05 |
| **Sensitive File Leaks** | Exposed `.env`, `.git` repository, database backups (`.sql`), and admin portals | OWASP A05 (CWE-552) |
| **Session Cookie Security** | Insecure cookies missing `HttpOnly`, `Secure`, and `SameSite` flags | OWASP A01 (CWE-1004) |
| **SSL/TLS & Cryptography** | Deprecated TLS 1.0/1.1 protocols, expired/invalid certificates, plaintext HTTP | OWASP A02 (CWE-319) |
| **Frontend Secret Auditor** | Leaked AWS, Google API, Stripe, GitHub, Slack tokens in JS source code | OWASP A07 (CWE-798) |
| **Surface Crawler** | Automated route discovery, internal endpoint mapping, and form extraction | AppSec Recon |

---

## 📂 Dedicated Target Report Isolation

Each target website scanned is saved into its own isolated dossier folder under `reports/<domain>/`:

```
reports/
└── example.com/
    ├── xtsec_audit_report.html          # Interactive SPA Report with PDF Print
    ├── xtsec_executive_report.md        # Detailed Pentest Markdown Report
    ├── xtsec_scan_data.json             # Structured CI/CD JSON Dataset
    └── remediation_patches.conf         # Ready-to-apply Server Hardening Config
```

---

## ⚙️ Installation & Usage

### 1. Clone & Install
```bash
git clone https://github.com/Saura0S/xtsec.git
cd xtsec
pip install -r requirements.txt
pip install -e .
```

### 2. Run a Full Vulnerability Assessment
```bash
# Basic scan
python3 -m xtsec.cli -u example.com

# Deep crawl and export all reports
python3 -m xtsec.cli -u example.com --crawl --all-reports
```

---

## 👤 Author & Connect

Developed by **Saurabh ([@Saura0S](https://github.com/Saura0S))**.

* 🌐 **GitHub**: [@Saura0S](https://github.com/Saura0S)
* 🎮 **Discord Community**: [Join Discord](https://discord.gg/523wGqAP4W)
* 📸 **Instagram**: [@SAURABH_xt_0](https://www.instagram.com/SAURABH_xt_0)

---

## 📄 License

Distributed under the [MIT License](LICENSE).