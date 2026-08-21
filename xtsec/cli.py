"""
XTSec - Enterprise Web Vulnerability & Penetration Testing CLI
Author: Saurabh (@Saura0S)
"""

import sys
import os
import argparse
import time
from urllib.parse import urlparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Windows UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from xtsec.auditors.crawler import SurfaceCrawler
from xtsec.auditors.header_auditor import HeaderAuditor
from xtsec.auditors.exposure_auditor import ExposureAuditor
from xtsec.auditors.cookie_auditor import CookieAuditor
from xtsec.auditors.ssl_auditor import SSLAuditor
from xtsec.auditors.secret_auditor import SecretAuditor
from xtsec.reports.generator import XTSecReportGenerator

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

BANNER = r"""[bold red]
 __   _______ ____            
 \ \ / /_   _/ ___|  ___  ___ 
  \ V /  | | \___ \ / _ \/ __|
   | |   | |  ___) |  __/ (__ 
   |_|   |_| |____/ \___|\___|
[/][bold dim]
  Enterprise Web Vulnerability & Posture Auditor | Built by @Saura0S v1.0.0
[/]"""


def normalize_target(target: str):
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    parsed = urlparse(target)
    domain = parsed.netloc.split(":")[0]
    base_url = f"{parsed.scheme}://{domain}"
    return domain, base_url


def main():
    parser = argparse.ArgumentParser(
        description="XTSec — Enterprise Web Vulnerability & Pentesting Audit Suite",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL or domain to audit (e.g. example.com)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Custom output directory (default: reports/<domain>/)")
    parser.add_argument("--crawl", action="store_true", help="Enable deep route and JavaScript crawler")
    parser.add_argument("--all-reports", action="store_true", help="Automatically export HTML, Markdown, JSON, and Patches")
    parser.add_argument("--timeout", type=int, default=6, help="Network timeout in seconds (default: 6)")

    args = parser.parse_args()
    domain, base_url = normalize_target(args.url)

    console = Console(legacy_windows=False) if RICH_AVAILABLE else None
    if console:
        console.print(BANNER)
        console.print(f"[bold cyan]🎯 Target:[/] [white]{domain}[/] ([dim]{base_url}[/])\n")
    else:
        print(f"[*] XTSec auditing {domain} ({base_url})...\n")

    start_time = time.time()
    session = requests.Session()
    session.headers.update({"User-Agent": "XTSec-Pentest-Auditor/1.0 (+https://github.com/Saura0S)"})

    context = {}
    if args.crawl:
        if console:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as prog:
                prog.add_task(description="[cyan]1/6 Mapping attack surface & crawling routes...", total=None)
                crawler = SurfaceCrawler(timeout=args.timeout)
                crawl_data = crawler.crawl(base_url, session)
        else:
            print("[*] 1/6 Crawling routes...")
            crawler = SurfaceCrawler(timeout=args.timeout)
            crawl_data = crawler.crawl(base_url, session)
        context.update(crawl_data)

    all_findings = []
    auditors = [
        ("2/6 Auditing SSL/TLS encryption & transport...", SSLAuditor()),
        ("3/6 Auditing HTTP defensive headers & CORS...", HeaderAuditor()),
        ("4/6 Auditing session cookies & security flags...", CookieAuditor()),
        ("5/6 Scanning for exposed sensitive files & gateways...", ExposureAuditor()),
        ("6/6 Inspecting client scripts for leaked API secrets...", SecretAuditor())
    ]

    for desc, auditor in auditors:
        if console:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as prog:
                prog.add_task(description=f"[cyan]{desc}", total=None)
                results = auditor.audit(base_url, session, context)
        else:
            print(f"[*] {desc}")
            results = auditor.audit(base_url, session, context)

        all_findings.extend(results)

    scan_duration = round(time.time() - start_time, 2)
    scan_meta = {
        "scan_time": scan_duration,
        "crawled_count": len(context.get("crawled_urls", [base_url]))
    }

    # Render Dashboard
    generator = XTSecReportGenerator(domain, base_url, all_findings, scan_meta)
    generator.print_terminal_dashboard()

    # Determine Destination
    safe_domain = domain.replace(":", "_").replace("/", "_")
    target_dir = args.output if args.output else os.path.join("reports", safe_domain)

    if args.all_reports or args.output:
        generator.export_all(target_dir)
    else:
        # Save by default to reports/<domain>/
        generator.export_all(target_dir)

    if console:
        console.print(f"\n[bold green]✔ XTSec Audit Finished in [cyan]{scan_duration}s[/]![/]\n")


if __name__ == "__main__":
    main()