"""
Lightweight Web Surface & Route Crawler
"""

import re
from urllib.parse import urljoin, urlparse
from typing import Set, List, Dict, Any
from bs4 import BeautifulSoup
import requests


class SurfaceCrawler:
    """Discovers internal routes, forms, scripts, and attack surface endpoints."""

    def __init__(self, max_pages: int = 15, timeout: int = 5):
        self.max_pages = max_pages
        self.timeout = timeout

    def crawl(self, base_url: str, session: requests.Session) -> Dict[str, Any]:
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc.split(":")[0]

        visited: Set[str] = set()
        queue: List[str] = [base_url]
        discovered_scripts: Set[str] = set()
        discovered_forms: List[Dict[str, Any]] = []

        while queue and len(visited) < self.max_pages:
            current_url = queue.pop(0)
            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                resp = session.get(current_url, timeout=self.timeout, verify=False, allow_redirects=True)
                if not resp.headers.get("Content-Type", "").startswith("text/html"):
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract Links
                for tag in soup.find_all("a", href=True):
                    link = urljoin(current_url, tag["href"])
                    parsed_link = urlparse(link)
                    if parsed_link.netloc.split(":")[0] == base_domain:
                        clean_link = link.split("#")[0].rstrip("/")
                        if clean_link and clean_link not in visited and clean_link not in queue:
                            queue.append(clean_link)

                # Extract JS Scripts
                for script in soup.find_all("script", src=True):
                    script_url = urljoin(current_url, script["src"])
                    discovered_scripts.add(script_url)

                # Extract HTML Forms
                for form in soup.find_all("form"):
                    action = urljoin(current_url, form.get("action", ""))
                    method = form.get("method", "GET").upper()
                    inputs = [inp.get("name") for inp in form.find_all(["input", "textarea", "select"]) if inp.get("name")]
                    discovered_forms.append({
                        "page_url": current_url,
                        "action": action,
                        "method": method,
                        "inputs": inputs
                    })

            except requests.RequestException:
                continue

        return {
            "crawled_urls": list(visited),
            "scripts": list(discovered_scripts),
            "forms": discovered_forms,
            "total_endpoints": len(visited)
        }