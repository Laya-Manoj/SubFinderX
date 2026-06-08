"""
Shared helpers for passive source modules.
"""

from __future__ import annotations

import re
from typing import Iterable, Set

from core.utils.config import APIConfig
from core.utils.dedupe import dedupe_subdomains

BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


def browser_headers(api_cfg: APIConfig) -> dict[str, str]:
    return {
        "User-Agent": api_cfg.user_agent or BROWSER_USER_AGENT,
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }


def filter_for_domain(subdomains: Iterable[str], domain: str) -> Set[str]:
    domain = domain.lower().strip()
    filtered: Set[str] = set()
    for host in dedupe_subdomains(subdomains):
        if host == domain:
            continue
        if host.endswith(f".{domain}"):
            filtered.add(host)
    return filtered


def parse_rapiddns_html(body: str, domain: str) -> Set[str]:
    """Extract subdomains from RapidDNS HTML result tables."""

    domain_esc = re.escape(domain)
    patterns = (
        rf'<td><a[^>]*>([a-zA-Z0-9][-a-zA-Z0-9_.]*\.{domain_esc})</a></td>',
        rf'<td>([a-zA-Z0-9][-a-zA-Z0-9_.]*\.{domain_esc})</td>',
        rf'>([a-zA-Z0-9][-a-zA-Z0-9_.]*\.{domain_esc})<',
    )
    candidates: Set[str] = set()
    for pattern in patterns:
        candidates.update(re.findall(pattern, body, flags=re.IGNORECASE))
    return dedupe_subdomains(c.lower() for c in candidates)


def parse_dnsdumpster_html(body: str, domain: str) -> Set[str]:
    """Extract subdomains from DNSDumpster result HTML."""

    domain_esc = re.escape(domain)
    patterns = (
        rf'<td class="col-md-10[^"]*">([a-zA-Z0-9][-a-zA-Z0-9_.]*\.{domain_esc})</td>',
        rf'<td[^>]*>\s*([a-zA-Z0-9][-a-zA-Z0-9_.]*\.{domain_esc})\s*</td>',
        rf'>([a-zA-Z0-9][-a-zA-Z0-9_.]*\.{domain_esc})<',
        rf'"hostname"\s*:\s*"([a-zA-Z0-9][-a-zA-Z0-9_.]*\.{domain_esc})"',
    )
    candidates: Set[str] = set()
    for pattern in patterns:
        candidates.update(re.findall(pattern, body, flags=re.IGNORECASE))
    return dedupe_subdomains(c.lower() for c in candidates)
