"""
HackerTarget hostsearch passive subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"


async def fetch_hackertarget(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query the free HackerTarget hostsearch API for subdomains."""

    url = HACKERTARGET_URL.format(domain=domain)
    headers = browser_headers(api_cfg)

    async with httpx.AsyncClient(timeout=25.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(client, url, source="hackertarget", max_retries=max_retries)
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")
        body = resp.text.strip()

    if not body or "error" in body.lower()[:80]:
        return SourceResult(subdomains=set(), status="empty", reason="no results")

    candidates: Set[str] = set()
    for line in body.splitlines():
        host = line.split(",", 1)[0].strip().lower()
        if host and host != domain and host.endswith(f".{domain}"):
            candidates.add(host)

    return SourceResult.ok(filter_for_domain(candidates, domain))
