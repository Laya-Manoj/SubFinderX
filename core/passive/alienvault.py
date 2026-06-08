"""
AlienVault OTX passive DNS subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

OTX_PASSIVE_DNS_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


async def fetch_alienvault(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query AlienVault OTX passive DNS records for subdomains."""

    url = OTX_PASSIVE_DNS_URL.format(domain=domain)
    headers = browser_headers(api_cfg)

    async with httpx.AsyncClient(timeout=25.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(client, url, source="alienvault", max_retries=max_retries)
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

        try:
            data = resp.json()
        except Exception:
            return SourceResult.unavailable("invalid JSON response")

    candidates: Set[str] = set()
    for entry in data.get("passive_dns") or []:
        hostname = (entry.get("hostname") or "").strip().lower()
        if hostname and hostname != domain and hostname.endswith(f".{domain}"):
            candidates.add(hostname)

    return SourceResult.ok(filter_for_domain(candidates, domain))
