"""
Subdomain Center passive enumeration (free, no API key).
"""

from __future__ import annotations

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

SUBDOMAIN_CENTER_URL = "https://api.subdomain.center/?domain={domain}"


async def fetch_subdomain_center(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query the Subdomain Center public API."""

    url = SUBDOMAIN_CENTER_URL.format(domain=domain)
    headers = browser_headers(api_cfg)

    async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(client, url, source="subdomain_center", max_retries=max_retries)
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

        try:
            labels = resp.json()
        except Exception:
            return SourceResult.unavailable("invalid JSON response")

    if not isinstance(labels, list):
        return SourceResult(subdomains=set(), status="empty", reason="no results")

    fqdn_list = []
    for item in labels:
        if not isinstance(item, str):
            continue
        host = item.strip().lower()
        if not host:
            continue
        if host.endswith(f".{domain}"):
            fqdn_list.append(host)
        elif "." not in host:
            fqdn_list.append(f"{host}.{domain}")

    normalized = filter_for_domain(fqdn_list, domain)
    return SourceResult.ok(normalized)
