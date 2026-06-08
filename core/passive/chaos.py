"""
ProjectDiscovery Chaos-based subdomain enumeration.
"""

from __future__ import annotations

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

CHAOS_BASE_URL = "https://dns.projectdiscovery.io"


async def fetch_chaos(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Enumerate subdomains using ProjectDiscovery Chaos API."""

    if not api_cfg.chaos_api_key:
        return SourceResult.skipped("SUBHUNTER_CHAOS_API_KEY not set")

    headers = browser_headers(api_cfg)
    headers["Authorization"] = api_cfg.chaos_api_key

    async with httpx.AsyncClient(base_url=CHAOS_BASE_URL, timeout=20.0, headers=headers) as client:
        resp = await fetch_get_with_retry(
            client,
            f"/dns/{domain}/subdomains",
            source="chaos",
            max_retries=max_retries,
        )
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        return SourceResult.unavailable("invalid JSON response")

    subs = data.get("subdomains") or []
    fqdn_list = [f"{s}.{domain}" for s in subs]
    return SourceResult.ok(filter_for_domain(fqdn_list, domain))
