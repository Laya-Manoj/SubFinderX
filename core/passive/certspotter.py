"""
Cert Spotter Certificate Transparency passive enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


async def fetch_certspotter(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query Cert Spotter CT logs for subdomains (API key recommended)."""

    headers = browser_headers(api_cfg)
    if api_cfg.certspotter_api_key:
        headers["Authorization"] = f"Bearer {api_cfg.certspotter_api_key}"

    params = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
    }

    async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(
            client,
            CERTSPOTTER_URL,
            source="certspotter",
            max_retries=max_retries,
            params=params,
        )
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code == 401:
            return SourceResult.skipped("SUBHUNTER_CERTSPOTTER_API_KEY not set or invalid")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

        try:
            rows = resp.json()
        except Exception:
            return SourceResult.unavailable("invalid JSON response")

    candidates: Set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in row.get("dns_names") or []:
            if isinstance(name, str) and name.strip():
                candidates.add(name.strip().lower())

    normalized = filter_for_domain(candidates, domain)
    return SourceResult.ok(normalized)
