"""
SecurityTrails-based subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

ST_BASE_URL = "https://api.securitytrails.com/v1"


async def fetch_securitytrails(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Enumerate subdomains using the SecurityTrails API."""

    if not api_cfg.securitytrails_api_key:
        return SourceResult.skipped("SUBHUNTER_SECURITYTRAILS_API_KEY not set")

    headers = browser_headers(api_cfg)
    headers["APIKEY"] = api_cfg.securitytrails_api_key

    async with httpx.AsyncClient(base_url=ST_BASE_URL, timeout=20.0, headers=headers) as client:
        resp = await fetch_get_with_retry(
            client,
            f"/domain/{domain}/subdomains",
            source="securitytrails",
            max_retries=max_retries,
            params={"children_only": "false"},
        )
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        return SourceResult.unavailable("invalid JSON response")

    subdomains: Set[str] = set()
    for label in data.get("subdomains", []):
        subdomains.add(f"{label}.{domain}")

    return SourceResult.ok(filter_for_domain(subdomains, domain))
