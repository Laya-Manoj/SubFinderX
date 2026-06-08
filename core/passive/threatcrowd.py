"""
ThreatCrowd passive subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

THREATCROWD_URL = "https://threatcrowd.org/searchApi/v2/domain/report/"


async def fetch_threatcrowd(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query ThreatCrowd domain report API for related subdomains."""

    headers = browser_headers(api_cfg)
    params = {"domain": domain}

    async with httpx.AsyncClient(timeout=25.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(
            client,
            THREATCROWD_URL,
            source="threatcrowd",
            max_retries=max_retries,
            params=params,
        )
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

        try:
            data = resp.json()
        except Exception:
            return SourceResult.unavailable("invalid JSON response")

    if data.get("response_code") == 0:
        return SourceResult(subdomains=set(), status="empty", reason="no results")

    candidates: Set[str] = set()
    for host in data.get("subdomains") or []:
        if isinstance(host, str) and host.strip():
            candidates.add(host.strip().lower())

    normalized = filter_for_domain(candidates, domain)
    return SourceResult.ok(normalized)
