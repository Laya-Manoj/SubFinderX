"""
URLScan.io search-based passive subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


async def fetch_urlscan(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Search URLScan.io for hosts observed under the target domain."""

    headers = browser_headers(api_cfg)
    params = {"q": f"domain:{domain}", "size": 10000}

    async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(
            client,
            URLSCAN_SEARCH_URL,
            source="urlscan",
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

    candidates: Set[str] = set()
    for item in data.get("results") or []:
        page = item.get("page") or {}
        task = item.get("task") or {}
        for host in (page.get("domain"), task.get("domain"), page.get("apexDomain")):
            if isinstance(host, str) and host.strip():
                candidates.add(host.strip().lower())

    normalized = filter_for_domain(candidates, domain)
    return SourceResult.ok(normalized)
