"""
Wayback Machine (CDX API) historical subdomain enumeration.
"""

from __future__ import annotations

from typing import Set
from urllib.parse import urlparse

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

CDX_URL = "https://web.archive.org/cdx/search/cdx"


async def fetch_wayback(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Enumerate historical subdomains using the Internet Archive CDX API."""

    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": 10000,
    }

    headers = browser_headers(api_cfg)

    async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(
            client,
            CDX_URL,
            source="wayback",
            max_retries=max_retries,
            params=params,
        )
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

    try:
        rows = resp.json()
    except Exception:
        return SourceResult.unavailable("invalid JSON response")

    if not isinstance(rows, list) or len(rows) <= 1:
        return SourceResult(subdomains=set(), status="empty", reason="no results")

    hosts: Set[str] = set()
    for row in rows[1:]:
        if not row:
            continue
        original = row[0]
        try:
            host = urlparse(original).hostname
        except Exception:
            host = None
        if host and host != domain:
            hosts.add(host)

    return SourceResult.ok(filter_for_domain(hosts, domain))
