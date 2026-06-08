"""
Common Crawl index passive subdomain enumeration.
"""

from __future__ import annotations

import json
from typing import Set
from urllib.parse import urlparse

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"


async def _latest_crawl_index(client: httpx.AsyncClient, max_retries: int) -> str | None:
    resp = await fetch_get_with_retry(client, COLLINFO_URL, source="commoncrawl", max_retries=max_retries)
    if resp is None or resp.status_code >= 400:
        return None
    try:
        collections = resp.json()
    except Exception:
        return None
    if not collections:
        return None
    return collections[0].get("id")


async def fetch_commoncrawl(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query the Common Crawl CDX index for hosts under the target domain."""

    headers = browser_headers(api_cfg)

    async with httpx.AsyncClient(timeout=35.0, headers=headers, follow_redirects=True) as client:
        index_id = await _latest_crawl_index(client, max_retries)
        if not index_id:
            return SourceResult.unavailable("could not resolve Common Crawl index")

        index_url = f"https://index.commoncrawl.org/{index_id}-index"
        params = {"url": f"*.{domain}/*", "output": "json", "limit": 5000}
        resp = await fetch_get_with_retry(
            client,
            index_url,
            source="commoncrawl",
            max_retries=max_retries,
            params=params,
        )
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

    candidates: Set[str] = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url") or ""
        host = urlparse(url).hostname
        if host:
            candidates.add(host.lower())

    normalized = filter_for_domain(candidates, domain)
    return SourceResult.ok(normalized)
