"""
Wayback Machine (CDX API) historical subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from subfinderx.core.utils.config import APIConfig
from subfinderx.core.utils.dedupe import dedupe_subdomains


CDX_URL = "https://web.archive.org/cdx/search/cdx"


async def fetch_wayback(domain: str, api_cfg: APIConfig) -> Set[str]:
    """
    Enumerate historical subdomains using the Internet Archive CDX API.

    This queries for URLs matching *.domain and extracts hostnames.
    """

    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
    }

    headers = {"User-Agent": api_cfg.user_agent}

    async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
        try:
            resp = await client.get(CDX_URL, params=params)
            resp.raise_for_status()
        except Exception:
            return set()

    try:
        rows = resp.json()
    except Exception:
        return set()

    # First row is header.
    if not isinstance(rows, list) or len(rows) <= 1:
        return set()

    hosts: Set[str] = set()
    for row in rows[1:]:
        if not row:
            continue
        original = row[0]
        # original is a URL; extract hostname.
        try:
            # Avoid importing urlparse at module import time to keep dependencies minimal.
            from urllib.parse import urlparse

            host = urlparse(original).hostname
        except Exception:
            host = None
        if host and host != domain:
            hosts.add(host)

    return dedupe_subdomains(hosts)

