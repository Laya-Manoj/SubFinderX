"""
crt.sh Certificate Transparency enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

CRTURL_TEMPLATE = "https://crt.sh/?q=%25.{domain}&output=json"


async def fetch_crtsh(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query crt.sh for certificates issued for the target domain."""

    url = CRTURL_TEMPLATE.format(domain=domain)
    headers = browser_headers(api_cfg)

    async with httpx.AsyncClient(timeout=35.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(client, url, source="crtsh", max_retries=max_retries)
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        return SourceResult.unavailable("invalid JSON response")

    if not isinstance(data, list):
        return SourceResult(subdomains=set(), status="empty", reason="no results")

    candidates: Set[str] = set()
    for entry in data:
        name_val = entry.get("name_value") or ""
        for line in str(name_val).splitlines():
            line = line.strip()
            if line and line != domain:
                candidates.add(line)

    return SourceResult.ok(filter_for_domain(candidates, domain))
