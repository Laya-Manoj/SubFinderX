"""
VirusTotal-based subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def fetch_virustotal(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Enumerate subdomains using VirusTotal siblings relationship."""

    if not api_cfg.virustotal_api_key:
        return SourceResult.skipped("SUBHUNTER_VT_API_KEY not set")

    headers = browser_headers(api_cfg)
    headers["x-apikey"] = api_cfg.virustotal_api_key

    subdomains: Set[str] = set()
    next_cursor: str | None = None
    last_reason = ""

    async with httpx.AsyncClient(base_url=VT_BASE_URL, timeout=20.0, headers=headers) as client:
        while True:
            params: dict[str, str] = {}
            if next_cursor:
                params["cursor"] = next_cursor

            resp = await fetch_get_with_retry(
                client,
                f"/domains/{domain}/siblings",
                source="virustotal",
                max_retries=max_retries,
                params=params or None,
            )
            if resp is None:
                last_reason = "network error"
                break
            if resp.status_code >= 400:
                last_reason = f"HTTP {resp.status_code}"
                break

            try:
                data = resp.json()
            except Exception:
                last_reason = "invalid JSON response"
                break

            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                host = attrs.get("last_https_certificate", {}).get("subject", {}).get("CN")
                if host and host != domain:
                    subdomains.add(host)

                dom_id = item.get("id")
                if dom_id and dom_id != domain:
                    subdomains.add(dom_id)

            next_cursor = data.get("meta", {}).get("cursor")
            if not next_cursor:
                break

    normalized = filter_for_domain(subdomains, domain)
    if normalized:
        return SourceResult.ok(normalized)
    if last_reason:
        return SourceResult.unavailable(last_reason)
    return SourceResult(subdomains=set(), status="empty", reason="no results")
