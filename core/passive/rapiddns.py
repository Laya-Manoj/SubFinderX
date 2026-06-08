"""
RapidDNS passive subdomain enumeration.
"""

from __future__ import annotations

import json
from typing import Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain, parse_rapiddns_html
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

RAPIDDNS_PAGE_URL = "https://rapiddns.io/subdomain/{domain}?full=1"
RAPIDDNS_EXPORT_URL = "https://rapiddns.io/api/export?domain={domain}&format=json"


def _parse_export_payload(body: str, domain: str) -> Set[str]:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return set()

    candidates: Set[str] = set()
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict):
                host = str(row.get("subdomain") or row.get("hostname") or "").strip().lower()
                if host:
                    candidates.add(host)
            elif isinstance(row, str):
                candidates.add(row.strip().lower())
    elif isinstance(data, dict):
        for key in ("data", "subdomains", "results"):
            rows = data.get(key) or []
            for row in rows:
                if isinstance(row, dict):
                    host = str(row.get("subdomain") or row.get("hostname") or "").strip().lower()
                    if host:
                        candidates.add(host)
    return filter_for_domain(candidates, domain)


async def fetch_rapiddns(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query RapidDNS for subdomains associated with the target domain."""

    headers = browser_headers(api_cfg)
    candidates: Set[str] = set()
    last_status: int | None = None

    async with httpx.AsyncClient(timeout=35.0, headers=headers, follow_redirects=True) as client:
        export_url = RAPIDDNS_EXPORT_URL.format(domain=domain)
        export_resp = await fetch_get_with_retry(
            client,
            export_url,
            source="rapiddns",
            max_retries=max_retries,
        )
        if export_resp is not None:
            last_status = export_resp.status_code
            if export_resp.status_code < 400:
                candidates.update(_parse_export_payload(export_resp.text, domain))

        if not candidates:
            page_url = RAPIDDNS_PAGE_URL.format(domain=domain)
            page_resp = await fetch_get_with_retry(
                client,
                page_url,
                source="rapiddns",
                max_retries=max_retries,
            )
            if page_resp is None:
                return SourceResult.unavailable("network error")
            last_status = page_resp.status_code
            if page_resp.status_code >= 400:
                return SourceResult.unavailable(f"HTTP {page_resp.status_code}")
            candidates.update(parse_rapiddns_html(page_resp.text, domain))

    normalized = filter_for_domain(candidates, domain)
    if normalized:
        return SourceResult.ok(normalized)
    if last_status is not None and last_status >= 400:
        return SourceResult.unavailable(f"HTTP {last_status}")
    return SourceResult(subdomains=set(), status="empty", reason="no results")
