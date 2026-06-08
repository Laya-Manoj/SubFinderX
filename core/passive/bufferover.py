"""
BufferOver passive subdomain enumeration.

The BufferOver free API now requires an x-api-key header. Request a free key at
https://tls.bufferover.run/ and set SUBHUNTER_BUFFEROVER_API_KEY.
"""

from __future__ import annotations

from typing import Iterable, Set

import httpx

from core.passive.helpers import browser_headers, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.dedupe import dedupe_subdomains
from core.utils.http_retry import fetch_get_with_retry

BUFFEROVER_ENDPOINTS = (
    "https://tls.bufferover.run/dns?q=.{domain}",
    "https://dns.bufferover.run/dns?q=.{domain}",
)


def _extract_hosts(domain: str, rows: Iterable) -> Set[str]:
    hosts: Set[str] = set()
    for row in rows:
        if not isinstance(row, str):
            continue
        host = row.split(",", 1)[0].strip().lower()
        if host and host != domain and host.endswith(f".{domain}"):
            hosts.add(host)
    return hosts


async def fetch_bufferover(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query BufferOver TLS and FDNS endpoints for subdomains."""

    headers = browser_headers(api_cfg)
    if api_cfg.bufferover_api_key:
        headers["x-api-key"] = api_cfg.bufferover_api_key
    else:
        return SourceResult.skipped(
            "SUBHUNTER_BUFFEROVER_API_KEY not set (free key required at tls.bufferover.run)"
        )

    candidates: Set[str] = set()
    last_reason = "all endpoints failed"
    last_status: int | None = None

    async with httpx.AsyncClient(timeout=25.0, headers=headers, follow_redirects=True) as client:
        for template in BUFFEROVER_ENDPOINTS:
            url = template.format(domain=domain)
            try:
                resp = await fetch_get_with_retry(
                    client,
                    url,
                    source="bufferover",
                    max_retries=max_retries,
                )
            except httpx.HTTPError as exc:
                last_reason = f"connection error: {exc}"
                continue

            if resp is None:
                last_reason = "network error"
                continue

            last_status = resp.status_code
            if resp.status_code >= 400:
                last_reason = f"HTTP {resp.status_code}"
                continue

            try:
                data = resp.json()
            except Exception:
                last_reason = "invalid JSON response"
                continue

            for key in ("Results", "FDNS_A", "RDNS"):
                rows = data.get(key) or []
                candidates.update(_extract_hosts(domain, rows))

    normalized = filter_for_domain(candidates, domain)
    if normalized:
        return SourceResult.ok(normalized)

    if last_status is not None:
        return SourceResult.unavailable(last_reason)
    return SourceResult.unavailable(last_reason)
