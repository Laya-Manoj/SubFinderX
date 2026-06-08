"""
Anubis (jldc.me) passive subdomain enumeration.
"""

from __future__ import annotations

import httpx

from core.passive.helpers import BROWSER_USER_AGENT, filter_for_domain
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_get_with_retry

ANUBIS_URL = "https://jldc.me/anubis/subdomains/{domain}"


async def fetch_anubis(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Query the Anubis public subdomain database."""

    url = ANUBIS_URL.format(domain=domain)
    headers = {
        "User-Agent": BROWSER_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://jldc.me/",
    }

    async with httpx.AsyncClient(timeout=25.0, headers=headers, follow_redirects=True) as client:
        resp = await fetch_get_with_retry(client, url, source="anubis", max_retries=max_retries)
        if resp is None:
            return SourceResult.unavailable("network error")
        if resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {resp.status_code}")

        try:
            labels = resp.json()
        except Exception:
            return SourceResult.unavailable("invalid JSON response")

    if not isinstance(labels, list):
        return SourceResult(subdomains=set(), status="empty", reason="no results")

    fqdn_list = []
    for label in labels:
        if not isinstance(label, str):
            continue
        label = label.strip().lower()
        if not label:
            continue
        if label.endswith(f".{domain}"):
            fqdn_list.append(label)
        else:
            fqdn_list.append(f"{label}.{domain}")

    return SourceResult.ok(filter_for_domain(fqdn_list, domain))
