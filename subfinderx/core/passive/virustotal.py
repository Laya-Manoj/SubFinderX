"""
VirusTotal-based subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from subfinderx.core.utils.config import APIConfig
from subfinderx.core.utils.dedupe import dedupe_subdomains


VT_BASE_URL = "https://www.virustotal.com/api/v3"


async def fetch_virustotal(domain: str, api_cfg: APIConfig) -> Set[str]:
    """
    Enumerate subdomains using VirusTotal.

    This implementation uses the "siblings" relationship which, for
    a given domain, returns related subdomains belonging to the same
    zone. The exact visibility depends on your VT plan.
    """

    if not api_cfg.virustotal_api_key:
        return set()

    headers = {
        "x-apikey": api_cfg.virustotal_api_key,
        "User-Agent": api_cfg.user_agent,
    }

    subdomains: Set[str] = set()
    next_cursor: str | None = None

    async with httpx.AsyncClient(base_url=VT_BASE_URL, timeout=20.0, headers=headers) as client:
        while True:
            params = {}
            if next_cursor:
                params["cursor"] = next_cursor

            try:
                resp = await client.get(f"/domains/{domain}/siblings", params=params)
                resp.raise_for_status()
            except Exception:
                break

            try:
                data = resp.json()
            except Exception:
                break

            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                host = attrs.get("last_https_certificate", {}).get("subject", {}).get("CN")
                if host and host != domain:
                    subdomains.add(host)

                # Also use the id field which usually contains the domain.
                dom_id = item.get("id")
                if dom_id and dom_id != domain:
                    subdomains.add(dom_id)

            next_cursor = data.get("meta", {}).get("cursor")
            if not next_cursor:
                break

    return dedupe_subdomains(subdomains)

