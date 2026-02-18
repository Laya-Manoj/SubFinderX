"""
ProjectDiscovery Chaos-based subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from subfinderx.core.utils.config import APIConfig
from subfinderx.core.utils.dedupe import dedupe_subdomains


CHAOS_BASE_URL = "https://dns.projectdiscovery.io"


async def fetch_chaos(domain: str, api_cfg: APIConfig) -> Set[str]:
    """
    Enumerate subdomains using ProjectDiscovery Chaos API.

    Requires SUBHUNTER_CHAOS_API_KEY to be set.
    """

    if not api_cfg.chaos_api_key:
        return set()

    headers = {
        "Authorization": api_cfg.chaos_api_key,
        "User-Agent": api_cfg.user_agent,
    }

    async with httpx.AsyncClient(base_url=CHAOS_BASE_URL, timeout=20.0, headers=headers) as client:
        try:
            resp = await client.get(f"/dns/{domain}/subdomains")
            resp.raise_for_status()
        except Exception:
            return set()

    try:
        data = resp.json()
    except Exception:
        return set()

    subs = data.get("subdomains") or []
    fqdn_list = [f"{s}.{domain}" for s in subs]
    return dedupe_subdomains(fqdn_list)

