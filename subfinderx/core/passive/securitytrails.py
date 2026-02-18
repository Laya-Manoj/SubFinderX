"""
SecurityTrails-based subdomain enumeration.
"""

from __future__ import annotations

from typing import Set

import httpx

from subfinderx.core.utils.config import APIConfig
from subfinderx.core.utils.dedupe import dedupe_subdomains


ST_BASE_URL = "https://api.securitytrails.com/v1"


async def fetch_securitytrails(domain: str, api_cfg: APIConfig) -> Set[str]:
    """
    Enumerate subdomains using the SecurityTrails public API.

    This implementation uses the documented subdomains endpoint:
      GET /domain/{domain}/subdomains
    """

    if not api_cfg.securitytrails_api_key:
        return set()

    headers = {
        "APIKEY": api_cfg.securitytrails_api_key,
        "User-Agent": api_cfg.user_agent,
    }

    async with httpx.AsyncClient(base_url=ST_BASE_URL, timeout=20.0, headers=headers) as client:
        try:
            resp = await client.get(f"/domain/{domain}/subdomains", params={"children_only": "false"})
            resp.raise_for_status()
        except Exception:
            return set()

    try:
        data = resp.json()
    except Exception:
        return set()

    subdomains: Set[str] = set()
    for label in data.get("subdomains", []):
        # SecurityTrails returns only the left-most label; reconstruct FQDN.
        fqdn = f"{label}.{domain}"
        subdomains.add(fqdn)

    return dedupe_subdomains(subdomains)

