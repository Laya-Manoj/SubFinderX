"""
crt.sh Certificate Transparency enumeration.
"""

from __future__ import annotations

import asyncio
from typing import Iterable, Set

import httpx

from core.utils.config import APIConfig
from core.utils.dedupe import dedupe_subdomains


CRTURL_TEMPLATE = "https://crt.sh/?q=%25.{domain}&output=json"


async def fetch_crtsh(domain: str, api_cfg: APIConfig) -> Set[str]:
    """
    Query crt.sh for certificates issued for the target domain.

    Returns a set of normalized subdomains.
    """

    url = CRTURL_TEMPLATE.format(domain=domain)
    headers = {"User-Agent": api_cfg.user_agent}

    async with httpx.AsyncClient(timeout=35.0, headers=headers, follow_redirects=True) as client:
        resp = None
        for attempt in range(2):
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                break
            except Exception:
                if attempt == 1:
                    return set()
                continue

    try:
        if resp is None:
            return set()
        data = resp.json()
    except Exception:
        return set()

    candidates: Set[str] = set()
    for entry in data:
        # crt.sh may use "name_value" with line-separated DNS names
        name_val = entry.get("name_value") or ""
        for line in str(name_val).splitlines():
            line = line.strip()
            if line and line != domain:
                candidates.add(line)

    return dedupe_subdomains(candidates)

