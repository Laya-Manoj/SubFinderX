"""
HTTP probing of subdomains using httpx.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Tuple

import httpx


class HTTPProbeResult:
    __slots__ = ("is_live", "status_code", "title", "redirect_to")

    def __init__(
        self,
        is_live: bool,
        status_code: Optional[int],
        title: str | None,
        redirect_to: str | None = None,
    ):
        self.is_live = is_live
        self.status_code = status_code
        self.title = title or ""
        self.redirect_to = redirect_to or ""


async def probe_host(client: httpx.AsyncClient, host: str) -> HTTPProbeResult:
    """
    Probe a hostname over HTTP/HTTPS.

    Strategy:
      - Try HTTPS first, then HTTP if HTTPS fails.
      - Consider a host live if any request returns a status code.
    """

    async def _fetch(url: str) -> Optional[Tuple[int, str, str]]:
        resp = None
        for attempt in range(2):
            try:
                # Keep redirects visible for analysis and reporting.
                resp = await client.get(url, timeout=6.0, follow_redirects=False)
                break
            except Exception:
                if attempt == 1:
                    return None
                continue

        if resp is None:
            return None

        status = resp.status_code
        redirect_to = ""
        if 300 <= status <= 399:
            location = resp.headers.get("location", "")
            if location:
                try:
                    redirect_to = str(resp.url.join(location))
                except Exception:
                    redirect_to = location

        # Simple title extraction to avoid BS4 dependency.
        title = ""
        try:
            text = await resp.aread()
            snippet = text.decode(errors="ignore")[:4096]
            start = snippet.lower().find("<title>")
            end = snippet.lower().find("</title>")
            if start != -1 and end != -1 and end > start:
                title = snippet[start + 7 : end].strip()
        except Exception:
            title = ""
        return status, title, redirect_to

    # Prefer HTTPS.
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        res = await _fetch(url)
        if res:
            status, title, redirect_to = res
            is_live = 200 <= status <= 399
            return HTTPProbeResult(is_live, status, title, redirect_to)

    return HTTPProbeResult(False, None, "", "")


async def bulk_probe(hosts: List[str], concurrency: int = 25) -> Dict[str, HTTPProbeResult]:
    """
    Probe many hosts concurrently.
    """

    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, HTTPProbeResult] = {}

    async with httpx.AsyncClient() as client:
        async def _worker(h: str) -> None:
            async with sem:
                results[h] = await probe_host(client, h)

        await asyncio.gather(*[_worker(h) for h in hosts])

    return results

