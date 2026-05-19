"""
HTTP probing of subdomains using httpx.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Tuple

import httpx


class HTTPProbeResult:
    __slots__ = ("is_live", "status_code", "title", "redirect_to", "protocol", "status")

    def __init__(
        self,
        is_live: bool,
        status_code: Optional[int],
        title: str | None,
        redirect_to: str | None = None,
        protocol: str | None = None,
    ):
        self.is_live = is_live
        self.status_code = status_code
        self.title = title or ""
        self.redirect_to = redirect_to or ""
        self.protocol = protocol or ""
        self.status = "active" if is_live else "inactive"


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SubFinderX/1.0"
)


def _is_live_status_code(status: Optional[int]) -> bool:
    if status is None:
        return False
    return 100 <= status <= 599


async def probe_host(
    client: httpx.AsyncClient,
    host: str,
    timeout: float = 8.0,
) -> HTTPProbeResult:
    """
    Probe a hostname over HTTP/HTTPS.

    Strategy:
      - Try HTTPS first, then HTTP if HTTPS fails.
      - Consider a host live when an HTTP response is received (any status).
    """

    async def _fetch(url: str) -> Optional[Tuple[int, str, str, str]]:
        try:
            resp = await client.get(
                url,
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            )
        except Exception:
            return None

        status = resp.status_code
        redirect_to = str(resp.url) if resp.history else ""

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
        return status, title, redirect_to, resp.url.scheme

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        res = await _fetch(url)
        if res:
            status, title, redirect_to, protocol = res
            is_live = _is_live_status_code(status)
            return HTTPProbeResult(is_live, status, title, redirect_to, protocol)

    return HTTPProbeResult(False, None, "", "", "")


async def bulk_probe(
    hosts: List[str],
    concurrency: int = 25,
    timeout: float = 8.0,
) -> Dict[str, HTTPProbeResult]:
    """
    Probe many hosts concurrently.
    """

    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, HTTPProbeResult] = {}

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        async def _worker(h: str) -> None:
            async with sem:
                results[h] = await probe_host(client, h, timeout=timeout)

        await asyncio.gather(*[_worker(h) for h in hosts])

    return results

