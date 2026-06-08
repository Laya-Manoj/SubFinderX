"""
DNSDumpster passive subdomain enumeration via the current HTMX API.
"""

from __future__ import annotations

import re

import httpx

from core.passive.helpers import browser_headers, filter_for_domain, parse_dnsdumpster_html
from core.passive.types import SourceResult
from core.utils.config import APIConfig
from core.utils.http_retry import fetch_with_retry

DNSDUMPSTER_URL = "https://dnsdumpster.com/"
DNSDUMPSTER_API_URL = "https://api.dnsdumpster.com/htmld/"
_TOKEN_RE = re.compile(r'hx-headers=\'\{"Authorization":\s*"([^"]+)"\}\'')


async def fetch_dnsdumpster(domain: str, api_cfg: APIConfig, *, max_retries: int = 4) -> SourceResult:
    """Fetch DNSDumpster results using the embedded session token from the landing page."""

    headers = browser_headers(api_cfg)
    headers["Referer"] = DNSDUMPSTER_URL

    async with httpx.AsyncClient(timeout=40.0, headers=headers, follow_redirects=True) as client:
        page_resp = await fetch_with_retry(
            client,
            "GET",
            DNSDUMPSTER_URL,
            source="dnsdumpster",
            max_retries=max_retries,
        )
        if page_resp is None:
            return SourceResult.unavailable("network error")
        if page_resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {page_resp.status_code}")

        token_match = _TOKEN_RE.search(page_resp.text)
        if not token_match:
            return SourceResult.unavailable("authorization token not found")

        api_headers = {
            **headers,
            "Authorization": token_match.group(1),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        post_resp = await fetch_with_retry(
            client,
            "POST",
            DNSDUMPSTER_API_URL,
            source="dnsdumpster",
            max_retries=max_retries,
            headers=api_headers,
            data={"target": domain},
        )
        if post_resp is None:
            return SourceResult.unavailable("network error")
        if post_resp.status_code >= 400:
            return SourceResult.unavailable(f"HTTP {post_resp.status_code}")

    normalized = filter_for_domain(parse_dnsdumpster_html(post_resp.text, domain), domain)
    return SourceResult.ok(normalized)
