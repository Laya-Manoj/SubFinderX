"""
Shared HTTP retry helpers for passive enumeration sources.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger("subfinderx.passive")

RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_RETRIES = 4
DEFAULT_BASE_DELAY = 1.0


async def fetch_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    source: str = "unknown",
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    **kwargs: Any,
) -> httpx.Response | None:
    """
    Perform an HTTP request with exponential backoff on transient failures.

    Retries on HTTP 429, 500, 502, 503, 504 and common network errors.
    """

    last_response: httpx.Response | None = None

    for attempt in range(max_retries + 1):
        try:
            response = await client.request(method, url, **kwargs)
            last_response = response

            if response.status_code in RETRYABLE_STATUS_CODES:
                if attempt < max_retries:
                    delay = base_delay * (2**attempt)
                    logger.info(
                        "[passive] %s: HTTP %d, retry %d/%d in %.1fs",
                        source,
                        response.status_code,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.warning(
                    "[passive] %s: HTTP %d after %d retries",
                    source,
                    response.status_code,
                    max_retries,
                )
                return response

            logger.info("[passive] %s: HTTP %d", source, response.status_code)
            return response

        except (httpx.TimeoutException, httpx.NetworkError, httpx.ConnectError) as exc:
            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                logger.info(
                    "[passive] %s: network error (%s), retry %d/%d in %.1fs",
                    source,
                    exc,
                    attempt + 1,
                    max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            logger.warning(
                "[passive] %s: network error after %d retries: %s",
                source,
                max_retries,
                exc,
            )
            return None
        except httpx.HTTPError as exc:
            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                logger.info(
                    "[passive] %s: HTTP error (%s), retry %d/%d in %.1fs",
                    source,
                    exc,
                    attempt + 1,
                    max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
                continue
            logger.warning(
                "[passive] %s: HTTP error after %d retries: %s",
                source,
                max_retries,
                exc,
            )
            return None

    return last_response


async def fetch_get_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    source: str = "unknown",
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    **kwargs: Any,
) -> httpx.Response | None:
    """Convenience wrapper for GET requests with retry logic."""

    return await fetch_with_retry(
        client,
        "GET",
        url,
        source=source,
        max_retries=max_retries,
        base_delay=base_delay,
        **kwargs,
    )
