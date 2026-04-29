"""
Asynchronous DNS resolution helpers using dnspython.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple

import dns.asyncresolver
import dns.exception


async def resolve_host(host: str) -> Tuple[bool, List[str]]:
    """
    Resolve a hostname to A/AAAA/CNAME records.

    Returns (is_live, records).
    """

    resolver = dns.asyncresolver.Resolver()
    records: List[str] = []
    live = False

    for rtype in ("A", "AAAA", "CNAME"):
        for attempt in range(2):
            try:
                answer = await resolver.resolve(host, rtype, lifetime=5.0)
                for rr in answer:
                    records.append(f"{rtype} {rr.to_text()}")
                live = True
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                break
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                if attempt == 1:
                    break
                continue
            except Exception:
                break

    return live, records


async def bulk_resolve(hosts: List[str], concurrency: int = 25) -> Dict[str, Tuple[bool, List[str]]]:
    """
    Resolve many hosts concurrently with a semaphore.
    """

    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, Tuple[bool, List[str]]] = {}

    async def _worker(h: str) -> None:
        async with sem:
            is_live, recs = await resolve_host(h)
            results[h] = (is_live, recs)

    await asyncio.gather(*[_worker(h) for h in hosts])
    return results

