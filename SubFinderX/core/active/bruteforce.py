"""
Async brute-force subdomain enumeration via wordlist + DNS resolution.

Reads a wordlist, builds candidates as subdomain.{domain}, resolves each
with dnspython, and returns only successfully resolved hosts.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Set

from subfinderx.core.active.dns_resolve import resolve_host


def load_wordlist(path: str | Path) -> list[str]:
    """
    Load and normalize wordlist lines (strip, lowercase, skip empty).
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    lines: list[str] = []
    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                lines.append(word)
    return lines


async def brute_force(
    domain: str,
    wordlist_path: str | Path,
    concurrency: int = 25,
) -> Set[str]:
    """
    Enumerate subdomains by appending each wordlist entry to domain,
    resolving via DNS, and returning only hosts that resolve successfully.

    - domain: base domain (e.g. example.com)
    - wordlist_path: path to file with one subdomain label per line
    - concurrency: max concurrent DNS lookups

    Returns a set of resolved subdomain FQDNs (e.g. www.example.com).
    """
    domain = domain.strip().lower().rstrip(".")
    words = load_wordlist(wordlist_path)
    candidates = [f"{w}.{domain}" for w in words]

    if not candidates:
        return set()

    sem = asyncio.Semaphore(concurrency)
    resolved: Set[str] = set()

    async def _resolve(host: str) -> None:
        async with sem:
            is_live, _ = await resolve_host(host)
            if is_live:
                resolved.add(host)

    await asyncio.gather(*[_resolve(h) for h in candidates])
    return resolved
