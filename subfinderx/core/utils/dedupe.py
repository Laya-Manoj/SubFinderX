"""
Subdomain normalization and de-duplication helpers.
"""

from __future__ import annotations

import re
from typing import Iterable, Set

SUBDOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9_*~-]+\.)+[a-zA-Z]{2,}$")


def normalize_subdomain(name: str) -> str | None:
    """
    Normalize a subdomain string.

    - Lowercase
    - Strip surrounding whitespace and trailing dot
    - Basic sanity regex validation
    """

    if not name:
        return None

    candidate = name.strip().lower().rstrip(".")

    if not candidate:
        return None

    if not SUBDOMAIN_REGEX.match(candidate):
        return None

    return candidate


def dedupe_subdomains(subdomains: Iterable[str]) -> Set[str]:
    """
    Normalize and de-duplicate an iterable of subdomains.
    Invalid entries are silently discarded.
    """

    normalized: Set[str] = set()
    for item in subdomains:
        norm = normalize_subdomain(item)
        if norm:
            normalized.add(norm)
    return normalized

