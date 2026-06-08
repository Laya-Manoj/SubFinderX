"""
File-based cache for passive enumeration results (24-hour TTL).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Set

logger = logging.getLogger("subfinderx.passive")

CACHE_TTL_SECONDS = 24 * 60 * 60
_DEFAULT_CACHE_DIR = Path.home() / ".subfinderx" / "passive_cache"


def _cache_dir() -> Path:
    override = os.getenv("SUBHUNTER_CACHE_DIR")
    if override:
        return Path(override)
    return _DEFAULT_CACHE_DIR


def _safe_key(domain: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", domain.lower())


def _cache_path(source: str, domain: str) -> Path:
    return _cache_dir() / f"{source}_{_safe_key(domain)}.json"


def save(source: str, domain: str, subdomains: Set[str]) -> None:
    """Persist passive results for a source/domain pair."""

    if not subdomains:
        return

    path = _cache_path(source, domain)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "source": source,
            "domain": domain.lower(),
            "cached_at": time.time(),
            "subdomains": sorted(subdomains),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError as exc:
        logger.debug("[passive] cache write failed for %s/%s: %s", source, domain, exc)


def load(source: str, domain: str) -> Set[str] | None:
    """Load cached subdomains if present and not expired."""

    path = _cache_path(source, domain)
    if not path.is_file():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    cached_at = payload.get("cached_at", 0)
    if time.time() - cached_at > CACHE_TTL_SECONDS:
        return None

    items = payload.get("subdomains") or []
    return set(items)


def has_valid(source: str, domain: str) -> bool:
    """Return True when a non-expired cache entry exists."""

    return load(source, domain) is not None
