"""
Shared types for passive enumeration sources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

import httpx


@dataclass(slots=True)
class SourceResult:
    """Outcome from a single passive source query."""

    subdomains: Set[str]
    status: str = "ok"
    reason: str = ""

    @classmethod
    def ok(cls, subdomains: Set[str]) -> SourceResult:
        if subdomains:
            return cls(subdomains=subdomains, status="ok")
        return cls(subdomains=set(), status="empty", reason="no results")

    @classmethod
    def unavailable(cls, reason: str) -> SourceResult:
        return cls(subdomains=set(), status="unavailable", reason=reason)

    @classmethod
    def skipped(cls, reason: str) -> SourceResult:
        return cls(subdomains=set(), status="skipped", reason=reason)

    @classmethod
    def cached(cls, subdomains: Set[str], reason: str) -> SourceResult:
        return cls(subdomains=subdomains, status="cached", reason=reason)

    @classmethod
    def from_http(
        cls,
        resp: httpx.Response | None,
        subdomains: Set[str],
        *,
        network_error: str = "",
    ) -> SourceResult:
        if resp is None:
            detail = network_error or "network error"
            return cls.unavailable(detail)
        if resp.status_code >= 400:
            return cls.unavailable(f"HTTP {resp.status_code}")
        return cls.ok(subdomains)

    def to_report_entry(self, source: str) -> Dict[str, Any]:
        return {
            "source": source,
            "status": self.status,
            "reason": self.reason,
            "count": len(self.subdomains),
        }


@dataclass(slots=True)
class PassiveEnumerationResult:
    """Aggregated passive enumeration output."""

    subdomains: Set[str]
    sources: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def combined_unique(self) -> int:
        return len(self.subdomains)
