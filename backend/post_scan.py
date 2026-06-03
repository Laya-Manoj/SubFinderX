"""
Post-scan enrichment: risk analysis and analytics.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict

from risk_analysis import apply_risk_analysis
from security_observation import apply_security_observations

logger = logging.getLogger("subfinderx.post_scan")

_SCREENSHOT_ENTRY_KEYS = ("screenshot_url", "screenshot_path")
_SCREENSHOT_RESULT_KEYS = ("screenshot_session", "scan_session")


def strip_screenshot_fields(result: Dict[str, Any]) -> Dict[str, Any]:
    """Ignore legacy screenshot metadata from older scan results."""
    for key in _SCREENSHOT_RESULT_KEYS:
        result.pop(key, None)
    for entry in result.get("subdomains", []):
        for key in _SCREENSHOT_ENTRY_KEYS:
            entry.pop(key, None)
    return result


def build_analytics(result: Dict[str, Any]) -> Dict[str, Any]:
    port_counts: Counter = Counter()
    for entry in result.get("subdomains", []):
        for port in entry.get("open_ports") or []:
            port_counts[str(port)] += 1

    classified = result.get("classified") or {}
    category_distribution = {key: len(hosts) for key, hosts in classified.items()}

    summary = result.get("scan_summary") or {}
    analytics = {
        "port_distribution": dict(port_counts.most_common(12)),
        "category_distribution": category_distribution,
        "status_breakdown": {
            "live": summary.get("live", 0),
            "inactive": summary.get("inactive", 0),
            "unverified": summary.get("unverified", 0),
        },
    }
    result["analytics"] = analytics
    return analytics


def enrich_scan_result(result: Dict[str, Any], scan_mode: str) -> Dict[str, Any]:
    """Apply risk scoring, security observations, and analytics."""
    logger.info("post-scan enrichment started (mode=%s)", scan_mode)
    apply_risk_analysis(result)
    apply_security_observations(result)
    build_analytics(result)
    logger.info(
        "post-scan enrichment completed: high=%d medium=%d low=%d",
        result.get("risk_summary", {}).get("high", 0),
        result.get("risk_summary", {}).get("medium", 0),
        result.get("risk_summary", {}).get("low", 0),
    )
    return strip_screenshot_fields(result)
