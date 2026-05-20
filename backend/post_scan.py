"""
Post-scan enrichment: risk analysis, analytics, screenshots.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict

from risk_analysis import apply_risk_analysis
from screenshot_capture import capture_screenshots_for_scan

logger = logging.getLogger("subfinderx.post_scan")

SCREENSHOT_BUDGET_QUICK = 18.0
SCREENSHOT_BUDGET_FULL = 45.0


def _session_id(result: Dict[str, Any]) -> str:
    domain = re.sub(r"[^a-zA-Z0-9._-]+", "_", result.get("domain", "scan"))
    ts = (result.get("scanned_at") or datetime.utcnow().isoformat())[:19]
    ts = ts.replace(":", "").replace("-", "").replace("T", "_")
    return f"{domain}_{ts}"


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


async def enrich_scan_result(result: Dict[str, Any], scan_mode: str) -> Dict[str, Any]:
    """
    Apply risk scoring, analytics, and optional screenshots without failing the scan.
    """
    session_id = _session_id(result)
    result["scan_session"] = session_id

    logger.info("risk analysis started")
    apply_risk_analysis(result)
    build_analytics(result)
    logger.info(
        "risk analysis completed: high=%d medium=%d low=%d",
        result.get("risk_summary", {}).get("high", 0),
        result.get("risk_summary", {}).get("medium", 0),
        result.get("risk_summary", {}).get("low", 0),
    )

    budget = SCREENSHOT_BUDGET_QUICK if scan_mode == "quick" else SCREENSHOT_BUDGET_FULL
    try:
        await asyncio.wait_for(
            capture_screenshots_for_scan(result, session_id, scan_mode),
            timeout=budget,
        )
    except asyncio.TimeoutError:
        logger.warning("screenshot capture timed out after %.0fs", budget)
    except Exception as exc:
        logger.warning("screenshot capture error: %s", exc)

    return result
