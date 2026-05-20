"""
Risk scoring for discovered live subdomains.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

SENSITIVE_KEYWORDS = (
    "admin",
    "dev",
    "test",
    "uat",
    "staging",
    "intranet",
    "portal",
    "dashboard",
    "api",
    "internal",
    "vpn",
    "jenkins",
    "grafana",
    "kibana",
)

LOGIN_TITLE_KEYWORDS = (
    "login",
    "log in",
    "sign in",
    "signin",
    "authentication",
    "authenticate",
    "sso",
    "password",
    "portal access",
)

INTERNAL_PATTERNS = (
    "intranet",
    "internal",
    "corp",
    "local",
    "private",
    "vpn",
    "adfs",
)

RISKY_PORTS = {21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5432, 6379, 8080, 8443}
HIGH_RISK_PORTS = {22, 445, 3389, 3306, 6379}


def _status_code(entry: Dict[str, Any]) -> int | None:
    status = entry.get("status") or entry.get("http_status")
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def compute_risk(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return risk_level, risk_score, and risk_factors for a subdomain entry."""
    score = 0
    factors: List[str] = []
    name = str(entry.get("name", "")).lower()
    title = str(entry.get("title", "")).lower()
    missing = entry.get("security_headers", {}).get("missing_headers") or []
    open_ports = entry.get("open_ports") or []
    status = _status_code(entry)

    for keyword in SENSITIVE_KEYWORDS:
        if keyword in name:
            score += 2
            factors.append(f"Sensitive keyword: {keyword}")
            break

    for pattern in INTERNAL_PATTERNS:
        if pattern in name:
            score += 2
            factors.append(f"Internal naming pattern: {pattern}")
            break

    for keyword in LOGIN_TITLE_KEYWORDS:
        if keyword in title:
            score += 2
            factors.append("Login-related page title")
            break

    if missing:
        score += min(3, len(missing))
        factors.append(f"{len(missing)} missing security header(s)")

    if open_ports:
        score += 1
        factors.append(f"{len(open_ports)} exposed port(s)")
        if any(int(p) in HIGH_RISK_PORTS for p in open_ports):
            score += 2
            factors.append("High-risk service port exposed")
        elif any(int(p) in RISKY_PORTS for p in open_ports):
            score += 1
            factors.append("Risky service port exposed")

    if status is not None:
        if status in (401, 403):
            score += 2
            factors.append(f"Restricted HTTP status ({status})")
        elif status >= 500:
            score += 1
            factors.append(f"Server error status ({status})")
        elif status == 200 and not missing:
            score = max(0, score - 1)

    if score >= 7:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_level": level,
        "risk_score": score,
        "risk_factors": factors[:8],
    }


def apply_risk_analysis(result: Dict[str, Any]) -> Dict[str, Any]:
    """Annotate all subdomains with risk data and populate risk_summary."""
    risk_summary = {"high": 0, "medium": 0, "low": 0}
    live_subdomains: List[Dict[str, Any]] = []

    for entry in result.get("subdomains", []):
        is_live = entry.get("status_label") == "active" or entry.get("is_live")
        if is_live:
            risk = compute_risk(entry)
            entry.update(risk)
            key = risk["risk_level"].lower()
            risk_summary[key] = risk_summary.get(key, 0) + 1
            live_subdomains.append(entry)
        else:
            entry["risk_level"] = "N/A"
            entry["risk_score"] = 0
            entry["risk_factors"] = []

    result["risk_summary"] = risk_summary
    result["live_subdomains"] = live_subdomains

    scan_summary = result.setdefault("scan_summary", {})
    scan_summary["high_risk"] = risk_summary["high"]
    scan_summary["medium_risk"] = risk_summary["medium"]
    scan_summary["low_risk"] = risk_summary["low"]

    return result
