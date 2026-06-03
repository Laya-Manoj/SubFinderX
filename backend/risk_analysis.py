"""
Lightweight risk scoring for discovered live subdomains.
"""

from __future__ import annotations

from typing import Any, Dict, List

PRIMARY_KEYWORDS = ("admin", "api", "dev", "staging", "internal", "test")
HIGH_RISK_KEYWORDS = ("admin", "dev", "staging", "internal")
UNUSUAL_PORTS = {21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5432, 6379, 8080, 8443}

_LEVEL_SCORE = {"High": 7, "Medium": 4, "Low": 1}


def _status_code(entry: Dict[str, Any]) -> int | None:
    status = entry.get("status") or entry.get("http_status")
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _is_http_accessible(entry: Dict[str, Any], status: int | None) -> bool:
    if entry.get("is_live") or entry.get("status_label") == "active":
        return True
    return status is not None and 200 <= status < 400


def _port_ints(open_ports: List[Any]) -> List[int]:
    ports: List[int] = []
    for port in open_ports:
        try:
            ports.append(int(port))
        except (TypeError, ValueError):
            continue
    return ports


def compute_risk(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Return risk_level, risk_score, and risk_factors for a live subdomain entry."""
    name = str(entry.get("name", "")).lower()
    missing = entry.get("security_headers", {}).get("missing_headers") or []
    ports = _port_ints(entry.get("open_ports") or [])
    status = _status_code(entry)

    missing_count = len(missing)
    port_count = len(ports)
    sensitive = any(keyword in name for keyword in PRIMARY_KEYWORDS)
    high_keyword = any(keyword in name for keyword in HIGH_RISK_KEYWORDS)
    unusual_port = any(port in UNUSUAL_PORTS for port in ports)
    http_accessible = _is_http_accessible(entry, status)

    factors: List[str] = []
    level = "Low"

    if http_accessible:
        factors.append("HTTP-accessible host")

    if high_keyword and missing_count >= 2 and port_count >= 2:
        level = "High"
        factors.append("Sensitive environment with weak headers and multiple exposed ports")
    elif high_keyword and missing_count >= 2:
        level = "High"
        factors.append("Sensitive keyword with multiple missing security headers")
    elif sensitive and missing_count >= 2 and (port_count >= 2 or unusual_port):
        level = "High"
        factors.append("Sensitive host with header gaps and unusual exposure")
    elif missing_count >= 3:
        level = "Medium"
        factors.append(f"{missing_count} missing security header(s)")
    elif sensitive and missing_count >= 1:
        level = "Medium"
        factors.append("Sensitive keyword with missing security headers")
    elif port_count >= 2 or unusual_port:
        level = "Medium"
        factors.append("Multiple or unusual open ports detected")
    elif http_accessible and missing_count >= 2:
        level = "Medium"
        factors.append("Live host with several missing security headers")

    if sensitive and "Sensitive keyword" not in " ".join(factors):
        factors.append("Sensitive keyword in subdomain name")
    if unusual_port and "unusual" not in " ".join(factors).lower():
        factors.append("Unusual service port exposed")

    return {
        "risk_level": level,
        "risk_score": _LEVEL_SCORE[level],
        "risk_factors": factors[:6],
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
