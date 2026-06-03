"""
Human-readable security observations for discovered subdomains.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

ADMIN_KEYWORDS = (
    "admin",
    "login",
    "signin",
    "sign-in",
    "auth",
    "dashboard",
    "portal",
    "cpanel",
    "manage",
    "wp-admin",
)

DEV_KEYWORDS = (
    "dev",
    "staging",
    "stage",
    "test",
    "uat",
    "qa",
    "sandbox",
    "preview",
    "beta",
    "demo",
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

WARN_PHRASES = (
    "administrative",
    "development or staging",
    "missing important browser",
    "misconfigured",
    "high-risk",
    "exposed",
)


def _status_code(entry: Dict[str, Any]) -> int | None:
    status = entry.get("status") or entry.get("http_status")
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _open_port_set(entry: Dict[str, Any]) -> set[int]:
    ports: set[int] = set()
    for port in entry.get("open_ports") or []:
        try:
            ports.add(int(port))
        except (TypeError, ValueError):
            continue
    return ports


def _is_live(entry: Dict[str, Any]) -> bool:
    label = str(entry.get("status_label", "")).lower()
    return label == "active" or bool(entry.get("is_live"))


def _observation_level(observations: List[str]) -> str:
    text = " ".join(observations).lower()
    if any(phrase in text for phrase in WARN_PHRASES):
        return "warn"
    if observations:
        return "info"
    return "neutral"


def compute_security_observation(entry: Dict[str, Any]) -> Dict[str, str]:
    """Return security_observation text and security_observation_level (warn|info|neutral)."""
    label = str(entry.get("status_label", "")).lower()

    if label == "unverified":
        return {
            "security_observation": "Host discovered; HTTP response not yet confirmed.",
            "security_observation_level": "neutral",
        }

    if not _is_live(entry):
        return {
            "security_observation": "Host discovered but currently unresponsive.",
            "security_observation_level": "neutral",
        }

    name = str(entry.get("name", "")).lower()
    title = str(entry.get("title", "")).lower()
    missing = entry.get("security_headers", {}).get("missing_headers") or []
    ports = _open_port_set(entry)
    status = _status_code(entry)
    observations: List[str] = []

    if any(keyword in name for keyword in ADMIN_KEYWORDS) or any(
        keyword in title for keyword in LOGIN_TITLE_KEYWORDS
    ):
        observations.append("Potential administrative interface detected.")

    if any(keyword in name for keyword in DEV_KEYWORDS):
        observations.append("Possible development or staging environment exposed.")

    if len(missing) >= 2:
        observations.append("Missing important browser security protections.")

    if 80 in ports and 443 in ports:
        observations.append("Public web service exposed over HTTP/HTTPS.")

    if status is not None:
        if status >= 500:
            observations.append("Server returned an error response; service may be misconfigured.")
        elif status in (401, 403):
            observations.append("Access-restricted page detected.")

    if not observations:
        return {
            "security_observation": "No major exposure indicators detected.",
            "security_observation_level": "neutral",
        }

    return {
        "security_observation": " ".join(observations),
        "security_observation_level": _observation_level(observations),
    }


def apply_security_observations(result: Dict[str, Any]) -> Dict[str, Any]:
    """Annotate every subdomain entry with security_observation fields."""
    for entry in result.get("subdomains", []):
        entry.update(compute_security_observation(entry))
    return result
