"""
Wrapper around existing SubFinderX modules for web API scans.
"""

from __future__ import annotations
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import asyncio
import socket
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Iterable, List, Set

import httpx

from core.active.bruteforce import brute_force
from core.active.http_probe import bulk_probe
from core.passive.chaos import fetch_chaos
from core.passive.crtsh import fetch_crtsh
from core.passive.securitytrails import fetch_securitytrails
from core.passive.virustotal import fetch_virustotal
from core.passive.wayback import fetch_wayback
from core.utils.config import RuntimeConfig, load_api_config
from core.utils.dedupe import dedupe_subdomains

# Keep scans lightweight and ethical by default.
MAX_SUBDOMAINS = 400
MAX_BRUTEFORCE_WORDS = 5000
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 8080]
PORT_TIMEOUT_SECONDS = 0.5
LIVE_ANALYSIS_LIMIT = 15
DEFAULT_WORDLIST_PATH = Path(__file__).parent / "wordlists" / "default_wordlist.txt"
FALLBACK_WORDS = ["www", "api", "app", "admin", "portal", "dev", "staging", "test", "mail", "cdn"]
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def classify_subdomain(name: str) -> str:
    lowered = name.lower()
    if "admin" in lowered:
        return "admin"
    if "api" in lowered:
        return "api"
    if "dev" in lowered or "test" in lowered:
        return "dev"
    return "others"


def scan_common_ports(domain: str) -> Dict[str, List[int]]:
    """Lightweight common port scan with short socket timeout."""
    open_ports: List[int] = []
    closed_ports: List[int] = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT_SECONDS)
        try:
            if sock.connect_ex((domain, port)) == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)
        except OSError:
            closed_ports.append(port)
        finally:
            sock.close()
    return {"open_ports": sorted(open_ports), "closed_ports": sorted(closed_ports)}


async def analyze_security_headers(url: str) -> Dict[str, Any]:
    """Analyze key security headers from an HTTP response."""
    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = None
        for target_url in (url, url.replace("https://", "http://")):
            try:
                response = await client.get(target_url, timeout=6.0)
                break
            except Exception:
                continue

    if response is None:
        return {"headers_present": {}, "missing_headers": list(SECURITY_HEADERS)}

    present = {header: bool(response.headers.get(header)) for header in SECURITY_HEADERS}
    missing = [header for header, exists in present.items() if not exists]
    return {"headers_present": present, "missing_headers": missing}


async def run_scan(
    domain: str,
    authorized: bool,
    include_bruteforce: bool = True,
    scan_mode: str = "quick",
    wordlist_path: str | None = None,
    user_wordlist_lines: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Run a complete scan by reusing existing SubFinderX modules.
    """
    if not authorized:
        raise PermissionError("Scanning allowed only on authorized targets")

    api_cfg = load_api_config()
    rt_cfg = RuntimeConfig(domain=domain.strip().lower(), concurrency=20, silent=True)
    normalized_mode = (scan_mode or "quick").strip().lower()
    brute_force_enabled = include_bruteforce and normalized_mode == "full"

    passive_subs = await enumerate_passive(rt_cfg.domain, api_cfg, rt_cfg)
    source_map: Dict[str, Set[str]] = defaultdict(set)
    for host in passive_subs:
        source_map[host].add("passive")

    all_subs = set(passive_subs)
    if brute_force_enabled:
        brute_subs, wordlist_meta = await run_bruteforce_with_wordlists(
            domain=rt_cfg.domain,
            user_wordlist_lines=user_wordlist_lines or [],
            wordlist_path=wordlist_path,
            concurrency=20,
        )
        all_subs.update(brute_subs)
        for host in brute_subs:
            source_map[host].add("brute-force")
    else:
        wordlist_meta = {"used_default": False, "custom_entries": 0, "combined_entries": 0}

    discovered_subs = sorted(dedupe_subdomains(all_subs))
    print(f"[scan] discovered total subdomains before HTTP probing: {len(discovered_subs)}")
    http_results = await bulk_probe(discovered_subs, concurrency=20) if discovered_subs else {}

    # LIVE is based only on successful HTTP responses in the 2xx-3xx range.
    http_live_hosts = [host for host in discovered_subs if (http_results.get(host) and http_results[host].is_live)]

    analysis_targets = http_live_hosts[:LIVE_ANALYSIS_LIMIT]
    port_details: Dict[str, Dict[str, List[int]]] = {}
    security_headers: Dict[str, Dict[str, Any]] = {}

    if analysis_targets:
        port_results = await asyncio.gather(*(asyncio.to_thread(scan_common_ports, host) for host in analysis_targets))
        port_details = {host: result for host, result in zip(analysis_targets, port_results, strict=False)}
        header_results = await asyncio.gather(*(analyze_security_headers(f"https://{host}") for host in analysis_targets))
        security_headers = {host: result for host, result in zip(analysis_targets, header_results, strict=False)}

    status_codes = Counter()
    live_subdomains: List[Dict[str, Any]] = []
    dead_subdomains: List[str] = []
    subdomains: List[Dict[str, Any]] = []
    classified: Dict[str, List[str]] = defaultdict(list)

    for sub in discovered_subs:
        http_info = http_results.get(sub)
        is_live = bool(http_info and http_info.is_live)

        if is_live:
            if http_info and http_info.status_code:
                status_codes[str(http_info.status_code)] += 1
            live_subdomains.append(
                {
                    "name": sub,
                    "status": http_info.status_code if http_info else None,
                    "title": http_info.title if http_info else "",
                    "open_ports": port_details.get(sub, {}).get("open_ports", []),
                    "closed_ports": port_details.get(sub, {}).get("closed_ports", []),
                    "security_headers": security_headers.get(
                        sub, {"headers_present": {}, "missing_headers": list(SECURITY_HEADERS)}
                    ),
                    "redirect_to": http_info.redirect_to if http_info else "",
                    "source": sorted(source_map.get(sub, {"passive"})),
                    "is_live": True,
                }
            )
        else:
            dead_subdomains.append(sub)

        subdomains.append(
            {
                "name": sub,
                "status": http_info.status_code if http_info else None,
                "title": http_info.title if http_info else "",
                "open_ports": port_details.get(sub, {}).get("open_ports", []),
                "closed_ports": port_details.get(sub, {}).get("closed_ports", []),
                "security_headers": security_headers.get(
                    sub, {"headers_present": {}, "missing_headers": list(SECURITY_HEADERS)}
                ),
                "redirect_to": http_info.redirect_to if http_info else "",
                "source": sorted(source_map.get(sub, {"passive"})),
                "is_live": is_live,
            }
        )

        classified[classify_subdomain(sub)].append(sub)

    brute_force_count = len([s for s in discovered_subs if "brute-force" in source_map.get(s, set())])
    passive_count = len([s for s in discovered_subs if "passive" in source_map.get(s, set())])

    return {
        "domain": rt_cfg.domain,
        "scan_mode": normalized_mode,
        "scanned_at": datetime.utcnow().isoformat(),
        "total_subdomains": len(discovered_subs),
        "live_subdomains": live_subdomains,
        "dead_subdomains": sorted(dead_subdomains),
        "brute_force_count": brute_force_count,
        "passive_count": passive_count,
        "subdomains": subdomains,
        "status_codes": dict(status_codes),
        "analyzed_live_subdomains": len(analysis_targets),
        "wordlist": wordlist_meta,
        "classified": {
            "admin": sorted(classified["admin"]),
            "api": sorted(classified["api"]),
            "dev": sorted(classified["dev"]),
            "others": sorted(classified["others"]),
        },
    }


async def enumerate_passive(domain: str, api_cfg, rt_cfg: RuntimeConfig):
    # Keep crt.sh as required fallback and always execute it.
    sources = {
        "crtsh": fetch_crtsh(domain, api_cfg),
        "wayback": fetch_wayback(domain, api_cfg),
        "chaos": fetch_chaos(domain, api_cfg),
        "virustotal": fetch_virustotal(domain, api_cfg),
        "securitytrails": fetch_securitytrails(domain, api_cfg),
    }
    names = list(sources.keys())
    results = await asyncio.gather(*sources.values(), return_exceptions=True)

    all_subdomains = set()
    crtsh_subs = set()
    for source_name, result in zip(names, results, strict=False):
        if isinstance(result, Exception):
            print(f"[passive] {source_name}: failed ({result})")
            continue
        source_subs = set(result)
        print(f"[passive] {source_name}: {len(source_subs)} results")
        all_subdomains.update(source_subs)
        if source_name == "crtsh":
            crtsh_subs = source_subs

    # Retry crt.sh once if the first attempt had no usable data.
    if not crtsh_subs:
        retry_crtsh = await fetch_crtsh(domain, api_cfg)
        print(f"[passive] crtsh retry: {len(retry_crtsh)} results")
        all_subdomains.update(retry_crtsh)

    final_passive = dedupe_subdomains(all_subdomains)
    print(f"[passive] combined unique: {len(final_passive)}")
    return final_passive


def _normalize_wordlist_lines(lines: Iterable[str]) -> List[str]:
    cleaned: List[str] = []
    for line in lines:
        candidate = line.strip().lower()
        if not candidate or candidate.startswith("#"):
            continue
        cleaned.append(candidate)
    return cleaned


def _load_default_wordlist() -> List[str]:
    if not DEFAULT_WORDLIST_PATH.exists():
        print("[bruteforce] default wordlist missing, using in-code fallback list")
        return list(FALLBACK_WORDS)
    return _normalize_wordlist_lines(DEFAULT_WORDLIST_PATH.read_text(encoding="utf-8").splitlines())


async def run_bruteforce_with_wordlists(
    domain: str,
    user_wordlist_lines: List[str],
    wordlist_path: str | None,
    concurrency: int,
) -> tuple[Set[str], Dict[str, Any]]:
    default_lines = _load_default_wordlist()
    custom_lines = _normalize_wordlist_lines(user_wordlist_lines)

    if wordlist_path:
        path = Path(wordlist_path)
        if path.exists():
            custom_lines.extend(_normalize_wordlist_lines(path.read_text(encoding="utf-8").splitlines()))

    combined = []
    seen = set()
    for item in default_lines + custom_lines:
        if item in seen:
            continue
        seen.add(item)
        combined.append(item)

    if not combined:
        return set(), {"used_default": False, "custom_entries": 0, "combined_entries": 0}

    combined = combined[:MAX_BRUTEFORCE_WORDS]
    print(f"[bruteforce] generated candidates from wordlist: {len(combined)}")

    with NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as tmp_file:
        tmp_file.write("\n".join(combined))
        tmp_path = tmp_file.name

    try:
        brute_subs = await brute_force(domain, tmp_path, concurrency=concurrency)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    print(f"[bruteforce] resolved domains: {len(brute_subs)}")

    return brute_subs, {
        "used_default": bool(default_lines),
        "custom_entries": len(custom_lines),
        "combined_entries": len(combined),
    }
