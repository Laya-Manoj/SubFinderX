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
DEFAULT_PORTS = [80, 443, 8080, 8443, 22]
PORT_TIMEOUT_SECONDS = 1.0
DEFAULT_WORDLIST_PATH = Path(__file__).parent / "wordlists" / "default_wordlist.txt"
FALLBACK_WORDS = ["www", "api", "app", "admin", "portal", "dev", "staging", "test", "mail", "cdn"]


def classify_subdomain(name: str) -> str:
    lowered = name.lower()
    if "admin" in lowered:
        return "admin"
    if "api" in lowered:
        return "api"
    if "dev" in lowered or "test" in lowered:
        return "dev"
    return "others"


async def scan_ports(host: str, ports: List[int] | None = None) -> List[int]:
    """Perform a lightweight async TCP connect scan."""
    open_ports: List[int] = []
    target_ports = ports or DEFAULT_PORTS

    async def check_port(port: int) -> None:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=PORT_TIMEOUT_SECONDS)
            writer.close()
            await writer.wait_closed()
            _ = reader
            open_ports.append(port)
        except (asyncio.TimeoutError, OSError, socket.gaierror):
            return

    await asyncio.gather(*(check_port(port) for port in target_ports))
    return sorted(open_ports)


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

    open_ports: Dict[str, List[int]] = {}
    if http_live_hosts:
        port_results = await asyncio.gather(*(scan_ports(host) for host in http_live_hosts))
        open_ports = {host: ports for host, ports in zip(http_live_hosts, port_results, strict=False) if ports}

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
                    "open_ports": open_ports.get(sub, []),
                    "redirect_to": http_info.redirect_to if http_info else "",
                    "source": sorted(source_map.get(sub, {"passive"})),
                }
            )
        else:
            dead_subdomains.append(sub)

        subdomains.append(
            {
                "name": sub,
                "status": http_info.status_code if http_info else None,
                "title": http_info.title if http_info else "",
                "open_ports": open_ports.get(sub, []),
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
        "open_ports": open_ports,
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
