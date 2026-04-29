"""
SubHunter - Modern asynchronous subdomain enumeration tool.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Set

from subfinderx.core.active.bruteforce import brute_force
from subfinderx.core.active.dns_resolve import bulk_resolve
from subfinderx.core.active.http_probe import HTTPProbeResult, bulk_probe
from subfinderx.core.passive.chaos import fetch_chaos
from subfinderx.core.passive.crtsh import fetch_crtsh
from subfinderx.core.passive.securitytrails import fetch_securitytrails
from subfinderx.core.passive.virustotal import fetch_virustotal
from subfinderx.core.passive.wayback import fetch_wayback
from subfinderx.core.utils.config import APIConfig, RuntimeConfig, load_api_config
from subfinderx.core.utils.db import SubdomainRecord, get_historical_subdomains, init_db, upsert_subdomain
from subfinderx.core.utils.dedupe import dedupe_subdomains
from subfinderx.core.utils.output import emit_json, emit_subdomain_list, emit_txt, log_error, log_info


@dataclass(slots=True)
class SubdomainStatus:
    """Single subdomain with classification and tracking data."""

    name: str
    is_live: bool
    first_seen: datetime
    last_seen: datetime
    http_status: int | None = None
    http_title: str = ""
    dns_records: List[str] | None = None


async def enumerate_passive(domain: str, api_cfg: APIConfig, rt_cfg: RuntimeConfig) -> Set[str]:
    """
    Run all passive enumeration sources concurrently.
    """

    coros = [
        fetch_crtsh(domain, api_cfg),
        fetch_wayback(domain, api_cfg),
        fetch_chaos(domain, api_cfg),
        fetch_virustotal(domain, api_cfg),
        fetch_securitytrails(domain, api_cfg),
    ]

    log_info("[*] Launching passive enumeration...", silent=rt_cfg.silent)
    results = await asyncio.gather(*coros, return_exceptions=True)

    all_subs: Set[str] = set()
    for result in results:
        if isinstance(result, Exception):
            continue
        all_subs.update(result)

    return dedupe_subdomains(all_subs)


async def classify_and_persist(
    rt_cfg: RuntimeConfig,
    api_cfg: APIConfig,
) -> Dict[str, SubdomainStatus]:
    """
    Full reconnaissance pipeline:
      - Passive enumeration
      - Active DNS resolution
      - HTTP probing
      - SQLite persistence + classification
      - Merge historical subdomains from DB
    """

    init_db()

    passive_subs = await enumerate_passive(rt_cfg.domain, api_cfg, rt_cfg)
    log_info(f"[+] Passive subdomains discovered: {len(passive_subs)}", silent=rt_cfg.silent)

    if rt_cfg.bruteforce and rt_cfg.wordlist_path:
        log_info("[*] Running brute-force enumeration...", silent=rt_cfg.silent)
        brute_subs = await brute_force(
            rt_cfg.domain,
            rt_cfg.wordlist_path,
            concurrency=rt_cfg.concurrency,
        )
        log_info(f"[+] Brute-force resolved: {len(brute_subs)}", silent=rt_cfg.silent)
        all_subs = dedupe_subdomains(passive_subs | brute_subs)
    else:
        all_subs = passive_subs

    dns_results: Dict[str, tuple[bool, List[str]]] = {}
    http_results: Dict[str, HTTPProbeResult] = {}

    if all_subs:
        log_info(f"[*] Performing DNS resolution on {len(all_subs)} hosts...", silent=rt_cfg.silent)
        dns_results = await bulk_resolve(sorted(all_subs), concurrency=rt_cfg.concurrency)

        live_candidates = [h for h, (is_live, _) in dns_results.items() if is_live]
        log_info(f"[*] Probing HTTP on {len(live_candidates)} hosts...", silent=rt_cfg.silent)
        http_results = await bulk_probe(sorted(live_candidates), concurrency=rt_cfg.concurrency)

    historical = {rec.subdomain: rec for rec in get_historical_subdomains(rt_cfg.domain)}
    status_map: Dict[str, SubdomainStatus] = {}

    for sub in all_subs:
        dns_live, dns_recs = dns_results.get(sub, (False, []))
        http_info = http_results.get(sub)
        is_live = dns_live or (http_info.is_live if http_info else False)

        rec = upsert_subdomain(rt_cfg.domain, sub, is_live=is_live)

        status_map[sub] = SubdomainStatus(
            name=sub,
            is_live=is_live,
            first_seen=rec.first_seen,
            last_seen=rec.last_seen,
            http_status=http_info.status_code if http_info else None,
            http_title=http_info.title if http_info else "",
            dns_records=dns_recs or None,
        )

    # Merge in historical subdomains not seen this run.
    for sub, rec in historical.items():
        if sub in status_map:
            continue
        status_map[sub] = SubdomainStatus(
            name=sub,
            is_live=rec.is_live,
            first_seen=rec.first_seen,
            last_seen=rec.last_seen,
            http_status=None,
            http_title="",
            dns_records=None,
        )

    return status_map


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subfinderx",
        description=(
            "SubFinderX - asynchronous subdomain reconnaissance with passive OSINT, "
            "DNS resolution, HTTP probing, and historical tracking."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  subhunter -d example.com\n"
            "  subhunter -d example.com --only-new\n"
            "  subhunter -d example.com --json\n"
        ),
    )

    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Target domain to enumerate (e.g. example.com).",
    )
    parser.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Output results in JSON format (machine-readable).",
    )
    parser.add_argument(
        "--txt",
        dest="output_txt",
        action="store_true",
        help="Output plain-text list of subdomains (one per line).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=25,
        help="Maximum number of concurrent network tasks (default: 25).",
    )
    parser.add_argument(
        "--silent",
        action="store_true",
        help="Suppress banner and progress messages; emit only the selected output format.",
    )
    parser.add_argument(
        "--only-new",
        dest="only_new",
        action="store_true",
        help="Show only subdomains first seen by this tool in the current run.",
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Enable brute-force subdomain enumeration from a wordlist (merged with passive results).",
    )
    parser.add_argument(
        "--wordlist",
        dest="wordlist_path",
        metavar="PATH",
        default=None,
        help="Path to wordlist file for brute-force (required when --bruteforce is set).",
    )
    return parser


def build_runtime_config(args: argparse.Namespace) -> RuntimeConfig:
    return RuntimeConfig(
        domain=args.domain.strip().lower(),
        concurrency=max(1, args.threads),
        output_json=args.output_json,
        output_txt=args.output_txt,
        silent=args.silent,
        only_new=args.only_new,
        bruteforce=getattr(args, "bruteforce", False),
        wordlist_path=getattr(args, "wordlist_path", None),
    )


def summarize(
    status_map: Dict[str, SubdomainStatus],
    rt_cfg: RuntimeConfig,
    run_started_at: datetime,
) -> dict:
    """
    Build a structured summary for human-readable and JSON output.
    first_seen_by_tool: when SubHunter first observed the subdomain (same as first_seen).
    """

    total = len(status_map)
    live = sum(1 for s in status_map.values() if s.is_live)
    historical = sum(1 for s in status_map.values() if not s.is_live)
    newly_discovered = sum(1 for s in status_map.values() if s.first_seen >= run_started_at)

    sorted_subs = sorted(status_map.values(), key=lambda x: (not x.is_live, x.name))

    return {
        "domain": rt_cfg.domain,
        "total_subdomains": total,
        "live": live,
        "historical": historical,
        "newly_discovered_today": newly_discovered,
        "subdomains": [
            {
                "name": s.name,
                "is_live": s.is_live,
                "first_seen": s.first_seen.isoformat(),
                "last_seen": s.last_seen.isoformat(),
                "http_status": s.http_status,
                "http_title": s.http_title,
                "first_seen_this_run": s.first_seen >= run_started_at,
            }
            for s in sorted_subs
        ],
    }


def handle_output(summary: dict, rt_cfg: RuntimeConfig) -> None:
    """
    Emit CLI output: summary above list, then [LIVE]/[DEAD] entries.
    --json emits only structured output; --txt emits only subdomain names.
    """

    if rt_cfg.output_json:
        # JSON: subdomain, is_live, first_seen, last_seen (first_seen = when tool first observed)
        json_data = {
            "domain": summary["domain"],
            "total_subdomains": summary["total_subdomains"],
            "live": summary["live"],
            "historical": summary["historical"],
            "newly_discovered_today": summary["newly_discovered_today"],
            "subdomains": [
                {
                    "subdomain": item["name"],
                    "is_live": item["is_live"],
                    "first_seen": item["first_seen"],
                    "last_seen": item["last_seen"],
                }
                for item in summary["subdomains"]
            ],
        }
        emit_json(json_data, silent=rt_cfg.silent)
        return

    if rt_cfg.output_txt:
        lines = [item["name"] for item in summary["subdomains"]]
        emit_txt(lines, silent=rt_cfg.silent)
        return

    # Default: human-readable with summary above list
    log_info("", silent=rt_cfg.silent)
    log_info(f"[+] Domain: {summary['domain']}", silent=rt_cfg.silent)
    log_info(f"[+] Total Subdomains Found: {summary['total_subdomains']}", silent=rt_cfg.silent)
    log_info(f"[+] Live: {summary['live']}", silent=rt_cfg.silent)
    log_info(f"[+] Historical (DEAD): {summary['historical']}", silent=rt_cfg.silent)
    log_info(
        f"[+] First Seen By Tool (This Run): {summary['newly_discovered_today']}",
        silent=rt_cfg.silent,
    )
    log_info("", silent=rt_cfg.silent)

    entries = summary["subdomains"]
    if rt_cfg.only_new:
        entries = [e for e in entries if e.get("first_seen_this_run")]

        if not entries:
            log_info("[+] No new subdomains discovered since last run.", silent=rt_cfg.silent)
            return

        log_info("[+] Newly discovered subdomains:", silent=rt_cfg.silent)

    emit_subdomain_list(entries, silent=rt_cfg.silent)


async def async_main(args: argparse.Namespace) -> int:
    if getattr(args, "bruteforce", False) and not getattr(args, "wordlist_path", None):
        log_error("--wordlist PATH is required when --bruteforce is set.")
        return 1

    api_cfg = load_api_config()
    rt_cfg = build_runtime_config(args)
    run_started_at = datetime.utcnow()

    log_info(f"[*] Starting SubFinderX against {rt_cfg.domain}", silent=rt_cfg.silent)

    try:
        status_map = await classify_and_persist(rt_cfg, api_cfg)
    except FileNotFoundError as e:
        log_error(str(e))
        return 1
    summary = summarize(status_map, rt_cfg, run_started_at=run_started_at)
    handle_output(summary, rt_cfg)

    return 0


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        exit_code = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        log_error("Interrupted by user.")
        exit_code = 1
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

