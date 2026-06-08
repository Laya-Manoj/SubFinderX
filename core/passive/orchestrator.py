"""
Central orchestration for passive subdomain enumeration.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Dict, List

from core.passive.alienvault import fetch_alienvault
from core.passive.anubis import fetch_anubis
from core.passive.bufferover import fetch_bufferover
from core.passive.certspotter import fetch_certspotter
from core.passive.chaos import fetch_chaos
from core.passive.commoncrawl import fetch_commoncrawl
from core.passive.crtsh import fetch_crtsh
from core.passive.dnsdumpster import fetch_dnsdumpster
from core.passive.hackertarget import fetch_hackertarget
from core.passive.rapiddns import fetch_rapiddns
from core.passive.securitytrails import fetch_securitytrails
from core.passive.subdomain_center import fetch_subdomain_center
from core.passive.threatcrowd import fetch_threatcrowd
from core.passive.types import PassiveEnumerationResult, SourceResult
from core.passive.urlscan import fetch_urlscan
from core.passive.virustotal import fetch_virustotal
from core.passive.wayback import fetch_wayback
from core.utils.config import APIConfig
from core.utils.dedupe import dedupe_subdomains
from core.utils import passive_cache

logger = logging.getLogger("subfinderx.passive")

FetchFn = Callable[..., Awaitable[SourceResult]]

PASSIVE_SOURCES: Dict[str, FetchFn] = {
    "crtsh": fetch_crtsh,
    "certspotter": fetch_certspotter,
    "wayback": fetch_wayback,
    "chaos": fetch_chaos,
    "virustotal": fetch_virustotal,
    "securitytrails": fetch_securitytrails,
    "hackertarget": fetch_hackertarget,
    "rapiddns": fetch_rapiddns,
    "subdomain_center": fetch_subdomain_center,
    "urlscan": fetch_urlscan,
    "threatcrowd": fetch_threatcrowd,
    "commoncrawl": fetch_commoncrawl,
    "dnsdumpster": fetch_dnsdumpster,
    "bufferover": fetch_bufferover,
    "alienvault": fetch_alienvault,
    "anubis": fetch_anubis,
}


def _log_source_line(source_name: str, result: SourceResult, *, emit_print: bool) -> None:
    entry = result.to_report_entry(source_name)
    if result.status == "ok":
        message = f"[passive] {source_name}: {entry['count']} results"
    elif result.status == "cached":
        message = f"[passive] {source_name}: {entry['count']} results (cached)"
    elif result.status == "skipped":
        message = f"[passive] {source_name}: skipped ({result.reason})"
    elif result.status == "empty":
        message = f"[passive] {source_name}: 0 results"
    else:
        message = f"[passive] {source_name}: unavailable ({result.reason})"

    logger.info(message)
    if emit_print:
        print(message)

    health_msg = f"[passive] source={source_name} status={result.status}"
    if result.reason:
        health_msg += f" reason={result.reason}"
    logger.info(health_msg)


async def _run_source(
    name: str,
    fetch_fn: FetchFn,
    domain: str,
    api_cfg: APIConfig,
    *,
    max_retries: int,
    use_cache: bool,
) -> SourceResult:
    """Run a single passive source with optional cache fallback."""

    try:
        result = await fetch_fn(domain, api_cfg, max_retries=max_retries)
        result = SourceResult(
            subdomains=dedupe_subdomains(result.subdomains),
            status=result.status,
            reason=result.reason,
        )

        if result.subdomains:
            if use_cache:
                passive_cache.save(name, domain, result.subdomains)
            return result

        if result.status == "skipped":
            return result

        if use_cache:
            cached = passive_cache.load(name, domain)
            if cached:
                cached_set = dedupe_subdomains(cached)
                return SourceResult.cached(
                    cached_set,
                    result.reason or "live fetch empty, using 24h cache",
                )

        return result

    except Exception as exc:
        logger.warning("[passive] %s: failed (%s)", name, exc)
        if use_cache:
            cached = passive_cache.load(name, domain)
            if cached:
                cached_set = dedupe_subdomains(cached)
                return SourceResult.cached(cached_set, f"exception: {exc}")
        return SourceResult.unavailable(str(exc))


async def enumerate_all_passive(
    domain: str,
    api_cfg: APIConfig,
    *,
    max_retries: int = 4,
    use_cache: bool = True,
    per_source_timeout: float | None = None,
    emit_print: bool = False,
) -> PassiveEnumerationResult:
    """
    Run all passive sources concurrently, merge results, and log per-source stats.

    No source failure prevents the scan from continuing. Cached data is used
    when a live fetch returns empty or raises an error.
    """

    domain = domain.strip().lower()

    async def _bounded(name: str, fetch_fn: FetchFn) -> SourceResult:
        coro = _run_source(
            name,
            fetch_fn,
            domain,
            api_cfg,
            max_retries=max_retries,
            use_cache=use_cache,
        )
        if per_source_timeout is not None:
            try:
                return await asyncio.wait_for(coro, timeout=per_source_timeout)
            except asyncio.TimeoutError:
                logger.warning(
                    "[passive] %s: timed out after %.0fs",
                    name,
                    per_source_timeout,
                )
                if use_cache:
                    cached = passive_cache.load(name, domain)
                    if cached:
                        cached_set = dedupe_subdomains(cached)
                        return SourceResult.cached(cached_set, "timed out, using 24h cache")
                return SourceResult.unavailable(f"timed out after {per_source_timeout:.0f}s")
        return await coro

    names = list(PASSIVE_SOURCES.keys())
    tasks = [_bounded(name, PASSIVE_SOURCES[name]) for name in names]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_subdomains: set[str] = set()
    source_reports: List[dict] = []

    for source_name, result in zip(names, results, strict=False):
        if isinstance(result, Exception):
            entry = SourceResult.unavailable(str(result)).to_report_entry(source_name)
            source_reports.append(entry)
            _log_source_line(source_name, SourceResult.unavailable(str(result)), emit_print=emit_print)
            if use_cache:
                cached = passive_cache.load(source_name, domain)
                if cached:
                    cached_set = dedupe_subdomains(cached)
                    cached_result = SourceResult.cached(cached_set, str(result))
                    source_reports.append(cached_result.to_report_entry(f"{source_name}_cache"))
                    all_subdomains.update(cached_set)
            continue

        entry = result.to_report_entry(source_name)
        source_reports.append(entry)
        _log_source_line(source_name, result, emit_print=emit_print)
        all_subdomains.update(result.subdomains)

    final_passive = dedupe_subdomains(all_subdomains)
    combined_msg = f"[passive] combined unique: {len(final_passive)}"
    logger.info(combined_msg)
    if emit_print:
        print(combined_msg)

    source_reports.append(
        {
            "source": "combined",
            "status": "ok",
            "reason": "",
            "count": len(final_passive),
        }
    )

    return PassiveEnumerationResult(subdomains=final_passive, sources=source_reports)
