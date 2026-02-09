"""
Output and logging utilities for SubHunter.
"""

from __future__ import annotations

import json
import sys
from typing import Iterable, List, TextIO


def _writeln(stream: TextIO, message: str, *, end: str = "\n") -> None:
    stream.write(message + end)
    stream.flush()


def log_info(message: str, *, silent: bool = False) -> None:
    """Log a normal informational message."""
    if silent:
        return
    _writeln(sys.stdout, message)


def log_error(message: str) -> None:
    """Log an error message to stderr."""
    _writeln(sys.stderr, message)


def emit_json(
    data: dict,
    *,
    pretty: bool = True,
    silent: bool = False,
) -> None:
    """Emit JSON to stdout."""
    if silent:
        return
    if pretty:
        _writeln(sys.stdout, json.dumps(data, indent=2, sort_keys=False))
    else:
        _writeln(sys.stdout, json.dumps(data, separators=(",", ":")))


def emit_txt(lines: Iterable[str], *, silent: bool = False) -> None:
    """Emit plain-text lines to stdout."""
    if silent:
        return
    for line in lines:
        _writeln(sys.stdout, line)


def emit_subdomain_list(
    subdomains: List[dict],
    *,
    silent: bool = False,
) -> None:
    """
    Emit a human-readable list of subdomains with [LIVE] / [DEAD] and HTTP info.

    Each entry is expected to have:
      - name: subdomain string
      - is_live: bool
      - http_status: optional int
      - http_title: optional str
    """
    if silent:
        return

    for item in subdomains:
        name = item.get("name", "")
        is_live = bool(item.get("is_live"))
        http_status = item.get("http_status")
        http_title = (item.get("http_title") or "").strip()

        status = "[LIVE]" if is_live else "[DEAD]"

        if is_live and http_status is not None:
            if http_title:
                line = f"{status} {name}  ({http_status} | {http_title})"
            else:
                line = f"{status} {name}  ({http_status})"
        else:
            line = f"{status} {name}"

        _writeln(sys.stdout, line)

