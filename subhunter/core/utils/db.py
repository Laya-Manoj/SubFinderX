"""
SQLite persistence for SubHunter.

Tracks first_seen / last_seen timestamps and liveness for subdomains.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

DB_PATH = Path(__file__).resolve().parents[3] / "db" / "history.db"


@dataclass(slots=True)
class SubdomainRecord:
    domain: str
    subdomain: str
    first_seen: datetime
    last_seen: datetime
    is_live: bool


def _ensure_parent_dir() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def _get_conn() -> Iterable[sqlite3.Connection]:
    _ensure_parent_dir()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they do not exist."""
    with _get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subdomains (
                domain      TEXT NOT NULL,
                subdomain   TEXT NOT NULL,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                is_live     INTEGER NOT NULL,
                PRIMARY KEY (domain, subdomain)
            )
            """
        )


def upsert_subdomain(domain: str, subdomain: str, *, is_live: bool) -> SubdomainRecord:
    """
    Insert or update a subdomain record.

    Returns the resulting record from the database.
    """

    now = datetime.utcnow().isoformat(timespec="seconds")

    with _get_conn() as conn:
        cur = conn.cursor()

        cur.execute(
            "SELECT first_seen, is_live FROM subdomains WHERE domain=? AND subdomain=?",
            (domain, subdomain),
        )
        row = cur.fetchone()

        if row is None:
            first_seen = now
            cur.execute(
                """
                INSERT INTO subdomains (domain, subdomain, first_seen, last_seen, is_live)
                VALUES (?, ?, ?, ?, ?)
                """,
                (domain, subdomain, first_seen, now, int(is_live)),
            )
        else:
            first_seen, existing_is_live = row
            # Preserve earliest observation and update liveness.
            cur.execute(
                """
                UPDATE subdomains
                   SET last_seen = ?,
                       is_live = ?
                 WHERE domain = ? AND subdomain = ?
                """,
                (now, int(is_live), domain, subdomain),
            )

        cur.execute(
            "SELECT domain, subdomain, first_seen, last_seen, is_live FROM subdomains WHERE domain=? AND subdomain=?",
            (domain, subdomain),
        )
        domain_v, subdomain_v, first_seen_v, last_seen_v, is_live_v = cur.fetchone()

    return SubdomainRecord(
        domain=domain_v,
        subdomain=subdomain_v,
        first_seen=datetime.fromisoformat(first_seen_v),
        last_seen=datetime.fromisoformat(last_seen_v),
        is_live=bool(is_live_v),
    )


def get_historical_subdomains(domain: str) -> List[SubdomainRecord]:
    """Return all known subdomains for a domain."""
    init_db()
    with _get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT domain, subdomain, first_seen, last_seen, is_live FROM subdomains WHERE domain=?",
            (domain,),
        )
        rows = cur.fetchall()

    records: List[SubdomainRecord] = []
    for domain_v, subdomain_v, first_seen_v, last_seen_v, is_live_v in rows:
        records.append(
            SubdomainRecord(
                domain=domain_v,
                subdomain=subdomain_v,
                first_seen=datetime.fromisoformat(first_seen_v),
                last_seen=datetime.fromisoformat(last_seen_v),
                is_live=bool(is_live_v),
            )
        )
    return records

