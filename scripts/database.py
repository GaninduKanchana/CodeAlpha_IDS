"""
database.py
------------
SQLite database layer for the CodeAlpha IDS project.

All queries use parameterized SQL (never string concatenation/f-strings for
values) to avoid SQL injection, even though input here comes from our own
local Suricata logs rather than untrusted external users.
"""

import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "ids_alerts.db")
DB_PATH = os.path.abspath(DB_PATH)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    src_ip          TEXT,
    src_port        INTEGER,
    dest_ip         TEXT,
    dest_port       INTEGER,
    proto           TEXT,
    signature       TEXT NOT NULL,
    signature_id    INTEGER,
    severity        INTEGER,
    category        TEXT,
    action          TEXT,
    raw_event_hash  TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_signature_id ON alerts(signature_id);
"""


@contextmanager
def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Create the alerts table and indexes if they don't already exist."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        conn.commit()


def insert_alert(alert: dict) -> bool:
    """
    Insert a normalized alert dict into the database.
    Returns True if inserted, False if it was a duplicate (already seen).
    Uses a parameterized query — values are never interpolated into SQL text.
    """
    query = """
        INSERT OR IGNORE INTO alerts
            (timestamp, src_ip, src_port, dest_ip, dest_port, proto,
             signature, signature_id, severity, category, action, raw_event_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        alert.get("timestamp"),
        alert.get("src_ip"),
        alert.get("src_port"),
        alert.get("dest_ip"),
        alert.get("dest_port"),
        alert.get("proto"),
        alert.get("signature"),
        alert.get("signature_id"),
        alert.get("severity"),
        alert.get("category"),
        alert.get("action"),
        alert.get("raw_event_hash"),
    )
    with get_connection() as conn:
        cur = conn.execute(query, params)
        conn.commit()
        return cur.rowcount > 0


def get_summary_counts() -> dict:
    """Return total + per-severity alert counts."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
        ).fetchall()
    by_sev = {1: 0, 2: 0, 3: 0, 4: 0}
    for row in rows:
        if row["severity"] in by_sev:
            by_sev[row["severity"]] = row["c"]
    return {
        "total": total,
        "critical": by_sev[1],
        "high": by_sev[2],
        "medium": by_sev[3],
        "low": by_sev[4],
    }


def get_alerts_over_time(limit_hours: int = 24) -> list:
    # Suricata's timestamp format (e.g. "2026-09-27T22:25:26.245506+0530") uses
    # a timezone offset without a colon, which SQLite's strftime() cannot parse
    # (it silently returns NULL). We bucket by hour using substr() instead,
    # which works on the fixed-width ISO-8601 prefix regardless of the offset.
    query = """
        SELECT substr(timestamp, 1, 13) || ':00' AS bucket, COUNT(*) AS c
        FROM alerts
        WHERE timestamp IS NOT NULL
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(query, (limit_hours,)).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_top_source_ips(limit: int = 5) -> list:
    query = """
        SELECT src_ip, COUNT(*) AS c FROM alerts
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip ORDER BY c DESC LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_top_dest_ports(limit: int = 5) -> list:
    query = """
        SELECT dest_port, COUNT(*) AS c FROM alerts
        WHERE dest_port IS NOT NULL
        GROUP BY dest_port ORDER BY c DESC LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_top_signatures(limit: int = 5) -> list:
    query = """
        SELECT signature, signature_id, COUNT(*) AS c FROM alerts
        GROUP BY signature_id ORDER BY c DESC LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_recent_alerts(limit: int = 100, search: str = None, severity: int = None) -> list:
    """
    Return recent alerts, optionally filtered by a search term (matched
    against signature/src_ip/dest_ip) and/or severity. All filtering is done
    with parameterized queries.
    """
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if search:
        query += " AND (signature LIKE ? OR src_ip LIKE ? OR dest_ip LIKE ?)"
        like = f"%{search}%"
        params.extend([like, like, like])

    if severity is not None:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print(f"[INFO] Database initialized at: {DB_PATH}")
