"""
Shared SQLite logging layer for the honeypot suite.

All decoy services (SSH, HTTP, FTP) write raw interaction events into a
single `events` table. The triage engine reads from this table, scores
each event, and writes results into the `triage` table. The dashboard
reads from both.

This module intentionally has zero external dependencies so it can be
dropped into any of the service scripts without a venv.
"""
import sqlite3
import threading
import time
import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "honeypot.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    service TEXT NOT NULL,          -- ssh | http | ftp
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    event_type TEXT NOT NULL,       -- connect | auth_attempt | request | command | disconnect
    username TEXT,
    password TEXT,
    raw_payload TEXT,               -- full request line / command / banner exchange
    extra_json TEXT                 -- arbitrary structured detail (headers, etc.)
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);

CREATE TABLE IF NOT EXISTS triage (
    event_id INTEGER PRIMARY KEY,
    severity TEXT NOT NULL,         -- info | low | medium | high | critical
    score INTEGER NOT NULL,         -- 0-100
    category TEXT NOT NULL,         -- recon | brute_force | exploit_attempt | malware_drop | known_bad_ip | benign
    iocs_json TEXT,                 -- extracted indicators of compromise
    rationale TEXT,                 -- human-readable explanation of the score
    triaged_at REAL NOT NULL,
    FOREIGN KEY(event_id) REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    src_ip TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    total_events INTEGER NOT NULL DEFAULT 0,
    max_severity_score INTEGER NOT NULL DEFAULT 0,
    distinct_services INTEGER NOT NULL DEFAULT 0,
    is_known_bad INTEGER NOT NULL DEFAULT 0
);
"""


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = get_conn()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()


def log_event(service, src_ip, src_port, event_type, username=None,
              password=None, raw_payload=None, extra=None):
    """Insert one raw event and return its row id."""
    with _lock:
        conn = get_conn()
        cur = conn.execute(
            """INSERT INTO events
               (ts, service, src_ip, src_port, event_type, username, password, raw_payload, extra_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (time.time(), service, src_ip, src_port, event_type, username,
             password, raw_payload, json.dumps(extra or {})),
        )
        conn.commit()
        event_id = cur.lastrowid
        conn.close()
    return event_id


if __name__ == "__main__":
    init_db()
    print(f"Initialized DB at {DB_PATH}")
