from __future__ import annotations
import sqlite3
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

_UPDATABLE = {
    "alive", "http_status", "title", "response_ms", "last_checked",
    "category", "category_confidence", "matched_terms", "snippet",
    "content_simhash", "cluster_id", "is_canonical", "clone_of", "trust",
    "pgp_fingerprint", "inbound_links",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    url TEXT PRIMARY KEY,
    host TEXT, source TEXT, depth INTEGER,
    first_seen TEXT, last_checked TEXT,
    alive INTEGER, http_status INTEGER, title TEXT, response_ms INTEGER,
    category TEXT DEFAULT 'unknown', category_confidence REAL,
    matched_terms TEXT, snippet TEXT,
    content_simhash TEXT, cluster_id TEXT,
    is_canonical INTEGER DEFAULT 0, clone_of TEXT,
    trust TEXT, pgp_fingerprint TEXT, inbound_links INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS frontier (
    url TEXT PRIMARY KEY, depth INTEGER,
    state TEXT DEFAULT 'pending', enqueued_at TEXT, attempts INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clusters (
    cluster_id TEXT PRIMARY KEY, canonical_url TEXT,
    member_count INTEGER, chosen_by TEXT
);
CREATE TABLE IF NOT EXISTS crawl_runs (
    run_id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT,
    seeds_count INTEGER, discovered INTEGER, alive_count INTEGER, stop_reason TEXT
);
CREATE TABLE IF NOT EXISTS leak_hits (
    hit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, url TEXT, host TEXT, category TEXT, trust TEXT,
    term TEXT, context_snippet TEXT, matched_at TEXT
);
CREATE TABLE IF NOT EXISTS url_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT, host TEXT,
    field TEXT, old_value TEXT, new_value TEXT,
    observed_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, dedup_key TEXT UNIQUE,
    url TEXT, host TEXT, term TEXT,
    status TEXT, severity TEXT,
    first_seen TEXT, last_seen TEXT, resolved_at TEXT,
    context_snippet TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER, dedup_key TEXT,
    event TEXT, severity TEXT, title TEXT, body TEXT,
    created_at TEXT, delivered INTEGER DEFAULT 0, delivery_error TEXT
);
"""

class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        # Concurrency safety: WAL lets a reader (stats/export) run without
        # blocking the writer, and busy_timeout makes a second writer wait up
        # to 5s for the lock instead of failing immediately with "database is
        # locked" if a one-off command overlaps the loop service.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def upsert_url(self, url, host, source, depth, first_seen) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO urls (url, host, source, depth, first_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (url, host, source, depth, first_seen),
        )
        self.conn.commit()

    def update_url(self, url, **fields) -> None:
        cols = [k for k in fields if k in _UPDATABLE]
        if not cols:
            return
        assignments = ", ".join(f"{c} = ?" for c in cols)
        self.conn.execute(
            f"UPDATE urls SET {assignments} WHERE url = ?",
            [fields[c] for c in cols] + [url],
        )
        self.conn.commit()

    def get_url(self, url) -> dict | None:
        cur = self.conn.execute("SELECT * FROM urls WHERE url = ?", (url,))
        row = cur.fetchone()
        return dict(row) if row else None

    def all_urls(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM urls")]

    def enqueue(self, url, depth) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO frontier (url, depth, state, enqueued_at) "
            "VALUES (?, ?, 'pending', datetime('now'))",
            (url, depth),
        )
        self.conn.commit()

    def next_pending(self, limit) -> list[dict]:
        rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM frontier WHERE state='pending' "
            "ORDER BY depth ASC LIMIT ?", (limit,))]
        for r in rows:
            self.conn.execute(
                "UPDATE frontier SET state='in_progress' WHERE url=?", (r["url"],))
        self.conn.commit()
        return rows

    def mark_frontier(self, url, state) -> None:
        self.conn.execute("UPDATE frontier SET state=? WHERE url=?", (state, url))
        self.conn.commit()

    def count_frontier(self, state) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM frontier WHERE state=?", (state,)).fetchone()[0]

    def reset_state(self, from_state, to_state) -> int:
        cur = self.conn.execute(
            "UPDATE frontier SET state=? WHERE state=?", (to_state, from_state))
        self.conn.commit()
        return cur.rowcount

    def start_run(self, run_id, started_at, seeds_count) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO crawl_runs (run_id, started_at, seeds_count) "
            "VALUES (?, ?, ?)", (run_id, started_at, seeds_count))
        self.conn.commit()

    def finish_run(self, run_id, finished_at, discovered, alive_count, stop_reason) -> None:
        self.conn.execute(
            "UPDATE crawl_runs SET finished_at=?, discovered=?, alive_count=?, "
            "stop_reason=? WHERE run_id=?",
            (finished_at, discovered, alive_count, stop_reason, run_id))
        self.conn.commit()

    def set_cluster(self, cluster_id, canonical_url, member_count, chosen_by) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO clusters "
            "(cluster_id, canonical_url, member_count, chosen_by) VALUES (?, ?, ?, ?)",
            (cluster_id, canonical_url, member_count, chosen_by))
        self.conn.commit()

    def record_leak_hit(self, run_id, url, host, category, trust,
                        term, context_snippet, matched_at) -> None:
        self.conn.execute(
            "INSERT INTO leak_hits (run_id, url, host, category, trust, term, "
            "context_snippet, matched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, url, host, category, trust, term, context_snippet, matched_at))
        self.conn.commit()

    def canonical_trusted_urls(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM urls WHERE is_canonical=1 AND trust IN ('verified','probable')")]

    def record_url_event(self, url, host, field, old_value, new_value, observed_at) -> None:
        self.conn.execute(
            "INSERT INTO url_events (url, host, field, old_value, new_value, observed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url, host, field, old_value, new_value, observed_at))
        self.conn.commit()

    def get_finding(self, dedup_key) -> dict | None:
        cur = self.conn.execute("SELECT * FROM findings WHERE dedup_key = ?", (dedup_key,))
        row = cur.fetchone()
        return dict(row) if row else None

    def open_finding(self, kind, dedup_key, url, host, term, severity,
                     context_snippet, now) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO findings "
            "(kind, dedup_key, url, host, term, status, severity, first_seen, "
            " last_seen, context_snippet) "
            "VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)",
            (kind, dedup_key, url, host, term, severity, now, now, context_snippet))
        self.conn.commit()

    def touch_finding(self, dedup_key, last_seen) -> None:
        self.conn.execute("UPDATE findings SET last_seen = ? WHERE dedup_key = ?",
                          (last_seen, dedup_key))
        self.conn.commit()

    def resolve_finding(self, dedup_key, resolved_at) -> None:
        self.conn.execute(
            "UPDATE findings SET status = 'resolved', resolved_at = ? WHERE dedup_key = ?",
            (resolved_at, dedup_key))
        self.conn.commit()

    def reopen_finding(self, dedup_key, now, context_snippet) -> None:
        self.conn.execute(
            "UPDATE findings SET status = 'open', resolved_at = NULL, "
            "last_seen = ?, context_snippet = ? WHERE dedup_key = ?",
            (now, context_snippet, dedup_key))
        self.conn.commit()

    def open_findings(self, kind=None) -> list[dict]:
        if kind:
            cur = self.conn.execute(
                "SELECT * FROM findings WHERE status = 'open' AND kind = ?", (kind,))
        else:
            cur = self.conn.execute("SELECT * FROM findings WHERE status = 'open'")
        return [dict(r) for r in cur]

    def list_findings(self, status=None) -> list[dict]:
        if status and status != "all":
            cur = self.conn.execute(
                "SELECT * FROM findings WHERE status = ? ORDER BY finding_id DESC",
                (status,))
        else:
            cur = self.conn.execute("SELECT * FROM findings ORDER BY finding_id DESC")
        return [dict(r) for r in cur]

    def record_alert(self, finding_id, dedup_key, event, severity, title, body,
                     created_at, delivered, delivery_error) -> int:
        cur = self.conn.execute(
            "INSERT INTO alerts (finding_id, dedup_key, event, severity, title, "
            "body, created_at, delivered, delivery_error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding_id, dedup_key, event, severity, title, body, created_at,
             delivered, delivery_error))
        self.conn.commit()
        return cur.lastrowid

    def leak_hits_for_run(self, run_id) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM leak_hits WHERE run_id = ?", (run_id,))]
