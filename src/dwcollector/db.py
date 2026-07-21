from __future__ import annotations
import sqlite3

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
"""

class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row

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
