from dwcollector.db import Database

def make_db(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.init_schema()
    return db

def test_wal_and_busy_timeout_pragmas(tmp_path):
    # Fix 4: a file-backed DB must open in WAL with a busy_timeout, so an
    # overlapping one-off command doesn't hit "database is locked".
    db = make_db(tmp_path)
    mode = db.conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    assert db.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000

def test_upsert_and_get(tmp_path):
    db = make_db(tmp_path)
    db.upsert_url("http://a.onion/", "a.onion", "seed", 0, "2026-07-21T00:00:00")
    row = db.get_url("http://a.onion/")
    assert row["host"] == "a.onion"
    assert row["source"] == "seed"
    assert row["trust"] is None or row["trust"] == ""

def test_upsert_is_idempotent(tmp_path):
    db = make_db(tmp_path)
    db.upsert_url("http://a.onion/", "a.onion", "seed", 0, "2026-07-21T00:00:00")
    db.upsert_url("http://a.onion/", "a.onion", "crawled", 5, "2026-07-21T01:00:00")
    row = db.get_url("http://a.onion/")
    assert row["source"] == "seed"      # original preserved
    assert row["depth"] == 0

def test_update_url(tmp_path):
    db = make_db(tmp_path)
    db.upsert_url("http://a.onion/", "a.onion", "seed", 0, "2026-07-21T00:00:00")
    db.update_url("http://a.onion/", alive=1, http_status=200, title="Home")
    row = db.get_url("http://a.onion/")
    assert row["alive"] == 1
    assert row["http_status"] == 200
    assert row["title"] == "Home"

def test_frontier_roundtrip(tmp_path):
    db = make_db(tmp_path)
    db.enqueue("http://a.onion/", 0)
    db.enqueue("http://a.onion/", 0)         # duplicate ignored
    assert db.count_frontier("pending") == 1
    batch = db.next_pending(10)
    assert batch[0]["url"] == "http://a.onion/"
    assert db.count_frontier("pending") == 0
    assert db.count_frontier("in_progress") == 1
    db.mark_frontier("http://a.onion/", "done")
    assert db.count_frontier("done") == 1

def test_reset_state(tmp_path):
    db = make_db(tmp_path)
    db.enqueue("http://a.onion/", 0)
    db.enqueue("http://b.onion/", 0)
    db.enqueue("http://c.onion/", 0)
    db.mark_frontier("http://a.onion/", "deferred")
    db.mark_frontier("http://b.onion/", "deferred")
    # c stays pending — must not be touched
    count = db.reset_state("deferred", "pending")
    assert count == 2
    assert db.count_frontier("pending") == 3
    assert db.count_frontier("deferred") == 0

def test_canonical_trusted_filter(tmp_path):
    db = make_db(tmp_path)
    for u, canon, trust in [
        ("http://good.onion/", 1, "verified"),
        ("http://ok.onion/", 1, "probable"),
        ("http://clone.onion/", 0, "suspected_clone"),
        ("http://meh.onion/", 1, "unknown"),
    ]:
        db.upsert_url(u, u[7:-1], "crawled", 1, "2026-07-21T00:00:00")
        db.update_url(u, is_canonical=canon, trust=trust)
    urls = {r["url"] for r in db.canonical_trusted_urls()}
    assert urls == {"http://good.onion/", "http://ok.onion/"}

def test_finding_lifecycle_methods(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    key = "leak:http://x.onion/|acme.com"
    assert db.get_finding(key) is None
    db.open_finding("leak", key, "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ctx", "2026-07-23T00:00:00")
    f = db.get_finding(key)
    assert f["status"] == "open" and f["severity"] == "critical"
    assert f["term"] == "acme.com" and f["finding_id"] >= 1
    # idempotent open (INSERT OR IGNORE)
    db.open_finding("leak", key, "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ctx2", "2026-07-23T01:00:00")
    assert db.get_finding(key)["context_snippet"] == "ctx"
    db.touch_finding(key, "2026-07-23T02:00:00")
    assert db.get_finding(key)["last_seen"] == "2026-07-23T02:00:00"
    assert len(db.open_findings("leak")) == 1
    db.resolve_finding(key, "2026-07-23T03:00:00")
    assert db.get_finding(key)["status"] == "resolved"
    assert db.open_findings("leak") == []
    db.reopen_finding(key, "2026-07-23T04:00:00", "ctx3")
    assert db.get_finding(key)["status"] == "open"
    assert db.get_finding(key)["resolved_at"] is None
    assert db.get_finding(key)["context_snippet"] == "ctx3"
    assert len(db.list_findings("all")) == 1

def test_record_url_event_and_alert(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_url_event("http://x.onion/", "x.onion", "alive", "1", "0",
                        "2026-07-23T00:00:00")
    ev = list(db.conn.execute("SELECT field, old_value, new_value FROM url_events"))
    assert ev[0][0] == "alive" and ev[0][1] == "1" and ev[0][2] == "0"
    aid = db.record_alert(1, "leak:k", "opened", "critical", "t", "b",
                          "2026-07-23T00:00:00", 1, None)
    assert aid >= 1
    row = list(db.conn.execute("SELECT event, delivered FROM alerts"))[0]
    assert row[0] == "opened" and row[1] == 1

def test_leak_hits_for_run(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_leak_hit("run1", "http://x.onion/", "x.onion", "leak-site",
                       "verified", "acme.com", "snippet", "2026-07-23T00:00:00")
    db.record_leak_hit("run2", "http://y.onion/", "y.onion", "leak-site",
                       "verified", "acme.com", "snippet", "2026-07-23T00:00:00")
    rows = db.leak_hits_for_run("run1")
    assert len(rows) == 1 and rows[0]["url"] == "http://x.onion/"

def test_update_url_records_material_change_events(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://x.onion/"
    db.upsert_url(u, "x.onion", "crawled", 1, "2026-07-23T00:00:00")
    # first set alive=1 (from NULL) -> one event
    db.update_url(u, alive=1, observed_at="2026-07-23T01:00:00")
    # change alive 1->0 and trust None->verified -> two events
    db.update_url(u, alive=0, trust="verified", observed_at="2026-07-23T02:00:00")
    evs = [dict(r) for r in db.conn.execute(
        "SELECT field, old_value, new_value, observed_at FROM url_events ORDER BY event_id")]
    fields = [(e["field"], e["old_value"], e["new_value"]) for e in evs]
    assert ("alive", None, "1") in fields
    assert ("alive", "1", "0") in fields
    assert ("trust", None, "verified") in fields
    assert evs[-1]["observed_at"] == "2026-07-23T02:00:00"

def test_update_url_ignores_nonmaterial_and_unchanged(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://x.onion/"
    db.upsert_url(u, "x.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, alive=1, observed_at="2026-07-23T01:00:00")
    # non-material field change (title) -> no event
    db.update_url(u, title="New Title", observed_at="2026-07-23T02:00:00")
    # unchanged material (alive stays 1) -> no event
    db.update_url(u, alive=1, observed_at="2026-07-23T03:00:00")
    count = db.conn.execute("SELECT COUNT(*) FROM url_events").fetchone()[0]
    assert count == 1  # only the initial alive NULL->1

def test_update_url_state_write_survives_history_failure(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://x.onion/"
    db.upsert_url(u, "x.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, alive=1, observed_at="2026-07-23T01:00:00")
    # Break history recording (e.g. disk/locking issue) and confirm the
    # material state UPDATE still commits instead of being lost.
    db.conn.execute("DROP TABLE url_events")
    db.update_url(u, alive=0, observed_at="2026-07-23T02:00:00")
    assert db.get_url(u)["alive"] == 0

def test_record_leak_hit_stores_match_kind_and_count(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_leak_hit("r1", "http://x.onion/", "x.onion", "leak-site", "verified",
                       "pii:credit-card", "•••• •••• •••• 1111", "2026-07-23T00:00:00",
                       match_kind="pii", match_count=7)
    row = db.leak_hits_for_run("r1")[0]
    assert row["match_kind"] == "pii" and row["match_count"] == 7


def test_record_leak_hit_defaults(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_leak_hit("r1", "http://x.onion/", "x.onion", "leak-site", "verified",
                       "acme.com", "…acme.com…", "2026-07-23T00:00:00")
    row = db.leak_hits_for_run("r1")[0]
    assert row["match_kind"] == "literal" and row["match_count"] == 1


def test_init_schema_adds_columns_to_legacy_leak_hits(tmp_path):
    import sqlite3
    p = str(tmp_path / "legacy.db")
    # simulate a pre-Task-7 leak_hits with no match_kind/match_count
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE leak_hits (hit_id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "run_id TEXT, url TEXT, host TEXT, category TEXT, trust TEXT, "
              "term TEXT, context_snippet TEXT, matched_at TEXT)")
    c.commit(); c.close()
    db = Database(p); db.init_schema()           # must not raise; adds columns
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(leak_hits)")}
    assert "match_kind" in cols and "match_count" in cols

def test_live_cluster_siblings(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    def add(url, cid, alive):
        db.upsert_url(url, url.split("//")[1].strip("/"), "crawled", 1, "2026-07-23T00:00:00")
        db.update_url(url, cluster_id=cid, alive=alive)
    add("http://anchor.onion/", "c000001", 0)   # the (dead) anchor
    add("http://sib-alive.onion/", "c000001", 1) # live sibling -> candidate
    add("http://sib-dead.onion/", "c000001", 0)  # dead sibling -> excluded
    add("http://other.onion/", "c000002", 1)     # different cluster -> excluded
    sibs = db.live_cluster_siblings("c000001", "http://anchor.onion/")
    urls = {s["url"] for s in sibs}
    assert urls == {"http://sib-alive.onion/"}
    assert db.live_cluster_siblings(None, "http://anchor.onion/") == []


def test_migration_adds_disposition_and_suppressed_columns(tmp_path):
    import sqlite3
    p = str(tmp_path / "legacy.db")
    c = sqlite3.connect(p)
    # legacy findings/alerts WITHOUT the new columns
    c.execute("CREATE TABLE findings (finding_id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "kind TEXT, dedup_key TEXT UNIQUE, url TEXT, host TEXT, term TEXT, "
              "status TEXT, severity TEXT, first_seen TEXT, last_seen TEXT, "
              "resolved_at TEXT, context_snippet TEXT)")
    c.execute("CREATE TABLE alerts (alert_id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "finding_id INTEGER, dedup_key TEXT, event TEXT, severity TEXT, "
              "title TEXT, body TEXT, created_at TEXT, delivered INTEGER, delivery_error TEXT)")
    c.commit(); c.close()
    db = Database(p); db.init_schema()                       # must not raise
    fcols = {r[1] for r in db.conn.execute("PRAGMA table_info(findings)")}
    acols = {r[1] for r in db.conn.execute("PRAGMA table_info(alerts)")}
    assert {"disposition", "disposition_actor", "disposition_at"} <= fcols
    assert "suppressed" in acols
    dl = {r[1] for r in db.conn.execute("PRAGMA table_info(disposition_log)")}
    assert {"finding_id", "disposition", "note", "actor", "at"} <= dl


def test_record_alert_stores_suppressed(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_alert(1, "k", "opened", "critical", "t", "b",
                    "2026-07-24T00:00:00", 0, None, suppressed=1)
    row = list(db.conn.execute("SELECT suppressed FROM alerts"))[0]
    assert row[0] == 1


def test_get_finding_by_id(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:u|t", "u", "h", "t", "critical", "s", "2026-07-24T00:00:00")
    f = db.get_finding("leak:u|t")
    assert db.get_finding_by_id(f["finding_id"])["dedup_key"] == "leak:u|t"
    assert db.get_finding_by_id(99999) is None
    # a fresh finding defaults to disposition 'new'
    assert f["disposition"] == "new"
