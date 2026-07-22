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
