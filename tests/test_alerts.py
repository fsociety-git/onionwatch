import json
from types import SimpleNamespace
from dwcollector.db import Database
from dwcollector.alerts import emit, reconcile_leaks


def _cfg(tmp_path, webhook=""):
    return SimpleNamespace(
        alerts_path=str(tmp_path / "alerts.jsonl"),
        alert_webhook=webhook,
    )


def _leak_finding(db):
    key = "leak:http://x.onion/|acme.com"
    db.open_finding("leak", key, "http://x.onion/", "x.onion", "acme.com",
                    "critical", "…acme.com…", "2026-07-23T00:00:00")
    return db.get_finding(key)


def test_emit_writes_sink_and_db(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    f = _leak_finding(db)
    payload = emit(db, cfg, f, "opened", "2026-07-23T01:00:00")
    # jsonl sink
    lines = open(cfg.alerts_path, encoding="utf-8").read().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["event"] == "opened" and rec["severity"] == "critical"
    assert rec["term"] == "acme.com"
    # db row
    row = list(db.conn.execute("SELECT event, severity, delivered FROM alerts"))[0]
    assert row[0] == "opened" and row[1] == "critical" and row[2] == 0
    assert payload["dedup_key"] == f["dedup_key"]


def test_emit_calls_webhook_when_configured(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path, webhook="https://sink.local/hook")
    f = _leak_finding(db)
    calls = []
    emit(db, cfg, f, "opened", "2026-07-23T01:00:00",
         post_fn=lambda c, p: calls.append((c.alert_webhook, p)))
    assert len(calls) == 1 and calls[0][0] == "https://sink.local/hook"
    assert list(db.conn.execute("SELECT delivered FROM alerts"))[0][0] == 1


def test_emit_webhook_failure_is_recorded_not_raised(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path, webhook="https://sink.local/hook")
    f = _leak_finding(db)

    def boom(c, p):
        raise RuntimeError("connection refused")

    # must not raise
    emit(db, cfg, f, "opened", "2026-07-23T01:00:00", post_fn=boom)
    row = list(db.conn.execute("SELECT delivered, delivery_error FROM alerts"))[0]
    assert row[0] == 0
    assert "connection refused" in row[1]


class _DbDown:
    """Stub db whose durable-record write always fails."""

    def record_alert(self, *args, **kwargs):
        raise RuntimeError("db down")


def test_emit_does_not_raise_when_record_alert_fails(tmp_path):
    cfg = _cfg(tmp_path)
    finding = {
        "kind": "leak",
        "dedup_key": "leak:http://x.onion/|acme.com",
        "url": "http://x.onion/",
        "host": "x.onion",
        "term": "acme.com",
        "severity": "critical",
        "context_snippet": "…acme.com…",
        "finding_id": 1,
    }
    # must not raise even though the durable record write blows up
    payload = emit(_DbDown(), cfg, finding, "opened", "2026-07-23T01:00:00")
    assert isinstance(payload, dict)
    assert payload["dedup_key"] == finding["dedup_key"]


def test_reconcile_leaks_full_lifecycle(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    sink = []
    ef = lambda db, cfg, f, ev, now: sink.append((ev, f["dedup_key"])) or {"e": ev}
    u = "http://x.onion/"; key = f"leak:{u}|acme.com"

    # cycle 1: hit -> open + CRITICAL opened
    db.record_leak_hit("r1", u, "x.onion", "leak-site", "verified",
                       "acme.com", "…acme.com…", "2026-07-23T01:00:00")
    a1 = reconcile_leaks(db, cfg, "r1", {u}, "2026-07-23T01:00:00", emit_fn=ef)
    assert len(a1) == 1 and sink[-1] == ("opened", key)
    assert db.get_finding(key)["status"] == "open"

    # cycle 2: same hit, covered -> silent (no new alert)
    db.record_leak_hit("r2", u, "x.onion", "leak-site", "verified",
                       "acme.com", "…acme.com…", "2026-07-23T02:00:00")
    a2 = reconcile_leaks(db, cfg, "r2", {u}, "2026-07-23T02:00:00", emit_fn=ef)
    assert a2 == []
    assert db.get_finding(key)["last_seen"] == "2026-07-23T02:00:00"

    # cycle 3: no hit, url covered -> resolve
    a3 = reconcile_leaks(db, cfg, "r3", {u}, "2026-07-23T03:00:00", emit_fn=ef)
    assert len(a3) == 1 and sink[-1] == ("resolved", key)
    assert db.get_finding(key)["status"] == "resolved"

    # cycle 4: hit again -> reopen + CRITICAL opened
    db.record_leak_hit("r4", u, "x.onion", "leak-site", "verified",
                       "acme.com", "…acme.com…", "2026-07-23T04:00:00")
    a4 = reconcile_leaks(db, cfg, "r4", {u}, "2026-07-23T04:00:00", emit_fn=ef)
    assert len(a4) == 1 and sink[-1] == ("opened", key)
    assert db.get_finding(key)["status"] == "open"


def test_reconcile_leaks_uncovered_url_stays_open(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    ef = lambda db, cfg, f, ev, now: {"e": ev}
    u = "http://x.onion/"; key = f"leak:{u}|acme.com"
    db.record_leak_hit("r1", u, "x.onion", "leak-site", "verified",
                       "acme.com", "…", "2026-07-23T01:00:00")
    reconcile_leaks(db, cfg, "r1", {u}, "2026-07-23T01:00:00", emit_fn=ef)
    # next run: no hit AND url NOT covered (site unreachable) -> must stay open
    a = reconcile_leaks(db, cfg, "r2", set(), "2026-07-23T02:00:00", emit_fn=ef)
    assert a == []
    assert db.get_finding(key)["status"] == "open"
