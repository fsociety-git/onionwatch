import json
from types import SimpleNamespace
from dwcollector.db import Database
from dwcollector.alerts import emit


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
