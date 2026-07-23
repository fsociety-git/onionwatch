import json
from types import SimpleNamespace
from dwcollector.db import Database
from dwcollector.alerts import emit, reconcile_leaks, reconcile_dead_originals


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


def _canonical(db, url, alive):
    host = url.split("//")[1].strip("/")
    db.upsert_url(url, host, "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(url, is_canonical=1, trust="verified", alive=alive)


def test_reconcile_dead_original_lifecycle(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    sink = []
    ef = lambda db, cfg, f, ev, now: sink.append((ev, f["severity"], f["dedup_key"])) or {"e": ev}
    u = "http://orig.onion/"; key = f"dead:{u}"

    # alive -> no finding
    _canonical(db, u, alive=1)
    a0 = reconcile_dead_originals(db, cfg, "2026-07-23T01:00:00", emit_fn=ef)
    assert a0 == [] and db.get_finding(key) is None

    # went dark -> open HIGH
    db.update_url(u, alive=0)
    a1 = reconcile_dead_originals(db, cfg, "2026-07-23T02:00:00", emit_fn=ef)
    assert len(a1) == 1 and sink[-1] == ("opened", "high", key)
    assert db.get_finding(key)["status"] == "open"

    # still dark -> silent
    a2 = reconcile_dead_originals(db, cfg, "2026-07-23T03:00:00", emit_fn=ef)
    assert a2 == []

    # recovered -> resolve
    db.update_url(u, alive=1)
    a3 = reconcile_dead_originals(db, cfg, "2026-07-23T04:00:00", emit_fn=ef)
    assert len(a3) == 1 and sink[-1][0] == "resolved"
    assert db.get_finding(key)["status"] == "resolved"


from dwcollector.alerts import _title, _body


def _pii_finding():
    return {"kind": "leak", "dedup_key": "leak:http://x.onion/|pii:credit-card",
            "url": "http://x.onion/", "host": "x.onion", "term": "pii:credit-card",
            "severity": "critical", "context_snippet": "•••• •••• •••• 1111"}


def _ident_finding():
    return {"kind": "leak", "dedup_key": "leak:http://x.onion/|acme.com",
            "url": "http://x.onion/", "host": "x.onion", "term": "acme.com",
            "severity": "critical", "context_snippet": "…acme.com…"}


def test_title_pii_reads_naturally():
    t = _title(_pii_finding(), "opened")
    assert "Credit-card" in t and "x.onion" in t
    assert "Client identifier 'pii:" not in t


def test_title_identifier_unchanged():
    assert _title(_ident_finding(), "opened") == \
        "Client identifier 'acme.com' exposed on x.onion"


def test_body_pii_does_not_leak_raw_but_shows_masked():
    b = _body(_pii_finding(), "opened")
    assert "1111" in b and "•" in b


from dwcollector.alerts import reconcile_dead_originals, _candidate_note


def _dead_anchor_with_sibling(db, alive_sibling: bool):
    a = "http://anchor.onion/"
    db.upsert_url(a, "anchor.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(a, is_canonical=1, trust="verified", cluster_id="c1", alive=0)
    if alive_sibling:
        s = "http://sib.onion/"
        db.upsert_url(s, "sib.onion", "crawled", 1, "2026-07-23T00:00:00")
        db.update_url(s, cluster_id="c1", alive=1)
    return a


def test_candidate_note_lists_live_siblings(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _dead_anchor_with_sibling(db, alive_sibling=True)
    note = _candidate_note(db, db.get_url("http://anchor.onion/"))
    assert "verify before trusting" in note and "http://sib.onion/" in note


def test_candidate_note_no_sibling(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _dead_anchor_with_sibling(db, alive_sibling=False)
    note = _candidate_note(db, db.get_url("http://anchor.onion/"))
    assert "no live successor" in note


def test_reconcile_dead_original_carries_candidates(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)   # helper already in test_alerts.py
    _dead_anchor_with_sibling(db, alive_sibling=True)
    reconcile_dead_originals(db, cfg, "2026-07-23T00:00:00",
                             emit_fn=lambda db, cfg, f, ev, now: {"e": ev})
    f = db.get_finding("dead:http://anchor.onion/")
    assert f["status"] == "open"
    assert "http://sib.onion/" in (f["context_snippet"] or "")


from dwcollector.alerts import reconcile_anchor_identity


def _anchor_row(db, url="http://aaaaaaaaaaaaaaaa.onion/", host="aaaaaaaaaaaaaaaa.onion"):
    db.upsert_url(url, host, "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(url, is_canonical=1, trust="verified", cluster_id="c1", alive=1)
    return url


def test_reconcile_anchor_identity_lifecycle(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    u = _anchor_row(db)
    ef = lambda db, cfg, f, ev, now: (ev, f["severity"], f["dedup_key"])
    key = f"identity:{u}"

    # fail -> open HIGH
    a1 = reconcile_anchor_identity(db, cfg, {u}, {u}, "2026-07-23T01:00:00", emit_fn=ef)
    assert len(a1) == 1 and a1[0] == ("opened", "high", key)
    assert db.get_finding(key)["status"] == "open"

    # still failing (checked+failed) -> silent
    assert reconcile_anchor_identity(db, cfg, {u}, {u}, "2026-07-23T02:00:00", emit_fn=ef) == []

    # dead / unchecked this run (not in identity_checked) -> stays open (coverage gate)
    assert reconcile_anchor_identity(db, cfg, set(), set(), "2026-07-23T03:00:00", emit_fn=ef) == []
    assert db.get_finding(key)["status"] == "open"

    # checked and passed -> resolve
    a4 = reconcile_anchor_identity(db, cfg, {u}, set(), "2026-07-23T04:00:00", emit_fn=ef)
    assert len(a4) == 1 and a4[0][0] == "resolved"
    assert db.get_finding(key)["status"] == "resolved"


def test_anchor_identity_title_and_body():
    f = {"kind": "anchor_identity", "host": "aaaaaaaaaaaaaaaa.onion", "url": "http://aaaaaaaaaaaaaaaa.onion/",
         "context_snippet": "verify before trusting — candidate successors: http://sib.onion/"}
    assert _title(f, "opened") == "Verified anchor aaaaaaaaaaaaaaaa.onion failed identity re-verification"
    assert "recovered" in _title(f, "resolved")
    assert "http://sib.onion/" in _body(f, "opened")


def test_dead_original_body_carries_candidate_note():
    f = {"kind": "dead_original", "host": "x.onion", "url": "http://x.onion/",
         "context_snippet": "verify before trusting — candidate successors: http://sib.onion/"}
    assert "http://sib.onion/" in _body(f, "opened")
