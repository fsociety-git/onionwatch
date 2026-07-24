import json
from types import SimpleNamespace
from dwcollector.db import Database
from dwcollector.alerts import emit, reconcile_leaks, reconcile_dead_originals
from dwcollector.alerts import reconcile_listing_matches


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


def test_emit_suppresses_dispositioned_finding(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path, webhook="https://sink.local/hook")
    db.open_finding("leak", "leak:x|t", "http://x.onion/", "x.onion", "t",
                    "critical", "…", "2026-07-24T00:00:00")
    db.set_disposition(db.get_finding("leak:x|t")["finding_id"],
                       "false_positive", None, None, "2026-07-24T01:00:00")
    f = db.get_finding("leak:x|t")
    calls = []
    emit(db, cfg, f, "opened", "2026-07-24T02:00:00", post_fn=lambda c, p: calls.append(p))
    # no delivery
    assert calls == []                                    # webhook not called
    assert not (tmp_path / "alerts.jsonl").exists() or \
           open(cfg.alerts_path).read() == ""             # no jsonl line
    # audited as suppressed
    row = list(db.conn.execute("SELECT delivered, suppressed FROM alerts"))[0]
    assert row[0] == 0 and row[1] == 1


def test_emit_delivers_when_not_dispositioned(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path, webhook="https://sink.local/hook")
    db.open_finding("leak", "leak:x|t", "http://x.onion/", "x.onion", "t",
                    "critical", "…", "2026-07-24T00:00:00")
    f = db.get_finding("leak:x|t")                        # disposition defaults to 'new'
    calls = []
    emit(db, cfg, f, "opened", "2026-07-24T02:00:00", post_fn=lambda c, p: calls.append(p))
    assert len(calls) == 1                                # delivered
    assert open(cfg.alerts_path).read() != ""            # jsonl written
    row = list(db.conn.execute("SELECT suppressed FROM alerts"))[0]
    assert row[0] == 0


def _listing(price_raw, product_text, price_value=None, currency="USD"):
    return {"price_value": price_value, "currency": currency,
            "price_raw": price_raw, "product_text": product_text}


def test_reconcile_listing_match_opens_finding(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    db.replace_listings("http://m.onion/1", "m.onion",
                        [_listing("0.05 BTC", "acme-db dump 0.05 BTC")], "t0")
    alerts = reconcile_listing_matches(db, cfg, ["acme-db"], [], "t1")
    fs = db.open_findings("market_listing")
    assert len(fs) == 1
    f = fs[0]
    assert f["kind"] == "market_listing" and f["severity"] == "high"
    assert f["term"] == "acme-db" and f["host"] == "m.onion"
    assert f["dedup_key"] == "listing:m.onion|acme-db"
    assert "0.05 BTC" in f["context_snippet"]        # price in evidence
    assert len(alerts) == 1


def test_reconcile_listing_dedup_same_host_term(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    # two different listing URLs on the same host, both matching the term
    db.replace_listings("http://m.onion/1", "m.onion",
                        [_listing("0.05 BTC", "acme-db one 0.05 BTC")], "t0")
    db.replace_listings("http://m.onion/2", "m.onion",
                        [_listing("1.0 XMR", "acme-db two 1.0 XMR")], "t0")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t1")
    assert len(db.open_findings("market_listing")) == 1     # one finding, host+term


def test_reconcile_listing_resolves_when_gone(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    db.replace_listings("http://m.onion/1", "m.onion",
                        [_listing("0.05 BTC", "acme-db dump")], "t0")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t1")
    db.replace_listings("http://m.onion/1", "m.onion", [], "t2")   # extraction cleared it
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t3")
    assert db.get_finding("listing:m.onion|acme-db")["status"] == "resolved"


def test_reconcile_listing_reopens(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    db.replace_listings("http://m.onion/1", "m.onion",
                        [_listing("0.05 BTC", "acme-db dump")], "t0")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t1")
    db.replace_listings("http://m.onion/1", "m.onion", [], "t2")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t3")      # resolved
    db.replace_listings("http://m.onion/1", "m.onion",
                        [_listing("0.05 BTC", "acme-db back")], "t4")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t5")      # reopened
    assert db.get_finding("listing:m.onion|acme-db")["status"] == "open"


def test_reconcile_listing_pii_match_is_masked(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    db.replace_listings("http://m.onion/c", "m.onion",
                        [_listing("$50", "cards 4111111111111111 for sale")], "t0")
    reconcile_listing_matches(db, cfg, [], ["credit-card"], "t1")
    fs = db.open_findings("market_listing")
    assert len(fs) == 1
    f = fs[0]
    assert f["term"] == "pii:credit-card"
    assert "4111111111111111" not in f["context_snippet"]   # raw PII never stored
    assert "$50" in f["context_snippet"]                    # price present


def test_reconcile_listing_suppressed_disposition(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    url = "http://m.onion/1"
    db.replace_listings(url, "m.onion",
                        [_listing("0.05 BTC", "acme-db 0.05 BTC")], "t0")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t1")       # opened -> delivered
    fid = db.get_finding("listing:m.onion|acme-db")["finding_id"]
    db.set_disposition(fid, "false_positive", None, None, "t2")
    db.replace_listings(url, "m.onion", [], "t3")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t4")       # resolved -> suppressed
    lines = open(cfg.alerts_path, encoding="utf-8").read().splitlines()
    assert len(lines) == 1        # only the opened alert; resolved was suppressed


def test_reconcile_listing_no_listings_returns_empty(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    assert reconcile_listing_matches(db, cfg, ["acme-db"], [], "t0") == []


def test_market_listing_alert_copy():
    from dwcollector.alerts import _title, _body
    f = {"kind": "market_listing", "term": "acme-db", "host": "m.onion",
         "url": "http://m.onion/1", "context_snippet": "[0.05 BTC] acme-db 0.05 BTC"}
    t_open, t_res = _title(f, "opened"), _title(f, "resolved")
    assert "acme-db" in t_open and "m.onion" in t_open and "listing" in t_open.lower()
    assert t_open != t_res
    assert "went dark" not in t_open and "went dark" not in t_res   # not dead-original copy
    b = _body(f, "opened")
    assert "acme-db" in b and "http://m.onion/1" in b and "listing" in b.lower()


def test_market_listing_finding_assignable_to_case(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = _cfg(tmp_path)
    db.replace_listings("http://m.onion/1", "m.onion",
                        [_listing("0.05 BTC", "acme-db dump 0.05 BTC")], "t0")
    reconcile_listing_matches(db, cfg, ["acme-db"], [], "t1")
    fid = db.get_finding("listing:m.onion|acme-db")["finding_id"]
    cid = db.create_case("acme breach", "acme.com", "analyst", "2026-07-24T00:00:00")
    db.assign_finding(fid, cid, "analyst", "2026-07-24T00:00:00")
    findings = db.case_findings(cid)
    assert [f["finding_id"] for f in findings] == [fid]
    assert findings[0]["kind"] == "market_listing"
