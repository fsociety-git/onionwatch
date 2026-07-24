import json
from dwcollector.db import Database
from dwcollector.report import client_findings, build_report, render_json, render_markdown

CLIENT = {"name": "Acme", "terms": ["acme.com", "fuzzy:secret.com"]}


def _leak(db, term, dedup, sev="critical", status="open", disp="new",
          when="2026-07-24T05:00:00", host="x.onion"):
    db.open_finding("leak", dedup, "http://" + host + "/", host, term, sev,
                    "ev-" + term, when)          # first_seen == last_seen == when
    fid = db.get_finding(dedup)["finding_id"]
    if status == "resolved":
        db.resolve_finding(dedup, when)
    if disp != "new":
        db.set_disposition(fid, disp, None, None, when)
    return fid


def test_client_findings_selects_by_client_terms(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _leak(db, "acme.com", "leak:a")
    _leak(db, "secret.com", "leak:b")            # matched via client's fuzzy:secret.com
    _leak(db, "other.com", "leak:c")             # not a client term
    _leak(db, "pii:credit-card", "leak:p")       # leak-kind but not a client key
    db.open_finding("dead_original", "dead:x", "u", "h", None, "high", None, "2026-07-24T00:00:00")
    rows = client_findings(db, CLIENT, include_all=False, since=None)
    assert {f["term"] for f in rows} == {"acme.com", "secret.com"}


def test_client_findings_disposition_and_all_flag(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _leak(db, "acme.com", "leak:fp", disp="false_positive", host="x1.onion")
    _leak(db, "acme.com", "leak:ok", disp="confirmed", host="x2.onion")
    assert len(client_findings(db, CLIENT, include_all=False, since=None)) == 1   # fp excluded
    assert len(client_findings(db, CLIENT, include_all=True, since=None)) == 2    # --all includes


def test_client_findings_since_filter(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _leak(db, "acme.com", "leak:old", when="2026-07-01T00:00:00", host="o.onion")
    _leak(db, "acme.com", "leak:new", when="2026-07-20T00:00:00", host="n.onion")
    rows = client_findings(db, CLIENT, include_all=False, since="2026-07-10T00:00:00")
    assert [f["host"] for f in rows] == ["n.onion"]


def test_client_findings_ordering(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _leak(db, "acme.com", "leak:r", sev="critical", status="resolved",
          when="2026-07-24T09:00:00", host="r.onion")     # resolved -> last
    _leak(db, "acme.com", "leak:oh", sev="high", status="open",
          when="2026-07-24T01:00:00", host="oh.onion")    # open high
    _leak(db, "acme.com", "leak:oc", sev="critical", status="open",
          when="2026-07-24T02:00:00", host="oc.onion")    # open critical -> first
    rows = client_findings(db, CLIENT, include_all=False, since=None)
    assert [f["host"] for f in rows] == ["oc.onion", "oh.onion", "r.onion"]


def test_build_report_summary_and_render(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _leak(db, "acme.com", "leak:a", sev="critical", status="open", host="a.onion")
    _leak(db, "acme.com", "leak:b", sev="high", status="resolved", host="b.onion")
    rows = client_findings(db, CLIENT, include_all=False, since=None)
    rep = build_report("Acme", rows, "2026-07-24T10:00:00", None)
    assert rep["summary"] == {"total": 2, "open": 1, "resolved": 1,
                              "critical": 1, "high": 1, "sites": 2}
    j = json.loads(render_json(rep))
    assert j["client"] == "Acme" and len(j["findings"]) == 2
    md = render_markdown(rep)
    assert "Acme" in md and "a.onion" in md and "acme.com" in md


def test_report_includes_client_cases(tmp_path):
    from dwcollector.report import client_cases
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cid = db.create_case("Acme breach", "Acme", None, "2026-07-24T00:00:00")
    db.create_case("Other", "Beta", None, "2026-07-24T00:00:00")     # different client
    fid = _leak(db, "acme.com", "leak:a")
    db.assign_finding(fid, cid, None, "2026-07-24T01:00:00")

    cases = client_cases(db, "Acme")
    assert [c["title"] for c in cases] == ["Acme breach"]            # Beta's case excluded
    assert cases[0]["findings"] == 1 and cases[0]["state"] == "open"

    rep = build_report("Acme", client_findings(db, CLIENT, False, None),
                       "2026-07-24T10:00:00", None, cases=cases)
    assert rep["cases"][0]["title"] == "Acme breach"
    import json
    assert json.loads(render_json(rep))["cases"][0]["case_id"] == cid
    md = render_markdown(rep)
    assert "Cases" in md and "Acme breach" in md


def test_finding_entry_shared_shape_and_kind(tmp_path):
    from dwcollector.report import _finding_entry
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _leak(db, "acme.com", "leak:a")
    f = db.get_finding("leak:a")
    entry = _finding_entry(f)
    assert entry == {
        "host": "x.onion", "term": "acme.com", "kind": "leak",
        "severity": "critical", "status": "open", "disposition": "new",
        "first_seen": "2026-07-24T05:00:00", "last_seen": "2026-07-24T05:00:00",
        "evidence": "ev-acme.com",
    }


def test_build_report_findings_gain_kind_key(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _leak(db, "acme.com", "leak:a")
    rep = build_report("Acme", client_findings(db, CLIENT, False, None),
                       "2026-07-24T10:00:00", None)
    entry = rep["findings"][0]
    # all previously-existing keys still present, plus the additive kind
    for k in ("host", "term", "severity", "status", "disposition",
              "first_seen", "last_seen", "evidence"):
        assert k in entry
    assert entry["kind"] == "leak"
