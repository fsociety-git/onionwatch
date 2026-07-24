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
