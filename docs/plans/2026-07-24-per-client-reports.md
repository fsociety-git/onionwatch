# Per-Client Reports — Implementation Plan


**Goal:** Produce a Markdown/JSON report of one client's dark-web leak findings (with evidence and disposition), backed by a minimal `clients.toml` model that also feeds the loop's watchlist.

**Architecture:** `clients.toml` maps clients to watchlist terms (`config.load_clients`); the loop's watchlist becomes `terms.txt` ∪ client terms. Membership is derived at report time — a finding belongs to a client when its `term` equals a client term's underlying key (`matching.underlying_key`). A new `report.py` selects/summarizes/renders; a `report` CLI command prints to stdout.

**Tech Stack:** Python 3.11+, stdlib only (json, tomllib via existing `_read_toml`), pytest. No new dependencies.

**Spec:** `docs/specs/2026-07-24-per-client-reports-design.md`

## Global Constraints

- Python 3.11+; add no new third-party dependencies.
- **Opt-in:** absent `clients.toml` → `load_clients` returns `[]` → the watchlist union with `[]` is unchanged and `report` for any name errors cleanly. Zero behavior change until `clients.toml` exists.
- **Report scope:** `kind='leak'` findings whose `term` is in the client's resolved key set; **exclude `false_positive`/`dismissed`** unless `--all`; include open + resolved. PII (`pii:*`) and infrastructure (`dead_original`/`anchor_identity`) findings are never in a client report.
- `underlying_key` mirrors `match_term`'s key derivation exactly: strip `fuzzy:`/`enc:`/`cred:` to the identifier; leave `re:`-prefixed and literal terms verbatim.
- Watchlist union applies **only in `run_cycle`**; the ad-hoc `hunt --terms FILE` (`_run_hunt`) is left unchanged.
- Reports contain only the already-masked/bounded `context_snippet` evidence — never raw leaked data.
- Timestamps UTC `"%Y-%m-%dT%H:%M:%S"`; `--since` compared as an ISO string (lexicographic == chronological for that format).
- Follow existing test style: `pytest`, `Database(str(tmp_path / "t.db"))`, `capsys` for CLI output.

---

### Task 1: Foundation helpers — `matching.underlying_key` + `config.load_clients`

**Files:**
- Modify: `src/onionwatch/matching.py` (add `underlying_key`)
- Modify: `src/onionwatch/config.py` (add `load_clients`)
- Test: `tests/test_matching.py`, `tests/test_config.py` (append)

**Interfaces:**
- Produces: `matching.underlying_key(term: str) -> str`; `config.load_clients(path="clients.toml") -> list[dict]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_matching.py`:

```python
from onionwatch.matching import underlying_key


def test_underlying_key_strips_prefixes_but_keeps_re_and_literal():
    assert underlying_key("acme.com") == "acme.com"          # literal unchanged
    assert underlying_key("fuzzy:acme.com") == "acme.com"    # fuzzy stripped
    assert underlying_key("enc:SECRET") == "SECRET"          # enc stripped
    assert underlying_key("cred:u@x.com") == "u@x.com"       # cred stripped
    assert underlying_key("re:ACME-[A-Z]+") == "re:ACME-[A-Z]+"  # re: kept (matches finding key)
```

Append to `tests/test_config.py`:

```python
def test_load_clients_missing_file_returns_empty(tmp_path):
    from onionwatch.config import load_clients
    assert load_clients(str(tmp_path / "nope.toml")) == []


def test_load_clients_parses_and_skips_malformed(tmp_path, capsys):
    from onionwatch.config import load_clients
    p = tmp_path / "clients.toml"
    p.write_text(
        '[[client]]\n'
        'name = "Acme Corp"\n'
        'terms = ["acme-corp.com", "fuzzy:ACME-DB"]\n\n'
        '[[client]]\n'          # malformed: no terms
        'name = "Beta"\n'
    )
    cs = load_clients(str(p))
    assert [c["name"] for c in cs] == ["Acme Corp"]
    assert "Beta" in capsys.readouterr().err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_matching.py::test_underlying_key_strips_prefixes_but_keeps_re_and_literal tests/test_config.py::test_load_clients_missing_file_returns_empty -v`
Expected: FAIL — `ImportError` for `underlying_key` / `load_clients`

- [ ] **Step 3: Write minimal implementation**

Add to `src/onionwatch/matching.py`:

```python
def underlying_key(term: str) -> str:
    """The finding key for a watchlist term: fuzzy:/enc:/cred: strip to the
    identifier; re: and literal terms are kept verbatim (mirrors match_term)."""
    for p in ("fuzzy:", "enc:", "cred:"):
        if term.startswith(p):
            return term[len(p):]
    return term
```

Add to `src/onionwatch/config.py` (near `load_sources`):

```python
def load_clients(path: str = "clients.toml") -> list[dict]:
    try:
        data = _read_toml(path)
    except FileNotFoundError:
        return []
    valid: list[dict] = []
    for i, c in enumerate(data.get("client", [])):
        name, terms = c.get("name"), c.get("terms")
        if name and isinstance(terms, list) and terms:
            valid.append(c)
        else:
            print(f"clients: skipping malformed client entry #{i} ({name or '?'})",
                  file=sys.stderr)
    return valid
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_matching.py tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/matching.py src/onionwatch/config.py tests/test_matching.py tests/test_config.py
git commit -m "feat: underlying_key + load_clients for per-client reports"
```

---

### Task 2: `report.py` — selection, summary, renderers

**Files:**
- Create: `src/onionwatch/report.py`
- Test: `tests/test_report.py` (create)

**Interfaces:**
- Consumes: `matching.underlying_key` (Task 1), `db.list_findings`.
- Produces: `client_findings(db, client, include_all, since) -> list[dict]`; `build_report(client_name, findings, now, since=None) -> dict`; `render_json(report) -> str`; `render_markdown(report) -> str`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report.py`:

```python
import json
from onionwatch.db import Database
from onionwatch.report import client_findings, build_report, render_json, render_markdown

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report.py::test_client_findings_selects_by_client_terms -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.report'`

- [ ] **Step 3: Write minimal implementation**

Create `src/onionwatch/report.py`:

```python
from __future__ import annotations
import json
from .matching import underlying_key

_DISMISSED = ("false_positive", "dismissed")


def client_findings(db, client: dict, include_all: bool, since: str | None) -> list[dict]:
    keys = {underlying_key(t) for t in client.get("terms", [])}
    rows = [f for f in db.list_findings()
            if f.get("kind") == "leak" and f.get("term") in keys]
    if not include_all:
        rows = [f for f in rows if f.get("disposition") not in _DISMISSED]
    if since:
        rows = [f for f in rows if (f.get("last_seen") or "") >= since]
    # stable two-pass: most-recent first, then open-before-resolved / critical-before-high
    rows.sort(key=lambda f: f.get("last_seen") or "", reverse=True)
    rows.sort(key=lambda f: (0 if f.get("status") == "open" else 1,
                             0 if f.get("severity") == "critical" else 1))
    return rows


def build_report(client_name: str, findings: list[dict], now: str,
                 since: str | None = None) -> dict:
    summary = {
        "total": len(findings),
        "open": sum(1 for f in findings if f.get("status") == "open"),
        "resolved": sum(1 for f in findings if f.get("status") == "resolved"),
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high": sum(1 for f in findings if f.get("severity") == "high"),
        "sites": len({f.get("host") for f in findings}),
    }
    return {
        "client": client_name, "generated_at": now, "since": since,
        "summary": summary,
        "findings": [{
            "host": f.get("host"), "term": f.get("term"), "severity": f.get("severity"),
            "status": f.get("status"), "disposition": f.get("disposition") or "new",
            "first_seen": f.get("first_seen"), "last_seen": f.get("last_seen"),
            "evidence": f.get("context_snippet") or "",
        } for f in findings],
    }


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render_markdown(report: dict) -> str:
    s = report["summary"]
    since = f"  ·  since {report['since']}" if report.get("since") else ""
    lines = [
        f"# Dark-web exposure report — {report['client']}",
        "",
        f"Generated: {report['generated_at']}{since}",
        "",
        (f"**{s['total']}** findings — {s['open']} open, {s['resolved']} resolved · "
         f"{s['critical']} critical, {s['high']} high · {s['sites']} sites"),
        "",
    ]
    if not report["findings"]:
        lines.append("_No findings._")
    for f in report["findings"]:
        lines += [
            f"## {f['host']} — `{f['term']}`",
            f"- Severity: {f['severity']}  ·  Status: {f['status']}  ·  Disposition: {f['disposition']}",
            f"- First seen: {f['first_seen']}  ·  Last seen: {f['last_seen']}",
            f"- Evidence: {f['evidence']}",
            "",
        ]
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_report.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/report.py tests/test_report.py
git commit -m "feat: report.py — client_findings, build_report, md/json renderers"
```

---

### Task 3: CLI — watchlist union in `run_cycle` + `report` command

**Files:**
- Modify: `src/onionwatch/cli.py` (import, `run_cycle` term assembly, `build_parser`, `_run_report`, `main` dispatch)
- Test: `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `load_clients` (Task 1), `client_findings`/`build_report`/`render_json`/`render_markdown` (Task 2).
- Produces: `run_cycle` hunts `terms.txt` ∪ client terms; `report --client NAME [--format md|json] [--since DATE] [--all]`; `_run_report(db, args) -> int`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli.py`:

```python
from onionwatch.report import client_findings as _cf  # noqa: F401 (ensures import path)


def test_run_cycle_unions_client_terms(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.hunt import HuntOutcome
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    (tmp_path / "wl.txt").write_text("baseterm\n")
    cfg = Config(watchlist_terms=str(tmp_path / "wl.txt"),
                 alerts_path=str(tmp_path / "a.jsonl"))
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "C", "terms": ["clientterm"]}])
    monkeypatch.setattr(cli_mod, "load_sources", lambda p: [])
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda p: {"verified_onions": [], "pgp": {}, "directories": []})
    recorded = {}

    async def hunt_stub(db, client, terms, run_id, now, detectors=None, verified=None):
        recorded["terms"] = terms
        return HuntOutcome(0, set(), set(), set())
    monkeypatch.setattr(cli_mod, "hunt", hunt_stub)

    res = run_cycle(cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
                    crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
                    cluster_fn=lambda *a, **k: 0, client_factory=lambda cfg: _StubClient(""))
    assert res["ok"] is True
    assert "baseterm" in recorded["terms"] and "clientterm" in recorded["terms"]


def test_report_command_json_and_unknown_client(tmp_path, capsys, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "ev", "2026-07-24T00:00:00")
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "Acme", "terms": ["acme.com"]}])

    args = build_parser().parse_args(["report", "--client", "Acme", "--format", "json"])
    assert _run_report(db, args) == 0
    import json as _json
    doc = _json.loads(capsys.readouterr().out)
    assert doc["client"] == "Acme" and doc["summary"]["total"] == 1

    bad = build_parser().parse_args(["report", "--client", "Nope"])
    assert _run_report(db, bad) == 1
    assert "Nope" in capsys.readouterr().err


def test_report_all_flag_includes_dismissed(tmp_path, capsys, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "ev", "2026-07-24T00:00:00")
    db.set_disposition(db.get_finding("leak:http://x.onion/|acme.com")["finding_id"],
                       "dismissed", None, None, "2026-07-24T01:00:00")
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "Acme", "terms": ["acme.com"]}])
    import json as _json
    _run_report(db, build_parser().parse_args(["report", "--client", "Acme", "--format", "json"]))
    assert _json.loads(capsys.readouterr().out)["summary"]["total"] == 0   # dismissed excluded
    _run_report(db, build_parser().parse_args(["report", "--client", "Acme", "--format", "json", "--all"]))
    assert _json.loads(capsys.readouterr().out)["summary"]["total"] == 1   # --all includes
```

(`_StubClient`, `Config`, `Database`, `SimpleNamespace`, `run_cycle` are already imported in `tests/test_cli.py` from earlier specs.)

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_run_cycle_unions_client_terms -v`
Expected: FAIL — `run_cycle` doesn't union client terms (`recorded["terms"]` lacks `clientterm`); `_run_report`/`report` don't exist

- [ ] **Step 3: Write minimal implementation**

In `src/onionwatch/cli.py`, extend the config import to include `load_clients`, and add the report imports:

```python
from .config import (load_config, load_categories, load_verified_sources,
                     load_sources, load_clients)
from .report import client_findings, build_report, render_json, render_markdown
```

In `run_cycle`, replace the term-loading lines:

```python
        terms = []
        if os.path.exists(cfg.watchlist_terms):
            terms = load_terms(cfg.watchlist_terms)
```

with the client-augmented union:

```python
        clients = load_clients("clients.toml")
        base = load_terms(cfg.watchlist_terms) if os.path.exists(cfg.watchlist_terms) else []
        terms = list(dict.fromkeys(base + [t for c in clients for t in c["terms"]]))
```

(Everything else in the block — `verified`, `run_id`, `go_hunt`, the `if terms:` gate — is unchanged; the union just feeds the existing logic.)

Add the `report` subparser in `build_parser` (after `history`):

```python
    rp = sub.add_parser("report")
    rp.add_argument("--client", required=True)
    rp.add_argument("--format", choices=["md", "json"], default="md")
    rp.add_argument("--since", default=None)
    rp.add_argument("--all", action="store_true")
```

Add the handler (near `_run_alerts`):

```python
def _run_report(db, args) -> int:
    clients = load_clients("clients.toml")
    client = next((c for c in clients if c.get("name") == args.client), None)
    if client is None:
        print(f"unknown client: {args.client!r}", file=sys.stderr)
        return 1
    findings = client_findings(db, client, args.all, args.since)
    report = build_report(args.client, findings, _now(), args.since)
    print(render_json(report) if args.format == "json" else render_markdown(report))
    return 0
```

Add the dispatch branch in `main` (after the `history` branch):

```python
    elif args.command == "report":
        return _run_report(db, args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (new tests + existing cli tests — the existing `run_cycle` tests still pass because with no `clients.toml`/monkeypatch the union equals the old `terms.txt`-only list, and their injected stubs are unaffected)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/cli.py tests/test_cli.py
git commit -m "feat: run_cycle unions client terms; report CLI command"
```

---

### Task 4: Docs — `clients.toml.example` + README

**Files:**
- Create: `clients.toml.example`
- Modify: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Create `clients.toml.example`**

Create `clients.toml.example`:

```toml
# Clients and the watchlist terms that belong to them. Optional; absent = no
# clients (per-client reports unavailable, watchlist unchanged).
# Client terms are added to the loop's hunt watchlist (deduped with terms.txt),
# and a client's report includes findings matching these terms. Terms may use
# the same match prefixes as the watchlist (fuzzy:/enc:/cred:/re:).

# [[client]]
# name  = "Acme Corp"
# terms = ["acme-corp.com", "billing@acme-corp.com", "fuzzy:ACME-CUSTOMER-DB"]
```

- [ ] **Step 2: Document per-client reports in README**

Add a "Per-client reports" subsection to `README.md` near the alerting/triage content covering: `clients.toml` (default absent = off) maps clients to watchlist terms; those terms are added to the loop watchlist (deduped) so they're hunted; `onionwatch report --client "Acme Corp" [--format md|json] [--since DATE] [--all]` writes a report to stdout (redirect to a file); the report includes the client's **leak** findings (open + resolved) with evidence and disposition; `false_positive`/`dismissed` are excluded unless `--all`; `--since` limits to findings active since a date; and that reports contain only masked evidence, never raw leaked data. Note the Markdown output converts to PDF/DOCX with any standard tool.

- [ ] **Step 3: Verify suite green and commit**

Run: `pytest -q`
Expected: all green (docs-only change).

```bash
git add README.md clients.toml.example
git commit -m "docs: document per-client reports and clients.toml"
```

---

## Final verification

- [ ] Run the full suite: `pytest -q` — expect all prior tests plus the new ones green.
- [ ] Smoke a report offline: open a leak finding for `acme.com`, add a client `Acme` with that term (monkeypatch or a temp `clients.toml`), run `report --client Acme --format md` — expect a Markdown report listing the finding.
- [ ] Confirm `run_cycle` with no `clients.toml` is unchanged and `git log --oneline` shows one commit per task with a clean tree.
