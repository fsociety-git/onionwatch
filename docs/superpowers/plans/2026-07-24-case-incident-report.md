# Standalone Single-Case Incident Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `report --case <id>` — a full Markdown/JSON incident dossier for one case (metadata, summary, every member finding, complete timeline).

**Architecture:** Reuse the existing case-management data layer (`get_case`, `case_findings`, `case_history`) and render through new dedicated functions in `report.py` (`build_case_report` + `render_case_markdown`/`render_case_json`), sharing a `_finding_entry` helper with the per-client report. Wire it into the existing `report` CLI command via a required, mutually-exclusive `--client`/`--case` group. No schema changes.

**Tech Stack:** Python 3.11+, stdlib only (`json`, `datetime`), pytest.

## Global Constraints

- Python 3.11+; **no new dependencies** (stdlib only).
- Additive only: the existing per-client report (`report --client`), its summary, findings section, and `--all`/`--since` filters must remain behaviorally unchanged — except each client finding entry gains one additive `kind` key.
- Membership on the case path is **unfiltered**: the case report renders exactly what `db.case_findings(case_id)` returns — no kind filter, no disposition filter. `--all`/`--since` do not apply to the case path.
- Evidence is the existing bounded `context_snippet`; no new evidence gathering, no raw PII/secret introduced.
- Error idiom matches the existing handlers: bad id → clear stderr message + `return 1`, never a traceback or partial output.
- Follow existing test style: `pytest`, `Database(str(tmp_path / "t.db"))`, `build_parser().parse_args([...])`, `capsys`.
- Timestamps are ISO-8601 `"%Y-%m-%dT%H:%M:%S"`.
- Run the suite with `.venv/bin/python -m pytest` (pytest is not on PATH). Baseline before this plan: **203 passed, 1 deselected**.

---

## File Structure

- `src/dwcollector/report.py` (modify) — add `_finding_entry`, `_fmt_delta`, `_duration`, `_count_by`, `build_case_report`, `render_case_json`, `render_case_markdown`; refactor `build_report` to call `_finding_entry`.
- `src/dwcollector/cli.py` (modify) — make `report`'s `--client`/`--case` a required mutually-exclusive group; branch `_run_report` on `args.case`; extend the `.report` import.
- `tests/test_report.py` (modify) — tests for the shared helper/refactor, `build_case_report`, and the renderers.
- `tests/test_cli.py` (modify) — tests for the case-report CLI path and the mutually-exclusive group.
- `README.md` (modify) — document `report --case`.

---

### Task 1: Shared `_finding_entry` helper + `build_report` refactor

**Files:**
- Modify: `src/dwcollector/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `_finding_entry(f: dict) -> dict` returning `{host, term, kind, severity, status, disposition, first_seen, last_seen, evidence}`. `build_report` uses it for each finding entry (its output is unchanged except each finding entry now also carries `kind`).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_report.py` (the `_leak` helper and `CLIENT` already exist at the top of the file):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_report.py::test_finding_entry_shared_shape_and_kind tests/test_report.py::test_build_report_findings_gain_kind_key -v`
Expected: FAIL — `ImportError: cannot import name '_finding_entry'` (first test), and `KeyError`/assert on `kind` (second).

- [ ] **Step 3: Add the helper and refactor `build_report`**

In `src/dwcollector/report.py`, add the helper just below the `_DISMISSED` constant (after line 5):

```python
def _finding_entry(f: dict) -> dict:
    return {
        "host": f.get("host"), "term": f.get("term"), "kind": f.get("kind"),
        "severity": f.get("severity"), "status": f.get("status"),
        "disposition": f.get("disposition") or "new",
        "first_seen": f.get("first_seen"), "last_seen": f.get("last_seen"),
        "evidence": f.get("context_snippet") or "",
    }
```

Then replace the `"findings": [ ... ]` list-comprehension in `build_report` (currently lines 43-48) with:

```python
        "findings": [_finding_entry(f) for f in findings],
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_report.py -v`
Expected: PASS (the two new tests and all pre-existing report tests, including `test_report_includes_client_cases`).

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/report.py tests/test_report.py
git commit -m "refactor: shared _finding_entry helper (adds additive kind key)"
```

---

### Task 2: `build_case_report` + duration/count helpers

**Files:**
- Modify: `src/dwcollector/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `_finding_entry` (Task 1); `db.get_case`, `db.case_findings`, `db.case_history` (existing).
- Produces:
  - `build_case_report(case: dict, findings: list[dict], history: list[dict], now: str) -> dict` returning `{case: {case_id,title,client,state,created_at,created_by,closed_at,duration}, generated_at, summary: {total,open,resolved,critical,high,by_kind,by_disposition,sites}, findings: [_finding_entry...], timeline: [{at,actor,event,note}...]}`.
  - `_duration(created_at, closed_at, now) -> str`; `_count_by(findings, key) -> dict`; `_fmt_delta(td) -> str`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_report.py`. Add this import near the top imports (or inline in each test):

```python
from dwcollector.report import build_case_report, render_case_json, render_case_markdown
```

Then the tests:

```python
def _mixed_case(tmp_path):
    """A case with a false_positive critical leak and a high dead_original."""
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cid = db.create_case("Acme breach", "Acme", "an@corp", "2026-07-24T00:00:00")
    db.open_finding("leak", "leak:a", "http://a.onion/", "a.onion", "acme.com",
                    "critical", "ev-a", "2026-07-24T01:00:00")
    fa = db.get_finding("leak:a")["finding_id"]
    db.set_disposition(fa, "false_positive", None, "an@corp", "2026-07-24T01:30:00")
    db.open_finding("dead_original", "dead:b", "http://b.onion/", "b.onion", None,
                    "high", None, "2026-07-24T02:00:00")
    fb = db.get_finding("dead:b")["finding_id"]
    db.assign_finding(fa, cid, "an@corp", "2026-07-24T03:00:00")
    db.assign_finding(fb, cid, "an@corp", "2026-07-24T03:05:00")
    return db, cid


def test_build_case_report_metadata_and_summary(tmp_path):
    db, cid = _mixed_case(tmp_path)
    rep = build_case_report(db.get_case(cid), db.case_findings(cid),
                            db.case_history(cid), "2026-07-26T00:00:00")
    assert rep["case"]["case_id"] == cid
    assert rep["case"]["title"] == "Acme breach"
    assert rep["case"]["client"] == "Acme"
    assert rep["case"]["state"] == "open"
    assert rep["case"]["closed_at"] is None
    assert rep["case"]["duration"].startswith("open ")     # created -> now, open
    s = rep["summary"]
    assert s["total"] == 2 and s["critical"] == 1 and s["high"] == 1
    assert s["sites"] == 2
    assert s["by_kind"] == {"leak": 1, "dead_original": 1}
    assert s["by_disposition"] == {"false_positive": 1, "new": 1}


def test_build_case_report_curated_includes_false_positive(tmp_path):
    db, cid = _mixed_case(tmp_path)
    rep = build_case_report(db.get_case(cid), db.case_findings(cid),
                            db.case_history(cid), "2026-07-26T00:00:00")
    # the false_positive member is NOT filtered out (curated, unfiltered)
    assert any(f["disposition"] == "false_positive" for f in rep["findings"])
    assert len(rep["findings"]) == 2


def test_build_case_report_timeline_complete_and_ordered(tmp_path):
    db, cid = _mixed_case(tmp_path)
    rep = build_case_report(db.get_case(cid), db.case_findings(cid),
                            db.case_history(cid), "2026-07-26T00:00:00")
    events = [e["event"] for e in rep["timeline"]]
    assert events[0] == "created"                          # oldest-first
    assert "assigned finding #1" in events and "assigned finding #2" in events
    # timeline carries actor + timestamp
    assert all("at" in e and "actor" in e for e in rep["timeline"])


def test_build_case_report_duration_closed(tmp_path):
    db, cid = _mixed_case(tmp_path)
    db.set_case_state(cid, "closed", None, "an@corp", "2026-07-24T04:00:00")
    rep = build_case_report(db.get_case(cid), db.case_findings(cid),
                            db.case_history(cid), "2026-07-30T00:00:00")
    # created 00:00 -> closed 04:00 == 4h; must NOT be labeled open
    assert rep["case"]["closed_at"] == "2026-07-24T04:00:00"
    assert rep["case"]["duration"] == "4h"


def test_duration_degrades_on_bad_timestamp(tmp_path):
    from dwcollector.report import _duration
    assert _duration(None, None, "2026-07-24T00:00:00") == ""
    assert _duration("garbage", None, "2026-07-24T00:00:00") == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_report.py -k "case_report or duration_degrades" -v`
Expected: FAIL — `ImportError: cannot import name 'build_case_report'`.

- [ ] **Step 3: Implement the builder and helpers**

At the top of `src/dwcollector/report.py`, extend the imports (currently `import json`):

```python
import json
from datetime import datetime
```

Add a module constant near `_DISMISSED`:

```python
_TS = "%Y-%m-%dT%H:%M:%S"
```

Add the helpers and builder (place after `_finding_entry`):

```python
def _fmt_delta(td) -> str:
    total = max(0, int(td.total_seconds()))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if not parts:
        parts.append(f"{mins}m")
    return " ".join(parts)


def _parse_ts(s):
    try:
        return datetime.strptime(s, _TS)
    except (TypeError, ValueError):
        return None


def _duration(created_at, closed_at, now) -> str:
    start = _parse_ts(created_at)
    if start is None:
        return ""
    if closed_at:
        end = _parse_ts(closed_at)
        return _fmt_delta(end - start) if end else ""
    end = _parse_ts(now)
    return "open " + _fmt_delta(end - start) if end else ""


def _count_by(findings, key) -> dict:
    fn = key if callable(key) else (lambda f: f.get(key))
    out = {}
    for f in findings:
        k = fn(f)
        out[k] = out.get(k, 0) + 1
    return out


def build_case_report(case: dict, findings: list[dict],
                      history: list[dict], now: str) -> dict:
    summary = {
        "total": len(findings),
        "open": sum(1 for f in findings if f.get("status") == "open"),
        "resolved": sum(1 for f in findings if f.get("status") == "resolved"),
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high": sum(1 for f in findings if f.get("severity") == "high"),
        "by_kind": _count_by(findings, "kind"),
        "by_disposition": _count_by(findings, lambda f: f.get("disposition") or "new"),
        "sites": len({f.get("host") for f in findings}),
    }
    return {
        "case": {
            "case_id": case["case_id"], "title": case["title"],
            "client": case.get("client"), "state": case["state"],
            "created_at": case.get("created_at"),
            "created_by": case.get("created_by"),
            "closed_at": case.get("closed_at"),
            "duration": _duration(case.get("created_at"),
                                  case.get("closed_at"), now),
        },
        "generated_at": now,
        "summary": summary,
        "findings": [_finding_entry(f) for f in findings],
        "timeline": [{"at": h.get("at"), "actor": h.get("actor"),
                      "event": h.get("event"), "note": h.get("note")}
                     for h in history],
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_report.py -v`
Expected: PASS (all new case-report tests + all prior report tests).

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/report.py tests/test_report.py
git commit -m "feat: build_case_report + duration/count helpers"
```

---

### Task 3: Case renderers (`render_case_json` / `render_case_markdown`)

**Files:**
- Modify: `src/dwcollector/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `build_case_report` output (Task 2).
- Produces: `render_case_json(report: dict) -> str`; `render_case_markdown(report: dict) -> str`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_report.py` (reuses `_mixed_case` from Task 2):

```python
def test_render_case_json_round_trips(tmp_path):
    db, cid = _mixed_case(tmp_path)
    rep = build_case_report(db.get_case(cid), db.case_findings(cid),
                            db.case_history(cid), "2026-07-26T00:00:00")
    doc = json.loads(render_case_json(rep))
    assert doc["case"]["case_id"] == cid
    assert doc["summary"]["total"] == 2
    assert len(doc["timeline"]) == len(rep["timeline"])


def test_render_case_markdown_contains_key_content(tmp_path):
    db, cid = _mixed_case(tmp_path)
    rep = build_case_report(db.get_case(cid), db.case_findings(cid),
                            db.case_history(cid), "2026-07-26T00:00:00")
    md = render_case_markdown(rep)
    assert "# Incident Report: Acme breach" in md
    assert f"case #{cid}" in md
    assert "acme.com" in md and "a.onion" in md      # a member finding
    assert "## Timeline" in md
    assert "created" in md                            # a timeline event
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_report.py -k "render_case" -v`
Expected: FAIL — `ImportError: cannot import name 'render_case_json'`.

- [ ] **Step 3: Implement the renderers**

Append to `src/dwcollector/report.py`:

```python
def render_case_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render_case_markdown(report: dict) -> str:
    c, s = report["case"], report["summary"]
    by_kind = ", ".join(f"{k} {n}" for k, n in s["by_kind"].items()) or "none"
    by_disp = ", ".join(f"{k} {n}" for k, n in s["by_disposition"].items()) or "none"
    lines = [
        f"# Incident Report: {c['title']} (case #{c['case_id']})",
        "",
        f"- Client: {c['client'] or '—'}",
        f"- State: {c['state']}  ·  Duration: {c['duration'] or '—'}",
        f"- Opened: {c['created_at']} by {c['created_by'] or '—'}",
        f"- Closed: {c['closed_at'] or '—'}",
        f"- Generated: {report['generated_at']}",
        "",
        (f"**{s['total']}** findings — {s['open']} open, {s['resolved']} resolved · "
         f"{s['critical']} critical, {s['high']} high · {s['sites']} sites"),
        f"- By kind: {by_kind}",
        f"- By disposition: {by_disp}",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("_No findings in this case._")
        lines.append("")
    for f in report["findings"]:
        lines += [
            f"### {f['host']} — `{f['term']}`",
            (f"- Kind: {f['kind']}  ·  Severity: {f['severity']}  ·  "
             f"Status: {f['status']}  ·  Disposition: {f['disposition']}"),
            f"- First seen: {f['first_seen']}  ·  Last seen: {f['last_seen']}",
            f"- Evidence: {f['evidence']}",
            "",
        ]
    lines += ["## Timeline", ""]
    if not report["timeline"]:
        lines.append("_No timeline events._")
    for e in report["timeline"]:
        note = f" — {e['note']}" if e.get("note") else ""
        lines.append(f"- {e['at']} — {e['actor'] or '—'}: {e['event']}{note}")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_report.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/report.py tests/test_report.py
git commit -m "feat: render_case_json/markdown incident-report renderers"
```

---

### Task 4: CLI wiring (`report --case` + mutually-exclusive group)

**Files:**
- Modify: `src/dwcollector/cli.py` (report subparser ~lines 73-77; `.report` import ~lines 22-23; `_run_report` ~lines 232-242)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `build_case_report`, `render_case_json`, `render_case_markdown` (Tasks 2-3); `db.get_case`, `db.case_findings`, `db.case_history` (existing); `_now`, `sys` (existing in cli.py).
- Produces: `report --case <int>` path in `_run_report`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py` (the file already imports `Database`, `build_parser`, `_run_case`; add `_run_report` and `pytest`/`json` where used):

```python
def test_report_case_command(tmp_path, capsys):
    import json as _json
    from dwcollector.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cid = db.create_case("Acme breach", "Acme", "an@corp", "2026-07-24T00:00:00")
    db.open_finding("leak", "leak:x", "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ev", "2026-07-24T01:00:00")
    fid = db.get_finding("leak:x")["finding_id"]
    db.assign_finding(fid, cid, "an@corp", "2026-07-24T02:00:00")

    # JSON
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", str(cid), "--format", "json"])) == 0
    doc = _json.loads(capsys.readouterr().out)
    assert doc["case"]["case_id"] == cid and doc["summary"]["total"] == 1

    # Markdown
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", str(cid)])) == 0
    md = capsys.readouterr().out
    assert f"case #{cid}" in md and "x.onion" in md and "acme.com" in md

    # unknown case id -> stderr + exit 1
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", "99999"])) == 1
    assert "99999" in capsys.readouterr().err


def test_report_requires_exactly_one_target():
    import pytest
    from dwcollector.cli import build_parser
    with pytest.raises(SystemExit):                     # neither --client nor --case
        build_parser().parse_args(["report"])
    with pytest.raises(SystemExit):                     # both -> mutually exclusive
        build_parser().parse_args(["report", "--client", "A", "--case", "1"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k "report_case or report_requires" -v`
Expected: FAIL — `test_report_case_command` fails because `--case` is an unrecognized argument today (argparse raises `SystemExit` during `parse_args`, before `_run_report` runs). (`test_report_requires_exactly_one_target` may pass incidentally today — `--client` is currently `required=True` and `--case` is unrecognized, so both invocations already error — but it becomes a meaningful guard once the mutually-exclusive group exists.)

- [ ] **Step 3: Update the subparser, import, and handler**

In `src/dwcollector/cli.py`, replace the report subparser block (currently lines 73-77):

```python
    rp = sub.add_parser("report")
    rg = rp.add_mutually_exclusive_group(required=True)
    rg.add_argument("--client")
    rg.add_argument("--case", type=int)
    rp.add_argument("--format", choices=["md", "json"], default="md")
    rp.add_argument("--since", default=None)
    rp.add_argument("--all", action="store_true")
```

Extend the `.report` import (currently lines 22-23):

```python
from .report import (client_findings, build_report, render_json, render_markdown,
                     client_cases, build_case_report, render_case_json,
                     render_case_markdown)
```

Replace `_run_report` (currently lines 232-242) with the case branch first:

```python
def _run_report(db, args) -> int:
    if args.case is not None:
        case = db.get_case(args.case)
        if case is None:
            print(f"no case #{args.case}", file=sys.stderr)
            return 1
        report = build_case_report(case, db.case_findings(args.case),
                                   db.case_history(args.case), _now())
        print(render_case_json(report) if args.format == "json"
              else render_case_markdown(report))
        return 0
    clients = load_clients("clients.toml")
    client = next((c for c in clients if c.get("name") == args.client), None)
    if client is None:
        print(f"unknown client: {args.client!r}", file=sys.stderr)
        return 1
    findings = client_findings(db, client, args.all, args.since)
    cases = client_cases(db, args.client)
    report = build_report(args.client, findings, _now(), args.since, cases=cases)
    print(render_json(report) if args.format == "json" else render_markdown(report))
    return 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_cli.py -v`
Expected: PASS — the two new tests plus the pre-existing `test_report_command_json_and_unknown_client` and `test_report_all_flag_includes_dismissed` (they pass `--client`, so `args.case` is `None` and the client branch runs unchanged).

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — all tests green (baseline 203 + the new tests).

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/cli.py tests/test_cli.py
git commit -m "feat: report --case CLI path with mutually-exclusive client/case group"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the shipped `report --case` behavior (Tasks 1-4). No code.

- [ ] **Step 1: Document `report --case`**

Find the per-client report section in `README.md` (search for `report --client`). Immediately after it, add a subsection describing the single-case incident report. Match the file's existing heading level and imperative tone. Use exactly this content:

```markdown
### Single-case incident report

Produce a full incident dossier for one case:

    dwcollector report --case 42 [--format md|json]

The report contains the case metadata (title, client, state, opened/closed
timestamps, duration), a summary (finding counts by status, severity, kind, and
disposition, plus distinct sites), every member finding in full (host, matched
identifier, kind, severity, status, disposition, first/last seen, and the
bounded evidence snippet), and the complete case timeline (every event —
creation, assignments, state changes, and notes — with actor and timestamp).

`--case` and `--client` are mutually exclusive; exactly one is required.
`--all` and `--since` apply only to `--client` — a case report is already the
analyst's curated set, so it renders every member finding unconditionally
(remove a finding with `case unassign`, not a report flag).
```

- [ ] **Step 2: Verify docs-only (no code touched)**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — unchanged suite (docs edit only).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document report --case single-case incident report"
```

---

## Notes for the executor

- The case report is **unfiltered** — do not add any disposition or kind filter on the case path. If a test seems to want filtering, re-read the Global Constraints; the curated-set behavior is intentional (`test_build_case_report_curated_includes_false_positive` guards it).
- `_run_report` keeps its `(db, args)` signature — do not add a `cfg` parameter.
- The mutually-exclusive group must be `required=True` so `report` with neither target is an argparse error (exit 2), matching `test_report_requires_exactly_one_target`.
- Existing `report --client` tests must stay green unchanged — the only change they tolerate is each client finding entry gaining an additive `kind` key.
