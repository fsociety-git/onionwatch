# Case Management — Implementation Plan


**Goal:** Let an analyst group findings into cases (incidents) with a three-state lifecycle, an optional client, and an append-only timeline, driven from a nested `case` CLI group and rolled up into the per-client report.

**Architecture:** New `cases` + `case_log` tables and a nullable `findings.case_id` (analyst-owned; reconcilers never touch it). DB methods create/read/list cases and assign/unassign/state/note them. A nested `case` CLI group. The per-client report gains a Cases section.

**Tech Stack:** Python 3.11+, sqlite3 (stdlib), pytest. No new dependencies.

**Spec:** `docs/specs/2026-07-24-case-management-design.md`

## Global Constraints

- Python 3.11+; add no new third-party dependencies. Every DB write commits.
- **`case_id` and case state are analyst-owned** — the reconcilers (`open_finding`/`reopen_finding`/`resolve_finding`/`touch_finding`, `reconcile_*`) must NEVER write `case_id`; case membership survives the finding lifecycle (like `disposition`).
- **Migration idempotent:** new tables in `SCHEMA` + `ALTER TABLE findings ADD COLUMN case_id INTEGER` in the existing `init_schema` loop (swallow `sqlite3.OperationalError`).
- One case per finding (`case_id` column, nullable). Manual assignment only.
- `set_case_state` sets `closed_at = now` when state is `closed`, and `NULL` otherwise (reopening clears it).
- CLI: ids are `type=int`; bad/absent id → clear stderr + non-zero exit; `--by` optional (free-text actor); state constrained via argparse `choices`.
- The `report --client` Cases section is **additive** — `build_report` gains a `cases` default, and the Markdown Cases section only renders when cases are present, so existing report behavior/tests are unchanged.
- Follow existing test style: `pytest`, `Database(str(tmp_path / "t.db"))`, `capsys`.

---

### Task 1: Schema + migration + case create/read/list

**Files:**
- Modify: `src/onionwatch/db.py` (`SCHEMA`, `init_schema`, add `create_case`/`get_case`/`list_cases`)
- Test: `tests/test_db.py` (append)

**Interfaces:**
- Produces: `cases` + `case_log` tables, `findings.case_id`; `create_case(title, client, actor, now) -> int`, `get_case(case_id) -> dict | None`, `list_cases(client=None, state=None) -> list[dict]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
def test_case_migration_adds_tables_and_column(tmp_path):
    import sqlite3
    p = str(tmp_path / "legacy.db")
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE findings (finding_id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "kind TEXT, dedup_key TEXT UNIQUE, url TEXT, host TEXT, term TEXT, "
              "status TEXT, severity TEXT, first_seen TEXT, last_seen TEXT, "
              "resolved_at TEXT, context_snippet TEXT)")
    c.commit(); c.close()
    db = Database(p); db.init_schema()                          # must not raise
    fcols = {r[1] for r in db.conn.execute("PRAGMA table_info(findings)")}
    assert "case_id" in fcols
    assert {r[1] for r in db.conn.execute("PRAGMA table_info(cases)")} >= \
        {"case_id", "title", "client", "state", "created_at", "created_by", "closed_at"}
    assert {r[1] for r in db.conn.execute("PRAGMA table_info(case_log)")} >= \
        {"case_id", "event", "note", "actor", "at"}


def test_create_case_and_list(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cid = db.create_case("Acme billing breach", "Acme Corp", "alice", "2026-07-24T00:00:00")
    assert cid >= 1
    c = db.get_case(cid)
    assert c["title"] == "Acme billing breach" and c["client"] == "Acme Corp"
    assert c["state"] == "open" and c["created_by"] == "alice"
    # created event logged
    log = list(db.conn.execute("SELECT event FROM case_log WHERE case_id=?", (cid,)))
    assert log[0][0] == "created"
    # list filters
    db.create_case("Internal", None, None, "2026-07-24T01:00:00")
    assert {c["title"] for c in db.list_cases(client="Acme Corp")} == {"Acme billing breach"}
    assert len(db.list_cases()) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_create_case_and_list -v`
Expected: FAIL — `AttributeError: 'Database' object has no attribute 'create_case'`

- [ ] **Step 3: Write minimal implementation**

Add `case_id INTEGER` to the `findings` table in `SCHEMA` (after `disposition_at`):

```sql
    disposition TEXT DEFAULT 'new', disposition_actor TEXT, disposition_at TEXT,
    case_id INTEGER
```

Add two tables to `SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS cases (
    case_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT, client TEXT,
    state TEXT DEFAULT 'open',
    created_at TEXT, created_by TEXT, closed_at TEXT
);
CREATE TABLE IF NOT EXISTS case_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER, event TEXT, note TEXT, actor TEXT, at TEXT
);
```

Append the migration DDL to the `init_schema` loop:

```python
            "ALTER TABLE findings ADD COLUMN case_id INTEGER",
```

Add the methods to `Database`:

```python
    def create_case(self, title, client, actor, now) -> int:
        cur = self.conn.execute(
            "INSERT INTO cases (title, client, state, created_at, created_by) "
            "VALUES (?, ?, 'open', ?, ?)", (title, client, now, actor))
        case_id = cur.lastrowid
        self.conn.execute(
            "INSERT INTO case_log (case_id, event, note, actor, at) "
            "VALUES (?, 'created', ?, ?, ?)", (case_id, title, actor, now))
        self.conn.commit()
        return case_id

    def get_case(self, case_id) -> dict | None:
        cur = self.conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_cases(self, client=None, state=None) -> list[dict]:
        q, params, conds = "SELECT * FROM cases", [], []
        if client:
            conds.append("client = ?"); params.append(client)
        if state:
            conds.append("state = ?"); params.append(state)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        return [dict(r) for r in self.conn.execute(q + " ORDER BY case_id DESC", params)]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green (additive schema; existing callers unaffected).

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: cases/case_log tables, findings.case_id, create/get/list_cases"
```

---

### Task 2: Case membership, state, notes, and reads

**Files:**
- Modify: `src/onionwatch/db.py`
- Test: `tests/test_db.py` (append)

**Interfaces:**
- Consumes: Task 1 schema, `get_finding_by_id` (existing).
- Produces: `assign_finding`, `unassign_finding`, `set_case_state`, `add_case_note`, `case_findings`, `case_history`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
def _case_finding(db, dedup, sev="critical"):
    db.open_finding("leak", dedup, "http://x.onion/", "x.onion", "t", sev, "ev",
                    "2026-07-24T00:00:00")
    return db.get_finding(dedup)["finding_id"]


def test_assign_unassign_finding(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cid = db.create_case("C", None, None, "2026-07-24T00:00:00")
    fid = _case_finding(db, "leak:a")
    db.assign_finding(fid, cid, "alice", "2026-07-24T01:00:00")
    assert db.get_finding_by_id(fid)["case_id"] == cid
    assert [f["finding_id"] for f in db.case_findings(cid)] == [fid]
    assert any("assigned finding" in e["event"] for e in db.case_history(cid))
    db.unassign_finding(fid, "alice", "2026-07-24T02:00:00")
    assert db.get_finding_by_id(fid)["case_id"] is None
    assert db.case_findings(cid) == []
    assert any("unassigned finding" in e["event"] for e in db.case_history(cid))
    # unassign a finding with no case -> no-op, no raise, no new log
    n = len(db.case_history(cid))
    db.unassign_finding(fid, None, "2026-07-24T03:00:00")
    assert len(db.case_history(cid)) == n


def test_set_case_state_and_note(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cid = db.create_case("C", None, None, "2026-07-24T00:00:00")
    db.set_case_state(cid, "investigating", "on it", "alice", "2026-07-24T01:00:00")
    assert db.get_case(cid)["state"] == "investigating"
    assert db.get_case(cid)["closed_at"] is None
    db.set_case_state(cid, "closed", None, "alice", "2026-07-24T02:00:00")
    assert db.get_case(cid)["state"] == "closed"
    assert db.get_case(cid)["closed_at"] == "2026-07-24T02:00:00"
    db.set_case_state(cid, "open", None, "alice", "2026-07-24T03:00:00")   # reopen clears closed_at
    assert db.get_case(cid)["closed_at"] is None
    db.add_case_note(cid, "a comment", "bob", "2026-07-24T04:00:00")
    hist = db.case_history(cid)
    assert any(e["event"] == "note" and e["note"] == "a comment" for e in hist)
    assert any(e["event"] == "state: closed" for e in hist)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_assign_unassign_finding -v`
Expected: FAIL — `AttributeError: 'Database' object has no attribute 'assign_finding'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/onionwatch/db.py`:

```python
    def _case_log(self, case_id, event, note, actor, now) -> None:
        self.conn.execute(
            "INSERT INTO case_log (case_id, event, note, actor, at) VALUES (?, ?, ?, ?, ?)",
            (case_id, event, note, actor, now))

    def assign_finding(self, finding_id, case_id, actor, now) -> None:
        self.conn.execute("UPDATE findings SET case_id = ? WHERE finding_id = ?",
                          (case_id, finding_id))
        self._case_log(case_id, f"assigned finding #{finding_id}", None, actor, now)
        self.conn.commit()

    def unassign_finding(self, finding_id, actor, now) -> None:
        row = self.get_finding_by_id(finding_id)
        if row is None or row.get("case_id") is None:
            return
        cid = row["case_id"]
        self.conn.execute("UPDATE findings SET case_id = NULL WHERE finding_id = ?",
                          (finding_id,))
        self._case_log(cid, f"unassigned finding #{finding_id}", None, actor, now)
        self.conn.commit()

    def set_case_state(self, case_id, state, note, actor, now) -> None:
        closed_at = now if state == "closed" else None
        self.conn.execute("UPDATE cases SET state = ?, closed_at = ? WHERE case_id = ?",
                          (state, closed_at, case_id))
        self._case_log(case_id, f"state: {state}", note, actor, now)
        self.conn.commit()

    def add_case_note(self, case_id, note, actor, now) -> None:
        self._case_log(case_id, "note", note, actor, now)
        self.conn.commit()

    def case_findings(self, case_id) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM findings WHERE case_id = ? "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, last_seen DESC",
            (case_id,))]

    def case_history(self, case_id) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM case_log WHERE case_id = ? ORDER BY log_id", (case_id,))]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: assign/unassign/state/note case methods + case_findings/history"
```

---

### Task 3: CLI — nested `case` command group

**Files:**
- Modify: `src/onionwatch/cli.py` (`build_parser`, add `_run_case`, `main` dispatch)
- Test: `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: the Task 1–2 DB methods, `get_finding_by_id` (existing).
- Produces: `onionwatch case {create|list|show|assign|unassign|state|note}`; `_run_case(db, args) -> int`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli.py`:

```python
from onionwatch.cli import build_parser, _run_case


def _seed_case_finding(db, dedup="leak:http://x.onion/|acme.com"):
    db.open_finding("leak", dedup, "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ev", "2026-07-24T00:00:00")
    return db.get_finding(dedup)["finding_id"]


def test_case_create_assign_state_show(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_case_finding(db)

    assert _run_case(db, build_parser().parse_args(
        ["case", "create", "Acme breach", "--client", "Acme Corp"])) == 0
    out = capsys.readouterr().out
    assert "created case #1" in out
    cid = 1

    assert _run_case(db, build_parser().parse_args(
        ["case", "assign", str(fid), str(cid), "--by", "alice"])) == 0
    capsys.readouterr()
    assert db.get_finding_by_id(fid)["case_id"] == cid

    assert _run_case(db, build_parser().parse_args(
        ["case", "state", str(cid), "investigating", "--note", "working"])) == 0
    capsys.readouterr()
    assert db.get_case(cid)["state"] == "investigating"

    assert _run_case(db, build_parser().parse_args(["case", "show", str(cid)])) == 0
    show = capsys.readouterr().out
    assert "Acme breach" in show and f"#{fid}" in show and "investigating" in show
    assert "assigned finding" in show          # timeline present


def test_case_bad_ids_error(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    assert _run_case(db, build_parser().parse_args(["case", "show", "999"])) == 1
    assert "999" in capsys.readouterr().err
    db.create_case("C", None, None, "2026-07-24T00:00:00")
    assert _run_case(db, build_parser().parse_args(["case", "assign", "42", "1"])) == 1  # no finding #42
    assert "42" in capsys.readouterr().err


def test_case_list_and_note(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _run_case(db, build_parser().parse_args(["case", "create", "One", "--client", "Acme"]))
    _run_case(db, build_parser().parse_args(["case", "create", "Two"]))
    capsys.readouterr()
    _run_case(db, build_parser().parse_args(["case", "list", "--client", "Acme"]))
    lst = capsys.readouterr().out
    assert "One" in lst and "Two" not in lst
    assert _run_case(db, build_parser().parse_args(["case", "note", "1", "--text", "hi"])) == 0
    assert any(e["note"] == "hi" for e in db.case_history(1))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_case_create_assign_state_show -v`
Expected: FAIL — `ImportError: cannot import name '_run_case'` / `invalid choice: 'case'`

- [ ] **Step 3: Write minimal implementation**

In `build_parser`, add the nested `case` group (after the `report` subparser):

```python
    cp = sub.add_parser("case")
    csub = cp.add_subparsers(dest="case_action", required=True)
    cc = csub.add_parser("create"); cc.add_argument("title")
    cc.add_argument("--client", default=None); cc.add_argument("--by", default=None)
    cl = csub.add_parser("list")
    cl.add_argument("--client", default=None); cl.add_argument("--state", default=None)
    cs = csub.add_parser("show"); cs.add_argument("case_id", type=int)
    ca = csub.add_parser("assign")
    ca.add_argument("finding_id", type=int); ca.add_argument("case_id", type=int)
    ca.add_argument("--by", default=None)
    cu = csub.add_parser("unassign")
    cu.add_argument("finding_id", type=int); cu.add_argument("--by", default=None)
    cst = csub.add_parser("state"); cst.add_argument("case_id", type=int)
    cst.add_argument("value", choices=["open", "investigating", "closed"])
    cst.add_argument("--note", default=None); cst.add_argument("--by", default=None)
    cn = csub.add_parser("note"); cn.add_argument("case_id", type=int)
    cn.add_argument("--text", required=True); cn.add_argument("--by", default=None)
```

Add the handler (near `_run_report`):

```python
def _run_case(db, args) -> int:
    a = args.case_action
    if a == "create":
        cid = db.create_case(args.title, args.client, args.by, _now())
        print(f"created case #{cid}")
        return 0
    if a == "list":
        for c in db.list_cases(client=args.client, state=args.state):
            n = len(db.case_findings(c["case_id"]))
            print(f"#{c['case_id']} [{c['state']}] {c.get('client') or '-'} "
                  f"— {c['title']} ({n} findings)")
        return 0
    if a == "show":
        c = db.get_case(args.case_id)
        if c is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        closed = f", closed {c['closed_at']}" if c.get("closed_at") else ""
        print(f"#{c['case_id']} [{c['state']}] {c.get('client') or '-'} — {c['title']}")
        print(f"created {c['created_at']} by {c.get('created_by') or '-'}{closed}")
        print("findings:")
        for f in db.case_findings(args.case_id):
            print(f"  #{f['finding_id']} {f['severity']} {f['kind']} "
                  f"{f.get('term') or '-'} @ {f['host']} [{f.get('disposition') or 'new'}]")
        print("timeline:")
        for e in db.case_history(args.case_id):
            note = f" {e['note']}" if e.get("note") else ""
            print(f"  {e['at']} {e['event']} [{e.get('actor') or '-'}]{note}")
        return 0
    if a == "assign":
        if db.get_finding_by_id(args.finding_id) is None:
            print(f"no finding #{args.finding_id}", file=sys.stderr)
            return 1
        if db.get_case(args.case_id) is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        db.assign_finding(args.finding_id, args.case_id, args.by, _now())
        print(f"assigned #{args.finding_id} -> case #{args.case_id}")
        return 0
    if a == "unassign":
        if db.get_finding_by_id(args.finding_id) is None:
            print(f"no finding #{args.finding_id}", file=sys.stderr)
            return 1
        db.unassign_finding(args.finding_id, args.by, _now())
        print(f"unassigned #{args.finding_id}")
        return 0
    if a == "state":
        if db.get_case(args.case_id) is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        db.set_case_state(args.case_id, args.value, args.note, args.by, _now())
        print(f"case #{args.case_id} -> {args.value}")
        return 0
    if a == "note":
        if db.get_case(args.case_id) is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        db.add_case_note(args.case_id, args.text, args.by, _now())
        print(f"note added to case #{args.case_id}")
        return 0
    return 1
```

Add the dispatch branch in `main` (after the `report` branch):

```python
    elif args.command == "case":
        return _run_case(db, args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (new case tests + existing cli tests)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/cli.py tests/test_cli.py
git commit -m "feat: nested case CLI group (create/list/show/assign/unassign/state/note)"
```

---

### Task 4: Report rollup — Cases section in `report --client`

**Files:**
- Modify: `src/onionwatch/report.py` (`client_cases`, `build_report`, `render_markdown`)
- Modify: `src/onionwatch/cli.py` (`_run_report` computes + passes cases; import `client_cases`)
- Test: `tests/test_report.py`, `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `db.list_cases`/`db.case_findings` (Tasks 1–2).
- Produces: `client_cases(db, client_name) -> list[dict]`; `build_report(..., cases=None)` gains a `cases` field; `render_markdown` gains a Cases section.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_report.py`:

```python
def test_report_includes_client_cases(tmp_path):
    from onionwatch.report import client_cases
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
```

(`_leak` and `CLIENT` already exist in `tests/test_report.py` from the reports spec.)

Append to `tests/test_cli.py`:

```python
def test_report_command_shows_cases(tmp_path, capsys, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "ev", "2026-07-24T00:00:00")
    cid = db.create_case("Acme breach", "Acme", None, "2026-07-24T00:00:00")
    db.assign_finding(db.get_finding("leak:http://x.onion/|acme.com")["finding_id"],
                      cid, None, "2026-07-24T01:00:00")
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "Acme", "terms": ["acme.com"]}])
    import json
    _run_report(db, build_parser().parse_args(["report", "--client", "Acme", "--format", "json"]))
    doc = json.loads(capsys.readouterr().out)
    assert doc["cases"][0]["title"] == "Acme breach"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_report.py::test_report_includes_client_cases -v`
Expected: FAIL — `ImportError: cannot import name 'client_cases'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/onionwatch/report.py`:

```python
def client_cases(db, client_name: str) -> list[dict]:
    return [{"case_id": c["case_id"], "title": c["title"], "state": c["state"],
             "findings": len(db.case_findings(c["case_id"]))}
            for c in db.list_cases(client=client_name)]
```

Change `build_report` to accept and include `cases`:

```python
def build_report(client_name: str, findings: list[dict], now: str,
                 since: str | None = None, cases: list[dict] | None = None) -> dict:
    summary = { ... }                                  # unchanged
    return {
        "client": client_name, "generated_at": now, "since": since,
        "summary": summary,
        "cases": cases or [],
        "findings": [ ... ],                           # unchanged
    }
```

In `render_markdown`, after the summary block and before the findings loop, add a Cases section (renders only when present):

```python
    if report.get("cases"):
        lines += ["## Cases", ""]
        for c in report["cases"]:
            lines.append(f"- #{c['case_id']} [{c['state']}] {c['title']} "
                         f"({c['findings']} findings)")
        lines.append("")
```

In `src/onionwatch/cli.py`, import `client_cases` and pass cases in `_run_report`:

```python
from .report import (client_findings, build_report, render_json, render_markdown,
                     client_cases)
```
```python
    findings = client_findings(db, client, args.all, args.since)
    cases = client_cases(db, args.client)
    report = build_report(args.client, findings, _now(), args.since, cases=cases)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_report.py tests/test_cli.py -v`
Expected: PASS (new tests + existing report/cli tests — `build_report`'s new `cases` param defaults to `None`→`[]`, and the Markdown Cases section only renders when non-empty, so existing report tests are unaffected)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/report.py src/onionwatch/cli.py tests/test_report.py tests/test_cli.py
git commit -m "feat: client report Cases rollup (client_cases + build_report/render + wiring)"
```

---

### Task 5: Docs — README

**Files:**
- Modify: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Document case management in README**

Add a "Case management" subsection to `README.md` near the triage/report content covering: a case groups related findings into an incident; a finding belongs to at most one case (`case_id`), assigned manually; three states (`open`/`investigating`/`closed`); an optional free-text client; the append-only timeline; the commands `case create "<title>" [--client] [--by]`, `case list [--client] [--state]`, `case show <id>`, `case assign <finding_id> <case_id>`, `case unassign <finding_id>`, `case state <id> <state> [--note]`, `case note <id> --text`; and that a client's cases appear as a Cases section in `report --client`. Note case membership/state are analyst-owned and untouched by the detection lifecycle.

- [ ] **Step 2: Verify suite green and commit**

Run: `pytest -q`
Expected: all green (docs-only change).

```bash
git add README.md
git commit -m "docs: document case management"
```

---

## Final verification

- [ ] Run the full suite: `pytest -q` — expect all prior tests plus the new ones green.
- [ ] Smoke the flow offline: open a leak finding, `case create "X"`, `case assign <fid> 1`, `case state 1 investigating`, `case show 1` (shows the finding + timeline); confirm `report --client` lists the case when the case's client matches.
- [ ] Confirm `git log --oneline` shows one commit per task and the tree is clean.
