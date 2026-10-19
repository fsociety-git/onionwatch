# Finding Disposition & Triage — Implementation Plan


**Goal:** Let an analyst triage findings — set a disposition (new/confirmed/false_positive/dismissed) with an append-only note history, work a severity-ordered triage queue, and stop alerts for findings dispositioned as not-a-threat.

**Architecture:** Analyst-owned `disposition` columns are added to `findings` (orthogonal to the machine `status`, never touched by reconcilers), plus a `disposition_log` history table and an `alerts.suppressed` flag. `emit` gains one suppression check. New CLI verbs (`triage`, `disposition`, `note`, `history`) drive it.

**Tech Stack:** Python 3.11+, sqlite3 (stdlib), pytest + pytest-asyncio. No new dependencies.

**Spec:** `docs/specs/2026-07-24-finding-disposition-triage-design.md`

## Global Constraints

- Python 3.11+; add no new third-party dependencies.
- **Disposition is analyst-owned**; the reconcilers (`reconcile_leaks`/`_dead_originals`/`_anchor_identity`) must never write it. `reopen_finding` already doesn't touch it — stickiness comes for free; do not add disposition writes to any reconcile path.
- **Migration is idempotent:** new columns added in `SCHEMA` (fresh DBs) AND via `ALTER TABLE … ADD COLUMN` wrapped in `except sqlite3.OperationalError` (existing DBs), matching the existing `leak_hits` migration.
- **Suppression rule:** a finding whose `disposition` is `false_positive` or `dismissed` → `emit` delivers **nothing** (no JSONL, no stderr, no webhook) and records a `suppressed=1` audit row; `new`/`confirmed` emit exactly as today. Suppression is best-effort and never raises.
- Findings are addressed by the stable integer `finding_id` at the CLI; a bad/absent id → clear stderr message + non-zero exit, no crash.
- Existing leak/PII/identifier/anchor alert wording and behavior for non-dispositioned findings stay unchanged.
- Timestamps UTC `"%Y-%m-%dT%H:%M:%S"` (via `cli._now()`).
- Follow existing test style: `pytest`, `Database(str(tmp_path / "t.db"))`, `capsys` for CLI output.

---

### Task 1: Schema + migration + `record_alert(suppressed)` + `get_finding_by_id`

**Files:**
- Modify: `src/onionwatch/db.py` (`SCHEMA`, `init_schema`, `record_alert`, add `get_finding_by_id`)
- Test: `tests/test_db.py` (append)

**Interfaces:**
- Produces: `findings` gains `disposition TEXT DEFAULT 'new'`, `disposition_actor TEXT`, `disposition_at TEXT`; `alerts` gains `suppressed INTEGER DEFAULT 0`; new `disposition_log` table. `record_alert(..., suppressed=0)`. `get_finding_by_id(finding_id) -> dict | None`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
def test_migration_adds_disposition_and_suppressed_columns(tmp_path):
    import sqlite3
    p = str(tmp_path / "legacy.db")
    c = sqlite3.connect(p)
    # legacy findings/alerts WITHOUT the new columns
    c.execute("CREATE TABLE findings (finding_id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "kind TEXT, dedup_key TEXT UNIQUE, url TEXT, host TEXT, term TEXT, "
              "status TEXT, severity TEXT, first_seen TEXT, last_seen TEXT, "
              "resolved_at TEXT, context_snippet TEXT)")
    c.execute("CREATE TABLE alerts (alert_id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "finding_id INTEGER, dedup_key TEXT, event TEXT, severity TEXT, "
              "title TEXT, body TEXT, created_at TEXT, delivered INTEGER, delivery_error TEXT)")
    c.commit(); c.close()
    db = Database(p); db.init_schema()                       # must not raise
    fcols = {r[1] for r in db.conn.execute("PRAGMA table_info(findings)")}
    acols = {r[1] for r in db.conn.execute("PRAGMA table_info(alerts)")}
    assert {"disposition", "disposition_actor", "disposition_at"} <= fcols
    assert "suppressed" in acols
    dl = {r[1] for r in db.conn.execute("PRAGMA table_info(disposition_log)")}
    assert {"finding_id", "disposition", "note", "actor", "at"} <= dl


def test_record_alert_stores_suppressed(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_alert(1, "k", "opened", "critical", "t", "b",
                    "2026-07-24T00:00:00", 0, None, suppressed=1)
    row = list(db.conn.execute("SELECT suppressed FROM alerts"))[0]
    assert row[0] == 1


def test_get_finding_by_id(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:u|t", "u", "h", "t", "critical", "s", "2026-07-24T00:00:00")
    f = db.get_finding("leak:u|t")
    assert db.get_finding_by_id(f["finding_id"])["dedup_key"] == "leak:u|t"
    assert db.get_finding_by_id(99999) is None
    # a fresh finding defaults to disposition 'new'
    assert f["disposition"] == "new"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_get_finding_by_id -v`
Expected: FAIL — `AttributeError: 'Database' object has no attribute 'get_finding_by_id'` (and the suppressed/disposition columns don't exist)

- [ ] **Step 3: Write minimal implementation**

In `src/onionwatch/db.py`, update the `findings` table in `SCHEMA` to add three columns:

```sql
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, dedup_key TEXT UNIQUE,
    url TEXT, host TEXT, term TEXT,
    status TEXT, severity TEXT,
    first_seen TEXT, last_seen TEXT, resolved_at TEXT,
    context_snippet TEXT,
    disposition TEXT DEFAULT 'new', disposition_actor TEXT, disposition_at TEXT
);
```

Add `suppressed INTEGER DEFAULT 0` to the `alerts` table in `SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER, dedup_key TEXT,
    event TEXT, severity TEXT, title TEXT, body TEXT,
    created_at TEXT, delivered INTEGER DEFAULT 0, delivery_error TEXT,
    suppressed INTEGER DEFAULT 0
);
```

Add the `disposition_log` table to `SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS disposition_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    disposition TEXT, note TEXT, actor TEXT, at TEXT
);
```

Append the migration DDLs to the `init_schema` loop (after the `leak_hits` ones):

```python
            "ALTER TABLE findings ADD COLUMN disposition TEXT DEFAULT 'new'",
            "ALTER TABLE findings ADD COLUMN disposition_actor TEXT",
            "ALTER TABLE findings ADD COLUMN disposition_at TEXT",
            "ALTER TABLE alerts ADD COLUMN suppressed INTEGER DEFAULT 0",
```

Add `suppressed=0` to `record_alert`:

```python
    def record_alert(self, finding_id, dedup_key, event, severity, title, body,
                     created_at, delivered, delivery_error, suppressed=0) -> int:
        cur = self.conn.execute(
            "INSERT INTO alerts (finding_id, dedup_key, event, severity, title, "
            "body, created_at, delivered, delivery_error, suppressed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding_id, dedup_key, event, severity, title, body, created_at,
             delivered, delivery_error, suppressed))
        self.conn.commit()
        return cur.lastrowid
```

Add `get_finding_by_id` (near `get_finding`):

```python
    def get_finding_by_id(self, finding_id) -> dict | None:
        cur = self.conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
        row = cur.fetchone()
        return dict(row) if row else None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS (new + existing db tests)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green — existing `record_alert` callers (in `alerts.emit`) still pass 9 positional args; `suppressed` defaults to 0.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: findings disposition columns, disposition_log, alerts.suppressed + migration"
```

---

### Task 2: Disposition DB methods

**Files:**
- Modify: `src/onionwatch/db.py`
- Test: `tests/test_db.py` (append)

**Interfaces:**
- Consumes: schema + `get_finding_by_id` (Task 1).
- Produces: `set_disposition(finding_id, disposition, note, actor, now)`, `add_note(finding_id, note, actor, now)`, `triage_queue() -> list[dict]`, `disposition_history(finding_id) -> list[dict]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
def _mk_finding(db, dedup, sev="critical", now="2026-07-24T00:00:00"):
    db.open_finding("leak", dedup, "u", "h", "t", sev, "s", now)
    return db.get_finding(dedup)["finding_id"]


def test_set_disposition_updates_finding_and_logs(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _mk_finding(db, "leak:u|t")
    db.set_disposition(fid, "confirmed", "client billing DB", "alice", "2026-07-24T01:00:00")
    f = db.get_finding_by_id(fid)
    assert f["disposition"] == "confirmed" and f["disposition_actor"] == "alice"
    hist = db.disposition_history(fid)
    assert len(hist) == 1 and hist[0]["disposition"] == "confirmed"
    assert hist[0]["note"] == "client billing DB"
    db.set_disposition(fid, "dismissed", None, "bob", "2026-07-24T02:00:00")
    assert db.get_finding_by_id(fid)["disposition"] == "dismissed"
    assert len(db.disposition_history(fid)) == 2          # history grows


def test_add_note_does_not_change_disposition(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _mk_finding(db, "leak:u|t")
    db.set_disposition(fid, "confirmed", None, "alice", "2026-07-24T01:00:00")
    db.add_note(fid, "still investigating", "alice", "2026-07-24T02:00:00")
    assert db.get_finding_by_id(fid)["disposition"] == "confirmed"   # unchanged
    hist = db.disposition_history(fid)
    assert len(hist) == 2 and hist[-1]["note"] == "still investigating"
    assert hist[-1]["disposition"] == "confirmed"         # note carries current disposition


def test_triage_queue_open_new_severity_ordered(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    hi = _mk_finding(db, "leak:a|t", sev="high", now="2026-07-24T00:00:00")
    crit = _mk_finding(db, "leak:b|t", sev="critical", now="2026-07-24T00:00:01")
    done = _mk_finding(db, "leak:c|t", sev="critical")
    db.set_disposition(done, "false_positive", None, None, "2026-07-24T03:00:00")  # drops out
    db.resolve_finding("leak:a|t", "2026-07-24T04:00:00")   # 'hi' now resolved -> excluded
    q = db.triage_queue()
    ids = [f["finding_id"] for f in q]
    assert ids == [crit]        # only open+new; critical first; resolved 'hi' and dispositioned 'done' excluded


def test_disposition_sticky_across_reopen(tmp_path):
    # A disposition survives the machine resolve->reopen lifecycle (reconcilers
    # never touch it). Uses the raw finding methods that the reconcilers call.
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _mk_finding(db, "leak:u|t")
    db.set_disposition(fid, "false_positive", None, None, "2026-07-24T01:00:00")
    db.resolve_finding("leak:u|t", "2026-07-24T02:00:00")
    db.reopen_finding("leak:u|t", "2026-07-24T03:00:00", "s")     # machine reopen
    assert db.get_finding_by_id(fid)["disposition"] == "false_positive"
    assert db.get_finding_by_id(fid)["status"] == "open"          # status did flip
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_set_disposition_updates_finding_and_logs -v`
Expected: FAIL — `AttributeError: 'Database' object has no attribute 'set_disposition'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/onionwatch/db.py`:

```python
    def set_disposition(self, finding_id, disposition, note, actor, now) -> None:
        self.conn.execute(
            "UPDATE findings SET disposition = ?, disposition_actor = ?, "
            "disposition_at = ? WHERE finding_id = ?",
            (disposition, actor, now, finding_id))
        self.conn.execute(
            "INSERT INTO disposition_log (finding_id, disposition, note, actor, at) "
            "VALUES (?, ?, ?, ?, ?)",
            (finding_id, disposition, note, actor, now))
        self.conn.commit()

    def add_note(self, finding_id, note, actor, now) -> None:
        row = self.get_finding_by_id(finding_id)
        if row is None:
            return
        self.conn.execute(
            "INSERT INTO disposition_log (finding_id, disposition, note, actor, at) "
            "VALUES (?, ?, ?, ?, ?)",
            (finding_id, row.get("disposition"), note, actor, now))
        self.conn.commit()

    def triage_queue(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM findings WHERE status = 'open' AND disposition = 'new' "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, last_seen DESC")]

    def disposition_history(self, finding_id) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM disposition_log WHERE finding_id = ? ORDER BY log_id",
            (finding_id,))]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: set_disposition/add_note/triage_queue/disposition_history"
```

---

### Task 3: Alert suppression in `emit`

**Files:**
- Modify: `src/onionwatch/alerts.py` (`emit`, add `SUPPRESSED_DISPOSITIONS`)
- Test: `tests/test_alerts.py` (append)

**Interfaces:**
- Consumes: `record_alert(..., suppressed=)` (Task 1), `finding["disposition"]` (Task 1 schema).
- Produces: `emit` returns early (delivering nothing, recording a `suppressed=1` row) when the finding's disposition is `false_positive`/`dismissed`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_alerts.py`:

```python
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
```

(`_cfg` already exists in `tests/test_alerts.py`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alerts.py::test_emit_suppresses_dispositioned_finding -v`
Expected: FAIL — `emit` delivers to the webhook (`calls` non-empty) and writes no `suppressed=1` row

- [ ] **Step 3: Write minimal implementation**

In `src/onionwatch/alerts.py`, add the constant near the other severity constants:

```python
SUPPRESSED_DISPOSITIONS = ("false_positive", "dismissed")
```

In `emit`, insert the suppression check right after `payload` is built and before the `delivered = 0` line:

```python
    if finding.get("disposition") in SUPPRESSED_DISPOSITIONS:
        try:
            db.record_alert(finding.get("finding_id"), finding["dedup_key"], event,
                            severity, title, body, now, 0, None, suppressed=1)
        except Exception:  # noqa: BLE001 - best-effort audit; never crash the loop
            pass
        return payload
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_alerts.py -v`
Expected: PASS (new suppression tests + existing emit/reconcile tests, whose findings default to `disposition='new'` → unchanged behavior)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/alerts.py tests/test_alerts.py
git commit -m "feat: emit suppresses alerts for false_positive/dismissed findings"
```

---

### Task 4: CLI — `triage` / `disposition` / `note` / `history` + `alerts` disposition column

**Files:**
- Modify: `src/onionwatch/cli.py` (`build_parser`, handlers, `main` dispatch, `_run_alerts`)
- Test: `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `triage_queue`, `get_finding_by_id`, `set_disposition`, `add_note`, `disposition_history` (Tasks 1–2).
- Produces: subcommands `triage`, `disposition <id> <value>`, `note <id> --text`, `history <id>`; `_run_alerts` shows disposition.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli.py`:

```python
from onionwatch.cli import build_parser, _run_triage, _run_disposition, _run_note, _run_history


def _seed_finding(db, dedup="leak:http://x.onion/|acme.com", sev="critical"):
    db.open_finding("leak", dedup, "http://x.onion/", "x.onion", "acme.com",
                    sev, "…", "2026-07-24T00:00:00")
    return db.get_finding(dedup)["finding_id"]


def test_triage_and_disposition_flow(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_finding(db)
    _run_triage(db)
    assert f"#{fid}" in capsys.readouterr().out              # in the queue

    args = build_parser().parse_args(
        ["disposition", str(fid), "false_positive", "--note", "test data", "--by", "alice"])
    assert _run_disposition(db, args) == 0
    assert db.get_finding_by_id(fid)["disposition"] == "false_positive"
    capsys.readouterr()                                     # clear the "#id -> …" output

    _run_triage(db)
    assert f"#{fid}" not in capsys.readouterr().out          # dropped from queue after disposition

    hargs = build_parser().parse_args(["history", str(fid)])
    _run_history(db, hargs)
    hout = capsys.readouterr().out
    assert "false_positive" in hout and "test data" in hout and "alice" in hout


def test_disposition_bad_id_errors(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    args = build_parser().parse_args(["disposition", "99999", "confirmed"])
    assert _run_disposition(db, args) == 1                   # non-zero exit
    assert "99999" in capsys.readouterr().err


def test_note_command_appends(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_finding(db)
    args = build_parser().parse_args(["note", str(fid), "--text", "watching this"])
    assert _run_note(db, args) == 0
    assert any(e["note"] == "watching this" for e in db.disposition_history(fid))


def test_alerts_command_shows_disposition(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_finding(db)
    db.set_disposition(fid, "confirmed", None, None, "2026-07-24T01:00:00")
    args = build_parser().parse_args(["alerts", "--status", "open"])
    _run_alerts(db, args)
    assert "confirmed" in capsys.readouterr().out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_triage_and_disposition_flow -v`
Expected: FAIL — `ImportError: cannot import name '_run_triage'` / `invalid choice: 'triage'`

- [ ] **Step 3: Write minimal implementation**

In `build_parser`, after the `alerts` subparser, add:

```python
    sub.add_parser("triage")

    dp = sub.add_parser("disposition")
    dp.add_argument("finding_id", type=int)
    dp.add_argument("value", choices=["new", "confirmed", "false_positive", "dismissed"])
    dp.add_argument("--note", default=None)
    dp.add_argument("--by", default=None)

    npp = sub.add_parser("note")
    npp.add_argument("finding_id", type=int)
    npp.add_argument("--text", required=True)
    npp.add_argument("--by", default=None)

    hp = sub.add_parser("history")
    hp.add_argument("finding_id", type=int)
```

Add handlers (near `_run_alerts`):

```python
def _run_triage(db) -> None:
    rows = db.triage_queue()
    for f in rows:
        print(f"#{f['finding_id']} [{f['severity']}] {f['kind']} "
              f"{f.get('term') or '-'} @ {f['host']}")
    print(f"queue: {len(rows)}")


def _run_disposition(db, args) -> int:
    if db.get_finding_by_id(args.finding_id) is None:
        print(f"no finding #{args.finding_id}", file=sys.stderr)
        return 1
    db.set_disposition(args.finding_id, args.value, args.note, args.by, _now())
    print(f"#{args.finding_id} -> {args.value}")
    return 0


def _run_note(db, args) -> int:
    if db.get_finding_by_id(args.finding_id) is None:
        print(f"no finding #{args.finding_id}", file=sys.stderr)
        return 1
    db.add_note(args.finding_id, args.text, args.by, _now())
    print(f"note added to #{args.finding_id}")
    return 0


def _run_history(db, args) -> None:
    for e in db.disposition_history(args.finding_id):
        print(f"{e['at']} {e['disposition']} "
              f"[{e.get('actor') or '-'}] {e.get('note') or ''}")
```

Extend `_run_alerts` to show the disposition and the finding id:

```python
def _run_alerts(db, args) -> None:
    rows = db.list_findings(None if args.status == "all" else args.status)
    for f in rows:
        when = f.get("resolved_at") or f.get("last_seen") or f.get("first_seen")
        term = f.get("term") or "-"
        disp = f.get("disposition") or "new"
        print(f"#{f['finding_id']} [{f['status']}/{disp}] {f['severity']} {f['kind']} "
              f"{term} @ {f['host']} ({when})")
    print(f"total: {len(rows)}")
```

Add dispatch branches in `main` (after the `alerts` branch):

```python
    elif args.command == "triage":
        _run_triage(db)
    elif args.command == "disposition":
        return _run_disposition(db, args)
    elif args.command == "note":
        return _run_note(db, args)
    elif args.command == "history":
        _run_history(db, args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (new commands + existing cli tests; the existing `test_alerts_command_lists_findings` still passes — it asserts substrings `"acme.com"`/`"critical"`/`"total: 1"`, all still present)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/cli.py tests/test_cli.py
git commit -m "feat: triage/disposition/note/history CLI + disposition in alerts listing"
```

---

### Task 5: Docs — README

**Files:**
- Modify: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Document triage & disposition in README**

Add an "Analyst triage & disposition" subsection to `README.md` near the alerting content covering: dispositions (`new`/`confirmed`/`false_positive`/`dismissed`), that disposition is separate from the machine `status` and **sticky** across reopen; the **triage queue** (`onionwatch triage` — open, un-triaged, severity-first); the commands `disposition <id> <value> [--note] [--by]`, `note <id> --text`, `history <id>`, and that `alerts` now shows disposition; and that marking a finding `false_positive`/`dismissed` **suppresses its future alerts** (audited via a suppressed alert row), while `new`/`confirmed` keep alerting.

- [ ] **Step 2: Verify suite green and commit**

Run: `pytest -q`
Expected: all green (docs-only change).

```bash
git add README.md
git commit -m "docs: document analyst triage & disposition"
```

---

## Final verification

- [ ] Run the full suite: `pytest -q` — expect all prior tests plus the new ones green.
- [ ] Smoke the flow offline against a scratch DB: open a finding, `disposition <id> false_positive`, confirm `triage` no longer lists it and `history <id>` shows the entry.
- [ ] Confirm `git log --oneline` shows one commit per task and the tree is clean.
