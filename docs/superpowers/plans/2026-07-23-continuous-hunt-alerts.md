# Continuous Hunting + Temporal Tracking + Alerting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn dwcollector from a passive collector into a monitoring service by adding a history event-log, loop-integrated hunting, and a deduplicated, lifecycle-tracked alert engine with a local sink plus one optional webhook.

**Architecture:** Three additive SQLite tables (`url_events`, `findings`, `alerts`). History is captured automatically inside `Database.update_url` by diffing a fixed set of material fields. A new `alerts.py` module reconciles this run's leak hits and dead canonical originals into an open/resolved finding lifecycle and emits alerts to a local JSONL sink + stderr + optional webhook. The supervisor loop's `run_cycle` gains a hunt+reconcile step reading a config watchlist.

**Tech Stack:** Python 3.11+, sqlite3 (stdlib), httpx[socks]==0.27.2, pytest + pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-07-23-continuous-hunt-history-alerts-design.md`

## Global Constraints

- Python 3.11+ (uses `tomllib`). One line each below applies to every task.
- Timestamps are UTC, format `"%Y-%m-%dT%H:%M:%S"` (matches existing `cli._now()`).
- Every `Database` write method calls `self.conn.commit()` (existing convention).
- Alert delivery (JSONL append + webhook POST) must **never** raise out of `emit`; failures are caught and recorded in `alerts.delivery_error`.
- Evidence-only: never store full leaked datasets — only matched term + short snippet (existing convention; do not change).
- Webhook POST is a plain outbound `httpx` call (NOT via Tor), short timeout.
- Follow existing test style: `pytest`, `@pytest.mark.asyncio` for async, `Database(str(tmp_path / "t.db"))`, in-repo stub clients returning `FetchResult`.
- Dependency floor: add no new third-party dependencies (httpx already present).

---

### Task 1: Schema + findings/alerts/events DB methods

**Files:**
- Modify: `src/dwcollector/db.py` (add tables to `SCHEMA`; add methods; add module helpers)
- Test: `tests/test_db.py` (append tests)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `Database.record_url_event(url, host, field, old_value, new_value, observed_at) -> None`
  - `Database.get_finding(dedup_key) -> dict | None`
  - `Database.open_finding(kind, dedup_key, url, host, term, severity, context_snippet, now) -> None`
  - `Database.touch_finding(dedup_key, last_seen) -> None`
  - `Database.resolve_finding(dedup_key, resolved_at) -> None`
  - `Database.reopen_finding(dedup_key, now, context_snippet) -> None`
  - `Database.open_findings(kind=None) -> list[dict]`
  - `Database.list_findings(status=None) -> list[dict]`
  - `Database.record_alert(finding_id, dedup_key, event, severity, title, body, created_at, delivered, delivery_error) -> int`
  - `Database.leak_hits_for_run(run_id) -> list[dict]`
  - module helper `_utcnow() -> str`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
from dwcollector.db import Database

def test_finding_lifecycle_methods(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    key = "leak:http://x.onion/|acme.com"
    assert db.get_finding(key) is None
    db.open_finding("leak", key, "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ctx", "2026-07-23T00:00:00")
    f = db.get_finding(key)
    assert f["status"] == "open" and f["severity"] == "critical"
    assert f["term"] == "acme.com" and f["finding_id"] >= 1
    # idempotent open (INSERT OR IGNORE)
    db.open_finding("leak", key, "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ctx2", "2026-07-23T01:00:00")
    assert db.get_finding(key)["context_snippet"] == "ctx"
    db.touch_finding(key, "2026-07-23T02:00:00")
    assert db.get_finding(key)["last_seen"] == "2026-07-23T02:00:00"
    assert len(db.open_findings("leak")) == 1
    db.resolve_finding(key, "2026-07-23T03:00:00")
    assert db.get_finding(key)["status"] == "resolved"
    assert db.open_findings("leak") == []
    db.reopen_finding(key, "2026-07-23T04:00:00", "ctx3")
    assert db.get_finding(key)["status"] == "open"
    assert db.get_finding(key)["resolved_at"] is None
    assert db.get_finding(key)["context_snippet"] == "ctx3"
    assert len(db.list_findings("all")) == 1

def test_record_url_event_and_alert(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_url_event("http://x.onion/", "x.onion", "alive", "1", "0",
                        "2026-07-23T00:00:00")
    ev = list(db.conn.execute("SELECT field, old_value, new_value FROM url_events"))
    assert ev[0][0] == "alive" and ev[0][1] == "1" and ev[0][2] == "0"
    aid = db.record_alert(1, "leak:k", "opened", "critical", "t", "b",
                          "2026-07-23T00:00:00", 1, None)
    assert aid >= 1
    row = list(db.conn.execute("SELECT event, delivered FROM alerts"))[0]
    assert row[0] == "opened" and row[1] == 1

def test_leak_hits_for_run(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_leak_hit("run1", "http://x.onion/", "x.onion", "leak-site",
                       "verified", "acme.com", "snippet", "2026-07-23T00:00:00")
    db.record_leak_hit("run2", "http://y.onion/", "y.onion", "leak-site",
                       "verified", "acme.com", "snippet", "2026-07-23T00:00:00")
    rows = db.leak_hits_for_run("run1")
    assert len(rows) == 1 and rows[0]["url"] == "http://x.onion/"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_finding_lifecycle_methods -v`
Expected: FAIL — `AttributeError: 'Database' object has no attribute 'get_finding'`

- [ ] **Step 3: Write minimal implementation**

In `src/dwcollector/db.py`, add near the top (after `import sqlite3`):

```python
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
```

Append these three tables inside the `SCHEMA` string (before the closing `"""`):

```sql
CREATE TABLE IF NOT EXISTS url_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT, host TEXT,
    field TEXT, old_value TEXT, new_value TEXT,
    observed_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, dedup_key TEXT UNIQUE,
    url TEXT, host TEXT, term TEXT,
    status TEXT, severity TEXT,
    first_seen TEXT, last_seen TEXT, resolved_at TEXT,
    context_snippet TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER, dedup_key TEXT,
    event TEXT, severity TEXT, title TEXT, body TEXT,
    created_at TEXT, delivered INTEGER DEFAULT 0, delivery_error TEXT
);
```

Add these methods to the `Database` class:

```python
    def record_url_event(self, url, host, field, old_value, new_value, observed_at) -> None:
        self.conn.execute(
            "INSERT INTO url_events (url, host, field, old_value, new_value, observed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url, host, field, old_value, new_value, observed_at))
        self.conn.commit()

    def get_finding(self, dedup_key) -> dict | None:
        cur = self.conn.execute("SELECT * FROM findings WHERE dedup_key = ?", (dedup_key,))
        row = cur.fetchone()
        return dict(row) if row else None

    def open_finding(self, kind, dedup_key, url, host, term, severity,
                     context_snippet, now) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO findings "
            "(kind, dedup_key, url, host, term, status, severity, first_seen, "
            " last_seen, context_snippet) "
            "VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)",
            (kind, dedup_key, url, host, term, severity, now, now, context_snippet))
        self.conn.commit()

    def touch_finding(self, dedup_key, last_seen) -> None:
        self.conn.execute("UPDATE findings SET last_seen = ? WHERE dedup_key = ?",
                          (last_seen, dedup_key))
        self.conn.commit()

    def resolve_finding(self, dedup_key, resolved_at) -> None:
        self.conn.execute(
            "UPDATE findings SET status = 'resolved', resolved_at = ? WHERE dedup_key = ?",
            (resolved_at, dedup_key))
        self.conn.commit()

    def reopen_finding(self, dedup_key, now, context_snippet) -> None:
        self.conn.execute(
            "UPDATE findings SET status = 'open', resolved_at = NULL, "
            "last_seen = ?, context_snippet = ? WHERE dedup_key = ?",
            (now, context_snippet, dedup_key))
        self.conn.commit()

    def open_findings(self, kind=None) -> list[dict]:
        if kind:
            cur = self.conn.execute(
                "SELECT * FROM findings WHERE status = 'open' AND kind = ?", (kind,))
        else:
            cur = self.conn.execute("SELECT * FROM findings WHERE status = 'open'")
        return [dict(r) for r in cur]

    def list_findings(self, status=None) -> list[dict]:
        if status and status != "all":
            cur = self.conn.execute(
                "SELECT * FROM findings WHERE status = ? ORDER BY finding_id DESC",
                (status,))
        else:
            cur = self.conn.execute("SELECT * FROM findings ORDER BY finding_id DESC")
        return [dict(r) for r in cur]

    def record_alert(self, finding_id, dedup_key, event, severity, title, body,
                     created_at, delivered, delivery_error) -> int:
        cur = self.conn.execute(
            "INSERT INTO alerts (finding_id, dedup_key, event, severity, title, "
            "body, created_at, delivered, delivery_error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding_id, dedup_key, event, severity, title, body, created_at,
             delivered, delivery_error))
        self.conn.commit()
        return cur.lastrowid

    def leak_hits_for_run(self, run_id) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM leak_hits WHERE run_id = ?", (run_id,))]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS (new tests + existing db tests all green)

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/db.py tests/test_db.py
git commit -m "feat: add url_events/findings/alerts tables and DB methods"
```

---

### Task 2: History-aware `update_url`

**Files:**
- Modify: `src/dwcollector/db.py` (`_UPDATABLE` region + `update_url`)
- Test: `tests/test_db.py` (append)

**Interfaces:**
- Consumes: `Database.get_url`, `url_events` table (Task 1).
- Produces: `Database.update_url(url, observed_at=None, **fields)` now appends a `url_events` row per changed material field. Signature gains keyword-only-ish `observed_at` param (defaults to `_utcnow()`). Material set constant `_MATERIAL`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
def test_update_url_records_material_change_events(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://x.onion/"
    db.upsert_url(u, "x.onion", "crawled", 1, "2026-07-23T00:00:00")
    # first set alive=1 (from NULL) -> one event
    db.update_url(u, alive=1, observed_at="2026-07-23T01:00:00")
    # change alive 1->0 and trust None->verified -> two events
    db.update_url(u, alive=0, trust="verified", observed_at="2026-07-23T02:00:00")
    evs = [dict(r) for r in db.conn.execute(
        "SELECT field, old_value, new_value, observed_at FROM url_events ORDER BY event_id")]
    fields = [(e["field"], e["old_value"], e["new_value"]) for e in evs]
    assert ("alive", None, "1") in fields
    assert ("alive", "1", "0") in fields
    assert ("trust", None, "verified") in fields
    assert evs[-1]["observed_at"] == "2026-07-23T02:00:00"

def test_update_url_ignores_nonmaterial_and_unchanged(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://x.onion/"
    db.upsert_url(u, "x.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, alive=1, observed_at="2026-07-23T01:00:00")
    # non-material field change (title) -> no event
    db.update_url(u, title="New Title", observed_at="2026-07-23T02:00:00")
    # unchanged material (alive stays 1) -> no event
    db.update_url(u, alive=1, observed_at="2026-07-23T03:00:00")
    count = db.conn.execute("SELECT COUNT(*) FROM url_events").fetchone()[0]
    assert count == 1  # only the initial alive NULL->1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_update_url_records_material_change_events -v`
Expected: FAIL — `update_url` has no `observed_at` param / no events written (`TypeError` or assertion failure)

- [ ] **Step 3: Write minimal implementation**

In `src/dwcollector/db.py`, add the material-set constant next to `_UPDATABLE`:

```python
_MATERIAL = (
    "alive", "http_status", "content_simhash",
    "category", "trust", "is_canonical", "clone_of",
)


def _as_text(v):
    return None if v is None else str(v)
```

Replace the existing `update_url` method with:

```python
    def update_url(self, url, observed_at=None, **fields) -> None:
        cols = [k for k in fields if k in _UPDATABLE]
        if not cols:
            return
        material = [c for c in cols if c in _MATERIAL]
        old = {}
        host = None
        if material:
            row = self.get_url(url)
            if row is not None:
                old = {c: row.get(c) for c in material}
                host = row.get("host")
        assignments = ", ".join(f"{c} = ?" for c in cols)
        self.conn.execute(
            f"UPDATE urls SET {assignments} WHERE url = ?",
            [fields[c] for c in cols] + [url],
        )
        if old:
            obs = observed_at or _utcnow()
            for c in material:
                if fields[c] != old.get(c):
                    self.conn.execute(
                        "INSERT INTO url_events "
                        "(url, host, field, old_value, new_value, observed_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (url, host, c, _as_text(old.get(c)), _as_text(fields[c]), obs))
        self.conn.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS (new history tests + all existing db tests)

- [ ] **Step 5: Run full suite to check nothing regressed**

Run: `pytest -q`
Expected: all previously-passing tests still pass (existing `update_url` callers are unaffected — the extra kwarg defaults to `None`).

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/db.py tests/test_db.py
git commit -m "feat: record url_events for material field changes in update_url"
```

---

### Task 3: Config fields for watchlist, sink, webhook

**Files:**
- Modify: `src/dwcollector/config.py` (`Config` dataclass)
- Modify: `config.toml` (document the new keys, commented defaults)
- Test: `tests/test_config.py` (append)

**Interfaces:**
- Consumes: nothing.
- Produces: `Config.watchlist_terms: str = "terms.txt"`, `Config.alerts_path: str = "data/alerts.jsonl"`, `Config.alert_webhook: str = ""`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
from dwcollector.config import Config, load_config

def test_alert_config_defaults():
    c = Config()
    assert c.watchlist_terms == "terms.txt"
    assert c.alerts_path == "data/alerts.jsonl"
    assert c.alert_webhook == ""

def test_alert_config_parsed_from_toml(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        'watchlist_terms = "wl.txt"\n'
        'alerts_path = "out/a.jsonl"\n'
        'alert_webhook = "https://sink.local/hook"\n'
    )
    c = load_config(str(p))
    assert c.watchlist_terms == "wl.txt"
    assert c.alerts_path == "out/a.jsonl"
    assert c.alert_webhook == "https://sink.local/hook"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py::test_alert_config_defaults -v`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'watchlist_terms'`

- [ ] **Step 3: Write minimal implementation**

In `src/dwcollector/config.py`, add three fields to the `Config` dataclass (after `simhash_distance`):

```python
    watchlist_terms: str = "terms.txt"
    alerts_path: str = "data/alerts.jsonl"
    alert_webhook: str = ""          # empty = webhook disabled
```

Append to `config.toml`:

```toml
# --- alerting (Tier 1) ---
watchlist_terms = "terms.txt"
alerts_path     = "data/alerts.jsonl"
alert_webhook   = ""            # optional outbound POST target; "" disables
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/config.py config.toml tests/test_config.py
git commit -m "feat: add watchlist_terms/alerts_path/alert_webhook config"
```

---

### Task 4: `hunt()` returns covered URLs

**Files:**
- Modify: `src/dwcollector/hunt.py` (`hunt`)
- Modify: `tests/test_hunt.py` (update existing `test_hunt_records_hits`)
- Test: `tests/test_hunt.py` (append coverage test)

**Interfaces:**
- Consumes: existing `match_terms`, `db.canonical_trusted_urls`, `db.record_leak_hit`.
- Produces: `hunt(db, client, terms, run_id, now) -> tuple[int, set[str]]` — `(hit_count, covered_urls)` where `covered_urls` is the set of URLs successfully fetched (HTTP-OK) this run.

- [ ] **Step 1: Update the existing test + write the failing coverage test**

In `tests/test_hunt.py`, change the end of `test_hunt_records_hits` from:

```python
    n = await hunt(db, SiteClient(html), ["admin@acme.com"], "run1", "2026-07-21T00:00:00")
    assert n == 1
```

to:

```python
    n, covered = await hunt(db, SiteClient(html), ["admin@acme.com"], "run1", "2026-07-21T00:00:00")
    assert n == 1
    assert covered == {u}
```

Append a new test:

```python
class FlakyClient:
    """Returns OK for allowed urls, a failed FetchResult otherwise."""
    def __init__(self, html, ok_urls):
        self.html = html; self.ok_urls = ok_urls
    async def fetch(self, url):
        if url in self.ok_urls:
            return FetchResult(url, 200, self.html, 10, True)
        return FetchResult(url, None, "", 10, False)

@pytest.mark.asyncio
async def test_hunt_covered_excludes_unreachable(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    good = "http://good.onion/"; bad = "http://bad.onion/"
    for h in (good, bad):
        db.upsert_url(h, h.split("//")[1].strip("/"), "crawled", 1, "2026-07-23T00:00:00")
        db.update_url(h, is_canonical=1, trust="verified", category="leak-site")
    html = "<html><body>admin@acme.com</body></html>"
    client = FlakyClient(html, ok_urls={good})
    n, covered = await hunt(db, client, ["admin@acme.com"], "run1", "2026-07-23T00:00:00")
    assert covered == {good}          # bad.onion was unreachable -> not covered
    assert n == 1                      # only good.onion produced a hit
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hunt.py::test_hunt_covered_excludes_unreachable -v`
Expected: FAIL — `TypeError: cannot unpack non-iterable int object` (hunt still returns an int)

- [ ] **Step 3: Write minimal implementation**

Replace `hunt` in `src/dwcollector/hunt.py`:

```python
async def hunt(db, client, terms: list[str], run_id: str, now: str) -> tuple[int, set[str]]:
    count = 0
    covered: set[str] = set()
    for row in db.canonical_trusted_urls():
        res = await client.fetch(row["url"])
        if not (res.ok and res.status and res.status < 400):
            continue
        covered.add(row["url"])
        text = visible_text(res.html)
        for term, ctx in match_terms(text, terms):
            db.record_leak_hit(
                run_id, row["url"], row["host"], row.get("category"),
                row.get("trust"), term, ctx, now)
            count += 1
    return count, covered
```

- [ ] **Step 4: Update the manual CLI caller**

In `src/dwcollector/cli.py`, in `_run_hunt`'s inner `go()`, change:

```python
            n = await hunt(db, client, terms, f"hunt-{_now()}", _now())
            print("leak hits:", n)
```

to:

```python
            n, _ = await hunt(db, client, terms, f"hunt-{_now()}", _now())
            print("leak hits:", n)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_hunt.py tests/test_cli.py -q`
Expected: PASS (updated + new hunt tests, and CLI hunt path still works)

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/hunt.py src/dwcollector/cli.py tests/test_hunt.py
git commit -m "feat: hunt() returns (count, covered_urls) for coverage-gated resolve"
```

---

### Task 5: Alert emission (`alerts.py` — `emit`)

**Files:**
- Create: `src/dwcollector/alerts.py`
- Test: `tests/test_alerts.py` (create)

**Interfaces:**
- Consumes: `Database.record_alert` (Task 1); `Config.alerts_path`, `Config.alert_webhook` (Task 3).
- Produces:
  - `emit(db, cfg, finding, event, now, post_fn=_post_webhook) -> dict` — builds payload, writes `alerts` row, appends JSONL, prints stderr, POSTs webhook when configured; never raises.
  - `_post_webhook(cfg, payload) -> None` (real httpx POST; injectable for tests)
  - `_append_jsonl(path, payload) -> None`, `_title(finding, event) -> str`, `_body(finding, event) -> str`

- [ ] **Step 1: Write the failing test**

Create `tests/test_alerts.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alerts.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'dwcollector.alerts'`

- [ ] **Step 3: Write minimal implementation**

Create `src/dwcollector/alerts.py`:

```python
from __future__ import annotations
import json
import os
import sys


def _post_webhook(cfg, payload) -> None:
    import httpx
    with httpx.Client(timeout=10.0) as c:
        c.post(cfg.alert_webhook, json=payload)


def _append_jsonl(path: str, payload: dict) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")


def _title(finding: dict, event: str) -> str:
    if finding["kind"] == "leak":
        if event == "opened":
            return f"Client identifier '{finding['term']}' exposed on {finding['host']}"
        return f"Exposure of '{finding['term']}' on {finding['host']} resolved"
    if event == "opened":
        return f"Verified original {finding['host']} went dark"
    return f"Verified original {finding['host']} recovered"


def _body(finding: dict, event: str) -> str:
    if finding["kind"] == "leak":
        return (f"url={finding['url']} term={finding['term']} "
                f"snippet={finding.get('context_snippet') or ''}")
    return f"url={finding['url']} — canonical trusted site liveness changed"


def emit(db, cfg, finding: dict, event: str, now: str, post_fn=_post_webhook) -> dict:
    severity = finding["severity"]
    title = _title(finding, event)
    body = _body(finding, event)
    payload = {
        "event": event, "severity": severity, "kind": finding["kind"],
        "url": finding.get("url"), "host": finding.get("host"),
        "term": finding.get("term"), "title": title, "body": body,
        "created_at": now, "dedup_key": finding["dedup_key"],
    }
    delivered = 0
    error = None
    try:
        _append_jsonl(cfg.alerts_path, payload)
    except Exception as exc:  # noqa: BLE001 - sink failure must not crash loop
        error = f"jsonl: {exc!r}"
    print(f"[alert] {severity.upper()} {event} {title}", file=sys.stderr)
    if cfg.alert_webhook:
        try:
            post_fn(cfg, payload)
            delivered = 1
        except Exception as exc:  # noqa: BLE001 - webhook failure must not crash loop
            error = (error + "; " if error else "") + f"webhook: {exc!r}"
    db.record_alert(finding.get("finding_id"), finding["dedup_key"], event,
                    severity, title, body, now, delivered, error)
    return payload
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_alerts.py -v`
Expected: PASS (all three emit tests)

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/alerts.py tests/test_alerts.py
git commit -m "feat: alert emission to sink + optional webhook, failure-safe"
```

---

### Task 6: `reconcile_leaks` (leak finding lifecycle + coverage gate)

**Files:**
- Modify: `src/dwcollector/alerts.py` (add `reconcile_leaks`, `LEAK_SEVERITY`)
- Test: `tests/test_alerts.py` (append)

**Interfaces:**
- Consumes: `db.leak_hits_for_run`, `db.get_finding`, `db.open_finding`, `db.reopen_finding`, `db.touch_finding`, `db.open_findings`, `db.resolve_finding`; `emit` (Task 5).
- Produces: `reconcile_leaks(db, cfg, run_id, covered_urls, now, emit_fn=emit) -> list[dict]` — returns the list of emitted alert payloads.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_alerts.py`:

```python
from dwcollector.alerts import reconcile_leaks


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alerts.py::test_reconcile_leaks_full_lifecycle -v`
Expected: FAIL — `ImportError: cannot import name 'reconcile_leaks'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/dwcollector/alerts.py`:

```python
LEAK_SEVERITY = "critical"


def reconcile_leaks(db, cfg, run_id, covered_urls, now, emit_fn=emit) -> list[dict]:
    alerts = []
    seen_keys = set()
    for h in db.leak_hits_for_run(run_id):
        key = f"leak:{h['url']}|{h['term']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        existing = db.get_finding(key)
        if existing is None:
            db.open_finding("leak", key, h["url"], h["host"], h["term"],
                            LEAK_SEVERITY, h.get("context_snippet"), now)
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        elif existing["status"] == "resolved":
            db.reopen_finding(key, now, h.get("context_snippet"))
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        else:
            db.touch_finding(key, now)
    for f in db.open_findings("leak"):
        if f["dedup_key"] in seen_keys:
            continue
        if f["url"] in covered_urls:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_alerts.py -v`
Expected: PASS (lifecycle + coverage-gate tests)

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/alerts.py tests/test_alerts.py
git commit -m "feat: reconcile_leaks with open/resolved lifecycle + coverage gate"
```

---

### Task 7: `reconcile_dead_originals` (dead-original lifecycle)

**Files:**
- Modify: `src/dwcollector/alerts.py` (add `reconcile_dead_originals`, `DEAD_SEVERITY`)
- Test: `tests/test_alerts.py` (append)

**Interfaces:**
- Consumes: `db.canonical_trusted_urls`, `db.get_finding`, `db.open_finding`, `db.reopen_finding`, `db.touch_finding`, `db.open_findings`, `db.resolve_finding`; `emit`.
- Produces: `reconcile_dead_originals(db, cfg, now, emit_fn=emit) -> list[dict]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_alerts.py`:

```python
from dwcollector.alerts import reconcile_dead_originals


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alerts.py::test_reconcile_dead_original_lifecycle -v`
Expected: FAIL — `ImportError: cannot import name 'reconcile_dead_originals'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/dwcollector/alerts.py`:

```python
DEAD_SEVERITY = "high"


def reconcile_dead_originals(db, cfg, now, emit_fn=emit) -> list[dict]:
    alerts = []
    dead_keys = set()
    for r in db.canonical_trusted_urls():
        key = f"dead:{r['url']}"
        if r.get("alive") == 0:
            dead_keys.add(key)
            existing = db.get_finding(key)
            if existing is None:
                db.open_finding("dead_original", key, r["url"], r["host"], None,
                                DEAD_SEVERITY, None, now)
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            elif existing["status"] == "resolved":
                db.reopen_finding(key, now, None)
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            else:
                db.touch_finding(key, now)
    for f in db.open_findings("dead_original"):
        if f["dedup_key"] not in dead_keys:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_alerts.py -v`
Expected: PASS (all alerts tests)

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/alerts.py tests/test_alerts.py
git commit -m "feat: reconcile_dead_originals for canonical-site liveness alerts"
```

---

### Task 8: Wire hunt + reconcile into `run_cycle`

**Files:**
- Modify: `src/dwcollector/cli.py` (`run_cycle`)
- Test: `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `hunt` (Task 4), `reconcile_leaks` (Task 6), `reconcile_dead_originals` (Task 7), `load_terms`, `Config.watchlist_terms`.
- Produces: `run_cycle` result dict gains `"alerts": int` (and `"hunt_skipped"` when no watchlist). `run_cycle` keeps its never-raises contract.

Note: `run_cycle` currently takes `(cfg, db, seeds_path)`. Hunting needs a Tor client and the watchlist. Add hunting as a new isolated `try/except` block **after** the existing cluster block. To keep the integration test hermetic (no real Tor / no real httpx client construction), the crawl and hunt blocks share one injectable `client_factory` parameter defaulting to `TorClient`, and `crawl_fn`/`cluster_fn` are injectable too.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli.py` (imports at top of file as needed):

```python
from types import SimpleNamespace
from dwcollector.cli import run_cycle
from dwcollector.config import Config
from dwcollector.db import Database
from dwcollector.tor_client import FetchResult


class _StubClient:
    """Async-context client whose fetch always returns the given html OK."""
    def __init__(self, html): self.html = html
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def fetch(self, url):
        return FetchResult(url, 200, self.html, 10, True)


def test_run_cycle_hunts_and_alerts(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    # a verified canonical site to hunt
    u = "http://good.onion/"
    db.upsert_url(u, "good.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site", alive=1)
    wl = tmp_path / "wl.txt"; wl.write_text("acme.com\n")
    cfg = Config(watchlist_terms=str(wl), alerts_path=str(tmp_path / "a.jsonl"))

    html = "<html><body>dump has acme.com inside</body></html>"
    res = run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=1, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient(html),
    )
    assert res["ok"] is True
    assert res["alerts"] == 1
    fs = db.list_findings("open")
    assert any(f["kind"] == "leak" and f["severity"] == "critical" for f in fs)


def test_run_cycle_skips_hunt_without_watchlist(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(watchlist_terms=str(tmp_path / "missing.txt"),
                 alerts_path=str(tmp_path / "a.jsonl"))
    res = run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient(""),
    )
    assert res["ok"] is True
    assert res.get("alerts", 0) == 0
    assert "hunt_skipped" in res
```

Note: this test drives `run_cycle` through injected `crawl_fn`, `cluster_fn`, and `client_factory` seams. Task implementation must add those parameters (defaulting to the real `crawl`, `run_clustering`, and `TorClient`) so production behavior is unchanged.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_run_cycle_hunts_and_alerts -v`
Expected: FAIL — `run_cycle` has no `crawl_fn`/`hunt_client_factory` params (`TypeError`) or returns no `"alerts"` key.

- [ ] **Step 3: Write minimal implementation**

In `src/dwcollector/cli.py`, add imports near the top:

```python
from .alerts import reconcile_leaks, reconcile_dead_originals
```

Replace `run_cycle` with the version below (adds injectable seams + hunt/alert block; keeps existing crawl/cluster logic and never-raises contract):

```python
def run_cycle(cfg, db, seeds_path: str = "seeds.txt",
              crawl_fn=crawl, cluster_fn=run_clustering,
              client_factory=None) -> dict:
    """Run one crawl+cluster+hunt cycle for the supervisor loop.

    Reads `seeds_path` fresh every cycle (INSERT-OR-IGNORE upserts make
    re-seeding a no-op while self-healing a lost DB). Resumability comes from
    the frontier table. Never raises: each stage is isolated so one failure is
    logged into the returned dict and the loop moves on. `crawl_fn`,
    `cluster_fn`, and `client_factory` are injectable for tests; production
    leaves them at the real implementations.
    """
    if client_factory is None:
        client_factory = TorClient
    result: dict = {"ok": True, "started_at": _now()}

    try:
        seeds = _read_seeds(seeds_path)

        async def go():
            async with client_factory(cfg) as client:
                return await crawl_fn(cfg, db, client, seeds,
                                      f"run-{_now()}", _now())

        stats = asyncio.run(go())
        result["crawl"] = {
            "discovered": stats.discovered,
            "alive": stats.alive,
            "stop_reason": stats.stop_reason,
        }
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"crawl failed: {exc!r}"
        return result

    try:
        verified = load_verified_sources("verified_sources.toml")
        result["clusters"] = cluster_fn(db, verified, cfg.simhash_distance)
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"cluster failed: {exc!r}"

    try:
        terms = []
        if os.path.exists(cfg.watchlist_terms):
            terms = load_terms(cfg.watchlist_terms)
        if not terms:
            result["alerts"] = 0
            result["hunt_skipped"] = "no watchlist terms"
        else:
            run_id = f"run-{_now()}"

            async def go_hunt():
                async with client_factory(cfg) as client:
                    return await hunt(db, client, terms, run_id, _now())

            _, covered = asyncio.run(go_hunt())
            emitted = reconcile_leaks(db, cfg, run_id, covered, _now())
            emitted += reconcile_dead_originals(db, cfg, _now())
            result["alerts"] = len(emitted)
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"hunt/alert failed: {exc!r}"

    return result
```

Confirm `load_terms` is imported at the top of `cli.py` (it is: `from .hunt import hunt, load_terms`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (new run_cycle integration tests + existing CLI tests)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/cli.py tests/test_cli.py
git commit -m "feat: wire hunt + reconcile into run_cycle with injectable seams"
```

---

### Task 9: `alerts` CLI command

**Files:**
- Modify: `src/dwcollector/cli.py` (`build_parser`, add `_run_alerts`, dispatch in `main`)
- Test: `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `Database.list_findings` (Task 1).
- Produces: `dwcollector alerts [--status open|resolved|all]` (default `open`); `_run_alerts(db, args) -> None`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli.py`:

```python
from dwcollector.cli import build_parser, _run_alerts


def test_alerts_command_lists_findings(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "…", "2026-07-23T00:00:00")
    db.open_finding("dead_original", "dead:http://y.onion/", "http://y.onion/",
                    "y.onion", None, "high", None, "2026-07-23T00:00:00")
    db.resolve_finding("dead:http://y.onion/", "2026-07-23T01:00:00")

    args = build_parser().parse_args(["alerts", "--status", "open"])
    _run_alerts(db, args)
    out = capsys.readouterr().out
    assert "acme.com" in out and "critical" in out
    assert "y.onion" not in out          # resolved, excluded by --status open
    assert "total: 1" in out

    args_all = build_parser().parse_args(["alerts", "--status", "all"])
    _run_alerts(db, args_all)
    out_all = capsys.readouterr().out
    assert "total: 2" in out_all
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_alerts_command_lists_findings -v`
Expected: FAIL — `argument command: invalid choice: 'alerts'` (or `ImportError` for `_run_alerts`)

- [ ] **Step 3: Write minimal implementation**

In `src/dwcollector/cli.py` `build_parser`, add after the `stats` parser:

```python
    ap = sub.add_parser("alerts")
    ap.add_argument("--status", choices=["open", "resolved", "all"], default="open")
```

Add the handler function (near `_run_stats`):

```python
def _run_alerts(db, args) -> None:
    rows = db.list_findings(None if args.status == "all" else args.status)
    for f in rows:
        when = f.get("resolved_at") or f.get("last_seen") or f.get("first_seen")
        term = f.get("term") or "-"
        print(f"[{f['status']}] {f['severity']} {f['kind']} "
              f"{term} @ {f['host']} ({when})")
    print(f"total: {len(rows)}")
```

Add dispatch in `main` (after the `stats` branch):

```python
    elif args.command == "alerts":
        _run_alerts(db, args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py::test_alerts_command_lists_findings -v`
Expected: PASS

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/cli.py tests/test_cli.py
git commit -m "feat: add `alerts` CLI command to list findings by status"
```

---

### Task 10: README + docs.example refresh

**Files:**
- Modify: `README.md` (document alerting, watchlist, `alerts` command, webhook)
- Modify: `verified_sources.toml.example` / add a `terms.txt.example` (watchlist example)

**Interfaces:** none (docs only).

- [ ] **Step 1: Add a `terms.txt.example`**

Create `terms.txt.example`:

```
# One identifier per line. Lines starting with # are ignored.
# Literal substring match, case-insensitive. Prefix with re: for regex.
acme-corp.com
billing@acme-corp.com
re:ACME-[A-Z]+-DB
```

- [ ] **Step 2: Document alerting in README**

Add a section to `README.md` describing: the watchlist (`watchlist_terms`), that `loop` now hunts every cycle, the two alert types (CRITICAL new-leak / HIGH dead-original), the open/resolved lifecycle, the local `alerts.jsonl` sink + optional `alert_webhook`, and the `dwcollector alerts --status open|resolved|all` command. Note the coverage-gated resolve behavior (findings on unreachable sites stay open).

- [ ] **Step 3: Verify the suite is still green and commit**

Run: `pytest -q`
Expected: all green (docs change touches no code).

```bash
git add README.md terms.txt.example
git commit -m "docs: document alerting, watchlist, and alerts command"
```

---

## Final verification

- [ ] Run the full suite: `pytest -q` — expect all prior tests plus new ones green.
- [ ] Smoke the new command against a scratch DB:
  `python -m dwcollector --db /tmp/smoke.db alerts --status all` — expect `total: 0`.
- [ ] Confirm `git log --oneline` shows one commit per task and the tree is clean.
