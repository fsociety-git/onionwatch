# Trust-Anchor Re-Verification — Implementation Plan


**Goal:** Keep the trust-anchor set self-monitoring — fresh liveness, PGP identity re-verification with a safety cutout, and live cluster-sibling re-anchor candidates surfaced on the alert — by folding anchor health-checking into the hunt pass.

**Architecture:** `hunt()` gains anchor health-checking (updates `alive`, re-checks PGP identity, skips searching dead/compromised anchors) and returns a `HuntOutcome` dataclass. A new `anchor_identity` HIGH finding and the existing `dead_original` finding carry live cluster-sibling candidates. The loop runs the anchor pass every cycle even without a watchlist.

**Tech Stack:** Python 3.11+, stdlib + existing deps only (no new dependencies), pytest + pytest-asyncio.

**Spec:** `docs/specs/2026-07-23-trust-anchor-reverification-design.md`

## Global Constraints

- Python 3.11+; add no new third-party dependencies.
- **CRITICAL severity stays reserved for client-data exposure.** Anchor problems (dead / identity-failed) are **HIGH**.
- **Safety cutout:** a dead OR identity-failed anchor is NOT searched — it must not appear in `covered_urls` and no `leak_hits` row may be recorded for it, even if its page contains a watchlist term.
- Identity re-verification is **PGP-anchors-only** (host in `verified["pgp"]`); allow-list-only anchors get liveness re-check only (never in `identity_checked`).
- `hunt()` now **updates `alive`** for every anchor it probes (via `db.update_url`).
- Existing leak/identifier/PII alert wording stays byte-identical.
- Candidate notes contain only `.onion` addresses already in the DB — no secrets/PII.
- Timestamps UTC `"%Y-%m-%dT%H:%M:%S"` (passed through).
- Follow existing test style: `pytest`, `@pytest.mark.asyncio`, `Database(str(tmp_path / "t.db"))`, in-repo stub clients returning `FetchResult(url, status, html, response_ms, ok)`.

---

### Task 1: `is_pgp_anchor` in `verify.py`

**Files:**
- Modify: `src/onionwatch/verify.py`
- Test: `tests/test_verify.py` (append)

**Interfaces:**
- Consumes: `onion_host` (already imported in `verify.py`).
- Produces: `is_pgp_anchor(row: dict, verified: dict) -> bool` — True iff the row's onion host is a key in `verified["pgp"]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_verify.py`:

Onion hosts must be valid 16-char (v2) base32 addresses — `onion_host()` returns `None` for anything else (e.g. `aaaaaaaaaaaaaaaa.onion`), which would make `is_pgp_anchor` always False. Use `aaaaaaaaaaaaaaaa.onion` / `bbbbbbbbbbbbbbbb.onion`, matching the existing `tests/test_verify.py` fixtures.

```python
from onionwatch.verify import is_pgp_anchor


def test_is_pgp_anchor():
    verified = {"pgp": {"aaaaaaaaaaaaaaaa.onion": "AAAA BBBB"}, "verified_onions": []}
    assert is_pgp_anchor({"url": "http://aaaaaaaaaaaaaaaa.onion/"}, verified) is True
    assert is_pgp_anchor({"url": "http://bbbbbbbbbbbbbbbb.onion/"}, verified) is False
    assert is_pgp_anchor({"url": "http://aaaaaaaaaaaaaaaa.onion/"}, {"pgp": {}}) is False
    assert is_pgp_anchor({"url": "http://aaaaaaaaaaaaaaaa.onion/"}, {}) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_verify.py::test_is_pgp_anchor -v`
Expected: FAIL — `ImportError: cannot import name 'is_pgp_anchor'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/onionwatch/verify.py`:

```python
def is_pgp_anchor(row: dict, verified: dict) -> bool:
    return onion_host(row["url"]) in verified.get("pgp", {})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_verify.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/verify.py tests/test_verify.py
git commit -m "feat: is_pgp_anchor helper for identity re-verification"
```

---

### Task 2: `Database.live_cluster_siblings`

**Files:**
- Modify: `src/onionwatch/db.py`
- Test: `tests/test_db.py` (append)

**Interfaces:**
- Produces: `Database.live_cluster_siblings(cluster_id, exclude_url) -> list[dict]` — alive rows in the same cluster, excluding `exclude_url`. Returns `[]` when `cluster_id` is falsy.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
def test_live_cluster_siblings(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    def add(url, cid, alive):
        db.upsert_url(url, url.split("//")[1].strip("/"), "crawled", 1, "2026-07-23T00:00:00")
        db.update_url(url, cluster_id=cid, alive=alive)
    add("http://anchor.onion/", "c000001", 0)   # the (dead) anchor
    add("http://sib-alive.onion/", "c000001", 1) # live sibling -> candidate
    add("http://sib-dead.onion/", "c000001", 0)  # dead sibling -> excluded
    add("http://other.onion/", "c000002", 1)     # different cluster -> excluded
    sibs = db.live_cluster_siblings("c000001", "http://anchor.onion/")
    urls = {s["url"] for s in sibs}
    assert urls == {"http://sib-alive.onion/"}
    assert db.live_cluster_siblings(None, "http://anchor.onion/") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_live_cluster_siblings -v`
Expected: FAIL — `AttributeError: 'Database' object has no attribute 'live_cluster_siblings'`

- [ ] **Step 3: Write minimal implementation**

Add to the `Database` class in `src/onionwatch/db.py`:

```python
    def live_cluster_siblings(self, cluster_id, exclude_url) -> list[dict]:
        if not cluster_id:
            return []
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM urls WHERE cluster_id = ? AND url != ? AND alive = 1",
            (cluster_id, exclude_url))]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: live_cluster_siblings for re-anchor candidates"
```

---

### Task 3: `HuntOutcome` + anchor health-checking in `hunt()`

**Files:**
- Modify: `src/onionwatch/hunt.py` (imports, `HuntOutcome`, `hunt`)
- Modify: `tests/test_hunt.py` (update existing unpackings; append new tests)

**Interfaces:**
- Consumes: `is_pgp_anchor` (Task 1), `verify.pgp_matches` (existing), `find_matches`, `visible_text`, `db.update_url`, `db.record_leak_hit`.
- Produces:
  - `HuntOutcome(hit_count: int, covered_urls: set[str], identity_checked: set[str], identity_failed: set[str])`
  - `hunt(db, client, terms, run_id, now, detectors=None, verified=None) -> HuntOutcome` — updates `alive` per anchor; re-checks PGP identity; safety cutout skips searching dead/identity-failed anchors.

- [ ] **Step 1: Update existing test unpackings + write new failing tests**

In `tests/test_hunt.py`, **every** existing `await hunt(...)` call currently binds a 2-tuple (`n, covered = ...` or `n, _ = ...`). Change each to bind the outcome and use its fields. The affected calls and their replacements:

- `test_hunt_records_hits`:
  ```python
  outcome = await hunt(db, SiteClient(html), ["admin@acme.com"], "run1", "2026-07-21T00:00:00")
  assert outcome.hit_count == 1
  assert outcome.covered_urls == {u}
  ```
- `test_hunt_covered_excludes_unreachable`:
  ```python
  outcome = await hunt(db, client, ["admin@acme.com"], "run1", "2026-07-23T00:00:00")
  assert outcome.covered_urls == {good}
  assert outcome.hit_count == 1
  ```
- `test_hunt_skips_dead_site_records_no_hit`:
  ```python
  outcome = await hunt(db, DeadClient(), ["admin@acme.com"], "run1", "2026-07-23T00:00:00")
  assert outcome.hit_count == 0
  assert outcome.covered_urls == set()
  ```
- `test_hunt_records_fuzzy_and_pii`:
  ```python
  outcome = await hunt(db, SiteClient(html), ["fuzzy:acme.com"], "run1", "2026-07-23T00:00:00", detectors=["credit-card"])
  assert outcome.covered_urls == {u}
  # then use db.leak_hits_for_run("run1") as before
  ```
- `test_hunt_defaults_no_detectors`:
  ```python
  outcome = await hunt(db, SiteClient("<html><body>acme.com</body></html>"), ["acme.com"], "run1", "2026-07-23T00:00:00")
  # (row assertions unchanged)
  ```

(If a test's exact variable names differ, the rule is: `outcome = await hunt(...)`, then `outcome.hit_count` for the count and `outcome.covered_urls` for the covered set. Grep `await hunt(` to find them all.)

Then append these new tests:

```python
from onionwatch.hunt import HuntOutcome

FP = "1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678"  # 10 groups of 4 hex


def _add_anchor(db, url, host):
    db.upsert_url(url, host, "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(url, is_canonical=1, trust="verified", category="leak-site")


class MapClient:
    """Serves a per-url html; url not in the map -> unreachable FetchResult."""
    def __init__(self, pages): self.pages = pages
    async def fetch(self, url):
        if url in self.pages:
            return FetchResult(url, 200, self.pages[url], 10, True)
        return FetchResult(url, None, "", 10, False)


@pytest.mark.asyncio
async def test_hunt_updates_alive(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    up, down = "http://up.onion/", "http://down.onion/"
    _add_anchor(db, up, "up.onion"); _add_anchor(db, down, "down.onion")
    await hunt(db, MapClient({up: "<html><body>hi</body></html>"}), [], "run1", "2026-07-23T00:00:00")
    assert db.get_url(up)["alive"] == 1
    assert db.get_url(down)["alive"] == 0


@pytest.mark.asyncio
async def test_hunt_identity_failure_is_not_searched(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    _add_anchor(db, u, "aaaaaaaaaaaaaaaa.onion")
    verified = {"pgp": {"aaaaaaaaaaaaaaaa.onion": FP}, "verified_onions": [], "directories": []}
    # page is ALIVE and contains a watchlist term, but carries NO valid fingerprint
    bad = "<html><body>leak of admin@acme.com but wrong key here</body></html>"
    outcome = await hunt(db, MapClient({u: bad}), ["admin@acme.com"], "run1",
                         "2026-07-23T00:00:00", verified=verified)
    assert u in outcome.identity_checked and u in outcome.identity_failed
    assert u not in outcome.covered_urls               # safety cutout
    assert db.leak_hits_for_run("run1") == []          # NOT searched despite the term
    assert db.get_url(u)["alive"] == 1                 # it is alive, just not trusted


@pytest.mark.asyncio
async def test_hunt_identity_ok_is_searched(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    _add_anchor(db, u, "aaaaaaaaaaaaaaaa.onion")
    verified = {"pgp": {"aaaaaaaaaaaaaaaa.onion": FP}, "verified_onions": [], "directories": []}
    ok = f"<html><body>key {FP} — leak of admin@acme.com</body></html>"
    outcome = await hunt(db, MapClient({u: ok}), ["admin@acme.com"], "run1",
                         "2026-07-23T00:00:00", verified=verified)
    assert u in outcome.identity_checked and u not in outcome.identity_failed
    assert u in outcome.covered_urls
    assert outcome.hit_count == 1


@pytest.mark.asyncio
async def test_hunt_allowlist_anchor_liveness_only(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    _add_anchor(db, u, "aaaaaaaaaaaaaaaa.onion")
    verified = {"pgp": {}, "verified_onions": ["aaaaaaaaaaaaaaaa.onion"], "directories": []}
    outcome = await hunt(db, MapClient({u: "<html><body>hi acme.com</body></html>"}),
                         ["acme.com"], "run1", "2026-07-23T00:00:00", verified=verified)
    assert u not in outcome.identity_checked           # no fingerprint to check
    assert u in outcome.covered_urls                   # still searched
    assert outcome.hit_count == 1
```

(`SiteClient`/`DeadClient` already exist in `tests/test_hunt.py` from specs #1/#2; reuse them.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hunt.py::test_hunt_identity_failure_is_not_searched -v`
Expected: FAIL — `hunt()` has no `verified` kwarg / returns a tuple (`AttributeError`/`TypeError`)

- [ ] **Step 3: Write minimal implementation**

In `src/onionwatch/hunt.py`, update the imports at the top:

```python
from dataclasses import dataclass
from .discover import visible_text
from .matching import find_matches
from .verify import is_pgp_anchor, pgp_matches
```

Add the dataclass and replace `hunt`:

```python
@dataclass
class HuntOutcome:
    hit_count: int
    covered_urls: set
    identity_checked: set
    identity_failed: set


async def hunt(db, client, terms: list[str], run_id: str, now: str,
               detectors=None, verified=None) -> HuntOutcome:
    detectors = detectors or []
    verified = verified or {}
    count = 0
    covered: set[str] = set()
    identity_checked: set[str] = set()
    identity_failed: set[str] = set()
    for row in db.canonical_trusted_urls():
        res = await client.fetch(row["url"])
        ok = bool(res.ok and res.status and res.status < 400)
        db.update_url(row["url"], alive=1 if ok else 0,
                      http_status=res.status, last_checked=now)
        if not ok:
            continue
        text = visible_text(res.html)
        if is_pgp_anchor(row, verified):
            identity_checked.add(row["url"])
            if not pgp_matches(row["url"], text, verified):
                identity_failed.add(row["url"])
                continue          # SAFETY CUTOUT: never search a compromised anchor
        covered.add(row["url"])
        for mt in find_matches(text, terms, detectors):
            db.record_leak_hit(
                run_id, row["url"], row["host"], row.get("category"),
                row.get("trust"), mt.key, mt.context, now,
                match_kind=mt.kind, match_count=mt.count)
            count += 1
    return HuntOutcome(count, covered, identity_checked, identity_failed)
```

Keep `match_terms` in the module (unused by `hunt`, used by its own tests).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hunt.py -v`
Expected: PASS (updated existing + new tests)

- [ ] **Step 5: Run full suite (catch other hunt callers)**

Run: `pytest -q`
Expected: `tests/test_cli.py` may FAIL on `_run_hunt`/`run_cycle` unpacking — that is fixed in Task 6. All of `test_hunt.py` and non-cli suites pass. If any NON-cli test fails, fix it here before committing. Note in the commit that cli call sites are updated in Task 6.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/hunt.py tests/test_hunt.py
git commit -m "feat: hunt anchor health-check (alive+identity), HuntOutcome, safety cutout"
```

---

### Task 4: Re-anchor candidate note + enrich `dead_original`

**Files:**
- Modify: `src/onionwatch/alerts.py` (`_candidate_note`, `reconcile_dead_originals`)
- Test: `tests/test_alerts.py` (append)

**Interfaces:**
- Consumes: `db.live_cluster_siblings` (Task 2).
- Produces: `_candidate_note(db, row) -> str`; `reconcile_dead_originals` stores the candidate note as the finding `context_snippet` on open and reopen.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_alerts.py`:

```python
from onionwatch.alerts import reconcile_dead_originals, _candidate_note


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alerts.py::test_candidate_note_lists_live_siblings -v`
Expected: FAIL — `ImportError: cannot import name '_candidate_note'`

- [ ] **Step 3: Write minimal implementation**

Add the helper to `src/onionwatch/alerts.py`:

```python
def _candidate_note(db, row: dict) -> str:
    sibs = db.live_cluster_siblings(row.get("cluster_id"), row["url"])
    if sibs:
        urls = ", ".join(s["url"] for s in sibs)
        return f"verify before trusting — candidate successors: {urls}"
    return "verify before trusting — no live successor discovered yet"
```

In `reconcile_dead_originals`, replace the two `None` context-snippet arguments with the candidate note. The open call becomes:

```python
                db.open_finding("dead_original", key, r["url"], r["host"], None,
                                DEAD_SEVERITY, _candidate_note(db, r), now)
```

and the reopen call becomes:

```python
                db.reopen_finding(key, now, _candidate_note(db, r))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_alerts.py -v`
Expected: PASS (new + existing alerts tests; existing dead-original lifecycle tests still pass — they don't assert the snippet)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/alerts.py tests/test_alerts.py
git commit -m "feat: re-anchor candidate note; dead_original alerts carry candidates"
```

---

### Task 5: `reconcile_anchor_identity` + alert copy

**Files:**
- Modify: `src/onionwatch/alerts.py` (`ANCHOR_IDENTITY_SEVERITY`, `reconcile_anchor_identity`, `_title`, `_body`)
- Test: `tests/test_alerts.py` (append)

**Interfaces:**
- Consumes: `_candidate_note` (Task 4), `db.get_url`, finding lifecycle methods, `emit`.
- Produces: `reconcile_anchor_identity(db, cfg, identity_checked, identity_failed, now, emit_fn=emit) -> list[dict]`; `_title`/`_body` render the `anchor_identity` kind and surface the candidate note for both anchor kinds.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_alerts.py`:

```python
from onionwatch.alerts import reconcile_anchor_identity, _title, _body


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alerts.py::test_reconcile_anchor_identity_lifecycle -v`
Expected: FAIL — `ImportError: cannot import name 'reconcile_anchor_identity'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/onionwatch/alerts.py` (near the other severity constants):

```python
ANCHOR_IDENTITY_SEVERITY = "high"


def reconcile_anchor_identity(db, cfg, identity_checked, identity_failed, now,
                              emit_fn=emit) -> list[dict]:
    alerts = []
    for url in identity_failed:
        key = f"identity:{url}"
        row = db.get_url(url) or {"url": url, "host": None, "cluster_id": None}
        note = _candidate_note(db, row)
        existing = db.get_finding(key)
        if existing is None:
            db.open_finding("anchor_identity", key, url, row.get("host"), None,
                            ANCHOR_IDENTITY_SEVERITY, note, now)
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        elif existing["status"] == "resolved":
            db.reopen_finding(key, now, note)
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        else:
            db.touch_finding(key, now)
    recovered = set(identity_checked) - set(identity_failed)
    for f in db.open_findings("anchor_identity"):
        if f["url"] in recovered:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts
```

Update `_title` — insert an `anchor_identity` branch **before** the final dead-original returns:

```python
    if finding["kind"] == "anchor_identity":
        if event == "opened":
            return f"Verified anchor {finding['host']} failed identity re-verification"
        return f"Anchor {finding['host']} identity re-verification recovered"
    if event == "opened":
        return f"Verified original {finding['host']} went dark"
    return f"Verified original {finding['host']} recovered"
```

Replace `_body` so anchor kinds surface the candidate note:

```python
def _body(finding: dict, event: str) -> str:
    if finding["kind"] == "leak":
        return (f"url={finding['url']} term={finding['term']} "
                f"snippet={finding.get('context_snippet') or ''}")
    reason = ("anchor identity re-verification failed"
              if finding["kind"] == "anchor_identity"
              else "canonical trusted site liveness changed")
    note = finding.get("context_snippet") or ""
    body = f"url={finding['url']} — {reason}"
    return f"{body} · {note}" if note else body
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_alerts.py -v`
Expected: PASS (new + existing; existing dead-original/leak wording tests still pass)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/alerts.py tests/test_alerts.py
git commit -m "feat: anchor_identity HIGH finding + alert copy with candidates"
```

---

### Task 6: Loop wiring in `run_cycle` + `_run_hunt`

**Files:**
- Modify: `src/onionwatch/cli.py` (imports, `_run_hunt`, `run_cycle`)
- Test: `tests/test_cli.py` (update existing; append one integration test)

**Interfaces:**
- Consumes: `HuntOutcome` (Task 3), `reconcile_anchor_identity` (Task 5), `load_verified_sources` (already imported).
- Produces: `run_cycle` runs the anchor pass **every cycle** (even with no watchlist), passes `verified` to `hunt`, runs `reconcile_dead_originals` + `reconcile_anchor_identity` always and `reconcile_leaks` only when terms exist. `_run_hunt` uses `HuntOutcome.hit_count`.

- [ ] **Step 1: Write the failing test**

In `tests/test_cli.py`, add `reconcile_anchor_identity` awareness via one integration test (imports as needed; `_StubClient`, `Config`, `Database`, `FetchResult` are already used in this file):

`run_cycle` is a **synchronous** function (it calls `asyncio.run` internally), so this test is a plain `def` — NOT async and NOT `@pytest.mark.asyncio`. `SimpleNamespace` is already imported in `tests/test_cli.py` (from spec #1); if not, add `from types import SimpleNamespace`.

```python
def test_run_cycle_reverifies_anchor_identity(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    db.upsert_url(u, "aaaaaaaaaaaaaaaa.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", cluster_id="c1")
    cfg = Config(watchlist_terms=str(tmp_path / "wl.txt"),   # missing -> no terms
                 alerts_path=str(tmp_path / "a.jsonl"))
    # verified marks aaaaaaaaaaaaaaaa.onion as a PGP anchor; the served page has NO valid fp
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "directories": [],
                                      "pgp": {"aaaaaaaaaaaaaaaa.onion": "1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678"}})

    class _Stub:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch(self, url):
            return FetchResult(url, 200, "<html><body>no key here</body></html>", 10, True)

    res = run_cycle(cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
                    crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=1, stop_reason="ok"),
                    cluster_fn=lambda *a, **k: 0,
                    client_factory=lambda cfg: _Stub())
    assert res["ok"] is True
    # anchor pass ran despite no watchlist, and identity failure opened a HIGH finding
    fs = db.list_findings("open")
    assert any(f["kind"] == "anchor_identity" and f["severity"] == "high" for f in fs)
    assert res["alerts"] >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_run_cycle_reverifies_anchor_identity -v`
Expected: FAIL — `run_cycle` skips hunt when no watchlist / no `reconcile_anchor_identity` / `HuntOutcome` unpack error

- [ ] **Step 3: Write minimal implementation**

In `src/onionwatch/cli.py`, extend the alerts import:

```python
from .alerts import reconcile_leaks, reconcile_dead_originals, reconcile_anchor_identity
```

Update `_run_hunt`'s inner `go()`:

```python
        async with TorClient(cfg) as client:
            outcome = await hunt(db, client, terms, f"hunt-{_now()}", _now(),
                                 detectors=cfg.pii_detectors)
            print("leak hits:", outcome.hit_count)
```

Replace the hunt/alert `try` block in `run_cycle` with:

```python
    try:
        terms = []
        if os.path.exists(cfg.watchlist_terms):
            terms = load_terms(cfg.watchlist_terms)
        verified = load_verified_sources("verified_sources.toml")
        run_id = f"run-{_now()}"

        async def go_hunt():
            async with client_factory(cfg) as client:
                return await hunt(db, client, terms, run_id, _now(),
                                  detectors=cfg.pii_detectors, verified=verified)

        outcome = asyncio.run(go_hunt())
        emitted = []
        if terms:
            emitted += reconcile_leaks(db, cfg, run_id, outcome.covered_urls, _now())
        else:
            result["hunt_skipped"] = "no watchlist terms (anchors still re-verified)"
        emitted += reconcile_dead_originals(db, cfg, _now())
        emitted += reconcile_anchor_identity(db, cfg, outcome.identity_checked,
                                             outcome.identity_failed, _now())
        result["alerts"] = len(emitted)
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"hunt/alert failed: {exc!r}"

    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (new integration test + existing run_cycle tests — the existing `test_run_cycle_hunts_and_alerts` still asserts `alerts == 1` since the alive anchor with no PGP entry is searched and produces the one leak; `test_run_cycle_skips_hunt_without_watchlist` still finds `"hunt_skipped"` in the result and `alerts == 0` when there are no canonical anchors).

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/cli.py tests/test_cli.py
git commit -m "feat: run_cycle re-verifies anchors every cycle (even without watchlist)"
```

---

### Task 7: Docs — README

**Files:**
- Modify: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Document trust-anchor re-verification in README**

Add a "Trust-anchor re-verification" subsection near the trust-model / alerting content covering: that each cycle re-probes the verified/probable anchors (fresh liveness, so the HIGH dead-original alert actually fires); that PGP-anchored sites are additionally identity-checked (fingerprint re-confirmed) and a mismatch raises a **HIGH `anchor_identity`** alert; the **safety cutout** (a dead or identity-failed anchor is never searched, so the watchlist is never sent to a compromised anchor); that alerts carry **re-anchor candidates** (live cluster siblings) framed "verify before trusting — never auto-added" and that promotion to the trust list is a manual operator step (edit `verified_sources.toml`); the PGP-anchors-only limitation for identity checks; and that the anchor pass runs every cycle even without a watchlist loaded.

- [ ] **Step 2: Verify suite green and commit**

Run: `pytest -q`
Expected: all green (docs-only change).

```bash
git add README.md
git commit -m "docs: document trust-anchor re-verification"
```

---

## Final verification

- [ ] Run the full suite: `pytest -q` — expect all prior tests plus the new ones green.
- [ ] Smoke the safety cutout offline: a stubbed `hunt` over a PGP anchor whose page lacks the expected fingerprint records **no** `leak_hits` even when the page contains a watchlist term (covered by `test_hunt_identity_failure_is_not_searched`).
- [ ] Confirm `git log --oneline` shows one commit per task and the tree is clean.
