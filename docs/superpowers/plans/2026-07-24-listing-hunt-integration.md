# Listing → Hunt Finding Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a market listing whose product text matches a watchlist term into a `market_listing` finding that flows into the existing alert/triage/disposition/case machinery.

**Architecture:** A new `reconcile_listing_matches` reconciler in `alerts.py` (mirroring `reconcile_leaks`) matches the persistent `listings` table against the hunt watchlist via `find_matches`, and maintains `market_listing` findings on an open/resolved lifecycle through `open_finding`/`reopen_finding`/`resolve_finding` + `emit`. `run_cycle` calls it after the existing reconcilers, gated on `extract_listings`. No schema change.

**Tech Stack:** Python 3.11+, sqlite3, pytest. Stdlib only.

## Global Constraints

- Python 3.11+; **no new dependencies** (stdlib only).
- **No schema change:** `market_listing` is a new `kind` value in the existing `findings` table.
- **Reuse the matcher:** matching uses `find_matches(product_text, terms, detectors)` — the same function/watchlist/detectors the hunt uses. Do not write a new matcher.
- **Dedup identity:** `dedup_key = f"listing:{host}|{mt.key}"` (host + matched term). One finding per (market host, identifier).
- **Severity:** all `market_listing` findings are `"high"` (a `LISTING_SEVERITY` constant). Not CRITICAL.
- **No raw PII/secret stored:** the finding's `context_snippet` uses the match's already-masked `mt.context` (not the raw `product_text`), prefixed with the non-sensitive `price_raw`.
- **Resolution has no `covered_urls` guard:** the `listings` table is persistent state; a `(host, term)` absent from all current listings is genuinely gone (a page not re-crawled keeps its listings rows, so its findings stay open).
- **Gating:** `run_cycle` calls the reconciler only when `cfg.extract_listings` is on AND the watchlist is non-empty. Not on the ad-hoc `hunt --terms` path.
- Follow existing test style: `Database(str(tmp_path / "t.db"))`, `db.init_schema()`, `_cfg(tmp_path)` = `SimpleNamespace(alerts_path=..., alert_webhook="")`, pytest; `run_cycle` tests inject `crawl_fn`/`cluster_fn`/`client_factory` and monkeypatch `load_verified_sources`.
- Run the suite with `.venv/bin/python -m pytest` (pytest is not on PATH). Baseline before this plan: **247 passed, 1 deselected**.

Interfaces this plan relies on (all exist):
- `db.list_listings(...) -> list[dict]` (rows: url, host, price_value, currency, price_raw, product_text, extracted_at).
- `db.open_finding(kind, dedup_key, url, host, term, severity, context_snippet, now)`, `db.reopen_finding(dedup_key, now, context_snippet)`, `db.touch_finding(dedup_key, last_seen)`, `db.resolve_finding(dedup_key, resolved_at)`, `db.get_finding(dedup_key)`, `db.open_findings(kind=None)`.
- `alerts.emit(db, cfg, finding, event, now)` — suppresses when `finding["disposition"]` in `("false_positive","dismissed")`.
- `matching.find_matches(text, terms, detectors) -> list[Match]`; `Match.kind`, `Match.key` (underlying identifier or `pii:<detector>`), `Match.context` (masked for pii/credential).
- `Config.extract_listings` (bool), `Config.pii_detectors` (list).

---

## File Structure

- `src/dwcollector/alerts.py` (modify) — `LISTING_SEVERITY`, `find_matches` import, `_listing_snippet`, `reconcile_listing_matches`, and `market_listing` branches in `_title`/`_body`.
- `src/dwcollector/cli.py` (modify) — import the reconciler; call it in `run_cycle` after `reconcile_anchor_identity`.
- `tests/test_alerts.py` (modify) — reconciler + alert-copy tests.
- `tests/test_cli.py` (modify) — `run_cycle` wiring tests.
- `README.md` (modify) — document the feature.

---

### Task 1: `reconcile_listing_matches` + evidence + alert copy (`alerts.py`)

**Files:**
- Modify: `src/dwcollector/alerts.py` (imports ~line 1-4; severity constants ~line 7-10; `_title` ~line 27-45; `_body` ~line 47-57; add new functions near `reconcile_leaks` ~line 104)
- Test: `tests/test_alerts.py`

**Interfaces:**
- Consumes: `find_matches`, the db finding lifecycle methods, `emit`.
- Produces: `reconcile_listing_matches(db, cfg, terms, detectors, now, emit_fn=emit) -> list[dict]`; `_listing_snippet(lst, mt) -> str`; `LISTING_SEVERITY`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_alerts.py` (the file already imports `Database`, `emit`, and has `_cfg`; add `reconcile_listing_matches` to the imports):

```python
from dwcollector.alerts import reconcile_listing_matches


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_alerts.py -k "listing or market_listing" -v`
Expected: FAIL — `ImportError: cannot import name 'reconcile_listing_matches'`.

- [ ] **Step 3: Implement in `alerts.py`**

Add the import (after the existing `import sys`, ~line 4):

```python
from .matching import find_matches
```

Add the severity constant (with the other severities, ~line 9):

```python
LISTING_SEVERITY = "high"
```

Add a `market_listing` branch to `_title`, immediately before the final dead-original fallthrough (`if event == "opened": return f"Verified original ..."`):

```python
    if finding["kind"] == "market_listing":
        if event == "opened":
            return (f"Watchlist term '{finding['term']}' offered in a market "
                    f"listing on {finding['host']}")
        return f"Market listing of '{finding['term']}' on {finding['host']} gone"
```

Add a `market_listing` branch to `_body`, immediately after the `leak` branch (before the `reason = (...)` line):

```python
    if finding["kind"] == "market_listing":
        note = finding.get("context_snippet") or ""
        body = (f"url={finding['url']} term={finding['term']} "
                f"— matched in an extracted marketplace listing")
        return f"{body} · {note}" if note else body
```

Add the snippet helper and reconciler (near `reconcile_leaks`, ~line 104):

```python
def _listing_snippet(lst, mt) -> str:
    price = lst.get("price_raw") or ""
    return f"[{price}] {mt.context}" if price else mt.context


def reconcile_listing_matches(db, cfg, terms, detectors, now, emit_fn=emit) -> list[dict]:
    alerts, seen_keys = [], set()
    for lst in db.list_listings():
        for mt in find_matches(lst.get("product_text") or "", terms, detectors):
            key = f"listing:{lst['host']}|{mt.key}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            snippet = _listing_snippet(lst, mt)
            existing = db.get_finding(key)
            if existing is None:
                db.open_finding("market_listing", key, lst["url"], lst["host"],
                                mt.key, LISTING_SEVERITY, snippet, now)
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            elif existing["status"] == "resolved":
                db.reopen_finding(key, now, snippet)
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            else:
                db.touch_finding(key, now)
    for f in db.open_findings("market_listing"):
        if f["dedup_key"] not in seen_keys:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_alerts.py -v`
Expected: PASS (the eight new tests plus all pre-existing alerts tests).

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/alerts.py tests/test_alerts.py
git commit -m "feat: reconcile_listing_matches — market_listing findings from listings"
```

---

### Task 2: `run_cycle` wiring (`cli.py`)

**Files:**
- Modify: `src/dwcollector/cli.py` (alerts import ~line 21; `run_cycle` after `reconcile_anchor_identity` ~line 430)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `reconcile_listing_matches` (Task 1); the existing `terms`/`cfg.pii_detectors` locals in `run_cycle`.
- Produces: listing findings generated each production cycle when `extract_listings` is on.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py` (the file already imports `run_cycle`, `Config`, `SimpleNamespace`, `Database`, and defines `_StubClient`):

```python
def test_run_cycle_creates_market_listing_findings(tmp_path, monkeypatch):
    import dwcollector.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://m.onion/1", "m.onion", [
        {"price_value": 0.05, "currency": "BTC", "price_raw": "0.05 BTC",
         "product_text": "acme.com dump 0.05 BTC"}], "2026-07-24T00:00:00")
    wl = tmp_path / "wl.txt"; wl.write_text("acme.com\n")
    cfg = Config(watchlist_terms=str(wl), alerts_path=str(tmp_path / "a.jsonl"),
                 extract_listings=True)
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "pgp": {}, "directories": []})
    res = run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient("<html></html>"))
    assert res["ok"] is True
    fs = db.list_findings("open")
    assert any(f["kind"] == "market_listing" and f["term"] == "acme.com"
               and f["severity"] == "high" for f in fs)


def test_run_cycle_no_listing_findings_when_extract_off(tmp_path, monkeypatch):
    import dwcollector.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://m.onion/1", "m.onion", [
        {"price_value": 0.05, "currency": "BTC", "price_raw": "0.05 BTC",
         "product_text": "acme.com dump"}], "2026-07-24T00:00:00")
    wl = tmp_path / "wl.txt"; wl.write_text("acme.com\n")
    cfg = Config(watchlist_terms=str(wl), alerts_path=str(tmp_path / "a.jsonl"),
                 extract_listings=False)          # gate off
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "pgp": {}, "directories": []})
    run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient("<html></html>"))
    assert not any(f["kind"] == "market_listing" for f in db.list_findings("open"))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k "market_listing or listing_findings" -v`
Expected: FAIL — `test_run_cycle_creates_market_listing_findings` finds no `market_listing` finding (reconciler not yet wired into `run_cycle`).

- [ ] **Step 3: Wire the reconciler into `run_cycle`**

Extend the alerts import in `src/dwcollector/cli.py` (currently line 21):

```python
from .alerts import (reconcile_leaks, reconcile_dead_originals,
                     reconcile_anchor_identity, reconcile_listing_matches)
```

In `run_cycle`, immediately after the `reconcile_anchor_identity(...)` call (~line 429-430), add:

```python
        if cfg.extract_listings and terms:
            emitted += reconcile_listing_matches(db, cfg, terms, cfg.pii_detectors, _now())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_cli.py -v`
Expected: PASS (the two new tests plus all pre-existing cli tests, including the other `run_cycle` tests).

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — all green.

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/cli.py tests/test_cli.py
git commit -m "feat: run_cycle generates market_listing findings when extraction is on"
```

---

### Task 3: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the shipped behavior (Tasks 1-2). No code.

- [ ] **Step 1: Document listing findings**

In `README.md`, extend the existing `## Market-listing extraction (optional)` section (search for it) by appending a short paragraph at its end describing the finding integration. Use exactly this content (keep it inside that section, do not create a new top-level heading):

```markdown
When listing extraction is on and a watchlist term (from `terms.txt` or a
client's `clients.toml` terms) matches a listing's product text, dwcollector
raises a **`market_listing` finding** (severity `high`) — "this identifier is
being sold on market H." These findings flow into the same
`alerts`/`triage`/`disposition`/`history` and case machinery as any other
finding, so a match on a market is triaged and cased like a leak. Findings are
keyed per market host + identifier (price lives in the evidence, not the
identity), and resolve when the matching listing stops appearing. Matching reuses
the hunt's pattern-aware matcher (literal / `fuzzy:` / `enc:` / `cred:` / `re:` /
PII detectors); a `cred:`/PII match's stored evidence is masked. CRITICAL stays
reserved for confirmed leaks — market matches are `high`, a best-effort lead.
```

- [ ] **Step 2: Verify docs-only (no code touched)**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — unchanged suite (docs edit only).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document market_listing findings from listing extraction"
```

---

## Notes for the executor

- Do NOT add a `covered_urls` guard to the resolution loop — the `listings` table is persistent state, and its absence is intentional (see Global Constraints). `test_reconcile_listing_resolves_when_gone` and `..._reopens` depend on this.
- The finding's `context_snippet` must be built from `mt.context` (masked), never the raw `product_text` — `test_reconcile_listing_pii_match_is_masked` guards it.
- Severity is `"high"` for all `market_listing` findings (the `LISTING_SEVERITY` constant); do not make it client-aware or CRITICAL.
- The `run_cycle` gate is `if cfg.extract_listings and terms:` — both conditions. `test_run_cycle_no_listing_findings_when_extract_off` guards the off case.
- `market_listing` branches in `_title`/`_body` must come before the dead-original fallthrough, else the wrong copy renders (`test_market_listing_alert_copy` guards it).
