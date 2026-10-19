# Design: Listing → Hunt Finding Integration

**Date:** 2026-07-24
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2 analyst-workflow follow-on. A market listing whose product
text matches a watchlist term becomes a `market_listing` **finding** flowing
into the existing emit → alert → triage → disposition → case machinery. Reuses
the pattern-aware matcher and the reconciler pattern. No new dependencies; no
schema change.

## Problem

Listing extraction populates a queryable `listings` store, but nothing connects
it to the analyst workflow. If a client's identifier — or any watchlist term —
appears in a marketplace listing (i.e. is being **sold**), an analyst only finds
it by manually querying `listings`. Meanwhile the existing `hunt()` scans **only
`canonical_trusted_urls()`** (verified/anchored sites), so marketplace listings
are entirely outside hunt coverage — a client identifier being sold on a market
generates no finding and no alert today.

This spec closes that gap: a new reconciler matches listings against the
watchlist and raises `market_listing` findings, giving "your identifier is being
sold on market H" the same alert/triage/case treatment as any other finding —
with **no redundancy** against leak findings (different surface entirely).

## Design decisions (ratified during brainstorming)

- **Matcher (A):** reuse the pattern-aware `find_matches(product_text, terms,
  detectors)` against the same watchlist (`terms.txt` ∪ client terms) and PII
  detectors the hunt uses — literal / `fuzzy:` / `enc:` / `cred:` / `re:` / PII
  shapes all apply, consistent with the hunt.
- **Dedup identity (A):** `(host + matched term)` — dedup_key
  `listing:{host}|{mt.key}`. Stable against the volatile parts (price, listing
  URL, re-extraction); "identifier X is sold on market H."
- **Severity (A):** a single `high` for all `market_listing` findings. Listings
  are a best-effort lead signal, so CRITICAL stays reserved for confirmed direct
  leaks; triage promotes a real one.
- **Gating (A):** reuse the `extract_listings` gate — no new flag. Runs in
  `run_cycle` after the existing reconcilers; a no-op when extraction is off
  (no listings) or the watchlist is empty. Only matches produce findings, so
  volume is bounded by matches, not listing count.

## Architecture

### Data flow

`run_cycle` (production loop) → after the existing reconcilers, call
`reconcile_listing_matches(db, cfg, terms, cfg.pii_detectors, now)`. It reads the
persistent `listings` table (populated by extraction), runs `find_matches` on
each listing's `product_text` against the watchlist, and maintains
`market_listing` findings on an open/resolved lifecycle via
`open_finding`/`reopen_finding`/`resolve_finding` + `emit`. Because it plugs into
those, listing findings automatically get alerting, disposition suppression,
triage, and case assignment — no new subsystem.

### 1. `reconcile_listing_matches` (new, in `alerts.py`)

Mirrors `reconcile_leaks`:

```python
LISTING_SEVERITY = "high"

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

**Resolution needs no `covered_urls` guard** (unlike `reconcile_leaks`): the
`listings` table is persistent state, not per-run. A `(host, term)` absent from
*all* current listings genuinely no longer appears — and a marketplace page not
re-crawled this cycle keeps its listings rows (replace-per-crawl only replaces on
a successful crawl), so its findings correctly stay open. A finding resolves only
when extraction actually removed the matching listing.

`find_matches` imported from `.matching` (already used by `hunt`).

### 2. Finding shape + evidence (`_listing_snippet`)

- `kind="market_listing"`, `severity="high"`, `term = mt.key`, `url` = the
  matching listing's URL, `host` = the market host.
- `context_snippet` prefixes the **price** to the **match context**:

```python
def _listing_snippet(lst, mt) -> str:
    price = lst.get("price_raw") or ""
    return f"[{price}] {mt.context}" if price else mt.context
```

Using `mt.context` (not raw `product_text`) preserves masking — a `cred:`/PII
match's context is already masked, so **no raw secret/PII is stored**. `price_raw`
is a non-sensitive token (e.g. `0.05 BTC`), so the alert can say "seen at 0.05
BTC."

### 3. Alert copy (`_title` / `_body` in `alerts.py`)

Add a `market_listing` branch to each, **before** the dead-original fallthrough
(else a listing finding would render dead-original copy):

- `_title`: opened → `Watchlist term '<term>' offered in a market listing on
  <host>`; resolved → `Market listing of '<term>' on <host> gone`.
- `_body`: `url=<url> term=<term> — matched in an extracted marketplace listing`
  plus the `context_snippet` (price + evidence).

### 4. `run_cycle` wiring + gating (`cli.py`)

After the `reconcile_anchor_identity` call, add:

```python
        if cfg.extract_listings and terms:
            emitted += reconcile_listing_matches(db, cfg, terms, cfg.pii_detectors, _now())
```

Reuses the already-built `terms` (watchlist ∪ client terms) and
`cfg.pii_detectors`. Gated on `extract_listings` (off → no listings → the loop
body is empty anyway, but the explicit guard skips the query) and a non-empty
watchlist. Applies only in `run_cycle`, not the ad-hoc `hunt --terms` path
(consistent with the watchlist-union and per-client-report decisions). Imported
alongside the other reconcilers in `cli.py`.

## Error handling

- The `run_cycle` hunt/alert block already sits in a cycle-isolating
  `try/except`; a failure here is caught and recorded, never fatal.
- A listing with `product_text` `None`/empty → `find_matches("", …)` → no matches.
- Disposition suppression is automatic: a `market_listing` finding dispositioned
  `false_positive`/`dismissed` suppresses re-alerts via the existing `emit`
  check, and disposition is sticky across reopen (reconcilers never touch it).
- No schema change — `market_listing` is a new `kind` value in the existing
  `findings` table; case assignment (`case_id`) works unchanged.

## Testing (TDD, existing pytest style)

- **reconcile:** a listing matching a watchlist term opens a `market_listing`
  finding (severity `high`, dedup `listing:host|term`, `price_raw` in the
  snippet); a second matching listing on the same host+term does **not** create a
  second finding (dedup); when the matching listing is gone (replaced/cleared),
  the finding resolves; a re-appearing match reopens a resolved finding.
- **matcher parity:** a `fuzzy:` watchlist entry matching a listing produces a
  finding; a `cred:`/PII match's stored `context_snippet` is masked (no raw
  secret/PII).
- **suppression:** a `false_positive`-dispositioned listing finding suppresses
  its re-alert (first alert fires; subsequent do not).
- **alert copy:** `_title`/`_body` produce market-listing-specific text for
  opened and resolved, distinct from the dead-original default.
- **gating:** with `extract_listings=False` (or an empty watchlist),
  `reconcile_listing_matches` is not invoked by `run_cycle`; a direct call with
  no listings returns `[]`; findings of other kinds are unaffected.
- **integration:** a `market_listing` finding can be assigned to a case and
  appears in `case_findings` and the case report (regular-finding plumbing).

## Out of scope (explicitly deferred)

- **Per-client leak report inclusion** — `report --client` stays leak-only
  (`kind='leak'`); listing findings surface via `alerts`/`triage`/`cases`/case
  reports. A listings section in the client report is a later refinement.
- **Client-aware CRITICAL severity** — single `high` for now; listings are
  best-effort, so CRITICAL stays for confirmed leaks.
- **Price-threshold / currency filters on finding creation** — every watchlist
  match becomes a finding; price is evidence, not a gate.
- **Matching the raw `product_text` instead of the extracted price context** —
  matching runs on `product_text` (the bounded window already stored); no new
  page fetching or body storage.
