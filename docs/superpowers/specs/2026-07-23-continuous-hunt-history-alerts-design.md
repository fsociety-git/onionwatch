# Design: Continuous Hunting + Temporal Tracking + Alerting

**Date:** 2026-07-23
**Status:** Approved — ready for implementation planning
**Scope:** Tier 1, spec #1 of 3 (the coupled core). Follow-on specs: fuzzy/pattern-aware hunting (#2), trust-anchor re-verification (#3).

## Problem

dwcollector today *records* but does not *warn*. Three gaps make it a passive
collector rather than a monitoring service:

1. **No history.** The `urls` table holds only current state — every crawl
   overwrites `last_checked`, `alive`, `content_simhash`, `title`, etc. The
   tool literally cannot answer "when did this change?"
2. **The loop never hunts.** `supervisor_loop` / `run_cycle` run `crawl` +
   `cluster` only. Continuous monitoring never searches for client data on a
   schedule; `hunt` is a manual one-off command.
3. **No alerting and no dedup.** `hunt()` re-records every match on every run
   into an append-only `leak_hits` table. There is no notion of a *new* finding
   versus one already reported, and nothing is pushed to a human.

This spec turns the tool from "records" into "warns" by adding a lightweight
history event-log, wiring hunting into the loop, and adding a deduplicated,
lifecycle-tracked alert engine with a local sink plus one optional webhook.

## Design decisions (ratified during brainstorming)

- **History model — hybrid.** Keep the single-state `urls` row; additionally
  write an append-only event whenever a *material* field changes, carrying the
  before→after values for that field. Enough to drive "this is new" alerts and
  answer "what changed and when" without full-snapshot storage blowup.
- **Alert delivery — local sink + one pluggable webhook.** Alerts are written
  to an `alerts` table + an append-only `alerts.jsonl` file and printed to
  stderr (the source of truth, fully offline-testable). If a webhook URL is
  configured, the alert is also POSTed to it. No SMTP/Slack-specific code. An
  outbound webhook to the operator's own infrastructure does not violate the
  "nothing leaves our infrastructure" positioning.
- **Push-worthy events — exactly two.** Everything material is logged; only two
  events are *pushed*:
  - **CRITICAL — new leak hit:** a client identifier surfaced on a verified
    site that we had not already reported.
  - **HIGH — verified original went dark:** a canonical trusted site anchoring
    clone-detection flipped `alive → dead`. (Detection only; the remediation
    workflow is spec #3.)
  Log-only (not pushed): simhash content change, new-site discovery/category,
  trust/cluster changes on non-canonical sites.
- **Dedup identity — `(url, term)` with an open/resolved lifecycle.** A finding
  opens on first sighting (fires the alert), stays open silently while it keeps
  matching, resolves when a hunt no longer finds it, and re-fires only on
  `resolved → open`. Same lifecycle for dead-original findings keyed on `url`.
- **Loop wiring — hunt every cycle.** Each loop iteration runs
  crawl → cluster → hunt → reconcile, reading the watchlist from a configured
  path. One cadence, one process. The manual `hunt --terms` command stays.

## Architecture

### 1. Schema additions (`db.py`)

All additive; no existing table or column changes.

```sql
CREATE TABLE IF NOT EXISTS url_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT, host TEXT,
    field TEXT,              -- material field that changed
    old_value TEXT, new_value TEXT,
    observed_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT,               -- 'leak' | 'dead_original'
    dedup_key TEXT UNIQUE,   -- 'leak:<url>|<term>' | 'dead:<url>'
    url TEXT, host TEXT, term TEXT,
    status TEXT,             -- 'open' | 'resolved'
    severity TEXT,           -- 'critical' | 'high'
    first_seen TEXT, last_seen TEXT, resolved_at TEXT,
    context_snippet TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER, dedup_key TEXT,
    event TEXT,              -- 'opened' | 'resolved'
    severity TEXT, title TEXT, body TEXT,
    created_at TEXT,
    delivered INTEGER DEFAULT 0, delivery_error TEXT
);
```

New `Database` methods (thin wrappers matching existing style):
`record_url_event`, `upsert_finding`, `get_finding(dedup_key)`,
`open_findings(kind=None)`, `resolve_finding(dedup_key, resolved_at)`,
`record_alert`, `recent_alerts(limit)`.

### 2. History tracking — automatic via `update_url`

`Database.update_url` becomes history-aware. Before applying the UPDATE it
SELECTs the old values for the **material set**:

```
{alive, http_status, content_simhash, category, trust, is_canonical, clone_of}
```

After the UPDATE, for each material field whose value actually changed it
appends a `url_events` row (`field`, `old_value`, `new_value`, `observed_at =
now`). Non-material fields (`last_checked`, `response_ms`, `title`, `snippet`,
etc.) are excluded as noise. Because every existing write flows through
`update_url`, discovery/probe/cluster all gain history with **zero call-site
changes**. Cost: one extra SELECT per update — acceptable at this scale.

`observed_at` uses the same UTC `_now()` format already used across the app.
`update_url` gains an optional `observed_at` param (defaulting to a UTC
timestamp) so tests can assert deterministic values.

### 3. Alert engine (`alerts.py`, new module)

Pure functions over `db` + `cfg`, no global state:

- `reconcile_leaks(db, cfg, run_id, covered_urls, now) -> list[Alert]`
  After `hunt()` has written this run's rows to `leak_hits`, compute the run's
  set of `(url, term)`. For each:
  - no open `leak` finding for that key → **open** finding, emit CRITICAL
    `opened` alert.
  - open finding exists → update `last_seen`, stay silent.
  Resolve is **coverage-gated to avoid false-resolve on transient failures**:
  `hunt()` reports `covered_urls` — the set of URLs it *successfully fetched*
  this run (HTTP-OK, text extracted). An open `leak` finding resolves **only if
  its url is in `covered_urls` and its `(url, term)` was not matched this run**.
  A finding whose site was unreachable this cycle (not in `covered_urls`) stays
  open untouched — we didn't actually check it, so we make no claim.

- `reconcile_dead_originals(db, cfg, now) -> list[Alert]`
  For each `canonical_trusted_urls()` row: `alive == 0` and no open
  `dead_original` finding → **open** + emit HIGH `opened`. `alive == 1` with an
  open finding → **resolve** + emit `resolved`.

- `emit(db, cfg, finding, event, now)`
  Builds title/body, writes the `alerts` row, appends one JSON line to
  `cfg.alerts_path`, prints a one-line summary to stderr, and — if
  `cfg.alert_webhook` is set — POSTs the JSON payload. File-append and webhook
  are each wrapped so any failure is caught, recorded in `alerts.delivery_error`
  / `delivered=0`, and **never propagates**. The DB `alerts` row is always
  written first and is the durable record.

The webhook POST uses the existing `httpx` dependency with a short timeout. It
is a plain outbound POST — it does **not** go through Tor (the sink is operator
infrastructure, not a .onion).

### 4. Config additions (`config.py` / `config.toml`)

Three new `Config` fields with defaults:

```python
watchlist_terms: str = "terms.txt"
alerts_path: str = "data/alerts.jsonl"
alert_webhook: str = ""          # empty = disabled
```

The existing unknown-key warning already covers typos. `alert_webhook = ""`
means no webhook is attempted.

### 5. Loop wiring (`cli.py` `run_cycle`)

After the existing crawl and cluster steps, add a hunt+reconcile step wrapped in
its own `try/except` (matching the current per-step isolation, so a hunt failure
logs and the loop continues):

```
terms = load_terms(cfg.watchlist_terms)   # skipped if file missing/empty
run_id = f"run-<now>"                      # reuse the cycle's run id
covered = await hunt(db, client, terms, run_id, now)   # returns set of fetched urls
alerts = (reconcile_leaks(db, cfg, run_id, covered, now)
          + reconcile_dead_originals(db, cfg, now))
result["alerts"] = len(alerts)
```

`hunt()` gains a return value: the set of URLs it successfully fetched this run
(currently it returns only an `int` hit count). The manual `hunt --terms` CLI
path ignores the returned set — behavior there is unchanged.

If the watchlist file is missing or empty, the hunt step is skipped cleanly
(logged, not an error) so a fresh box without a configured watchlist still runs.
The manual `hunt --terms` command is unchanged and does **not** auto-reconcile
(it stays a raw one-off); reconciliation is a loop/`run_cycle` concern.

### 6. New CLI command — `alerts`

```
dwcollector alerts [--status open|resolved|all]   # default: open
```

Lists findings with lifecycle state (kind, severity, url, term, status,
first_seen, last_seen/resolved_at) so an analyst sees current exposures without
tailing the JSONL file. Read-only.

## Error handling

- Alert delivery never crashes the loop: DB row written first; file + webhook
  failures caught and recorded in `delivery_error`.
- The reconcile step runs under the loop's existing per-step `try/except`.
- Missing/empty watchlist → hunt skipped, logged, cycle continues.
- History SELECT-before-update failures are non-fatal to the update itself
  (history is best-effort; the state write is the priority).

## Testing (TDD, existing pytest style)

- **history:** `update_url` emits one `url_events` row per changed material
  field, none for unchanged or non-material fields; deterministic `observed_at`.
- **leak lifecycle:** open on first sighting (CRITICAL emitted) → silent while
  present → resolve when absent *and covered* → reopen on reappearance.
- **coverage gate:** a finding whose url is **not** in `covered_urls` (site
  unreachable this run) stays open and does **not** resolve or re-fire.
- **dead-original lifecycle:** open on `alive→dead` (HIGH) → resolve on recovery.
- **emit:** writes `alerts` row + JSONL line + stderr; webhook POST called with
  correct payload when configured; webhook failure path records
  `delivery_error`, leaves `delivered=0`, and does not raise (loop survives).
- **config:** new keys parsed with defaults; empty `alert_webhook` disables POST.
- **loop integration:** one `run_cycle` end-to-end with a stub client and a
  small watchlist produces the expected findings/alerts and never raises.

## Out of scope (explicitly deferred)

- Fuzzy/encoded/credential-format matching → spec #2.
- Trust-anchor re-verification & address-rotation handling → spec #3 (this spec
  only *flags* a dead canonical original).
- Periodic re-alert / reminder cadence for still-open findings (option C from
  brainstorming) — add later as a config knob if analysts want it.
- SMTP/Slack-specific channels — the single webhook is the seam.
- Full page-state snapshots / arbitrary time-travel — event-log only.
