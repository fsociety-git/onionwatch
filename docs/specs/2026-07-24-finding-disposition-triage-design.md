# Design: Finding Disposition & Triage

**Date:** 2026-07-24
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2, analyst-workflow spec #1 of a decomposed set. Follow-on
analyst-workflow specs (separate): case management; per-client reports; client
association. This spec is the foundation the others build on.

## Problem

onionwatch detects and alerts, but an analyst can't *work* the findings. The
`findings` table has a machine-owned `status` (`open`/`resolved`, driven by the
reconcilers each cycle) but nothing analyst-owned: no way to mark a false
positive, no notes, no history, no triage queue. So a recurring false match
keeps firing CRITICAL alerts forever, and an analyst can only *view* findings
(the read-only `alerts` command), never triage them.

This spec adds an analyst **disposition** dimension to findings — orthogonal to
the machine `status` — with a triage queue, an append-only history log, and
alert suppression for dispositioned-away findings, all via CLI + SQLite.

## Design decisions (ratified during brainstorming)

- **CLI + DB, no UI.** The workflow lives in SQLite (disposition fields, history
  log) and is driven by CLI commands. A dashboard could later read the same DB;
  it is out of scope here.
- **Four-value disposition, orthogonal to `status`:** `new` (default,
  un-triaged), `confirmed`, `false_positive`, `dismissed`. The reconcilers
  **never** touch `disposition`; they only touch `status`.
- **Sticky:** disposition persists across the open/resolved/reopen lifecycle
  (`reopen_finding` already never touches it), so a re-detection of something an
  analyst judged `false_positive` stays that way and doesn't re-surface as `new`.
- **Triage queue** = `status='open' AND disposition='new'`, ordered
  critical-before-high then most-recent.
- **Suppress re-alerts for `false_positive`/`dismissed`:** a dispositioned-away
  finding goes off the alert radar — the reconcilers still track its lifecycle
  but `emit` delivers nothing (no sink, no stderr, no webhook). The *first* alert
  always fires (a fresh finding is `new`); suppression only applies after triage.
  A `suppressed=1` alert row is still recorded for audit.
- **Current disposition + append-only history log.** `findings` carries the
  current disposition (fast single-table queue query); a `disposition_log` table
  records every change (`finding_id, disposition, note, actor, at`). Notes live
  in the log, so a note can be added without changing disposition.

## Architecture

### 1. Schema (additive + idempotent migration)

Extend the `findings` and `alerts` tables in `SCHEMA` and add a new table; for
existing DBs, add the columns via idempotent `ALTER TABLE` in `init_schema`
(same pattern as spec #2's `leak_hits` columns — swallow `sqlite3.OperationalError`).

```sql
-- findings gains (analyst-owned; reconcilers never write these):
--   disposition TEXT DEFAULT 'new', disposition_actor TEXT, disposition_at TEXT

CREATE TABLE IF NOT EXISTS disposition_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    disposition TEXT,      -- disposition in effect at this log entry
    note TEXT,             -- optional analyst note (may be the whole point of the entry)
    actor TEXT,            -- who (optional)
    at TEXT                -- when (UTC)
);

-- alerts gains: suppressed INTEGER DEFAULT 0
```

`init_schema` migration statements (append to the existing loop):
`ALTER TABLE findings ADD COLUMN disposition TEXT DEFAULT 'new'`,
`… disposition_actor TEXT`, `… disposition_at TEXT`,
`ALTER TABLE alerts ADD COLUMN suppressed INTEGER DEFAULT 0`.

### 2. DB methods (`db.py`)

- `get_finding_by_id(finding_id) -> dict | None` — CLI addresses findings by the
  stable `finding_id`.
- `set_disposition(finding_id, disposition, note, actor, now) -> None` — one
  atomic change: `UPDATE findings SET disposition=?, disposition_actor=?,
  disposition_at=? WHERE finding_id=?` **and** `INSERT INTO disposition_log
  (finding_id, disposition, note, actor, at) VALUES (...)`. Single commit.
- `add_note(finding_id, note, actor, now) -> None` — read the finding's current
  `disposition`, append a `disposition_log` row with that disposition + the note;
  do **not** change `findings.disposition`.
- `triage_queue() -> list[dict]` —
  `SELECT * FROM findings WHERE status='open' AND disposition='new'
   ORDER BY (CASE severity WHEN 'critical' THEN 0 ELSE 1 END), last_seen DESC`.
- `disposition_history(finding_id) -> list[dict]` — `disposition_log` rows for a
  finding, oldest first.
- `record_alert(...)` gains a trailing `suppressed=0` param and inserts it.

### 3. Alert suppression (`alerts.py`) — one contained coupling

At the top of `emit`, after building `title`/`body`/`payload` and before the
JSONL/stderr/webhook delivery:

```python
SUPPRESSED = ("false_positive", "dismissed")

def emit(db, cfg, finding, event, now, post_fn=_post_webhook) -> dict:
    severity = finding["severity"]
    title = _title(finding, event); body = _body(finding, event)
    payload = { ... }                      # unchanged
    if finding.get("disposition") in SUPPRESSED:
        try:
            db.record_alert(finding.get("finding_id"), finding["dedup_key"], event,
                            severity, title, body, now, 0, None, suppressed=1)
        except Exception:                  # best-effort audit; never crash the loop
            pass
        return payload                     # deliver nothing
    # ... existing sink + stderr + webhook + record_alert(..., suppressed=0) ...
```

No reconciler changes: `db.get_finding(...)` is `SELECT *`, so the finding dict
passed to `emit` already carries `disposition`. Stickiness needs no code —
`reopen_finding` never touches disposition (confirm this holds).

### 4. CLI commands (`cli.py`)

- **`triage`** — `onionwatch triage` prints the queue (`triage_queue()`), one
  line per finding incl. `finding_id`, severity, kind, term/host. Read-only.
- **`disposition`** — `onionwatch disposition <finding_id>
  <new|confirmed|false_positive|dismissed> [--note TEXT] [--by ACTOR]` →
  validate the finding exists (`get_finding_by_id`), then `set_disposition`.
- **`note`** — `onionwatch note <finding_id> --text TEXT [--by ACTOR]` →
  `add_note` (comment without changing disposition).
- **`history`** — `onionwatch history <finding_id>` → print
  `disposition_history` rows.
- Extend **`alerts`** (`_run_alerts`) to include the `disposition` in each line.

`--by` is optional; the recorded `actor` is its value or `None`. Finding handles
are `finding_id` integers. Unknown/absent finding_id → a clear stderr message,
non-zero exit, no crash.

## Error handling

- `set_disposition`/`add_note` on a nonexistent `finding_id`: the CLI checks
  `get_finding_by_id` first and reports a clear error; the DB methods are no-ops
  on a missing id (the `UPDATE` matches nothing; `add_note` skips if the finding
  is absent).
- Suppressed-alert audit write is best-effort (wrapped) — never crashes the loop.
- Migration is idempotent; a legacy DB gains the columns without error.
- Disposition values are constrained at the CLI (argparse `choices`); the DB
  layer stores whatever it's given (no new enforcement).

## Testing (TDD, existing pytest style)

- **set_disposition:** updates `findings.disposition`/`_actor`/`_at` and appends
  one `disposition_log` row; a second change appends a second row (history grows).
- **add_note:** appends a log row carrying the current disposition + note, and
  leaves `findings.disposition` unchanged.
- **triage_queue:** returns only `open` + `new`, critical-before-high then
  recency; a finding dispositioned `confirmed`/`false_positive`/`dismissed` drops
  out; a resolved finding is excluded.
- **sticky:** open a finding, disposition it `false_positive`, resolve then
  reopen it via the reconciler path — disposition is still `false_positive`.
- **suppression:** `emit` for a `false_positive`/`dismissed` finding writes a
  `suppressed=1` alerts row and produces **no** JSONL line and calls **no**
  webhook (assert the sink file and an injected `post_fn` are untouched); a
  `new`/`confirmed` finding emits normally (`suppressed=0`, sink written).
- **CLI:** `triage` lists the queue; `disposition` sets + logs (and validates a
  bad finding_id); `note` appends; `history` prints the trail; `alerts` shows the
  disposition column.
- **migration:** a legacy `findings`/`alerts` (built without the new columns)
  gains them after `init_schema`, no raise.

## Out of scope (explicitly deferred)

- **Case management** (grouping findings into per-client/incident cases) — next
  analyst-workflow spec; disposition is a prerequisite.
- **Per-client reports** — a later spec; will consume dispositions + history.
- **Client association** (tying findings/terms to clients) — cross-cutting, folds
  into the reports/cases spec where "per-client" first matters.
- **`in_progress` disposition** — deliberately omitted (a case concept); the set
  stays four values.
- **A web UI / dashboard** — the CLI+DB layer is designed so a UI could read the
  same tables later.
- **Per-analyst auth / real user accounts** — `--by` is a free-text actor label.
