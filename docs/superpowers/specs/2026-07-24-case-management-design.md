# Design: Case Management

**Date:** 2026-07-24
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2, analyst-workflow spec #3. Builds on disposition/triage and
the per-client report/client model (both merged). Follow-on: standalone
`report --case <id>` incident-report deliverable (deferred).

## Problem

Analysts can triage and disposition individual findings and report per client,
but there is no way to **group related findings into an incident** — "these four
exposures are all the Acme billing-DB breach" — track its state, keep a timeline,
and surface it in a client report. Each finding stands alone.

This spec adds a **case** entity: an analyst-created grouping of findings with a
state lifecycle, an optional client, and an append-only timeline, addressable
from the CLI and rolled up into the per-client report.

## Design decisions (ratified during brainstorming)

- **Membership (A):** manual assignment, one case per finding, via a nullable
  `case_id` column on `findings` (analyst-owned; reconcilers never touch it). A
  case's findings = `findings WHERE case_id = X`. No auto-grouping.
- **State (A):** three states — `open` (default) → `investigating` → `closed`.
  Analyst-owned; nothing machine-reconciles a case. Constrained at the CLI.
- **Client (A):** optional, free-text `client` on a case (ideally a
  `clients.toml` name but not validated — matches how `--by` works).
- **Reporting (A):** a `case show` console working view + a **Cases** section in
  the existing `report --client`. A standalone `report --case` is deferred.

## Architecture

### 1. Schema (additive + idempotent migration)

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
-- findings gains: case_id INTEGER   (nullable; analyst-owned)
```

Migration: add the two tables to `SCHEMA` and append
`ALTER TABLE findings ADD COLUMN case_id INTEGER` to the existing idempotent
`init_schema` ALTER loop (swallow `sqlite3.OperationalError`). The reconcilers
(`open_finding`/`reopen_finding`/`resolve_finding`/`touch_finding` and
`reconcile_*`) never write `case_id` — case membership survives the finding
lifecycle, same as `disposition`.

### 2. DB methods (`db.py`)

- `create_case(title, client, actor, now) -> int` — INSERT into `cases`, append a
  `case_log` `created` row, return `case_id`.
- `get_case(case_id) -> dict | None`; `list_cases(client=None, state=None) -> list[dict]`.
- `set_case_state(case_id, state, note, actor, now)` — UPDATE `cases.state` (set
  `closed_at = now` when state is `closed`, else leave/clear), append a
  `state:<state>` log row.
- `assign_finding(finding_id, case_id, actor, now)` — `UPDATE findings SET
  case_id = ?`, append `assigned finding #<id>` to the case log.
- `unassign_finding(finding_id, actor, now)` — read the finding's current
  `case_id`; `UPDATE findings SET case_id = NULL`; append `unassigned finding
  #<id>` to that case's log (no-op if the finding has no case).
- `add_case_note(case_id, note, actor, now)` — append a `note` log row.
- `case_findings(case_id) -> list[dict]` — `findings WHERE case_id = ?`,
  severity/last_seen ordered.
- `case_history(case_id) -> list[dict]` — `case_log` rows oldest-first.

Every mutating method commits (existing convention).

### 3. CLI — nested `case` command group (`cli.py`)

`case` uses argparse **nested subparsers** (`dwcollector case <action>`):

- `case create "<title>" [--client NAME] [--by ACTOR]` → prints the new `case_id`.
- `case list [--client NAME] [--state STATE]` → one line per case (id, state,
  client, title, finding count).
- `case show <case_id>` → header (title / client / state / created) + member
  findings (finding_id, severity, host, term, disposition) + the timeline
  (`case_history`). Unknown id → stderr + exit 1.
- `case assign <finding_id> <case_id> [--by]` — validate both exist → assign, else
  stderr + exit 1.
- `case unassign <finding_id> [--by]` — validate finding exists → unassign.
- `case state <case_id> <open|investigating|closed> [--note] [--by]` — validate
  case → set state.
- `case note <case_id> --text "…" [--by]` — validate case → add note.

State is constrained via argparse `choices`; ids are `type=int`. `--by` optional
(free-text actor, or null). A dispatch branch in `main` routes `case` to a
`_run_case(db, args)` handler that switches on the nested action and returns an
exit code.

### 4. Report rollup (`report.py`)

`client_cases(db, client_name) -> list[dict]` — `list_cases(client=client_name)`,
each annotated with its member-finding count (`len(case_findings(case_id))`).
`build_report` gains a `cases` list in its output (`{case_id, title, state,
findings}`), and `render_markdown`/`render_json` add a **Cases** section listing
the client's cases (id, title, state, finding count). The existing findings
section, summary, filters (`--all`/`--since`) are unchanged.

## Error handling

- Bad/absent `case_id` or `finding_id` at the CLI → clear stderr message +
  non-zero exit; DB methods no-op on a missing id (`UPDATE` matches nothing).
- `unassign_finding` on a finding with no case → no-op (nothing to log).
- Migration idempotent; a legacy DB gains `case_id`/tables without error.
- Case membership and state are analyst-owned; no reconcile path writes them.
- Case actor/client are free-text; no new validation or enforcement.

## Testing (TDD, existing pytest style)

- **DB:** `create_case` returns an id and logs `created`; `assign_finding` sets
  `case_id` and logs; `unassign_finding` clears it and logs to the right case
  (and no-ops when unassigned); `set_case_state` updates state, sets `closed_at`
  on close, and logs; `add_case_note` logs; `case_findings`/`case_history` and
  `list_cases(client=..., state=...)` filter correctly.
- **CLI:** `case create` prints the new id; `case assign`/`state`/`note` validate
  a bad id → exit 1 + stderr; `case show` renders header + members + timeline;
  `case list` filters by client/state.
- **Report:** `report --client` includes a Cases section with the client's cases
  and finding counts (JSON `cases` array + Markdown section); a case for a
  different client is not included.
- **Migration:** a legacy `findings` (no `case_id`) gains it after `init_schema`;
  a legacy DB with no `cases`/`case_log` gains them; no raise.

## Out of scope (explicitly deferred)

- **Standalone `report --case <id>`** (a full Markdown/JSON single-case incident
  report) — a natural next spec; the data + renderers exist to build on.
- **Auto-grouping / suggested cases** — membership stays manual.
- **Multi-case membership** (a finding in >1 case) — one case per finding via the
  `case_id` column; a link table can come later if needed.
- **A `contained` state** — the three-state lifecycle is deliberate; add later if
  IR teams want the mitigated-but-not-closed distinction.
- **Validating case `client` against `clients.toml`** — free-text by design.
