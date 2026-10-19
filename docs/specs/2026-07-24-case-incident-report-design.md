# Design: Standalone Single-Case Incident Report

**Date:** 2026-07-24
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2, analyst-workflow follow-on. Builds on case management
(merged) and the per-client report/client model (merged). Adds a
`report --case <id>` deliverable: a full incident dossier for one case.

## Problem

Case management can group findings into an incident, track its state, keep a
timeline, and surface a one-line-per-case rollup inside `report --client`. But
there is no way to produce a **standalone, full-detail report for a single
case** — the "hand it to the client / attach it to the ticket" artifact that
tells the whole story of one incident: what the case is, what was exposed, and
what the analyst did about it.

This spec adds `report --case <id>`: a Markdown or JSON incident dossier for one
case, reusing the case-management data layer and the `report.py` rendering
conventions. No schema changes; no new dependencies.

## Design decisions (ratified during brainstorming)

- **Content (A) — full incident dossier:** case metadata + a summary + every
  member finding in full detail + the complete timeline. The timeline is the
  part the per-client report cannot show and is core to an incident record.
- **Invocation (A) — `report --case <id>`:** add `--case` to the existing
  `report` command, mutually exclusive with `--client` (exactly one required).
  Reuses `--format`; keeps all report rendering in one handler.
- **Membership (A) — every member finding, unconditionally:** the report renders
  exactly what `case_findings(case_id)` returns — no kind filter, no disposition
  filter. A case is the analyst's explicit curation; `case unassign` is the
  removal lever, not a report-time flag. `--all`/`--since` do not apply to the
  case path.
- **Code organization (A) — dedicated case functions in `report.py`:**
  `build_case_report` + `render_case_markdown`/`render_case_json`, factoring the
  shared per-finding/evidence rendering into a helper both report types call.

## Architecture

### Data flow

`report --case 42` → `_run_report` takes the case branch → loads
`case = db.get_case(42)`, `findings = db.case_findings(42)`,
`history = db.case_history(42)` → `build_case_report(case, findings, history,
now)` builds a plain dict → `render_case_markdown` / `render_case_json`
serialize it → stdout (like `export` and the per-client report). All three DB
accessors already exist (`get_case`, `case_findings`, `case_history`); no schema
change.

### 1. Shared per-finding helper (`report.py`)

Factor the per-finding entry the per-client report already builds into a shared
helper so both reports render findings identically:

```python
def _finding_entry(f: dict) -> dict:
    return {"host": f["host"], "term": f["term"], "kind": f["kind"],
            "severity": f["severity"], "status": f["status"],
            "disposition": f.get("disposition") or "new",
            "first_seen": f["first_seen"], "last_seen": f["last_seen"],
            "evidence": f.get("context_snippet") or ""}
```

`build_report` (the per-client builder) is refactored to call `_finding_entry`
for each finding. Its output is unchanged **except for one additive key**,
`kind`: the client report is leak-only so `kind` was previously implicit, and a
case can hold any kind, so the shared entry carries it. Adding `kind` does not
remove or rename any existing key, so the change is purely additive and is
regression-guarded by a test.

Evidence masking is unchanged: `context_snippet` is the existing bounded excerpt;
`cred:`/PII-detector matches are already masked at match time, other matches show
the surrounding page text. No new evidence gathering.

### 2. `build_case_report(case, findings, history, now) -> dict`

```python
def build_case_report(case, findings, history, now) -> dict:
    return {
        "case": {
            "case_id": case["case_id"], "title": case["title"],
            "client": case["client"], "state": case["state"],
            "created_at": case["created_at"], "created_by": case["created_by"],
            "closed_at": case["closed_at"],
            "duration": _duration(case["created_at"], case["closed_at"], now),
        },
        "generated_at": now,
        "summary": {
            "total": len(findings),
            "open": sum(1 for f in findings if f["status"] == "open"),
            "resolved": sum(1 for f in findings if f["status"] == "resolved"),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "by_kind": _count_by(findings, "kind"),
            "by_disposition": _count_by(findings,
                                        lambda f: f.get("disposition") or "new"),
            "sites": len({f["host"] for f in findings}),
        },
        "findings": [_finding_entry(f) for f in findings],
        "timeline": [{"at": h["at"], "actor": h["actor"],
                      "event": h["event"], "note": h["note"]} for h in history],
    }
```

- `_duration(created_at, closed_at, now)`: if `closed_at` is set, the elapsed
  time from created→closed (rendered like `"3d 4h"` or a day count); else the
  elapsed time from created→now labeled open (e.g. `"open 5d"`). ISO-8601
  `"%Y-%m-%dT%H:%M:%S"` timestamps; a small local helper computes the delta.
  Malformed/empty timestamps degrade to `""` (never raises).
- `_count_by(findings, key)`: a small helper returning a `{value: count}` dict;
  `key` is a field name or a callable. Counts reflect the actual member mix
  (findings can be any kind, not just leak).
- `findings` and `timeline` preserve the order the DB accessors return
  (`case_findings` severity/last_seen ordered; `case_history` oldest-first).

### 3. Renderers (`report.py`)

```python
def render_case_json(report) -> str: ...      # json.dumps(report, indent=2)
def render_case_markdown(report) -> str: ...
```

`render_case_markdown` produces:

- A title: `# Incident Report: <title> (case #<id>)`.
- A metadata block: client, state, opened (created_at + created_by), closed
  (closed_at or "—"), duration.
- A summary line: total / open / resolved / critical / high / distinct sites,
  plus the by-kind and by-disposition breakdowns.
- A **Findings** section: one block per member finding via the shared entry
  (host, matched term, kind, severity, status, disposition, first/last seen, and
  the bounded evidence snippet).
- A **Timeline** section: one line per event, oldest-first —
  `<timestamp> — <actor>: <event>` (with the note appended when present).

### 4. CLI (`cli.py`)

`report` gains `--case <int>` in a **required, mutually-exclusive group** with
`--client` (argparse enforces exactly one):

```
onionwatch report (--client "Acme Corp" | --case 42) [--format md|json] [--since DATE] [--all]
```

`--format md|json` applies to both paths. `--all` and `--since` apply only to
the `--client` path (a case is already curated); the help text says so and the
case branch ignores them.

`_run_report(cfg, db, args)` branches on which id was supplied:

- `args.case` set → `case = db.get_case(args.case)`; if `None` → stderr
  `"no case #<id>"` + `return 1`. Else load `case_findings`/`case_history`, build
  and render, print to stdout, `return 0`.
- `args.client` set → the existing per-client path, unchanged.

### 5. Error handling

- Unknown/absent `--case` id → clear stderr message + non-zero exit; no
  traceback, no partial output.
- Neither `--client` nor `--case` → argparse error (group is required); both →
  argparse error (mutually exclusive). Standard argparse exit code 2.
- A valid case with zero findings → a valid dossier with zero counts and the
  `created` timeline event only; exit 0 (not an error).
- `_duration` degrades to `""` on malformed/missing timestamps; never raises.
- Evidence masking unchanged; this feature only renders existing findings, so no
  raw PII/secret is introduced.

## Testing (TDD, existing pytest style)

- **`_finding_entry` / `build_report` regression:** the per-client report's
  finding entries are unchanged after the refactor (same keys/values, plus the
  additive `kind`); an existing client-report test still passes.
- **`build_case_report`:** case metadata carried through; `_duration` renders an
  open case (created→now) and a closed case (created→closed); summary counts
  (total/open/resolved/critical/high/sites) correct; `by_kind`/`by_disposition`
  reflect a mixed-kind, mixed-disposition member set; findings carry masked
  evidence; timeline is complete and oldest-first.
- **Renderers:** `render_case_json` round-trips the dict; `render_case_markdown`
  contains the case title, `case #<id>`, each member's host + term, and each
  timeline event.
- **Curated/unfiltered:** a member finding dispositioned `false_positive` still
  appears in the case report (no disposition filtering on the case path).
- **CLI:** `report --case N --format json` emits valid JSON; `--format md` emits
  Markdown; an unknown `--case` id → exit 1 + stderr; `--client` + `--case`
  together → argparse error (exit 2); neither → argparse error (exit 2); an
  empty case → a valid report with zero counts, exit 0.

## Out of scope (explicitly deferred)

- **HTML/PDF rendering** — needs a new dependency; Markdown → PDF via an external
  tool covers it.
- **`--out FILE`** — reports go to stdout (redirect), matching `export` and the
  per-client report.
- **Auto-generated remediation recommendations** — the report records the
  incident; advising on it is a human/analyst judgment, not generated copy.
- **Cross-case / portfolio rollups** — a multi-case or client-portfolio incident
  summary is a later spec; this is one case per report.
- **Redacting/filtering members in the report** — membership is curated via
  `case assign`/`case unassign`; the report mirrors the case exactly.
