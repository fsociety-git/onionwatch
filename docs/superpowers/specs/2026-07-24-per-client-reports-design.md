# Design: Per-Client Reports (with minimal client association)

**Date:** 2026-07-24
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2, analyst-workflow spec #2. Builds on disposition & triage
(merged). Bundles a minimal client model (its first consumer is this report).
Follow-on analyst-workflow spec: case management.

## Problem

dwcollector can now detect, alert, triage, and disposition findings — but there
is no way to produce a **client-facing report** of a given client's exposures.
The watchlist is a flat `terms.txt`; a finding records the matched `term` but
nothing ties a term to a client (`acme-corp.com`, `billing@acme-corp.com`, and
`ACME-CUSTOMER-DB` are three unrelated strings, not "Acme's identifiers"). So
"a client's findings" is undefined.

This spec adds a minimal **client model** (`clients.toml` mapping clients to
watchlist terms) and a **report generator** that produces a Markdown or JSON
report of one client's leak findings, with evidence and disposition, excluding
analyst-dismissed noise.

## Design decisions (ratified during brainstorming)

- **Client model augments the watchlist (option A):** `clients.toml` is optional
  and additive. The hunt watchlist becomes `terms.txt` ∪ all client terms
  (deduped), so client terms actually get hunted. Absent `clients.toml` → no
  clients, reports unavailable, zero behavior change.
- **Derive client membership at report time** (no schema change): a finding
  belongs to a client if its `term` is one of the client's terms. `clients.toml`
  is the single source of truth.
- **Report scope (option A):** a client report is the client's **leak** findings
  (`kind='leak'`), **excluding** `false_positive`/`dismissed` (a `--all` flag
  includes them), across both `open` and `resolved` (labeled). Generic PII
  detector findings and infrastructure findings (`dead_original`,
  `anchor_identity`) are excluded — they aren't tied to a client identifier.
- **Formats (option A):** Markdown (default) + JSON. No HTML/PDF (would need a
  new dependency); write to stdout like `export`.
- **Time filter (option A):** optional `--since <date>` (`last_seen >= date`).

## Architecture

### 1. Client config (`config.py`)

`load_clients(path="clients.toml") -> list[dict]` — parses `[[client]]` entries;
each needs `name` (non-empty) and a non-empty `terms` list; malformed entries
warn to stderr and are skipped; missing file → `[]` (mirrors `load_sources`).

```toml
[[client]]
name = "Acme Corp"
terms = ["acme-corp.com", "billing@acme-corp.com", "fuzzy:ACME-CUSTOMER-DB"]
```

### 2. Term-key mapping (`matching.py`)

Client terms may carry match prefixes (`fuzzy:ACME-CUSTOMER-DB`), but a finding
records the *underlying key* (`ACME-CUSTOMER-DB`). Add a shared helper so report
selection matches findings correctly:

```python
def underlying_key(term: str) -> str:
    # mirrors how match_term derives Match.key: fuzzy:/enc:/cred: are stripped
    # to the identifier; re: and literal terms are kept verbatim (a re: finding's
    # key is the full 're:PATTERN').
    for p in ("fuzzy:", "enc:", "cred:"):
        if term.startswith(p):
            return term[len(p):]
    return term
```

### 3. Watchlist union (`cli.py` — `run_cycle` only)

The continuous loop's standing watchlist becomes `terms.txt` plus every client's
terms, deduped order-preserving, so client terms are hunted every cycle:

```python
clients = load_clients("clients.toml")
base = load_terms(cfg.watchlist_terms) if os.path.exists(cfg.watchlist_terms) else []
terms = list(dict.fromkeys(base + [t for c in clients for t in c["terms"]]))
```

The union applies **only in `run_cycle`** (the production loop). The ad-hoc
`hunt --terms FILE` command (`_run_hunt`) is left unchanged — it hunts exactly
the file the operator named, without silently adding client terms. When
`clients.toml` is absent, `clients = []`, so `terms` is unchanged from today.

### 4. Report generation (new `report.py`)

```python
def client_findings(db, client: dict, include_all: bool, since: str | None) -> list[dict]:
    keys = {underlying_key(t) for t in client["terms"]}
    rows = [f for f in db.list_findings()
            if f["kind"] == "leak" and f["term"] in keys]
    if not include_all:
        rows = [f for f in rows if f.get("disposition") not in ("false_positive", "dismissed")]
    if since:
        rows = [f for f in rows if (f.get("last_seen") or "") >= since]
    # stable two-pass sort: last_seen DESC first, then (status, severity) — the
    # stable sort preserves most-recent-first within each status/severity group.
    rows.sort(key=lambda f: f.get("last_seen") or "", reverse=True)
    rows.sort(key=lambda f: (0 if f["status"] == "open" else 1,
                             0 if f["severity"] == "critical" else 1))
    return rows

def build_report(client_name, findings, now, since) -> dict:
    summary = {
        "total": len(findings),
        "open": sum(1 for f in findings if f["status"] == "open"),
        "resolved": sum(1 for f in findings if f["status"] == "resolved"),
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "sites": len({f["host"] for f in findings}),
    }
    return {"client": client_name, "generated_at": now, "since": since,
            "summary": summary,
            "findings": [{ "host": f["host"], "term": f["term"], "severity": f["severity"],
                           "status": f["status"], "disposition": f.get("disposition") or "new",
                           "first_seen": f["first_seen"], "last_seen": f["last_seen"],
                           "evidence": f.get("context_snippet") or "" } for f in findings]}

def render_json(report) -> str: ...      # json.dumps(report, indent=2)
def render_markdown(report) -> str: ...  # header + summary table + per-finding sections
```

(`_neg` gives descending `last_seen` sort within Python's ascending `sort`; a
small local helper, e.g. sort on a tuple with a reverse key — implementation
detail for the plan.)

`render_markdown` produces a client-facing document: a title with the client
name and generated timestamp (and the `since` window if set), a summary line
(total / open / resolved / by-severity / distinct sites), then one section per
finding with site, matched identifier, first/last seen, status, disposition, and
the masked evidence snippet.

### 5. CLI (`cli.py`)

```
dwcollector report --client "Acme Corp" [--format md|json] [--since DATE] [--all]
```

`_run_report(cfg, db, args)`: `clients = load_clients("clients.toml")`; find the
client whose `name == args.client` (case-sensitive); if none → stderr message +
`return 1`. Else `findings = client_findings(db, client, args.all, args.since)`,
`report = build_report(args.client, findings, _now(), args.since)`, print
`render_markdown`/`render_json` to stdout. `--format` choices `md`/`json`
(default `md`); `--all` store_true; `--since` optional string.

## Error handling

- Missing/malformed `clients.toml`: `load_clients` → `[]` / warn+skip (never
  raises); with no clients, `report` for any name → "unknown client" + exit 1.
- Unknown `--client` → clear stderr message + non-zero exit; no crash.
- A client with zero matching findings → a valid (empty) report with zero counts,
  exit 0 (not an error).
- `--since` is compared as an ISO-8601 string (lexicographic == chronological for
  the app's `"%Y-%m-%dT%H:%M:%S"` format); a malformed `--since` simply filters
  by string comparison (documented; no date parsing/validation in v1).
- Reports contain only already-masked/bounded `context_snippet` evidence — no raw
  leaked data (consistent with the evidence-only guarantee).

## Testing (TDD, existing pytest style)

- **load_clients:** parses client entries; missing file → `[]`; an entry missing
  `name` or `terms` warns and is skipped.
- **underlying_key:** strips `fuzzy:`/`enc:`/`cred:` to the identifier; leaves
  `re:`-prefixed and literal terms unchanged.
- **client_findings:** selects `kind='leak'` findings whose `term` is in the
  client's resolved key set (including a `fuzzy:`-prefixed client term mapping to
  its stripped finding); excludes `false_positive`/`dismissed` by default and
  includes them with `include_all=True`; `--since` keeps only `last_seen >=`
  window; a PII/dead_original/anchor_identity finding is never selected; ordering
  is open-before-resolved, critical-before-high, most-recent.
- **build_report:** summary counts (total/open/resolved/critical/high/distinct
  sites) are correct; finding entries carry the masked evidence.
- **render_json/render_markdown:** JSON round-trips the report dict; Markdown
  contains the client name, the summary numbers, and each finding's host + term.
- **watchlist union:** `run_cycle` (or the union helper) hunts `terms.txt` terms
  **and** client terms (a client-only term produces a leak hit); dedup holds.
- **CLI:** `report --client Acme --format json` emits valid JSON; `--format md`
  emits Markdown; an unknown `--client` returns exit 1 with a stderr message;
  `--all` includes a dismissed finding that the default omits.

## Out of scope (explicitly deferred)

- **Case management** (grouping findings into per-client/incident cases) — the
  next analyst-workflow spec.
- **HTML/PDF rendering** — needs a new dependency; Markdown → PDF via an external
  tool covers it for now.
- **Persisted client tags on findings** — membership is derived at report time;
  persistence (for historical attribution when a client's terms change) can come
  later if needed.
- **Client-scoped PII findings** — a generic `pii:` finding isn't tied to a
  client identifier; associating PII to a client (e.g. PII found on the same page
  as the client's term) is a later refinement.
- **`--out FILE`** — reports go to stdout (redirect), matching `export`.
- **A `clients` listing command** — operators author `clients.toml`; add later if
  wanted.
