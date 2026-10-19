# Design: Category-Aware Crawl Prioritization

**Date:** 2026-07-24
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2, discovery. Makes the crawl frontier priority-ordered so
high-value targets are fetched first, by propagating a fetched page's category
weight to the child links it yields. Opt-in via config; absent config → the
current breadth-first crawl is byte-identical. No new dependencies.

## Problem

The crawl frontier is strictly breadth-first: `next_pending` orders by `depth
ASC`, so within a run every page at depth N is fetched before any page at depth
N+1, in discovery order. A `market` or leak-forum page discovered late waits
behind an arbitrary pile of unknown/low-value pages. Under a bounded run
(`max_urls`, `time_budget_min`), the high-value pages an analyst actually cares
about may never be reached before the budget runs out.

A page's own category is only known **after** it is fetched and categorized, so
a not-yet-fetched URL cannot be prioritized by its own category. But its
**parent** was just categorized when the link was discovered. This spec
propagates the parent page's category weight to its child links at enqueue time
and makes the frontier dequeue highest-priority-first.

## Design decisions (ratified during brainstorming)

- **Priority source (A):** parent's category → an operator-configured integer
  weight map. The category signal is already computed for free during the crawl.
  Confidence-weighting and anchor-text/URL heuristics are deferred.
- **Ordering (A):** `priority DESC, then depth ASC` — highest-value tier first,
  breadth-first within a tier. A clean superset of today: all-zero priorities
  reproduce the current order exactly.
- **Re-discovery (A):** keep-highest. Re-enqueuing a still-`pending` URL upgrades
  its priority to the max of the existing and new value (never lowers it, never
  touches an already-started row), so a URL linked from any high-value page gets
  that page's priority regardless of discovery order.
- **Fallback (A):** a single `default` weight (default 0) covers seeds and any
  child whose parent category is `unknown` or absent from the map. No config at
  all → everything 0 → unchanged BFS.

## Architecture

### Data flow

A page is fetched → `categorize()` computes its `category` (already happens).
Its child onion links are extracted and enqueued **with a priority derived from
the parent's category** via `priority_for`. `next_pending` dequeues by priority
first, so subsequent batches favor children of high-value pages. Priority is set
at enqueue (the only moment the parent's category is known) and frozen on the
row, upgraded only if a higher-value parent later links the same pending URL.

### 1. Schema + `enqueue` (`db.py`)

Add a `priority` column to `frontier`:

```sql
CREATE TABLE IF NOT EXISTS frontier (
    url TEXT PRIMARY KEY, depth INTEGER,
    state TEXT DEFAULT 'pending', enqueued_at TEXT, attempts INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0
);
```

Migration: add `priority` to the `SCHEMA` table (fresh DBs) **and** append
`ALTER TABLE frontier ADD COLUMN priority INTEGER DEFAULT 0` to the idempotent
`init_schema` ALTER loop (swallow `sqlite3.OperationalError`) — the same additive
pattern used for `findings.case_id`. A legacy `frontier`'s existing pending rows
default to priority 0.

`enqueue` gains a `priority` parameter and becomes a **keep-highest upsert**:

```python
def enqueue(self, url, depth, priority=0) -> None:
    self.conn.execute(
        "INSERT INTO frontier (url, depth, state, enqueued_at, priority) "
        "VALUES (?, ?, 'pending', datetime('now'), ?) "
        "ON CONFLICT(url) DO UPDATE SET priority = excluded.priority "
        "  WHERE frontier.state = 'pending' AND frontier.priority < excluded.priority",
        (url, depth, priority))
    self.conn.commit()
```

- New URL → inserted at the given priority.
- Already `pending` with a lower priority → upgraded.
- Already `pending` with an equal/higher priority, or already
  `in_progress`/`done`/`deferred`/`failed` → untouched.

The default `priority=0` keeps every existing caller behaviorally identical.
(SQLite's `ON CONFLICT ... DO UPDATE` upsert requires SQLite ≥ 3.24, 2018 —
well below any supported runtime.)

### 2. Ordering (`db.py`)

`next_pending` changes its ordering:

```python
"SELECT * FROM frontier WHERE state='pending' "
"ORDER BY priority DESC, depth ASC LIMIT ?"
```

Highest-priority tier first, breadth-first within a tier. With all priorities 0
(no config) the result order is identical to today's `depth ASC`.

### 3. Config + propagation (`config.py`, `discover.py`, `sources.py`)

`config.toml` gains an optional `[crawl_priority]` table mapping category name →
integer weight, plus an optional `default`:

```toml
[crawl_priority]
default = 0
market = 100
forum  = 80
paste  = 60
```

`Config` gains a field:

```python
crawl_priority: dict = field(default_factory=dict)
```

`load_config` already filters to known field names, so an absent `[crawl_priority]`
table → `{}` (all priorities resolve to 0). A small helper in `config.py`:

```python
def priority_for(category: str, weights: dict) -> int:
    return int(weights.get(category, weights.get("default", 0)))
```

In `discover.crawl`, after the parent page is categorized (`cat.category`), each
child link is enqueued with the parent's weight:

```python
child_priority = priority_for(cat.category, config.crawl_priority)
...
db.enqueue(link, depth + 1, child_priority)
```

Seeds have no parent category. Both the depth-0 seed enqueues in
`discover.crawl` (watchlist/terms seeds) and the source-harvested seed enqueues
in `sources.py` use the `default` weight, read directly as
`config.crawl_priority.get("default", 0)`. (This is the same value
`priority_for` returns for any unmapped category, so seeds and children of
`unknown` pages share one fallback.)

### 4. Error handling

- Missing `[crawl_priority]` → empty map → priority 0 everywhere → unchanged BFS.
- A category not in the map (including `unknown`) → `default` (0 unless set).
- Weights are operator-owned integers; `priority_for` coerces with `int(...)`. A
  malformed value (non-numeric) raises through the existing `load_config` path,
  consistent with how the rest of `config.toml` is handled today (no new
  swallowing). Negative weights are permitted (sort below the default).
- Migration is idempotent; a legacy `frontier` gains `priority` without error.
- `deferred`/`failed` rows retain their stored priority when a later run resets
  them to `pending`; the keep-highest upsert never lowers a row.
- Priority only affects not-yet-started URLs; an `in_progress` fetch is never
  reordered or interrupted.

## Testing (TDD, existing pytest style)

- **`enqueue`:** a new URL stores the given priority; re-enqueuing a `pending`
  URL with a higher priority upgrades it; with an equal/lower priority does not
  change it; an `in_progress`/`done` row is never modified by re-enqueue.
- **`next_pending`:** returns a higher-priority URL before a lower-priority one
  regardless of depth; ties broken by `depth ASC`; with all priorities 0 the
  order matches the pre-change `depth ASC` behavior (regression).
- **`priority_for`:** a mapped category returns its weight; an unmapped category
  and `unknown` return `default`; with no `default` key, returns 0.
- **`discover.crawl` integration:** a page categorized as a weighted category
  enqueues its children at that weight; a seed enqueues at `default`; with no
  `[crawl_priority]` table, crawl order and behavior are unchanged.
- **Migration:** a legacy `frontier` with no `priority` column gains it after
  `init_schema`, no raise; a pre-existing pending row reads back priority 0.

## Out of scope (explicitly deferred)

- **Depth/decay dampening** within a high-value subtree — `max_depth` and the
  per-host page cap already bound how deep a single site is crawled.
- **Anchor-text / URL-path heuristics** (brainstorm option 1C) — a later
  refinement if the category weight alone proves too coarse.
- **Confidence-weighted priority** (option 1B) — parent `category_confidence` is
  a noisy ratio; deferred.
- **Re-ordering `in_progress` work** — priority governs only not-yet-started
  URLs.
- **Starvation guards** — deprioritized URLs waiting across runs is the intended
  behavior (crawl high-value first); the persistent frontier keeps them for a
  later run.
