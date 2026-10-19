# Design: Broader Discovery — Seed-Source Harvesting

**Date:** 2026-07-23
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2, spec #1 (first "serious capability" spec). Tier 1 (specs #1–3) is complete and merged. Follow-on Tier 2 candidates: category-aware crawl prioritization; analyst workflow layer; content-extraction depth.

## Problem

Coverage is the thing a crawler lives or dies on, and discovery is where
onionwatch is thinnest. Today `crawl()` starts only from a static `seeds.txt`
and drains the frontier breadth-first, discovering whatever those seeds happen
to link to. It never pulls from external indexes, so sites that aren't already
linked from a seed are simply never found. `ahmia_enabled` exists in config but
is not wired into `crawl()`.

This spec broadens discovery by harvesting fresh seeds each cycle from
operator-configured `.onion` **seed sources** — directory/index pages and
category-targeted search queries against a search index (e.g. Ahmia's onion
mirror) — all fetched through the existing Tor client.

## Design decisions (ratified during brainstorming)

- **Entry-point ingestion first** (breadth), ahead of the separate
  category-aware-prioritization spec — ingestion finds *new* sites;
  prioritization only reallocates a fixed budget.
- **Tor-only `.onion` sources.** Ahmia runs an onion service and directories are
  `.onion`, so every source is reachable through the current Tor client. No
  clearnet fetch path, no ToS/legal gray areas. Clearnet sources are a possible
  later spec.
- **Two source types:** **index** (fetch a directory/index page, mine its onion
  links) and **search** (expand a URL template over category keywords, mine each
  results page). Search is the "smart" part — it targets high-value site types.
- **Harvest every cycle, per-source cap, opt-in.** Dedup is free
  (INSERT-OR-IGNORE), so re-harvesting is a no-op; a `max_seeds_per_source` cap
  stops one huge index flooding a cycle; sources default to **empty**, so there
  is zero behavior change and zero extra Tor load until configured.
- **Operator-configured source addresses** — no hardcoded `.onion`.

## Architecture

### 1. New module `sources.py`

```python
async def harvest(client, sources: list[dict], cap: int) -> list[tuple[str, str]]:
    """Fetch each configured source via the Tor client, extract onion links,
    and return (normalized_onion_url, source_name) pairs (deduped within the
    harvest). Never raises: a per-source/per-query fetch or parse failure is
    caught, logged to stderr, and skipped."""
```

Per source (`dict` with `name`, `type`, …):
- **index** (`url`): `res = await client.fetch(url)`; if OK, `extract_onion_links(res.html, url)`; keep up to `cap` entries.
- **search** (`url_template`, `queries: list[str]`): for each keyword, fetch
  `url_template.format(query=quote(keyword, safe=""))`, `extract_onion_links`,
  aggregate up to `cap` across the whole source (not per query).

`extract_onion_links` returns a `set`; sort each source's extracted onions
(e.g. `sorted(...)`) before applying `cap` so the capped selection is
deterministic (stable tests, reproducible harvests).

Each candidate is passed through `normalize_url` and kept only if
`onion_host(url)` is non-None. The `(url, name)` list is deduped by url within
the harvest (downstream INSERT-OR-IGNORE dedups against existing rows). A small
`config.per_host_delay` sleep between fetches for politeness (reuse the existing
knob). Fetch/extraction of one source is wrapped in `try/except Exception` so
one bad source never aborts the harvest.

Helpers reused (no new parsing surface): `extract_onion_links`, `normalize_url`,
`onion_host` (all in `discover.py`).

### 2. Config — `sources.toml` + loader

New operator file, same pattern as `categories.toml` / `verified_sources.toml`,
**default empty (opt-in)**:

```toml
[[source]]
name = "ahmia-index"
type = "index"
url  = "http://<ahmia-onion>/onions/"

[[source]]
name = "ahmia-search"
type = "search"
url_template = "http://<ahmia-onion>/search/?q={query}"
queries = ["market", "leak", "shop", "forum", "carding"]
```

`config.load_sources(path: str = "sources.toml") -> list[dict]`:
- Missing file → `[]` (no harvest).
- Each entry validated: `name` present; `type in {"index","search"}`; index
  needs `url`; search needs `url_template` (containing `{query}`) and a non-empty
  `queries` list. A malformed entry warns to stderr (matching the existing
  unknown-key warning idiom) and is skipped; valid entries are kept.

New `Config` field `max_seeds_per_source: int = 200`, documented in
`config.toml`.

### 3. Integration into `crawl()`

Signature gains `sources=None`:
`crawl(config, db, client, seeds, run_id, now, rules=None, sources=None)`.

At crawl start — after the existing `reset_state("deferred","pending")` /
`reset_state("in_progress","pending")` recovery and before the `seeds.txt`
seeding loop — harvest and enqueue:

```python
if sources:
    for url, name in await harvest(client, sources, config.max_seeds_per_source):
        db.upsert_url(url, onion_host(url) or "", name, 0, now)   # source-tagged provenance
        db.enqueue(url, 0)                                        # depth-0 seed
```

`sources=None`/empty → no harvest → **byte-identical current behavior**. Dedup
is automatic (both `upsert_url` and `enqueue` are INSERT-OR-IGNORE). Harvested
onions are depth-0 seeds tagged with their source name in `urls.source`
(distinct from `"seed"` for `seeds.txt` and `"crawled"` for link-discovered).

### 4. Loop wiring (`cli.py`)

- `run_cycle`: load `sources = load_sources("sources.toml")` and pass `sources`
  into the `crawl(...)` call (crawl reads `config.max_seeds_per_source`
  internally). The existing crawl stage's `try/except` isolation is preserved.
- `_run_crawl` (manual `crawl` command): same — load sources, pass them.
- Both leave `sources=[]` behavior identical to today.

Each cycle harvests fresh; because dedup makes re-harvest a no-op, a site that
appears in Ahmia next week is picked up on the next cycle.

## Error handling

- `harvest` never raises: each source/query fetch+parse is isolated; a
  down/slow/garbage source is logged and skipped, others still contribute.
- A source that yields more than `cap` onions is truncated to `cap` (logged).
- Malformed `sources.toml` entries are warned and skipped at load; a completely
  missing file is silently `[]`.
- Non-onion or unparseable links from a source page are filtered by
  `onion_host`.
- The crawl stage keeps its existing per-stage `try/except` in `run_cycle`, so
  even an unexpected harvest error can't crash the supervisor loop.

## Testing (TDD, existing pytest style)

- **harvest — index:** a stub client serving an index page with several onion
  links returns those (normalized, source-tagged), capped at `cap`;
  non-onion/junk links filtered.
- **harvest — search:** `url_template` is expanded over `queries` (assert each
  query URL is fetched), results aggregated and capped across the source.
- **harvest — failure isolation:** one source whose fetch fails (or returns
  non-OK) is skipped while a second source still yields its onions; `harvest`
  does not raise.
- **harvest — dedup:** the same onion appearing on two sources/queries appears
  once in the returned list.
- **config:** `load_sources` parses index+search entries; missing file → `[]`;
  an entry missing required keys (or a search entry with no `{query}`/empty
  `queries`) is warned and skipped; `max_seeds_per_source` default is 200.
- **crawl integration:** `crawl(..., sources=[...])` with a stub client enqueues
  the harvested onions as depth-0 `frontier` rows and `urls` rows tagged with
  the source name; `crawl(..., sources=None)` leaves seeding behavior unchanged.
- **end-to-end `run_cycle`:** with a configured index source and a stub client,
  the harvested seeds land in the frontier/urls and the cycle never raises.

## Out of scope (explicitly deferred)

- **Category-aware crawl prioritization** — the separate Tier 2 spec; this spec
  only *adds* seeds, it does not change frontier ordering (still depth-first).
- **Clearnet sources** (raw `ahmia.fi`, aggregators, Telegram/paste bridges) —
  would need a second fetch path; revisit only if onion sources prove
  insufficient.
- **Pagination / deep search-result crawling** — v1 harvests the first results
  page per query; deeper pagination is a later refinement.
- **Source health/quality scoring** (which sources yield the most live/relevant
  onions) — provenance is recorded now (`urls.source`); scoring can come later.
- **A separate harvest interval** — harvest rides the crawl cadence; add a timer
  only if Tor load warrants it.
