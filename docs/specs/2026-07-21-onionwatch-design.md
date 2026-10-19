# onionwatch — Design

**Date:** 2026-07-21
**Status:** Approved (revised), pending implementation plan

## Purpose

A self-contained Tor crawler for **threat hunting**. It deep-crawls `.onion`
directory sites to discover URLs, verifies liveness via a containerised Tor,
categorises each site, and — critically — distinguishes **legit original sites
from clone/phishing mirrors** so the operator works from a curated, trustworthy
set. It can then **hunt for a client's data** across those legit sites to detect
leaks.

Intended, authorised use: a threat hunter checking whether a client's data has
been leaked to the dark web. Not for accessing, downloading, or redistributing
leaked datasets — only for detecting and reporting exposure.

## Stack

- **Python 3.12** in a local virtualenv (system Python is 3.9).
- **`httpx[socks]`** — async HTTP over a Tor SOCKS proxy.
- **`selectolax`** — fast HTML parsing (links + visible text).
- **`stem`** — Tor control-port checks and circuit rotation (`NEWNYM`).
- **simhash** (small local implementation or `simhash` lib) — content
  fingerprinting for clone detection.
- **stdlib `sqlite3`** — storage. **stdlib `tomllib`** — config.
- **Docker + Docker Compose** — reproducible Tor proxy (and optional crawler
  container).

## Deployment — Docker + Tor

The crawler is proxy-agnostic (points at whatever SOCKS proxy `config.toml`
names), but the recommended, reproducible setup is Docker Compose:

```
docker-compose.yml
├── service: tor          # Tor daemon, exposes SOCKS 9050 (+ control 9051)
│                         # torrc mounted from ./tor/torrc
├── service: onionwatch  # built from Dockerfile, runs the CLI
│                         # depends_on tor; mounts ./data for the DB
└── (optional) tor-2..N   # extra Tor instances for parallel circuits/throughput
```

- Liveness and crawling route through the `tor` container's SOCKS port.
- Multiple Tor instances (round-robined by the client) give more concurrent
  circuits for deep crawls and faster liveness sweeps.
- The existing host Tor on `127.0.0.1:9050` remains usable by setting
  `socks_proxy` accordingly — Docker is the default, not a hard requirement.

## Architecture — async worker pool, resumable

```
seeds.txt + Ahmia + verified lists ─► frontier (DB-backed) ─► N workers ─► SQLite
                                            ▲                     │
                                            └──── new .onion ─────┘
      crawl (deep BFS) → fingerprint → categorise → probe → cluster → hunt
```

### 1. Deep discovery (resumable BFS with safety caps)
- Seed from `seeds.txt`, the Ahmia listing, and verified mirror lists.
- **Depth is unbounded** (`max_depth = 0`), but every run is bounded by:
  `max_urls`, `time_budget_minutes`, and `per_host_page_cap`. Runs always
  terminate.
- The **frontier is persisted in SQLite** (`frontier` table with per-URL state),
  so a crawl is **resumable** — stop and restart, or crawl deeper over successive
  runs, without losing progress or re-fetching completed URLs.
- Each fetched page: extract `.onion` links (parser + regex), dedupe against DB,
  enqueue unseen at `depth + 1`.
- **Discovery is category-agnostic:** every `.onion` link is captured and
  followed regardless of site type. Categorisation only *labels* sites after the
  fact — it never filters what gets discovered. Marketplaces, forums, leak/paste
  sites, crypto, hosting, wikis, and blogs are all collected. Category filtering
  applies only at the export / leak-hunt stage, on demand.

### 2. Liveness probe
For each discovered `.onion` root: `alive`, `http_status`, `title`,
`response_ms`, `last_checked`. `onionwatch probe` re-checks known URLs without
discovery.

### 3. Categorisation (keyword rules)
- `categories.toml`: category → keyword/regex terms. Categories: `marketplace`,
  `forum`, `hosting`, `crypto`, `search`, `wiki/directory`, `paste`, `leak-site`,
  `blog`, `unknown`.
- Score title + visible text; highest score wins. Store `category`,
  `category_confidence`, `matched_terms`, and a bounded `snippet` (~500 chars)
  for offline re-categorisation.

### 4. Clone / original detection (verified anchor + clustering)
The core trust step. Combines an external source of truth with content
clustering:

1. **Content fingerprint:** compute a `content_simhash` over each page's
   normalized structure+text.
2. **Cluster:** group sites whose fingerprints are within
   `simhash_distance_threshold` (Hamming distance) into a `cluster_id` — these
   are near-duplicates (mirrors/clones of one site).
3. **Anchor to truth:** load verified addresses from `verified_sources.toml`
   (PGP-signed / dark.fail-style directories, Ahmia). Optionally match a site's
   published PGP key fingerprint.
4. **Pick canonical** per cluster, in priority order:
   verified-list match → valid matching PGP key → oldest `first_seen` → most
   inbound links.
5. **Label:** canonical gets `is_canonical = 1`; others get `clone_of =
   <canonical url>`. Each URL gets a `trust` level:
   `verified` / `probable` / `unknown` / `suspected_clone`.

`onionwatch cluster` runs/reruns this step over stored fingerprints (offline).
Leak hunting and default exports operate on **canonical + trusted** sites only,
filtering clones out — which is exactly the "only legit sites" requirement.

> Limitation, stated plainly: automated legit-vs-phishing is heuristic. The
> verified anchor makes it defensible, but `suspected_clone` / `unknown` items
> are surfaced for operator review rather than silently trusted.

### 5. Leak hunt
`onionwatch hunt --terms client.txt` scans **canonical legit sites** for client
identifiers (domains, emails, keywords; regex supported):
- Fetches page content of in-scope sites through Tor (content fetched
  transiently for matching).
- Records each hit in `leak_hits`: which site/url, matched term, and a short
  surrounding **context snippet** — **not** the full leaked data.
- Reports a summary (site, category, trust, matched terms, count).

### Politeness / resilience
Per-host rate limit, capped concurrency, request timeout, retry-with-backoff,
configurable User-Agent, Tor circuit rotation on repeated failures. No auth, no
form submission.

## Data model — SQLite `onionwatch.db`

### `urls`
| column | type | notes |
| --- | --- | --- |
| `url` | TEXT PK | normalized |
| `host` | TEXT | `.onion` host |
| `source` | TEXT | `seed` / `ahmia` / `verified` / `crawled` |
| `depth` | INT | BFS depth at discovery |
| `first_seen` / `last_checked` | TEXT | ISO timestamps |
| `alive` | INT | 0/1, nullable |
| `http_status` | INT | nullable |
| `title` | TEXT | nullable |
| `response_ms` | INT | nullable |
| `category` | TEXT | default `unknown` |
| `category_confidence` | REAL | 0.0–1.0 |
| `matched_terms` | TEXT | JSON array |
| `snippet` | TEXT | ≤500 chars |
| `content_simhash` | TEXT | 64-bit fingerprint |
| `cluster_id` | TEXT | nullable |
| `is_canonical` | INT | 0/1 |
| `clone_of` | TEXT | canonical url, nullable |
| `trust` | TEXT | verified / probable / unknown / suspected_clone |
| `pgp_fingerprint` | TEXT | nullable |
| `inbound_links` | INT | count of internal discoverers |

### `frontier` (resumable crawl)
`url` PK, `depth`, `state` (pending/in_progress/done/failed), `enqueued_at`,
`attempts`.

### `clusters`
`cluster_id` PK, `canonical_url`, `member_count`, `chosen_by`
(verified/pgp/first_seen/inbound).

### `crawl_runs`
`run_id` PK, `started_at`, `finished_at`, `seeds_count`, `discovered`,
`alive_count`, `stop_reason` (max_urls/time_budget/frontier_empty).

### `leak_hits`
`hit_id` PK, `run_id`, `url`, `host`, `category`, `trust`, `term`,
`context_snippet`, `matched_at`.

## Config

### `config.toml`
```toml
socks_proxy       = "socks5://tor:9050"   # docker; or 127.0.0.1:9050 on host
tor_control_port  = 9051
max_depth         = 0        # 0 = unlimited
max_urls          = 50000    # per-run safety cap
time_budget_min   = 120      # per-run wall-clock cap
per_host_page_cap = 500
concurrency       = 8
per_host_delay    = 2.0
request_timeout   = 60.0
max_retries       = 3
user_agent        = "onionwatch/0.1"
ahmia_enabled     = true
snippet_chars     = 500
simhash_distance  = 3        # max Hamming distance = same site
```

### `verified_sources.toml`
Operator-maintained list of trusted mirror directories / verified onion
addresses and (optional) expected PGP key fingerprints — the source of truth for
clone detection.

### `categories.toml`
Category → keyword/regex ruleset (see §3).

## CLI

```
onionwatch crawl [--resume]         # deep discovery + liveness + fingerprint + categorise
onionwatch probe                    # re-check liveness of known URLs
onionwatch categorize               # re-apply categories.toml to snippets
onionwatch cluster                  # (re)run clone/original detection
onionwatch hunt --terms client.txt  # search canonical legit sites for client data
onionwatch export --format csv|json [--trust verified --category leak-site]
onionwatch stats                    # totals: alive / by source / category / trust / clusters
```

## Project layout

```
onionwatch/
├── docker-compose.yml
├── Dockerfile
├── tor/torrc
├── src/onionwatch/
│   ├── __init__.py
│   ├── config.py        # load config.toml / categories.toml / verified_sources.toml
│   ├── db.py            # schema, upserts, queries, frontier
│   ├── tor_client.py    # httpx over SOCKS; retries; circuit rotation (stem)
│   ├── discover.py      # resumable BFS worker pool, link extraction
│   ├── probe.py         # liveness checks
│   ├── categorize.py    # keyword-rule classifier
│   ├── fingerprint.py   # simhash over normalized content
│   ├── cluster.py       # clustering + verified-anchor canonical selection
│   ├── verify.py        # ingest verified_sources, PGP fingerprint match
│   ├── hunt.py          # leak search over canonical sites
│   └── cli.py           # argparse entrypoint
├── tests/               # offline unit tests (mocked responses/HTML)
├── data/                # onionwatch.db (gitignored)
├── seeds.txt · config.toml · categories.toml · verified_sources.toml
├── requirements.txt · README.md · .gitignore
```

## Testing

- **Unit (offline, default):** link extraction, `.onion` regex, dedup, frontier
  state machine, DB ops, categoriser, simhash fingerprint + Hamming distance,
  clustering + canonical selection, leak-term matching — all mocked, no live Tor.
- **Smoke (opt-in):** one marked test fetching a known site through live Tor
  (docker), skipped by default.

## Safety / scope

- Threat-hunting tool for **authorised** leak detection on a client's own data.
- Clone detection anchors to verified sources; ambiguous items are surfaced for
  review, never silently trusted.
- Leak hunt stores only **matches + short context**, never full leaked datasets.
- No authentication, form submission, or credential handling. Polite by default.
- `.gitignore` excludes the DB, `seeds.txt`, `verified_sources.toml`, exports,
  and the venv, so collected data and sources are never committed.

## Defaults confirmed

Clone detection = **verified anchor + clustering** · depth = **deep with safety
caps, resumable** · scope = **collector + leak hunt** · Docker Tor = default
proxy · `concurrency=8`, `simhash_distance=3`, Ahmia **on**, snippet **stored**.
```
