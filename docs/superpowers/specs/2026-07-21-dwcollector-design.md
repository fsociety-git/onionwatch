# dwcollector — Design

**Date:** 2026-07-21
**Status:** Approved, pending implementation plan

## Purpose

A self-contained Tor crawler that discovers `.onion` URLs from directory sites,
follows links to a bounded depth, checks whether each discovered site is alive,
categorises it via an editable keyword ruleset, and stores everything queryable
in SQLite. Scope is **discovery + liveness + categorisation only** — no full page
content is archived (a bounded text snippet is kept solely to enable offline
re-categorisation).

Intended use: threat-intelligence / security research URL collection.

## Stack

- **Python 3.12** in a local virtualenv (system Python is 3.9; a venv keeps the
  project on a modern runtime).
- **`httpx[socks]`** — async HTTP routed through the existing Tor SOCKS proxy at
  `127.0.0.1:9050`.
- **`selectolax`** — fast HTML parsing for link + text extraction.
- **`stem`** — optional Tor control-port checks (circuit health / NEWNYM). Not
  required for core operation.
- **stdlib `sqlite3`** — storage. No external DB.
- **stdlib `tomllib`** — read `config.toml` / `categories.toml`.

## Architecture — async worker pool

Chosen over Scrapy: lighter, no framework lock-in, and Tor throughput (not the
framework) is the bottleneck. Chosen over a synchronous crawler: Tor latency is
high and highly variable, so concurrency is essential for reasonable throughput.

```
seeds.txt + Ahmia API ─► frontier queue ─► N async workers ─► SQLite
                              ▲                   │
                              └── new .onion ─────┘   (BFS to max depth)
```

### Discovery loop (BFS)
1. Seed the frontier from `seeds.txt` (clearnet + `.onion`) and, if enabled, the
   Ahmia public listing.
2. Each worker dequeues a URL, fetches it through Tor.
3. Extract `.onion` links from the response (parser + regex over hrefs and raw
   text).
4. Dedupe candidates against the DB; enqueue unseen ones at `depth + 1`.
5. Continue until the frontier is empty or `max_depth` is reached.

### Liveness probe
For each newly discovered `.onion` **root**, record: `alive` (bool), `http_status`,
page `title`, and `response_ms`. During a full crawl this is a byproduct of the
fetch; the standalone `probe` command re-checks known URLs without discovery.

### Categorisation (keyword rules)
- `categories.toml` maps each category to a list of keyword/regex terms.
- Seed categories: `marketplace`, `forum`, `hosting`, `crypto`, `search`,
  `wiki/directory`, `blog`, and `unknown` (default when nothing matches).
- At fetch time, score the page's title + visible text against each category's
  terms. Highest score wins; ties broken by category order in the file.
- `category_confidence` = normalized match score (matched term weight / total).
- `matched_terms` stored for transparency and ruleset tuning.
- A bounded **`snippet`** (~500 chars of visible text) is stored per URL so the
  ruleset can be edited and re-applied offline via `dwcollector categorize`,
  without re-crawling.

### Politeness / resilience
- Per-host rate limit (`per_host_delay`), capped global concurrency.
- Request timeout, retry-with-exponential-backoff (Tor circuits fail often).
- Configurable User-Agent.
- No auth attempts, no form submission, no content download beyond the parsed
  page needed for link extraction and the bounded snippet.

## Data model — SQLite `dwcollector.db`

### `urls`
| column | type | notes |
| --- | --- | --- |
| `url` | TEXT PK | normalized |
| `host` | TEXT | `.onion` host |
| `source` | TEXT | `seed` / `ahmia` / `crawled` |
| `depth` | INT | BFS depth at discovery |
| `first_seen` | TEXT | ISO timestamp |
| `last_checked` | TEXT | ISO timestamp, nullable |
| `alive` | INT | 0/1, nullable until probed |
| `http_status` | INT | nullable |
| `title` | TEXT | nullable |
| `response_ms` | INT | nullable |
| `category` | TEXT | default `unknown` |
| `category_confidence` | REAL | 0.0–1.0 |
| `matched_terms` | TEXT | JSON array |
| `snippet` | TEXT | ≤500 chars, nullable |

### `crawl_runs`
| column | type |
| --- | --- |
| `run_id` | TEXT PK |
| `started_at` | TEXT |
| `finished_at` | TEXT |
| `seeds_count` | INT |
| `discovered` | INT |
| `alive_count` | INT |

## Config — `config.toml`

```toml
socks_proxy      = "socks5://127.0.0.1:9050"
max_depth        = 2
concurrency      = 5
per_host_delay   = 2.0     # seconds
request_timeout  = 60.0    # seconds
max_retries      = 3
user_agent       = "dwcollector/0.1"
ahmia_enabled    = true
snippet_chars    = 500
```

## CLI

```
dwcollector crawl                    # discovery + liveness + categorise -> DB
dwcollector probe                    # re-check liveness of known URLs only
dwcollector categorize               # re-apply categories.toml to stored snippets
dwcollector export --format csv|json [--category marketplace]
dwcollector stats                    # totals: all / alive / by source / by category
```

## Project layout

```
dwcollector/
├── src/dwcollector/
│   ├── __init__.py
│   ├── config.py        # load config.toml + categories.toml
│   ├── db.py            # schema, upserts, queries
│   ├── tor_client.py    # httpx client bound to Tor SOCKS; retry/backoff
│   ├── discover.py      # frontier, BFS worker pool, link extraction
│   ├── probe.py         # liveness checks
│   ├── categorize.py    # keyword-rule classifier
│   └── cli.py           # argparse entrypoint
├── tests/               # offline unit tests (mocked responses)
├── seeds.txt
├── config.toml
├── categories.toml
├── requirements.txt
├── README.md
└── .gitignore
```

## Testing

- **Unit tests (offline, default):** link extraction, `.onion` regex, dedup, DB
  upserts/queries, and the categoriser — all with mocked HTML/responses. No live
  Tor required.
- **Smoke test (opt-in):** a single marked test that fetches one known site
  through live Tor, skipped by default.

## Safety / scope

- URL-discovery + liveness + categorisation only. No page-content archiving
  beyond the bounded classification snippet.
- No authentication, no form submission, no credential handling.
- Polite by default (rate limits, backoff, timeouts).
- `.gitignore` excludes `dwcollector.db`, `seeds.txt`, the venv, and exports so
  collected data and seed sources are never committed.

## Defaults confirmed

`max_depth=2`, `concurrency=5`, Ahmia pull **on**, bounded snippet **stored**.
