# dwcollector

A Tor-based threat-hunting crawler: deep-discovers `.onion` sites across all
categories, checks liveness through a containerised Tor, categorises them,
distinguishes legit originals from clone/phishing mirrors, and hunts a client's
identifiers across the curated legit sites.

**Authorised use only** — for detecting whether a client's data has leaked to the
dark web. It does not download or store full leaked datasets, only matches +
short context.

## Setup

    python3.12 -m venv .venv
    .venv/bin/pip install -r requirements.txt && .venv/bin/pip install -e .

Before running, copy the example config files and edit them (all are
gitignored — they hold your own seed list, trust anchors, and watchlist):

    cp seeds.txt.example seeds.txt
    cp verified_sources.toml.example verified_sources.toml
    cp terms.txt.example terms.txt

- `seeds.txt` — one starting `.onion` URL per line; the crawler deep-discovers
  outward from these via link extraction.
- `verified_sources.toml` — known-good onions, PGP fingerprints and directory
  pages used by `cluster` to tell a legitimate site apart from a clone/phishing
  mirror and assign trust levels.
- `terms.txt` — client identifiers (email, domain, etc.) to hunt on verified
  sites; the watchlist file is optional and read every cycle if it exists.

## Run with Docker (recommended)

    docker compose up -d tor
    docker compose run --rm dwcollector crawl
    docker compose run --rm dwcollector cluster
    docker compose run --rm dwcollector hunt --terms client.txt

### 24/7 operation

`docker compose up -d` (no `run --rm`, no command override) starts the
`dwcollector` service with its default command, `loop --interval 1800`: a
supervisor that repeats crawl (resuming the existing frontier) + cluster every
30 minutes, forever, logging each cycle's result instead of dying on a bad
cycle. Combined with `restart: unless-stopped`, this gives a self-healing
continuous crawler on a dedicated VM — it comes back up after a crash, OOM, or
host reboot and picks up the frontier where it left off. Run it standalone
(without Docker) via `dwcollector loop`.

### Continuous monitoring and alerts

When a `watchlist_terms` file exists (configured in `config.toml`, default:
`terms.txt`), every `loop` cycle also hunts for client identifiers across the
verified/probable trusted sites and reconciles findings into alerts.

**Watchlist format:** one identifier per line; lines starting with `#` are
ignored. Identifiers default to case-insensitive literal substring match; prefix
with `re:` for regex patterns. Example:

    acme-corp.com
    billing@acme-corp.com
    re:ACME-[A-Z]+-DB

**Alert types:**

- **CRITICAL** (`new-leak`): A client identifier was found on a verified original site,
  never seen there before. Severity: `critical`.
- **HIGH** (`dead-original`): A verified original site that previously carried a client
  identifier went dark / unreachable. Severity: `high`.

Findings have an open/resolved lifecycle. A leak finding resolves when the
identifier no longer appears on a URL the crawler can reach; a dead-original
resolves when the site becomes reachable again. **Important:** findings on sites
that the crawler cannot reach (coverage-gated) stay open rather than
false-resolving — they're unverified as resolved.

**Alert sinks:**

- **Local log:** alerts are appended to `alerts_path` (configured in
  `config.toml`, default: `data/alerts.jsonl`) as JSON Lines records. Each
  record includes the event (opened/resolved), severity, kind, URL, host, term,
  title, body, and a webhook delivery status.
- **Webhook:** if `alert_webhook` is configured (a URL), each alert is
  posted as JSON. Webhook failures do not block the crawler — they are logged
  and the cycle continues.
- **stderr:** all alerts are also logged to stderr as `[alert] <SEVERITY>
  <event> <title>` for immediate visibility.

**Querying alerts:**

    dwcollector alerts --status open          # open findings only
    dwcollector alerts --status resolved      # resolved findings only
    dwcollector alerts --status all           # both

Each row shows the finding's status, severity, kind (leak/dead_original), term
(if applicable), host, and timestamp.

## Run on host (uses your Tor on 127.0.0.1:9050)

Set `socks_proxy = "socks5://127.0.0.1:9050"` in `config.toml`, then:

    dwcollector crawl            # deep discovery + liveness + categorise + fingerprint
    dwcollector cluster          # original-vs-clone detection, trust levels
    dwcollector hunt --terms client.txt
    dwcollector export --format csv --trust verified --category leak-site
    dwcollector stats

Crawls are resumable: re-run `dwcollector crawl --resume` to continue the frontier.
A crawler process killed mid-run (OOM, `docker restart`, host reboot) also
recovers automatically — any URL left stuck `in_progress` by the dead process
is reset to `pending` and retried on the next `crawl`.

## Pipeline

crawl → (fingerprint + categorise inline) → cluster → hunt

## Trust model & hunt scope

`cluster` assigns trust only from an **anchor**, never from a site merely being
un-clustered:

- `verified` — the onion is in your `verified_sources.toml` `verified_onions`.
- `probable` — the canonical row carries a PGP fingerprint (extracted from the
  page during `crawl`) that matches the host's key in `verified_sources.toml`.
- `unknown` — a lone site, or a cluster head with no anchor. **Not** auto-trusted.
- `suspected_clone` — a non-canonical member of a clone cluster.

`hunt` scans only the anchored legit sites (`verified` / `probable`). A phishing
clone whose real original was never crawled therefore can't be mistaken for a
trusted site just because it stands alone. **You MUST populate
`verified_sources.toml` for `hunt` to have any scope** — with no anchors, nothing
is trusted and `hunt` has nothing to scan.

`unknown` / `suspected_clone` sites are surfaced for operator review rather than
auto-trusted — inspect them with, e.g.:

    dwcollector export --trust unknown
    dwcollector export --trust suspected_clone

## Concurrency & single-writer safety

The database opens in WAL mode with a busy timeout, but the design still assumes
a **single writer**. Do **not** run one-off writing commands
(`crawl` / `cluster` / `hunt`) while the `loop` service is running: a second
crawl's `in_progress` reset can hijack the loop's in-flight frontier rows. Stop
the service first (`docker compose stop dwcollector`), or run only read-only
commands (`stats`, `export`) alongside the loop.

## Known limitations / follow-ups

Documented, not yet implemented:

- **Clustering cost.** `cluster_rows` is O(n²) and re-runs over all URLs every
  loop cycle; at tens of thousands of rows a cycle's clustering can exceed the
  interval. Future: simhash banding / incremental clustering.
- **No re-probe.** The `loop` never re-checks liveness or re-fingerprints sites
  it already knows (discovered once = frozen). Future: periodic re-probe of
  stale rows within the cycle.
- **Crash recovery assumes one crawler.** The `in_progress` → `pending` reset is
  safe only for a single crawler process; make it age-based before allowing
  concurrent crawlers.
- **`inbound_links` is never populated**, so the last-resort canonical
  tiebreaker is currently inert.

## Tuning clone detection

`cluster` groups URLs whose `content_simhash` values are within
`simhash_distance` bits of each other (Hamming distance over a 64-bit simhash).
The default, `simhash_distance = 3` in `config.toml`, only merges
identical-or-near-identical pages — the common case for a straight mirror or
phishing clone of a marketplace/forum.

Raising it catches more near-duplicates — useful for short or thin pages,
where small amounts of boilerplate text can push an otherwise-identical page's
simhash further apart — but it also raises the risk of over-merging distinct
sites that just happen to share a lot of generic template text (e.g. two
unrelated forums built on the same software). Tune this against your own
crawl data: start at the default, inspect a cluster's members with
`dwcollector export`, and raise it only if genuine mirrors are being missed.

## Tests

    .venv/bin/pytest            # offline unit tests
    .venv/bin/pytest -m live    # opt-in live-Tor smoke tests
