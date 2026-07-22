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

Before running, copy the two example config files and edit them (both are
gitignored — they hold your own seed list and trust anchors, not sample data):

    cp seeds.txt.example seeds.txt
    cp verified_sources.toml.example verified_sources.toml

- `seeds.txt` — one starting `.onion` URL per line; the crawler deep-discovers
  outward from these via link extraction.
- `verified_sources.toml` — known-good onions, PGP fingerprints and directory
  pages used by `cluster` to tell a legitimate site apart from a clone/phishing
  mirror and assign trust levels.

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
