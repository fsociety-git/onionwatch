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
    cp sources.toml.example sources.toml  # optional

- `seeds.txt` — one starting `.onion` URL per line; the crawler deep-discovers
  outward from these via link extraction.
- `verified_sources.toml` — known-good onions, PGP fingerprints and directory
  pages used by `cluster` to tell a legitimate site apart from a clone/phishing
  mirror and assign trust levels.
- `terms.txt` — client identifiers (email, domain, etc.) to hunt on verified
  sites; the watchlist file is optional and read every cycle if it exists.

### Seed sources (broader discovery)

`sources.toml` (optional; default absent = disabled) lists `.onion` directory
indexes and search sources that are automatically harvested each crawl cycle
through Tor, expanding the discovery frontier beyond manual seed URLs. Two source
types are supported:

- **Index sources** (`type = "index"`): the crawler fetches a directory page and
  mines every `.onion` link it contains, enqueueing each as a depth-0 seed.
- **Search sources** (`type = "search"`): the crawler queries a `.onion` search
  index (e.g., Ahmia's onion mirror) with a list of keywords, extracting and
  enqueueing `.onion` links from each results page.

Each harvested onion is tagged with its source name for tracking provenance. The
`max_seeds_per_source` config parameter (default: 200) caps seeds from each
source per cycle. Harvesting is **failure-isolated**: if a source is unreachable,
misconfigured, or returns invalid HTML, it is skipped and logged; one broken
source never aborts the harvest or crawl. Participation is **fully opt-in** —
with no `sources.toml` file, the crawler operates as before. **Note:** Tor-only
— clearnet (HTTP/HTTPS) sources are not supported; all harvesting happens
through the Tor client configured in `config.toml`.

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

**Matching modes:**

Terms support four rich matching modes — each is opt-in via a prefix:

- **Literal (bare term):** case-insensitive substring match. `acme-corp.com` matches "ACME-CORP.COM", "acme-corp.com", and substrings like "my.acme-corp.com.net".
- **Regex (`re:`):** compiled case-insensitively; use standard Python regex syntax. `re:acme-(corp|trading)` matches "acme-corp" or "acme-trading" in any case.
- **Fuzzy (`fuzzy:`):** matches the term plus defanged/obfuscated forms — including bracket/paren notation (`acme[.]com`, `acme(dot)com`), dot-word (`acme dot com`), and Cyrillic homoglyphs disguised as Latin letters. `fuzzy:acme.com` catches "acme[.]com", "acme(.)com", "acme dot com", etc.
- **Encoded (`enc:`):** matches base64, URL-encoded, and hex encodings of the term. `enc:ACME-API-KEY` finds "QUNNRS1BUEktS0VZ" (base64) and other variants in the text.
- **Credential (`cred:`):** finds the term as a username/email in credential pairs (e.g., `username:password` or `email|apikey`). The password/secret is captured and stored **masked** as `<identifier>:<bullet-chars>` (the secret is replaced with bullet characters, never stored in clear). `cred:billing@acme-corp.com` finds "billing@acme-corp.com:mysecret" and records it as `billing@acme-corp.com:••••••••`.

**PII detectors:**

In addition to watchlist terms, `hunt` can scan for Personally Identifiable Information (PII) — credit cards, bank account numbers (IBANs), and Social Security Numbers — when configured. Enable them in `config.toml`:

    pii_detectors = ["credit-card", "iban", "us-ssn"]

Available detectors (all opt-in, default: empty):

- **`credit-card`:** detects 13–19 digit card numbers (with optional spaces or hyphens); validates using Luhn algorithm.
- **`iban`:** detects IBAN (International Bank Account Number) format; validates using mod-97 checksum. Detects contiguous IBANs only (spaces between digit groups will not match).
- **`us-ssn`:** detects U.S. Social Security Numbers in format NNN-NN-NNNN; validates area, group, and serial rules.

All PII matches are stored **masked**: credit cards as `•••• •••• •••• XXXX` (last 4 digits), SSNs as `•••-••-XXXX` (last 4 digits), and IBANs as masked except the last 4 characters. PII is recorded as one finding per site and detector type (not per card/SSN/IBAN), with a match count showing how many instances were found on that site.

**Alert types:**

- **CRITICAL** (`leak`): A client identifier was found on a verified/probable trusted site,
  never seen there before. Severity: `critical`.
- **HIGH** (`dead_original`): A verified/probable trusted site (a clone-detection anchor)
  went dark / unreachable. Severity: `high`.
- **HIGH** (`anchor_identity`): A PGP-anchored verified/probable trusted site failed
  identity re-verification (fingerprint mismatch). Severity: `high`.

Findings have an open/resolved lifecycle. A leak finding resolves when the
identifier no longer appears on a URL the crawler can reach; a dead-original
resolves when the site becomes reachable again. **Important:** findings on sites
that the crawler cannot reach (coverage-gated) stay open rather than
false-resolving — they're unverified as resolved.

**Trust-anchor re-verification:**

Every cycle, the crawler re-probes each verified/probable canonical anchor for
fresh liveness — this is how the HIGH `dead_original` alert actually fires when
an anchor goes dark. For **PGP-anchored sites only** (those with a fingerprint
entry in `verified_sources.toml`), the crawler additionally performs identity
re-verification: it extracts the site's advertised PGP fingerprint from the page
and confirms it matches the operator's known-good key. A fingerprint mismatch
raises a HIGH `anchor_identity` alert.

**Safety cutout:** A dead or identity-failed anchor is never searched, so the
client watchlist is never sent to a compromised anchor. This prevents leaking
identifiers to an attacker who has hijacked a domain or impersonated a trusted
site.

**Re-anchor candidates:** Alerts for dead or identity-failed anchors include
suggested successor candidates — live sibling sites in the same cluster,
included as a note: "verify before trusting — candidate successors: [URL list]".
These candidates are **never auto-added** to the trust list; promotion to
verified/probable status requires manual operator review and editing of
`verified_sources.toml`.

**Identity checks are PGP-anchors-only:** Allow-listed onions in
`verified_sources.toml` (without a corresponding PGP fingerprint entry) skip
identity re-verification; only PGP-anchored sites are fingerprint-checked.

**Anchor pass runs every cycle:** The liveness and identity checks run on every
loop cycle, even if no watchlist file is loaded, ensuring continuous monitoring
of the trust anchors.

**Alert sinks:**

- **Local log:** alerts are appended to `alerts_path` (configured in
  `config.toml`, default: `data/alerts.jsonl`) as JSON Lines records. Each
  record includes the event (opened/resolved), severity, kind, URL, host, term,
  title, body, created_at, and a dedup key. Webhook delivery status
  (`delivered` / `delivery_error`) is not written to this file — it's recorded
  in the internal DB-backed alerts table, surfaced via `dwcollector alerts`.
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
(if applicable), host, timestamp, and the analyst disposition.

### Analyst triage & disposition

Findings flow through both a machine state (`open`/`resolved`, the status in
alerts logic) and an analyst disposition layer for human review and suppression.

**Disposition values:**

- **`new`** (default): finding just opened, awaiting triage.
- **`confirmed`**: analyst reviewed and confirmed this is a real exposure.
- **`false_positive`**: analyst reviewed and determined this is a false alarm
  (e.g. legitimate exposure, test data, or misidentification).
- **`dismissed`**: analyst reviewed but is deferring action (e.g. low priority,
  duplicate, already known).

Disposition is **analyst-owned**: only analysts set it (via the CLI commands
below), and reconcilers never touch it. Critically, **disposition is sticky
across the open/resolved lifecycle** — if you mark a finding `false_positive`
when it's open and then it resolves and reopens later, it remains
`false_positive` and stays suppressed.

**Suppression:**

Marking a finding `false_positive` or `dismissed` **suppresses all future
alerts** for that finding (webhook + JSONL sink), recorded as a suppressed alert
row in the database. Findings with disposition `new` or `confirmed` continue to
alert normally. **Important:** the **first alert always fires** (a fresh finding
is born `new` and not yet disposed); suppression only applies *after* you
disposition it.

**Triage queue:**

    dwcollector triage

Lists all open, un-triaged findings (those with `disposition = 'new'`), ordered
by severity (critical first), then by last-seen timestamp (most recently seen first). Use this to find
which findings need review.

**Disposition commands:**

Set disposition with an optional note and analyst actor:

    dwcollector disposition <finding_id> <value> [--note "..."] [--by "analyst@corp"]

Example:

    dwcollector disposition 42 false_positive --note "Test data from staging" --by "alice@corp"

Add a note to a finding without changing its disposition:

    dwcollector note <finding_id> --text "Contact vendor re: remediation" [--by "bob@corp"]

Review the full history of disposition changes and notes for a finding:

    dwcollector history <finding_id>

Outputs the timestamp, disposition (or note marker), actor, and comment for each
log entry, in chronological order.

### Per-client reports

`clients.toml` (optional; default absent = off) maps clients to watchlist terms.
Each client is a `[[client]]` section with a `name` and a list of `terms`:

    cp clients.toml.example clients.toml
    # edit clients.toml to add your clients and their watchlist terms

Client terms are added to the `loop` supervisor's hunt watchlist (deduped with
`terms.txt`), so they're hunted alongside the standard watchlist. Generate a
report for a specific client:

    dwcollector report --client "Acme Corp" [--format md|json] [--since DATE] [--all]

The command writes a Markdown or JSON report to stdout (redirect to a file as
needed). The report includes the client's **leak** findings (both open and
resolved) with evidence and disposition. By default, findings marked
`false_positive` or `dismissed` are excluded; pass `--all` to include them.
Use `--since DATE` to limit findings to those active since a specific date.

Evidence is a **bounded excerpt** around each match (never full leaked datasets). Credential and PII-detector matches are masked; plain term matches show surrounding page text. Markdown
reports are human-readable and can be converted to PDF or DOCX using standard
tools like Pandoc.

### Case management

Cases group related findings into a single incident for analysis and tracking.
A finding belongs to at most one case (via its `case_id`), assigned manually by
analysts. Cases have three states — `open`, `investigating`, `closed` — and
track an optional client reference (a free-text field, independent of the
`clients.toml` watchlist). The case timeline is append-only: all membership
changes (assign/unassign), state transitions, and analyst notes are logged with
timestamp and actor.

**Case membership and state are analyst-owned:** only analysts create cases,
assign findings, change states, and add notes. The detection and reconciliation
lifecycle (crawl/hunt/cluster) never touches `case_id` or case state — cases are
a purely analyst-driven review layer.

**Commands:**

Create a new case:

    dwcollector case create "<title>" [--client "Name"] [--by "analyst@corp"]

List cases with optional filtering:

    dwcollector case list [--client "Name"] [--state open|investigating|closed]

Show case details (header, member findings, timeline):

    dwcollector case show <case_id>

Assign a finding to a case:

    dwcollector case assign <finding_id> <case_id> [--by "analyst@corp"]

Remove a finding from a case:

    dwcollector case unassign <finding_id> [--by "analyst@corp"]

Change a case's state and optionally add a note:

    dwcollector case state <case_id> <open|investigating|closed> [--note "..."] [--by "analyst@corp"]

Add a note to a case without changing state:

    dwcollector case note <case_id> --text "..." [--by "analyst@corp"]

Cases appear as a **Cases** section in the per-client report:

    dwcollector report --client "Acme Corp" [--format md|json] [--since DATE] [--all]

The report includes a **Cases** section with a one-line summary per case for that client — case id, state, title, and the number of findings assigned to it.

### Single-case incident report

Produce a full incident dossier for one case:

    dwcollector report --case 42 [--format md|json]

The report contains the case metadata (title, client, state, opened/closed
timestamps, duration), a summary (finding counts by status, severity, kind, and
disposition, plus distinct sites), every member finding in full (host, matched
identifier, kind, severity, status, disposition, first/last seen, and the
bounded evidence snippet), and the complete case timeline (every event —
creation, assignments, state changes, and notes — with actor and timestamp).

`--case` and `--client` are mutually exclusive; exactly one is required.
`--all` and `--since` apply only to `--client` — a case report is already the
analyst's curated set, so it renders every member finding unconditionally
(remove a finding with `case unassign`, not a report flag).

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
