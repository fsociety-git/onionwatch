# Design: Market-Listing Content Extraction

**Date:** 2026-07-24
**Status:** Approved — ready for implementation planning
**Scope:** Tier 2 discovery, final spec. On marketplace-category pages,
generically extract price-anchored listing records into a queryable `listings`
store, surfaced via a `listings` CLI command. Opt-in; no page bodies stored; no
per-market selectors. Uses the existing `selectolax` dependency; no new deps.
Hunt/finding integration is a deferred follow-on.

## Problem

The crawler categorizes pages (`marketplace`, `forum`, …) but treats a market's
content as opaque text — a bounded `snippet` and a simhash, nothing structured.
An analyst monitoring a client cannot ask "what is being sold on this cloned
market, and at what price?" without reading each page by hand.

This spec adds a **generic, market-agnostic extractor** that turns a
marketplace page's visible text into **price-anchored listing records** (a
price, its currency, the raw matched token, and a bounded window of surrounding
product text), stored in a new `listings` table and queryable from the CLI.

**Honest framing (stated up front):** robust per-market listing parsing is the
hardest problem in the roadmap — onion markets vary wildly in HTML, use
anti-scraping, price in crypto and fiat, often obfuscated, in many languages.
This feature deliberately does **not** attempt a clean structured catalog. It
produces a **best-effort lead signal**: where prices appear near product text,
capture a bounded record. It will catch some non-listing prices (an escrow fee,
a "$5 tip") and miss obfuscated/imaged prices. It is a lead surface an analyst
filters, not a source of truth.

## Design decisions (ratified during brainstorming)

- **Approach (A):** generic pattern-based extraction, market-agnostic, no
  per-site selector config. (Per-market selectors deferred.)
- **Detection unit (A):** price-anchored records with a bounded text window —
  each detected price becomes one listing carrying a `±window`-char slice of
  surrounding visible text as its product context.
- **When/where (A):** inline during the crawl, into a new `listings` table; no
  page bodies persisted (consistent with the bounded-evidence model).
- **Lifecycle (A):** replace-per-crawl snapshot — each successful crawl of a URL
  deletes that URL's prior listings and inserts the current extraction. No
  temporal dedup (the generic extractor has no stable listing identity).
- **Currencies (A):** crypto (BTC, XMR) + major fiat (USD, EUR, GBP); store
  parsed value + currency code + raw matched token; no FX conversion.
- **Surface (A):** standalone queryable store + a `listings` CLI command.
  Extraction does **not** create findings; hunt integration is the next spec.

## Architecture

### Pipeline / data flow

In `discover.crawl`, on an alive page (`res.ok and status < 400`) whose category
is a configured listing category, the already-computed `visible_text` is passed
to a pure `extract_listings(text, ...)` returning price-anchored records, which
are written via `db.replace_listings(url, host, records, now)` (delete this
URL's prior listings, insert the current snapshot). Extraction runs alongside
the existing categorize/snippet/fingerprint work; no HTML/body is persisted.
With the opt-in flag off, none of this runs and crawl behavior is byte-identical.

### 1. The extractor (`extract.py`, new — the core)

A pure, DB-free, HTML-free function operating on visible text (trivially
testable):

```python
def extract_listings(text: str, *, window: int, max_listings: int) -> list[dict]:
    # returns [{price_value, currency, price_raw, product_text}, ...]
```

- **Detect prices:** a currency-token regex over `text` matching crypto
  (`₿`, `BTC`, `XMR`, `Monero`) and major fiat (`$`/`USD`, `€`/`EUR`,
  `£`/`GBP`) in the common arrangements: amount-then-token (`0.05 BTC`,
  `50 USD`), token-then-amount (`BTC 0.05`, `USD 50`), and adjacent-symbol
  (`₿0.05`, `$50`, `€45`). A bare fiat **symbol** must be immediately adjacent
  to digits (reduces false positives from stray `$`/`£` in prose).
- **One record per price match**, in document order, capped at `max_listings`
  (a pathological page cannot emit thousands).
- **Bound the context:** capture `text[max(0, start-window) : end+window]`,
  whitespace-collapsed, as `product_text` — the evidence window, same idea as
  the existing `snippet`.
- **Parse the amount:** a helper `parse_price(raw) -> tuple[float | None, str]`
  returns `(value, currency_code)`. It normalizes the token to a canonical
  currency code (`₿`/`btc`→`BTC`, `monero`→`XMR`, `$`→`USD`, `€`→`EUR`,
  `£`→`GBP`, case-insensitive), strips the token, and best-effort parses the
  numeric part:
  - Digits with an optional single decimal point → `float`.
  - Thousands separators handled pragmatically: if both `,` and `.` appear, the
    last-occurring one is the decimal separator; if only `,` appears, it is
    treated as a thousands separator when it groups 3 trailing digits, else as a
    decimal point.
  - Anything it cannot resolve → `value = None`.
  - `parse_price` **never raises**.
- **The raw matched token is always stored** (`price_raw`), so nothing is lost
  even when `price_value` is `None`.

### 2. Schema + DB methods (`db.py`)

New table added to `SCHEMA` (created via `CREATE TABLE IF NOT EXISTS`,
idempotent, no ALTER needed since it is a brand-new table):

```sql
CREATE TABLE IF NOT EXISTS listings (
    listing_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT, host TEXT,
    price_value REAL, currency TEXT, price_raw TEXT,
    product_text TEXT, extracted_at TEXT
);
```

- `replace_listings(url, host, records, now) -> None` — `DELETE FROM listings
  WHERE url = ?`, then insert each record (`price_value`, `currency`,
  `price_raw`, `product_text`, `extracted_at = now`) in one committed
  transaction. An empty `records` list clears the URL's rows and inserts nothing.
- `list_listings(host=None, currency=None, min_price=None, max_price=None,
  contains=None) -> list[dict]` — dynamic WHERE: `host` exact; `currency` exact;
  `min_price`/`max_price` compare `price_value` (rows with `NULL` price_value are
  excluded when a price filter is set); `contains` is a `LIKE '%…%'` filter on
  `product_text`. Ordered `host, listing_id`.

### 3. Config + crawl integration (`config.py`, `discover.py`)

`Config` gains (defaults keep the feature off and inert):

```python
    extract_listings: bool = False            # opt-in master switch
    listing_categories: list = field(default_factory=lambda: ["marketplace"])
    listing_window: int = 120
    max_listings_per_page: int = 200
```

In `discover.crawl`'s alive branch, after `cat = categorize(...)` and its
`db.update_url(...)`:

```python
if config.extract_listings and cat.category in config.listing_categories:
    records = extract_listings(text, window=config.listing_window,
                               max_listings=config.max_listings_per_page)
    db.replace_listings(url, host or "", records, now)
```

`extract_listings` is imported from `.extract`. This sits inside the existing
per-URL `try/except` in `handle`, so a malformed page cannot abort the crawl.

### 4. CLI (`cli.py`)

```
onionwatch listings [--host H] [--currency C] [--min-price N] [--max-price N]
                     [--contains TEXT] [--format table|json]
```

`_run_listings(db, args)`: `rows = db.list_listings(host=args.host,
currency=args.currency, min_price=args.min_price, max_price=args.max_price,
contains=args.contains)`; print JSON (`json.dumps(rows, indent=2)`) when
`--format json`, else a plain table (host, `price_value` + currency or the raw
token, a truncated `product_text`) to stdout, like `export`/`stats`. `--currency`
is upper-cased before matching; `--min-price`/`--max-price` are `type=float`;
`--format` choices `table`/`json` (default `table`). Empty result → a valid empty
listing, exit 0.

## Error handling

- Opt-in off (default) → no extraction, no `listings` writes, unchanged crawl.
- Extraction runs inside `handle`'s existing per-URL `try/except`; a malformed
  page is isolated and marked `failed`, never aborting the crawl.
- A page with no detectable prices → `replace_listings(url, host, [], now)`
  clears any stale rows and inserts nothing (valid, not an error).
- `parse_price` never raises; ambiguous amounts store `price_value = NULL` and
  the raw token.
- `listings` is a new table via `IF NOT EXISTS` (idempotent); a legacy DB gains
  it on the next `init_schema` with no error.
- CLI price filters are `float`; a malformed `--min-price` fails at argparse
  (exit 2), consistent with other numeric flags.

## Testing (TDD, existing pytest style)

- **`extract_listings` / `parse_price`:** detects BTC/XMR/USD/EUR/GBP in
  amount-then-token, token-then-amount, and adjacent-symbol arrangements; bounds
  the `product_text` window; caps at `max_listings`; price-free text → `[]`; a
  bare `$` not adjacent to digits is not matched; `parse_price` returns
  value+currency, `NULL` on an unparseable amount, and always preserves
  `price_raw`; a European `1.234,56` and a `1,234.56` both parse sanely.
- **DB:** `replace_listings` inserts a snapshot; a second call for the same URL
  replaces (no accumulation); `list_listings` filters by host / currency /
  price-range / contains; a `NULL`-price row is excluded when a price filter is
  set and included otherwise.
- **`discover.crawl` integration:** a marketplace page with prices populates
  `listings`; `extract_listings=False` → no listings; a non-listing-category
  page → no listings even with the flag on; an extraction that raises does not
  abort the crawl.
- **CLI:** `listings --format json` emits valid JSON; each filter narrows the
  result; an empty result is valid output at exit 0.
- **Migration:** a legacy DB (no `listings` table) gains it after `init_schema`,
  no raise.

## Out of scope (explicitly deferred)

- **Hunt/finding integration** — a listing whose `product_text` matches a client
  watchlist term becoming a finding (new `market_listing` kind flowing into
  alert → triage → case → report). The natural next spec; the `listings` data
  will be there to build on.
- **Per-market selector rules** and **temporal price history** — both require a
  stable listing identity the generic extractor cannot provide.
- **FX / crypto rate conversion** — needs a live rate source (new dependency /
  staleness); prices are stored in their native currency only.
- **Per-client report rollup of listings** — CLI query surface only for v1.
- **Vendor-name extraction as a distinct field** — vendor text is captured only
  within `product_text`; a dedicated vendor field needs structure the generic
  extractor does not have.
