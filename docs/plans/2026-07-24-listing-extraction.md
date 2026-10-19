# Market-Listing Content Extraction Implementation Plan


**Goal:** On marketplace-category pages, generically extract price-anchored listing records into a queryable `listings` store, surfaced via a `listings` CLI command. Opt-in; no page bodies stored.

**Architecture:** A pure `extract.py` scans visible text for price/currency tokens and returns bounded price-anchored records. `discover.crawl` calls it inline on listing-category pages and writes a replace-per-crawl snapshot via `db.replace_listings`. A `listings` CLI command queries `db.list_listings`. No new dependencies.

**Tech Stack:** Python 3.11+, sqlite3, `re` (stdlib), pytest/pytest-asyncio. Stdlib only (`selectolax` already present but not needed here — extraction works on the already-computed `visible_text`).

## Global Constraints

- Python 3.11+; **no new dependencies** (stdlib only).
- **Opt-in / additive:** with `extract_listings = False` (the default), no extraction runs, nothing is written to `listings`, and crawl behavior is byte-identical to today. Headline invariant.
- **No page bodies stored:** extraction consumes the already-computed `visible_text`; only bounded `product_text` windows are persisted (bounded-evidence model).
- **Replace-per-crawl:** each successful crawl of a URL deletes that URL's prior listings and inserts the current snapshot — no accumulation, no temporal dedup.
- **Best-effort, failure-isolated:** extraction runs inside the crawl's existing per-URL `try/except`; a malformed page must never abort the crawl. `parse`/extract code never raises on bad input.
- Currencies: crypto BTC, XMR (incl. `₿`, "Monero") + fiat USD `$`, EUR `€`, GBP `£`. No FX conversion; native currency only. Always store the raw matched token.
- `listings` is a brand-new table via `CREATE TABLE IF NOT EXISTS` in `SCHEMA` (idempotent; no ALTER needed).
- Follow existing test style: `Database(str(tmp_path / "t.db"))`, `db.init_schema()`, pytest, `@pytest.mark.asyncio` + `FakeClient` for crawl tests, `Config(...)` kwargs, `build_parser().parse_args([...])`, `capsys`.
- Run the suite with `.venv/bin/python -m pytest` (pytest is not on PATH). Baseline before this plan: **229 passed, 1 deselected**.

---

## File Structure

- `src/onionwatch/extract.py` (create) — pure extractor: `extract_listings` + `_parse_amount` + currency tables/patterns.
- `src/onionwatch/db.py` (modify) — `listings` table in `SCHEMA`; `replace_listings`, `list_listings`.
- `src/onionwatch/config.py` (modify) — 4 `Config` fields.
- `src/onionwatch/discover.py` (modify) — import + one extraction call in the alive branch.
- `src/onionwatch/cli.py` (modify) — `listings` subparser, `_run_listings`, dispatch branch.
- `tests/test_extract.py` (create), `tests/test_db.py`, `tests/test_discover.py`, `tests/test_cli.py` (modify) — tests.
- `README.md` (modify) — document `listings` + `[extract_listings]` config.

---

### Task 1: The extractor (`extract.py`)

**Files:**
- Create: `src/onionwatch/extract.py`
- Test: `tests/test_extract.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `extract_listings(text: str, *, window: int, max_listings: int) -> list[dict]` returning records `{price_value: float|None, currency: str, price_raw: str, product_text: str}`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_extract.py`:

```python
from onionwatch.extract import extract_listings


def test_detects_each_currency_and_arrangement():
    text = ("cocaine 0.05 BTC in stock | ledger dump XMR 1.5 | "
            "cvv pack $50 fresh | db €45.00 leaked | fullz 30 GBP")
    recs = extract_listings(text, window=20, max_listings=100)
    pairs = {(r["currency"], r["price_value"]) for r in recs}
    assert ("BTC", 0.05) in pairs
    assert ("XMR", 1.5) in pairs
    assert ("USD", 50.0) in pairs
    assert ("EUR", 45.0) in pairs
    assert ("GBP", 30.0) in pairs


def test_symbol_currency_normalization():
    recs = extract_listings("price ₿0.1 and £20 today", window=10, max_listings=10)
    got = {(r["currency"], r["price_value"]) for r in recs}
    assert ("BTC", 0.1) in got
    assert ("GBP", 20.0) in got


def test_bounds_product_text_window():
    text = "A" * 200 + " item 0.05 BTC " + "B" * 200
    recs = extract_listings(text, window=15, max_listings=10)
    assert len(recs) == 1
    pt = recs[0]["product_text"]
    assert "item" in pt and "0.05 BTC" in pt
    # window-bounded: nowhere near the full 400+ char text
    assert len(pt) <= 15 + len("0.05 BTC") + 15 + 5


def test_caps_at_max_listings():
    text = " ".join(f"{i} USD" for i in range(1, 20))
    recs = extract_listings(text, window=5, max_listings=3)
    assert len(recs) == 3


def test_no_prices_returns_empty():
    assert extract_listings("just some ordinary prose, no prices here", window=20, max_listings=10) == []
    assert extract_listings("", window=20, max_listings=10) == []


def test_bare_symbol_not_adjacent_is_ignored():
    # "$" not immediately followed by digits must not match; a real "$5" must
    recs = extract_listings("pay in $ currency, actual price $5 each", window=10, max_listings=10)
    assert [(r["currency"], r["price_value"]) for r in recs] == [("USD", 5.0)]


def test_price_raw_preserved_and_value_none_when_unparseable():
    recs = extract_listings("weird $1.2.3 tag", window=10, max_listings=10)
    assert len(recs) == 1
    assert recs[0]["currency"] == "USD"
    assert recs[0]["price_value"] is None       # unparseable amount
    assert recs[0]["price_raw"] == "$1.2.3"     # raw token always kept


def test_thousands_and_decimal_separators():
    # US-style 1,234.56 and EU-style 1.234,56 both -> 1234.56
    us = extract_listings("bulk $1,234.56 lot", window=5, max_listings=5)
    eu = extract_listings("bulk €1.234,56 lot", window=5, max_listings=5)
    assert us[0]["price_value"] == 1234.56
    assert eu[0]["price_value"] == 1234.56
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_extract.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.extract'`.

- [ ] **Step 3: Implement `extract.py`**

Create `src/onionwatch/extract.py`:

```python
from __future__ import annotations
import re

# canonical currency codes
_CUR_CODE = {"btc": "BTC", "xmr": "XMR", "monero": "XMR",
             "usd": "USD", "eur": "EUR", "gbp": "GBP"}
_CUR_SYM = {"₿": "BTC", "$": "USD", "€": "EUR", "£": "GBP"}

_NUM = r"\d[\d.,]*\d|\d"
_CODE = r"btc|xmr|monero|usd|eur|gbp"
_SYM = r"[₿$€£]"

# (compiled pattern, kind). Symbol patterns require the symbol IMMEDIATELY
# adjacent to the number (no space) to avoid matching a bare "$" in prose;
# code patterns allow an optional space ("0.05 BTC" / "BTC0.05").
_PATTERNS = [
    (re.compile(rf"(?P<sym>{_SYM})(?P<amt>{_NUM})"), "sym"),
    (re.compile(rf"(?P<amt>{_NUM})(?P<sym>{_SYM})"), "sym"),
    (re.compile(rf"\b(?P<code>{_CODE})\s?(?P<amt>{_NUM})", re.I), "code"),
    (re.compile(rf"(?P<amt>{_NUM})\s?(?P<code>{_CODE})\b", re.I), "code"),
]


def _parse_amount(s: str) -> float | None:
    s = s.strip()
    has_comma, has_dot = "," in s, "." in s
    try:
        if has_comma and has_dot:
            # the last-occurring separator is the decimal point
            if s.rfind(",") > s.rfind("."):
                s = s.replace(".", "").replace(",", ".")
            else:
                s = s.replace(",", "")
        elif has_comma:
            # comma-only: thousands if every group is <=3 digits and the last is
            # exactly 3; otherwise treat the comma as a decimal point
            frac = s.rsplit(",", 1)[-1]
            if len(frac) == 3 and all(len(p) <= 3 for p in s.split(",")):
                s = s.replace(",", "")
            else:
                s = s.replace(",", ".")
        return float(s)
    except ValueError:
        return None


def extract_listings(text: str, *, window: int, max_listings: int) -> list[dict]:
    if not text:
        return []
    hits = []  # (start, end, currency, raw, amt)
    for pat, kind in _PATTERNS:
        for m in pat.finditer(text):
            if kind == "sym":
                currency = _CUR_SYM[m.group("sym")]
            else:
                currency = _CUR_CODE[m.group("code").lower()]
            hits.append((m.start(), m.end(), currency, m.group(0), m.group("amt")))
    hits.sort(key=lambda h: h[0])
    records: list[dict] = []
    last_end = -1
    for start, end, currency, raw, amt in hits:
        if start < last_end:
            continue  # overlaps an already-accepted price token
        last_end = end
        ctx = text[max(0, start - window): end + window]
        records.append({
            "price_value": _parse_amount(amt),
            "currency": currency,
            "price_raw": raw.strip(),
            "product_text": " ".join(ctx.split()),
        })
        if len(records) >= max_listings:
            break
    return records
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_extract.py -v`
Expected: PASS (all 8 tests).

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/extract.py tests/test_extract.py
git commit -m "feat: generic price-anchored listing extractor"
```

---

### Task 2: `listings` table + DB methods

**Files:**
- Modify: `src/onionwatch/db.py` (`SCHEMA` — add table before the closing `"""` ~line 92; add methods near the other query methods)
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `replace_listings(url, host, records, now) -> None`; `list_listings(host=None, currency=None, min_price=None, max_price=None, contains=None) -> list[dict]`. `records` are dicts with keys `price_value, currency, price_raw, product_text`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_db.py`:

```python
def _rec(price_value, currency, raw, text):
    return {"price_value": price_value, "currency": currency,
            "price_raw": raw, "product_text": text}


def test_replace_listings_inserts_and_replaces(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    url = "http://m.onion/p"
    db.replace_listings(url, "m.onion", [
        _rec(0.05, "BTC", "0.05 BTC", "cocaine 0.05 BTC"),
        _rec(50.0, "USD", "$50", "cvv $50"),
    ], "2026-07-24T00:00:00")
    assert len(db.list_listings(host="m.onion")) == 2
    # second crawl replaces (no accumulation)
    db.replace_listings(url, "m.onion", [
        _rec(1.5, "XMR", "1.5 XMR", "ledger 1.5 XMR"),
    ], "2026-07-24T01:00:00")
    rows = db.list_listings(host="m.onion")
    assert len(rows) == 1 and rows[0]["currency"] == "XMR"


def test_replace_listings_empty_clears(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    url = "http://m.onion/p"
    db.replace_listings(url, "m.onion", [_rec(50.0, "USD", "$50", "x")], "t0")
    db.replace_listings(url, "m.onion", [], "t1")     # no prices this crawl
    assert db.list_listings(host="m.onion") == []


def test_list_listings_filters(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://a.onion/1", "a.onion", [
        _rec(0.05, "BTC", "0.05 BTC", "cocaine grams"),
        _rec(50.0, "USD", "$50", "cvv pack"),
        _rec(None, "USD", "$1.2.3", "weird tag"),
    ], "t0")
    db.replace_listings("http://b.onion/1", "b.onion", [
        _rec(200.0, "USD", "$200", "passport scan"),
    ], "t0")
    assert {r["host"] for r in db.list_listings(host="a.onion")} == {"a.onion"}
    assert all(r["currency"] == "USD" for r in db.list_listings(currency="USD"))
    # price range excludes NULL-price rows
    usd_cheap = db.list_listings(currency="USD", min_price=10, max_price=100)
    assert [r["price_raw"] for r in usd_cheap] == ["$50"]
    assert [r["product_text"] for r in db.list_listings(contains="passport")] == ["passport scan"]


def test_listings_migration_on_legacy_db(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.init_schema()   # idempotent second run must not raise
    assert db.list_listings() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_db.py -k "listings" -v`
Expected: FAIL — `sqlite3.OperationalError: no such table: listings` / `AttributeError: 'Database' object has no attribute 'replace_listings'`.

- [ ] **Step 3: Add the table and methods**

In `src/onionwatch/db.py`, add to `SCHEMA` immediately before the closing `"""` (after the `case_log` table, ~line 92):

```sql
CREATE TABLE IF NOT EXISTS listings (
    listing_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT, host TEXT,
    price_value REAL, currency TEXT, price_raw TEXT,
    product_text TEXT, extracted_at TEXT
);
```

Add these methods to the `Database` class (near the other query/mutation methods):

```python
    def replace_listings(self, url, host, records, now) -> None:
        self.conn.execute("DELETE FROM listings WHERE url = ?", (url,))
        self.conn.executemany(
            "INSERT INTO listings "
            "(url, host, price_value, currency, price_raw, product_text, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(url, host, r.get("price_value"), r.get("currency"), r.get("price_raw"),
              r.get("product_text"), now) for r in records])
        self.conn.commit()

    def list_listings(self, host=None, currency=None, min_price=None,
                      max_price=None, contains=None) -> list[dict]:
        q, conds, params = "SELECT * FROM listings", [], []
        if host:
            conds.append("host = ?"); params.append(host)
        if currency:
            conds.append("currency = ?"); params.append(currency)
        if min_price is not None:
            conds.append("price_value IS NOT NULL AND price_value >= ?"); params.append(min_price)
        if max_price is not None:
            conds.append("price_value IS NOT NULL AND price_value <= ?"); params.append(max_price)
        if contains:
            conds.append("product_text LIKE ?"); params.append(f"%{contains}%")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        return [dict(r) for r in self.conn.execute(q + " ORDER BY host, listing_id", params)]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_db.py -v`
Expected: PASS (the four new tests plus all pre-existing db tests).

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: listings table + replace_listings/list_listings"
```

---

### Task 3: Config fields + `discover.crawl` integration

**Files:**
- Modify: `src/onionwatch/config.py` (`Config` dataclass, after `crawl_priority` ~line 27)
- Modify: `src/onionwatch/discover.py` (import; alive branch after the category `db.update_url(...)` ~line 152)
- Test: `tests/test_discover.py`

**Interfaces:**
- Consumes: `extract_listings` (Task 1); `replace_listings` (Task 2); `Config` (this task).
- Produces: extraction wired into `crawl` for listing-category pages when `extract_listings` is on.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_discover.py` (reuses the module's `FakeClient`, `Config`, `Database`, `crawl`, `@pytest.mark.asyncio`):

```python
@pytest.mark.asyncio
async def test_crawl_extracts_listings_on_marketplace(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    pages = {A: "<html><body>market vendor escrow cocaine 0.05 BTC cvv $50</body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=5, concurrency=1, per_host_delay=0,
                 extract_listings=True, listing_categories=["marketplace"])
    rules = {"marketplace": ["market", "vendor", "escrow"]}
    await crawl(cfg, db, FakeClient(pages), [A], "run_ext", "2026-07-24T00:00:00",
                rules=rules)
    rows = db.list_listings(host="aaaaaaaaaaaaaaaa.onion")
    currencies = {r["currency"] for r in rows}
    assert "BTC" in currencies and "USD" in currencies


@pytest.mark.asyncio
async def test_crawl_no_extraction_when_flag_off(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    pages = {A: "<html><body>market vendor cocaine 0.05 BTC</body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=5, concurrency=1, per_host_delay=0)   # extract_listings defaults False
    rules = {"marketplace": ["market", "vendor"]}
    await crawl(cfg, db, FakeClient(pages), [A], "run_off", "2026-07-24T00:00:00",
                rules=rules)
    assert db.list_listings() == []


@pytest.mark.asyncio
async def test_crawl_no_extraction_on_non_listing_category(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    pages = {A: "<html><body>forum board discussion price 0.05 BTC</body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=5, concurrency=1, per_host_delay=0,
                 extract_listings=True, listing_categories=["marketplace"])
    rules = {"forum": ["forum", "board"]}   # page categorizes as forum, not marketplace
    await crawl(cfg, db, FakeClient(pages), [A], "run_forum", "2026-07-24T00:00:00",
                rules=rules)
    assert db.list_listings() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_discover.py -k "extract or listing or non_listing" -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'extract_listings'` (Config field missing).

- [ ] **Step 3: Add config fields and wire extraction**

In `src/onionwatch/config.py`, add to the `Config` dataclass after `crawl_priority` (~line 27):

```python
    extract_listings: bool = False
    listing_categories: list[str] = field(default_factory=lambda: ["marketplace"])
    listing_window: int = 120
    max_listings_per_page: int = 200
```

In `src/onionwatch/discover.py`, add the import near the other package imports (the module already imports `from .config import priority_for`; extend or add):

```python
from .extract import extract_listings
```

In the alive branch, immediately after the `db.update_url(...)` call that stores the category (right before or after the `child_priority = ...` line, ~line 153), add:

```python
                if config.extract_listings and cat.category in config.listing_categories:
                    db.replace_listings(
                        url, host or "",
                        extract_listings(text, window=config.listing_window,
                                         max_listings=config.max_listings_per_page),
                        now)
```

(This sits inside `handle`'s existing `try/except`, so a raising extraction cannot abort the crawl.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_discover.py -v`
Expected: PASS (the three new tests plus all pre-existing discover tests).

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — all green (baseline 229 + new tests so far).

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/config.py src/onionwatch/discover.py tests/test_discover.py
git commit -m "feat: wire listing extraction into crawl (opt-in, listing categories)"
```

---

### Task 4: `listings` CLI command

**Files:**
- Modify: `src/onionwatch/cli.py` (subparser near `export` ~line 48-53; `_run_listings` handler near `_run_export` ~line 163; dispatch branch after `case` ~line 491)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `list_listings` (Task 2).
- Produces: `onionwatch listings [...]` → `_run_listings(db, args)`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py`:

```python
def test_listings_command_json_and_filters(tmp_path, capsys):
    import json as _json
    from onionwatch.cli import build_parser, _run_listings
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://a.onion/1", "a.onion", [
        {"price_value": 0.05, "currency": "BTC", "price_raw": "0.05 BTC", "product_text": "cocaine grams"},
        {"price_value": 50.0, "currency": "USD", "price_raw": "$50", "product_text": "cvv pack"},
    ], "2026-07-24T00:00:00")

    # JSON, all
    _run_listings(db, build_parser().parse_args(["listings", "--format", "json"]))
    doc = _json.loads(capsys.readouterr().out)
    assert len(doc) == 2

    # currency filter is upper-cased
    _run_listings(db, build_parser().parse_args(["listings", "--currency", "usd", "--format", "json"]))
    doc = _json.loads(capsys.readouterr().out)
    assert len(doc) == 1 and doc[0]["currency"] == "USD"

    # contains filter
    _run_listings(db, build_parser().parse_args(["listings", "--contains", "cocaine", "--format", "json"]))
    doc = _json.loads(capsys.readouterr().out)
    assert len(doc) == 1 and doc[0]["product_text"] == "cocaine grams"


def test_listings_command_empty_ok(tmp_path, capsys):
    from onionwatch.cli import build_parser, _run_listings
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    # table format, no rows -> valid output, no crash
    _run_listings(db, build_parser().parse_args(["listings"]))
    out = capsys.readouterr().out
    assert "total: 0" in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k "listings" -v`
Expected: FAIL — `ImportError: cannot import name '_run_listings'` / argparse error on the unknown `listings` command.

- [ ] **Step 3: Add subparser, handler, and dispatch**

In `src/onionwatch/cli.py`, add a subparser near the `export` one (after the `stats` parser, ~line 53):

```python
    lp = sub.add_parser("listings")
    lp.add_argument("--host", default=None)
    lp.add_argument("--currency", default=None)
    lp.add_argument("--min-price", type=float, default=None)
    lp.add_argument("--max-price", type=float, default=None)
    lp.add_argument("--contains", default=None)
    lp.add_argument("--format", choices=["table", "json"], default="table")
```

Add the handler near `_run_export` (~line 163):

```python
def _run_listings(db, args):
    currency = args.currency.upper() if args.currency else None
    rows = db.list_listings(host=args.host, currency=currency,
                            min_price=args.min_price, max_price=args.max_price,
                            contains=args.contains)
    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2)
        print()
    else:
        for r in rows:
            price = (f"{r['price_value']} {r['currency']}"
                     if r["price_value"] is not None else r["price_raw"])
            text = (r["product_text"] or "")[:80]
            print(f"{r['host']}  {price}  {text}")
        print(f"total: {len(rows)}")
```

Add the dispatch branch after the `case` branch (~line 491-492), before `return 0`:

```python
    elif args.command == "listings":
        _run_listings(db, args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_cli.py -v`
Expected: PASS (the two new tests plus all pre-existing cli tests).

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — all green.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/cli.py tests/test_cli.py
git commit -m "feat: listings CLI query command"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the shipped behavior (Tasks 1-4). No code.

- [ ] **Step 1: Document listing extraction**

Add a new top-level `## Market-listing extraction (optional)` section to `README.md`, placed near the other optional-crawl-feature sections (e.g. after `## Crawl prioritization (optional)`). Match the file's heading style and tone. Use exactly this content:

```markdown
## Market-listing extraction (optional)

On marketplace pages, onionwatch can extract price-anchored **listing records**
— a best-effort signal of what is being sold and at what price. It is off by
default. Enable it in `config.toml`:

    extract_listings   = true
    listing_categories = ["marketplace"]   # which categories trigger extraction
    listing_window     = 120               # chars of context captured per listing
    max_listings_per_page = 200

When a page whose category is in `listing_categories` is crawled, its visible
text is scanned for prices in crypto (BTC, XMR) and major fiat (USD `$`, EUR
`€`, GBP `£`). Each price becomes a record: the parsed amount, the currency, the
raw matched token, and a bounded window of surrounding product text. Records are
stored per URL as a **replace-per-crawl snapshot** (each crawl overwrites that
page's listings with the current extraction — no history). No page bodies are
stored, only the bounded context windows.

Query them:

    onionwatch listings [--host H] [--currency BTC] \
                         [--min-price N] [--max-price N] \
                         [--contains TEXT] [--format table|json]

This is a **best-effort lead signal, not a clean catalog**: it will catch some
non-listing prices (an escrow fee, a tip) and miss obfuscated or image-based
prices. Prices are stored in their native currency — there is no FX conversion.
With `extract_listings` off (the default), nothing is extracted and crawl
behavior is unchanged.
```

- [ ] **Step 2: Verify docs-only (no code touched)**

Run: `.venv/bin/python -m pytest -q`
Expected: PASS — unchanged suite (docs edit only).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document market-listing extraction + listings command"
```

---

## Notes for the executor

- Opt-in-off is the headline invariant: `extract_listings` defaults `False`; with it off, no extraction runs and the crawl is byte-identical. `test_crawl_no_extraction_when_flag_off` guards it.
- Extraction consumes the already-computed `visible_text` (the `text` local in `handle`) — do NOT store or re-parse HTML.
- The extraction call sits inside `handle`'s existing `try/except`; keep it there so a raising page cannot abort the crawl.
- `_parse_amount` must never raise — return `None` for anything it can't resolve, and the record keeps `price_raw` regardless.
- Symbol currency patterns require the symbol immediately adjacent to the digits (`$50`, not `$ 50`); code patterns allow one optional space. This is deliberate (false-positive control) and covered by `test_bare_symbol_not_adjacent_is_ignored`.
- `list_listings` price filters must exclude `NULL`-price rows; `--currency` is upper-cased in the CLI before matching.
