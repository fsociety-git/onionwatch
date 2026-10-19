# onionwatch Implementation Plan


**Goal:** Build a Tor-based threat-hunting crawler that deep-discovers `.onion` sites across all categories, checks liveness through a containerised Tor, categorises them, distinguishes legit originals from clone/phishing mirrors, and hunts a client's identifiers across the curated legit sites.

**Architecture:** An async worker pool crawls a SQLite-backed, resumable frontier over the Tor SOCKS proxy. Each page is parsed for `.onion` links (category-agnostic discovery), fingerprinted with simhash, and categorised by an editable keyword ruleset. A clustering pass groups near-duplicate sites and anchors the canonical "original" to a verified/PGP source list, flagging the rest as clones. A leak-hunt command searches canonical legit sites for operator-supplied terms.

**Tech Stack:** Python 3.12 (venv), `httpx[socks]`, `selectolax`, `stem`, stdlib `sqlite3` + `tomllib`, Docker Compose (Tor), `pytest`.

## Global Constraints

- Python 3.12 in a local `.venv` (system Python is 3.9 — do not use it).
- All network I/O routes through the Tor SOCKS proxy named in `config.toml` (`socks5://tor:9050` under Docker, `socks5://127.0.0.1:9050` on host).
- Discovery is **category-agnostic**: never filter which `.onion` links get enqueued. Categories only label; filtering happens only at export/hunt.
- Default unit tests run **fully offline** with mocked HTTP/HTML — no live Tor. Live-Tor tests are marked `@pytest.mark.live` and skipped by default.
- Never commit collected data or sources: `data/`, `*.db`, `seeds.txt`, `verified_sources.toml`, exports are gitignored (already in `.gitignore`).
- TDD throughout: failing test → minimal code → passing test → commit. Small, frequent commits.
- Store only leak **matches + short context**, never full leaked datasets.

---

## File Structure

```
onionwatch/
├── docker-compose.yml          # Task 12: tor + onionwatch services
├── Dockerfile                  # Task 12
├── tor/torrc                   # Task 12
├── requirements.txt            # Task 1
├── config.toml                 # Task 1 (defaults)
├── categories.toml             # Task 7
├── verified_sources.toml       # Task 9 (example; real one gitignored)
├── seeds.txt                   # Task 5 (example; real one gitignored)
├── README.md                   # Task 13
├── src/onionwatch/
│   ├── __init__.py             # Task 1
│   ├── config.py               # Task 1  load_config / load_categories / load_verified
│   ├── db.py                   # Task 2  Database: schema, urls, frontier, runs, hits
│   ├── tor_client.py           # Task 3  TorClient: httpx SOCKS + retry/backoff
│   ├── discover.py             # Task 4-5 extract_onion_links / normalize / crawl
│   ├── probe.py                # Task 6  probe_url
│   ├── categorize.py           # Task 7  categorize
│   ├── fingerprint.py          # Task 8  simhash / hamming
│   ├── verify.py               # Task 9  is_verified / pgp match
│   ├── cluster.py              # Task 10 cluster_urls / choose_canonical
│   ├── hunt.py                 # Task 11 match_terms / hunt
│   └── cli.py                  # Task 12 argparse subcommands
└── tests/                      # one test module per source module
```

---

### Task 1: Project scaffold, config loader

**Files:**
- Create: `requirements.txt`, `config.toml`, `src/onionwatch/__init__.py`, `src/onionwatch/config.py`, `tests/test_config.py`, `pytest.ini`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Config` dataclass with fields `socks_proxy:str, tor_control_port:int, max_depth:int, max_urls:int, time_budget_min:int, per_host_page_cap:int, concurrency:int, per_host_delay:float, request_timeout:float, max_retries:int, user_agent:str, ahmia_enabled:bool, snippet_chars:int, simhash_distance:int`. Functions `load_config(path:str="config.toml")->Config`, `load_categories(path:str="categories.toml")->dict[str,list[str]]`, `load_verified_sources(path:str="verified_sources.toml")->dict`.

- [ ] **Step 1: Create venv and install deps**

```bash
cd onionwatch
/usr/bin/python3 -m venv .venv || python3.12 -m venv .venv
# If system python is 3.9, install 3.12 first: brew install python@3.12 && python3.12 -m venv .venv
.venv/bin/python --version    # must print Python 3.12.x
```

Create `requirements.txt`:

```
httpx[socks]==0.27.2
selectolax==0.3.21
stem==1.8.2
pytest==8.3.3
pytest-asyncio==0.24.0
```

```bash
.venv/bin/pip install -r requirements.txt
```

- [ ] **Step 2: Create `pytest.ini`**

```ini
[pytest]
asyncio_mode = auto
markers =
    live: tests that hit the live Tor network (skipped by default)
testpaths = tests
pythonpath = src
```

- [ ] **Step 3: Write the failing test** — `tests/test_config.py`

```python
from onionwatch.config import load_config, load_categories

def test_load_config_defaults(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        'socks_proxy = "socks5://127.0.0.1:9050"\n'
        "max_depth = 0\n"
        "concurrency = 8\n"
        "simhash_distance = 3\n"
    )
    cfg = load_config(str(cfg_file))
    assert cfg.socks_proxy == "socks5://127.0.0.1:9050"
    assert cfg.max_depth == 0
    assert cfg.concurrency == 8
    assert cfg.simhash_distance == 3
    # unspecified keys fall back to defaults
    assert cfg.request_timeout == 60.0
    assert cfg.ahmia_enabled is True

def test_load_categories(tmp_path):
    f = tmp_path / "categories.toml"
    f.write_text('marketplace = ["market", "vendor"]\nforum = ["forum", "board"]\n')
    rules = load_categories(str(f))
    assert rules["marketplace"] == ["market", "vendor"]
    assert rules["forum"] == ["forum", "board"]
```

- [ ] **Step 4: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.config'`

- [ ] **Step 5: Implement `src/onionwatch/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 6: Implement `src/onionwatch/config.py`**

```python
from __future__ import annotations
import tomllib
from dataclasses import dataclass, fields

@dataclass
class Config:
    socks_proxy: str = "socks5://tor:9050"
    tor_control_port: int = 9051
    max_depth: int = 0            # 0 = unlimited
    max_urls: int = 50000
    time_budget_min: int = 120
    per_host_page_cap: int = 500
    concurrency: int = 8
    per_host_delay: float = 2.0
    request_timeout: float = 60.0
    max_retries: int = 3
    user_agent: str = "onionwatch/0.1"
    ahmia_enabled: bool = True
    snippet_chars: int = 500
    simhash_distance: int = 3

def _read_toml(path: str) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)

def load_config(path: str = "config.toml") -> Config:
    data = _read_toml(path)
    known = {f.name for f in fields(Config)}
    return Config(**{k: v for k, v in data.items() if k in known})

def load_categories(path: str = "categories.toml") -> dict[str, list[str]]:
    return {k: list(v) for k, v in _read_toml(path).items()}

def load_verified_sources(path: str = "verified_sources.toml") -> dict:
    # returns {"verified_onions": [...], "pgp": {onion: fingerprint}, "directories": [...]}
    data = _read_toml(path)
    data.setdefault("verified_onions", [])
    data.setdefault("pgp", {})
    data.setdefault("directories", [])
    return data
```

- [ ] **Step 7: Create default `config.toml`**

```toml
socks_proxy       = "socks5://tor:9050"
tor_control_port  = 9051
max_depth         = 0
max_urls          = 50000
time_budget_min   = 120
per_host_page_cap = 500
concurrency       = 8
per_host_delay    = 2.0
request_timeout   = 60.0
max_retries       = 3
user_agent        = "onionwatch/0.1"
ahmia_enabled     = true
snippet_chars     = 500
simhash_distance  = 3
```

- [ ] **Step 8: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: PASS (2 passed)

- [ ] **Step 9: Commit**

```bash
git add requirements.txt config.toml pytest.ini src/onionwatch/__init__.py src/onionwatch/config.py tests/test_config.py
git commit -m "feat: project scaffold and config loader"
```

---

### Task 2: Database layer (schema, urls, frontier, runs, hits)

**Files:**
- Create: `src/onionwatch/db.py`, `tests/test_db.py`

**Interfaces:**
- Consumes: nothing.
- Produces: class `Database(path:str)` with methods:
  - `init_schema()->None`
  - `upsert_url(url:str, host:str, source:str, depth:int, first_seen:str)->None` (insert if new; never downgrades existing fields)
  - `update_url(url:str, **fields)->None` (sets any of alive, http_status, title, response_ms, last_checked, category, category_confidence, matched_terms, snippet, content_simhash, cluster_id, is_canonical, clone_of, trust, pgp_fingerprint, inbound_links)
  - `get_url(url:str)->dict|None`
  - `all_urls()->list[dict]`
  - `enqueue(url:str, depth:int)->None` (frontier, ignore if present)
  - `next_pending(limit:int)->list[dict]` (rows with state='pending', marks them 'in_progress')
  - `mark_frontier(url:str, state:str)->None`
  - `count_frontier(state:str)->int`
  - `start_run(run_id:str, started_at:str, seeds_count:int)->None`
  - `finish_run(run_id:str, finished_at:str, discovered:int, alive_count:int, stop_reason:str)->None`
  - `set_cluster(cluster_id:str, canonical_url:str, member_count:int, chosen_by:str)->None`
  - `record_leak_hit(run_id, url, host, category, trust, term, context_snippet, matched_at)->None`
  - `canonical_trusted_urls()->list[dict]` (is_canonical=1 AND trust IN ('verified','probable'))

- [ ] **Step 1: Write the failing test** — `tests/test_db.py`

```python
from onionwatch.db import Database

def make_db(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.init_schema()
    return db

def test_upsert_and_get(tmp_path):
    db = make_db(tmp_path)
    db.upsert_url("http://a.onion/", "a.onion", "seed", 0, "2026-07-21T00:00:00")
    row = db.get_url("http://a.onion/")
    assert row["host"] == "a.onion"
    assert row["source"] == "seed"
    assert row["trust"] is None or row["trust"] == ""

def test_upsert_is_idempotent(tmp_path):
    db = make_db(tmp_path)
    db.upsert_url("http://a.onion/", "a.onion", "seed", 0, "2026-07-21T00:00:00")
    db.upsert_url("http://a.onion/", "a.onion", "crawled", 5, "2026-07-21T01:00:00")
    row = db.get_url("http://a.onion/")
    assert row["source"] == "seed"      # original preserved
    assert row["depth"] == 0

def test_update_url(tmp_path):
    db = make_db(tmp_path)
    db.upsert_url("http://a.onion/", "a.onion", "seed", 0, "2026-07-21T00:00:00")
    db.update_url("http://a.onion/", alive=1, http_status=200, title="Home")
    row = db.get_url("http://a.onion/")
    assert row["alive"] == 1
    assert row["http_status"] == 200
    assert row["title"] == "Home"

def test_frontier_roundtrip(tmp_path):
    db = make_db(tmp_path)
    db.enqueue("http://a.onion/", 0)
    db.enqueue("http://a.onion/", 0)         # duplicate ignored
    assert db.count_frontier("pending") == 1
    batch = db.next_pending(10)
    assert batch[0]["url"] == "http://a.onion/"
    assert db.count_frontier("pending") == 0
    assert db.count_frontier("in_progress") == 1
    db.mark_frontier("http://a.onion/", "done")
    assert db.count_frontier("done") == 1

def test_canonical_trusted_filter(tmp_path):
    db = make_db(tmp_path)
    for u, canon, trust in [
        ("http://good.onion/", 1, "verified"),
        ("http://ok.onion/", 1, "probable"),
        ("http://clone.onion/", 0, "suspected_clone"),
        ("http://meh.onion/", 1, "unknown"),
    ]:
        db.upsert_url(u, u[7:-1], "crawled", 1, "2026-07-21T00:00:00")
        db.update_url(u, is_canonical=canon, trust=trust)
    urls = {r["url"] for r in db.canonical_trusted_urls()}
    assert urls == {"http://good.onion/", "http://ok.onion/"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_db.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.db'`

- [ ] **Step 3: Implement `src/onionwatch/db.py`**

```python
from __future__ import annotations
import sqlite3

_UPDATABLE = {
    "alive", "http_status", "title", "response_ms", "last_checked",
    "category", "category_confidence", "matched_terms", "snippet",
    "content_simhash", "cluster_id", "is_canonical", "clone_of", "trust",
    "pgp_fingerprint", "inbound_links",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    url TEXT PRIMARY KEY,
    host TEXT, source TEXT, depth INTEGER,
    first_seen TEXT, last_checked TEXT,
    alive INTEGER, http_status INTEGER, title TEXT, response_ms INTEGER,
    category TEXT DEFAULT 'unknown', category_confidence REAL,
    matched_terms TEXT, snippet TEXT,
    content_simhash TEXT, cluster_id TEXT,
    is_canonical INTEGER DEFAULT 0, clone_of TEXT,
    trust TEXT, pgp_fingerprint TEXT, inbound_links INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS frontier (
    url TEXT PRIMARY KEY, depth INTEGER,
    state TEXT DEFAULT 'pending', enqueued_at TEXT, attempts INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clusters (
    cluster_id TEXT PRIMARY KEY, canonical_url TEXT,
    member_count INTEGER, chosen_by TEXT
);
CREATE TABLE IF NOT EXISTS crawl_runs (
    run_id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT,
    seeds_count INTEGER, discovered INTEGER, alive_count INTEGER, stop_reason TEXT
);
CREATE TABLE IF NOT EXISTS leak_hits (
    hit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, url TEXT, host TEXT, category TEXT, trust TEXT,
    term TEXT, context_snippet TEXT, matched_at TEXT
);
"""

class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row

    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def upsert_url(self, url, host, source, depth, first_seen) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO urls (url, host, source, depth, first_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (url, host, source, depth, first_seen),
        )
        self.conn.commit()

    def update_url(self, url, **fields) -> None:
        cols = [k for k in fields if k in _UPDATABLE]
        if not cols:
            return
        assignments = ", ".join(f"{c} = ?" for c in cols)
        self.conn.execute(
            f"UPDATE urls SET {assignments} WHERE url = ?",
            [fields[c] for c in cols] + [url],
        )
        self.conn.commit()

    def get_url(self, url) -> dict | None:
        cur = self.conn.execute("SELECT * FROM urls WHERE url = ?", (url,))
        row = cur.fetchone()
        return dict(row) if row else None

    def all_urls(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM urls")]

    def enqueue(self, url, depth) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO frontier (url, depth, state, enqueued_at) "
            "VALUES (?, ?, 'pending', datetime('now'))",
            (url, depth),
        )
        self.conn.commit()

    def next_pending(self, limit) -> list[dict]:
        rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM frontier WHERE state='pending' "
            "ORDER BY depth ASC LIMIT ?", (limit,))]
        for r in rows:
            self.conn.execute(
                "UPDATE frontier SET state='in_progress' WHERE url=?", (r["url"],))
        self.conn.commit()
        return rows

    def mark_frontier(self, url, state) -> None:
        self.conn.execute("UPDATE frontier SET state=? WHERE url=?", (state, url))
        self.conn.commit()

    def count_frontier(self, state) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM frontier WHERE state=?", (state,)).fetchone()[0]

    def start_run(self, run_id, started_at, seeds_count) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO crawl_runs (run_id, started_at, seeds_count) "
            "VALUES (?, ?, ?)", (run_id, started_at, seeds_count))
        self.conn.commit()

    def finish_run(self, run_id, finished_at, discovered, alive_count, stop_reason) -> None:
        self.conn.execute(
            "UPDATE crawl_runs SET finished_at=?, discovered=?, alive_count=?, "
            "stop_reason=? WHERE run_id=?",
            (finished_at, discovered, alive_count, stop_reason, run_id))
        self.conn.commit()

    def set_cluster(self, cluster_id, canonical_url, member_count, chosen_by) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO clusters "
            "(cluster_id, canonical_url, member_count, chosen_by) VALUES (?, ?, ?, ?)",
            (cluster_id, canonical_url, member_count, chosen_by))
        self.conn.commit()

    def record_leak_hit(self, run_id, url, host, category, trust,
                        term, context_snippet, matched_at) -> None:
        self.conn.execute(
            "INSERT INTO leak_hits (run_id, url, host, category, trust, term, "
            "context_snippet, matched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, url, host, category, trust, term, context_snippet, matched_at))
        self.conn.commit()

    def canonical_trusted_urls(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM urls WHERE is_canonical=1 AND trust IN ('verified','probable')")]
```

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_db.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/db.py tests/test_db.py
git commit -m "feat: sqlite database layer with resumable frontier"
```

---

### Task 3: Tor client (httpx over SOCKS, retry/backoff)

**Files:**
- Create: `src/onionwatch/tor_client.py`, `tests/test_tor_client.py`

**Interfaces:**
- Consumes: `Config` (Task 1).
- Produces: `@dataclass FetchResult(url:str, status:int|None, html:str, elapsed_ms:int, ok:bool)`. Class `TorClient(config:Config, transport=None)` — async context manager. Method `async fetch(url:str)->FetchResult` (retries up to `config.max_retries` with exponential backoff; `ok=False`, `status=None` on total failure). The `transport` param lets tests inject an `httpx.MockTransport`.

- [ ] **Step 1: Write the failing test** — `tests/test_tor_client.py`

```python
import httpx
import pytest
from onionwatch.config import Config
from onionwatch.tor_client import TorClient

def handler_ok(request):
    return httpx.Response(200, text="<html><title>ok</title></html>")

@pytest.mark.asyncio
async def test_fetch_ok():
    cfg = Config(max_retries=1, request_timeout=5)
    transport = httpx.MockTransport(handler_ok)
    async with TorClient(cfg, transport=transport) as client:
        res = await client.fetch("http://a.onion/")
    assert res.ok is True
    assert res.status == 200
    assert "ok" in res.html

@pytest.mark.asyncio
async def test_fetch_retries_then_fails():
    calls = {"n": 0}
    def flaky(request):
        calls["n"] += 1
        raise httpx.ConnectError("boom")
    cfg = Config(max_retries=3, request_timeout=5)
    async with TorClient(cfg, transport=httpx.MockTransport(flaky)) as client:
        res = await client.fetch("http://x.onion/")
    assert res.ok is False
    assert res.status is None
    assert calls["n"] == 3       # tried max_retries times
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_tor_client.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.tor_client'`

- [ ] **Step 3: Implement `src/onionwatch/tor_client.py`**

```python
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass
import httpx
from .config import Config

@dataclass
class FetchResult:
    url: str
    status: int | None
    html: str
    elapsed_ms: int
    ok: bool

class TorClient:
    def __init__(self, config: Config, transport: httpx.BaseTransport | None = None):
        self.config = config
        kwargs = {
            "timeout": config.request_timeout,
            "headers": {"User-Agent": config.user_agent},
            "follow_redirects": True,
        }
        if transport is not None:
            kwargs["transport"] = transport          # test injection, no real proxy
        else:
            kwargs["proxy"] = config.socks_proxy      # route through Tor
        self._client = httpx.AsyncClient(**kwargs)

    async def __aenter__(self) -> "TorClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def fetch(self, url: str) -> FetchResult:
        start = time.monotonic()
        last_exc = None
        for attempt in range(self.config.max_retries):
            try:
                resp = await self._client.get(url)
                elapsed = int((time.monotonic() - start) * 1000)
                return FetchResult(url, resp.status_code, resp.text, elapsed, True)
            except (httpx.HTTPError, httpx.ConnectError) as exc:
                last_exc = exc
                await asyncio.sleep(min(2 ** attempt, 10))
        elapsed = int((time.monotonic() - start) * 1000)
        return FetchResult(url, None, "", elapsed, False)
```

Note: `time.monotonic` is allowed in normal runtime; only workflow-script `Date.now`/`Math.random` are restricted — this is application code, not a workflow script.

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_tor_client.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/tor_client.py tests/test_tor_client.py
git commit -m "feat: async Tor SOCKS client with retry/backoff"
```

---

### Task 4: Link extraction + URL normalization

**Files:**
- Create: `src/onionwatch/discover.py`, `tests/test_discover.py`

**Interfaces:**
- Consumes: nothing (pure functions).
- Produces: `normalize_url(url:str)->str` (lowercase host, strip fragments/trailing slash noise, ensure scheme); `onion_host(url:str)->str|None` (returns the `.onion` host or None); `extract_onion_links(html:str, base_url:str)->set[str]` (absolute, normalized `.onion` URLs from hrefs and raw text); `visible_text(html:str)->str` (parsed text for categorise/fingerprint).

- [ ] **Step 1: Write the failing test** — `tests/test_discover.py`

```python
from onionwatch.discover import (
    normalize_url, onion_host, extract_onion_links, visible_text,
)

ONION = "http://abcdefghij234567.onion"

def test_onion_host():
    assert onion_host(f"{ONION}/path") == "abcdefghij234567.onion"
    assert onion_host("https://example.com/") is None

def test_normalize_url():
    assert normalize_url(f"{ONION}/A/../b#frag") == f"{ONION}/b"
    assert normalize_url(f"{ONION}") == f"{ONION}/"

def test_extract_onion_links_from_href_and_text():
    html = f'''
      <a href="/dir">rel</a>
      <a href="{ONION}/x">abs</a>
      <a href="https://clearnet.com">skip</a>
      raw mention: qwerty1234567890.onion/page
    '''
    links = extract_onion_links(html, ONION + "/")
    assert f"{ONION}/dir" in links
    assert f"{ONION}/x" in links
    assert any("qwerty1234567890.onion" in u for u in links)
    assert all(".onion" in u for u in links)

def test_visible_text_strips_tags():
    txt = visible_text("<html><body><h1>Bitcoin</h1><p>market</p></body></html>")
    assert "Bitcoin" in txt and "market" in txt
    assert "<" not in txt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_discover.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.discover'`

- [ ] **Step 3: Implement the pure functions in `src/onionwatch/discover.py`**

```python
from __future__ import annotations
import re
from urllib.parse import urljoin, urlsplit, urlunsplit
from selectolax.parser import HTMLParser

_ONION_RE = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.IGNORECASE)

def onion_host(url: str) -> str | None:
    host = urlsplit(url).netloc.lower() or url.lower()
    m = _ONION_RE.search(host)
    return m.group(0).lower() if m else None

def normalize_url(url: str) -> str:
    parts = urlsplit(url if "://" in url else "http://" + url)
    scheme = parts.scheme or "http"
    netloc = parts.netloc.lower()
    # collapse ../ and . segments
    segments: list[str] = []
    for seg in parts.path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segments:
                segments.pop()
        else:
            segments.append(seg)
    path = "/" + "/".join(segments)
    return urlunsplit((scheme, netloc, path, parts.query, ""))

def extract_onion_links(html: str, base_url: str) -> set[str]:
    found: set[str] = set()
    tree = HTMLParser(html)
    for node in tree.css("a[href]"):
        href = node.attributes.get("href") or ""
        absolute = urljoin(base_url, href)
        if onion_host(absolute):
            found.add(normalize_url(absolute))
    # raw-text mentions not inside hrefs
    for m in _ONION_RE.finditer(html):
        found.add(normalize_url("http://" + m.group(0).lower()))
    return found

def visible_text(html: str) -> str:
    tree = HTMLParser(html)
    for tag in tree.css("script, style"):
        tag.decompose()
    body = tree.body or tree.root
    return re.sub(r"\s+", " ", body.text(separator=" ")).strip() if body else ""
```

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_discover.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/discover.py tests/test_discover.py
git commit -m "feat: onion link extraction and url normalization"
```

---

### Task 5: Resumable BFS crawl loop

**Files:**
- Modify: `src/onionwatch/discover.py` (add `crawl`)
- Create: `seeds.txt` (example), extend `tests/test_discover.py`

**Interfaces:**
- Consumes: `Config`, `Database`, `TorClient.fetch` (any object with `async fetch(url)->FetchResult`), `extract_onion_links`, `onion_host`.
- Produces: `@dataclass RunStats(run_id:str, discovered:int, alive:int, stop_reason:str)`; `async crawl(config, db, client, seeds:list[str], run_id:str, now:str)->RunStats`. Stop reasons: `"frontier_empty"`, `"max_urls"`, `"time_budget"`. Deep BFS bounded by `config.max_urls`, `config.time_budget_min`, `config.per_host_page_cap`. `now` is passed in (caller stamps the timestamp) so the function stays deterministic under test.

- [ ] **Step 1: Write the failing test** — append to `tests/test_discover.py`

```python
import pytest
from onionwatch.config import Config
from onionwatch.db import Database
from onionwatch.discover import crawl, FetchResult  # FetchResult re-exported for typing

class FakeClient:
    """Returns canned HTML per URL; unknown URLs 404."""
    def __init__(self, pages):
        self.pages = pages
    async def fetch(self, url):
        from onionwatch.tor_client import FetchResult as FR
        html = self.pages.get(url)
        if html is None:
            return FR(url, 404, "", 5, True)
        return FR(url, 200, html, 5, True)

@pytest.mark.asyncio
async def test_crawl_discovers_and_bounds(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    B = "http://bbbbbbbbbbbbbbbb.onion/"
    pages = {
        A: f'<a href="{B}">b</a>',
        B: f'<a href="{A}">a</a>',   # cycle back — must not loop forever
    }
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=10, concurrency=2, per_host_delay=0)
    stats = await crawl(cfg, db, FakeClient(pages), [A], "run1", "2026-07-21T00:00:00")
    urls = {r["url"] for r in db.all_urls()}
    assert A in urls and B in urls
    assert stats.discovered >= 2
    assert stats.stop_reason == "frontier_empty"

@pytest.mark.asyncio
async def test_crawl_respects_max_urls(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    pages = {A: "".join(
        f'<a href="http://{chr(97+i)*16}.onion/">x</a>' for i in range(9))}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=3, concurrency=2, per_host_delay=0)
    stats = await crawl(cfg, db, FakeClient(pages), [A], "run2", "2026-07-21T00:00:00")
    assert stats.stop_reason == "max_urls"
    assert stats.discovered <= 3 + 9   # bounded; does not enqueue unbounded
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_discover.py -k crawl -v`
Expected: FAIL — `ImportError: cannot import name 'crawl'`

- [ ] **Step 3: Implement `crawl` in `src/onionwatch/discover.py`**

Add these imports at the top of the file and append the code below:

```python
import asyncio
import time
from dataclasses import dataclass
from collections import defaultdict
from .tor_client import FetchResult  # re-export for tests/typing

@dataclass
class RunStats:
    run_id: str
    discovered: int
    alive: int
    stop_reason: str

async def crawl(config, db, client, seeds, run_id, now) -> RunStats:
    db.start_run(run_id, now, len(seeds))
    for s in seeds:
        db.enqueue(normalize_url(s), 0)
    host_pages: dict[str, int] = defaultdict(int)
    processed = 0
    alive = 0
    deadline = time.monotonic() + config.time_budget_min * 60
    stop_reason = "frontier_empty"

    async def handle(row):
        nonlocal alive
        url, depth = row["url"], row["depth"]
        host = onion_host(url)
        if host and host_pages[host] >= config.per_host_page_cap:
            db.mark_frontier(url, "done")
            return
        res = await client.fetch(url)
        if config.per_host_delay:
            await asyncio.sleep(config.per_host_delay)
        if host:
            host_pages[host] += 1
        if res.ok and res.status and res.status < 400:
            alive += 1
            db.upsert_url(url, host or "", "crawled", depth, now)
            db.update_url(url, alive=1, http_status=res.status, last_checked=now)
            if config.max_depth == 0 or depth < config.max_depth:
                for link in extract_onion_links(res.html, url):
                    if db.get_url(link) is None:
                        db.upsert_url(link, onion_host(link) or "", "crawled",
                                      depth + 1, now)
                        db.enqueue(link, depth + 1)
        else:
            db.upsert_url(url, host or "", "crawled", depth, now)
            db.update_url(url, alive=0, http_status=res.status, last_checked=now)
        db.mark_frontier(url, "done")

    while True:
        if processed >= config.max_urls:
            stop_reason = "max_urls"; break
        if time.monotonic() >= deadline:
            stop_reason = "time_budget"; break
        batch = db.next_pending(config.concurrency)
        if not batch:
            stop_reason = "frontier_empty"; break
        await asyncio.gather(*(handle(r) for r in batch))
        processed += len(batch)

    discovered = len(db.all_urls())
    db.finish_run(run_id, now, discovered, alive, stop_reason)
    return RunStats(run_id, discovered, alive, stop_reason)
```

- [ ] **Step 4: Create example `seeds.txt`**

```
# One URL per line. Clearnet directories and known .onion directories.
# Your real seeds.txt is gitignored. Examples:
https://ahmia.fi/
```

- [ ] **Step 5: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_discover.py -v`
Expected: PASS (all discover tests)

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/discover.py tests/test_discover.py seeds.txt
git commit -m "feat: resumable deep BFS crawl with safety caps"
```

---

### Task 6: Liveness probe

**Files:**
- Create: `src/onionwatch/probe.py`, `tests/test_probe.py`

**Interfaces:**
- Consumes: `TorClient.fetch`, `discover.visible_text`, `Database`.
- Produces: `@dataclass ProbeResult(url:str, alive:bool, status:int|None, title:str|None, response_ms:int)`; `extract_title(html:str)->str|None`; `async probe_url(client, url:str)->ProbeResult`; `async reprobe_all(db, client, now:str)->int` (re-checks every known URL, updates rows, returns count alive).

- [ ] **Step 1: Write the failing test** — `tests/test_probe.py`

```python
import pytest
from onionwatch.probe import extract_title, probe_url
from onionwatch.tor_client import FetchResult

class OneShot:
    def __init__(self, res): self.res = res
    async def fetch(self, url): return self.res

def test_extract_title():
    assert extract_title("<html><title> Hello </title></html>") == "Hello"
    assert extract_title("<html></html>") is None

@pytest.mark.asyncio
async def test_probe_alive():
    res = FetchResult("http://a.onion/", 200, "<title>Site</title>", 42, True)
    pr = await probe_url(OneShot(res), "http://a.onion/")
    assert pr.alive is True
    assert pr.status == 200
    assert pr.title == "Site"
    assert pr.response_ms == 42

@pytest.mark.asyncio
async def test_probe_dead():
    res = FetchResult("http://a.onion/", None, "", 60000, False)
    pr = await probe_url(OneShot(res), "http://a.onion/")
    assert pr.alive is False
    assert pr.title is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_probe.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.probe'`

- [ ] **Step 3: Implement `src/onionwatch/probe.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from selectolax.parser import HTMLParser

@dataclass
class ProbeResult:
    url: str
    alive: bool
    status: int | None
    title: str | None
    response_ms: int

def extract_title(html: str) -> str | None:
    node = HTMLParser(html).css_first("title")
    if node and node.text():
        return node.text().strip() or None
    return None

async def probe_url(client, url: str) -> ProbeResult:
    res = await client.fetch(url)
    alive = bool(res.ok and res.status and res.status < 400)
    title = extract_title(res.html) if alive else None
    return ProbeResult(url, alive, res.status, title, res.elapsed_ms)

async def reprobe_all(db, client, now: str) -> int:
    alive_count = 0
    for row in db.all_urls():
        pr = await probe_url(client, row["url"])
        db.update_url(row["url"], alive=int(pr.alive), http_status=pr.status,
                      title=pr.title, response_ms=pr.response_ms, last_checked=now)
        alive_count += int(pr.alive)
    return alive_count
```

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_probe.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/probe.py tests/test_probe.py
git commit -m "feat: liveness probe and reprobe"
```

---

### Task 7: Categoriser (keyword rules)

**Files:**
- Create: `src/onionwatch/categorize.py`, `categories.toml`, `tests/test_categorize.py`

**Interfaces:**
- Consumes: `load_categories` (Task 1), `discover.visible_text`.
- Produces: `@dataclass CategoryResult(category:str, confidence:float, matched_terms:list[str])`; `categorize(title:str, text:str, rules:dict[str,list[str]])->CategoryResult`. Highest match count wins; ties broken by rule insertion order; no match → `("unknown", 0.0, [])`. Confidence = matched_terms_for_winner / total_terms_matched_across_all.

- [ ] **Step 1: Write the failing test** — `tests/test_categorize.py`

```python
from onionwatch.categorize import categorize

RULES = {
    "marketplace": ["market", "vendor", "escrow"],
    "forum": ["forum", "board", "thread"],
    "crypto": ["bitcoin", "monero", "wallet"],
}

def test_categorize_marketplace():
    r = categorize("Best Market", "vendor escrow shop", RULES)
    assert r.category == "marketplace"
    assert "market" in r.matched_terms and "vendor" in r.matched_terms
    assert 0 < r.confidence <= 1

def test_categorize_unknown():
    r = categorize("Hello", "just a personal page", RULES)
    assert r.category == "unknown"
    assert r.confidence == 0.0
    assert r.matched_terms == []

def test_categorize_tiebreak_is_insertion_order():
    # one match each for marketplace and forum -> marketplace wins (declared first)
    r = categorize("", "market forum", RULES)
    assert r.category == "marketplace"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_categorize.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.categorize'`

- [ ] **Step 3: Implement `src/onionwatch/categorize.py`**

```python
from __future__ import annotations
import re
from dataclasses import dataclass

@dataclass
class CategoryResult:
    category: str
    confidence: float
    matched_terms: list[str]

def categorize(title: str, text: str, rules: dict[str, list[str]]) -> CategoryResult:
    haystack = f"{title} {text}".lower()
    per_category: dict[str, list[str]] = {}
    total = 0
    for category, terms in rules.items():
        hits = []
        for term in terms:
            if re.search(r"\b" + re.escape(term.lower()) + r"\b", haystack):
                hits.append(term)
        if hits:
            per_category[category] = hits
            total += len(hits)
    if not per_category:
        return CategoryResult("unknown", 0.0, [])
    # winner: most matches; ties -> first declared (dict preserves insertion order)
    winner = max(per_category, key=lambda c: len(per_category[c]))
    matched = per_category[winner]
    confidence = round(len(matched) / total, 3)
    return CategoryResult(winner, confidence, matched)
```

- [ ] **Step 4: Create `categories.toml`**

```toml
marketplace   = ["market", "vendor", "escrow", "cart", "listing", "shop"]
forum         = ["forum", "board", "thread", "reply", "topic"]
leak-site     = ["leaked", "leak", "breach", "dump", "database", "stealer", "combolist"]
paste         = ["paste", "pastebin", "raw text"]
hosting       = ["hosting", "upload", "file share", "image host"]
crypto        = ["bitcoin", "btc", "monero", "xmr", "wallet", "mixer", "tumbler"]
search        = ["search", "index", "directory", "engine"]
wiki-directory = ["wiki", "links", "onion list", "catalog"]
blog          = ["blog", "post", "diary", "journal"]
```

- [ ] **Step 5: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_categorize.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/categorize.py categories.toml tests/test_categorize.py
git commit -m "feat: keyword-rule categoriser"
```

---

### Task 8: Content fingerprint (simhash + hamming)

**Files:**
- Create: `src/onionwatch/fingerprint.py`, `tests/test_fingerprint.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `simhash(text:str, bits:int=64)->int`; `hamming(a:int, b:int)->int`; `to_hex(value:int)->str`; `from_hex(s:str)->int`. Near-identical text → small hamming distance; unrelated text → large.

- [ ] **Step 1: Write the failing test** — `tests/test_fingerprint.py`

```python
from onionwatch.fingerprint import simhash, hamming, to_hex, from_hex

def test_identical_text_zero_distance():
    a = simhash("the quick brown fox jumps over the lazy dog")
    b = simhash("the quick brown fox jumps over the lazy dog")
    assert hamming(a, b) == 0

def test_near_duplicate_small_distance():
    a = simhash("welcome to acme market place buy and sell goods here safely")
    b = simhash("welcome to acme market place buy and sell goods here safely now")
    assert hamming(a, b) <= 6

def test_unrelated_large_distance():
    a = simhash("bitcoin monero wallet mixer tumbler crypto exchange")
    b = simhash("poetry recipes gardening travel photography journal blog")
    assert hamming(a, b) >= 12

def test_hex_roundtrip():
    a = simhash("some content here")
    assert from_hex(to_hex(a)) == a
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_fingerprint.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.fingerprint'`

- [ ] **Step 3: Implement `src/onionwatch/fingerprint.py`**

```python
from __future__ import annotations
import hashlib
import re

def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())

def _token_hash(token: str, bits: int) -> int:
    digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") & ((1 << bits) - 1)

def simhash(text: str, bits: int = 64) -> int:
    vector = [0] * bits
    tokens = _tokens(text)
    if not tokens:
        return 0
    for token in tokens:
        h = _token_hash(token, bits)
        for i in range(bits):
            vector[i] += 1 if (h >> i) & 1 else -1
    result = 0
    for i in range(bits):
        if vector[i] > 0:
            result |= (1 << i)
    return result

def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")

def to_hex(value: int) -> str:
    return format(value, "016x")

def from_hex(s: str) -> int:
    return int(s, 16)
```

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_fingerprint.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/fingerprint.py tests/test_fingerprint.py
git commit -m "feat: simhash content fingerprint"
```

---

### Task 9: Verified-source ingestion + PGP match

**Files:**
- Create: `src/onionwatch/verify.py`, `verified_sources.toml` (example), `tests/test_verify.py`

**Interfaces:**
- Consumes: `load_verified_sources` (Task 1), `discover.onion_host`.
- Produces: `is_verified(url:str, verified:dict)->bool` (host in `verified_onions`); `pgp_fingerprint_in_page(text:str)->str|None` (extracts a PGP fingerprint if present); `pgp_matches(url:str, page_text:str, verified:dict)->bool` (extracted fingerprint equals the expected fingerprint for that onion in `verified["pgp"]`).

- [ ] **Step 1: Write the failing test** — `tests/test_verify.py`

```python
from onionwatch.verify import is_verified, pgp_fingerprint_in_page, pgp_matches

VERIFIED = {
    "verified_onions": ["aaaaaaaaaaaaaaaa.onion"],
    "pgp": {"aaaaaaaaaaaaaaaa.onion": "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"},
    "directories": [],
}

def test_is_verified():
    assert is_verified("http://aaaaaaaaaaaaaaaa.onion/x", VERIFIED) is True
    assert is_verified("http://zzzzzzzzzzzzzzzz.onion/", VERIFIED) is False

def test_extract_pgp_fingerprint():
    page = "Our key: AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333 trust it"
    fp = pgp_fingerprint_in_page(page)
    assert fp == "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"

def test_pgp_matches():
    page = "key AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
    assert pgp_matches("http://aaaaaaaaaaaaaaaa.onion/", page, VERIFIED) is True
    assert pgp_matches("http://zzzzzzzzzzzzzzzz.onion/", page, VERIFIED) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.verify'`

- [ ] **Step 3: Implement `src/onionwatch/verify.py`**

```python
from __future__ import annotations
import re
from .discover import onion_host

# 40-hex-char PGP v4 fingerprint, usually shown as 10 groups of 4 hex chars
_FP_GROUP = re.compile(r"\b(?:[0-9A-Fa-f]{4}[ ]{1,2}){9}[0-9A-Fa-f]{4}\b")

def _canon_fp(raw: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", raw).upper()

def is_verified(url: str, verified: dict) -> bool:
    host = onion_host(url)
    return host in set(verified.get("verified_onions", []))

def pgp_fingerprint_in_page(text: str) -> str | None:
    m = _FP_GROUP.search(text)
    return _canon_fp(m.group(0)) if m else None

def pgp_matches(url: str, page_text: str, verified: dict) -> bool:
    host = onion_host(url)
    expected = verified.get("pgp", {}).get(host)
    if not expected:
        return False
    got = pgp_fingerprint_in_page(page_text)
    return got is not None and got == _canon_fp(expected)
```

- [ ] **Step 4: Create example `verified_sources.toml`**

```toml
# Operator-maintained source of truth. The real file is gitignored.
# Verified/PGP-signed onion addresses of legitimate sites.
verified_onions = [
    # "exampleverifiedonionaddr56chars....onion",
]

# Optional: expected PGP fingerprint per onion (canonicalised on load).
[pgp]
# "exampleverifiedonionaddr....onion" = "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"

# Trusted directory sites to seed verified lists from.
directories = [
    # "https://dark.fail/",
]
```

- [ ] **Step 5: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/verify.py verified_sources.toml tests/test_verify.py
git commit -m "feat: verified-source and PGP fingerprint matching"
```

---

### Task 10: Clustering + canonical selection

**Files:**
- Create: `src/onionwatch/cluster.py`, `tests/test_cluster.py`

**Interfaces:**
- Consumes: `fingerprint.from_hex/hamming`, `verify.is_verified`, `Database`.
- Produces: `cluster_rows(rows:list[dict], distance:int)->list[list[dict]]` (groups url rows whose `content_simhash` are within `distance` hamming; rows without a simhash are singletons); `choose_canonical(cluster:list[dict], verified:dict)->tuple[dict,str]` (returns canonical row + `chosen_by` in priority: verified → pgp → first_seen → inbound_links); `run_clustering(db, verified, distance)->int` (writes cluster_id/is_canonical/clone_of/trust for all rows, returns cluster count). Trust rules: canonical & verified→`verified`; canonical & (pgp OR singleton)→`probable`; canonical & neither→`unknown`; non-canonical→`suspected_clone`.

- [ ] **Step 1: Write the failing test** — `tests/test_cluster.py`

```python
from onionwatch.cluster import cluster_rows, choose_canonical, run_clustering
from onionwatch.fingerprint import simhash, to_hex
from onionwatch.db import Database

def row(url, sh, first_seen="2026-07-21T00:00:00", inbound=0, host=None):
    return {"url": url, "content_simhash": sh,
            "first_seen": first_seen, "inbound_links": inbound,
            "host": host or url[7:-1]}

def test_cluster_groups_near_duplicates():
    sh_a = to_hex(simhash("welcome to acme market buy and sell goods safely here"))
    sh_b = to_hex(simhash("welcome to acme market buy and sell goods safely here now"))
    sh_c = to_hex(simhash("totally different poetry gardening travel photos journal"))
    rows = [row("http://a.onion/", sh_a),
            row("http://b.onion/", sh_b),
            row("http://c.onion/", sh_c)]
    clusters = cluster_rows(rows, distance=6)
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 2]     # a+b together, c alone

def test_choose_canonical_prefers_verified():
    verified = {"verified_onions": ["b.onion"], "pgp": {}}
    cluster = [row("http://a.onion/", "0", first_seen="2026-01-01T00:00:00"),
               row("http://b.onion/", "0", first_seen="2026-07-01T00:00:00")]
    canon, why = choose_canonical(cluster, verified)
    assert canon["url"] == "http://b.onion/"
    assert why == "verified"

def test_choose_canonical_falls_back_to_first_seen():
    verified = {"verified_onions": [], "pgp": {}}
    cluster = [row("http://a.onion/", "0", first_seen="2026-05-01T00:00:00"),
               row("http://b.onion/", "0", first_seen="2026-01-01T00:00:00")]
    canon, why = choose_canonical(cluster, verified)
    assert canon["url"] == "http://b.onion/"   # oldest
    assert why == "first_seen"

def test_run_clustering_writes_trust(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    sh = to_hex(simhash("acme market buy and sell goods safely here always open"))
    for u in ("http://a.onion/", "http://b.onion/"):
        db.upsert_url(u, u[7:-1], "crawled", 1, "2026-07-21T00:00:00")
        db.update_url(u, content_simhash=sh)
    verified = {"verified_onions": ["a.onion"], "pgp": {}}
    n = run_clustering(db, verified, distance=6)
    assert n == 1
    a = db.get_url("http://a.onion/"); b = db.get_url("http://b.onion/")
    assert a["is_canonical"] == 1 and a["trust"] == "verified"
    assert b["is_canonical"] == 0 and b["trust"] == "suspected_clone"
    assert b["clone_of"] == "http://a.onion/"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_cluster.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.cluster'`

- [ ] **Step 3: Implement `src/onionwatch/cluster.py`**

```python
from __future__ import annotations
from .fingerprint import from_hex, hamming
from .verify import is_verified

def cluster_rows(rows: list[dict], distance: int) -> list[list[dict]]:
    clusters: list[list[dict]] = []
    reps: list[int] = []            # representative simhash per cluster
    for r in rows:
        sh = r.get("content_simhash")
        if not sh:
            clusters.append([r]); reps.append(None)
            continue
        val = from_hex(sh)
        placed = False
        for i, rep in enumerate(reps):
            if rep is not None and hamming(val, rep) <= distance:
                clusters.append_to = None
                clusters[i].append(r); placed = True; break
        if not placed:
            clusters.append([r]); reps.append(val)
    return clusters

def choose_canonical(cluster: list[dict], verified: dict) -> tuple[dict, str]:
    for r in cluster:
        if is_verified(r["url"], verified):
            return r, "verified"
    for r in cluster:
        if r.get("pgp_fingerprint"):
            return r, "pgp"
    with_seen = [r for r in cluster if r.get("first_seen")]
    if with_seen:
        return min(with_seen, key=lambda r: r["first_seen"]), "first_seen"
    return max(cluster, key=lambda r: r.get("inbound_links") or 0), "inbound_links"

def run_clustering(db, verified: dict, distance: int) -> int:
    rows = db.all_urls()
    clusters = cluster_rows(rows, distance)
    count = 0
    for idx, cluster in enumerate(clusters):
        cluster_id = f"c{idx:06d}"
        canon, why = choose_canonical(cluster, verified)
        singleton = len(cluster) == 1
        db.set_cluster(cluster_id, canon["url"], len(cluster), why)
        for r in cluster:
            is_canon = r["url"] == canon["url"]
            if is_canon:
                if why == "verified":
                    trust = "verified"
                elif why == "pgp" or singleton:
                    trust = "probable"
                else:
                    trust = "unknown"
            else:
                trust = "suspected_clone"
            db.update_url(
                r["url"], cluster_id=cluster_id,
                is_canonical=1 if is_canon else 0,
                clone_of=None if is_canon else canon["url"],
                trust=trust)
        count += 1
    return count
```

Note: remove the stray `clusters.append_to = None` line — it is a typo guard; the correct body appends to `clusters[i]`. Final loop must read exactly:

```python
        for i, rep in enumerate(reps):
            if rep is not None and hamming(val, rep) <= distance:
                clusters[i].append(r); placed = True; break
```

- [ ] **Step 4: Fix the typo from Step 3**

Ensure `cluster_rows` inner loop matches the corrected block above (no `append_to`). Re-read the function before running tests.

- [ ] **Step 5: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_cluster.py -v`
Expected: PASS (4 passed)

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/cluster.py tests/test_cluster.py
git commit -m "feat: clone clustering and canonical selection with trust levels"
```

---

### Task 11: Leak hunt

**Files:**
- Create: `src/onionwatch/hunt.py`, `tests/test_hunt.py`

**Interfaces:**
- Consumes: `Database.canonical_trusted_urls`, `Database.record_leak_hit`, `TorClient.fetch`, `discover.visible_text`.
- Produces: `load_terms(path:str)->list[str]` (one term/regex per non-comment line); `match_terms(text:str, terms:list[str], ctx:int=60)->list[tuple[str,str]]` (returns `(term, context_snippet)` per match, context = `ctx` chars around it); `async hunt(db, client, terms:list[str], run_id:str, now:str)->int` (scans canonical trusted sites, records hits, returns hit count).

- [ ] **Step 1: Write the failing test** — `tests/test_hunt.py`

```python
import pytest
from onionwatch.hunt import match_terms, hunt
from onionwatch.tor_client import FetchResult
from onionwatch.db import Database

def test_match_terms_returns_context():
    text = "leak of acme corp dataset including admin@acme.com and more records"
    hits = match_terms(text, ["admin@acme.com", "acme corp"], ctx=10)
    terms = {t for t, _ in hits}
    assert "admin@acme.com" in terms and "acme corp" in terms
    for _, ctx in hits:
        assert len(ctx) <= 10 + 40  # roughly bounded

def test_match_terms_no_hit():
    assert match_terms("nothing here", ["secret"]) == []

class SiteClient:
    def __init__(self, html): self.html = html
    async def fetch(self, url):
        return FetchResult(url, 200, self.html, 10, True)

@pytest.mark.asyncio
async def test_hunt_records_hits(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://good.onion/"
    db.upsert_url(u, "good.onion", "crawled", 1, "2026-07-21T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site")
    html = "<html><body>dump contains admin@acme.com today</body></html>"
    n = await hunt(db, SiteClient(html), ["admin@acme.com"], "run1", "2026-07-21T00:00:00")
    assert n == 1
    hits = list(db.conn.execute("SELECT term, url FROM leak_hits"))
    assert hits[0][0] == "admin@acme.com"
    assert hits[0][1] == u
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_hunt.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.hunt'`

- [ ] **Step 3: Implement `src/onionwatch/hunt.py`**

```python
from __future__ import annotations
import re
from .discover import visible_text

def load_terms(path: str) -> list[str]:
    terms = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return terms

def match_terms(text: str, terms: list[str], ctx: int = 60) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for term in terms:
        for m in re.finditer(re.escape(term), text, re.IGNORECASE):
            start = max(0, m.start() - ctx)
            end = min(len(text), m.end() + ctx)
            hits.append((term, text[start:end].strip()))
    return hits

async def hunt(db, client, terms: list[str], run_id: str, now: str) -> int:
    count = 0
    for row in db.canonical_trusted_urls():
        res = await client.fetch(row["url"])
        if not (res.ok and res.status and res.status < 400):
            continue
        text = visible_text(res.html)
        for term, ctx in match_terms(text, terms):
            db.record_leak_hit(
                run_id, row["url"], row["host"], row.get("category"),
                row.get("trust"), term, ctx, now)
            count += 1
    return count
```

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_hunt.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/hunt.py tests/test_hunt.py
git commit -m "feat: leak hunt over canonical trusted sites"
```

---

### Task 12: CLI + Docker/Tor packaging

**Files:**
- Create: `src/onionwatch/cli.py`, `Dockerfile`, `docker-compose.yml`, `tor/torrc`, `tests/test_cli.py`

**Interfaces:**
- Consumes: everything above.
- Produces: console entrypoint `onionwatch` with subcommands `crawl [--resume]`, `probe`, `categorize`, `cluster`, `hunt --terms FILE`, `export --format {csv,json} [--trust T] [--category C]`, `stats`. `main(argv:list[str]|None=None)->int`.

- [ ] **Step 1: Write the failing test** — `tests/test_cli.py`

```python
from onionwatch.cli import build_parser

def test_parser_has_subcommands():
    p = build_parser()
    args = p.parse_args(["hunt", "--terms", "client.txt"])
    assert args.command == "hunt"
    assert args.terms == "client.txt"

def test_export_flags():
    p = build_parser()
    args = p.parse_args(["export", "--format", "csv", "--category", "leak-site"])
    assert args.format == "csv"
    assert args.category == "leak-site"

def test_crawl_resume_flag():
    p = build_parser()
    args = p.parse_args(["crawl", "--resume"])
    assert args.command == "crawl"
    assert args.resume is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.cli'`

- [ ] **Step 3: Implement `src/onionwatch/cli.py`**

```python
from __future__ import annotations
import argparse
import asyncio
import csv
import json
import sys
from datetime import datetime, timezone

from .config import load_config, load_categories, load_verified_sources
from .db import Database
from .tor_client import TorClient
from .discover import crawl, visible_text
from .probe import reprobe_all
from .categorize import categorize
from .fingerprint import simhash, to_hex
from .cluster import run_clustering
from .hunt import hunt, load_terms

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="onionwatch")
    p.add_argument("--config", default="config.toml")
    p.add_argument("--db", default="data/onionwatch.db")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("crawl"); c.add_argument("--resume", action="store_true")
    c.add_argument("--seeds", default="seeds.txt")
    sub.add_parser("probe")
    sub.add_parser("categorize")
    sub.add_parser("cluster")
    h = sub.add_parser("hunt"); h.add_argument("--terms", required=True)
    e = sub.add_parser("export")
    e.add_argument("--format", choices=["csv", "json"], default="json")
    e.add_argument("--trust", default=None)
    e.add_argument("--category", default=None)
    sub.add_parser("stats")
    return p

def _read_seeds(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return [ln.strip() for ln in fh
                    if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        return []

def _run_crawl(cfg, db, args):
    seeds = [] if args.resume else _read_seeds(args.seeds)
    async def go():
        async with TorClient(cfg) as client:
            stats = await crawl(cfg, db, client, seeds,
                                f"run-{_now()}", _now())
            print(f"discovered={stats.discovered} alive={stats.alive} "
                  f"stop={stats.stop_reason}")
    asyncio.run(go())

def _run_categorize(cfg, db):
    rules = load_categories("categories.toml")
    for row in db.all_urls():
        snippet = row.get("snippet") or ""
        res = categorize(row.get("title") or "", snippet, rules)
        db.update_url(row["url"], category=res.category,
                      category_confidence=res.confidence,
                      matched_terms=json.dumps(res.matched_terms))
    print("categorized", len(db.all_urls()), "urls")

def _run_cluster(cfg, db):
    verified = load_verified_sources("verified_sources.toml")
    n = run_clustering(db, verified, cfg.simhash_distance)
    print("clusters:", n)

def _run_hunt(cfg, db, args):
    terms = load_terms(args.terms)
    async def go():
        async with TorClient(cfg) as client:
            n = await hunt(db, client, terms, f"hunt-{_now()}", _now())
            print("leak hits:", n)
    asyncio.run(go())

def _run_export(db, args):
    rows = db.all_urls()
    if args.trust:
        rows = [r for r in rows if r.get("trust") == args.trust]
    if args.category:
        rows = [r for r in rows if r.get("category") == args.category]
    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2); print()
    else:
        if rows:
            w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)

def _run_stats(db):
    rows = db.all_urls()
    alive = sum(1 for r in rows if r.get("alive") == 1)
    by_cat: dict[str, int] = {}
    by_trust: dict[str, int] = {}
    for r in rows:
        by_cat[r.get("category") or "unknown"] = by_cat.get(r.get("category") or "unknown", 0) + 1
        by_trust[r.get("trust") or "unrated"] = by_trust.get(r.get("trust") or "unrated", 0) + 1
    print(f"total={len(rows)} alive={alive}")
    print("by_category:", by_cat)
    print("by_trust:", by_trust)

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)
    db = Database(args.db); db.init_schema()
    if args.command == "crawl":
        _run_crawl(cfg, db, args)
    elif args.command == "probe":
        async def go():
            async with TorClient(cfg) as client:
                print("alive:", await reprobe_all(db, client, _now()))
        asyncio.run(go())
    elif args.command == "categorize":
        _run_categorize(cfg, db)
    elif args.command == "cluster":
        _run_cluster(cfg, db)
    elif args.command == "hunt":
        _run_hunt(cfg, db, args)
    elif args.command == "export":
        _run_export(db, args)
    elif args.command == "stats":
        _run_stats(db)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Add console entrypoint** — create `pyproject.toml`

```toml
[project]
name = "onionwatch"
version = "0.1.0"
requires-python = ">=3.12"

[project.scripts]
onionwatch = "onionwatch.cli:main"

[tool.setuptools.packages.find]
where = ["src"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```

```bash
.venv/bin/pip install -e .
```

- [ ] **Step 5: Create `tor/torrc`**

```
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
CookieAuthentication 0
Log notice stdout
```

- [ ] **Step 6: Create `Dockerfile`**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .
COPY config.toml categories.toml ./
ENTRYPOINT ["onionwatch"]
CMD ["stats"]
```

- [ ] **Step 7: Create `docker-compose.yml`**

```yaml
services:
  tor:
    image: dperson/torproxy
    volumes:
      - ./tor/torrc:/etc/tor/torrc:ro
    expose:
      - "9050"
      - "9051"
    restart: unless-stopped

  onionwatch:
    build: .
    depends_on:
      - tor
    volumes:
      - ./data:/app/data
      - ./seeds.txt:/app/seeds.txt:ro
      - ./verified_sources.toml:/app/verified_sources.toml:ro
    environment:
      - PYTHONUNBUFFERED=1
    # override the default (stats) at run time, e.g.:
    #   docker compose run --rm onionwatch crawl
```

- [ ] **Step 8: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: PASS (3 passed)

- [ ] **Step 9: Run the whole suite**

Run: `.venv/bin/pytest -v`
Expected: PASS (all tasks' tests green)

- [ ] **Step 10: Commit**

```bash
git add src/onionwatch/cli.py pyproject.toml Dockerfile docker-compose.yml tor/torrc tests/test_cli.py
git commit -m "feat: CLI entrypoint and docker/tor packaging"
```

---

### Task 13: Wire fingerprint + categorise + snippet into crawl; README

**Files:**
- Modify: `src/onionwatch/discover.py` (store snippet, simhash, category during crawl)
- Create: `README.md`
- Modify: `tests/test_discover.py` (assert enrichment persisted)

**Interfaces:**
- Consumes: `fingerprint.simhash/to_hex`, `categorize.categorize`, `load_categories`, `discover.visible_text`, `probe.extract_title`.
- Produces: crawl now persists `title`, `snippet`, `content_simhash`, `category`, `category_confidence`, `matched_terms` on each alive URL. `crawl` gains optional `rules:dict|None=None` param (defaults to loading `categories.toml`; tests pass a dict).

- [ ] **Step 1: Write the failing test** — append to `tests/test_discover.py`

```python
@pytest.mark.asyncio
async def test_crawl_enriches_rows(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    pages = {A: "<html><title>Acme Market</title><body>vendor escrow shop</body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=5, concurrency=1, per_host_delay=0)
    rules = {"marketplace": ["market", "vendor", "escrow"]}
    await crawl(cfg, db, FakeClient(pages), [A], "run3", "2026-07-21T00:00:00",
                rules=rules)
    row = db.get_url(A)
    assert row["title"] == "Acme Market"
    assert row["content_simhash"] is not None
    assert row["category"] == "marketplace"
    assert row["snippet"] and len(row["snippet"]) <= 500
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_discover.py -k enriches -v`
Expected: FAIL — `crawl() got an unexpected keyword argument 'rules'`

- [ ] **Step 3: Update `crawl` in `src/onionwatch/discover.py`**

Change the signature and the alive-branch enrichment:

```python
async def crawl(config, db, client, seeds, run_id, now, rules=None) -> RunStats:
    if rules is None:
        try:
            from .config import load_categories
            rules = load_categories("categories.toml")
        except FileNotFoundError:
            rules = {}
    ...
```

Add these imports near the top:

```python
from .fingerprint import simhash, to_hex
from .categorize import categorize
from .probe import extract_title
```

In `handle`, inside the `if res.ok and res.status and res.status < 400:` block, right after `alive += 1` and the initial upsert/update, add:

```python
            text = visible_text(res.html)
            snippet = text[: config.snippet_chars]
            cat = categorize(extract_title(res.html) or "", text, rules)
            import json as _json
            db.update_url(
                url,
                title=extract_title(res.html),
                snippet=snippet,
                content_simhash=to_hex(simhash(text)),
                category=cat.category,
                category_confidence=cat.confidence,
                matched_terms=_json.dumps(cat.matched_terms),
            )
```

- [ ] **Step 4: Run tests to verify pass**

Run: `.venv/bin/pytest tests/test_discover.py -v`
Expected: PASS (all discover tests, including enrichment)

- [ ] **Step 5: Create `README.md`**

```markdown
# onionwatch

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

Provide `seeds.txt` (one URL per line) and, for clone detection,
`verified_sources.toml` (both gitignored).

## Run with Docker (recommended)

    docker compose up -d tor
    docker compose run --rm onionwatch crawl
    docker compose run --rm onionwatch cluster
    docker compose run --rm onionwatch hunt --terms client.txt

## Run on host (uses your Tor on 127.0.0.1:9050)

Set `socks_proxy = "socks5://127.0.0.1:9050"` in `config.toml`, then:

    onionwatch crawl            # deep discovery + liveness + categorise + fingerprint
    onionwatch cluster          # original-vs-clone detection, trust levels
    onionwatch hunt --terms client.txt
    onionwatch export --format csv --trust verified --category leak-site
    onionwatch stats

Crawls are resumable: re-run `onionwatch crawl --resume` to continue the frontier.

## Pipeline

crawl → (fingerprint + categorise inline) → cluster → hunt

## Tests

    .venv/bin/pytest            # offline unit tests
    .venv/bin/pytest -m live    # opt-in live-Tor smoke tests
```

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/discover.py tests/test_discover.py README.md
git commit -m "feat: enrich crawl with title/snippet/simhash/category; add README"
```

---

### Task 14: Live-Tor smoke test (opt-in)

**Files:**
- Create: `tests/test_live.py`

**Interfaces:**
- Consumes: `Config`, `TorClient`.

- [ ] **Step 1: Write the live smoke test** — `tests/test_live.py`

```python
import pytest
from onionwatch.config import Config
from onionwatch.tor_client import TorClient

@pytest.mark.live
@pytest.mark.asyncio
async def test_live_fetch_check_tpo():
    # Tor Project's own onion (stable, safe to hit): check.torproject.org clearnet
    cfg = Config(socks_proxy="socks5://127.0.0.1:9050", max_retries=2,
                 request_timeout=45)
    async with TorClient(cfg) as client:
        res = await client.fetch("https://check.torproject.org/")
    assert res.ok
    assert res.status == 200
    assert "Congratulations" in res.html or "Tor" in res.html
```

- [ ] **Step 2: Verify it is skipped by default**

Run: `.venv/bin/pytest -v`
Expected: `test_live_fetch_check_tpo` shows as deselected/skipped (not run).

- [ ] **Step 3: Run it explicitly against live Tor (host Tor on 9050)**

Run: `.venv/bin/pytest -m live -v`
Expected: PASS if Tor is reachable on `127.0.0.1:9050`. (Confirms end-to-end routing.)

- [ ] **Step 4: Commit**

```bash
git add tests/test_live.py
git commit -m "test: opt-in live Tor smoke test"
```

---

## Self-Review

**Spec coverage check** — every spec section maps to a task:
- Docker + Tor → Task 12 (compose, Dockerfile, torrc). ✓
- Deep resumable BFS + safety caps → Task 5 (frontier, max_urls/time_budget/per_host_cap, stop reasons); frontier table Task 2. ✓
- Category-agnostic discovery → Task 5 (`extract_onion_links` enqueues all onions unconditionally). ✓
- Liveness → Task 5 (inline) + Task 6 (standalone probe). ✓
- Categorisation (keyword rules, snippet, offline recat) → Task 7 + Task 13 (inline) + `categorize` CLI (Task 12). ✓
- Fingerprint (simhash) → Task 8, wired in Task 13. ✓
- Verified anchor + PGP → Task 9. ✓
- Clone/original clustering + trust levels → Task 10. ✓
- Leak hunt over canonical trusted sites → Task 11 + `hunt` CLI. ✓
- Data model (urls/frontier/clusters/crawl_runs/leak_hits) → Task 2. ✓
- CLI surface (crawl/probe/categorize/cluster/hunt/export/stats) → Task 12. ✓
- Offline tests default, live opt-in → all tasks + Task 14. ✓

**Placeholder scan:** No TBD/TODO. The one typo risk in Task 10 (`cluster_rows`) is explicitly called out with a corrective step (Steps 3–4). No "add error handling"-style hand-waving.

**Type consistency:** `FetchResult` produced in Task 3, imported by Tasks 5/6/11/13/14. `Database` method names match across Tasks 2/5/6/10/11/12. `crawl(...)` signature extended in Task 13 with a defaulted `rules` param — earlier Task 5 callers stay valid. `categorize`→`CategoryResult`, `simhash`/`to_hex`/`from_hex`/`hamming`, `is_verified`, `canonical_trusted_urls` names are used consistently everywhere they appear.
