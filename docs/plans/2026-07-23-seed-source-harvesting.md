# Broader Discovery — Seed-Source Harvesting — Implementation Plan


**Goal:** Broaden discovery by harvesting fresh seeds each cycle from operator-configured `.onion` index and category-search sources, fetched through the existing Tor client and enqueued as depth-0 source-tagged seeds.

**Architecture:** A new `sources.py` with one `harvest()` function fetches each configured source, extracts onion links (reusing `extract_onion_links`), and returns `(url, source_name)` pairs. `crawl()` gains a `sources` param and enqueues harvested onions at crawl start. Config carries a `sources.toml` (opt-in, default empty) and a `max_seeds_per_source` cap. The loop and manual crawl load and pass sources.

**Tech Stack:** Python 3.11+, stdlib + existing deps (selectolax via `extract_onion_links`), pytest + pytest-asyncio.

**Spec:** `docs/specs/2026-07-23-seed-source-harvesting-design.md`

## Global Constraints

- Python 3.11+; add no new third-party dependencies.
- **Opt-in:** sources default to empty (`sources.toml` missing → `[]`), so `crawl` with no sources is **byte-identical** to today's behavior — no harvest, no extra Tor load.
- **`harvest` never raises:** a per-source/per-query fetch or parse failure is caught, logged to stderr, and skipped; other sources/queries still contribute.
- All fetches go through the existing Tor client (sources are `.onion`). No clearnet path.
- Per-source `cap` bounds each source's contribution; **sort before capping** for deterministic selection.
- Reuse `extract_onion_links` / `normalize_url` / `onion_host` (all in `discover.py`) — no new parsing surface. `extract_onion_links` already returns normalized, onion-validated URLs.
- Harvested onions are enqueued as **depth-0** seeds, tagged in `urls.source` with the source `name` (distinct from `"seed"`/`"crawled"`).
- Follow existing test style: `pytest`, `@pytest.mark.asyncio`, in-repo stub clients returning `FetchResult(url, status, html, response_ms, ok)`.

---

### Task 1: `sources.py` — `harvest()`

**Files:**
- Create: `src/onionwatch/sources.py`
- Test: `tests/test_sources.py` (create)

**Interfaces:**
- Consumes: `extract_onion_links` (from `discover.py`), `FetchResult` (client contract).
- Produces: `harvest(client, sources: list[dict], cap: int) -> list[tuple[str, str]]` — `(onion_url, source_name)` pairs, deduped, capped per source, failure-isolated; module helper `_fetch_onions(client, url) -> set[str]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_sources.py`:

```python
import pytest
from onionwatch.sources import harvest
from onionwatch.tor_client import FetchResult


class MapClient:
    """Serves a per-url html; url not in the map -> unreachable FetchResult."""
    def __init__(self, pages): self.pages = pages
    async def fetch(self, url):
        if url in self.pages:
            return FetchResult(url, 200, self.pages[url], 10, True)
        return FetchResult(url, None, "", 10, False)


@pytest.mark.asyncio
async def test_harvest_index_extracts_and_tags():
    page = ('<a href="http://aaaaaaaaaaaaaaaa.onion/">m</a>'
            '<a href="http://bbbbbbbbbbbbbbbb.onion/">n</a>'
            '<a href="http://clearnet.example.com/">x</a>')
    sources = [{"name": "dir1", "type": "index", "url": "http://idx.onion/"}]
    out = await harvest(MapClient({"http://idx.onion/": page}), sources, cap=10)
    urls = [u for u, _ in out]
    assert any("aaaaaaaaaaaaaaaa.onion" in u for u in urls)
    assert any("bbbbbbbbbbbbbbbb.onion" in u for u in urls)
    assert not any("clearnet" in u for u in urls)        # non-onion filtered
    assert all(name == "dir1" for _, name in out)


@pytest.mark.asyncio
async def test_harvest_search_expands_queries_quoted():
    calls = []

    class RecClient:
        async def fetch(self, url):
            calls.append(url)
            return FetchResult(url, 200, '<a href="http://cccccccccccccccc.onion/">r</a>', 10, True)

    sources = [{"name": "s", "type": "search",
                "url_template": "http://srch.onion/search/?q={query}",
                "queries": ["market", "leak site"]}]
    out = await harvest(RecClient(), sources, cap=10)
    assert "http://srch.onion/search/?q=market" in calls
    assert "http://srch.onion/search/?q=leak%20site" in calls   # url-quoted
    assert any("cccccccccccccccc.onion" in u for u, _ in out)


@pytest.mark.asyncio
async def test_harvest_isolates_failure_and_dedups():
    page = '<a href="http://aaaaaaaaaaaaaaaa.onion/">m</a>'

    class C:
        async def fetch(self, url):
            if "bad" in url:
                raise RuntimeError("down")
            return FetchResult(url, 200, page, 10, True)

    sources = [
        {"name": "bad", "type": "index", "url": "http://bad.onion/"},
        {"name": "good1", "type": "index", "url": "http://g1.onion/"},
        {"name": "good2", "type": "index", "url": "http://g2.onion/"},
    ]
    out = await harvest(C(), sources, cap=10)          # must not raise
    urls = [u for u, _ in out]
    assert any("aaaaaaaaaaaaaaaa.onion" in u for u in urls)
    assert len(out) == 1                                # bad skipped; good1/good2 same onion deduped


@pytest.mark.asyncio
async def test_harvest_caps_per_source():
    page = " ".join(f'<a href="http://{c*16}.onion/">x</a>' for c in "abcde")
    sources = [{"name": "d", "type": "index", "url": "http://i.onion/"}]
    out = await harvest(MapClient({"http://i.onion/": page}), sources, cap=2)
    assert len(out) == 2                                # 5 onions capped to 2 (deterministic via sort)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_sources.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'onionwatch.sources'`

- [ ] **Step 3: Write minimal implementation**

Create `src/onionwatch/sources.py`:

```python
from __future__ import annotations
import sys
from urllib.parse import quote
from .discover import extract_onion_links


async def _fetch_onions(client, url: str) -> set[str]:
    """Fetch one url and return its extracted onion links; never raises."""
    try:
        res = await client.fetch(url)
    except Exception as exc:  # noqa: BLE001 - one bad fetch never aborts the harvest
        print(f"harvest: fetch failed {url}: {exc!r}", file=sys.stderr)
        return set()
    if res.ok and res.status and res.status < 400:
        return extract_onion_links(res.html, url)
    return set()


async def harvest(client, sources: list[dict], cap: int) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for src in sources:
        name = src.get("name") or src.get("type") or "source"
        try:
            found: set[str] = set()
            if src.get("type") == "index":
                found = await _fetch_onions(client, src["url"])
            elif src.get("type") == "search":
                for q in src.get("queries", []):
                    url = src["url_template"].format(query=quote(str(q), safe=""))
                    found |= await _fetch_onions(client, url)
            for url in sorted(found)[:cap]:      # sort -> deterministic cap
                if url in seen:
                    continue
                seen.add(url)
                out.append((url, name))
        except Exception as exc:  # noqa: BLE001 - one malformed source never aborts the harvest
            print(f"harvest: source {name!r} failed: {exc!r}", file=sys.stderr)
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_sources.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/sources.py tests/test_sources.py
git commit -m "feat: sources.harvest — fetch index/search onion sources for seeds"
```

---

### Task 2: Config — `load_sources` + `max_seeds_per_source`

**Files:**
- Modify: `src/onionwatch/config.py` (`Config`, add `load_sources`)
- Modify: `config.toml`
- Test: `tests/test_config.py` (append)

**Interfaces:**
- Consumes: `_read_toml` (existing).
- Produces: `Config.max_seeds_per_source: int = 200`; `config.load_sources(path="sources.toml") -> list[dict]` — parses `[[source]]` entries, validates, warns+skips malformed, missing file → `[]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
def test_max_seeds_per_source_default():
    from onionwatch.config import Config
    assert Config().max_seeds_per_source == 200


def test_load_sources_missing_file_returns_empty(tmp_path):
    from onionwatch.config import load_sources
    assert load_sources(str(tmp_path / "nope.toml")) == []


def test_load_sources_parses_and_skips_malformed(tmp_path, capsys):
    from onionwatch.config import load_sources
    p = tmp_path / "sources.toml"
    p.write_text(
        '[[source]]\n'
        'name = "idx"\n'
        'type = "index"\n'
        'url = "http://i.onion/"\n\n'
        '[[source]]\n'
        'name = "srch"\n'
        'type = "search"\n'
        'url_template = "http://s.onion/?q={query}"\n'
        'queries = ["market"]\n\n'
        '[[source]]\n'          # malformed: index with no url
        'name = "bad"\n'
        'type = "index"\n'
    )
    srcs = load_sources(str(p))
    assert {s["name"] for s in srcs} == {"idx", "srch"}
    assert "bad" in capsys.readouterr().err
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py::test_max_seeds_per_source_default -v`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'max_seeds_per_source'`

- [ ] **Step 3: Write minimal implementation**

Add to the `Config` dataclass in `src/onionwatch/config.py` (after `pii_detectors`):

```python
    max_seeds_per_source: int = 200
```

Add the loader (near `load_verified_sources`):

```python
def load_sources(path: str = "sources.toml") -> list[dict]:
    try:
        data = _read_toml(path)
    except FileNotFoundError:
        return []
    valid: list[dict] = []
    for i, s in enumerate(data.get("source", [])):
        name, typ = s.get("name"), s.get("type")
        ok = bool(name) and typ in ("index", "search")
        if ok and typ == "index":
            ok = bool(s.get("url"))
        if ok and typ == "search":
            tmpl = s.get("url_template") or ""
            ok = "{query}" in tmpl and bool(s.get("queries"))
        if ok:
            valid.append(s)
        else:
            print(f"sources: skipping malformed source entry #{i} "
                  f"({name or '?'})", file=sys.stderr)
    return valid
```

Append to `config.toml`:

```toml
# max onion seeds to take from each configured seed source per cycle
max_seeds_per_source = 200
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/onionwatch/config.py config.toml tests/test_config.py
git commit -m "feat: load_sources + max_seeds_per_source config"
```

---

### Task 3: Integrate harvest into `crawl()`

**Files:**
- Modify: `src/onionwatch/discover.py` (`crawl`)
- Test: `tests/test_discover.py` (append)

**Interfaces:**
- Consumes: `harvest` (Task 1), `Config.max_seeds_per_source` (Task 2), `db.upsert_url`/`db.enqueue`, `onion_host`.
- Produces: `crawl(config, db, client, seeds, run_id, now, rules=None, sources=None)` — when `sources` is non-empty, harvests and enqueues onions as depth-0 seeds tagged with source name before draining; `sources=None`/empty → unchanged.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_discover.py` (imports: `Config`, `Database`, `crawl`, `FetchResult`, `pytest` — mirror the file's existing imports):

```python
class _MapClient:
    def __init__(self, pages): self.pages = pages
    async def fetch(self, url):
        if url in self.pages:
            return FetchResult(url, 200, self.pages[url], 10, True)
        return FetchResult(url, None, "", 10, False)


@pytest.mark.asyncio
async def test_crawl_harvests_sources_as_depth0_seeds(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    page = '<a href="http://aaaaaaaaaaaaaaaa.onion/">m</a>'
    client = _MapClient({"http://idx.onion/": page})
    sources = [{"name": "dir1", "type": "index", "url": "http://idx.onion/"}]
    cfg = Config(max_urls=0, time_budget_min=60, per_host_delay=0)   # stop drain immediately; harvest runs first
    await crawl(cfg, db, client, [], "run1", "2026-07-23T00:00:00", rules={}, sources=sources)
    rows = db.all_urls()
    assert any(r["source"] == "dir1" and "aaaaaaaaaaaaaaaa.onion" in r["url"]
               and r["depth"] == 0 for r in rows)
    assert db.count_frontier("pending") >= 1     # enqueued


@pytest.mark.asyncio
async def test_crawl_no_sources_unchanged(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    client = _MapClient({})
    cfg = Config(max_urls=0, time_budget_min=60, per_host_delay=0)
    await crawl(cfg, db, client, [], "run1", "2026-07-23T00:00:00", rules={}, sources=None)
    assert db.all_urls() == []                    # nothing harvested
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_discover.py::test_crawl_harvests_sources_as_depth0_seeds -v`
Expected: FAIL — `crawl()` has no `sources` kwarg (`TypeError`)

- [ ] **Step 3: Write minimal implementation**

In `src/onionwatch/discover.py`, change the `crawl` signature to add `sources=None`:

```python
async def crawl(config, db, client, seeds, run_id, now, rules=None, sources=None) -> RunStats:
```

Immediately after the two `db.reset_state(...)` recovery calls and before `db.start_run(...)` / the `seeds` loop, add:

```python
    if sources:
        from .sources import harvest          # lazy: sources.py imports from discover
        for url, name in await harvest(client, sources, config.max_seeds_per_source):
            db.upsert_url(url, onion_host(url) or "", name, 0, now)
            db.enqueue(url, 0)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_discover.py -v`
Expected: PASS (new tests + existing discover tests unchanged)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green (existing crawl callers pass no `sources` → default `None` → unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/discover.py tests/test_discover.py
git commit -m "feat: crawl harvests configured seed sources as depth-0 seeds"
```

---

### Task 4: Loop wiring — `run_cycle` + `_run_crawl` load and pass sources

**Files:**
- Modify: `src/onionwatch/cli.py` (import, `_run_crawl`, `run_cycle`)
- Test: `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `load_sources` (Task 2), `crawl` with `sources` (Task 3).
- Produces: `_run_crawl` and `run_cycle` load `sources = load_sources("sources.toml")` and pass `sources=sources` into their `crawl`/`crawl_fn` call.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli.py` (`SimpleNamespace`, `Config`, `Database` already imported from earlier tasks; add `import onionwatch.cli as cli_mod` locally):

```python
def test_run_cycle_passes_sources_to_crawl(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(watchlist_terms=str(tmp_path / "none.txt"),
                 alerts_path=str(tmp_path / "a.jsonl"))
    src = [{"name": "s", "type": "index", "url": "http://i.onion/"}]
    monkeypatch.setattr(cli_mod, "load_sources", lambda path: src)
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "pgp": {}, "directories": []})

    recorded = {}

    def crawl_stub(cfg, db, client, seeds, run_id, now, sources=None, **k):
        recorded["sources"] = sources
        return SimpleNamespace(discovered=0, alive=0, stop_reason="ok")

    class _Stub:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch(self, url): return None

    res = run_cycle(cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
                    crawl_fn=crawl_stub, cluster_fn=lambda *a, **k: 0,
                    client_factory=lambda cfg: _Stub())
    assert res["ok"] is True
    assert recorded["sources"] == src


def test_run_crawl_passes_sources(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config()
    src = [{"name": "s", "type": "index", "url": "http://i.onion/"}]
    monkeypatch.setattr(cli_mod, "load_sources", lambda path: src)
    seeds_file = tmp_path / "seeds.txt"; seeds_file.write_text("")
    recorded = {}

    async def crawl_stub(cfg, db, client, seeds, run_id, now, sources=None, **k):
        recorded["sources"] = sources
        return SimpleNamespace(discovered=0, alive=0, stop_reason="ok")

    class _Stub:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch(self, url): return None

    monkeypatch.setattr(cli_mod, "crawl", crawl_stub)
    monkeypatch.setattr(cli_mod, "TorClient", lambda cfg: _Stub())
    args = SimpleNamespace(resume=False, seeds=str(seeds_file))
    cli_mod._run_crawl(cfg, db, args)
    assert recorded["sources"] == src
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py::test_run_cycle_passes_sources_to_crawl -v`
Expected: FAIL — `run_cycle` doesn't load/pass sources (`recorded["sources"]` is `None`/KeyError)

- [ ] **Step 3: Write minimal implementation**

In `src/onionwatch/cli.py`, ensure `load_sources` is imported (it's in `config.py`):

```python
from .config import load_config, load_categories, load_verified_sources, load_sources
```

In `_run_crawl`, load sources and pass them:

```python
def _run_crawl(cfg, db, args):
    seeds = [] if args.resume else _read_seeds(args.seeds)
    sources = load_sources("sources.toml")

    async def go():
        async with TorClient(cfg) as client:
            stats = await crawl(cfg, db, client, seeds,
                                 f"run-{_now()}", _now(), sources=sources)
            print(f"discovered={stats.discovered} alive={stats.alive} "
                  f"stop={stats.stop_reason}")
    asyncio.run(go())
```

In `run_cycle`'s crawl block, load sources and pass to `crawl_fn`:

```python
    try:
        seeds = _read_seeds(seeds_path)
        sources = load_sources("sources.toml")

        async def go():
            async with client_factory(cfg) as client:
                out = crawl_fn(cfg, db, client, seeds,
                               f"run-{_now()}", _now(), sources=sources)
                if inspect.isawaitable(out):
                    out = await out
                return out
        ...
```

(Keep the rest of the crawl block — `stats = asyncio.run(go())`, the `result["crawl"]` assignment, and the `except` — unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: PASS (new wiring tests + existing run_cycle/crawl tests — the injected `crawl_fn` stubs already accept `**k`, so the added `sources=` kwarg is absorbed)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/onionwatch/cli.py tests/test_cli.py
git commit -m "feat: run_cycle and crawl CLI load and pass seed sources"
```

---

### Task 5: Docs — `sources.toml.example` + README

**Files:**
- Create: `sources.toml.example`
- Modify: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Create `sources.toml.example`**

Create `sources.toml.example`:

```toml
# Seed sources harvested each crawl cycle (all fetched through Tor).
# Copy to sources.toml and fill in real .onion addresses. Empty/absent = disabled.
#
# type = "index":  fetch the page and enqueue every onion link it contains.
# type = "search": fetch url_template once per query keyword and enqueue the
#                  onion links from each results page ({query} is url-encoded).

# [[source]]
# name = "ahmia-index"
# type = "index"
# url  = "http://<ahmia-onion-address>.onion/onions/"

# [[source]]
# name = "ahmia-search"
# type = "search"
# url_template = "http://<ahmia-onion-address>.onion/search/?q={query}"
# queries = ["market", "leak", "shop", "forum", "carding"]
```

- [ ] **Step 2: Document seed-source harvesting in README**

Add a "Seed sources (broader discovery)" subsection to `README.md` near the crawl/discovery content covering: that `sources.toml` (default absent = off) lists `.onion` **index** and **search** sources harvested each cycle through Tor; index = mine a directory page's onion links, search = query a search index (e.g. Ahmia's onion mirror) by category keyword; harvested onions become depth-0 seeds tagged with the source name; the `max_seeds_per_source` cap; that harvesting is failure-isolated (a down source is skipped) and fully opt-in; and the Tor-only limitation (clearnet sources are not supported).

- [ ] **Step 3: Verify suite green and commit**

Run: `pytest -q`
Expected: all green (docs-only change).

```bash
git add README.md sources.toml.example
git commit -m "docs: document seed-source harvesting"
```

---

## Final verification

- [ ] Run the full suite: `pytest -q` — expect all prior tests plus the new ones green.
- [ ] Smoke harvest offline:
  `python -c "import asyncio; from onionwatch.sources import harvest; from onionwatch.tor_client import FetchResult"` then exercise `harvest` with a stub client serving an onion-linked page — expect `(url, name)` pairs.
- [ ] Confirm `crawl` with no `sources.toml` is unchanged (existing crawl tests green) and `git log --oneline` shows one commit per task with a clean tree.
