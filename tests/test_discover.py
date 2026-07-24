from dwcollector.discover import (
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
      raw mention: qwertyuiopasdfgh.onion/page
    '''
    links = extract_onion_links(html, ONION + "/")
    assert f"{ONION}/dir" in links
    assert f"{ONION}/x" in links
    assert any("qwertyuiopasdfgh.onion" in u for u in links)
    assert all(".onion" in u for u in links)

def test_visible_text_strips_tags():
    txt = visible_text("<html><body><h1>Bitcoin</h1><p>market</p></body></html>")
    assert "Bitcoin" in txt and "market" in txt
    assert "<" not in txt

import asyncio
from collections import defaultdict

import pytest
from dwcollector.config import Config
from dwcollector.db import Database
from dwcollector.discover import crawl, onion_host, FetchResult  # FetchResult re-exported for typing

class FakeClient:
    """Returns canned HTML per URL; unknown URLs 404."""
    def __init__(self, pages):
        self.pages = pages
    async def fetch(self, url):
        from dwcollector.tor_client import FetchResult as FR
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


# --- Fix 2: per-URL exception isolation -------------------------------------

@pytest.mark.asyncio
async def test_crawl_isolates_per_url_exceptions(tmp_path):
    """One URL raising inside handle() must not abort the whole crawl."""
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    B = "http://bbbbbbbbbbbbbbbb.onion/"

    class BoomClient:
        async def fetch(self, url):
            from dwcollector.tor_client import FetchResult as FR
            if url == A:
                raise RuntimeError("boom: malformed page")
            return FR(url, 200, "", 1, True)

    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=10, concurrency=2, per_host_delay=0)
    stats = await crawl(cfg, db, BoomClient(), [A, B], "run_boom", "2026-07-21T00:00:00")

    # crawl must reach a normal stop reason (i.e. finish_run ran, run wasn't stranded)
    assert stats.stop_reason in ("frontier_empty", "max_urls", "time_budget")

    row_a = db.conn.execute(
        "SELECT state FROM frontier WHERE url=?", (A,)).fetchone()
    row_b = db.conn.execute(
        "SELECT state FROM frontier WHERE url=?", (B,)).fetchone()
    assert row_a["state"] == "failed"
    assert row_b["state"] == "done"   # other URL in the batch still processed


# --- Fix 3: per-host cap concurrency race -------------------------------------

@pytest.mark.asyncio
async def test_crawl_per_host_cap_is_atomic_under_concurrency(tmp_path):
    """The cap check+increment must be atomic (no await between them), so a
    batch of same-host URLs cannot all sneak past the cap before any of them
    increment the counter."""
    HOST = "cccccccccccccccc.onion"
    A = f"http://{HOST}/"
    children = [f"http://{HOST}/p{i}" for i in range(6)]
    pages = {A: "".join(f'<a href="{c}">c</a>' for c in children)}
    for c in children:
        pages[c] = ""

    class RacyClient:
        """Like FakeClient, but yields control (await asyncio.sleep(0)) inside
        fetch() so concurrently-gathered handle() coroutines truly interleave —
        this is what exposes a non-atomic check-then-increment race."""
        def __init__(self, pages):
            self.pages = pages
            self.fetch_count = defaultdict(int)

        async def fetch(self, url):
            from dwcollector.tor_client import FetchResult as FR
            host = onion_host(url)
            await asyncio.sleep(0)
            self.fetch_count[host] += 1
            html = self.pages.get(url, "")
            return FR(url, 200, html, 1, True)

    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=100, concurrency=6, per_host_delay=0, per_host_page_cap=2)
    client = RacyClient(pages)
    await crawl(cfg, db, client, [A], "run_race", "2026-07-21T00:00:00")

    assert client.fetch_count[HOST] <= cfg.per_host_page_cap


# --- Fix 4: cap-skipped URLs must be retryable across runs -------------------

@pytest.mark.asyncio
async def test_capped_url_marked_deferred_not_done(tmp_path):
    HOST = "dddddddddddddddd.onion"
    A = f"http://{HOST}/"
    B = f"http://{HOST}/b"
    pages = {A: f'<a href="{B}">b</a>', B: ""}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=10, concurrency=4, per_host_delay=0, per_host_page_cap=1)
    await crawl(cfg, db, FakeClient(pages), [A], "run_cap", "2026-07-21T00:00:00")

    row = db.conn.execute("SELECT state FROM frontier WHERE url=?", (B,)).fetchone()
    assert row["state"] == "deferred"


@pytest.mark.asyncio
async def test_deferred_url_retried_on_next_crawl(tmp_path):
    HOST = "eeeeeeeeeeeeeeee.onion"
    A = f"http://{HOST}/"
    B = f"http://{HOST}/b"
    pages = {A: f'<a href="{B}">b</a>', B: ""}
    db = Database(str(tmp_path / "t.db")); db.init_schema()

    cfg_capped = Config(max_urls=10, concurrency=4, per_host_delay=0, per_host_page_cap=1)
    await crawl(cfg_capped, db, FakeClient(pages), [A], "run_defer_a", "2026-07-21T00:00:00")
    row = db.conn.execute("SELECT state FROM frontier WHERE url=?", (B,)).fetchone()
    assert row["state"] == "deferred"

    # fresh crawl, higher per-host budget: previously deferred URL gets a fresh
    # per-host budget and is actually processed this time (no re-seeding needed)
    cfg_open = Config(max_urls=10, concurrency=4, per_host_delay=0, per_host_page_cap=1000)
    await crawl(cfg_open, db, FakeClient(pages), [], "run_defer_b", "2026-07-21T01:00:00")

    row2 = db.conn.execute("SELECT state FROM frontier WHERE url=?", (B,)).fetchone()
    assert row2["state"] == "done"
    url_row = db.get_url(B)
    assert url_row["alive"] == 1


@pytest.mark.asyncio
async def test_capped_seed_still_gets_url_row(tmp_path):
    """Minor fix: a seed skipped by the cap on its own first attempt must still
    have a row in `urls` (upserted at enqueue time, not only after a fetch)."""
    HOST = "ffffffffffffffff.onion"
    A = f"http://{HOST}/"
    B = f"http://{HOST}/other"
    pages = {A: "", B: ""}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=10, concurrency=4, per_host_delay=0, per_host_page_cap=1)
    await crawl(cfg, db, FakeClient(pages), [A, B], "run_seedcap", "2026-07-21T00:00:00")

    assert db.get_url(A) is not None
    assert db.get_url(B) is not None


# --- Task 13: enrichment (title/snippet/simhash/category) persisted ---------

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


# --- Fix 2: PGP fingerprint extracted from page text and persisted ----------

@pytest.mark.asyncio
async def test_crawl_populates_pgp_fingerprint(tmp_path):
    """A crawled alive page whose visible text contains a PGP fingerprint must
    have that fingerprint persisted (canonicalized 40-hex) on its url row, so
    the validated-PGP canonical tier has something to check against."""
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    fp_shown = "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333"
    pages = {A: f"<html><body><p>Contact key: {fp_shown}</p></body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=5, concurrency=1, per_host_delay=0)
    await crawl(cfg, db, FakeClient(pages), [A], "run_pgp", "2026-07-21T00:00:00")
    row = db.get_url(A)
    assert row["pgp_fingerprint"] == "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"


@pytest.mark.asyncio
async def test_crawl_pgp_fingerprint_none_when_absent(tmp_path):
    """No fingerprint in the page -> pgp_fingerprint stays NULL (not a stray)."""
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    pages = {A: "<html><body><p>just some ordinary market text</p></body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=5, concurrency=1, per_host_delay=0)
    await crawl(cfg, db, FakeClient(pages), [A], "run_nopgp", "2026-07-21T00:00:00")
    row = db.get_url(A)
    assert row["pgp_fingerprint"] is None


@pytest.mark.asyncio
async def test_crawl_pgp_fingerprint_marks_canonical_via_pgp_tier(tmp_path):
    """End-to-end: a crawled page's extracted fingerprint, when it matches
    verified['pgp'] for that host, lets run_clustering mark it canonical via
    the pgp tier with trust 'probable'."""
    from dwcollector.cluster import run_clustering
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    fp_shown = "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333"
    pages = {A: f"<html><body><p>PGP: {fp_shown}</p></body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=5, concurrency=1, per_host_delay=0)
    await crawl(cfg, db, FakeClient(pages), [A], "run_pgp2", "2026-07-21T00:00:00")
    verified = {"verified_onions": [],
                "pgp": {"aaaaaaaaaaaaaaaa.onion": fp_shown}}
    run_clustering(db, verified, distance=3)
    row = db.get_url(A)
    assert row["is_canonical"] == 1
    assert row["trust"] == "probable"


# --- Task 13: crash recovery — in_progress frontier rows are retried --------

@pytest.mark.asyncio
async def test_in_progress_url_retried_on_next_crawl(tmp_path):
    """Simulate a crawler process killed mid-fetch: the frontier row is stuck
    in 'in_progress' (next_pending() sets that state before the fetch even
    starts). A fresh crawl process must reset such orphaned rows back to
    'pending' and actually process them, not leave them stranded forever."""
    HOST = "gggggggggggggggg.onion"
    A = f"http://{HOST}/"
    pages = {A: "<html><title>Recovered</title><body>content</body></html>"}
    db = Database(str(tmp_path / "t.db")); db.init_schema()

    # Simulate the crashed prior run: row exists and is stuck in_progress.
    db.upsert_url(A, HOST, "seed", 0, "2026-07-21T00:00:00")
    db.enqueue(A, 0)
    db.next_pending(10)  # flips state to 'in_progress', as a real crawl would
    row = db.conn.execute("SELECT state FROM frontier WHERE url=?", (A,)).fetchone()
    assert row["state"] == "in_progress"

    cfg = Config(max_urls=10, concurrency=1, per_host_delay=0)
    await crawl(cfg, db, FakeClient(pages), [], "run_recover", "2026-07-21T01:00:00")

    row2 = db.conn.execute("SELECT state FROM frontier WHERE url=?", (A,)).fetchone()
    assert row2["state"] == "done"
    url_row = db.get_url(A)
    assert url_row["alive"] == 1


# --- Task 3: harvest sources as depth-0 seeds --------------------------------

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


# --- Task 3: propagate parent-category priority into the crawl frontier ----

@pytest.mark.asyncio
async def test_crawl_child_inherits_parent_category_priority(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    B = "http://bbbbbbbbbbbbbbbb.onion/"
    # A categorizes as marketplace; it links B
    pages = {A: f'<html><title>Shop</title><body>market vendor escrow '
                f'<a href="{B}">b</a></body></html>'}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=1, concurrency=1, per_host_delay=0,        # fetch A only
                 crawl_priority={"marketplace": 100})
    rules = {"marketplace": ["market", "vendor", "escrow"]}
    await crawl(cfg, db, FakeClient(pages), [A], "run_pri", "2026-07-24T00:00:00",
                rules=rules)
    # B is still pending (A was the only fetch) and carries the parent's weight
    row = db.conn.execute(
        "SELECT state, priority FROM frontier WHERE url=?", (B,)).fetchone()
    assert row["state"] == "pending"
    assert row["priority"] == 100


@pytest.mark.asyncio
async def test_crawl_seed_uses_default_priority(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=0, concurrency=1, per_host_delay=0,        # don't drain
                 crawl_priority={"default": 7})
    await crawl(cfg, db, FakeClient({A: ""}), [A], "run_seed", "2026-07-24T00:00:00",
                rules={})
    row = db.conn.execute(
        "SELECT priority FROM frontier WHERE url=?", (A,)).fetchone()
    assert row["priority"] == 7


@pytest.mark.asyncio
async def test_crawl_no_priority_config_children_zero(tmp_path):
    A = "http://aaaaaaaaaaaaaaaa.onion/"
    B = "http://bbbbbbbbbbbbbbbb.onion/"
    pages = {A: f'<html><body>market vendor <a href="{B}">b</a></body></html>'}
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(max_urls=1, concurrency=1, per_host_delay=0)        # no crawl_priority
    rules = {"marketplace": ["market", "vendor"]}
    await crawl(cfg, db, FakeClient(pages), [A], "run_zero", "2026-07-24T00:00:00",
                rules=rules)
    row = db.conn.execute(
        "SELECT priority FROM frontier WHERE url=?", (B,)).fetchone()
    assert row["priority"] == 0                                      # unchanged BFS
