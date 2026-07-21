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

import pytest
from dwcollector.config import Config
from dwcollector.db import Database
from dwcollector.discover import crawl, FetchResult  # FetchResult re-exported for typing

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
