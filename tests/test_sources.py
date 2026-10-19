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
async def test_harvest_isolates_parse_failure(monkeypatch):
    def boom(html, url):
        raise RuntimeError("parse exploded")

    monkeypatch.setattr("onionwatch.sources.extract_onion_links", boom)
    page = '<a href="http://aaaaaaaaaaaaaaaa.onion/">m</a>'
    sources = [{"name": "dir1", "type": "index", "url": "http://idx.onion/"}]
    out = await harvest(MapClient({"http://idx.onion/": page}), sources, cap=10)  # must not raise
    assert out == []


@pytest.mark.asyncio
async def test_harvest_caps_per_source():
    page = " ".join(f'<a href="http://{c*16}.onion/">x</a>' for c in "abcde")
    sources = [{"name": "d", "type": "index", "url": "http://i.onion/"}]
    out = await harvest(MapClient({"http://i.onion/": page}), sources, cap=2)
    assert len(out) == 2                                # 5 onions capped to 2 (deterministic via sort)
