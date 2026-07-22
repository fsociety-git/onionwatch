import pytest
from dwcollector.hunt import match_terms, hunt
from dwcollector.tor_client import FetchResult
from dwcollector.db import Database

def test_match_terms_returns_context():
    text = "leak of acme corp dataset including admin@acme.com and more records"
    hits = match_terms(text, ["admin@acme.com", "acme corp"], ctx=10)
    terms = {t for t, _ in hits}
    assert "admin@acme.com" in terms and "acme corp" in terms
    for _, ctx in hits:
        assert len(ctx) <= 10 + 40  # roughly bounded

def test_match_terms_no_hit():
    assert match_terms("nothing here", ["secret"]) == []

def test_match_terms_regex_prefix_matches_pattern():
    text = "leak dump reached admin@acme.com in the payload"
    hits = match_terms(text, [r"re:admin@\w+\.com"], ctx=10)
    assert len(hits) == 1
    term, ctx = hits[0]
    assert term == r"re:admin@\w+\.com"
    assert "admin@acme.com" in ctx
    assert len(ctx) <= 10 + len("admin@acme.com") + 10

def test_match_terms_literal_term_does_not_match_as_regex():
    # "a.b.com" contains a regex metachar ('.') but must be matched literally,
    # so it should NOT match "axbxcom" (which a regex "." would match).
    hits = match_terms("axbxcom should not match", ["a.b.com"])
    assert hits == []
    hits2 = match_terms("contact a.b.com for details", ["a.b.com"])
    assert len(hits2) == 1
    assert hits2[0][0] == "a.b.com"

def test_match_terms_invalid_regex_is_skipped_not_raised():
    text = "admin@acme.com appears here and so does secretword"
    # "re:[unclosed" is an invalid pattern and must be silently skipped,
    # while the other literal term still matches.
    hits = match_terms(text, ["re:[unclosed", "secretword"])
    terms = {t for t, _ in hits}
    assert "re:[unclosed" not in terms
    assert "secretword" in terms

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

class DeadSiteClient:
    """Simulates a fetch failure / non-ok response (e.g. site is down)."""
    def __init__(self, html):
        self.html = html  # would match if it were ever scanned

    async def fetch(self, url):
        return FetchResult(url, 500, self.html, 10, False)

@pytest.mark.asyncio
async def test_hunt_skips_dead_site_records_no_hit(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://dead.onion/"
    db.upsert_url(u, "dead.onion", "crawled", 1, "2026-07-21T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site")
    html = "<html><body>dump contains admin@acme.com today</body></html>"
    n = await hunt(db, DeadSiteClient(html), ["admin@acme.com"], "run1", "2026-07-21T00:00:00")
    assert n == 0
    hits = list(db.conn.execute("SELECT term, url FROM leak_hits"))
    assert hits == []
