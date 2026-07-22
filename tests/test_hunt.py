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
