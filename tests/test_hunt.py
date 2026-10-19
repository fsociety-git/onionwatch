import pytest
from onionwatch.hunt import match_terms, hunt
from onionwatch.tor_client import FetchResult
from onionwatch.db import Database
from onionwatch.matching import find_matches  # noqa: F401 (ensures module import path)

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
    outcome = await hunt(db, SiteClient(html), ["admin@acme.com"], "run1", "2026-07-21T00:00:00")
    assert outcome.hit_count == 1
    assert outcome.covered_urls == {u}
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
    outcome = await hunt(db, DeadSiteClient(html), ["admin@acme.com"], "run1", "2026-07-21T00:00:00")
    assert outcome.hit_count == 0
    assert outcome.covered_urls == set()
    hits = list(db.conn.execute("SELECT term, url FROM leak_hits"))
    assert hits == []

class FlakyClient:
    """Returns OK for allowed urls, a failed FetchResult otherwise."""
    def __init__(self, html, ok_urls):
        self.html = html; self.ok_urls = ok_urls
    async def fetch(self, url):
        if url in self.ok_urls:
            return FetchResult(url, 200, self.html, 10, True)
        return FetchResult(url, None, "", 10, False)

@pytest.mark.asyncio
async def test_hunt_covered_excludes_unreachable(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    good = "http://good.onion/"; bad = "http://bad.onion/"
    for h in (good, bad):
        db.upsert_url(h, h.split("//")[1].strip("/"), "crawled", 1, "2026-07-23T00:00:00")
        db.update_url(h, is_canonical=1, trust="verified", category="leak-site")
    html = "<html><body>admin@acme.com</body></html>"
    client = FlakyClient(html, ok_urls={good})
    outcome = await hunt(db, client, ["admin@acme.com"], "run1", "2026-07-23T00:00:00")
    assert outcome.covered_urls == {good}          # bad.onion was unreachable -> not covered
    assert outcome.hit_count == 1                      # only good.onion produced a hit


@pytest.mark.asyncio
async def test_hunt_records_fuzzy_and_pii(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://good.onion/"
    db.upsert_url(u, "good.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site")
    html = ("<html><body>leak of acme[.]com plus card 4111 1111 1111 1111"
            "</body></html>")
    outcome = await hunt(db, SiteClient(html), ["fuzzy:acme.com"],
                            "run1", "2026-07-23T00:00:00", detectors=["credit-card"])
    assert outcome.covered_urls == {u}
    rows = {(r["term"], r["match_kind"]) for r in db.leak_hits_for_run("run1")}
    assert ("acme.com", "fuzzy") in rows
    assert ("pii:credit-card", "pii") in rows
    # raw card digits never stored
    assert all("4111111111111111" not in (r["context_snippet"] or "")
               for r in db.leak_hits_for_run("run1"))


@pytest.mark.asyncio
async def test_hunt_defaults_no_detectors(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://good.onion/"
    db.upsert_url(u, "good.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site")
    outcome = await hunt(db, SiteClient("<html><body>acme.com</body></html>"),
                      ["acme.com"], "run1", "2026-07-23T00:00:00")
    row = db.leak_hits_for_run("run1")[0]
    assert row["term"] == "acme.com" and row["match_kind"] == "literal"


from onionwatch.hunt import HuntOutcome

FP = "1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678"  # 10 groups of 4 hex


def _add_anchor(db, url, host):
    db.upsert_url(url, host, "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(url, is_canonical=1, trust="verified", category="leak-site")


class MapClient:
    """Serves a per-url html; url not in the map -> unreachable FetchResult."""
    def __init__(self, pages): self.pages = pages
    async def fetch(self, url):
        if url in self.pages:
            return FetchResult(url, 200, self.pages[url], 10, True)
        return FetchResult(url, None, "", 10, False)


@pytest.mark.asyncio
async def test_hunt_updates_alive(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    up, down = "http://up.onion/", "http://down.onion/"
    _add_anchor(db, up, "up.onion"); _add_anchor(db, down, "down.onion")
    await hunt(db, MapClient({up: "<html><body>hi</body></html>"}), [], "run1", "2026-07-23T00:00:00")
    assert db.get_url(up)["alive"] == 1
    assert db.get_url(down)["alive"] == 0


@pytest.mark.asyncio
async def test_hunt_identity_failure_is_not_searched(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    _add_anchor(db, u, "aaaaaaaaaaaaaaaa.onion")
    verified = {"pgp": {"aaaaaaaaaaaaaaaa.onion": FP}, "verified_onions": [], "directories": []}
    # page is ALIVE and contains a watchlist term, but carries NO valid fingerprint
    bad = "<html><body>leak of admin@acme.com but wrong key here</body></html>"
    outcome = await hunt(db, MapClient({u: bad}), ["admin@acme.com"], "run1",
                         "2026-07-23T00:00:00", verified=verified)
    assert u in outcome.identity_checked and u in outcome.identity_failed
    assert u not in outcome.covered_urls               # safety cutout
    assert db.leak_hits_for_run("run1") == []          # NOT searched despite the term
    assert db.get_url(u)["alive"] == 1                 # it is alive, just not trusted


@pytest.mark.asyncio
async def test_hunt_identity_ok_is_searched(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    _add_anchor(db, u, "aaaaaaaaaaaaaaaa.onion")
    verified = {"pgp": {"aaaaaaaaaaaaaaaa.onion": FP}, "verified_onions": [], "directories": []}
    ok = f"<html><body>key {FP} — leak of admin@acme.com</body></html>"
    outcome = await hunt(db, MapClient({u: ok}), ["admin@acme.com"], "run1",
                         "2026-07-23T00:00:00", verified=verified)
    assert u in outcome.identity_checked and u not in outcome.identity_failed
    assert u in outcome.covered_urls
    assert outcome.hit_count == 1


@pytest.mark.asyncio
async def test_hunt_allowlist_anchor_liveness_only(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    _add_anchor(db, u, "aaaaaaaaaaaaaaaa.onion")
    verified = {"pgp": {}, "verified_onions": ["aaaaaaaaaaaaaaaa.onion"], "directories": []}
    outcome = await hunt(db, MapClient({u: "<html><body>hi acme.com</body></html>"}),
                         ["acme.com"], "run1", "2026-07-23T00:00:00", verified=verified)
    assert u not in outcome.identity_checked           # no fingerprint to check
    assert u in outcome.covered_urls                   # still searched
    assert outcome.hit_count == 1
