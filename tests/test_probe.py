import pytest
from dwcollector.db import Database
from dwcollector.probe import extract_title, probe_url, reprobe_all
from dwcollector.tor_client import FetchResult

class OneShot:
    def __init__(self, res): self.res = res
    async def fetch(self, url): return self.res

class ByUrl:
    def __init__(self, results): self.results = results
    async def fetch(self, url): return self.results[url]

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

@pytest.mark.asyncio
async def test_reprobe_all_updates_real_db(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    db.init_schema()
    db.upsert_url("http://alive.onion/", "alive.onion", "seed", 0, "2026-07-21T00:00:00")
    db.upsert_url("http://dead.onion/", "dead.onion", "seed", 0, "2026-07-21T00:00:00")

    client = ByUrl({
        "http://alive.onion/": FetchResult(
            "http://alive.onion/", 200, "<title>Alive Site</title>", 50, True),
        "http://dead.onion/": FetchResult("http://dead.onion/", None, "", 60000, False),
    })

    alive_count = await reprobe_all(db, client, "2026-07-21T00:00:00")

    assert alive_count == 1

    alive_row = db.get_url("http://alive.onion/")
    assert alive_row["alive"] == 1
    assert alive_row["http_status"] == 200
    assert alive_row["title"] == "Alive Site"
    assert alive_row["last_checked"] == "2026-07-21T00:00:00"

    dead_row = db.get_url("http://dead.onion/")
    assert dead_row["alive"] == 0
    assert dead_row["http_status"] is None
