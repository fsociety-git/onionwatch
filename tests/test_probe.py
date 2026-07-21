import pytest
from dwcollector.probe import extract_title, probe_url
from dwcollector.tor_client import FetchResult

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
