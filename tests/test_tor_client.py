import httpx
import pytest
from dwcollector.config import Config
from dwcollector.tor_client import TorClient

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
