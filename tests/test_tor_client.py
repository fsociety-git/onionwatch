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


@pytest.mark.asyncio
async def test_fetch_does_not_sleep_after_final_attempt(monkeypatch):
    # Fix 5: with max_retries attempts there should be exactly max_retries-1
    # backoff sleeps -- no wasted sleep after the last failed attempt.
    import dwcollector.tor_client as tc
    sleeps = []

    async def fake_sleep(secs):
        sleeps.append(secs)

    monkeypatch.setattr(tc.asyncio, "sleep", fake_sleep)

    def flaky(request):
        raise httpx.ConnectError("boom")

    cfg = Config(max_retries=3, request_timeout=5)
    async with TorClient(cfg, transport=httpx.MockTransport(flaky)) as client:
        await client.fetch("http://x.onion/")
    assert len(sleeps) == 2       # max_retries - 1, not 3
