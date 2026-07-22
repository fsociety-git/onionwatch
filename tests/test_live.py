import pytest
from dwcollector.config import Config
from dwcollector.tor_client import TorClient

@pytest.mark.live
@pytest.mark.asyncio
async def test_live_fetch_check_tpo():
    # Tor Project's own onion (stable, safe to hit): check.torproject.org clearnet
    cfg = Config(socks_proxy="socks5://127.0.0.1:9050", max_retries=2,
                 request_timeout=45)
    async with TorClient(cfg) as client:
        res = await client.fetch("https://check.torproject.org/")
    assert res.ok
    assert res.status == 200
    assert "Congratulations" in res.html or "Tor" in res.html
