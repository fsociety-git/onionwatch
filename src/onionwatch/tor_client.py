from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass
import httpx
from .config import Config

@dataclass
class FetchResult:
    url: str
    status: int | None
    html: str
    elapsed_ms: int
    ok: bool

class TorClient:
    def __init__(self, config: Config, transport: httpx.BaseTransport | None = None):
        self.config = config
        kwargs = {
            "timeout": config.request_timeout,
            "headers": {"User-Agent": config.user_agent},
            "follow_redirects": True,
        }
        if transport is not None:
            kwargs["transport"] = transport          # test injection, no real proxy
        else:
            kwargs["proxy"] = config.socks_proxy      # route through Tor
        self._client = httpx.AsyncClient(**kwargs)

    async def __aenter__(self) -> "TorClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def fetch(self, url: str) -> FetchResult:
        start = time.monotonic()
        last_exc = None
        for attempt in range(self.config.max_retries):
            try:
                resp = await self._client.get(url)
                elapsed = int((time.monotonic() - start) * 1000)
                return FetchResult(url, resp.status_code, resp.text, elapsed, True)
            except (httpx.HTTPError, httpx.ConnectError) as exc:
                last_exc = exc
                # Don't sleep after the final attempt -- we're about to give up.
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(min(2 ** attempt, 10))
        elapsed = int((time.monotonic() - start) * 1000)
        return FetchResult(url, None, "", elapsed, False)
