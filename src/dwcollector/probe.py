from __future__ import annotations
from dataclasses import dataclass
from selectolax.parser import HTMLParser

@dataclass
class ProbeResult:
    url: str
    alive: bool
    status: int | None
    title: str | None
    response_ms: int

def extract_title(html: str) -> str | None:
    node = HTMLParser(html).css_first("title")
    if node and node.text():
        return node.text().strip() or None
    return None

async def probe_url(client, url: str) -> ProbeResult:
    res = await client.fetch(url)
    alive = bool(res.ok and res.status and res.status < 400)
    title = extract_title(res.html) if alive else None
    return ProbeResult(url, alive, res.status, title, res.elapsed_ms)

async def reprobe_all(db, client, now: str) -> int:
    alive_count = 0
    for row in db.all_urls():
        pr = await probe_url(client, row["url"])
        db.update_url(row["url"], alive=int(pr.alive), http_status=pr.status,
                      title=pr.title, response_ms=pr.response_ms, last_checked=now)
        alive_count += int(pr.alive)
    return alive_count
