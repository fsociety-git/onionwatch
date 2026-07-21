from __future__ import annotations
import asyncio
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit
from selectolax.parser import HTMLParser
from .tor_client import FetchResult  # re-export for tests/typing

_ONION_RE = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.IGNORECASE)

def onion_host(url: str) -> str | None:
    host = urlsplit(url).netloc.lower() or url.lower()
    m = _ONION_RE.search(host)
    return m.group(0).lower() if m else None

def normalize_url(url: str) -> str:
    parts = urlsplit(url if "://" in url else "http://" + url)
    scheme = parts.scheme or "http"
    netloc = parts.netloc.lower()
    # collapse ../ and . segments
    segments: list[str] = []
    for seg in parts.path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segments:
                segments.pop()
        else:
            segments.append(seg)
    path = "/" + "/".join(segments)
    return urlunsplit((scheme, netloc, path, parts.query, ""))

def extract_onion_links(html: str, base_url: str) -> set[str]:
    found: set[str] = set()
    tree = HTMLParser(html)
    for node in tree.css("a[href]"):
        href = node.attributes.get("href") or ""
        absolute = urljoin(base_url, href)
        if onion_host(absolute):
            found.add(normalize_url(absolute))
    # raw-text mentions not inside hrefs
    for m in _ONION_RE.finditer(html):
        found.add(normalize_url("http://" + m.group(0).lower()))
    return found

def visible_text(html: str) -> str:
    tree = HTMLParser(html)
    for tag in tree.css("script, style"):
        tag.decompose()
    body = tree.body or tree.root
    return re.sub(r"\s+", " ", body.text(separator=" ")).strip() if body else ""

@dataclass
class RunStats:
    run_id: str
    discovered: int
    alive: int
    stop_reason: str

async def crawl(config, db, client, seeds, run_id, now) -> RunStats:
    db.start_run(run_id, now, len(seeds))
    for s in seeds:
        db.enqueue(normalize_url(s), 0)
    host_pages: dict[str, int] = defaultdict(int)
    processed = 0
    alive = 0
    deadline = time.monotonic() + config.time_budget_min * 60
    stop_reason = "frontier_empty"

    async def handle(row):
        nonlocal alive
        url, depth = row["url"], row["depth"]
        host = onion_host(url)
        if host and host_pages[host] >= config.per_host_page_cap:
            db.mark_frontier(url, "done")
            return
        res = await client.fetch(url)
        if config.per_host_delay:
            await asyncio.sleep(config.per_host_delay)
        if host:
            host_pages[host] += 1
        if res.ok and res.status and res.status < 400:
            alive += 1
            db.upsert_url(url, host or "", "crawled", depth, now)
            db.update_url(url, alive=1, http_status=res.status, last_checked=now)
            if config.max_depth == 0 or depth < config.max_depth:
                for link in extract_onion_links(res.html, url):
                    if db.get_url(link) is None:
                        db.upsert_url(link, onion_host(link) or "", "crawled",
                                      depth + 1, now)
                        db.enqueue(link, depth + 1)
        else:
            db.upsert_url(url, host or "", "crawled", depth, now)
            db.update_url(url, alive=0, http_status=res.status, last_checked=now)
        db.mark_frontier(url, "done")

    while True:
        if processed >= config.max_urls:
            stop_reason = "max_urls"; break
        if time.monotonic() >= deadline:
            stop_reason = "time_budget"; break
        batch = db.next_pending(config.concurrency)
        if not batch:
            stop_reason = "frontier_empty"; break
        await asyncio.gather(*(handle(r) for r in batch))
        processed += len(batch)

    discovered = len(db.all_urls())
    db.finish_run(run_id, now, discovered, alive, stop_reason)
    return RunStats(run_id, discovered, alive, stop_reason)
