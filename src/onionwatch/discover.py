from __future__ import annotations
import asyncio
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit
from selectolax.parser import HTMLParser
from .tor_client import FetchResult  # re-export for tests/typing
from .fingerprint import simhash, to_hex
from .categorize import categorize
from .config import priority_for
from .extract import extract_listings
from .probe import extract_title

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

async def crawl(config, db, client, seeds, run_id, now, rules=None, sources=None) -> RunStats:
    # Imported lazily to avoid a discover<->verify import cycle (verify imports
    # onion_host from this module at load time).
    from .verify import pgp_fingerprint_in_page

    if rules is None:
        try:
            from .config import load_categories
            rules = load_categories("categories.toml")
        except FileNotFoundError:
            rules = {}

    # Retry URLs that were skipped by a per-host cap in a previous run, now
    # that this run starts with a fresh per-host budget. Must happen before
    # seeding/processing so the reset rows are eligible via next_pending().
    db.reset_state("deferred", "pending")
    # 24/7 crash recovery: a previous crawler process may have been killed
    # (OOM, host reboot, container restart) after next_pending() flipped a
    # frontier row to 'in_progress' but before it was ever marked
    # 'done'/'failed'/'deferred'. Such rows would otherwise be stranded
    # forever, since next_pending() only selects state='pending'. Reset them
    # so this run retries them. Safe because the deployment model is a single
    # crawler process at a time -- there is no concurrently-running crawl
    # whose legitimately-in-flight rows this could steal.
    db.reset_state("in_progress", "pending")
    seed_priority = config.crawl_priority.get("default", 0)

    if sources:
        from .sources import harvest          # lazy: sources.py imports from discover
        for url, name in await harvest(client, sources, config.max_seeds_per_source, delay=config.per_host_delay):
            db.upsert_url(url, onion_host(url) or "", name, 0, now)
            db.enqueue(url, 0, seed_priority)

    db.start_run(run_id, now, len(seeds))
    for s in seeds:
        seed_url = normalize_url(s)
        # Upsert now (not only after a successful fetch) so a seed that gets
        # skipped by the per-host cap on its first attempt still has a row.
        db.upsert_url(seed_url, onion_host(seed_url) or "", "seed", 0, now)
        db.enqueue(seed_url, 0, seed_priority)
    host_pages: dict[str, int] = defaultdict(int)
    processed = 0
    alive = 0
    deadline = time.monotonic() + config.time_budget_min * 60
    stop_reason = "frontier_empty"

    async def handle(row):
        nonlocal alive
        url, depth = row["url"], row["depth"]
        host = None
        try:
            host = onion_host(url)
            if host:
                # Reserve the per-host slot atomically: check-and-increment
                # with no `await` between them, so concurrently-gathered
                # same-host URLs cannot all pass the check before any of
                # them registers its increment.
                if host_pages[host] >= config.per_host_page_cap:
                    # Retryable in a future run once the per-host budget
                    # resets — never mark a cap-skipped URL "done".
                    db.mark_frontier(url, "deferred")
                    return
                host_pages[host] += 1

            res = await client.fetch(url)
            if config.per_host_delay:
                await asyncio.sleep(config.per_host_delay)

            if res.ok and res.status and res.status < 400:
                alive += 1
                db.upsert_url(url, host or "", "crawled", depth, now)
                db.update_url(url, alive=1, http_status=res.status, last_checked=now)
                text = visible_text(res.html)
                snippet = text[: config.snippet_chars]
                title = extract_title(res.html)
                cat = categorize(title or "", text, rules)
                db.update_url(
                    url,
                    title=title,
                    snippet=snippet,
                    content_simhash=to_hex(simhash(text)),
                    category=cat.category,
                    category_confidence=cat.confidence,
                    matched_terms=json.dumps(cat.matched_terms),
                    pgp_fingerprint=pgp_fingerprint_in_page(text),
                )
                if config.extract_listings and cat.category in config.listing_categories:
                    db.replace_listings(url, host or "",
                        extract_listings(text, window=config.listing_window,
                                         max_listings=config.max_listings_per_page), now)
                child_priority = priority_for(cat.category, config.crawl_priority)
                if config.max_depth == 0 or depth < config.max_depth:
                    for link in extract_onion_links(res.html, url):
                        if db.get_url(link) is None:
                            db.upsert_url(link, onion_host(link) or "", "crawled",
                                          depth + 1, now)
                            db.enqueue(link, depth + 1, child_priority)
            else:
                db.upsert_url(url, host or "", "crawled", depth, now)
                db.update_url(url, alive=0, http_status=res.status, last_checked=now)
            db.mark_frontier(url, "done")
        except Exception:
            # Never let one bad page (e.g. a malformed page crashing link
            # extraction) abort the whole crawl. Isolate it, record it, move on.
            db.upsert_url(url, host or "", "crawled", depth, now)
            db.update_url(url, alive=0, last_checked=now)
            db.mark_frontier(url, "failed")

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
