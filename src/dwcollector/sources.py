from __future__ import annotations
import sys
from urllib.parse import quote
from .discover import extract_onion_links


async def _fetch_onions(client, url: str) -> set[str]:
    """Fetch one url and return its extracted onion links; never raises."""
    try:
        res = await client.fetch(url)
    except Exception as exc:  # noqa: BLE001 - one bad fetch never aborts the harvest
        print(f"harvest: fetch failed {url}: {exc!r}", file=sys.stderr)
        return set()
    if res.ok and res.status and res.status < 400:
        return extract_onion_links(res.html, url)
    return set()


async def harvest(client, sources: list[dict], cap: int) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for src in sources:
        name = src.get("name") or src.get("type") or "source"
        try:
            found: set[str] = set()
            if src.get("type") == "index":
                found = await _fetch_onions(client, src["url"])
            elif src.get("type") == "search":
                for q in src.get("queries", []):
                    url = src["url_template"].format(query=quote(str(q), safe=""))
                    found |= await _fetch_onions(client, url)
            for url in sorted(found)[:cap]:      # sort -> deterministic cap
                if url in seen:
                    continue
                seen.add(url)
                out.append((url, name))
        except Exception as exc:  # noqa: BLE001 - one malformed source never aborts the harvest
            print(f"harvest: source {name!r} failed: {exc!r}", file=sys.stderr)
    return out
