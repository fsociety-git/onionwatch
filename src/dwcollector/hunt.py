from __future__ import annotations
import re
from .discover import visible_text

def load_terms(path: str) -> list[str]:
    terms = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return terms

def match_terms(text: str, terms: list[str], ctx: int = 60) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for term in terms:
        for m in re.finditer(re.escape(term), text, re.IGNORECASE):
            start = max(0, m.start() - ctx)
            end = min(len(text), m.end() + ctx)
            hits.append((term, text[start:end].strip()))
    return hits

async def hunt(db, client, terms: list[str], run_id: str, now: str) -> int:
    count = 0
    for row in db.canonical_trusted_urls():
        res = await client.fetch(row["url"])
        if not (res.ok and res.status and res.status < 400):
            continue
        text = visible_text(res.html)
        for term, ctx in match_terms(text, terms):
            db.record_leak_hit(
                run_id, row["url"], row["host"], row.get("category"),
                row.get("trust"), term, ctx, now)
            count += 1
    return count
