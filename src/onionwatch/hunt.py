from __future__ import annotations
import re
from dataclasses import dataclass
from .discover import visible_text
from .matching import find_matches
from .verify import is_pgp_anchor, pgp_matches

def load_terms(path: str) -> list[str]:
    terms = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return terms

REGEX_PREFIX = "re:"

def match_terms(text: str, terms: list[str], ctx: int = 60) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for term in terms:
        if term.startswith(REGEX_PREFIX):
            pattern = term[len(REGEX_PREFIX):]
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
        else:
            compiled = re.compile(re.escape(term), re.IGNORECASE)
        for m in compiled.finditer(text):
            start = max(0, m.start() - ctx)
            end = min(len(text), m.end() + ctx)
            hits.append((term, text[start:end].strip()))
    return hits

@dataclass
class HuntOutcome:
    hit_count: int
    covered_urls: set
    identity_checked: set
    identity_failed: set


async def hunt(db, client, terms: list[str], run_id: str, now: str,
               detectors=None, verified=None) -> HuntOutcome:
    detectors = detectors or []
    verified = verified or {}
    count = 0
    covered: set[str] = set()
    identity_checked: set[str] = set()
    identity_failed: set[str] = set()
    for row in db.canonical_trusted_urls():
        res = await client.fetch(row["url"])
        ok = bool(res.ok and res.status and res.status < 400)
        db.update_url(row["url"], alive=1 if ok else 0,
                      http_status=res.status, last_checked=now)
        if not ok:
            continue
        text = visible_text(res.html)
        if is_pgp_anchor(row, verified):
            identity_checked.add(row["url"])
            if not pgp_matches(row["url"], text, verified):
                identity_failed.add(row["url"])
                continue          # SAFETY CUTOUT: never search a compromised anchor
        covered.add(row["url"])
        for mt in find_matches(text, terms, detectors):
            db.record_leak_hit(
                run_id, row["url"], row["host"], row.get("category"),
                row.get("trust"), mt.key, mt.context, now,
                match_kind=mt.kind, match_count=mt.count)
            count += 1
    return HuntOutcome(count, covered, identity_checked, identity_failed)
