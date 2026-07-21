from __future__ import annotations
import re
from .discover import onion_host

# 40-hex-char PGP v4 fingerprint, usually shown as 10 groups of 4 hex chars
_FP_GROUP = re.compile(r"\b(?:[0-9A-Fa-f]{4}[ ]{1,2}){9}[0-9A-Fa-f]{4}\b")

def _canon_fp(raw: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", raw).upper()

def is_verified(url: str, verified: dict) -> bool:
    host = onion_host(url)
    return host in set(verified.get("verified_onions", []))

def pgp_fingerprint_in_page(text: str) -> str | None:
    m = _FP_GROUP.search(text)
    return _canon_fp(m.group(0)) if m else None

def pgp_matches(url: str, page_text: str, verified: dict) -> bool:
    host = onion_host(url)
    expected = verified.get("pgp", {}).get(host)
    if not expected:
        return False
    got = pgp_fingerprint_in_page(page_text)
    return got is not None and got == _canon_fp(expected)
