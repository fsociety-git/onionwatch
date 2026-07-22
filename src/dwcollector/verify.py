from __future__ import annotations
import re
from .discover import onion_host

# 40-hex-char PGP v4 fingerprint, usually shown as 10 groups of 4 hex chars
_FP_GROUP = re.compile(r"\b(?:[0-9A-Fa-f]{4}[ ]{1,2}){9}[0-9A-Fa-f]{4}\b")

# A candidate match is ambiguous (part of a LONGER grouped-hex run) if it is
# immediately preceded or followed by another complete 4-hex group. Checked
# via post-match validation rather than lookbehind, since Python `re`
# lookbehind must be fixed-width and the separator is variable-width (1-2
# spaces).
_HEX_GROUP_BEFORE = re.compile(r"\b[0-9A-Fa-f]{4}[ ]{1,2}\Z")
_HEX_GROUP_AFTER = re.compile(r"\A[ ]{1,2}[0-9A-Fa-f]{4}\b")

def canon_fp(raw: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", raw).upper()

def is_verified(url: str, verified: dict) -> bool:
    host = onion_host(url)
    return host in set(verified.get("verified_onions", []))

def pgp_fingerprint_matches(host: str, stored_fp: str | None, verified: dict) -> bool:
    """True only if stored_fp, canonicalized, equals verified['pgp'][host],
    canonicalized. Used to validate a row's claimed PGP fingerprint against
    the operator's known-good key before trusting it as a canonical tier."""
    if not stored_fp:
        return False
    expected = verified.get("pgp", {}).get(host)
    if not expected:
        return False
    return canon_fp(stored_fp) == canon_fp(expected)

def pgp_fingerprint_in_page(text: str) -> str | None:
    for m in _FP_GROUP.finditer(text):
        before, after = text[: m.start()], text[m.end() :]
        if _HEX_GROUP_BEFORE.search(before) or _HEX_GROUP_AFTER.search(after):
            # Ambiguous: this 10-group window is embedded in a longer
            # grouped-hex run. Fail closed rather than return a truncated
            # fingerprint.
            continue
        return canon_fp(m.group(0))
    return None

def pgp_matches(url: str, page_text: str, verified: dict) -> bool:
    host = onion_host(url)
    expected = verified.get("pgp", {}).get(host)
    if not expected:
        return False
    got = pgp_fingerprint_in_page(page_text)
    return got is not None and got == canon_fp(expected)
