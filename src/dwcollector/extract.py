from __future__ import annotations
import re

# canonical currency codes
_CUR_CODE = {"btc": "BTC", "xmr": "XMR", "monero": "XMR",
             "usd": "USD", "eur": "EUR", "gbp": "GBP"}
_CUR_SYM = {"₿": "BTC", "$": "USD", "€": "EUR", "£": "GBP"}

_NUM = r"\d[\d.,]*\d|\d"
_CODE = r"btc|xmr|monero|usd|eur|gbp"
_SYM = r"[₿$€£]"

# (compiled pattern, kind). Symbol patterns require the symbol IMMEDIATELY
# adjacent to the number (no space) to avoid matching a bare "$" in prose;
# code patterns allow an optional space ("0.05 BTC" / "BTC0.05").
_PATTERNS = [
    (re.compile(rf"(?P<sym>{_SYM})(?P<amt>{_NUM})"), "sym"),
    (re.compile(rf"(?P<amt>{_NUM})(?P<sym>{_SYM})"), "sym"),
    (re.compile(rf"\b(?P<code>{_CODE})\s?(?P<amt>{_NUM})", re.I), "code"),
    (re.compile(rf"(?P<amt>{_NUM})\s?(?P<code>{_CODE})\b", re.I), "code"),
]


def _parse_amount(s: str) -> float | None:
    s = s.strip()
    has_comma, has_dot = "," in s, "." in s
    try:
        if has_comma and has_dot:
            # the last-occurring separator is the decimal point
            if s.rfind(",") > s.rfind("."):
                s = s.replace(".", "").replace(",", ".")
            else:
                s = s.replace(",", "")
        elif has_comma:
            # comma-only: thousands if every group is <=3 digits and the last is
            # exactly 3; otherwise treat the comma as a decimal point
            frac = s.rsplit(",", 1)[-1]
            if len(frac) == 3 and all(len(p) <= 3 for p in s.split(",")):
                s = s.replace(",", "")
            else:
                s = s.replace(",", ".")
        return float(s)
    except ValueError:
        return None


def extract_listings(text: str, *, window: int, max_listings: int) -> list[dict]:
    if not text:
        return []
    hits = []  # (start, end, currency, raw, amt)
    for pat, kind in _PATTERNS:
        for m in pat.finditer(text):
            if kind == "sym":
                currency = _CUR_SYM[m.group("sym")]
            else:
                currency = _CUR_CODE[m.group("code").lower()]
            hits.append((m.start(), m.end(), currency, m.group(0), m.group("amt")))
    hits.sort(key=lambda h: h[0])
    records: list[dict] = []
    last_end = -1
    for start, end, currency, raw, amt in hits:
        if start < last_end:
            continue  # overlaps an already-accepted price token
        last_end = end
        ctx = text[max(0, start - window): end + window]
        records.append({
            "price_value": _parse_amount(amt),
            "currency": currency,
            "price_raw": raw.strip(),
            "product_text": " ".join(ctx.split()),
        })
        if len(records) >= max_listings:
            break
    return records
