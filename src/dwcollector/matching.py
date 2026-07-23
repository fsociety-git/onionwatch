from __future__ import annotations
import base64
import re
from dataclasses import dataclass
from urllib.parse import quote


@dataclass
class Match:
    kind: str                       # literal | regex | fuzzy | encoded | credential | pii
    key: str                        # underlying identifier, or 'pii:<detector>'
    context: str                    # evidence snippet (masked for pii/credential)
    count: int = 1
    masked_sample: str | None = None


_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿"), None)
# small homoglyph confusables fold (Cyrillic -> Latin lookalikes)
_CONFUSABLES = str.maketrans({
    "а": "a", "о": "o", "е": "e",
    "р": "p", "с": "c", "х": "x",
})
_DOT = re.compile(r"\[\.\]|\(\.\)|\(dot\)|\s+dot\s+", re.IGNORECASE)
_AT = re.compile(r"\[@\]|\(@\)|\(at\)|\s+at\s+", re.IGNORECASE)
_AROUND = re.compile(r"\s*([.@])\s*")


def normalize_defang(s: str) -> str:
    s = s.translate(_ZERO_WIDTH).translate(_CONFUSABLES)
    s = _DOT.sub(".", s)
    s = _AT.sub("@", s)
    s = _AROUND.sub(r"\1", s)
    return s.casefold()


def encodings_of(value: str) -> list[str]:
    raw = value.encode("utf-8")
    out: set[str] = set()
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        b = enc(raw).decode("ascii")
        out.add(b)
        out.add(b.rstrip("="))
    h = raw.hex()
    out.add(h)
    out.add(h.upper())
    out.add(quote(value, safe=""))
    out.discard(value)
    return [e for e in out if e]


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)  # A->10 ... Z->35
    return int(digits) % 97 == 1


def ssn_valid(s: str) -> bool:
    m = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", s)
    if not m:
        return False
    area, group, serial = m.groups()
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _mask_card(raw: str) -> str:
    d = _digits(raw)
    return "•••• •••• •••• " + d[-4:]


def _mask_ssn(raw: str) -> str:
    return "•••-••-" + raw[-4:]


def _mask_iban(raw: str) -> str:
    s = raw.replace(" ", "")
    return "•" * max(0, len(s) - 4) + s[-4:]


_DETECTORS = {
    "credit-card": {
        "regex": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        "normalize": _digits,
        "validate": luhn_valid,
        "mask": _mask_card,
    },
    "iban": {
        "regex": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        "normalize": lambda m: m.replace(" ", ""),
        "validate": iban_valid,
        "mask": _mask_iban,
    },
    "us-ssn": {
        "regex": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "normalize": lambda m: m,
        "validate": ssn_valid,
        "mask": _mask_ssn,
    },
}


def available_detectors() -> list[str]:
    return list(_DETECTORS)


def run_detectors(text: str, names: list[str]) -> list[Match]:
    out: list[Match] = []
    for name in names:
        spec = _DETECTORS.get(name)
        if spec is None:
            continue
        count = 0
        sample = None
        for m in spec["regex"].finditer(text):
            raw = m.group(0)
            try:
                if not spec["validate"](spec["normalize"](raw)):
                    continue
            except Exception:  # noqa: BLE001 - one bad candidate never aborts the scan
                continue
            count += 1
            if sample is None:
                sample = spec["mask"](raw)
        if count:
            out.append(Match(kind="pii", key=f"pii:{name}",
                             context=sample or "", count=count, masked_sample=sample))
    return out
