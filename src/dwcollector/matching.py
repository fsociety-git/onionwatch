from __future__ import annotations
import re
from dataclasses import dataclass


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
