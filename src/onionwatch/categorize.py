from __future__ import annotations
import re
from dataclasses import dataclass

@dataclass
class CategoryResult:
    category: str
    confidence: float
    matched_terms: list[str]

def categorize(title: str, text: str, rules: dict[str, list[str]]) -> CategoryResult:
    haystack = f"{title} {text}".lower()
    per_category: dict[str, list[str]] = {}
    total = 0
    for category, terms in rules.items():
        hits = []
        for term in terms:
            if re.search(r"\b" + re.escape(term.lower()) + r"\b", haystack):
                hits.append(term)
        if hits:
            per_category[category] = hits
            total += len(hits)
    if not per_category:
        return CategoryResult("unknown", 0.0, [])
    # winner: most matches; ties -> first declared (dict preserves insertion order)
    winner = max(per_category, key=lambda c: len(per_category[c]))
    matched = per_category[winner]
    confidence = round(len(matched) / total, 3)
    return CategoryResult(winner, confidence, matched)
