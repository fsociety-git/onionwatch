from dwcollector.categorize import categorize

RULES = {
    "marketplace": ["market", "vendor", "escrow"],
    "forum": ["forum", "board", "thread"],
    "crypto": ["bitcoin", "monero", "wallet"],
}

def test_categorize_marketplace():
    r = categorize("Best Market", "vendor escrow shop", RULES)
    assert r.category == "marketplace"
    assert "market" in r.matched_terms and "vendor" in r.matched_terms
    assert 0 < r.confidence <= 1

def test_categorize_unknown():
    r = categorize("Hello", "just a personal page", RULES)
    assert r.category == "unknown"
    assert r.confidence == 0.0
    assert r.matched_terms == []

def test_categorize_tiebreak_is_insertion_order():
    # one match each for marketplace and forum -> marketplace wins (declared first)
    r = categorize("", "market forum", RULES)
    assert r.category == "marketplace"
