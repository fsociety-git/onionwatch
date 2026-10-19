from onionwatch.extract import extract_listings


def test_detects_each_currency_and_arrangement():
    text = ("cocaine 0.05 BTC in stock | ledger dump XMR 1.5 | "
            "cvv pack $50 fresh | db €45.00 leaked | fullz 30 GBP")
    recs = extract_listings(text, window=20, max_listings=100)
    pairs = {(r["currency"], r["price_value"]) for r in recs}
    assert ("BTC", 0.05) in pairs
    assert ("XMR", 1.5) in pairs
    assert ("USD", 50.0) in pairs
    assert ("EUR", 45.0) in pairs
    assert ("GBP", 30.0) in pairs


def test_symbol_currency_normalization():
    recs = extract_listings("price ₿0.1 and £20 today", window=10, max_listings=10)
    got = {(r["currency"], r["price_value"]) for r in recs}
    assert ("BTC", 0.1) in got
    assert ("GBP", 20.0) in got


def test_bounds_product_text_window():
    text = "A" * 200 + " item 0.05 BTC " + "B" * 200
    recs = extract_listings(text, window=15, max_listings=10)
    assert len(recs) == 1
    pt = recs[0]["product_text"]
    assert "item" in pt and "0.05 BTC" in pt
    # window-bounded: nowhere near the full 400+ char text
    assert len(pt) <= 15 + len("0.05 BTC") + 15 + 5


def test_caps_at_max_listings():
    text = " ".join(f"{i} USD" for i in range(1, 20))
    recs = extract_listings(text, window=5, max_listings=3)
    assert len(recs) == 3


def test_no_prices_returns_empty():
    assert extract_listings("just some ordinary prose, no prices here", window=20, max_listings=10) == []
    assert extract_listings("", window=20, max_listings=10) == []


def test_bare_symbol_not_adjacent_is_ignored():
    # "$" not immediately followed by digits must not match; a real "$5" must
    recs = extract_listings("pay in $ currency, actual price $5 each", window=10, max_listings=10)
    assert [(r["currency"], r["price_value"]) for r in recs] == [("USD", 5.0)]


def test_price_raw_preserved_and_value_none_when_unparseable():
    recs = extract_listings("weird $1.2.3 tag", window=10, max_listings=10)
    assert len(recs) == 1
    assert recs[0]["currency"] == "USD"
    assert recs[0]["price_value"] is None       # unparseable amount
    assert recs[0]["price_raw"] == "$1.2.3"     # raw token always kept


def test_thousands_and_decimal_separators():
    # US-style 1,234.56 and EU-style 1.234,56 both -> 1234.56
    us = extract_listings("bulk $1,234.56 lot", window=5, max_listings=5)
    eu = extract_listings("bulk €1.234,56 lot", window=5, max_listings=5)
    assert us[0]["price_value"] == 1234.56
    assert eu[0]["price_value"] == 1234.56


def test_max_listings_zero_or_negative_returns_empty():
    text = "cheap $5 and $10 here"
    # max_listings=0 should return empty
    assert extract_listings(text, window=5, max_listings=0) == []
    # max_listings=-1 should return empty
    assert extract_listings(text, window=5, max_listings=-1) == []
    # Sanity check: max_listings=1 returns exactly 1 record
    recs = extract_listings(text, window=5, max_listings=1)
    assert len(recs) == 1
    assert recs[0]["currency"] == "USD"
    assert recs[0]["price_value"] == 5.0
