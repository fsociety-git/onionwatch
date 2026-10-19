from onionwatch.fingerprint import simhash, hamming, to_hex, from_hex

def test_identical_text_zero_distance():
    a = simhash("the quick brown fox jumps over the lazy dog")
    b = simhash("the quick brown fox jumps over the lazy dog")
    assert hamming(a, b) == 0

def test_near_duplicate_small_distance():
    a = simhash(
        "welcome to our marketplace where buyers and sellers meet safely to trade "
        "goods and services every single day our platform offers secure escrow "
        "payments verified vendor profiles and a simple rating system so that new "
        "members can quickly find trustworthy trading partners and enjoy a smooth "
        "shopping experience from start to finish"
    )
    b = simhash(
        "welcome to our marketplace where buyers and sellers meet safely to trade "
        "goods and services every single day our platform offers secure escrow "
        "payments verified vendor profiles and a simple rating system so that new "
        "members can quickly find trustworthy trading partners and enjoy a smooth "
        "shopping experience from start to finish today"
    )
    assert hamming(a, b) <= 6

def test_unrelated_large_distance():
    a = simhash("bitcoin monero wallet mixer tumbler crypto exchange")
    b = simhash("poetry recipes gardening travel photography journal blog")
    assert hamming(a, b) >= 12

def test_hex_roundtrip():
    a = simhash("some content here")
    assert from_hex(to_hex(a)) == a

# --- Fix 1: non-Latin pages must get real (non-zero, distinct) fingerprints ---

def test_non_latin_text_gets_nonzero_distinct_simhash():
    # Before the tokenizer was broadened to \w+, an all-Cyrillic or all-Chinese
    # page tokenized to nothing -> simhash 0 -> every such page collided into
    # one bogus hamming-0 cluster. They must now hash to distinct non-zero
    # fingerprints.
    cyr = simhash("продажа товаров и услуг маркетплейс форум сообщество здесь")
    chi = simhash("市场论坛社区在这里出售商品和服务欢迎来到我们的平台")
    assert cyr != 0
    assert chi != 0
    assert cyr != chi
