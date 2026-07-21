from dwcollector.fingerprint import simhash, hamming, to_hex, from_hex

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
