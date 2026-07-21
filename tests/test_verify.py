from dwcollector.verify import is_verified, pgp_fingerprint_in_page, pgp_matches

VERIFIED = {
    "verified_onions": ["aaaaaaaaaaaaaaaa.onion"],
    "pgp": {"aaaaaaaaaaaaaaaa.onion": "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"},
    "directories": [],
}

def test_is_verified():
    assert is_verified("http://aaaaaaaaaaaaaaaa.onion/x", VERIFIED) is True
    assert is_verified("http://zzzzzzzzzzzzzzzz.onion/", VERIFIED) is False

def test_extract_pgp_fingerprint():
    page = "Our key: AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333 trust it"
    fp = pgp_fingerprint_in_page(page)
    assert fp == "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"

def test_pgp_matches():
    page = "key AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
    assert pgp_matches("http://aaaaaaaaaaaaaaaa.onion/", page, VERIFIED) is True
    assert pgp_matches("http://zzzzzzzzzzzzzzzz.onion/", page, VERIFIED) is False
