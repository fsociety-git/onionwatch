from onionwatch.verify import is_verified, pgp_fingerprint_in_page, pgp_matches

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


# --- Fix A: must not over-match a longer grouped-hex run (fail closed) ---

def test_extract_pgp_fingerprint_rejects_ambiguous_longer_run():
    # 13 groups of 4 hex chars = 52 hex chars, not a real 40-char fingerprint.
    # Must NOT silently truncate to the first 10 groups.
    page = (
        "Our key: AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333 "
        "4444 5555 6666 trust it"
    )
    assert pgp_fingerprint_in_page(page) is None


def test_extract_pgp_fingerprint_still_works_with_double_space():
    page = "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
    assert pgp_fingerprint_in_page(page) == "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"


# --- Fix B: negative / fail-closed path tests ---

def test_extract_pgp_fingerprint_returns_none_when_absent():
    assert pgp_fingerprint_in_page("no fingerprint here") is None


def test_is_verified_missing_verified_onions_key_returns_false():
    assert is_verified("http://aaaaaaaaaaaaaaaa.onion/", {}) is False


def test_pgp_matches_missing_pgp_key_returns_false():
    verified = {"verified_onions": ["aaaaaaaaaaaaaaaa.onion"]}
    page = "key AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
    assert pgp_matches("http://aaaaaaaaaaaaaaaa.onion/", page, verified) is False


def test_pgp_matches_false_when_host_not_in_pgp_dict():
    verified = {"verified_onions": [], "pgp": {}}
    page = "key AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
    assert pgp_matches("http://aaaaaaaaaaaaaaaa.onion/", page, verified) is False


def test_pgp_matches_false_when_page_has_no_fingerprint():
    page = "no fingerprint here at all"
    assert pgp_matches("http://aaaaaaaaaaaaaaaa.onion/", page, VERIFIED) is False


def test_pgp_matches_false_when_fingerprint_differs():
    page = "key FFFF EEEE DDDD CCCC BBBB  AAAA 3333 2222 1111 0000"
    assert pgp_matches("http://aaaaaaaaaaaaaaaa.onion/", page, VERIFIED) is False


from onionwatch.verify import is_pgp_anchor


def test_is_pgp_anchor():
    verified = {"pgp": {"aaaaaaaaaaaaaaaa.onion": "AAAA BBBB"}, "verified_onions": []}
    assert is_pgp_anchor({"url": "http://aaaaaaaaaaaaaaaa.onion/"}, verified) is True
    assert is_pgp_anchor({"url": "http://bbbbbbbbbbbbbbbb.onion/"}, verified) is False
    assert is_pgp_anchor({"url": "http://aaaaaaaaaaaaaaaa.onion/"}, {"pgp": {}}) is False
    assert is_pgp_anchor({"url": "http://aaaaaaaaaaaaaaaa.onion/"}, {}) is False
