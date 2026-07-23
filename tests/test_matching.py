import base64
from dwcollector.matching import Match, normalize_defang, encodings_of, luhn_valid, iban_valid, ssn_valid


def test_match_dataclass_defaults():
    m = Match(kind="literal", key="acme.com", context="...acme.com...")
    assert m.count == 1 and m.masked_sample is None


def test_normalize_defang_bracket_and_word_forms():
    assert normalize_defang("acme[.]com") == "acme.com"
    assert normalize_defang("acme(dot)com") == "acme.com"
    assert normalize_defang("acme . com") == "acme.com"
    assert normalize_defang("acme dot com") == "acme.com"
    assert normalize_defang("billing at acme.com") == "billing@acme.com"
    assert normalize_defang("billing[@]acme.com") == "billing@acme.com"


def test_normalize_defang_zero_width_and_case_and_homoglyph():
    assert normalize_defang("ac​me.COM") == "acme.com"       # zero-width + case
    assert normalize_defang("аcme.com") == "acme.com"        # cyrillic 'а' -> 'a'


def test_encodings_of_contains_expected_forms():
    encs = encodings_of("SECRET-KEY")
    raw = b"SECRET-KEY"
    assert base64.b64encode(raw).decode() in encs                 # padded std b64
    assert base64.b64encode(raw).decode().rstrip("=") in encs     # unpadded
    assert raw.hex() in encs and raw.hex().upper() in encs        # hex both cases
    assert "SECRET-KEY" not in encs                               # plain value excluded


def test_encodings_of_found_in_text():
    val = "acme-corp.com"
    blob = "dump line: " + base64.b64encode(val.encode()).decode() + " ;next"
    assert any(e in blob for e in encodings_of(val))


def test_luhn_valid():
    assert luhn_valid("4111111111111111")      # known-valid Visa test number
    assert not luhn_valid("4111111111111112")  # bad check digit
    assert not luhn_valid("1234")              # too short
    assert not luhn_valid("abcd111111111111")  # non-digit


def test_iban_valid():
    assert iban_valid("GB82 WEST 1234 5698 7654 32")   # valid UK test IBAN
    assert not iban_valid("GB00WEST12345698765432")    # bad checksum
    assert not iban_valid("nonsense")


def test_ssn_valid():
    assert ssn_valid("536-90-4399")
    assert not ssn_valid("000-12-3456")    # area 000
    assert not ssn_valid("666-12-3456")    # area 666
    assert not ssn_valid("900-12-3456")    # area 9xx
    assert not ssn_valid("123-00-4567")    # group 00
    assert not ssn_valid("123456789")      # wrong format
