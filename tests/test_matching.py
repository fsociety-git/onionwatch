import base64
from dwcollector.matching import Match, normalize_defang, encodings_of


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
