import base64
from onionwatch.matching import Match, normalize_defang, encodings_of, luhn_valid, iban_valid, ssn_valid, available_detectors, run_detectors, match_term


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


def test_available_detectors():
    names = available_detectors()
    assert {"credit-card", "iban", "us-ssn"} <= set(names)


def test_run_detectors_aggregates_and_masks_cards():
    text = "cards: 4111 1111 1111 1111 and 5555555555554444 plus junk 1234567890123456"
    ms = run_detectors(text, ["credit-card"])
    assert len(ms) == 1
    m = ms[0]
    assert m.key == "pii:credit-card" and m.kind == "pii"
    assert m.count == 2                              # two Luhn-valid; the junk one fails
    assert "1111111111111111" not in (m.masked_sample or "")   # raw never stored
    assert "1111111111111111" not in m.context
    assert m.masked_sample.endswith("1111")         # last-4 retained


def test_run_detectors_unknown_name_skipped():
    assert run_detectors("536-90-4399", ["not-a-detector"]) == []


def test_run_detectors_no_false_positive_without_validation():
    # 16 digits but not Luhn-valid -> no card finding
    assert run_detectors("order 1234567890123456 shipped", ["credit-card"]) == []


def test_run_detectors_finds_contiguous_iban():
    # GB82WEST12345698765432 is a valid UK test IBAN (contiguous, no spaces).
    assert iban_valid("GB82WEST12345698765432")
    text = "wire to iban GB82WEST12345698765432 today"
    ms = run_detectors(text, ["iban"])
    assert len(ms) == 1
    m = ms[0]
    assert m.key == "pii:iban" and m.kind == "pii"
    assert m.count == 1
    raw = "GB82WEST12345698765432"
    assert raw not in (m.masked_sample or "")
    assert raw not in m.context
    assert (m.masked_sample or "").endswith("5432")  # last-4 retained


def test_run_detectors_iban_does_not_swallow_trailing_token():
    # Regression guard: the IBAN regex must not greedily cross a space into a
    # following all-caps token (e.g. "SWIFT"). Detection must still fire once
    # for the contiguous IBAN, and the trailing word must not be absorbed.
    text = "pay GB82WEST12345698765432 SWIFT WESTGB2L done"
    ms = run_detectors(text, ["iban"])
    assert len(ms) == 1
    m = ms[0]
    assert m.key == "pii:iban" and m.kind == "pii"
    assert m.count == 1
    # masked sample corresponds to the 22-char IBAN only: 18 mask chars + last-4
    assert m.masked_sample == "•" * 18 + "5432"
    assert "SWIFT" not in (m.masked_sample or "")


def test_run_detectors_aggregates_and_masks_ssns():
    text = "ssns: 536-90-4399 and 457-55-5462 but not 000-12-3456"
    ms = run_detectors(text, ["us-ssn"])
    assert len(ms) == 1
    m = ms[0]
    assert m.key == "pii:us-ssn" and m.kind == "pii"
    assert m.count == 2                              # two valid; the invalid one (area 000) fails
    assert "536-90-4399" not in (m.masked_sample or "")
    assert "457-55-5462" not in (m.masked_sample or "")
    assert (m.masked_sample or "").startswith("•••-••-")


def test_match_term_literal_and_key():
    ms = match_term("leak has acme.com inside", ["acme.com"][0])
    assert len(ms) == 1 and ms[0].kind == "literal" and ms[0].key == "acme.com"


def test_match_term_regex_invalid_skipped():
    assert match_term("x", "re:[unclosed") == []


def test_match_term_regex_key_keeps_full_prefixed_term():
    # Backward compat: the pre-feature match_terms path recorded a regex hit's
    # term as the full "re:PATTERN" string. Findings dedup on (url, term), so
    # the Match.key here must stay the full prefixed term, not the stripped
    # pattern, or upgrades will spuriously reopen/resolve existing findings.
    ms = match_term("leak ACME-CUST-DB here", "re:ACME-[A-Z]+-DB")
    assert len(ms) == 1
    assert ms[0].kind == "regex"
    assert ms[0].key == "re:ACME-[A-Z]+-DB"


def test_match_term_fuzzy_matches_obfuscated_and_keys_on_identifier():
    ms = match_term("found acme[.]com in the paste", "fuzzy:acme.com")
    assert len(ms) == 1
    assert ms[0].kind == "fuzzy" and ms[0].key == "acme.com"
    assert "acme.com" in ms[0].context           # snippet is from normalized text


def test_match_term_encoded():
    import base64
    val = "acme-corp.com"
    text = "row " + base64.b64encode(val.encode()).decode() + " end"
    ms = match_term(text, "enc:" + val)
    assert len(ms) >= 1 and ms[0].kind == "encoded" and ms[0].key == val


def test_match_term_credential_pair_masks_secret():
    ms = match_term("dump: billing@acme.com:SuperSecret1 more", "cred:billing@acme.com")
    assert len(ms) == 1 and ms[0].kind == "credential" and ms[0].key == "billing@acme.com"
    assert "SuperSecret1" not in ms[0].context   # secret never stored
    assert "•" in ms[0].context


def test_match_term_credential_requires_secret():
    # bare identifier with no credential structure -> no credential match
    assert match_term("email billing@acme.com listed", "cred:billing@acme.com") == []


def test_match_term_empty_prefixed_value_skipped():
    assert match_term("anything", "fuzzy:") == []


def test_match_term_empty_re_pattern():
    assert match_term("anything at all", "re:") == []


def test_match_term_empty_term():
    assert match_term("anything at all", "") == []


from onionwatch.matching import find_matches


def test_find_matches_mixes_terms_and_detectors():
    text = "acme.com leaked; card 4111111111111111 too"
    ms = find_matches(text, ["acme.com"], ["credit-card"])
    kinds = {m.kind for m in ms}
    keys = {m.key for m in ms}
    assert "literal" in kinds and "pii" in kinds
    assert "acme.com" in keys and "pii:credit-card" in keys


def test_find_matches_literal_and_fuzzy_same_identifier_share_key():
    text = "here acme.com and also acme[.]com appear"
    ms = find_matches(text, ["acme.com", "fuzzy:acme.com"], [])
    # both techniques resolve to the same underlying identifier key
    assert {m.key for m in ms} == {"acme.com"}


from onionwatch.matching import underlying_key


def test_underlying_key_strips_prefixes_but_keeps_re_and_literal():
    assert underlying_key("acme.com") == "acme.com"          # literal unchanged
    assert underlying_key("fuzzy:acme.com") == "acme.com"    # fuzzy stripped
    assert underlying_key("enc:SECRET") == "SECRET"          # enc stripped
    assert underlying_key("cred:u@x.com") == "u@x.com"       # cred stripped
    assert underlying_key("re:ACME-[A-Z]+") == "re:ACME-[A-Z]+"  # re: kept (matches finding key)
