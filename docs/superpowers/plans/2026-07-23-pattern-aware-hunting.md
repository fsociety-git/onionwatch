# Richer / Pattern-Aware Hunting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Broaden leak hunting beyond exact-substring matching to catch disguised identifiers (defang, encoding, credential-pairs) and structured PII (card/IBAN/SSN), feeding every richer match through the existing `leak_hits → reconcile_leaks → finding → alert` pipeline.

**Architecture:** A new pure-logic module `matching.py` exposes `find_matches(text, terms, detectors, ctx) -> list[Match]`, built from small independently-tested helpers (defang normalizer, encoders, PII validators/detectors, per-term matchers). `hunt()` calls it instead of `match_terms`. Two additive `leak_hits` columns carry `match_kind`/`match_count`. The alert engine is untouched except a `pii:`-aware branch in `_title`/`_body`.

**Tech Stack:** Python 3.11+, stdlib only (base64, binascii, re, unicodedata, urllib.parse), pytest.

**Spec:** `docs/superpowers/specs/2026-07-23-pattern-aware-hunting-design.md`

## Global Constraints

- Python 3.11+; **stdlib only** — add no third-party dependencies.
- Bare literal terms and the `re:` prefix behave **exactly as today** — all richer matching is opt-in (per-term prefix or an enabled detector). `pii_detectors` defaults to empty.
- **Never store raw PII or credential secrets** — only masked samples/counts. This is a hard rule; a test must assert the raw value is absent from what's stored.
- Prefix grammar: no prefix = literal; `re:` = regex; `fuzzy:` = defang; `enc:` = encoded; `cred:` = credential-pair.
- `Match.key` is the **underlying identifier** (prefix stripped) for identifier techniques, or `pii:<detector>` for PII — so literal + fuzzy of the same identifier dedup to one finding downstream.
- Fuzzy evidence snippet comes from the **normalized** text (no original-index mapping).
- Timestamps UTC `"%Y-%m-%dT%H:%M:%S"` (unchanged; passed through).
- Follow existing test style: `pytest`, `@pytest.mark.asyncio` for async, `Database(str(tmp_path / "t.db"))`, in-repo stub clients returning `FetchResult(url, status, html, response_ms, ok)`.

---

### Task 1: `matching.py` scaffold — `Match` + `normalize_defang`

**Files:**
- Create: `src/dwcollector/matching.py`
- Test: `tests/test_matching.py` (create)

**Interfaces:**
- Produces: `Match` dataclass (`kind, key, context, count=1, masked_sample=None`); `normalize_defang(s: str) -> str`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_matching.py`:

```python
from dwcollector.matching import Match, normalize_defang


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_matching.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'dwcollector.matching'`

- [ ] **Step 3: Write minimal implementation**

Create `src/dwcollector/matching.py`:

```python
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass
class Match:
    kind: str                       # literal | regex | fuzzy | encoded | credential | pii
    key: str                        # underlying identifier, or 'pii:<detector>'
    context: str                    # evidence snippet (masked for pii/credential)
    count: int = 1
    masked_sample: str | None = None


_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍﻿"), None)
# small homoglyph confusables fold (Cyrillic -> Latin lookalikes)
_CONFUSABLES = str.maketrans({
    "а": "a", "о": "o", "е": "e",
    "р": "p", "с": "c", "х": "x",
})
_DOT = re.compile(r"\[\.\]|\(\.\)|\(dot\)|\s+dot\s+", re.IGNORECASE)
_AT = re.compile(r"\[@\]|\(@\)|\(at\)|\s+at\s+", re.IGNORECASE)
_AROUND = re.compile(r"\s*([.@])\s*")


def normalize_defang(s: str) -> str:
    s = s.translate(_ZERO_WIDTH).translate(_CONFUSABLES)
    s = _DOT.sub(".", s)
    s = _AT.sub("@", s)
    s = _AROUND.sub(r"\1", s)
    return s.casefold()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_matching.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/matching.py tests/test_matching.py
git commit -m "feat: matching.py scaffold with Match and normalize_defang"
```

---

### Task 2: Encoders — `encodings_of`

**Files:**
- Modify: `src/dwcollector/matching.py`
- Test: `tests/test_matching.py` (append)

**Interfaces:**
- Produces: `encodings_of(value: str) -> list[str]` — base64 (std+urlsafe, padded+unpadded), hex (lower+upper), URL percent-encoding; excludes any encoding equal to the plain value.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_matching.py`:

```python
import base64
from dwcollector.matching import encodings_of


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_matching.py::test_encodings_of_contains_expected_forms -v`
Expected: FAIL — `ImportError: cannot import name 'encodings_of'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/dwcollector/matching.py` (imports at top: `import base64` and `from urllib.parse import quote`):

```python
def encodings_of(value: str) -> list[str]:
    raw = value.encode("utf-8")
    out: set[str] = set()
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        b = enc(raw).decode("ascii")
        out.add(b)
        out.add(b.rstrip("="))
    h = raw.hex()
    out.add(h)
    out.add(h.upper())
    out.add(quote(value, safe=""))
    out.discard(value)
    return [e for e in out if e]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_matching.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/matching.py tests/test_matching.py
git commit -m "feat: encodings_of for base64/hex/url encoded-value matching"
```

---

### Task 3: PII validators — Luhn, IBAN mod-97, US SSN

**Files:**
- Modify: `src/dwcollector/matching.py`
- Test: `tests/test_matching.py` (append)

**Interfaces:**
- Produces: `luhn_valid(digits: str) -> bool`, `iban_valid(s: str) -> bool`, `ssn_valid(s: str) -> bool`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_matching.py`:

```python
from dwcollector.matching import luhn_valid, iban_valid, ssn_valid


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_matching.py::test_luhn_valid -v`
Expected: FAIL — `ImportError: cannot import name 'luhn_valid'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/dwcollector/matching.py`:

```python
def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)  # A->10 ... Z->35
    return int(digits) % 97 == 1


def ssn_valid(s: str) -> bool:
    m = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", s)
    if not m:
        return False
    area, group, serial = m.groups()
    if area in ("000", "666") or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_matching.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/matching.py tests/test_matching.py
git commit -m "feat: PII structural validators (Luhn, IBAN mod-97, US SSN)"
```

---

### Task 4: PII detectors — registry + `run_detectors` (aggregate + mask)

**Files:**
- Modify: `src/dwcollector/matching.py`
- Test: `tests/test_matching.py` (append)

**Interfaces:**
- Consumes: `Match`, `luhn_valid`, `iban_valid`, `ssn_valid` (Tasks 1, 3).
- Produces: `available_detectors() -> list[str]`; `run_detectors(text: str, names: list[str]) -> list[Match]` — one `Match(kind='pii', key='pii:<name>', count=N, masked_sample=..., context=masked_sample)` per detector with ≥1 validated hit; unknown names skipped; raw values never stored.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_matching.py`:

```python
from dwcollector.matching import available_detectors, run_detectors


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_matching.py::test_run_detectors_aggregates_and_masks_cards -v`
Expected: FAIL — `ImportError: cannot import name 'run_detectors'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/dwcollector/matching.py`:

```python
def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _mask_card(raw: str) -> str:
    d = _digits(raw)
    return "•••• •••• •••• " + d[-4:]


def _mask_ssn(raw: str) -> str:
    return "•••-••-" + raw[-4:]


def _mask_iban(raw: str) -> str:
    s = raw.replace(" ", "")
    return "•" * max(0, len(s) - 4) + s[-4:]


_DETECTORS = {
    "credit-card": {
        "regex": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        "normalize": _digits,
        "validate": luhn_valid,
        "mask": _mask_card,
    },
    "iban": {
        "regex": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        "normalize": lambda m: m.replace(" ", ""),
        "validate": iban_valid,
        "mask": _mask_iban,
    },
    "us-ssn": {
        "regex": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "normalize": lambda m: m,
        "validate": ssn_valid,
        "mask": _mask_ssn,
    },
}


def available_detectors() -> list[str]:
    return list(_DETECTORS)


def run_detectors(text: str, names: list[str]) -> list[Match]:
    out: list[Match] = []
    for name in names:
        spec = _DETECTORS.get(name)
        if spec is None:
            continue
        count = 0
        sample = None
        for m in spec["regex"].finditer(text):
            raw = m.group(0)
            try:
                if not spec["validate"](spec["normalize"](raw)):
                    continue
            except Exception:  # noqa: BLE001 - one bad candidate never aborts the scan
                continue
            count += 1
            if sample is None:
                sample = spec["mask"](raw)
        if count:
            out.append(Match(kind="pii", key=f"pii:{name}",
                             context=sample or "", count=count, masked_sample=sample))
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_matching.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/matching.py tests/test_matching.py
git commit -m "feat: validated, masked, aggregated PII shape detectors"
```

---

### Task 5: Per-term matchers — `match_term`

**Files:**
- Modify: `src/dwcollector/matching.py`
- Test: `tests/test_matching.py` (append)

**Interfaces:**
- Consumes: `Match`, `normalize_defang`, `encodings_of` (Tasks 1, 2).
- Produces: `match_term(text: str, term: str, ctx: int = 60) -> list[Match]` — dispatches on prefix. `key` is the underlying identifier (prefix stripped) for every kind. Credential secrets are masked; invalid/empty prefixed terms yield `[]` (never raise).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_matching.py`:

```python
from dwcollector.matching import match_term


def test_match_term_literal_and_key():
    ms = match_term("leak has acme.com inside", ["acme.com"][0])
    assert len(ms) == 1 and ms[0].kind == "literal" and ms[0].key == "acme.com"


def test_match_term_regex_invalid_skipped():
    assert match_term("x", "re:[unclosed") == []


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_matching.py::test_match_term_fuzzy_matches_obfuscated_and_keys_on_identifier -v`
Expected: FAIL — `ImportError: cannot import name 'match_term'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/dwcollector/matching.py`:

```python
def _snippet(text: str, start: int, end: int, ctx: int) -> str:
    return text[max(0, start - ctx):min(len(text), end + ctx)].strip()


def match_term(text: str, term: str, ctx: int = 60) -> list[Match]:
    if term.startswith("re:"):
        try:
            rx = re.compile(term[3:], re.IGNORECASE)
        except re.error:
            return []
        return [Match("regex", term, _snippet(text, m.start(), m.end(), ctx))
                for m in rx.finditer(text)]

    if term.startswith("fuzzy:"):
        ident = term[len("fuzzy:"):]
        if not ident:
            return []
        ntext, nident = normalize_defang(text), normalize_defang(ident)
        out, i = [], ntext.find(nident)
        while i != -1:
            out.append(Match("fuzzy", ident, _snippet(ntext, i, i + len(nident), ctx)))
            i = ntext.find(nident, i + 1)
        return out

    if term.startswith("enc:"):
        val = term[len("enc:"):]
        if not val:
            return []
        out = []
        for e in encodings_of(val):
            i = text.find(e)
            while i != -1:
                out.append(Match("encoded", val, _snippet(text, i, i + len(e), ctx)))
                i = text.find(e, i + 1)
        return out

    if term.startswith("cred:"):
        ident = term[len("cred:"):]
        if not ident:
            return []
        rx = re.compile(re.escape(ident) + r"\s*[:,|]\s*(\S+)", re.IGNORECASE)
        out = []
        for m in rx.finditer(text):
            secret = m.group(1)
            masked = ident + ":" + "•" * min(len(secret), 8)
            out.append(Match("credential", ident, masked))
        return out

    # default: literal case-insensitive substring
    rx = re.compile(re.escape(term), re.IGNORECASE)
    return [Match("literal", term, _snippet(text, m.start(), m.end(), ctx))
            for m in rx.finditer(text)]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_matching.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/matching.py tests/test_matching.py
git commit -m "feat: per-term matchers (literal/regex/fuzzy/encoded/credential)"
```

---

### Task 6: Public entry — `find_matches`

**Files:**
- Modify: `src/dwcollector/matching.py`
- Test: `tests/test_matching.py` (append)

**Interfaces:**
- Consumes: `match_term`, `run_detectors`.
- Produces: `find_matches(text: str, terms: list[str], detectors: list[str], ctx: int = 60) -> list[Match]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_matching.py`:

```python
from dwcollector.matching import find_matches


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_matching.py::test_find_matches_mixes_terms_and_detectors -v`
Expected: FAIL — `ImportError: cannot import name 'find_matches'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/dwcollector/matching.py`:

```python
def find_matches(text: str, terms: list[str], detectors: list[str],
                 ctx: int = 60) -> list[Match]:
    out: list[Match] = []
    for term in terms:
        out.extend(match_term(text, term, ctx))
    out.extend(run_detectors(text, detectors))
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_matching.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/matching.py tests/test_matching.py
git commit -m "feat: find_matches public entry point"
```

---

### Task 7: DB — `leak_hits` columns + `record_leak_hit` params + migration

**Files:**
- Modify: `src/dwcollector/db.py` (`SCHEMA`, `init_schema`, `record_leak_hit`)
- Test: `tests/test_db.py` (append)

**Interfaces:**
- Produces: `leak_hits` gains `match_kind TEXT DEFAULT 'literal'`, `match_count INTEGER DEFAULT 1`. `Database.record_leak_hit(run_id, url, host, category, trust, term, context_snippet, matched_at, match_kind='literal', match_count=1)`. `init_schema` idempotently adds the columns to a pre-existing DB.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_db.py`:

```python
def test_record_leak_hit_stores_match_kind_and_count(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_leak_hit("r1", "http://x.onion/", "x.onion", "leak-site", "verified",
                       "pii:credit-card", "•••• •••• •••• 1111", "2026-07-23T00:00:00",
                       match_kind="pii", match_count=7)
    row = db.leak_hits_for_run("r1")[0]
    assert row["match_kind"] == "pii" and row["match_count"] == 7


def test_record_leak_hit_defaults(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.record_leak_hit("r1", "http://x.onion/", "x.onion", "leak-site", "verified",
                       "acme.com", "…acme.com…", "2026-07-23T00:00:00")
    row = db.leak_hits_for_run("r1")[0]
    assert row["match_kind"] == "literal" and row["match_count"] == 1


def test_init_schema_adds_columns_to_legacy_leak_hits(tmp_path):
    import sqlite3
    p = str(tmp_path / "legacy.db")
    # simulate a pre-Task-7 leak_hits with no match_kind/match_count
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE leak_hits (hit_id INTEGER PRIMARY KEY AUTOINCREMENT, "
              "run_id TEXT, url TEXT, host TEXT, category TEXT, trust TEXT, "
              "term TEXT, context_snippet TEXT, matched_at TEXT)")
    c.commit(); c.close()
    db = Database(p); db.init_schema()           # must not raise; adds columns
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(leak_hits)")}
    assert "match_kind" in cols and "match_count" in cols
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_db.py::test_record_leak_hit_stores_match_kind_and_count -v`
Expected: FAIL — `sqlite3.OperationalError: table leak_hits has no column named match_kind` (or a TypeError on the new kwargs)

- [ ] **Step 3: Write minimal implementation**

In `src/dwcollector/db.py`, update the `leak_hits` table in `SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS leak_hits (
    hit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, url TEXT, host TEXT, category TEXT, trust TEXT,
    term TEXT, context_snippet TEXT, matched_at TEXT,
    match_kind TEXT DEFAULT 'literal', match_count INTEGER DEFAULT 1
);
```

Replace `init_schema` with an idempotent migration:

```python
    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        # Idempotent migration for DBs created before match_kind/match_count.
        for ddl in (
            "ALTER TABLE leak_hits ADD COLUMN match_kind TEXT DEFAULT 'literal'",
            "ALTER TABLE leak_hits ADD COLUMN match_count INTEGER DEFAULT 1",
        ):
            try:
                self.conn.execute(ddl)
            except sqlite3.OperationalError:
                pass  # column already present
        self.conn.commit()
```

Replace `record_leak_hit`:

```python
    def record_leak_hit(self, run_id, url, host, category, trust,
                        term, context_snippet, matched_at,
                        match_kind="literal", match_count=1) -> None:
        self.conn.execute(
            "INSERT INTO leak_hits (run_id, url, host, category, trust, term, "
            "context_snippet, matched_at, match_kind, match_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, url, host, category, trust, term, context_snippet, matched_at,
             match_kind, match_count))
        self.conn.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_db.py -v`
Expected: PASS (new + existing db tests; existing `record_leak_hit` callers still work via defaults)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green (existing hunt/alerts callers of `record_leak_hit` unaffected).

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/db.py tests/test_db.py
git commit -m "feat: leak_hits match_kind/match_count columns + idempotent migration"
```

---

### Task 8: Config — `pii_detectors` + unknown-name warning

**Files:**
- Modify: `src/dwcollector/config.py` (`Config`, `load_config`)
- Modify: `config.toml`
- Test: `tests/test_config.py` (append)

**Interfaces:**
- Consumes: `matching.available_detectors` (Task 4).
- Produces: `Config.pii_detectors: list[str]` (default empty). `load_config` warns to stderr for unknown detector names and drops them, keeping valid ones.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
def test_pii_detectors_default_empty():
    from dwcollector.config import Config
    assert Config().pii_detectors == []


def test_pii_detectors_parsed_and_unknown_warned(tmp_path, capsys):
    from dwcollector.config import load_config
    p = tmp_path / "c.toml"
    p.write_text('pii_detectors = ["credit-card", "not-real", "us-ssn"]\n')
    c = load_config(str(p))
    assert c.pii_detectors == ["credit-card", "us-ssn"]   # unknown dropped
    err = capsys.readouterr().err
    assert "not-real" in err                              # warned to stderr
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py::test_pii_detectors_default_empty -v`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'pii_detectors'`

- [ ] **Step 3: Write minimal implementation**

In `src/dwcollector/config.py`, add `field` to the dataclass import and a field to `Config`:

```python
from dataclasses import dataclass, fields, field
```

Add to the `Config` dataclass (after `alert_webhook`):

```python
    pii_detectors: list[str] = field(default_factory=list)
```

In `load_config`, after constructing `cfg` but before returning it, validate detectors (import locally to avoid any import-order concerns):

```python
    cfg = Config(**{k: v for k, v in data.items() if k in known})
    if cfg.pii_detectors:
        from .matching import available_detectors
        valid = set(available_detectors())
        unknown = [d for d in cfg.pii_detectors if d not in valid]
        if unknown:
            print(f"config: ignoring unknown pii_detectors: {', '.join(unknown)}",
                  file=sys.stderr)
        cfg.pii_detectors = [d for d in cfg.pii_detectors if d in valid]
    return cfg
```

(Adjust the final `return` so the existing `return Config(...)` becomes the `cfg = Config(...)` shown above.)

Append to `config.toml`:

```toml
# structured-PII shape detectors to run during hunts (opt-in; empty = off).
# available: credit-card, iban, us-ssn
pii_detectors = []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/config.py config.toml tests/test_config.py
git commit -m "feat: pii_detectors config with unknown-name validation"
```

---

### Task 9: Integrate `find_matches` into `hunt()`

**Files:**
- Modify: `src/dwcollector/hunt.py` (`hunt`)
- Modify: `src/dwcollector/cli.py` (`_run_hunt`, `run_cycle` hunt call — pass detectors)
- Test: `tests/test_hunt.py` (append; update existing if needed)

**Interfaces:**
- Consumes: `find_matches` (Task 6), `record_leak_hit` new params (Task 7), `cfg.pii_detectors` (Task 8).
- Produces: `hunt(db, client, terms, run_id, now, detectors=None) -> tuple[int, set[str]]` — records each match with `match_kind`/`match_count`. Default `detectors=None` → `[]`, so existing callers/tests are unaffected.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_hunt.py`:

```python
from dwcollector.matching import find_matches  # noqa: F401 (ensures module import path)


@pytest.mark.asyncio
async def test_hunt_records_fuzzy_and_pii(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://good.onion/"
    db.upsert_url(u, "good.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site")
    html = ("<html><body>leak of acme[.]com plus card 4111 1111 1111 1111"
            "</body></html>")
    n, covered = await hunt(db, SiteClient(html), ["fuzzy:acme.com"],
                            "run1", "2026-07-23T00:00:00", detectors=["credit-card"])
    assert covered == {u}
    rows = {(r["term"], r["match_kind"]) for r in db.leak_hits_for_run("run1")}
    assert ("acme.com", "fuzzy") in rows
    assert ("pii:credit-card", "pii") in rows
    # raw card digits never stored
    assert all("4111111111111111" not in (r["context_snippet"] or "")
               for r in db.leak_hits_for_run("run1"))


@pytest.mark.asyncio
async def test_hunt_defaults_no_detectors(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://good.onion/"
    db.upsert_url(u, "good.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site")
    n, _ = await hunt(db, SiteClient("<html><body>acme.com</body></html>"),
                      ["acme.com"], "run1", "2026-07-23T00:00:00")
    row = db.leak_hits_for_run("run1")[0]
    assert row["term"] == "acme.com" and row["match_kind"] == "literal"
```

(`SiteClient` already exists in `tests/test_hunt.py` from spec #1.)

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hunt.py::test_hunt_records_fuzzy_and_pii -v`
Expected: FAIL — `hunt()` has no `detectors` kwarg / still uses `match_terms` (TypeError or missing rows)

- [ ] **Step 3: Write minimal implementation**

Replace `hunt` in `src/dwcollector/hunt.py` (and update the import at the top from `from .discover import visible_text` — add `from .matching import find_matches`):

```python
async def hunt(db, client, terms: list[str], run_id: str, now: str,
               detectors=None) -> tuple[int, set[str]]:
    detectors = detectors or []
    count = 0
    covered: set[str] = set()
    for row in db.canonical_trusted_urls():
        res = await client.fetch(row["url"])
        if not (res.ok and res.status and res.status < 400):
            continue
        covered.add(row["url"])
        text = visible_text(res.html)
        for mt in find_matches(text, terms, detectors):
            db.record_leak_hit(
                run_id, row["url"], row["host"], row.get("category"),
                row.get("trust"), mt.key, mt.context, now,
                match_kind=mt.kind, match_count=mt.count)
            count += 1
    return count, covered
```

`match_terms` may remain in `hunt.py` (used by its own unit tests) — do not delete it; it is superseded by `find_matches` for the hunt path only.

In `src/dwcollector/cli.py`, pass detectors at both call sites:
- In `_run_hunt`'s inner `go()`: `n, _ = await hunt(db, client, terms, f"hunt-{_now()}", _now(), detectors=cfg.pii_detectors)`
- In `run_cycle`'s `go_hunt()`: `return await hunt(db, client, terms, run_id, _now(), detectors=cfg.pii_detectors)`

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hunt.py tests/test_cli.py -q`
Expected: PASS (new hunt tests + existing hunt/cli tests; the existing `test_hunt_records_hits` still passes because default matching is literal)

- [ ] **Step 5: Run full suite**

Run: `pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/dwcollector/hunt.py src/dwcollector/cli.py tests/test_hunt.py
git commit -m "feat: hunt() uses find_matches with pii detectors, records match_kind/count"
```

---

### Task 10: Alert copy — `pii:`-aware `_title`/`_body`

**Files:**
- Modify: `src/dwcollector/alerts.py` (`_title`, `_body`)
- Test: `tests/test_alerts.py` (append)

**Interfaces:**
- Produces: `_title`/`_body` render a natural PII message when `finding['term']` starts with `pii:`; identifier findings keep the exact existing wording.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_alerts.py`:

```python
from dwcollector.alerts import _title, _body


def _pii_finding():
    return {"kind": "leak", "dedup_key": "leak:http://x.onion/|pii:credit-card",
            "url": "http://x.onion/", "host": "x.onion", "term": "pii:credit-card",
            "severity": "critical", "context_snippet": "•••• •••• •••• 1111"}


def _ident_finding():
    return {"kind": "leak", "dedup_key": "leak:http://x.onion/|acme.com",
            "url": "http://x.onion/", "host": "x.onion", "term": "acme.com",
            "severity": "critical", "context_snippet": "…acme.com…"}


def test_title_pii_reads_naturally():
    t = _title(_pii_finding(), "opened")
    assert "Credit-card" in t and "x.onion" in t
    assert "Client identifier 'pii:" not in t


def test_title_identifier_unchanged():
    assert _title(_ident_finding(), "opened") == \
        "Client identifier 'acme.com' exposed on x.onion"


def test_body_pii_does_not_leak_raw_but_shows_masked():
    b = _body(_pii_finding(), "opened")
    assert "1111" in b and "•" in b
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_alerts.py::test_title_pii_reads_naturally -v`
Expected: FAIL — title renders `Client identifier 'pii:credit-card' exposed on x.onion`

- [ ] **Step 3: Write minimal implementation**

Replace `_title` and `_body` in `src/dwcollector/alerts.py`:

```python
def _title(finding: dict, event: str) -> str:
    term = finding.get("term") or ""
    if finding["kind"] == "leak" and term.startswith("pii:"):
        label = term[len("pii:"):].replace("-", " ")
        if event == "opened":
            return f"{label.capitalize()} data detected on {finding['host']}"
        return f"{label.capitalize()} exposure on {finding['host']} resolved"
    if finding["kind"] == "leak":
        if event == "opened":
            return f"Client identifier '{finding['term']}' exposed on {finding['host']}"
        return f"Exposure of '{finding['term']}' on {finding['host']} resolved"
    if event == "opened":
        return f"Verified original {finding['host']} went dark"
    return f"Verified original {finding['host']} recovered"


def _body(finding: dict, event: str) -> str:
    if finding["kind"] == "leak":
        return (f"url={finding['url']} term={finding['term']} "
                f"snippet={finding.get('context_snippet') or ''}")
    return f"url={finding['url']} — canonical trusted site liveness changed"
```

(`_body` already surfaces the masked snippet for all leak findings, including PII, so no PII-specific branch is needed there — the test confirms the masked sample flows through and no raw value is present.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_alerts.py -v`
Expected: PASS (new copy tests + existing alerts tests, whose identifier wording is unchanged)

- [ ] **Step 5: Commit**

```bash
git add src/dwcollector/alerts.py tests/test_alerts.py
git commit -m "feat: pii-aware alert title copy; identifier wording unchanged"
```

---

### Task 11: Docs — README + watchlist example

**Files:**
- Modify: `README.md`
- Modify: `terms.txt.example`

**Interfaces:** none (docs only).

- [ ] **Step 1: Extend `terms.txt.example`**

Append prefix examples to `terms.txt.example`:

```
# Matching modes (prefix a term to opt in; bare terms are literal, case-insensitive):
#   re:<regex>       regular expression
#   fuzzy:<ident>    defanged / obfuscated forms (acme[.]com, acme(dot)com, homoglyphs)
#   enc:<value>      base64 / hex / URL-encoded forms of the value
#   cred:<ident>     the identifier inside a credential pair (password is masked)
fuzzy:acme-corp.com
enc:ACME-API-KEY
cred:billing@acme-corp.com
```

- [ ] **Step 2: Document richer matching in README**

Add a "Matching modes" subsection to `README.md` describing: the four per-term prefixes (`re:`, `fuzzy:`, `enc:`, `cred:`) and what each catches; that bare terms stay literal/case-insensitive; the `pii_detectors` config option with the available detectors (`credit-card`, `iban`, `us-ssn`), that they are Luhn/checksum-validated and opt-in (default empty); and the evidence guarantee — PII and credential secrets are stored **masked**, never raw, with PII recorded as one finding per site+detector with a match count.

- [ ] **Step 3: Verify suite green and commit**

Run: `pytest -q`
Expected: all green (docs-only change).

```bash
git add README.md terms.txt.example
git commit -m "docs: document matching modes and pii detectors"
```

---

## Final verification

- [ ] Run the full suite: `pytest -q` — expect all prior tests plus the new ones green.
- [ ] Smoke matching offline:
  `python -c "from dwcollector.matching import find_matches; print([(m.kind,m.key) for m in find_matches('acme[.]com card 4111111111111111', ['fuzzy:acme.com'], ['credit-card'])])"`
  — expect a `('fuzzy','acme.com')` and a `('pii','pii:credit-card')` entry.
- [ ] Confirm `git log --oneline` shows one commit per task and the tree is clean.
