# Design: Richer / Pattern-Aware Hunting

**Date:** 2026-07-23
**Status:** Approved — ready for implementation planning
**Scope:** Tier 1, spec #2 of 3. Depends on spec #1 (continuous hunting + alerting, merged). Follow-on: trust-anchor re-verification (#3).

## Problem

`hunt()` currently matches watchlist terms as literal case-insensitive
substrings, plus an opt-in `re:` regex prefix (`match_terms` in `hunt.py`).
Real leaks are frequently disguised or reformatted, so exact matching silently
misses them:

- **Obfuscated identifiers** — `acme-corp[.]com`, `acme-corp(dot)com`,
  `acme-corp . com`, zero-width characters, homoglyphs.
- **Encoded identifiers** — the value hidden inside base64 / hex / URL-encoding
  in a dump, invisible to a plain-text search.
- **Credential dumps** — a watchlisted email buried in an `email:password`
  combo line.
- **Structured PII** — card numbers, IBANs, SSNs present as a *type* of data,
  independent of any specific client identifier.

This spec broadens matching to catch all four, feeding the richer matches
through the same `leak_hits → reconcile_leaks → finding → alert` pipeline spec
#1 built, so alerts become more complete without touching the alert engine.

## Design decisions (ratified during brainstorming)

- **Scope — four techniques:** defang/obfuscation ("fuzzy"), encoded-value
  matching, credential-pair awareness, and structured-PII shape detection.
- **Control model — hybrid, split by what the technique targets:**
  - Identifier-based techniques (fuzzy, encoded, credential-pair) → **per-term
    prefixes**, extending the existing `re:` convention. They disguise *a
    specific watchlisted identifier*, so per-term control is right and keeps
    false-positive management surgical.
  - Shape-based detection (PII) → **config-driven named detectors**
    (`pii_detectors = [...]`). These watch for a *type* of data everywhere, not
    a specific identifier, so a global list is the natural home.
- **PII recording — one finding per (site, detector), redacted + validated
  (option A):** one finding per `(site, detector)` with a match count and a
  **masked** sample; **never** store raw PII values; run a structural
  **validator** (Luhn, mod-97, format) before counting a hit to kill false
  positives.
- **Opt-in safety:** bare literal terms behave exactly as today. All aggressive
  matching is opt-in (per-term prefix or an enabled detector), so nothing gets
  noisier unless explicitly asked. `pii_detectors` defaults to empty.
- **Encoded prefix is `enc:`** (covers base64 + hex + URL, not just base64).
- **Starter PII detectors:** `credit-card` (Luhn), `iban` (mod-97), `us-ssn`
  (format).

## Architecture

### 1. New module `matching.py`

Matching has outgrown `match_terms`; factor it into a focused module with one
public entry point plus small, independently-testable helpers.

```python
@dataclass
class Match:
    kind: str          # 'literal' | 'regex' | 'fuzzy' | 'encoded' | 'credential' | 'pii'
    key: str           # underlying identifier (prefix stripped) OR 'pii:<detector>'
    context: str       # evidence snippet (original text, bounded by ctx)
    count: int = 1     # >1 only for aggregated PII
    masked_sample: str | None = None   # PII only; masked, never raw

def find_matches(text: str, terms: list[str],
                 detectors: list[str], ctx: int = 60) -> list[Match]: ...
```

`find_matches` parses each term's prefix into a matcher, runs it, runs any
enabled PII detectors, and returns a flat list of `Match`. Internals are small
pure functions (normalizers, encoders, validators) so each is unit-tested in
isolation. The existing `re:` prefix and literal behavior move here unchanged.

Prefix grammar (extends the existing `re:`):
- no prefix → **literal** (case-insensitive substring; unchanged)
- `re:` → **regex** (unchanged)
- `fuzzy:` → **fuzzy/defang**
- `enc:` → **encoded**
- `cred:` → **credential-pair**

### 2. Technique behavior

**Fuzzy (`fuzzy:<identifier>`).** Normalize *both* the identifier and the page
text through one defang pass, then substring-match the normalized identifier in
the normalized text. The evidence snippet is taken from the *original* text at
the matched span (so analysts see what was really on the page). Normalizations
(`normalize_defang(s)`):
- `[.]`, `(.)`, `(dot)`, ` dot ` → `.`
- `[@]`, `(at)`, ` at ` → `@`
- strip zero-width chars (U+200B, U+200C, U+200D, U+FEFF)
- collapse whitespace immediately around `.` and `@`
- a small homoglyph confusables fold (e.g. Cyrillic а/о/е/р/с → Latin a/o/e/p/c)
- casefold

**Encoded (`enc:<value>`).** Generate the value's encodings and substring-search
each in the page's extracted visible text: base64 (standard + urlsafe, padded
and unpadded), hex (lower + upper), and URL percent-encoding. Precise because we
search for a specific encoded string. The `Match.kind` is `encoded`; the context
shows where the encoded blob appears.

**Input text.** `find_matches` operates on the single `text` argument — the
page's extracted **visible text** (`visible_text(res.html)`), the same input
`hunt()` already feeds `match_terms` today. Scanning raw HTML/attributes/scripts
is out of scope: it would inflate PII false positives from markup and inline
code, and leaked dumps render as visible page text in practice.

**Credential-pair (`cred:<identifier>`).** Match the identifier when it appears
in a credential structure — `user:pass`, `email:hash`, `email,password`,
`email | password`. Record the finding for the identifier with
`kind='credential'`; **mask the password/secret half** in the stored snippet
(e.g. `billing@acme.com:••••••`) — the secret is never retained in full.

**PII detectors (config `pii_detectors`).** A registry of named detectors, each
a `(regex, validator)` pair, run over the text independent of terms:
- `credit-card` — 13–19 digit candidate runs, **Luhn**-validated.
- `iban` — country-code + digits candidate, **mod-97**-validated.
- `us-ssn` — `NNN-NN-NNNN` format with basic structural rules.
Matches for one detector on one page are **aggregated**: `count` = number of
validated hits, `masked_sample` = one representative match with all but the last
few characters masked (e.g. `•••• •••• •••• 1111`). Emitted as a single `Match`
with `kind='pii'`, `key='pii:<detector>'`.

### 3. Recording & dedup

- **Identifier techniques** key the finding on the *underlying identifier*
  (prefix stripped): literal `acme.com` and `fuzzy:acme.com` both produce
  `Match.key == 'acme.com'`, so they collapse to one finding
  (`leak:<url>|acme.com`) rather than alerting twice. The match method is
  metadata (`match_kind`), not part of the dedup key.
- **PII** → one finding per `(site, detector)`:
  `leak:<url>|pii:credit-card`, snippet = masked sample, `match_count` = count.
  PII findings are ordinary `kind='leak'` findings with a `pii:`-prefixed term,
  so they reuse the whole reconcile/lifecycle path — no new finding kind.
- **Schema:** two additive columns on `leak_hits` — `match_kind TEXT DEFAULT
  'literal'` and `match_count INTEGER DEFAULT 1`. `record_leak_hit` gains
  matching optional params. `reconcile_leaks`, the `findings`/`alerts` tables,
  and the `alerts` CLI are unchanged — they already key on `(url, term)` and
  treat the snippet opaquely. Severity stays **CRITICAL** for both plain-leak
  and PII findings.
- **Alert copy (one small change to `alerts.py`).** The emission *mechanics*
  (lifecycle, sink, webhook, dedup) are unchanged, but `_title`/`_body` assume
  the term is a client identifier and would render "Client identifier
  'pii:credit-card' exposed…". So `_title`/`_body` gain a `pii:`-term branch that
  reads naturally, e.g. **"Credit-card data detected on `<host>` (~N matches)"**.
  A term without the `pii:` prefix keeps the exact existing wording. This is the
  only change to the alert engine.

`hunt()` change: replace the `match_terms(...)` call with `find_matches(text,
terms, cfg.pii_detectors, ctx)`, and record each `Match` via `record_leak_hit`
passing `term=match.key`, `context_snippet=match.context` (or masked sample),
`match_kind=match.kind`, `match_count=match.count`. `hunt()`'s return contract
(`(count, covered_urls)`) is unchanged.

### 4. Config & defaults

- New `Config.pii_detectors: list[str] = field(default_factory=list)` — default
  empty (fully opt-in; no behavior change unless enabled). Documented in
  `config.toml`. Unknown detector names warn to stderr (consistent with the
  existing unknown-config-key warning) and are skipped.
- Bare literal terms and `re:` behave exactly as before. No global fuzzy toggle
  — aggressive identifier matching is always per-term opt-in.

### 5. Error handling

- An invalid `re:` pattern is skipped (existing behavior), extended: a malformed
  prefixed term (e.g. empty value after prefix) is skipped, not fatal.
- An unknown `pii_detectors` entry warns and is skipped; it never aborts a hunt.
- A detector's validator exception on one candidate is caught and that candidate
  skipped — a single malformed run never kills the scan.
- Raw PII values are never written to the DB, logs, or alerts sink — only
  masked samples and counts.

## Testing (TDD, existing pytest style)

- **normalizers:** `normalize_defang` folds each obfuscation form; homoglyph
  fold; zero-width stripping; casefold.
- **encoders:** base64 (std/urlsafe, padded/unpadded), hex, URL — each
  round-trips and is found in text; a non-encoded lookalike is not matched.
- **fuzzy:** `fuzzy:acme.com` matches `acme[.]com`, `acme(dot)com`,
  `acme.com` with a zero-width char; does NOT match unrelated text; snippet is
  from the original text.
- **credential-pair:** matches `email:pass` / `email,pass` structures; the
  password half is masked in the snippet; a bare email (no credential
  structure) does not trigger `credential` kind.
- **PII validators:** Luhn accept + reject; IBAN mod-97 accept + reject; SSN
  format accept + reject. A 16-digit non-Luhn string is not counted.
- **PII aggregation:** multiple valid cards on one page → one `Match`,
  `count == N`, `masked_sample` masked (no raw value present anywhere).
- **dedup:** literal `acme.com` + `fuzzy:acme.com` both present → matches share
  `key == 'acme.com'` → a single finding after reconcile.
- **find_matches integration:** mixed term list + detectors returns the expected
  set of `Match` objects.
- **hunt end-to-end:** records `match_kind`/`match_count` in `leak_hits`; a
  fuzzy/encoded/PII hit flows to a finding and a CRITICAL alert via the
  unchanged reconcile path.
- **alert copy:** a `pii:`-term finding renders PII-flavored title/body
  ("Credit-card data detected on …"), not "Client identifier 'pii:…' exposed";
  a normal identifier finding keeps the existing wording verbatim.
- **config:** `pii_detectors` parsed with empty default; unknown detector warns
  and is skipped.

## Out of scope (explicitly deferred)

- Trust-anchor re-verification / broadening *which* sites are hunted → spec #3.
- Per-detector severity tuning (all PII findings are CRITICAL for now).
- Language-specific / CJK obfuscation beyond the confusables fold.
- Decoding arbitrary nested/compressed encodings (gzip, multi-layer base64) —
  single-layer base64/hex/URL only.
- User-defined custom PII detectors from config (ship the built-in registry;
  custom detectors can come later).
