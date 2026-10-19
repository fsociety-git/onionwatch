# Design: Trust-Anchor Re-Verification

**Date:** 2026-07-23
**Status:** Approved — ready for implementation planning
**Scope:** Tier 1, spec #3 of 3 (final). Depends on spec #1 (alerting) and spec #2 (matching), both merged.

## Problem

Clone detection is anchored to `verified_sources.toml` (a `verified_onions`
allow-list + expected PGP fingerprints). Those anchors rot:

1. **Stale liveness.** Spec #1's HIGH `dead_original` alert fires when a
   canonical trusted anchor goes `alive → dead`, but the supervisor loop never
   re-probes already-crawled sites, so `alive` is stale and the alert never
   fires in steady state. (Carry-forward gap from spec #1.)
2. **Address rotation.** As criminal sites rotate `.onion` addresses, a verified
   original goes dark and a new address appears — but the new one isn't in
   `verified_sources.toml`, so it's treated as unknown/clone.
3. **Anchor takeover.** A PGP-anchored site can stay alive at the same address
   but be replaced by an impostor — liveness alone can't detect this.

This spec keeps the anchor set self-monitoring: fresh liveness, periodic
identity re-verification, and — when an anchor rots — an actionable list of
successor candidates for a human to verify. It never auto-promotes a site to
trusted (that decision stays human).

## Design decisions (ratified during brainstorming)

- **Scope (B):** re-probe anchors in the loop + PGP identity re-verification +
  surface re-anchor candidates. **No auto-re-anchoring** — auto-trusting a live
  look-alike is exactly how a phishing clone would hijack the "original" crown.
- **Integration (A) — single pass with a safety cutout.** Re-verification rides
  the existing hunt fetch over the anchor set (`canonical_trusted_urls()`): one
  fetch per anchor covers liveness, identity, and matching. **A dead or
  identity-failed anchor is NOT searched this cycle** — the safety cutout
  prevents sending the client watchlist to a dead/compromised anchor (i.e. to a
  possible attacker who replaced the original).
- **Candidates (A):** the successor candidates for a rotted anchor are the
  **live members of its cluster** (the current `suspected_clone` siblings),
  surfaced **in the alert body**, framed "verify before trusting — never
  auto-added." No dead-for-N-cycles threshold; candidates ride spec #1's
  open/resolved lifecycle (a transient blip opens then resolves).
- **Severity (A):** anchor identity failure is **HIGH**, distinct kind from
  `dead_original`. **CRITICAL stays reserved for client-data exposure.**
- **PGP-anchors-only identity check:** allow-list-only anchors have no expected
  fingerprint, so they get liveness re-check only. Documented limitation.

## Architecture

### 1. Re-verification pass (folded into `hunt`, single fetch)

The cycle's pass over `db.canonical_trusted_urls()` gains health-checking. For
each anchor, using ONE fetch:

```
res = await client.fetch(anchor["url"])
ok = res.ok and res.status and res.status < 400
db.update_url(anchor["url"], alive=int(ok), http_status=res.status, last_checked=now)
if not ok:
    continue                              # dead → reconcile_dead_originals handles it
text = visible_text(res.html)
if is_pgp_anchor(anchor, verified):
    identity_checked.add(anchor["url"])
    if not pgp_matches(anchor["url"], text, verified):
        identity_failed.add(anchor["url"])
        continue                          # SAFETY CUTOUT: do not search a compromised anchor
covered.add(anchor["url"])
for mt in find_matches(text, terms, detectors):
    db.record_leak_hit(..., term=mt.key, context_snippet=mt.context,
                        match_kind=mt.kind, match_count=mt.count)
    count += 1
```

- `is_pgp_anchor(row, verified)` (new, in `verify.py`): `onion_host(row["url"]) in
  verified.get("pgp", {})`.
- `pgp_matches(url, text, verified)` already exists in `verify.py`.
- `hunt()` now **updates `alive`** for every anchor it probes (previously it
  never touched `alive`) — this is what makes `dead_original` actually fire.
- `hunt()` returns a dataclass instead of the current `(count, covered)` tuple:

```python
@dataclass
class HuntOutcome:
    hit_count: int
    covered_urls: set[str]          # anchors actually searched (alive + identity-ok)
    identity_checked: set[str]      # reachable PGP anchors whose identity was evaluated
    identity_failed: set[str]       # subset of identity_checked that failed
```

`hunt()` gains a `verified=None` param (defaults to `{}` → no identity checks,
so existing callers/tests behave as before apart from the additive `alive`
write). Signature: `hunt(db, client, terms, run_id, now, detectors=None,
verified=None) -> HuntOutcome`.

### 2. Re-anchor candidates (`db.py`)

New method:

```python
def live_cluster_siblings(self, cluster_id, exclude_url) -> list[dict]:
    # rows in the same cluster, alive, excluding the rotted anchor itself
    "SELECT * FROM urls WHERE cluster_id = ? AND url != ? AND alive = 1"
```

Empty when the successor isn't discovered yet (honest "no candidate found").

### 3. Alerts (`alerts.py`)

- **`dead_original` (existing, HIGH)** — now fires (fresh `alive`);
  `reconcile_dead_originals` is extended so the opened finding's
  `context_snippet` carries the candidate note (see below).
- **`anchor_identity` (new, HIGH)** — `ANCHOR_IDENTITY_SEVERITY = "high"`,
  dedup key `identity:<url>`, kind `anchor_identity`:

```python
def reconcile_anchor_identity(db, cfg, identity_checked, identity_failed, now, emit_fn=emit):
    # open/reopen a HIGH finding for each url in identity_failed (with candidates)
    # resolve open anchor_identity findings whose url is in (identity_checked - identity_failed)
    #   -> coverage-gated: a dead/unchecked anchor's identity finding stays open
```

- **Candidate note** (helper in `alerts.py`): for a rotted anchor row, build a
  short string from `db.live_cluster_siblings(row["cluster_id"], row["url"])` —
  e.g. `"verify before trusting — candidate successors: a.onion, b.onion"` or
  `"verify before trusting — no live successor discovered yet"`. Stored as the
  finding's `context_snippet` on **both** the open and reopen paths (so a
  recurring rot always carries a fresh candidate list), for `dead_original` and
  `anchor_identity` alike.
- **Alert copy:** `_title`/`_body` gain an `anchor_identity` branch
  ("Verified anchor <host> failed identity re-verification" / recovered), and
  `_body` for `dead_original` **and** `anchor_identity` surfaces the candidate
  note from `context_snippet` (currently `_body` shows the snippet only for
  `leak` findings). CRITICAL/leak and identifier wording stay unchanged.

### 4. Loop wiring (`run_cycle`)

The anchor pass must run **every cycle regardless of whether a watchlist is
loaded** (re-verification is independent of client terms). Restructure the hunt
block so:

- Terms are read (may be empty). `hunt()` **always runs** (with possibly-empty
  `terms`) so the anchor set is re-probed and identity-checked every cycle;
  matching simply produces nothing when `terms`/`detectors` are empty.
- `verified = load_verified_sources("verified_sources.toml")` (already loaded
  for clustering) is passed to `hunt()`.
- Reconcilers: always run `reconcile_dead_originals` and
  `reconcile_anchor_identity`; run `reconcile_leaks` **only when `terms`** is
  non-empty (so removing the watchlist doesn't false-resolve leak findings).
- `result["alerts"] = len(emitted)`; when no terms, set
  `result["hunt_skipped"] = "no watchlist terms (anchors still re-verified)"`.

The cli `_run_hunt` (manual `hunt --terms`) updates its unpacking to the
`HuntOutcome` (uses `.hit_count`); it may pass `verified` too for parity.

### 5. Coverage-gate coherence

A dead or identity-failed anchor is not in `covered_urls`, so `reconcile_leaks`
(spec #1's coverage gate) leaves its existing leak findings **open** rather than
false-resolving — correct, because we deliberately did not search it.

## Error handling

- The re-verification pass runs under `run_cycle`'s existing per-stage
  `try/except`; a fetch/identity failure on one anchor is caught per-anchor
  (the loop continues) and never crashes the cycle.
- `pgp_matches`/`is_pgp_anchor` never raise on missing data (they already guard
  `None`/absent fingerprints).
- `live_cluster_siblings` on a row with no `cluster_id` returns `[]`.
- No raw secrets/PII involved here; candidate notes contain only `.onion`
  addresses already stored in the DB.

## Testing (TDD, existing pytest style)

- **liveness:** `hunt()` sets `alive=1` for a reachable anchor and `alive=0` for
  an unreachable one (via a stub client); a now-dead anchor makes
  `reconcile_dead_originals` open a HIGH `dead_original` finding.
- **identity failure + safety cutout:** a PGP anchor (host in `verified["pgp"]`)
  whose page no longer carries the expected fingerprint → in
  `identity_failed`, **not** in `covered_urls`, and **no leak hit recorded for
  it** even when its page contains a watchlist term; `reconcile_anchor_identity`
  opens a HIGH `anchor_identity` finding.
- **identity recovery:** fingerprint matches again → finding resolves; a dead
  (unchecked) anchor's identity finding stays open (coverage-gated).
- **candidates:** `live_cluster_siblings` returns alive siblings excluding the
  anchor; the dead/identity alert body carries the candidate note; empty cluster
  → "no live successor" note.
- **allow-list anchor:** a `verified_onions` anchor with no PGP entry is
  liveness-checked only (never in `identity_checked`).
- **no-watchlist path:** `run_cycle` with an empty watchlist still re-probes
  anchors and fires dead/identity alerts (anchor pass not skipped).
- **end-to-end `run_cycle`:** stubbed client, one dead + one identity-failed
  anchor → expected findings/alerts; never raises.
- **backward compat:** existing hunt/alerts/cli tests updated for the
  `HuntOutcome` return; identifier/leak alert wording unchanged.

## Out of scope (explicitly deferred)

- Auto-re-anchoring / auto-promoting a candidate to trusted (rejected by design).
- Identity re-verification for allow-list-only anchors (no fingerprint to check).
- A dedicated `onionwatch anchors` CLI view (candidates already ride the alert
  body / `alerts.jsonl` / finding record).
- Re-probing anchors listed in `verified_sources.toml` that were never crawled
  (no DB row to re-probe); the tool re-verifies anchors it has discovered.
- Robust space-formatted IBAN detection (carried over from spec #2, unrelated).
