from dwcollector.cluster import cluster_rows, choose_canonical, run_clustering
from dwcollector.fingerprint import simhash, to_hex
from dwcollector.db import Database

def row(url, sh, first_seen="2026-07-21T00:00:00", inbound=0, host=None,
        pgp_fingerprint=None):
    return {"url": url, "content_simhash": sh,
            "first_seen": first_seen, "inbound_links": inbound,
            "host": host or url[7:-1], "pgp_fingerprint": pgp_fingerprint}

def test_cluster_groups_near_duplicates():
    sh_a = to_hex(simhash("welcome to acme market buy and sell goods safely here"))
    sh_b = to_hex(simhash("welcome to acme market buy and sell goods safely here now"))
    sh_c = to_hex(simhash("totally different poetry gardening travel photos journal"))
    rows = [row("http://a.onion/", sh_a),
            row("http://b.onion/", sh_b),
            row("http://c.onion/", sh_c)]
    # NOTE: sh_a vs sh_b are 8 bits apart under the real simhash/blake2b
    # implementation (not <=6 as the brief's original distance=6 assumed),
    # while sh_a/sh_c and sh_b/sh_c are 35 apart. distance=10 preserves the
    # intended semantics (a+b cluster, c stays separate) with a wide margin.
    clusters = cluster_rows(rows, distance=10)
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 2]     # a+b together, c alone

def test_choose_canonical_prefers_verified():
    # NOTE: uses valid-format onion hosts (16-char base32 + .onion), matching
    # the _ONION_RE pattern in discover.py that is_verified()/onion_host()
    # rely on. The brief's original "a.onion"/"b.onion" fixtures are too
    # short to match that regex, so is_verified() would always return False
    # regardless of verified_onions -- the same class of bug already worked
    # around in tests/test_verify.py.
    verified = {"verified_onions": ["bbbbbbbbbbbbbbbb.onion"], "pgp": {}}
    cluster = [row("http://aaaaaaaaaaaaaaaa.onion/", "0", first_seen="2026-01-01T00:00:00"),
               row("http://bbbbbbbbbbbbbbbb.onion/", "0", first_seen="2026-07-01T00:00:00")]
    canon, why = choose_canonical(cluster, verified)
    assert canon["url"] == "http://bbbbbbbbbbbbbbbb.onion/"
    assert why == "verified"

def test_choose_canonical_falls_back_to_first_seen():
    verified = {"verified_onions": [], "pgp": {}}
    cluster = [row("http://a.onion/", "0", first_seen="2026-05-01T00:00:00"),
               row("http://b.onion/", "0", first_seen="2026-01-01T00:00:00")]
    canon, why = choose_canonical(cluster, verified)
    assert canon["url"] == "http://b.onion/"   # oldest
    assert why == "first_seen"

def test_run_clustering_writes_trust(tmp_path):
    # NOTE: valid-format onion hosts, see comment on
    # test_choose_canonical_prefers_verified above for why.
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    sh = to_hex(simhash("acme market buy and sell goods safely here always open"))
    for u in ("http://aaaaaaaaaaaaaaaa.onion/", "http://bbbbbbbbbbbbbbbb.onion/"):
        db.upsert_url(u, u[7:-1], "crawled", 1, "2026-07-21T00:00:00")
        db.update_url(u, content_simhash=sh)
    verified = {"verified_onions": ["aaaaaaaaaaaaaaaa.onion"], "pgp": {}}
    n = run_clustering(db, verified, distance=6)
    assert n == 1
    a = db.get_url("http://aaaaaaaaaaaaaaaa.onion/"); b = db.get_url("http://bbbbbbbbbbbbbbbb.onion/")
    assert a["is_canonical"] == 1 and a["trust"] == "verified"
    assert b["is_canonical"] == 0 and b["trust"] == "suspected_clone"
    assert b["clone_of"] == "http://aaaaaaaaaaaaaaaa.onion/"


# --- Fix 1: clustering must be transitive (single-linkage), not order-dependent ---

# Hand-crafted 64-bit hex simhashes, distances measured directly with
# dwcollector.fingerprint.hamming (not asserted blind):
#   hamming(sh_a, sh_b) == 2
#   hamming(sh_b, sh_c) == 2
#   hamming(sh_a, sh_c) == 4
# At distance=2: A-B and B-C are each directly linked, but A-C is NOT
# directly linked (4 > 2). Under old "compare only to cluster reps[0]"
# logic, if C is compared against A's representative it would be rejected
# and land in its own cluster despite being a genuine near-duplicate of B.
# Correct single-linkage clustering must still merge all three into one
# cluster, regardless of the order rows are processed in.
_SH_A = "0000000000000000"
_SH_B = "0000000000000003"
_SH_C = "000000000000000f"

def test_cluster_rows_transitive_single_linkage_forward_order():
    rows = [row("http://a.onion/", _SH_A),
            row("http://b.onion/", _SH_B),
            row("http://c.onion/", _SH_C)]
    clusters = cluster_rows(rows, distance=2)
    assert len(clusters) == 1
    assert len(clusters[0]) == 3

def test_cluster_rows_transitive_single_linkage_reverse_order():
    # Same rows, different input order -- result must not depend on order.
    rows = [row("http://c.onion/", _SH_C),
            row("http://a.onion/", _SH_A),
            row("http://b.onion/", _SH_B)]
    clusters = cluster_rows(rows, distance=2)
    assert len(clusters) == 1
    assert len(clusters[0]) == 3

def test_cluster_rows_does_not_over_merge_unrelated_pair():
    # hamming(0x0..0, 0xF..F) == 64 (measured), far beyond any sane distance.
    sh_x = "0000000000000000"
    sh_y = "ffffffffffffffff"
    rows = [row("http://x.onion/", sh_x), row("http://y.onion/", sh_y)]
    clusters = cluster_rows(rows, distance=2)
    assert sorted(len(c) for c in clusters) == [1, 1]


# --- Fix 2: pgp canonical tier must validate the stored fingerprint ---

def test_choose_canonical_pgp_mismatch_falls_through_to_first_seen():
    verified = {
        "verified_onions": [],
        "pgp": {"aaaaaaaaaaaaaaaa.onion":
                "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"},
    }
    cluster = [
        # well-formed fingerprint, but does NOT match verified["pgp"] for
        # this host -- must not win the pgp tier.
        row("http://aaaaaaaaaaaaaaaa.onion/", "0",
            first_seen="2026-05-01T00:00:00",
            pgp_fingerprint="FFFFEEEEDDDDCCCCBBBBAAAA1111222233330000"),
        row("http://bbbbbbbbbbbbbbbb.onion/", "0",
            first_seen="2026-01-01T00:00:00"),
    ]
    canon, why = choose_canonical(cluster, verified)
    assert why == "first_seen"
    assert canon["url"] == "http://bbbbbbbbbbbbbbbb.onion/"   # oldest, wins the fallback tier

def test_choose_canonical_pgp_match_wins_pgp_tier():
    verified = {
        "verified_onions": [],
        "pgp": {"bbbbbbbbbbbbbbbb.onion":
                "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"},
    }
    cluster = [
        # older first_seen, but no validated pgp -- must lose to the pgp tier.
        row("http://aaaaaaaaaaaaaaaa.onion/", "0",
            first_seen="2026-01-01T00:00:00"),
        row("http://bbbbbbbbbbbbbbbb.onion/", "0",
            first_seen="2026-07-01T00:00:00",
            pgp_fingerprint="AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"),
    ]
    canon, why = choose_canonical(cluster, verified)
    assert why == "pgp"
    assert canon["url"] == "http://bbbbbbbbbbbbbbbb.onion/"


# --- Fix 3: cover the previously-untested trust branches ---

def test_run_clustering_unknown_trust_for_unverified_multi_member_cluster(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    sh = to_hex(simhash("acme market buy and sell goods safely here always open"))
    db.upsert_url("http://aaaaaaaaaaaaaaaa.onion/", "aaaaaaaaaaaaaaaa.onion",
                  "crawled", 1, "2026-01-01T00:00:00")
    db.update_url("http://aaaaaaaaaaaaaaaa.onion/", content_simhash=sh)
    db.upsert_url("http://bbbbbbbbbbbbbbbb.onion/", "bbbbbbbbbbbbbbbb.onion",
                  "crawled", 1, "2026-07-01T00:00:00")
    db.update_url("http://bbbbbbbbbbbbbbbb.onion/", content_simhash=sh)
    verified = {"verified_onions": [], "pgp": {}}   # neither row verified nor pgp-matched
    n = run_clustering(db, verified, distance=6)
    assert n == 1
    a = db.get_url("http://aaaaaaaaaaaaaaaa.onion/")
    b = db.get_url("http://bbbbbbbbbbbbbbbb.onion/")
    # "a" has the older first_seen so it wins the fallback tier and becomes canonical.
    assert a["is_canonical"] == 1 and a["trust"] == "unknown"
    assert b["is_canonical"] == 0 and b["trust"] == "suspected_clone"

def test_run_clustering_singleton_gets_probable_trust(tmp_path):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    sh = to_hex(simhash("a totally unique page about rare stamps and coin collecting"))
    db.upsert_url("http://cccccccccccccccc.onion/", "cccccccccccccccc.onion",
                  "crawled", 1, "2026-07-21T00:00:00")
    db.update_url("http://cccccccccccccccc.onion/", content_simhash=sh)
    verified = {"verified_onions": [], "pgp": {}}
    n = run_clustering(db, verified, distance=6)
    assert n == 1
    c = db.get_url("http://cccccccccccccccc.onion/")
    assert c["is_canonical"] == 1 and c["trust"] == "probable"
