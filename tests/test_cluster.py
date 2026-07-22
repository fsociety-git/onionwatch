from dwcollector.cluster import cluster_rows, choose_canonical, run_clustering
from dwcollector.fingerprint import simhash, to_hex
from dwcollector.db import Database

def row(url, sh, first_seen="2026-07-21T00:00:00", inbound=0, host=None):
    return {"url": url, "content_simhash": sh,
            "first_seen": first_seen, "inbound_links": inbound,
            "host": host or url[7:-1]}

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
