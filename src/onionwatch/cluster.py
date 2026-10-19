from __future__ import annotations
from .fingerprint import from_hex, hamming
from .verify import is_verified, pgp_fingerprint_matches

def cluster_rows(rows: list[dict], distance: int) -> list[list[dict]]:
    """Group rows into connected components of the "hamming(simhash) <=
    distance" graph (single-linkage / transitive clustering), via union-find.

    A row joins a cluster if it is within `distance` of ANY member of that
    cluster, not just the cluster's first member -- so if A~B and B~C but
    A is not directly ~C, all three still end up in one cluster regardless
    of processing order. Rows without a content_simhash -- or whose simhash
    decodes to 0, which means "no fingerprint" (an empty or non-tokenizable
    page) -- never get unioned with anything and so remain singletons. This
    prevents every fingerprint-less page collapsing into one bogus
    hamming-0 cluster.
    """
    n = len(rows)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    def _val(r: dict) -> int | None:
        sh = r.get("content_simhash")
        if not sh:
            return None
        v = from_hex(sh)
        return v if v != 0 else None

    vals: list[int | None] = [_val(r) for r in rows]

    for i in range(n):
        if vals[i] is None:
            continue
        for j in range(i + 1, n):
            if vals[j] is None:
                continue
            if hamming(vals[i], vals[j]) <= distance:
                union(i, j)

    groups: dict[int, list[dict]] = {}
    for i, r in enumerate(rows):
        groups.setdefault(find(i), []).append(r)
    return list(groups.values())

def choose_canonical(cluster: list[dict], verified: dict) -> tuple[dict, str]:
    for r in cluster:
        if is_verified(r["url"], verified):
            return r, "verified"
    for r in cluster:
        if pgp_fingerprint_matches(r.get("host"), r.get("pgp_fingerprint"), verified):
            return r, "pgp"
    with_seen = [r for r in cluster if r.get("first_seen")]
    if with_seen:
        return min(with_seen, key=lambda r: r["first_seen"]), "first_seen"
    return max(cluster, key=lambda r: r.get("inbound_links") or 0), "inbound_links"

def run_clustering(db, verified: dict, distance: int) -> int:
    rows = db.all_urls()
    clusters = cluster_rows(rows, distance)
    count = 0
    for idx, cluster in enumerate(clusters):
        cluster_id = f"c{idx:06d}"
        canon, why = choose_canonical(cluster, verified)
        db.set_cluster(cluster_id, canon["url"], len(cluster), why)
        for r in cluster:
            is_canon = r["url"] == canon["url"]
            if is_canon:
                # Trust comes ONLY from an anchor: the verified list, or a
                # validated PGP fingerprint. A singleton or an unverified
                # multi-member cluster head is "unknown" -- never auto-trusted,
                # so a phishing clone whose real original was never crawled
                # can't be treated as legit just for being un-clustered.
                if why == "verified":
                    trust = "verified"
                elif why == "pgp":
                    trust = "probable"
                else:
                    trust = "unknown"
            else:
                trust = "suspected_clone"
            db.update_url(
                r["url"], cluster_id=cluster_id,
                is_canonical=1 if is_canon else 0,
                clone_of=None if is_canon else canon["url"],
                trust=trust)
        count += 1
    return count
