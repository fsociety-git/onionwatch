from __future__ import annotations
from .fingerprint import from_hex, hamming
from .verify import is_verified

def cluster_rows(rows: list[dict], distance: int) -> list[list[dict]]:
    clusters: list[list[dict]] = []
    reps: list[int] = []            # representative simhash per cluster
    for r in rows:
        sh = r.get("content_simhash")
        if not sh:
            clusters.append([r]); reps.append(None)
            continue
        val = from_hex(sh)
        placed = False
        for i, rep in enumerate(reps):
            if rep is not None and hamming(val, rep) <= distance:
                clusters[i].append(r); placed = True; break
        if not placed:
            clusters.append([r]); reps.append(val)
    return clusters

def choose_canonical(cluster: list[dict], verified: dict) -> tuple[dict, str]:
    for r in cluster:
        if is_verified(r["url"], verified):
            return r, "verified"
    for r in cluster:
        if r.get("pgp_fingerprint"):
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
        singleton = len(cluster) == 1
        db.set_cluster(cluster_id, canon["url"], len(cluster), why)
        for r in cluster:
            is_canon = r["url"] == canon["url"]
            if is_canon:
                if why == "verified":
                    trust = "verified"
                elif why == "pgp" or singleton:
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
