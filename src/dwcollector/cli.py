from __future__ import annotations
import argparse
import asyncio
import csv
import inspect
import json
import os
import sys
import time
from datetime import datetime, timezone

from .config import (load_config, load_categories, load_verified_sources,
                     load_sources, load_clients)
from .db import Database
from .tor_client import TorClient
from .discover import crawl
from .probe import reprobe_all
from .categorize import categorize
from .cluster import run_clustering
from .hunt import hunt, load_terms
from .alerts import reconcile_leaks, reconcile_dead_originals, reconcile_anchor_identity
from .report import (client_findings, build_report, render_json, render_markdown,
                     client_cases)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dwcollector")
    p.add_argument("--config", default="config.toml")
    p.add_argument("--db", default="data/dwcollector.db")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("crawl")
    c.add_argument("--resume", action="store_true")
    c.add_argument("--seeds", default="seeds.txt")

    sub.add_parser("probe")
    sub.add_parser("categorize")
    sub.add_parser("cluster")

    h = sub.add_parser("hunt")
    h.add_argument("--terms", required=True)

    e = sub.add_parser("export")
    e.add_argument("--format", choices=["csv", "json"], default="json")
    e.add_argument("--trust", default=None)
    e.add_argument("--category", default=None)

    sub.add_parser("stats")

    ap = sub.add_parser("alerts")
    ap.add_argument("--status", choices=["open", "resolved", "all"], default="open")

    sub.add_parser("triage")

    dp = sub.add_parser("disposition")
    dp.add_argument("finding_id", type=int)
    dp.add_argument("value", choices=["new", "confirmed", "false_positive", "dismissed"])
    dp.add_argument("--note", default=None)
    dp.add_argument("--by", default=None)

    npp = sub.add_parser("note")
    npp.add_argument("finding_id", type=int)
    npp.add_argument("--text", required=True)
    npp.add_argument("--by", default=None)

    hp = sub.add_parser("history")
    hp.add_argument("finding_id", type=int)

    rp = sub.add_parser("report")
    rp.add_argument("--client", required=True)
    rp.add_argument("--format", choices=["md", "json"], default="md")
    rp.add_argument("--since", default=None)
    rp.add_argument("--all", action="store_true")

    cp = sub.add_parser("case")
    csub = cp.add_subparsers(dest="case_action", required=True)
    cc = csub.add_parser("create"); cc.add_argument("title")
    cc.add_argument("--client", default=None); cc.add_argument("--by", default=None)
    cl = csub.add_parser("list")
    cl.add_argument("--client", default=None); cl.add_argument("--state", default=None)
    cs = csub.add_parser("show"); cs.add_argument("case_id", type=int)
    ca = csub.add_parser("assign")
    ca.add_argument("finding_id", type=int); ca.add_argument("case_id", type=int)
    ca.add_argument("--by", default=None)
    cu = csub.add_parser("unassign")
    cu.add_argument("finding_id", type=int); cu.add_argument("--by", default=None)
    cst = csub.add_parser("state"); cst.add_argument("case_id", type=int)
    cst.add_argument("value", choices=["open", "investigating", "closed"])
    cst.add_argument("--note", default=None); cst.add_argument("--by", default=None)
    cn = csub.add_parser("note"); cn.add_argument("case_id", type=int)
    cn.add_argument("--text", required=True); cn.add_argument("--by", default=None)

    # Additional requirement: a 24/7 supervisor loop for continuous VM
    # operation. Repeats "crawl --resume" + "cluster" forever, sleeping
    # `--interval` seconds between cycles. Resumability comes for free from
    # the SQLite frontier table that `crawl` already maintains.
    lp = sub.add_parser("loop")
    lp.add_argument("--interval", type=float, default=1800,
                     help="seconds to sleep between cycles (default: 1800 = 30min)")
    lp.add_argument("--seeds", default="seeds.txt")

    return p


def _read_seeds(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            return [ln.strip() for ln in fh
                    if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        return []


def _run_crawl(cfg, db, args):
    seeds = [] if args.resume else _read_seeds(args.seeds)
    sources = load_sources("sources.toml")

    async def go():
        async with TorClient(cfg) as client:
            stats = await crawl(cfg, db, client, seeds,
                                 f"run-{_now()}", _now(), sources=sources)
            print(f"discovered={stats.discovered} alive={stats.alive} "
                  f"stop={stats.stop_reason}")
    asyncio.run(go())


def _run_categorize(cfg, db):
    rules = load_categories("categories.toml")
    for row in db.all_urls():
        snippet = row.get("snippet") or ""
        res = categorize(row.get("title") or "", snippet, rules)
        db.update_url(row["url"], category=res.category,
                       category_confidence=res.confidence,
                       matched_terms=json.dumps(res.matched_terms))
    print("categorized", len(db.all_urls()), "urls")


def _run_cluster(cfg, db):
    verified = load_verified_sources("verified_sources.toml")
    n = run_clustering(db, verified, cfg.simhash_distance)
    print("clusters:", n)


def _run_hunt(cfg, db, args):
    terms = load_terms(args.terms)
    verified = load_verified_sources("verified_sources.toml")

    async def go():
        async with TorClient(cfg) as client:
            outcome = await hunt(db, client, terms, f"hunt-{_now()}", _now(),
                                 detectors=cfg.pii_detectors, verified=verified)
            print("leak hits:", outcome.hit_count)
    asyncio.run(go())


def _run_export(db, args):
    rows = db.all_urls()
    if args.trust:
        rows = [r for r in rows if r.get("trust") == args.trust]
    if args.category:
        rows = [r for r in rows if r.get("category") == args.category]
    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2)
        print()
    else:
        if rows:
            w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)


def _run_stats(db):
    rows = db.all_urls()
    alive = sum(1 for r in rows if r.get("alive") == 1)
    by_cat: dict[str, int] = {}
    by_trust: dict[str, int] = {}
    for r in rows:
        by_cat[r.get("category") or "unknown"] = by_cat.get(r.get("category") or "unknown", 0) + 1
        by_trust[r.get("trust") or "unrated"] = by_trust.get(r.get("trust") or "unrated", 0) + 1
    print(f"total={len(rows)} alive={alive}")
    print("by_category:", by_cat)
    print("by_trust:", by_trust)


def _run_alerts(db, args) -> None:
    rows = db.list_findings(None if args.status == "all" else args.status)
    for f in rows:
        when = f.get("resolved_at") or f.get("last_seen") or f.get("first_seen")
        term = f.get("term") or "-"
        disp = f.get("disposition") or "new"
        print(f"#{f['finding_id']} [{f['status']}/{disp}] {f['severity']} {f['kind']} "
              f"{term} @ {f['host']} ({when})")
    print(f"total: {len(rows)}")


def _run_triage(db) -> None:
    rows = db.triage_queue()
    for f in rows:
        print(f"#{f['finding_id']} [{f['severity']}] {f['kind']} "
              f"{f.get('term') or '-'} @ {f['host']}")
    print(f"queue: {len(rows)}")


def _run_disposition(db, args) -> int:
    if db.get_finding_by_id(args.finding_id) is None:
        print(f"no finding #{args.finding_id}", file=sys.stderr)
        return 1
    db.set_disposition(args.finding_id, args.value, args.note, args.by, _now())
    print(f"#{args.finding_id} -> {args.value}")
    return 0


def _run_note(db, args) -> int:
    if db.get_finding_by_id(args.finding_id) is None:
        print(f"no finding #{args.finding_id}", file=sys.stderr)
        return 1
    db.add_note(args.finding_id, args.text, args.by, _now())
    print(f"note added to #{args.finding_id}")
    return 0


def _run_history(db, args) -> None:
    for e in db.disposition_history(args.finding_id):
        print(f"{e['at']} {e['disposition']} "
              f"[{e.get('actor') or '-'}] {e.get('note') or ''}")


def _run_report(db, args) -> int:
    clients = load_clients("clients.toml")
    client = next((c for c in clients if c.get("name") == args.client), None)
    if client is None:
        print(f"unknown client: {args.client!r}", file=sys.stderr)
        return 1
    findings = client_findings(db, client, args.all, args.since)
    cases = client_cases(db, args.client)
    report = build_report(args.client, findings, _now(), args.since, cases=cases)
    print(render_json(report) if args.format == "json" else render_markdown(report))
    return 0


def _run_case(db, args) -> int:
    a = args.case_action
    if a == "create":
        cid = db.create_case(args.title, args.client, args.by, _now())
        print(f"created case #{cid}")
        return 0
    if a == "list":
        for c in db.list_cases(client=args.client, state=args.state):
            n = len(db.case_findings(c["case_id"]))
            print(f"#{c['case_id']} [{c['state']}] {c.get('client') or '-'} "
                  f"— {c['title']} ({n} findings)")
        return 0
    if a == "show":
        c = db.get_case(args.case_id)
        if c is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        closed = f", closed {c['closed_at']}" if c.get("closed_at") else ""
        print(f"#{c['case_id']} [{c['state']}] {c.get('client') or '-'} — {c['title']}")
        print(f"created {c['created_at']} by {c.get('created_by') or '-'}{closed}")
        print("findings:")
        for f in db.case_findings(args.case_id):
            print(f"  #{f['finding_id']} {f['severity']} {f['kind']} "
                  f"{f.get('term') or '-'} @ {f['host']} [{f.get('disposition') or 'new'}]")
        print("timeline:")
        for e in db.case_history(args.case_id):
            note = f" {e['note']}" if e.get("note") else ""
            print(f"  {e['at']} {e['event']} [{e.get('actor') or '-'}]{note}")
        return 0
    if a == "assign":
        if db.get_finding_by_id(args.finding_id) is None:
            print(f"no finding #{args.finding_id}", file=sys.stderr)
            return 1
        if db.get_case(args.case_id) is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        db.assign_finding(args.finding_id, args.case_id, args.by, _now())
        print(f"assigned #{args.finding_id} -> case #{args.case_id}")
        return 0
    if a == "unassign":
        if db.get_finding_by_id(args.finding_id) is None:
            print(f"no finding #{args.finding_id}", file=sys.stderr)
            return 1
        db.unassign_finding(args.finding_id, args.by, _now())
        print(f"unassigned #{args.finding_id}")
        return 0
    if a == "state":
        if db.get_case(args.case_id) is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        db.set_case_state(args.case_id, args.value, args.note, args.by, _now())
        print(f"case #{args.case_id} -> {args.value}")
        return 0
    if a == "note":
        if db.get_case(args.case_id) is None:
            print(f"no case #{args.case_id}", file=sys.stderr)
            return 1
        db.add_case_note(args.case_id, args.text, args.by, _now())
        print(f"note added to case #{args.case_id}")
        return 0
    return 1


def run_cycle(cfg, db, seeds_path: str = "seeds.txt",
              crawl_fn=None, cluster_fn=None,
              client_factory=None) -> dict:
    """Run one crawl+cluster+hunt cycle for the supervisor loop.

    Deliberately reads `seeds_path` fresh every cycle rather than honoring
    a "resume" toggle: `db.upsert_url`/`db.enqueue` are INSERT-OR-IGNORE, so
    re-supplying the same seeds against an already-populated SQLite frontier
    is a no-op for anything already known, while still self-healing a fresh
    (or partially-lost) database. The actual "resume" behavior -- picking up
    an in-progress crawl -- comes for free from the frontier table's
    'pending'/'in_progress'/'deferred' rows, which `crawl()` continues to
    drain regardless of what's passed as `seeds`.

    Never raises: any failure (Tor down, bad config file, etc.) is caught
    and reported in the returned dict so a 24/7 supervisor loop can log it
    and move on to the next cycle instead of dying. `crawl_fn`, `cluster_fn`,
    and `client_factory` are injectable for tests; production leaves them at
    the real implementations (`crawl`, `run_clustering`, `TorClient`).

    `crawl_fn`/`cluster_fn` default to `None` (resolved to the module-level
    `crawl`/`run_clustering` *inside* the function body, not as bound default
    values) so that `monkeypatch.setattr(cli_mod, "crawl", ...)` -- used by
    the existing per-stage isolation tests -- keeps working: a default bound
    at `def` time would freeze in the pre-monkeypatch function object.
    """
    if crawl_fn is None:
        crawl_fn = crawl
    if cluster_fn is None:
        cluster_fn = run_clustering
    if client_factory is None:
        client_factory = TorClient
    result: dict = {"ok": True, "started_at": _now()}

    try:
        seeds = _read_seeds(seeds_path)
        sources = load_sources("sources.toml")

        async def go():
            async with client_factory(cfg) as client:
                out = crawl_fn(cfg, db, client, seeds,
                                f"run-{_now()}", _now(), sources=sources)
                if inspect.isawaitable(out):
                    out = await out
                return out

        stats = asyncio.run(go())
        result["crawl"] = {
            "discovered": stats.discovered,
            "alive": stats.alive,
            "stop_reason": stats.stop_reason,
        }
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"crawl failed: {exc!r}"
        return result

    try:
        verified = load_verified_sources("verified_sources.toml")
        result["clusters"] = cluster_fn(db, verified, cfg.simhash_distance)
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"cluster failed: {exc!r}"

    try:
        clients = load_clients("clients.toml")
        base = load_terms(cfg.watchlist_terms) if os.path.exists(cfg.watchlist_terms) else []
        terms = list(dict.fromkeys(base + [t for c in clients for t in c["terms"]]))
        verified = load_verified_sources("verified_sources.toml")
        run_id = f"run-{_now()}"

        async def go_hunt():
            async with client_factory(cfg) as client:
                return await hunt(db, client, terms, run_id, _now(),
                                  detectors=cfg.pii_detectors, verified=verified)

        outcome = asyncio.run(go_hunt())
        emitted = []
        if terms:
            emitted += reconcile_leaks(db, cfg, run_id, outcome.covered_urls, _now())
        else:
            result["hunt_skipped"] = "no watchlist terms (anchors still re-verified)"
        emitted += reconcile_dead_originals(db, cfg, _now())
        emitted += reconcile_anchor_identity(db, cfg, outcome.identity_checked,
                                             outcome.identity_failed, _now())
        result["alerts"] = len(emitted)
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"hunt/alert failed: {exc!r}"

    return result


def supervisor_loop(cfg, db, seeds_path: str = "seeds.txt", interval: float = 1800,
                     max_iterations: int | None = None,
                     sleep_fn=time.sleep, cycle_fn=run_cycle) -> int:
    """Repeat `cycle_fn` (crawl --resume + cluster) forever, sleeping
    `interval` seconds between runs. `max_iterations` and `sleep_fn` exist so
    tests can bound and speed this up; production code (the `loop` CLI
    command / docker-compose's default command) leaves both at their
    infinite-loop / real-sleep defaults.

    A cycle that raises -- even though `run_cycle` already catches its own
    errors and returns {"ok": False, ...} -- is still caught here as a
    second line of defense, so a single bad cycle (of any kind) can never
    take down the supervisor: it is logged and the loop continues.
    """
    i = 0
    while max_iterations is None or i < max_iterations:
        try:
            result = cycle_fn(cfg, db, seeds_path)
            if result.get("ok", True):
                print(f"[loop] cycle {i} ok: {result}")
            else:
                print(f"[loop] cycle {i} FAILED: {result.get('error')}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - never let a bad cycle kill the loop
            print(f"[loop] cycle {i} CRASHED: {exc!r}", file=sys.stderr)
        i += 1
        if max_iterations is None or i < max_iterations:
            sleep_fn(interval)
    return i


def _run_loop(cfg, db, args):
    print(f"[loop] starting supervisor loop (interval={args.interval}s, "
          f"seeds={args.seeds}, db={args.db})")
    supervisor_loop(cfg, db, seeds_path=args.seeds, interval=args.interval)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config(args.config)

    db_dir = os.path.dirname(args.db)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    db = Database(args.db)
    db.init_schema()

    if args.command == "loop":
        _run_loop(cfg, db, args)
    elif args.command == "crawl":
        _run_crawl(cfg, db, args)
    elif args.command == "probe":
        async def go():
            async with TorClient(cfg) as client:
                print("alive:", await reprobe_all(db, client, _now()))
        asyncio.run(go())
    elif args.command == "categorize":
        _run_categorize(cfg, db)
    elif args.command == "cluster":
        _run_cluster(cfg, db)
    elif args.command == "hunt":
        _run_hunt(cfg, db, args)
    elif args.command == "export":
        _run_export(db, args)
    elif args.command == "stats":
        _run_stats(db)
    elif args.command == "alerts":
        _run_alerts(db, args)
    elif args.command == "triage":
        _run_triage(db)
    elif args.command == "disposition":
        return _run_disposition(db, args)
    elif args.command == "note":
        return _run_note(db, args)
    elif args.command == "history":
        _run_history(db, args)
    elif args.command == "report":
        return _run_report(db, args)
    elif args.command == "case":
        return _run_case(db, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
