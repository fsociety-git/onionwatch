from __future__ import annotations
import argparse
import asyncio
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone

from .config import load_config, load_categories, load_verified_sources
from .db import Database
from .tor_client import TorClient
from .discover import crawl
from .probe import reprobe_all
from .categorize import categorize
from .cluster import run_clustering
from .hunt import hunt, load_terms


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

    async def go():
        async with TorClient(cfg) as client:
            stats = await crawl(cfg, db, client, seeds,
                                 f"run-{_now()}", _now())
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

    async def go():
        async with TorClient(cfg) as client:
            n = await hunt(db, client, terms, f"hunt-{_now()}", _now())
            print("leak hits:", n)
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


def run_cycle(cfg, db, seeds_path: str = "seeds.txt") -> dict:
    """Run one crawl+cluster cycle for the supervisor loop.

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
    and move on to the next cycle instead of dying.
    """
    result: dict = {"ok": True, "started_at": _now()}
    try:
        seeds = _read_seeds(seeds_path)

        async def go():
            async with TorClient(cfg) as client:
                return await crawl(cfg, db, client, seeds,
                                    f"run-{_now()}", _now())

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
        result["clusters"] = run_clustering(db, verified, cfg.simhash_distance)
    except Exception as exc:  # noqa: BLE001 - isolate this cycle's failure
        result["ok"] = False
        result["error"] = f"cluster failed: {exc!r}"

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
