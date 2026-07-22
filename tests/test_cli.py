from dwcollector.cli import build_parser, run_cycle, supervisor_loop
from dwcollector.config import load_config
from dwcollector.db import Database


def test_parser_has_subcommands():
    p = build_parser()
    args = p.parse_args(["hunt", "--terms", "client.txt"])
    assert args.command == "hunt"
    assert args.terms == "client.txt"


def test_export_flags():
    p = build_parser()
    args = p.parse_args(["export", "--format", "csv", "--category", "leak-site"])
    assert args.format == "csv"
    assert args.category == "leak-site"


def test_crawl_resume_flag():
    p = build_parser()
    args = p.parse_args(["crawl", "--resume"])
    assert args.command == "crawl"
    assert args.resume is True


def test_loop_parser_defaults():
    p = build_parser()
    args = p.parse_args(["loop"])
    assert args.command == "loop"
    assert args.interval == 1800
    assert args.seeds == "seeds.txt"


def test_loop_parser_custom_interval():
    p = build_parser()
    args = p.parse_args(["loop", "--interval", "60"])
    assert args.interval == 60


def test_stats_and_probe_and_categorize_and_cluster_parse():
    p = build_parser()
    assert p.parse_args(["stats"]).command == "stats"
    assert p.parse_args(["probe"]).command == "probe"
    assert p.parse_args(["categorize"]).command == "categorize"
    assert p.parse_args(["cluster"]).command == "cluster"


# --- supervisor loop: single-cycle error isolation (Additional Requirement) ---
# These tests factor the loop body into `run_cycle`/`supervisor_loop` so we can
# exercise "one cycle's failure doesn't kill the loop" offline, without ever
# running (or needing to bound) a real infinite loop.

def test_supervisor_loop_survives_cycle_exception():
    calls = []

    def bad_cycle(cfg, db, seeds_path):
        calls.append(seeds_path)
        raise RuntimeError("boom")

    n = supervisor_loop(
        None, None, seeds_path="s.txt", interval=0,
        max_iterations=3, sleep_fn=lambda s: None, cycle_fn=bad_cycle,
    )
    assert n == 3
    assert calls == ["s.txt", "s.txt", "s.txt"]


def test_supervisor_loop_survives_cycle_error_result():
    calls = []

    def erroring_cycle(cfg, db, seeds_path):
        calls.append(1)
        return {"ok": False, "error": "boom"}

    n = supervisor_loop(
        None, None, interval=0, max_iterations=2,
        sleep_fn=lambda s: None, cycle_fn=erroring_cycle,
    )
    assert n == 2
    assert len(calls) == 2


def test_supervisor_loop_sleeps_between_cycles_not_after_last():
    sleeps = []

    def ok_cycle(cfg, db, seeds_path):
        return {"ok": True}

    supervisor_loop(
        None, None, interval=42, max_iterations=3,
        sleep_fn=lambda s: sleeps.append(s), cycle_fn=ok_cycle,
    )
    assert sleeps == [42, 42]  # slept between cycles, not after the final one


def test_run_cycle_isolates_crawl_exception(tmp_path, monkeypatch):
    import dwcollector.cli as cli_mod

    db = Database(str(tmp_path / "t.db"))
    db.init_schema()
    cfg = load_config("config.toml")

    def boom(*a, **kw):
        raise RuntimeError("network gone")

    monkeypatch.setattr(cli_mod, "crawl", boom)

    result = cli_mod.run_cycle(cfg, db, seeds_path=str(tmp_path / "nonexistent_seeds.txt"))
    assert result["ok"] is False
    assert "crawl failed" in result["error"]


def test_run_cycle_isolates_cluster_exception(tmp_path, monkeypatch):
    import dwcollector.cli as cli_mod

    db = Database(str(tmp_path / "t.db"))
    db.init_schema()
    cfg = load_config("config.toml")

    def boom(*a, **kw):
        raise RuntimeError("bad verified sources")

    monkeypatch.setattr(cli_mod, "run_clustering", boom)

    result = cli_mod.run_cycle(cfg, db, seeds_path=str(tmp_path / "nonexistent_seeds.txt"))
    assert result["ok"] is False
    assert "cluster failed" in result["error"]
