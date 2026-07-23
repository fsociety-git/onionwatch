from types import SimpleNamespace

from dwcollector.cli import build_parser, run_cycle, supervisor_loop, _run_alerts
from dwcollector.config import Config, load_config
from dwcollector.db import Database
from dwcollector.tor_client import FetchResult


class _StubClient:
    """Async-context client whose fetch always returns the given html OK."""
    def __init__(self, html): self.html = html
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def fetch(self, url):
        return FetchResult(url, 200, self.html, 10, True)


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


def test_run_cycle_hunts_and_alerts(tmp_path, monkeypatch):
    import dwcollector.cli as cli_mod

    db = Database(str(tmp_path / "t.db")); db.init_schema()
    # a verified canonical site to hunt
    u = "http://good.onion/"
    db.upsert_url(u, "good.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", category="leak-site", alive=1)
    wl = tmp_path / "wl.txt"; wl.write_text("acme.com\n")
    cfg = Config(watchlist_terms=str(wl), alerts_path=str(tmp_path / "a.jsonl"))

    # run_cycle's cluster stage hardcodes a load of "verified_sources.toml" from
    # the cwd before cluster_fn ever runs. That file is gitignored/untracked, so
    # on a clean checkout it's absent and load_verified_sources would raise,
    # making the whole cycle fail before the hunt stage we're testing here.
    # cluster_fn is stubbed and never consumes the returned value, so stubbing
    # load_verified_sources with the same empty-but-valid shape is safe and
    # makes this test hermetic (independent of any local operator config file).
    monkeypatch.setattr(
        cli_mod, "load_verified_sources",
        lambda path: {"verified_onions": [], "pgp": {}, "directories": []},
    )

    html = "<html><body>dump has acme.com inside</body></html>"
    res = run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=1, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient(html),
    )
    assert res["ok"] is True
    assert res["alerts"] == 1
    fs = db.list_findings("open")
    assert any(f["kind"] == "leak" and f["severity"] == "critical" for f in fs)


def test_run_cycle_skips_hunt_without_watchlist(tmp_path, monkeypatch):
    import dwcollector.cli as cli_mod

    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(watchlist_terms=str(tmp_path / "missing.txt"),
                 alerts_path=str(tmp_path / "a.jsonl"))
    # See comment in test_run_cycle_hunts_and_alerts: stub load_verified_sources
    # so this test doesn't depend on a local, gitignored verified_sources.toml.
    monkeypatch.setattr(
        cli_mod, "load_verified_sources",
        lambda path: {"verified_onions": [], "pgp": {}, "directories": []},
    )
    res = run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient(""),
    )
    assert res["ok"] is True
    assert res.get("alerts", 0) == 0
    assert "hunt_skipped" in res


def test_run_cycle_reverifies_anchor_identity(tmp_path, monkeypatch):
    import dwcollector.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    u = "http://aaaaaaaaaaaaaaaa.onion/"
    db.upsert_url(u, "aaaaaaaaaaaaaaaa.onion", "crawled", 1, "2026-07-23T00:00:00")
    db.update_url(u, is_canonical=1, trust="verified", cluster_id="c1")
    cfg = Config(watchlist_terms=str(tmp_path / "wl.txt"),   # missing -> no terms
                 alerts_path=str(tmp_path / "a.jsonl"))
    # verified marks aaaaaaaaaaaaaaaa.onion as a PGP anchor; the served page has NO valid fp
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "directories": [],
                                      "pgp": {"aaaaaaaaaaaaaaaa.onion": "1234 5678 9ABC DEF0 1234 5678 9ABC DEF0 1234 5678"}})

    class _Stub:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch(self, url):
            return FetchResult(url, 200, "<html><body>no key here</body></html>", 10, True)

    res = run_cycle(cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
                    crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=1, stop_reason="ok"),
                    cluster_fn=lambda *a, **k: 0,
                    client_factory=lambda cfg: _Stub())
    assert res["ok"] is True
    # anchor pass ran despite no watchlist, and identity failure opened a HIGH finding
    fs = db.list_findings("open")
    assert any(f["kind"] == "anchor_identity" and f["severity"] == "high" for f in fs)
    assert res["alerts"] >= 1


def test_alerts_command_lists_findings(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "…", "2026-07-23T00:00:00")
    db.open_finding("dead_original", "dead:http://y.onion/", "http://y.onion/",
                    "y.onion", None, "high", None, "2026-07-23T00:00:00")
    db.resolve_finding("dead:http://y.onion/", "2026-07-23T01:00:00")

    args = build_parser().parse_args(["alerts", "--status", "open"])
    _run_alerts(db, args)
    out = capsys.readouterr().out
    assert "acme.com" in out and "critical" in out
    assert "y.onion" not in out          # resolved, excluded by --status open
    assert "total: 1" in out

    args_all = build_parser().parse_args(["alerts", "--status", "all"])
    _run_alerts(db, args_all)
    out_all = capsys.readouterr().out
    assert "total: 2" in out_all
