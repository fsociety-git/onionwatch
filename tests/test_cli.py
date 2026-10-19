from types import SimpleNamespace

from onionwatch.cli import build_parser, run_cycle, supervisor_loop, _run_alerts
from onionwatch.config import Config, load_config
from onionwatch.db import Database
from onionwatch.hunt import HuntOutcome
from onionwatch.tor_client import FetchResult


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
    import onionwatch.cli as cli_mod

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
    import onionwatch.cli as cli_mod

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
    import onionwatch.cli as cli_mod

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
    import onionwatch.cli as cli_mod

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
    import onionwatch.cli as cli_mod
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


# --- regression: `hunt --terms` (manual CLI path) must pass `verified` into
# hunt() so the PGP-identity safety cutout (SAFETY CUTOUT in hunt.py) applies
# on this path too, not just inside run_cycle's supervisor loop. ---

def test_run_hunt_passes_verified_sources_to_hunt(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod

    known_verified = {
        "pgp": {"aaaaaaaaaaaaaaaa.onion": "AAAA BBBB"},
        "verified_onions": [],
        "directories": [],
    }
    monkeypatch.setattr(cli_mod, "load_verified_sources", lambda path: known_verified)

    class _StubTorClient:
        def __init__(self, cfg): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch(self, url):
            raise AssertionError("fetch should not be called; hunt() is stubbed")

    monkeypatch.setattr(cli_mod, "TorClient", _StubTorClient)

    calls = []

    async def fake_hunt(db, client, terms, run_id, now, detectors=None, verified=None):
        calls.append(verified)
        return HuntOutcome(0, set(), set(), set())

    monkeypatch.setattr(cli_mod, "hunt", fake_hunt)

    terms_path = tmp_path / "terms.txt"
    terms_path.write_text("acme.com\n")

    db = Database(str(tmp_path / "t.db"))
    db.init_schema()
    cfg = load_config("config.toml")
    args = SimpleNamespace(terms=str(terms_path))

    cli_mod._run_hunt(cfg, db, args)

    assert len(calls) == 1
    assert calls[0] == known_verified


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


def test_run_cycle_passes_sources_to_crawl(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config(watchlist_terms=str(tmp_path / "none.txt"),
                 alerts_path=str(tmp_path / "a.jsonl"))
    src = [{"name": "s", "type": "index", "url": "http://i.onion/"}]
    monkeypatch.setattr(cli_mod, "load_sources", lambda path: src)
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "pgp": {}, "directories": []})

    recorded = {}

    def crawl_stub(cfg, db, client, seeds, run_id, now, sources=None, **k):
        recorded["sources"] = sources
        return SimpleNamespace(discovered=0, alive=0, stop_reason="ok")

    class _Stub:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch(self, url): return None

    res = run_cycle(cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
                    crawl_fn=crawl_stub, cluster_fn=lambda *a, **k: 0,
                    client_factory=lambda cfg: _Stub())
    assert res["ok"] is True
    assert recorded["sources"] == src


def test_run_crawl_passes_sources(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cfg = Config()
    src = [{"name": "s", "type": "index", "url": "http://i.onion/"}]
    monkeypatch.setattr(cli_mod, "load_sources", lambda path: src)
    seeds_file = tmp_path / "seeds.txt"; seeds_file.write_text("")
    recorded = {}

    async def crawl_stub(cfg, db, client, seeds, run_id, now, sources=None, **k):
        recorded["sources"] = sources
        return SimpleNamespace(discovered=0, alive=0, stop_reason="ok")

    class _Stub:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def fetch(self, url): return None

    monkeypatch.setattr(cli_mod, "crawl", crawl_stub)
    monkeypatch.setattr(cli_mod, "TorClient", lambda cfg: _Stub())
    args = SimpleNamespace(resume=False, seeds=str(seeds_file))
    cli_mod._run_crawl(cfg, db, args)
    assert recorded["sources"] == src


# --- Task 4: triage / disposition / note / history commands ---

from onionwatch.cli import _run_triage, _run_disposition, _run_note, _run_history


def _seed_finding(db, dedup="leak:http://x.onion/|acme.com", sev="critical"):
    db.open_finding("leak", dedup, "http://x.onion/", "x.onion", "acme.com",
                    sev, "…", "2026-07-24T00:00:00")
    return db.get_finding(dedup)["finding_id"]


def test_triage_and_disposition_flow(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_finding(db)
    _run_triage(db)
    assert f"#{fid}" in capsys.readouterr().out              # in the queue

    args = build_parser().parse_args(
        ["disposition", str(fid), "false_positive", "--note", "test data", "--by", "alice"])
    assert _run_disposition(db, args) == 0
    assert db.get_finding_by_id(fid)["disposition"] == "false_positive"
    capsys.readouterr()                                     # clear the "#id -> …" output

    _run_triage(db)
    assert f"#{fid}" not in capsys.readouterr().out          # dropped from queue after disposition

    hargs = build_parser().parse_args(["history", str(fid)])
    _run_history(db, hargs)
    hout = capsys.readouterr().out
    assert "false_positive" in hout and "test data" in hout and "alice" in hout


def test_disposition_bad_id_errors(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    args = build_parser().parse_args(["disposition", "99999", "confirmed"])
    assert _run_disposition(db, args) == 1                   # non-zero exit
    assert "99999" in capsys.readouterr().err


def test_note_command_appends(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_finding(db)
    args = build_parser().parse_args(["note", str(fid), "--text", "watching this"])
    assert _run_note(db, args) == 0
    assert any(e["note"] == "watching this" for e in db.disposition_history(fid))


def test_alerts_command_shows_disposition(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_finding(db)
    db.set_disposition(fid, "confirmed", None, None, "2026-07-24T01:00:00")
    args = build_parser().parse_args(["alerts", "--status", "open"])
    _run_alerts(db, args)
    assert "confirmed" in capsys.readouterr().out


from onionwatch.report import client_findings as _cf  # noqa: F401 (ensures import path)


def test_run_cycle_unions_client_terms(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.hunt import HuntOutcome
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    (tmp_path / "wl.txt").write_text("baseterm\n")
    cfg = Config(watchlist_terms=str(tmp_path / "wl.txt"),
                 alerts_path=str(tmp_path / "a.jsonl"))
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "C", "terms": ["clientterm"]}])
    monkeypatch.setattr(cli_mod, "load_sources", lambda p: [])
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda p: {"verified_onions": [], "pgp": {}, "directories": []})
    recorded = {}

    async def hunt_stub(db, client, terms, run_id, now, detectors=None, verified=None):
        recorded["terms"] = terms
        return HuntOutcome(0, set(), set(), set())
    monkeypatch.setattr(cli_mod, "hunt", hunt_stub)

    res = run_cycle(cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
                    crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
                    cluster_fn=lambda *a, **k: 0, client_factory=lambda cfg: _StubClient(""))
    assert res["ok"] is True
    assert "baseterm" in recorded["terms"] and "clientterm" in recorded["terms"]


def test_report_command_json_and_unknown_client(tmp_path, capsys, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "ev", "2026-07-24T00:00:00")
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "Acme", "terms": ["acme.com"]}])

    args = build_parser().parse_args(["report", "--client", "Acme", "--format", "json"])
    assert _run_report(db, args) == 0
    import json as _json
    doc = _json.loads(capsys.readouterr().out)
    assert doc["client"] == "Acme" and doc["summary"]["total"] == 1

    bad = build_parser().parse_args(["report", "--client", "Nope"])
    assert _run_report(db, bad) == 1
    assert "Nope" in capsys.readouterr().err


def test_report_all_flag_includes_dismissed(tmp_path, capsys, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "ev", "2026-07-24T00:00:00")
    db.set_disposition(db.get_finding("leak:http://x.onion/|acme.com")["finding_id"],
                       "dismissed", None, None, "2026-07-24T01:00:00")
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "Acme", "terms": ["acme.com"]}])
    import json as _json
    _run_report(db, build_parser().parse_args(["report", "--client", "Acme", "--format", "json"]))
    assert _json.loads(capsys.readouterr().out)["summary"]["total"] == 0   # dismissed excluded
    _run_report(db, build_parser().parse_args(["report", "--client", "Acme", "--format", "json", "--all"]))
    assert _json.loads(capsys.readouterr().out)["summary"]["total"] == 1   # --all includes


def test_report_case_command(tmp_path, capsys):
    import json as _json
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    cid = db.create_case("Acme breach", "Acme", "an@corp", "2026-07-24T00:00:00")
    db.open_finding("leak", "leak:x", "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ev", "2026-07-24T01:00:00")
    fid = db.get_finding("leak:x")["finding_id"]
    db.assign_finding(fid, cid, "an@corp", "2026-07-24T02:00:00")

    # JSON
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", str(cid), "--format", "json"])) == 0
    doc = _json.loads(capsys.readouterr().out)
    assert doc["case"]["case_id"] == cid and doc["summary"]["total"] == 1

    # Markdown
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", str(cid)])) == 0
    md = capsys.readouterr().out
    assert f"case #{cid}" in md and "x.onion" in md and "acme.com" in md

    # unknown case id -> stderr + exit 1
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", "99999"])) == 1
    assert "99999" in capsys.readouterr().err


def test_report_case_empty_dossier(tmp_path, capsys):
    import json as _json
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()

    # Create a case with NO findings assigned
    cid = db.create_case("Empty case", "Acme", "an@corp", "2026-07-24T00:00:00")

    # JSON format: zero counts, exit 0
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", str(cid), "--format", "json"])) == 0
    doc = _json.loads(capsys.readouterr().out)
    assert doc["summary"]["total"] == 0
    assert doc["case"]["case_id"] == cid
    assert len(doc["timeline"]) > 0  # at least the "created" event

    # Markdown format: exit 0, contains case id and empty-findings placeholder
    assert _run_report(db, build_parser().parse_args(
        ["report", "--case", str(cid)])) == 0
    md = capsys.readouterr().out
    assert f"case #{cid}" in md
    assert "_No findings in this case._" in md


def test_report_requires_exactly_one_target():
    import pytest
    from onionwatch.cli import build_parser
    with pytest.raises(SystemExit):                     # neither --client nor --case
        build_parser().parse_args(["report"])
    with pytest.raises(SystemExit):                     # both -> mutually exclusive
        build_parser().parse_args(["report", "--client", "A", "--case", "1"])


# --- Task 3: nested `case` CLI command group ---

from onionwatch.cli import build_parser, _run_case


def _seed_case_finding(db, dedup="leak:http://x.onion/|acme.com"):
    db.open_finding("leak", dedup, "http://x.onion/", "x.onion", "acme.com",
                    "critical", "ev", "2026-07-24T00:00:00")
    return db.get_finding(dedup)["finding_id"]


def test_case_create_assign_state_show(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_case_finding(db)

    assert _run_case(db, build_parser().parse_args(
        ["case", "create", "Acme breach", "--client", "Acme Corp"])) == 0
    out = capsys.readouterr().out
    assert "created case #1" in out
    cid = 1

    assert _run_case(db, build_parser().parse_args(
        ["case", "assign", str(fid), str(cid), "--by", "alice"])) == 0
    capsys.readouterr()
    assert db.get_finding_by_id(fid)["case_id"] == cid

    assert _run_case(db, build_parser().parse_args(
        ["case", "state", str(cid), "investigating", "--note", "working"])) == 0
    capsys.readouterr()
    assert db.get_case(cid)["state"] == "investigating"

    assert _run_case(db, build_parser().parse_args(["case", "show", str(cid)])) == 0
    show = capsys.readouterr().out
    assert "Acme breach" in show and f"#{fid}" in show and "investigating" in show
    assert "assigned finding" in show          # timeline present


def test_case_bad_ids_error(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    assert _run_case(db, build_parser().parse_args(["case", "show", "999"])) == 1
    assert "999" in capsys.readouterr().err
    db.create_case("C", None, None, "2026-07-24T00:00:00")
    assert _run_case(db, build_parser().parse_args(["case", "assign", "42", "1"])) == 1  # no finding #42
    assert "42" in capsys.readouterr().err


def test_case_assign_bad_case_id(tmp_path, capsys):
    # Test case assign with valid finding but bad/nonexistent case_id.
    # This covers the second validation branch in the assign action.
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    fid = _seed_case_finding(db)

    # Try to assign valid finding to nonexistent case #999
    assert _run_case(db, build_parser().parse_args(
        ["case", "assign", str(fid), "999", "--by", "alice"])) == 1
    assert "999" in capsys.readouterr().err

    # Verify the finding's case_id was NOT set (no partial write)
    assert db.get_finding_by_id(fid)["case_id"] is None


def test_case_list_and_note(tmp_path, capsys):
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    _run_case(db, build_parser().parse_args(["case", "create", "One", "--client", "Acme"]))
    _run_case(db, build_parser().parse_args(["case", "create", "Two"]))
    capsys.readouterr()
    _run_case(db, build_parser().parse_args(["case", "list", "--client", "Acme"]))
    lst = capsys.readouterr().out
    assert "One" in lst and "Two" not in lst
    assert _run_case(db, build_parser().parse_args(["case", "note", "1", "--text", "hi"])) == 0
    assert any(e["note"] == "hi" for e in db.case_history(1))


def test_report_command_shows_cases(tmp_path, capsys, monkeypatch):
    import onionwatch.cli as cli_mod
    from onionwatch.cli import build_parser, _run_report
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.open_finding("leak", "leak:http://x.onion/|acme.com", "http://x.onion/",
                    "x.onion", "acme.com", "critical", "ev", "2026-07-24T00:00:00")
    cid = db.create_case("Acme breach", "Acme", None, "2026-07-24T00:00:00")
    db.assign_finding(db.get_finding("leak:http://x.onion/|acme.com")["finding_id"],
                      cid, None, "2026-07-24T01:00:00")
    monkeypatch.setattr(cli_mod, "load_clients",
                        lambda p: [{"name": "Acme", "terms": ["acme.com"]}])
    import json
    _run_report(db, build_parser().parse_args(["report", "--client", "Acme", "--format", "json"]))
    doc = json.loads(capsys.readouterr().out)
    assert doc["cases"][0]["title"] == "Acme breach"


# --- Task 4: listings CLI command ---

def test_listings_command_json_and_filters(tmp_path, capsys):
    import json as _json
    from onionwatch.cli import build_parser, _run_listings
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://a.onion/1", "a.onion", [
        {"price_value": 0.05, "currency": "BTC", "price_raw": "0.05 BTC", "product_text": "cocaine grams"},
        {"price_value": 50.0, "currency": "USD", "price_raw": "$50", "product_text": "cvv pack"},
    ], "2026-07-24T00:00:00")

    # JSON, all
    _run_listings(db, build_parser().parse_args(["listings", "--format", "json"]))
    doc = _json.loads(capsys.readouterr().out)
    assert len(doc) == 2

    # currency filter is upper-cased
    _run_listings(db, build_parser().parse_args(["listings", "--currency", "usd", "--format", "json"]))
    doc = _json.loads(capsys.readouterr().out)
    assert len(doc) == 1 and doc[0]["currency"] == "USD"

    # contains filter
    _run_listings(db, build_parser().parse_args(["listings", "--contains", "cocaine", "--format", "json"]))
    doc = _json.loads(capsys.readouterr().out)
    assert len(doc) == 1 and doc[0]["product_text"] == "cocaine grams"


def test_listings_command_empty_ok(tmp_path, capsys):
    from onionwatch.cli import build_parser, _run_listings
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    # table format, no rows -> valid output, no crash
    _run_listings(db, build_parser().parse_args(["listings"]))
    out = capsys.readouterr().out
    assert "total: 0" in out


def test_run_cycle_creates_market_listing_findings(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://m.onion/1", "m.onion", [
        {"price_value": 0.05, "currency": "BTC", "price_raw": "0.05 BTC",
         "product_text": "acme.com dump 0.05 BTC"}], "2026-07-24T00:00:00")
    wl = tmp_path / "wl.txt"; wl.write_text("acme.com\n")
    cfg = Config(watchlist_terms=str(wl), alerts_path=str(tmp_path / "a.jsonl"),
                 extract_listings=True)
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "pgp": {}, "directories": []})
    res = run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient("<html></html>"))
    assert res["ok"] is True
    fs = db.list_findings("open")
    assert any(f["kind"] == "market_listing" and f["term"] == "acme.com"
               and f["severity"] == "high" for f in fs)


def test_run_cycle_no_listing_findings_when_extract_off(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://m.onion/1", "m.onion", [
        {"price_value": 0.05, "currency": "BTC", "price_raw": "0.05 BTC",
         "product_text": "acme.com dump"}], "2026-07-24T00:00:00")
    wl = tmp_path / "wl.txt"; wl.write_text("acme.com\n")
    cfg = Config(watchlist_terms=str(wl), alerts_path=str(tmp_path / "a.jsonl"),
                 extract_listings=False)          # gate off
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "pgp": {}, "directories": []})
    run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient("<html></html>"))
    assert not any(f["kind"] == "market_listing" for f in db.list_findings("open"))


def test_run_cycle_no_listing_findings_when_watchlist_empty(tmp_path, monkeypatch):
    import onionwatch.cli as cli_mod
    db = Database(str(tmp_path / "t.db")); db.init_schema()
    db.replace_listings("http://m.onion/1", "m.onion", [
        {"price_value": 0.05, "currency": "BTC", "price_raw": "0.05 BTC",
         "product_text": "acme.com dump"}], "2026-07-24T00:00:00")
    cfg = Config(watchlist_terms=str(tmp_path / "missing.txt"),
                 alerts_path=str(tmp_path / "a.jsonl"),
                 extract_listings=True)
    monkeypatch.setattr(cli_mod, "load_verified_sources",
                        lambda path: {"verified_onions": [], "pgp": {}, "directories": []})
    run_cycle(
        cfg, db, seeds_path=str(tmp_path / "seeds.txt"),
        crawl_fn=lambda *a, **k: SimpleNamespace(discovered=0, alive=0, stop_reason="ok"),
        cluster_fn=lambda *a, **k: 0,
        client_factory=lambda cfg: _StubClient("<html></html>"))
    assert not any(f["kind"] == "market_listing" for f in db.list_findings("open"))
