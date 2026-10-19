from onionwatch.config import load_config, load_categories, load_verified_sources

def test_load_config_defaults(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        'socks_proxy = "socks5://127.0.0.1:9050"\n'
        "max_depth = 0\n"
        "concurrency = 8\n"
        "simhash_distance = 3\n"
    )
    cfg = load_config(str(cfg_file))
    assert cfg.socks_proxy == "socks5://127.0.0.1:9050"
    assert cfg.max_depth == 0
    assert cfg.concurrency == 8
    assert cfg.simhash_distance == 3
    # unspecified keys fall back to defaults
    assert cfg.request_timeout == 60.0
    assert cfg.ahmia_enabled is True

def test_load_config_warns_on_unknown_keys(tmp_path, capsys):
    # Fix 5: a typo'd tuning key must be surfaced on stderr (not silently
    # dropped) so it's visible on an unattended box -- then load proceeds.
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        "concurrency = 4\n"
        "conccurency = 99\n"          # typo -> should be reported
        'unknown_option = "x"\n'
    )
    cfg = load_config(str(cfg_file))
    assert cfg.concurrency == 4       # known key still applied
    err = capsys.readouterr().err
    assert "conccurency" in err
    assert "unknown_option" in err


def test_load_categories(tmp_path):
    f = tmp_path / "categories.toml"
    f.write_text('marketplace = ["market", "vendor"]\nforum = ["forum", "board"]\n')
    rules = load_categories(str(f))
    assert rules["marketplace"] == ["market", "vendor"]
    assert rules["forum"] == ["forum", "board"]

def test_load_verified_sources_lowercases_keys(tmp_path):
    f = tmp_path / "verified_sources.toml"
    f.write_text(
        'verified_onions = ["AAAABBBBCCCCDDDD.onion"]\n'
        "[pgp]\n"
        '"AAAABBBBCCCCDDDD.onion" = "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"\n'
    )
    verified = load_verified_sources(str(f))
    assert verified["verified_onions"] == ["aaaabbbbccccdddd.onion"]
    assert "aaaabbbbccccdddd.onion" in verified["pgp"]
    # fingerprint value itself is left untouched (canonicalized at compare time)
    assert verified["pgp"]["aaaabbbbccccdddd.onion"] == (
        "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
    )

def test_alert_config_defaults():
    from onionwatch.config import Config
    c = Config()
    assert c.watchlist_terms == "terms.txt"
    assert c.alerts_path == "data/alerts.jsonl"
    assert c.alert_webhook == ""

def test_alert_config_parsed_from_toml(tmp_path):
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text(
        'watchlist_terms = "wl.txt"\n'
        'alerts_path = "out/a.jsonl"\n'
        'alert_webhook = "https://sink.local/hook"\n'
    )
    cfg = load_config(str(cfg_file))
    assert cfg.watchlist_terms == "wl.txt"
    assert cfg.alerts_path == "out/a.jsonl"
    assert cfg.alert_webhook == "https://sink.local/hook"


def test_pii_detectors_default_empty():
    from onionwatch.config import Config
    assert Config().pii_detectors == []


def test_pii_detectors_parsed_and_unknown_warned(tmp_path, capsys):
    from onionwatch.config import load_config
    p = tmp_path / "c.toml"
    p.write_text('pii_detectors = ["credit-card", "not-real", "us-ssn"]\n')
    c = load_config(str(p))
    assert c.pii_detectors == ["credit-card", "us-ssn"]   # unknown dropped
    err = capsys.readouterr().err
    assert "not-real" in err                              # warned to stderr


def test_max_seeds_per_source_default():
    from onionwatch.config import Config
    assert Config().max_seeds_per_source == 200


def test_load_sources_missing_file_returns_empty(tmp_path):
    from onionwatch.config import load_sources
    assert load_sources(str(tmp_path / "nope.toml")) == []


def test_load_sources_parses_and_skips_malformed(tmp_path, capsys):
    from onionwatch.config import load_sources
    p = tmp_path / "sources.toml"
    p.write_text(
        '[[source]]\n'
        'name = "idx"\n'
        'type = "index"\n'
        'url = "http://i.onion/"\n\n'
        '[[source]]\n'
        'name = "srch"\n'
        'type = "search"\n'
        'url_template = "http://s.onion/?q={query}"\n'
        'queries = ["market"]\n\n'
        '[[source]]\n'          # malformed: index with no url
        'name = "bad"\n'
        'type = "index"\n'
    )
    srcs = load_sources(str(p))
    assert {s["name"] for s in srcs} == {"idx", "srch"}
    assert "bad" in capsys.readouterr().err


def test_load_clients_missing_file_returns_empty(tmp_path):
    from onionwatch.config import load_clients
    assert load_clients(str(tmp_path / "nope.toml")) == []


def test_load_clients_parses_and_skips_malformed(tmp_path, capsys):
    from onionwatch.config import load_clients
    p = tmp_path / "clients.toml"
    p.write_text(
        '[[client]]\n'
        'name = "Acme Corp"\n'
        'terms = ["acme-corp.com", "fuzzy:ACME-DB"]\n\n'
        '[[client]]\n'          # malformed: no terms
        'name = "Beta"\n'
    )
    cs = load_clients(str(p))
    assert [c["name"] for c in cs] == ["Acme Corp"]
    assert "Beta" in capsys.readouterr().err


def test_load_config_crawl_priority(tmp_path):
    from onionwatch.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        "concurrency = 8\n"
        "\n"
        "[crawl_priority]\n"
        "default = 0\n"
        "market = 100\n"
        "forum = 80\n"
    )
    cfg = load_config(str(cfg_file))
    assert cfg.crawl_priority == {"default": 0, "market": 100, "forum": 80}


def test_load_config_crawl_priority_absent_is_empty(tmp_path):
    from onionwatch.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("concurrency = 8\n")
    cfg = load_config(str(cfg_file))
    assert cfg.crawl_priority == {}


def test_priority_for_mapped_unmapped_and_default():
    from onionwatch.config import priority_for
    weights = {"default": 5, "market": 100}
    assert priority_for("market", weights) == 100     # mapped
    assert priority_for("forum", weights) == 5        # unmapped -> default
    assert priority_for("unknown", weights) == 5      # unknown -> default
    assert priority_for("market", {}) == 0            # no default -> 0
    assert priority_for("anything", {}) == 0


def test_crawl_priority_drops_non_integer_weights(tmp_path, capsys):
    from onionwatch.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        "concurrency = 8\n"
        "\n"
        "[crawl_priority]\n"
        "market = 100\n"
        'forum = "high"\n'
    )
    cfg = load_config(str(cfg_file))
    assert cfg.crawl_priority == {"market": 100}
    err = capsys.readouterr().err
    assert "forum" in err


def test_crawl_priority_all_integers_no_warning(tmp_path, capsys):
    from onionwatch.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        "concurrency = 8\n"
        "\n"
        "[crawl_priority]\n"
        "market = 100\n"
        "forum = 80\n"
    )
    cfg = load_config(str(cfg_file))
    assert cfg.crawl_priority == {"market": 100, "forum": 80}
    err = capsys.readouterr().err
    assert "crawl_priority" not in err
