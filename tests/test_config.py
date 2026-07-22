from dwcollector.config import load_config, load_categories, load_verified_sources

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
