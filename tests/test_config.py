from dwcollector.config import load_config, load_categories

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

def test_load_categories(tmp_path):
    f = tmp_path / "categories.toml"
    f.write_text('marketplace = ["market", "vendor"]\nforum = ["forum", "board"]\n')
    rules = load_categories(str(f))
    assert rules["marketplace"] == ["market", "vendor"]
    assert rules["forum"] == ["forum", "board"]
