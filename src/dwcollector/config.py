from __future__ import annotations
import tomllib
from dataclasses import dataclass, fields

@dataclass
class Config:
    socks_proxy: str = "socks5://tor:9050"
    tor_control_port: int = 9051
    max_depth: int = 0            # 0 = unlimited
    max_urls: int = 50000
    time_budget_min: int = 120
    per_host_page_cap: int = 500
    concurrency: int = 8
    per_host_delay: float = 2.0
    request_timeout: float = 60.0
    max_retries: int = 3
    user_agent: str = "dwcollector/0.1"
    ahmia_enabled: bool = True
    snippet_chars: int = 500
    simhash_distance: int = 3

def _read_toml(path: str) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)

def load_config(path: str = "config.toml") -> Config:
    data = _read_toml(path)
    known = {f.name for f in fields(Config)}
    return Config(**{k: v for k, v in data.items() if k in known})

def load_categories(path: str = "categories.toml") -> dict[str, list[str]]:
    return {k: list(v) for k, v in _read_toml(path).items()}

def load_verified_sources(path: str = "verified_sources.toml") -> dict:
    # returns {"verified_onions": [...], "pgp": {onion: fingerprint}, "directories": [...]}
    data = _read_toml(path)
    data.setdefault("verified_onions", [])
    data.setdefault("pgp", {})
    data.setdefault("directories", [])
    return data
