from __future__ import annotations
import sys
import tomllib
from dataclasses import dataclass, fields, field

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
    watchlist_terms: str = "terms.txt"
    alerts_path: str = "data/alerts.jsonl"
    alert_webhook: str = ""          # empty = webhook disabled
    pii_detectors: list[str] = field(default_factory=list)
    max_seeds_per_source: int = 200

def _read_toml(path: str) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)

def load_config(path: str = "config.toml") -> Config:
    data = _read_toml(path)
    known = {f.name for f in fields(Config)}
    # Surface typo'd/ignored tuning keys on an unattended box, then proceed.
    ignored = [k for k in data if k not in known]
    if ignored:
        print(f"config: ignoring unknown key(s): {', '.join(sorted(ignored))}",
              file=sys.stderr)
    cfg = Config(**{k: v for k, v in data.items() if k in known})
    if cfg.pii_detectors:
        from .matching import available_detectors
        valid = set(available_detectors())
        unknown = [d for d in cfg.pii_detectors if d not in valid]
        if unknown:
            print(f"config: ignoring unknown pii_detectors: {', '.join(unknown)}",
                  file=sys.stderr)
        cfg.pii_detectors = [d for d in cfg.pii_detectors if d in valid]
    return cfg

def load_categories(path: str = "categories.toml") -> dict[str, list[str]]:
    return {k: list(v) for k, v in _read_toml(path).items()}

def load_verified_sources(path: str = "verified_sources.toml") -> dict:
    # returns {"verified_onions": [...], "pgp": {onion: fingerprint}, "directories": [...]}
    data = _read_toml(path)
    data.setdefault("verified_onions", [])
    data.setdefault("pgp", {})
    data.setdefault("directories", [])
    # Normalize onion identifiers to lowercase (matches onion_host()'s always-
    # lowercase output) so hand-edited mixed-case entries don't silently fail
    # is_verified()/pgp_matches(). Fingerprint values are left untouched --
    # they're canonicalized separately at compare time.
    data["verified_onions"] = [str(h).lower() for h in data["verified_onions"]]
    data["pgp"] = {str(h).lower(): fp for h, fp in data["pgp"].items()}
    return data

def load_sources(path: str = "sources.toml") -> list[dict]:
    try:
        data = _read_toml(path)
    except FileNotFoundError:
        return []
    valid: list[dict] = []
    for i, s in enumerate(data.get("source", [])):
        name, typ = s.get("name"), s.get("type")
        ok = bool(name) and typ in ("index", "search")
        if ok and typ == "index":
            ok = bool(s.get("url"))
        if ok and typ == "search":
            tmpl = s.get("url_template") or ""
            ok = "{query}" in tmpl and bool(s.get("queries"))
        if ok:
            valid.append(s)
        else:
            print(f"sources: skipping malformed source entry #{i} "
                  f"({name or '?'})", file=sys.stderr)
    return valid
