from __future__ import annotations
import json
import os
import sys

from .matching import find_matches


LEAK_SEVERITY = "critical"
DEAD_SEVERITY = "high"
ANCHOR_IDENTITY_SEVERITY = "high"
LISTING_SEVERITY = "high"
SUPPRESSED_DISPOSITIONS = ("false_positive", "dismissed")


def _post_webhook(cfg, payload) -> None:
    import httpx
    with httpx.Client(timeout=10.0) as c:
        c.post(cfg.alert_webhook, json=payload)


def _append_jsonl(path: str, payload: dict) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")


def _title(finding: dict, event: str) -> str:
    term = finding.get("term") or ""
    if finding["kind"] == "leak" and term.startswith("pii:"):
        label = term[len("pii:"):]
        if event == "opened":
            return f"{label.capitalize()} data detected on {finding['host']}"
        return f"{label.capitalize()} exposure on {finding['host']} resolved"
    if finding["kind"] == "leak":
        if event == "opened":
            return f"Client identifier '{finding['term']}' exposed on {finding['host']}"
        return f"Exposure of '{finding['term']}' on {finding['host']} resolved"
    if finding["kind"] == "anchor_identity":
        if event == "opened":
            return f"Verified anchor {finding['host']} failed identity re-verification"
        return f"Anchor {finding['host']} identity re-verification recovered"
    if finding["kind"] == "market_listing":
        if event == "opened":
            return (f"Watchlist term '{finding['term']}' offered in a market "
                    f"listing on {finding['host']}")
        return f"Market listing of '{finding['term']}' on {finding['host']} gone"
    if event == "opened":
        return f"Verified original {finding['host']} went dark"
    return f"Verified original {finding['host']} recovered"


def _body(finding: dict, event: str) -> str:
    if finding["kind"] == "leak":
        return (f"url={finding['url']} term={finding['term']} "
                f"snippet={finding.get('context_snippet') or ''}")
    if finding["kind"] == "market_listing":
        note = finding.get("context_snippet") or ""
        body = (f"url={finding['url']} term={finding['term']} "
                f"— matched in an extracted marketplace listing")
        return f"{body} · {note}" if note else body
    reason = ("anchor identity re-verification failed"
              if finding["kind"] == "anchor_identity"
              else "canonical trusted site liveness changed")
    note = finding.get("context_snippet") or ""
    body = f"url={finding['url']} — {reason}"
    return f"{body} · {note}" if note else body


def emit(db, cfg, finding: dict, event: str, now: str, post_fn=_post_webhook) -> dict:
    severity = finding["severity"]
    title = _title(finding, event)
    body = _body(finding, event)
    payload = {
        "event": event, "severity": severity, "kind": finding["kind"],
        "url": finding.get("url"), "host": finding.get("host"),
        "term": finding.get("term"), "title": title, "body": body,
        "created_at": now, "dedup_key": finding["dedup_key"],
    }
    if finding.get("disposition") in SUPPRESSED_DISPOSITIONS:
        try:
            db.record_alert(finding.get("finding_id"), finding["dedup_key"], event,
                            severity, title, body, now, 0, None, suppressed=1)
        except Exception:  # noqa: BLE001 - best-effort audit; never crash the loop
            pass
        return payload
    delivered = 0
    error = None
    try:
        _append_jsonl(cfg.alerts_path, payload)
    except Exception as exc:  # noqa: BLE001 - sink failure must not crash loop
        error = f"jsonl: {exc!r}"
    try:
        print(f"[alert] {severity.upper()} {event} {title}", file=sys.stderr)
    except Exception:  # noqa: BLE001 - broken stderr must not crash loop
        pass
    if cfg.alert_webhook:
        try:
            post_fn(cfg, payload)
            delivered = 1
        except Exception as exc:  # noqa: BLE001 - webhook failure must not crash loop
            error = (error + "; " if error else "") + f"webhook: {exc!r}"
    # Durable record is best-effort; emit must never crash the caller's loop.
    try:
        db.record_alert(finding.get("finding_id"), finding["dedup_key"], event,
                        severity, title, body, now, delivered, error)
    except Exception as exc:  # noqa: BLE001 - db failure must not crash loop
        try:
            print(f"[alert] WARNING: failed to persist alert row: {exc!r}", file=sys.stderr)
        except Exception:  # noqa: BLE001 - broken stderr must not crash loop
            pass
    return payload


def reconcile_leaks(db, cfg, run_id, covered_urls, now, emit_fn=emit) -> list[dict]:
    alerts = []
    seen_keys = set()
    for h in db.leak_hits_for_run(run_id):
        key = f"leak:{h['url']}|{h['term']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        existing = db.get_finding(key)
        if existing is None:
            db.open_finding("leak", key, h["url"], h["host"], h["term"],
                            LEAK_SEVERITY, h.get("context_snippet"), now)
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        elif existing["status"] == "resolved":
            db.reopen_finding(key, now, h.get("context_snippet"))
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        else:
            db.touch_finding(key, now)
    for f in db.open_findings("leak"):
        if f["dedup_key"] in seen_keys:
            continue
        if f["url"] in covered_urls:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts


def _listing_snippet(lst, mt) -> str:
    price = lst.get("price_raw") or ""
    return f"[{price}] {mt.context}" if price else mt.context


def reconcile_listing_matches(db, cfg, terms, detectors, now, emit_fn=emit) -> list[dict]:
    alerts, seen_keys = [], set()
    for lst in db.list_listings():
        for mt in find_matches(lst.get("product_text") or "", terms, detectors):
            key = f"listing:{lst['host']}|{mt.key}"
            if key in seen_keys:
                continue
            seen_keys.add(key)
            snippet = _listing_snippet(lst, mt)
            existing = db.get_finding(key)
            if existing is None:
                db.open_finding("market_listing", key, lst["url"], lst["host"],
                                mt.key, LISTING_SEVERITY, snippet, now)
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            elif existing["status"] == "resolved":
                db.reopen_finding(key, now, snippet)
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            else:
                db.touch_finding(key, now)
    for f in db.open_findings("market_listing"):
        if f["dedup_key"] not in seen_keys:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts


def _candidate_note(db, row: dict) -> str:
    sibs = db.live_cluster_siblings(row.get("cluster_id"), row["url"])
    if sibs:
        urls = ", ".join(s["url"] for s in sibs)
        return f"verify before trusting — candidate successors: {urls}"
    return "verify before trusting — no live successor discovered yet"


def reconcile_dead_originals(db, cfg, now, emit_fn=emit) -> list[dict]:
    alerts = []
    dead_keys = set()
    for r in db.canonical_trusted_urls():
        key = f"dead:{r['url']}"
        if r.get("alive") == 0:
            dead_keys.add(key)
            existing = db.get_finding(key)
            if existing is None:
                db.open_finding("dead_original", key, r["url"], r["host"], None,
                                DEAD_SEVERITY, _candidate_note(db, r), now)
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            elif existing["status"] == "resolved":
                db.reopen_finding(key, now, _candidate_note(db, r))
                alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
            else:
                db.touch_finding(key, now)
    for f in db.open_findings("dead_original"):
        if f["dedup_key"] not in dead_keys:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts


def reconcile_anchor_identity(db, cfg, identity_checked, identity_failed, now,
                              emit_fn=emit) -> list[dict]:
    alerts = []
    for url in identity_failed:
        key = f"identity:{url}"
        row = db.get_url(url) or {"url": url, "host": None, "cluster_id": None}
        note = _candidate_note(db, row)
        existing = db.get_finding(key)
        if existing is None:
            db.open_finding("anchor_identity", key, url, row.get("host"), None,
                            ANCHOR_IDENTITY_SEVERITY, note, now)
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        elif existing["status"] == "resolved":
            db.reopen_finding(key, now, note)
            alerts.append(emit_fn(db, cfg, db.get_finding(key), "opened", now))
        else:
            db.touch_finding(key, now)
    recovered = set(identity_checked) - set(identity_failed)
    for f in db.open_findings("anchor_identity"):
        if f["url"] in recovered:
            db.resolve_finding(f["dedup_key"], now)
            alerts.append(emit_fn(db, cfg, db.get_finding(f["dedup_key"]), "resolved", now))
    return alerts
