from __future__ import annotations
import json
import os
import sys


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
    if finding["kind"] == "leak":
        if event == "opened":
            return f"Client identifier '{finding['term']}' exposed on {finding['host']}"
        return f"Exposure of '{finding['term']}' on {finding['host']} resolved"
    if event == "opened":
        return f"Verified original {finding['host']} went dark"
    return f"Verified original {finding['host']} recovered"


def _body(finding: dict, event: str) -> str:
    if finding["kind"] == "leak":
        return (f"url={finding['url']} term={finding['term']} "
                f"snippet={finding.get('context_snippet') or ''}")
    return f"url={finding['url']} — canonical trusted site liveness changed"


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
