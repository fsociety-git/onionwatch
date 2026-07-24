from __future__ import annotations
import json
from .matching import underlying_key

_DISMISSED = ("false_positive", "dismissed")


def client_findings(db, client: dict, include_all: bool, since: str | None) -> list[dict]:
    keys = {underlying_key(t) for t in client.get("terms", [])}
    rows = [f for f in db.list_findings()
            if f.get("kind") == "leak" and f.get("term") in keys]
    if not include_all:
        rows = [f for f in rows if f.get("disposition") not in _DISMISSED]
    if since:
        rows = [f for f in rows if (f.get("last_seen") or "") >= since]
    # stable two-pass: most-recent first, then open-before-resolved / critical-before-high
    rows.sort(key=lambda f: f.get("last_seen") or "", reverse=True)
    rows.sort(key=lambda f: (0 if f.get("status") == "open" else 1,
                             0 if f.get("severity") == "critical" else 1))
    return rows


def build_report(client_name: str, findings: list[dict], now: str,
                 since: str | None = None) -> dict:
    summary = {
        "total": len(findings),
        "open": sum(1 for f in findings if f.get("status") == "open"),
        "resolved": sum(1 for f in findings if f.get("status") == "resolved"),
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high": sum(1 for f in findings if f.get("severity") == "high"),
        "sites": len({f.get("host") for f in findings}),
    }
    return {
        "client": client_name, "generated_at": now, "since": since,
        "summary": summary,
        "findings": [{
            "host": f.get("host"), "term": f.get("term"), "severity": f.get("severity"),
            "status": f.get("status"), "disposition": f.get("disposition") or "new",
            "first_seen": f.get("first_seen"), "last_seen": f.get("last_seen"),
            "evidence": f.get("context_snippet") or "",
        } for f in findings],
    }


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render_markdown(report: dict) -> str:
    s = report["summary"]
    since = f"  ·  since {report['since']}" if report.get("since") else ""
    lines = [
        f"# Dark-web exposure report — {report['client']}",
        "",
        f"Generated: {report['generated_at']}{since}",
        "",
        (f"**{s['total']}** findings — {s['open']} open, {s['resolved']} resolved · "
         f"{s['critical']} critical, {s['high']} high · {s['sites']} sites"),
        "",
    ]
    if not report["findings"]:
        lines.append("_No findings._")
    for f in report["findings"]:
        lines += [
            f"## {f['host']} — `{f['term']}`",
            f"- Severity: {f['severity']}  ·  Status: {f['status']}  ·  Disposition: {f['disposition']}",
            f"- First seen: {f['first_seen']}  ·  Last seen: {f['last_seen']}",
            f"- Evidence: {f['evidence']}",
            "",
        ]
    return "\n".join(lines)
