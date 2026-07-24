from __future__ import annotations
import json
from datetime import datetime
from .matching import underlying_key

_DISMISSED = ("false_positive", "dismissed")
_TS = "%Y-%m-%dT%H:%M:%S"


def _finding_entry(f: dict) -> dict:
    return {
        "host": f.get("host"), "term": f.get("term"), "kind": f.get("kind"),
        "severity": f.get("severity"), "status": f.get("status"),
        "disposition": f.get("disposition") or "new",
        "first_seen": f.get("first_seen"), "last_seen": f.get("last_seen"),
        "evidence": f.get("context_snippet") or "",
    }


def _fmt_delta(td) -> str:
    total = max(0, int(td.total_seconds()))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if not parts:
        parts.append(f"{mins}m")
    return " ".join(parts)


def _parse_ts(s):
    try:
        return datetime.strptime(s, _TS)
    except (TypeError, ValueError):
        return None


def _duration(created_at, closed_at, now) -> str:
    start = _parse_ts(created_at)
    if start is None:
        return ""
    if closed_at:
        end = _parse_ts(closed_at)
        return _fmt_delta(end - start) if end else ""
    end = _parse_ts(now)
    return "open " + _fmt_delta(end - start) if end else ""


def _count_by(findings, key) -> dict:
    fn = key if callable(key) else (lambda f: f.get(key))
    out = {}
    for f in findings:
        k = fn(f)
        out[k] = out.get(k, 0) + 1
    return out


def build_case_report(case: dict, findings: list[dict],
                      history: list[dict], now: str) -> dict:
    summary = {
        "total": len(findings),
        "open": sum(1 for f in findings if f.get("status") == "open"),
        "resolved": sum(1 for f in findings if f.get("status") == "resolved"),
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high": sum(1 for f in findings if f.get("severity") == "high"),
        "by_kind": _count_by(findings, "kind"),
        "by_disposition": _count_by(findings, lambda f: f.get("disposition") or "new"),
        "sites": len({f.get("host") for f in findings}),
    }
    return {
        "case": {
            "case_id": case["case_id"], "title": case["title"],
            "client": case.get("client"), "state": case["state"],
            "created_at": case.get("created_at"),
            "created_by": case.get("created_by"),
            "closed_at": case.get("closed_at"),
            "duration": _duration(case.get("created_at"),
                                  case.get("closed_at"), now),
        },
        "generated_at": now,
        "summary": summary,
        "findings": [_finding_entry(f) for f in findings],
        "timeline": [{"at": h.get("at"), "actor": h.get("actor"),
                      "event": h.get("event"), "note": h.get("note")}
                     for h in history],
    }


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


def client_cases(db, client_name: str) -> list[dict]:
    return [{"case_id": c["case_id"], "title": c["title"], "state": c["state"],
             "findings": len(db.case_findings(c["case_id"]))}
            for c in db.list_cases(client=client_name)]


def build_report(client_name: str, findings: list[dict], now: str,
                 since: str | None = None, cases: list[dict] | None = None) -> dict:
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
        "cases": cases or [],
        "findings": [_finding_entry(f) for f in findings],
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
    if report.get("cases"):
        lines += ["## Cases", ""]
        for c in report["cases"]:
            lines.append(f"- #{c['case_id']} [{c['state']}] {c['title']} "
                         f"({c['findings']} findings)")
        lines.append("")
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


def render_case_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def render_case_markdown(report: dict) -> str:
    c, s = report["case"], report["summary"]
    by_kind = ", ".join(f"{k} {n}" for k, n in s["by_kind"].items()) or "none"
    by_disp = ", ".join(f"{k} {n}" for k, n in s["by_disposition"].items()) or "none"
    lines = [
        f"# Incident Report: {c['title']} (case #{c['case_id']})",
        "",
        f"- Client: {c['client'] or '—'}",
        f"- State: {c['state']}  ·  Duration: {c['duration'] or '—'}",
        f"- Opened: {c['created_at']} by {c['created_by'] or '—'}",
        f"- Closed: {c['closed_at'] or '—'}",
        f"- Generated: {report['generated_at']}",
        "",
        (f"**{s['total']}** findings — {s['open']} open, {s['resolved']} resolved · "
         f"{s['critical']} critical, {s['high']} high · {s['sites']} sites"),
        f"- By kind: {by_kind}",
        f"- By disposition: {by_disp}",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("_No findings in this case._")
        lines.append("")
    for f in report["findings"]:
        lines += [
            f"### {f['host']} — `{f['term']}`",
            (f"- Kind: {f['kind']}  ·  Severity: {f['severity']}  ·  "
             f"Status: {f['status']}  ·  Disposition: {f['disposition']}"),
            f"- First seen: {f['first_seen']}  ·  Last seen: {f['last_seen']}",
            f"- Evidence: {f['evidence']}",
            "",
        ]
    lines += ["## Timeline", ""]
    if not report["timeline"]:
        lines.append("_No timeline events._")
    for e in report["timeline"]:
        note = f" — {e['note']}" if e.get("note") else ""
        lines.append(f"- {e['at']} — {e['actor'] or '—'}: {e['event']}{note}")
    return "\n".join(lines)
