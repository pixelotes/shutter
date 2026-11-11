"""Notifications: Slack, Microsoft Teams, email (SMTP) and a generic webhook.

Configured as [[notify]] entries in shutter.toml. Secrets (webhook URLs, SMTP passwords) are read from
environment variables, never from the file. A notification failure is reported but never blocks or
aborts a run.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage
from pathlib import Path

EVENTS = ["dry-run", "execute-start", "execute-end", "execute-refused", "rollback-start", "rollback-end"]
DEFAULT_EVENTS = [e for e in EVENTS if e != "dry-run"]

TITLES = {
    "dry-run": "SHUTTER dry-run completed (nothing changed)",
    "execute-start": "🚨 SHUTTER containment STARTED",
    "execute-end": "🚨 SHUTTER containment FINISHED",
    "execute-refused": "SHUTTER execution REFUSED",
    "rollback-start": "SHUTTER rollback STARTED",
    "rollback-end": "SHUTTER rollback FINISHED",
}


def _summary(event: str, rep: dict, extra: dict) -> dict:
    items = rep["items"]
    by = {}
    for i in items:
        by[i["status"]] = by.get(i["status"], 0) + 1
    failed = [f"{i['category']}: {i['name']}" for i in items if i["status"] in ("failed", "drift", "in-progress")]
    return {
        "event": event, "title": TITLES[event], "tool": rep["tool"], "runId": rep["run"]["id"],
        "mode": rep["run"]["mode"], "tenantId": rep["run"]["tenantId"],
        "operator": rep["run"]["operator"].get("upn"), "startedAt": rep["run"]["startedAt"],
        "finishedAt": rep["run"].get("finishedAt"), "counts": by, "attention": failed[:20],
        "approval": rep["run"].get("approval", {}).get("approver", {}).get("upn"),
        **extra,
    }


def _text(s: dict) -> str:
    lines = [s["title"], f"Tenant: {s['tenantId']}", f"Operator: {s['operator']}", f"Run: {s['runId']} ({s['mode']})"]
    if s.get("approval"):
        lines.append(f"Approved by: {s['approval']}")
    if s["counts"]:
        lines.append("Items: " + ", ".join(f"{k}={v}" for k, v in sorted(s["counts"].items())))
    if s["attention"]:
        lines.append("Needs attention:\n" + "\n".join(f"  • {a}" for a in s["attention"]))
    if s.get("reason"):
        lines.append(f"Reason: {s['reason']}")
    if s.get("reportSha256"):
        lines.append(f"report.json sha256: {s['reportSha256']}")
    if s.get("archive"):
        lines.append("Archived: " + ", ".join(s["archive"]))
    return "\n".join(lines)


def _post(url: str, payload: dict) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


def _env(ch: dict, key: str) -> str:
    var = ch.get(key)
    val = os.environ.get(var or "")
    if not val:
        raise RuntimeError(f"environment variable {var!r} ({key}) is not set")
    return val


def send_slack(ch: dict, s: dict, report_dir: Path | None) -> None:
    _post(_env(ch, "url_env"), {"text": _text(s)})


def send_teams(ch: dict, s: dict, report_dir: Path | None) -> None:
    """Teams 'Workflows' incoming webhook (Adaptive Card)."""
    facts = [{"title": t, "value": str(v)} for t, v in (
        ("Tenant", s["tenantId"]), ("Operator", s["operator"]), ("Run", s["runId"]), ("Mode", s["mode"]),
        ("Approved by", s.get("approval")), ("Items", ", ".join(f"{k}={v}" for k, v in sorted(s["counts"].items()))),
        ("report.json sha256", s.get("reportSha256"))) if v]
    body = [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": s["title"], "wrap": True},
            {"type": "FactSet", "facts": facts}]
    if s["attention"]:
        body.append({"type": "TextBlock", "text": "Needs attention:\n- " + "\n- ".join(s["attention"]), "wrap": True, "color": "Attention"})
    if s.get("reason"):
        body.append({"type": "TextBlock", "text": f"Reason: {s['reason']}", "wrap": True})
    _post(_env(ch, "url_env"), {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                    "version": "1.4", "body": body}}]})


def send_webhook(ch: dict, s: dict, report_dir: Path | None) -> None:
    _post(_env(ch, "url_env"), s)


def send_email(ch: dict, s: dict, report_dir: Path | None) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"{s['title']} — tenant {s['tenantId'][:8]}"
    msg["From"] = ch["from"]
    msg["To"] = ", ".join(ch["to"])
    msg.set_content(_text(s))
    if ch.get("attach_report", True) and report_dir and (report_dir / "report.html").exists():
        msg.add_attachment((report_dir / "report.html").read_bytes(), maintype="text", subtype="html",
                           filename=f"shutter-{s['runId'][:8]}.html")
    with smtplib.SMTP(ch["smtp_host"], ch.get("smtp_port", 587), timeout=30) as smtp:
        if ch.get("starttls", True):
            smtp.starttls(context=ssl.create_default_context())
        if ch.get("username_env"):
            smtp.login(_env(ch, "username_env"), _env(ch, "password_env"))
        smtp.send_message(msg)


SENDERS = {"slack": send_slack, "teams": send_teams, "email": send_email, "webhook": send_webhook}


def notify(cfg: dict, event: str, rep: dict, report_dir: Path | None = None, **extra) -> list[dict]:
    results = []
    for ch in cfg.get("notify", []):
        if event not in ch.get("events", DEFAULT_EVENTS):
            continue
        name = ch.get("name", ch["type"])
        try:
            SENDERS[ch["type"]](ch, _summary(event, rep, extra), report_dir)
            results.append({"channel": name, "event": event, "ok": True})
        except Exception as e:  # never let a notification break containment
            results.append({"channel": name, "event": event, "ok": False, "error": str(e)[:300]})
            print(f"  \033[33m⚠ notification {name} ({event}) failed: {e}\033[0m")
    rep.setdefault("notifications", []).extend(results)
    return results
