"""persiana — emergency lockdown for Entra ID + Azure. Dry-run by default."""
from __future__ import annotations

import argparse
import copy
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, actions, config, inventory, preflight, report
from .http import ARM, GRAPH, Client

CATEGORIES = ["conditional-access", "sftp", "service-principal", "app-registration"]
RED, GREEN, YELLOW, BOLD, RESET = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[0m"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def print_checks(checks: list[dict]) -> bool:
    ok = True
    for c in checks:
        mark = f"{GREEN}✔{RESET}" if c["ok"] else f"{RED}✘{RESET}"
        print(f"  {mark} {c['name']}: {c['detail']}")
        ok &= c["ok"] or not c["blocking"]
    return ok


def confirm(tenant_id: str, phrase_arg: str | None, verb: str) -> bool:
    phrase = f"{verb} {tenant_id[:8]}"
    if phrase_arg is not None:
        return phrase_arg == phrase
    print(f"\n{RED}{BOLD}This will CHANGE production.{RESET} Type exactly: {BOLD}{phrase}{RESET}")
    return input("> ").strip() == phrase


def new_report(mode: str, who: dict, cfg_hash: str, tenant: str) -> dict:
    return {
        "schema": 1, "tool": {"name": "persiana", "version": __version__},
        "run": {"id": str(uuid.uuid4()), "mode": mode, "startedAt": now(), "finishedAt": None,
                "operator": {k: who.get(k) for k in ("kind", "id", "upn", "appId")},
                "tenantId": tenant, "configSha256": cfg_hash},
        "preflight": {"ok": None, "checks": []}, "items": [],
    }


def default_out(mode: str) -> Path:
    return Path("reports") / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{mode}"


def cmd_run(args, preflight_only: bool = False) -> int:
    cfg, cfg_hash = config.load(args.config)
    cats = set(args.only or CATEGORIES)
    graph, arm = Client(GRAPH), Client(ARM)
    who = preflight.identity(graph)
    mode = "preflight" if preflight_only else ("execute" if args.execute else "dry-run")
    rep = new_report(mode, who, cfg_hash, cfg["tenant_id"])
    print(f"{BOLD}persiana {__version__}{RESET} — mode: {BOLD}{mode.upper()}{RESET} — operator: {who['upn']}")

    print(f"\n{BOLD}[1/3] Preflight (identity){RESET}")
    checks = preflight.check_identity(graph, cfg, who, cats)
    if not print_checks(checks) and checks[0]["ok"] is False:
        print(f"{RED}Wrong tenant — aborting before any query.{RESET}")
        return 2

    print(f"\n{BOLD}[2/3] Inventory{RESET}")
    items: list[dict] = []
    if "conditional-access" in cats:
        items.append(inventory.conditional_access(graph, cfg))
        print(f"  CA policy: {items[-1]['name']} ({items[-1]['details']['currentState']})")
    if "sftp" in cats and cfg["sftp"].get("enabled", True):
        items += inventory.sftp_accounts(arm, graph)
        print(f"  SFTP storage accounts: {sum(i['category'] == 'sftp' for i in items)}")
    ctx = {"resources": {}, "sp_by_app": {}}
    if cats & {"service-principal", "app-registration"}:
        sps, ctx = inventory.service_principals(graph, arm, cfg, cfg["tenant_id"], who.get("appId"))
        if "service-principal" in cats:
            items += sps
        print(f"  Service principals flagged: {len(sps)}")
    if "app-registration" in cats and cfg["app_registrations"].get("enabled", True):
        apps = inventory.app_registrations(graph, cfg, ctx, items)
        items += apps
        print(f"  App registrations flagged: {len(apps)}")
    if args.only_id:
        wanted = set(args.only_id)
        items = [i for i in items if i["id"] in wanted or i["details"].get("appId") in wanted]
    rep["items"] = items

    print(f"\n{BOLD}[3/3] Preflight (scoped){RESET}")
    more = preflight.check_storage(arm, items) if "sftp" in cats else []
    more += preflight.check_ca_safety(next((i for i in items if i["category"] == "conditional-access"), None), cfg)
    print_checks(more)
    checks += more
    rep["preflight"] = {"ok": all(c["ok"] or not c["blocking"] for c in checks), "checks": checks}

    if mode == "execute":
        if not rep["preflight"]["ok"]:
            print(f"\n{RED}{BOLD}REFUSING TO EXECUTE: preflight failed.{RESET}")
            rep["run"]["mode"] = "execute-refused"
        elif not confirm(cfg["tenant_id"], args.confirm, "LOCKDOWN"):
            print(f"{YELLOW}Confirmation phrase did not match — nothing changed.{RESET}")
            rep["run"]["mode"] = "execute-aborted"
        else:
            order = {c: n for n, c in enumerate(CATEGORIES)}  # CA first: fastest impact
            for it in sorted(items, key=lambda i: order[i["category"]]):
                if it["status"] == "planned" and it["after"] is not None:
                    actions.apply(it, graph, arm)
                    print(f"  {it['status']:>8}  {it['category']:<18} {it['name']}" + (f"  {RED}{it['error']}{RESET}" if it["error"] else ""))

    rep["run"]["finishedAt"] = now()
    jp, hp = report.write(rep, Path(args.out) if args.out else default_out(rep["run"]["mode"]))
    print(f"\nReport: {hp}\nJSON:   {jp}")
    if not rep["preflight"]["ok"]:
        return 2
    return 1 if any(i["status"] == "failed" for i in items) else 0


def cmd_rollback(args) -> int:
    src = json.loads(Path(args.report).read_text())
    if src["run"]["mode"] != "execute":
        print(f"{RED}{args.report} is a '{src['run']['mode']}' report — only 'execute' reports can be rolled back.{RESET}")
        return 2
    cfg, cfg_hash = config.load(args.config)
    graph, arm = Client(GRAPH), Client(ARM)
    who = preflight.identity(graph)
    cats = {i["category"] for i in src["items"] if i["status"] == "applied"}
    rep = new_report("rollback-execute" if args.execute else "rollback-dry-run", who, cfg_hash, src["run"]["tenantId"])
    rep["run"]["sourceRunId"] = src["run"]["id"]
    print(f"{BOLD}persiana rollback{RESET} of run {src['run']['id']} ({src['run']['startedAt']})")
    checks = [preflight._check("Report tenant matches token", who["tenantId"] == src["run"]["tenantId"],
                               f"report={src['run']['tenantId']} token={who['tenantId']}")]
    cfg = {**cfg, "tenant_id": src["run"]["tenantId"]}
    checks += preflight.check_identity(graph, cfg, who, cats)[1:]
    checks += preflight.check_storage(arm, [i | {"status": "planned"} for i in src["items"] if i["status"] == "applied"])
    ok = print_checks(checks)
    rep["preflight"] = {"ok": ok, "checks": checks}
    execute = args.execute and ok
    if args.execute and not ok:
        print(f"{RED}{BOLD}REFUSING TO ROLL BACK: preflight failed.{RESET}")
        rep["run"]["mode"] = "rollback-refused"
    elif args.execute and not confirm(src["run"]["tenantId"], args.confirm, "ROLLBACK"):
        print(f"{YELLOW}Confirmation phrase did not match — nothing changed.{RESET}")
        execute, rep["run"]["mode"] = False, "rollback-aborted"
    order = {c: n for n, c in enumerate(reversed(CATEGORIES))}  # reverse order: apps first, CA last
    for it in sorted(copy.deepcopy(src["items"]), key=lambda i: order[i["category"]]):
        actions.revert(it, graph, arm, execute, args.force)
        if it["status"] != "not-applicable":
            print(f"  {it['status']:>8}  {it['category']:<18} {it['name']}" + (f"  {RED}{it['error']}{RESET}" if it["error"] else ""))
        rep["items"].append(it)
    rep["run"]["finishedAt"] = now()
    jp, hp = report.write(rep, Path(args.out) if args.out else default_out(rep["run"]["mode"]))
    print(f"\nReport: {hp}\nJSON:   {jp}")
    return 0 if ok and not any(i["status"] in ("failed", "drift") for i in rep["items"]) else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="persiana", description=__doc__)
    p.add_argument("--config", help="path to persiana.toml")
    p.add_argument("--out", help="output directory for report.json / report.html")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("preflight", "run"):
        s = sub.add_parser(name)
        s.add_argument("--only", nargs="+", choices=CATEGORIES, help="limit to these categories")
        s.add_argument("--only-id", nargs="+", help="limit to these object / resource / app IDs (testing)")
        if name == "run":
            s.add_argument("--execute", action="store_true", help="actually change things (default: dry-run)")
            s.add_argument("--confirm", help="non-interactive confirmation phrase")

    r = sub.add_parser("rollback")
    r.add_argument("report", help="report.json from an --execute run")
    r.add_argument("--execute", action="store_true", help="actually revert (default: dry-run)")
    r.add_argument("--force", action="store_true", help="overwrite objects changed after the lockdown")
    r.add_argument("--confirm", help="non-interactive confirmation phrase")

    args = p.parse_args(argv)
    if args.cmd == "rollback":
        return cmd_rollback(args)
    if args.cmd == "preflight":
        args.execute, args.confirm = False, None
        return cmd_run(args, preflight_only=True)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
