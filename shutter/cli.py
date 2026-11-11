"""SHUTTER — Azure Emergency Containment & Recovery. Dry-run by default."""
from __future__ import annotations

import argparse
import copy
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, actions, config, control, inventory, modules, notify, preflight, report
from .http import ARM, GRAPH, Client

# Execution order: identity-plane blocks first (fastest impact), then data plane. Rollback is reversed.
ORDER = ["conditional-access", "user", "revoke-sessions", "group-members", "tenant-setting", "rg-lock",
         "service-principal", "app-registration", "storage", "keyvault", "aks"]
RED, GREEN, YELLOW, BOLD, RESET = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[0m"

# switch -> categories it can produce (used for the identity preflight before discovery)
SWITCH_CATEGORIES = {
    "disable_guests": {"conditional-access", "group-members"},
    "disable_groups": {"conditional-access"},
    "remove_group_members": {"group-members"},
    "disable_enterprise_apps": {"service-principal"},
    "disable_app_registrations": {"app-registration", "service-principal"},
    "disable_users": {"user"},
    "revoke_sessions": {"revoke-sessions"},
    "disable_guest_invites": {"tenant-setting"},
    "disable_user_consent": {"tenant-setting"},
    "disable_storage": set(), "disable_keyvault_public_access": set(), "disable_aks": set(), "lock_resource_groups": set(),
}
LIST_SWITCHES = [k for k in SWITCH_CATEGORIES if k not in ("disable_guest_invites", "disable_user_consent")]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def print_checks(checks: list[dict]) -> bool:
    ok = True
    for c in checks:
        mark = f"{GREEN}✔{RESET}" if c["ok"] else f"{RED}✘{RESET}"
        print(f"  {mark} {c['name']}: {c['detail']}")
        ok &= c["ok"] or not c["blocking"]
    return ok


def print_item(it: dict) -> None:
    print(f"  {it['status']:>12}  {it['category']:<18} {it['name']}" + (f"  {RED}{it['error']}{RESET}" if it.get("error") else ""))


def confirm(tenant_id: str, phrase_arg: str | None, verb: str, warning: str = "This will CHANGE production.") -> bool:
    phrase = f"{verb} {tenant_id[:8]}"
    if phrase_arg is not None:
        return phrase_arg == phrase
    print(f"\n{RED}{BOLD}{warning}{RESET} Type exactly: {BOLD}{phrase}{RESET}")
    return input("> ").strip() == phrase


def new_report(mode: str, who: dict, cfg_hash: str, tenant: str) -> dict:
    return {
        "schema": 2, "tool": {"name": "shutter", "version": __version__},
        "run": {"id": str(uuid.uuid4()), "mode": mode, "status": "running", "startedAt": now(), "finishedAt": None,
                "operator": {k: who.get(k) for k in ("kind", "id", "upn", "appId")},
                "tenantId": tenant, "configSha256": cfg_hash},
        "preflight": {"ok": None, "checks": []}, "items": [],
    }


def default_out(mode: str) -> Path:
    return Path("reports") / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{mode}"


def finish(cfg: dict, rep: dict, out: Path, event: str | None) -> tuple[Path, Path]:
    rep["run"]["finishedAt"] = now()
    if rep["run"]["status"] == "running":
        rep["run"]["status"] = "completed"
    jp, hp = report.write(rep, out)
    archived = control.archive(cfg, rep["run"]["id"], out) if rep["run"]["mode"] in ("execute", "rollback-execute") else []
    if event:
        notify.notify(cfg, event, rep, out, reportSha256=report.sha256(jp), archive=archived)
        report.write(rep, out)  # persist notification results
    print(f"\nReport: {hp}\nJSON:   {jp}")
    if archived:
        print(f"Archived: {', '.join(archived)}")
    return jp, hp


# --------------------------------------------------------------------------- selection
def selection(args) -> dict:
    """Normalise switches. `None` = switch not given; `[]` = given without a list (= everything)."""
    sel = {k: modules.expand(getattr(args, k, None)) for k in LIST_SWITCHES}
    sel["disable_guest_invites"] = getattr(args, "disable_guest_invites", False)
    sel["disable_user_consent"] = getattr(args, "disable_user_consent", False)
    sel["storage_mode"] = getattr(args, "storage_mode", "both")
    sel["aks_mode"] = getattr(args, "aks_mode", None) or "stop"
    sel["exclude"] = modules.expand(getattr(args, "exclude", None)) or []
    if getattr(args, "all", False):
        for k in ("disable_guests", "disable_storage", "disable_enterprise_apps", "disable_app_registrations"):
            if sel[k] is None:
                sel[k] = []
    return sel


def selected(sel: dict) -> bool:
    return any(sel[k] is not None for k in LIST_SWITCHES) or sel["disable_guest_invites"] or sel["disable_user_consent"]


def expected_categories(sel: dict) -> set[str]:
    cats: set[str] = set()
    for k, c in SWITCH_CATEGORIES.items():
        if sel.get(k) not in (None, False):
            cats |= c
    if sel["disable_guests"] == []:
        cats.discard("group-members")  # all guests: no static group
    return cats


def apply_exclusions(items: list[dict], sel: dict, cfg: dict) -> None:
    ex = {e.lower() for e in sel["exclude"]}
    ctl = (cfg.get("control") or {}).get("storage_account")
    allow_res = {r.lower() for r in cfg["allowlist"].get("resource_ids", [])}
    for it in items:
        keys = {str(v).lower() for v in (it["id"], it["name"], it["details"].get("appId"), it["details"].get("upn")) if v}
        why = None
        if keys & ex:
            why = "Excluded with --exclude"
        elif it["id"].lower() in allow_res:
            why = "In allowlist.resource_ids"
        elif ctl and it["category"] == "storage" and it["name"].lower() == ctl.lower():
            why = "SHUTTER control storage account (lock, approvals, archive)"
        if why and it["status"] not in ("skipped-allowlist",):
            it.update(status="skipped-allowlist", action="none")
            it["reasons"].append(why)


def discover(graph, arm, cfg, who, sel) -> list[dict]:
    print(f"\n{BOLD}[2/3] Inventory{RESET}")
    items: list[dict] = []
    bg = set((cfg.get("break_glass") or {}).get("user_ids", []))

    def add(label, new):
        items.extend(new)
        print(f"  {label}: {len(new)}")

    if sel["disable_guests"] is not None:
        add("Guest block (CA)", inventory.guest_items(graph, cfg, sel["disable_guests"]))
    if sel["disable_groups"]:
        add("Group block (CA)", [modules.group_block_item(graph, cfg, modules.resolve_groups(graph, sel["disable_groups"]))])
    if sel["remove_group_members"]:
        keep = bg | {e for e in sel["exclude"] if modules.GUID.match(e)}
        keep |= {u["id"] for u in modules.resolve_users(graph, [e for e in sel["exclude"] if "@" in e])}
        add("Group membership removal", modules.remove_members_items(graph, modules.resolve_groups(graph, sel["remove_group_members"]), keep))
    if sel["disable_users"]:
        add("Users to disable", modules.user_items(graph, modules.resolve_users(graph, sel["disable_users"]), bg))
    if sel["revoke_sessions"]:
        add("Session revocations", modules.revoke_items(modules.resolve_users(graph, sel["revoke_sessions"]), bg))
    if sel["disable_guest_invites"] or sel["disable_user_consent"]:
        add("Tenant settings", modules.tenant_setting_items(graph, sel["disable_guest_invites"], sel["disable_user_consent"]))
    if sel["lock_resource_groups"]:
        add("Resource group locks", modules.rg_lock_items(arm, sel["lock_resource_groups"]))

    ea, ar = sel["disable_enterprise_apps"], sel["disable_app_registrations"]
    if ea is not None or ar is not None:
        sps, ctx = inventory.service_principals(graph, arm, cfg, cfg["tenant_id"], who.get("appId"))
        sp_items = []
        if ea == []:
            sp_items = sps
        elif ea:
            sp_items = modules.explicit_sp_items(graph, modules.resolve_service_principals(graph, ea), {s["id"]: s for s in sps}, cfg)
        add("Enterprise apps", sp_items)
        if ar is not None:
            detected = inventory.app_registrations(graph, cfg, ctx, sp_items)
            if ar:
                covered = {i["details"]["appId"]: i for i in sp_items}
                detected = modules.explicit_app_items(graph, modules.resolve_applications(graph, ar),
                                                      {a["id"]: a for a in detected}, covered, cfg)
            add("App registrations", detected)
    if sel["disable_storage"] is not None:
        add(f"Storage accounts ({sel['storage_mode']})", inventory.storage_items(arm, graph, sel["storage_mode"], sel["disable_storage"]))
    if sel["disable_keyvault_public_access"] is not None:
        add("Key vaults", modules.keyvault_items(arm, sel["disable_keyvault_public_access"]))
    if sel["disable_aks"] is not None:
        add(f"AKS clusters ({sel['aks_mode']})", modules.aks_items(arm, cfg, sel["aks_mode"], sel["disable_aks"]))
    apply_exclusions(items, sel, cfg)
    return items


# --------------------------------------------------------------------------- run
def load_plan(path: str, tenant: str) -> dict:
    plan = json.loads(Path(path).read_text())
    if plan["run"]["tenantId"] != tenant:
        raise SystemExit(f"{RED}{path} belongs to tenant {plan['run']['tenantId']}, config is {tenant}{RESET}")
    return plan


def cmd_run(args, preflight_only: bool = False) -> int:
    cfg, cfg_hash = config.load(args.config)
    approval_cfg = cfg.get("approval") or {}
    resume = getattr(args, "resume", None)
    from_plan = getattr(args, "from_plan", None)
    sel = selection(args)
    if not (resume or from_plan) and not selected(sel):
        print(f"{RED}Nothing selected.{RESET} Choose what to contain (e.g. --disable-guests --disable-storage), "
              "or --all for every default module. See `shutter run --help`.")
        return 2
    if (resume or from_plan) and selected(sel):
        print(f"{RED}--resume / --from-plan replay a saved plan; do not combine them with switches.{RESET}")
        return 2

    graph, arm = Client(GRAPH), Client(ARM)
    who = preflight.identity(graph)
    mode = "preflight" if preflight_only else ("execute" if args.execute or resume else "dry-run")

    if resume:
        rep = load_plan(resume, cfg["tenant_id"])
        if rep["run"]["mode"] != "execute" or rep["run"].get("status") == "completed":
            print(f"{RED}{resume} is not an interrupted execute run (mode={rep['run']['mode']}, status={rep['run'].get('status')}).{RESET}")
            return 2
        rep["run"].setdefault("resumes", []).append({"at": now(), "operator": who.get("upn")})
        rep["run"]["status"] = "running"
        out = Path(resume).parent
    else:
        rep = new_report(mode, who, cfg_hash, cfg["tenant_id"])
        rep["run"]["selection"] = sel
        out = Path(args.out) if args.out else default_out(mode)
    print(f"{BOLD}shutter {__version__}{RESET} — mode: {BOLD}{mode.upper()}{'' if not resume else ' (RESUME)'}{RESET} — operator: {who['upn']}")

    plan = load_plan(from_plan, cfg["tenant_id"]) if from_plan else None
    if plan and plan["run"]["mode"] != "dry-run":
        print(f"{RED}--from-plan needs a dry-run report (got {plan['run']['mode']}).{RESET}")
        return 2
    if resume:
        items = rep["items"]
    elif plan:
        items = copy.deepcopy(plan["items"])
        rep["run"]["planRunId"] = plan["run"]["id"]
        rep["run"]["selection"] = plan["run"].get("selection")
    else:
        items = None
    cats = expected_categories(sel) if items is None else {i["category"] for i in items}

    print(f"\n{BOLD}[1/3] Preflight (identity){RESET}")
    checks = preflight.check_identity(graph, cfg, who, cats)
    if not print_checks(checks) and checks[0]["ok"] is False:
        print(f"{RED}Wrong tenant — aborting before any query.{RESET}")
        return 2

    if items is None:
        try:
            items = discover(graph, arm, cfg, who, sel)
        except ValueError as e:
            print(f"\n{RED}{BOLD}Cannot build the plan: {e}{RESET}")
            return 2
    else:
        print(f"\n{BOLD}[2/3] Inventory{RESET}\n  Using {len(items)} item(s) from {'journal' if resume else 'plan'} — no re-discovery")
    rep["items"] = items

    print(f"\n{BOLD}[3/3] Preflight (scoped){RESET}")
    pending = [i for i in items if i["status"] in ("planned", "in-progress")]
    more = preflight.check_arm(arm, pending)
    more += preflight.check_ca_safety(items, cfg)
    if mode == "execute" and approval_cfg.get("required") and not resume:
        if not plan:
            more.append(preflight._check("Two-person approval", False, "approval is required: run with --from-plan <approved dry-run report.json>"))
        else:
            ok, detail, rec = control.check_approval(cfg, plan, who, lambda o, g: preflight.is_member(graph, o, g))
            more.append(preflight._check("Two-person approval", ok, detail))
            if rec:
                rep["run"]["approval"] = rec
    print_checks(more)
    checks += more
    rep["preflight"] = {"ok": all(c["ok"] or not c["blocking"] for c in checks), "checks": checks}

    if mode != "execute":
        rep["run"]["status"] = "completed"
        finish(cfg, rep, out, "dry-run" if mode == "dry-run" else None)
        return 0 if rep["preflight"]["ok"] else 2

    if not rep["preflight"]["ok"]:
        print(f"\n{RED}{BOLD}REFUSING TO EXECUTE: preflight failed.{RESET}")
        rep["run"]["mode"], rep["run"]["status"] = "execute-refused", "refused"
        finish(cfg, rep, out, "execute-refused")
        return 2
    if not confirm(cfg["tenant_id"], args.confirm, "LOCKDOWN"):
        print(f"{YELLOW}Confirmation phrase did not match — nothing changed.{RESET}")
        rep["run"]["mode"], rep["run"]["status"] = "execute-aborted", "aborted"
        finish(cfg, rep, out, None)
        return 2
    irreversible = [i for i in pending if i.get("irreversible")]
    if irreversible and not confirm(cfg["tenant_id"], getattr(args, "confirm_irreversible", None), "IRREVERSIBLE",
                                    f"{len(irreversible)} action(s) CANNOT be rolled back ({', '.join(sorted({i['action'] for i in irreversible}))})."):
        print(f"{YELLOW}Irreversible actions not confirmed — they will be skipped.{RESET}")
        for i in irreversible:
            i.update(status="skipped", action="none")
            i["reasons"].append("Irreversible action not confirmed")

    try:
        with control.RunLock(cfg, {"runId": rep["run"]["id"], "operator": who.get("upn"), "mode": "execute"}):
            journal = lambda: report.write_json(rep, out)  # noqa: E731
            journal()
            notify.notify(cfg, "execute-start", rep, out)
            order = {c: n for n, c in enumerate(ORDER)}
            for it in sorted(items, key=lambda i: order[i["category"]]):
                if it["status"] in ("planned", "in-progress") and (it.get("after") is not None or it.get("irreversible")):
                    actions.apply(it, graph, arm, journal)
                    journal()
                    print_item(it)
    except control.LockBusy as e:
        print(f"{RED}{BOLD}REFUSING TO EXECUTE: {e}{RESET}")
        rep["run"]["mode"], rep["run"]["status"] = "execute-refused", "refused"
        rep["preflight"]["checks"].append(preflight._check("Run lock", False, str(e)))
        rep["preflight"]["ok"] = False
        finish(cfg, rep, out, "execute-refused")
        return 2
    finish(cfg, rep, out, "execute-end")
    return 1 if any(i["status"] == "failed" for i in items) else 0


# --------------------------------------------------------------------------- rollback
def cmd_rollback(args) -> int:
    src = json.loads(Path(args.report).read_text())
    if src["run"]["mode"] != "execute":
        print(f"{RED}{args.report} is a '{src['run']['mode']}' report — only 'execute' reports can be rolled back.{RESET}")
        return 2
    cfg, cfg_hash = config.load(args.config)
    graph, arm = Client(GRAPH), Client(ARM)
    who = preflight.identity(graph)
    candidates = [i for i in src["items"] if i["status"] in ("applied", "in-progress") and not i.get("irreversible")]
    cats = {i["category"] for i in candidates}
    rep = new_report("rollback-execute" if args.execute else "rollback-dry-run", who, cfg_hash, src["run"]["tenantId"])
    rep["run"]["sourceRunId"] = src["run"]["id"]
    out = Path(args.out) if args.out else default_out(rep["run"]["mode"])
    status = src["run"].get("status", "completed")
    print(f"{BOLD}shutter rollback{RESET} of run {src['run']['id']} ({src['run']['startedAt']}, {status})")
    checks = [preflight._check("Report tenant matches token", who["tenantId"] == src["run"]["tenantId"],
                               f"report={src['run']['tenantId']} token={who['tenantId']}")]
    cfg = {**cfg, "tenant_id": src["run"]["tenantId"]}
    checks += preflight.check_identity(graph, cfg, who, cats)[1:]
    checks += preflight.check_arm(arm, [i | {"status": "planned"} for i in candidates])
    ok = print_checks(checks)
    rep["preflight"] = {"ok": ok, "checks": checks}
    execute = args.execute and ok
    if args.execute and not ok:
        print(f"{RED}{BOLD}REFUSING TO ROLL BACK: preflight failed.{RESET}")
        rep["run"]["mode"], rep["run"]["status"] = "rollback-refused", "refused"
        execute = False
    elif args.execute and not confirm(src["run"]["tenantId"], args.confirm, "ROLLBACK"):
        print(f"{YELLOW}Confirmation phrase did not match — nothing changed.{RESET}")
        execute, rep["run"]["mode"], rep["run"]["status"] = False, "rollback-aborted", "aborted"

    def do_revert():
        order = {c: n for n, c in enumerate(reversed(ORDER))}
        for it in sorted(copy.deepcopy(src["items"]), key=lambda i: order.get(i["category"], 0)):
            actions.revert(it, graph, arm, execute, args.force)
            if it["status"] != "not-applicable":
                print_item(it)
            rep["items"].append(it)
            if execute:
                report.write_json(rep, out)

    if execute:
        try:
            with control.RunLock(cfg, {"runId": rep["run"]["id"], "operator": who.get("upn"), "mode": "rollback"}):
                notify.notify(cfg, "rollback-start", rep, out)
                do_revert()
        except control.LockBusy as e:
            print(f"{RED}{BOLD}REFUSING TO ROLL BACK: {e}{RESET}")
            rep["run"]["mode"], rep["run"]["status"] = "rollback-refused", "refused"
            finish(cfg, rep, out, None)
            return 2
        finish(cfg, rep, out, "rollback-end")
    else:
        do_revert()
        finish(cfg, rep, out, None)
    return 0 if ok and not any(i["status"] in ("failed", "drift") for i in rep["items"]) else 1


# --------------------------------------------------------------------------- approve / unlock
def cmd_approve(args) -> int:
    cfg, _ = config.load(args.config)
    plan = load_plan(args.plan, cfg["tenant_id"])
    if plan["run"]["mode"] != "dry-run":
        print(f"{RED}Only dry-run reports can be approved.{RESET}")
        return 2
    graph = Client(GRAPH)
    who = preflight.identity(graph)
    if who["id"] == plan["run"]["operator"].get("id"):
        print(f"{YELLOW}Note: you produced this plan; the executor must be a different identity.{RESET}")
    group = (cfg.get("approval") or {}).get("approver_group_id")
    if group and not preflight.is_member(graph, who["id"], group):
        print(f"{RED}You are not in the approver group {group}.{RESET}")
        return 2
    planned = [i for i in plan["items"] if i["status"] == "planned"]
    print(f"{BOLD}Approving plan {plan['run']['id']}{RESET} ({len(planned)} change(s)) for tenant {plan['run']['tenantId']}")
    for it in planned:
        print(f"  {it['category']:<18} {it['action']:<32} {it['name']}" + (f"  {RED}IRREVERSIBLE{RESET}" if it.get("irreversible") else ""))
    if not confirm(plan["run"]["tenantId"], args.confirm, "APPROVE"):
        print(f"{YELLOW}Not approved.{RESET}")
        return 2
    ttl = args.ttl or (cfg.get("approval") or {}).get("ttl_minutes", 60)
    rec = control.approve(cfg, plan, who, ttl)
    print(f"{GREEN}Approved by {rec['approver']['upn']} until {rec['expiresAt']} (plan hash {rec['planHash'][:12]}).{RESET}")
    return 0


def cmd_unlock(args) -> int:
    cfg, _ = config.load(args.config)
    if control.break_lock(cfg):
        print(f"{GREEN}Lock broken for tenant {cfg['tenant_id']}.{RESET}")
        return 0
    print(f"{YELLOW}Nothing to unlock (no [control] storage configured, or no lock held).{RESET}")
    return 1


# --------------------------------------------------------------------------- argument parsing
SWITCH_HELP = """
switches — [LIST] optional: omitted means EVERYTHING in scope; (LIST) mandatory.
Lists take IDs (preferred), names, comma-separated values, or @file.txt (one per line).
"""


def add_switches(s: argparse.ArgumentParser) -> None:
    g = s.add_argument_group("containment switches", SWITCH_HELP)
    g.add_argument("--all", action="store_true", help="guests + storage + enterprise apps + app registrations (all defaults)")
    g.add_argument("--disable-guests", nargs="*", metavar="DOMAIN", help="block guests: all, or only these email domains (CA policy)")
    g.add_argument("--disable-groups", nargs="+", metavar="GROUP", help="block sign-in for members of these groups (CA policy)")
    g.add_argument("--remove-group-members", nargs="+", metavar="GROUP", help="remove all members of these groups (restorable)")
    g.add_argument("--disable-users", nargs="+", metavar="USER", help="disable these accounts (ID or UPN)")
    g.add_argument("--revoke-sessions", nargs="+", metavar="USER", help="revoke sign-in sessions — IRREVERSIBLE")
    g.add_argument("--disable-guest-invites", action="store_true", help="tenant setting: nobody can invite guests")
    g.add_argument("--disable-user-consent", action="store_true", help="tenant setting: users cannot consent to apps")
    g.add_argument("--disable-enterprise-apps", nargs="*", metavar="APP", help="disable service principals: high-privilege detection, or these")
    g.add_argument("--disable-app-registrations", nargs="*", metavar="APP", help="disable app registrations' local SP: detection, or these")
    g.add_argument("--disable-storage", nargs="*", metavar="ACCOUNT", help="storage accounts: all, or these")
    g.add_argument("--storage-mode", choices=["sftp", "public", "both"], default="both", help="what to close on storage (default: both)")
    g.add_argument("--disable-keyvault-public-access", nargs="*", metavar="VAULT", help="key vaults: all, or these")
    g.add_argument("--disable-aks", nargs="*", metavar="CLUSTER", help="AKS clusters: all, or these")
    g.add_argument("--aks-mode", choices=["stop", "restrict-api"], default="stop", help="stop the cluster, or restrict the API server to [aks] authorized_ip_ranges")
    g.add_argument("--lock-resource-groups", nargs="+", metavar="RG", help="add CanNotDelete locks to these resource groups")
    g.add_argument("--exclude", nargs="+", metavar="ID", help="never touch these (IDs, UPNs, appIds, names, resource IDs)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="shutter", description=__doc__)
    p.add_argument("--config", help="path to shutter.toml")
    p.add_argument("--out", help="output directory for report.json / report.html")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("preflight", "run"):
        s = sub.add_parser(name, formatter_class=argparse.RawDescriptionHelpFormatter)
        add_switches(s)
        if name == "run":
            s.add_argument("--execute", action="store_true", help="actually change things (default: dry-run)")
            s.add_argument("--confirm", help="non-interactive confirmation phrase")
            s.add_argument("--confirm-irreversible", help="non-interactive confirmation for irreversible actions")
            g = s.add_mutually_exclusive_group()
            g.add_argument("--from-plan", help="execute exactly the planned items of this dry-run report.json")
            g.add_argument("--resume", help="continue an interrupted --execute run from its report.json")

    r = sub.add_parser("rollback")
    r.add_argument("report", help="report.json from an --execute run (complete or interrupted)")
    r.add_argument("--execute", action="store_true", help="actually revert (default: dry-run)")
    r.add_argument("--force", action="store_true", help="overwrite objects changed after the lockdown")
    r.add_argument("--confirm", help="non-interactive confirmation phrase")

    a = sub.add_parser("approve", help="second operator approves a dry-run plan (two-person rule)")
    a.add_argument("plan", help="dry-run report.json")
    a.add_argument("--ttl", type=int, help="minutes the approval is valid (default from config, 60)")
    a.add_argument("--confirm", help="non-interactive confirmation phrase")

    sub.add_parser("unlock", help="break a stale run lock (after a crashed run)")

    args = p.parse_args(argv)
    if args.cmd == "rollback":
        return cmd_rollback(args)
    if args.cmd == "approve":
        return cmd_approve(args)
    if args.cmd == "unlock":
        return cmd_unlock(args)
    if args.cmd == "preflight":
        args.execute, args.confirm = False, None
        return cmd_run(args, preflight_only=True)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
