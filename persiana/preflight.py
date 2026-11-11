"""Permission checks. `run --execute` and `rollback --execute` refuse to start unless every check passes."""
from __future__ import annotations

import fnmatch

from .http import ApiError, Client

# Entra built-in role template IDs
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
CA_ADMIN = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
CLOUD_APP_ADMIN = "158c047a-c907-4556-b7ef-446551a6b5f7"
APP_ADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"

ROLE_NAMES = {GLOBAL_ADMIN: "Global Administrator", CA_ADMIN: "Conditional Access Administrator",
              SECURITY_ADMIN: "Security Administrator", CLOUD_APP_ADMIN: "Cloud Application Administrator",
              APP_ADMIN: "Application Administrator"}

GRAPH_PERMS = {
    "conditional-access": ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"],
    "service-principal": ["Application.ReadWrite.All"],
    "inventory": ["Directory.Read.All"],
}
STORAGE_ACTION = "Microsoft.Storage/storageAccounts/write"


def _check(name: str, ok: bool, detail: str, blocking: bool = True) -> dict:
    return {"name": name, "ok": ok, "detail": detail, "blocking": blocking}


def identity(graph: Client) -> dict:
    c = graph.claims
    if "scp" in c:  # delegated (user) token
        return {"kind": "user", "id": c.get("oid"), "upn": c.get("upn") or c.get("unique_name"),
                "tenantId": c.get("tid"), "scopes": c.get("scp", "").split(), "appId": None}
    return {"kind": "application", "id": c.get("oid"), "upn": c.get("app_displayname") or c.get("appid"),
            "tenantId": c.get("tid"), "scopes": c.get("roles", []), "appId": c.get("appid")}


def check_identity(graph: Client, cfg: dict, who: dict, categories: set[str]) -> list[dict]:
    checks = [_check("Tenant matches persiana.toml", who["tenantId"] == cfg["tenant_id"],
                     f"token tid={who['tenantId']} config={cfg['tenant_id']}")]
    have = set(who["scopes"])
    for cat, needed in GRAPH_PERMS.items():
        if cat != "inventory" and cat not in categories and not (cat == "service-principal" and "app-registration" in categories):
            continue
        missing = [p for p in needed if p not in have and not (p.endswith("Read.All") and p.replace("Read.All", "ReadWrite.All") in have)]
        checks.append(_check(f"Graph permissions for {cat}", not missing,
                             "ok: " + ", ".join(needed) if not missing else "missing: " + ", ".join(missing)))
    if who["kind"] == "user":
        try:
            roles = graph.get_all("/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId,displayName")
            active = {r["roleTemplateId"] for r in roles}
        except ApiError as e:
            active = set()
            checks.append(_check("Read active Entra roles", False, str(e)))
        names = ", ".join(sorted(ROLE_NAMES.get(r, r) for r in active & set(ROLE_NAMES))) or "none"
        if "conditional-access" in categories:
            checks.append(_check("Active Entra role for Conditional Access",
                                 bool(active & {GLOBAL_ADMIN, CA_ADMIN, SECURITY_ADMIN}),
                                 f"needs CA Admin / Security Admin / Global Admin (PIM must be ACTIVE). Active: {names}"))
        if categories & {"service-principal", "app-registration"}:
            checks.append(_check("Active Entra role for applications",
                                 bool(active & {GLOBAL_ADMIN, CLOUD_APP_ADMIN, APP_ADMIN}),
                                 f"needs Cloud App Admin / App Admin / Global Admin (PIM must be ACTIVE). Active: {names}"))
    return checks


def _allowed(action: str, perms: list[dict]) -> bool:
    ok = False
    for p in perms:
        if any(fnmatch.fnmatch(action.lower(), a.lower()) for a in p.get("actions", [])):
            if not any(fnmatch.fnmatch(action.lower(), n.lower()) for n in p.get("notActions", [])):
                ok = True
    return ok


def check_storage(arm: Client, items: list[dict]) -> list[dict]:
    denied = []
    for it in items:
        if it["category"] != "sftp" or it["status"] != "planned":
            continue
        try:
            perms = arm.get(f"{it['id']}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01")["value"]
        except ApiError as e:
            denied.append(f"{it['name']} ({e.status})")
            continue
        if not _allowed(STORAGE_ACTION, perms):
            denied.append(it["name"])
    n = sum(1 for i in items if i["category"] == "sftp")
    return [_check(f"{STORAGE_ACTION} on {n} SFTP storage account(s)", not denied,
                   "ok" if not denied else "denied on: " + ", ".join(denied))]


def check_ca_safety(ca_item: dict | None, cfg: dict) -> list[dict]:
    if not ca_item:
        return []
    excl = ca_item["details"]["excludedUsers"]
    need = cfg["conditional_access"].get("min_excluded_users", 1)
    return [_check("CA policy keeps break-glass exclusions", len(excl) >= need,
                   f"{len(excl)} excluded user(s): " + ", ".join(u.get("upn") or u["id"] for u in excl))]
