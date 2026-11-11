"""Permission checks. `run --execute` and `rollback --execute` refuse to start unless every check passes.

Requirements are data-driven per category, so only the modules selected for a run are checked.
"""
from __future__ import annotations

import fnmatch

from .http import ApiError, Client

# Entra built-in role template IDs
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
CA_ADMIN = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
CLOUD_APP_ADMIN = "158c047a-c907-4556-b7ef-446551a6b5f7"
APP_ADMIN = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1"
GROUPS_ADMIN = "fdd7a751-b60b-444a-984c-02652fe8fa1c"
PRIV_AUTH_ADMIN = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"
PRIV_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"

ROLE_NAMES = {GLOBAL_ADMIN: "Global Administrator", CA_ADMIN: "Conditional Access Administrator",
              SECURITY_ADMIN: "Security Administrator", CLOUD_APP_ADMIN: "Cloud Application Administrator",
              APP_ADMIN: "Application Administrator", USER_ADMIN: "User Administrator",
              GROUPS_ADMIN: "Groups Administrator", PRIV_AUTH_ADMIN: "Privileged Authentication Administrator",
              PRIV_ROLE_ADMIN: "Privileged Role Administrator"}

# category -> (graph permissions; each entry is a list of acceptable alternatives, active roles accepted)
GRAPH_REQUIREMENTS = {
    "inventory": ([["Directory.Read.All", "Directory.ReadWrite.All"]], None),
    "conditional-access": ([["Policy.Read.All"], ["Policy.ReadWrite.ConditionalAccess"]],
                           {GLOBAL_ADMIN, CA_ADMIN, SECURITY_ADMIN}),
    "service-principal": ([["Application.ReadWrite.All"]], {GLOBAL_ADMIN, CLOUD_APP_ADMIN, APP_ADMIN}),
    "app-registration": ([["Application.ReadWrite.All"]], {GLOBAL_ADMIN, CLOUD_APP_ADMIN, APP_ADMIN}),
    "group-members": ([["GroupMember.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All"]],
                      {GLOBAL_ADMIN, GROUPS_ADMIN, USER_ADMIN, PRIV_ROLE_ADMIN}),
    "user": ([["User.ReadWrite.All", "Directory.ReadWrite.All"]], {GLOBAL_ADMIN, USER_ADMIN, PRIV_AUTH_ADMIN}),
    "revoke-sessions": ([["User.RevokeSessions.All", "User.ReadWrite.All", "Directory.ReadWrite.All"]],
                        {GLOBAL_ADMIN, USER_ADMIN, PRIV_AUTH_ADMIN}),
    "tenant-setting": ([["Policy.ReadWrite.Authorization"]], {GLOBAL_ADMIN, PRIV_ROLE_ADMIN}),
}

# category -> ARM action that must be allowed on every affected resource
ARM_ACTIONS = {
    "storage": "Microsoft.Storage/storageAccounts/write",
    "keyvault": "Microsoft.KeyVault/vaults/write",
    "rg-lock": "Microsoft.Authorization/locks/write",
    "aks:stop": "Microsoft.ContainerService/managedClusters/stop/action",
    "aks:restrict-api": "Microsoft.ContainerService/managedClusters/write",
}


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
    checks = [_check("Tenant matches shutter.toml", who["tenantId"] == cfg["tenant_id"],
                     f"token tid={who['tenantId']} config={cfg['tenant_id']}")]
    have = set(who["scopes"])
    active: set[str] = set()
    if who["kind"] == "user":
        try:
            roles = graph.get_all("/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId,displayName")
            active = {r["roleTemplateId"] for r in roles}
        except ApiError as e:
            checks.append(_check("Read active Entra roles", False, str(e)))
    names = ", ".join(sorted(ROLE_NAMES.get(r, r) for r in active & set(ROLE_NAMES))) or "none"
    for cat in ["inventory"] + sorted(c for c in categories if c in GRAPH_REQUIREMENTS):
        perms, roles = GRAPH_REQUIREMENTS[cat]
        missing = [" or ".join(alts) for alts in perms if not have & set(alts)]
        checks.append(_check(f"Graph permissions for {cat}", not missing,
                             "ok" if not missing else "missing: " + "; ".join(missing)))
        if roles and who["kind"] == "user":
            need = " / ".join(sorted(ROLE_NAMES[r] for r in roles))
            checks.append(_check(f"Active Entra role for {cat}", bool(active & roles),
                                 f"needs {need} (PIM must be ACTIVE). Active: {names}"))
    return checks


def _allowed(action: str, perms: list[dict]) -> bool:
    ok = False
    for p in perms:
        if any(fnmatch.fnmatch(action.lower(), a.lower()) for a in p.get("actions", [])):
            if not any(fnmatch.fnmatch(action.lower(), n.lower()) for n in p.get("notActions", [])):
                ok = True
    return ok


def _arm_action(it: dict) -> str | None:
    if it["category"] == "aks":
        return ARM_ACTIONS["aks:stop" if "powerState" in (it.get("after") or {}) else "aks:restrict-api"]
    return ARM_ACTIONS.get(it["category"])


def check_arm(arm: Client, items: list[dict]) -> list[dict]:
    """Evaluate effective ARM permissions on every Azure resource the run will change."""
    by_action: dict[str, list[dict]] = {}
    for it in items:
        action = _arm_action(it)
        if action and it["status"] in ("planned", "in-progress"):
            by_action.setdefault(action, []).append(it)
    checks = []
    for action, its in sorted(by_action.items()):
        denied = []
        for it in its:
            try:
                perms = arm.get(f"{it['id']}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01")["value"]
            except ApiError as e:
                denied.append(f"{it['name']} ({e.status})")
                continue
            if not _allowed(action, perms):
                denied.append(it["name"])
        checks.append(_check(f"{action} on {len(its)} resource(s)", not denied,
                             "ok" if not denied else "denied on: " + ", ".join(denied)))
    return checks


def check_ca_safety(items: list[dict], cfg: dict) -> list[dict]:
    """Every CA policy the run enables must keep the break-glass accounts excluded."""
    checks = []
    for ca in (i for i in items if i["category"] == "conditional-access" and i["status"] in ("planned", "in-progress")):
        excl = ca["details"]["excludedUsers"]
        need = cfg["conditional_access"].get("min_excluded_users", 1)
        checks.append(_check(f"'{ca['name']}' keeps break-glass exclusions", len(excl) >= need,
                             f"{len(excl)} excluded user(s): " + ", ".join(u.get("upn") or u["id"] for u in excl)))
        bg = (cfg.get("break_glass") or {}).get("user_ids", [])
        if bg:
            missing = [u for u in bg if u not in {u["id"] for u in excl}]
            checks.append(_check(f"Every break-glass account is excluded from '{ca['name']}'", not missing,
                                 "ok" if not missing else "NOT excluded: " + ", ".join(missing)))
    return checks


def is_member(graph: Client, object_id: str, group_id: str) -> bool:
    try:
        res = graph.post(f"/v1.0/directoryObjects/{object_id}/checkMemberGroups", {"groupIds": [group_id]})
        return group_id in res.get("value", [])
    except ApiError:
        return False
