"""Containment modules beyond the original four: discovery for each switch, list resolution, and the
read / write handlers that actions.apply / actions.revert dispatch to.

Every handler pair must satisfy: write(target) followed by read() returns target (for the keys in
target). That is what makes apply idempotent and rollback drift-aware.
"""
from __future__ import annotations

import re
from pathlib import Path

from .http import ApiError, Client
from .inventory import (STORAGE_API, _ca_item, _item, group_members_item, select_resources,
                        strip_odata)

AKS_API = "2024-05-01"
KV_API = "2023-07-01"
LOCK_API = "2020-05-01"
LOCK_NAME = "shutter-emergency"
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


# --------------------------------------------------------------------------- list helpers
def expand(values: list[str] | None) -> list[str] | None:
    """`@file.txt` expands to one entry per non-empty, non-comment line."""
    if values is None:
        return None
    out = []
    for v in values:
        if v.startswith("@"):
            out += [ln.strip() for ln in Path(v[1:]).read_text().splitlines() if ln.strip() and not ln.startswith("#")]
        else:
            out += [x for x in v.split(",") if x]
    return out


def _q(s: str) -> str:
    return s.replace("'", "''")


def resolve_users(graph: Client, values: list[str]) -> list[dict]:
    out = []
    for v in values:
        try:  # /users/{id | userPrincipalName}
            out.append(graph.get(f"/v1.0/users/{v}?$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled"))
        except ApiError:
            raise ValueError(f"user {v!r} not found (use object ID or UPN)") from None
    return out


def resolve_groups(graph: Client, values: list[str]) -> list[dict]:
    out = []
    sel = "id,displayName,onPremisesSyncEnabled,membershipRule,isAssignableToRole"
    for v in values:
        if GUID.match(v):
            try:
                out.append(graph.get(f"/v1.0/groups/{v}?$select={sel}"))
                continue
            except ApiError:
                raise ValueError(f"group {v!r} not found") from None
        hits = graph.get_all(f"/v1.0/groups?$filter=displayName eq '{_q(v)}'&$select={sel}")
        if len(hits) != 1:
            raise ValueError(f"group name {v!r} matched {len(hits)} groups — use the object ID")
        out.append(hits[0])
    return out


def resolve_service_principals(graph: Client, values: list[str]) -> list[dict]:
    sel = ("id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,"
           "publisherName,createdDateTime")
    out = []
    for v in values:
        sp = None
        if GUID.match(v):
            for url in (f"/v1.0/servicePrincipals/{v}?$select={sel}", f"/v1.0/servicePrincipals(appId='{v}')?$select={sel}"):
                try:
                    sp = graph.get(url)
                    break
                except ApiError:
                    pass
        else:
            hits = graph.get_all(f"/v1.0/servicePrincipals?$filter=displayName eq '{_q(v)}'&$select={sel}")
            if len(hits) > 1:
                raise ValueError(f"app name {v!r} matched {len(hits)} service principals — use the appId")
            sp = hits[0] if hits else None
        if not sp:
            raise ValueError(f"enterprise app {v!r} not found")
        out.append(sp)
    return out


def resolve_applications(graph: Client, values: list[str]) -> list[dict]:
    out = []
    for v in values:
        app = None
        if GUID.match(v):
            for url in (f"/v1.0/applications/{v}", f"/v1.0/applications(appId='{v}')"):
                try:
                    app = graph.get(url + "?$select=id,appId,displayName,signInAudience")
                    break
                except ApiError:
                    pass
        else:
            hits = graph.get_all(f"/v1.0/applications?$filter=displayName eq '{_q(v)}'&$select=id,appId,displayName,signInAudience")
            if len(hits) > 1:
                raise ValueError(f"app registration name {v!r} matched {len(hits)} — use the appId")
            app = hits[0] if hits else None
        if not app:
            raise ValueError(f"app registration {v!r} not found")
        out.append(app)
    return out


# --------------------------------------------------------------------------- discovery per switch
def group_block_item(graph: Client, cfg: dict, groups: list[dict]) -> dict:
    pid = (cfg.get("groups") or {}).get("block_policy_id")
    if not pid:
        raise ValueError("--disable-groups needs [groups] block_policy_id: a pre-created CA policy that blocks "
                         "all cloud apps (state disabled), with the break-glass accounts excluded")
    if pid == cfg["conditional_access"]["policy_id"]:
        raise ValueError("[groups] block_policy_id must be a different policy from the guests policy")
    ids = {g["id"] for g in groups}

    def target(users):
        t = dict(users)
        t["includeGroups"] = sorted(set(t.get("includeGroups") or []) | ids)
        return t
    it = _ca_item(graph, pid, target, "block-groups", [f"Block sign-in for members of {g['displayName']}" for g in groups])
    it["details"]["blockedGroups"] = [{"id": g["id"], "displayName": g["displayName"]} for g in groups]
    return it


def remove_members_items(graph: Client, groups: list[dict], keep: set[str]) -> list[dict]:
    return [group_members_item(graph, g["id"], remove_all_except=keep, reason="Emergency removal of all members")
            for g in groups]


def user_items(graph: Client, users: list[dict], break_glass: set[str]) -> list[dict]:
    items = []
    for u in users:
        it = _item("user", u["id"], u["displayName"], action="disable-user", severity="high",
                   reasons=["Listed as compromised / to be disabled"],
                   details={"upn": u.get("userPrincipalName"), "userType": u.get("userType"),
                            "onPremisesSyncEnabled": u.get("onPremisesSyncEnabled")},
                   before={"accountEnabled": u.get("accountEnabled", True)}, after={"accountEnabled": False})
        if u["id"] in break_glass:
            it.update(status="skipped-allowlist", action="none")
            it["reasons"].append("Break-glass account")
        elif u.get("onPremisesSyncEnabled"):
            it.update(status="report-only", action="report-only")
            it["reasons"].append("Synced from on-prem AD: disable it there (cloud changes are overwritten)")
        elif u.get("accountEnabled") is False:
            it.update(status="skipped", action="noop")
            it["reasons"].append("Already disabled")
        items.append(it)
    return items


def revoke_items(users: list[dict], break_glass: set[str]) -> list[dict]:
    items = []
    for u in users:
        it = _item("revoke-sessions", u["id"], u["displayName"], action="revoke-sign-in-sessions", severity="high",
                   reasons=["Invalidate refresh tokens and session cookies"],
                   details={"upn": u.get("userPrincipalName"), "irreversible": True}, irreversible=True)
        if u["id"] in break_glass:
            it.update(status="skipped-allowlist", action="none")
        items.append(it)
    return items


AUTHZ = "/v1.0/policies/authorizationPolicy"


def tenant_setting_items(graph: Client, invites: bool, consent: bool) -> list[dict]:
    pol = graph.get(AUTHZ)
    items = []
    if invites:
        cur = pol.get("allowInvitesFrom")
        it = _item("tenant-setting", "allowInvitesFrom", "Guest invitations", action="disable-guest-invites",
                   severity="medium", reasons=["Nobody can invite new guests"],
                   details={"current": cur}, before={"allowInvitesFrom": cur}, after={"allowInvitesFrom": "none"})
        if cur == "none":
            it.update(status="skipped", action="noop")
        items.append(it)
    if consent:
        perms = pol.get("defaultUserRolePermissions") or {}
        cur = perms.get("permissionGrantPoliciesAssigned") or []
        keep = [p for p in cur if not p.startswith("ManagePermissionGrantsForSelf.")]
        it = _item("tenant-setting", "userConsent", "User consent to apps", action="disable-user-consent",
                   severity="high", reasons=["Users can no longer consent to applications (consent phishing)"],
                   details={"current": cur},
                   before={"defaultUserRolePermissions": perms},
                   after={"defaultUserRolePermissions": {**perms, "permissionGrantPoliciesAssigned": keep}})
        if keep == cur:
            it.update(status="skipped", action="noop")
        items.append(it)
    return items


def aks_items(arm: Client, cfg: dict, mode: str, names: list[str] | None) -> list[dict]:
    rows = arm.resource_graph("""
resources
| where type =~ 'microsoft.containerservice/managedclusters'
| project id, name, resourceGroup, subscriptionId, location, tags,
          powerState = tostring(properties.powerState.code),
          authorizedIPRanges = properties.apiServerAccessProfile.authorizedIPRanges,
          privateCluster = tobool(properties.apiServerAccessProfile.enablePrivateCluster),
          kubernetesVersion = tostring(properties.kubernetesVersion)
""")
    if names:
        rows = select_resources(rows, names, "AKS cluster")
    ranges = sorted((cfg.get("aks") or {}).get("authorized_ip_ranges", []))
    if mode == "restrict-api" and not ranges:
        raise ValueError("--aks-mode restrict-api needs [aks] authorized_ip_ranges in shutter.toml")
    items = []
    for r in rows:
        if mode == "stop":
            before, after = {"powerState": r.get("powerState") or "Running"}, {"powerState": "Stopped"}
            reasons = ["Stop the cluster (control plane and nodes)"]
        else:
            before = {"authorizedIPRanges": sorted(r.get("authorizedIPRanges") or [])}
            after = {"authorizedIPRanges": ranges}
            reasons = [f"Restrict API server to {', '.join(ranges)}"]
        it = _item("aks", r["id"], r["name"], action=f"aks-{mode}", severity="high", reasons=reasons,
                   details={k: r.get(k) for k in ("resourceGroup", "subscriptionId", "location", "kubernetesVersion",
                                                  "privateCluster", "powerState", "authorizedIPRanges")} | {"tags": r.get("tags") or {}},
                   before=before, after=after)
        if before == after:
            it.update(status="skipped", action="noop")
        elif mode == "restrict-api" and r.get("privateCluster"):
            it.update(status="report-only", action="report-only")
            it["reasons"].append("Private cluster: authorized IP ranges do not apply")
        items.append(it)
    return items


def keyvault_items(arm: Client, names: list[str] | None) -> list[dict]:
    rows = arm.resource_graph("""
resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, resourceGroup, subscriptionId, location, tags,
          publicNetworkAccess = tostring(properties.publicNetworkAccess)
""")
    if names:
        rows = select_resources(rows, names, "key vault")
    items = []
    for r in rows:
        cur = r.get("publicNetworkAccess") or "Enabled"
        if cur == "Disabled" and not names:
            continue
        it = _item("keyvault", r["id"], r["name"], action="disable-public-access", severity="high",
                   reasons=[f"Public network access: {cur}"],
                   details={k: r.get(k) for k in ("resourceGroup", "subscriptionId", "location")} | {"tags": r.get("tags") or {}},
                   before={"publicNetworkAccess": cur}, after={"publicNetworkAccess": "Disabled"})
        if cur == "Disabled":
            it.update(status="skipped", action="noop")
        items.append(it)
    return items


def rg_lock_items(arm: Client, names: list[str]) -> list[dict]:
    rows = arm.resource_graph("""
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| project id, name, subscriptionId, location, tags
""")
    rows = select_resources(rows, names, "resource group")
    items = []
    for r in rows:
        cur = _read_lock(arm, r["id"])
        it = _item("rg-lock", r["id"], r["name"], action="add-delete-lock", severity="medium",
                   reasons=["CanNotDelete lock against destruction / ransomware"],
                   details={"subscriptionId": r.get("subscriptionId"), "location": r.get("location"), "lockName": LOCK_NAME},
                   before=cur, after={"lock": "CanNotDelete"})
        if cur == it["after"]:
            it.update(status="skipped", action="noop")
        items.append(it)
    return items


def explicit_sp_items(graph: Client, sps: list[dict], flagged: dict[str, dict], cfg: dict) -> list[dict]:
    """--disable-enterprise-apps <list>: reuse detection details when the app was flagged anyway."""
    allow = cfg["allowlist"]
    items = []
    for sp in sps:
        if sp["id"] in flagged:
            it = flagged[sp["id"]]
            if it["status"] == "skipped-allowlist":
                it["reasons"].append("Explicitly listed, but allowlisted — remove it from the allowlist to disable it")
            items.append(it)
            continue
        it = _item("service-principal", sp["id"], sp["displayName"], action="disable-service-principal",
                   severity="medium", reasons=["Explicitly listed"],
                   details={"appId": sp["appId"], "servicePrincipalType": sp.get("servicePrincipalType"),
                            "publisher": sp.get("publisherName"), "ownerTenantId": sp.get("appOwnerOrganizationId"),
                            "createdDateTime": sp.get("createdDateTime")},
                   before={"accountEnabled": sp.get("accountEnabled", True)}, after={"accountEnabled": False})
        if sp.get("appOwnerOrganizationId") in allow["owner_tenant_ids"] or sp["appId"] in allow["app_ids"]:
            it.update(status="skipped-allowlist", action="none")
            it["reasons"].append("Microsoft first-party or allowlisted")
        elif sp.get("servicePrincipalType") == "ManagedIdentity":
            it.update(status="report-only", action="report-only")
        elif sp.get("accountEnabled") is False:
            it.update(status="skipped", action="noop")
        items.append(it)
    return items


def explicit_app_items(graph: Client, apps: list[dict], flagged: dict[str, dict], sp_items: dict[str, dict], cfg: dict) -> list[dict]:
    items = []
    for app in apps:
        if app["id"] in flagged:
            items.append(flagged[app["id"]])
            continue
        try:
            sp = graph.get(f"/v1.0/servicePrincipals(appId='{app['appId']}')?$select=id,accountEnabled")
        except ApiError:
            sp = None
        it = _item("app-registration", app["id"], app["displayName"], reasons=["Explicitly listed"],
                   details={"appId": app["appId"], "signInAudience": app.get("signInAudience"),
                            "multiTenant": app.get("signInAudience") != "AzureADMyOrg",
                            "servicePrincipalId": sp and sp["id"]})
        if app["appId"] in cfg["allowlist"]["app_ids"]:
            it.update(status="skipped-allowlist", action="none")
        elif app["appId"] in sp_items:
            it.update(status="covered", action="see-service-principal")
        elif not sp:
            it.update(status="report-only", action="report-only")
            it["reasons"].append("No service principal in this tenant")
        elif sp.get("accountEnabled") is False:
            it.update(status="skipped", action="noop")
        else:
            it.update(action="disable-service-principal", before={"accountEnabled": True}, after={"accountEnabled": False})
        items.append(it)
    return items


# --------------------------------------------------------------------------- read / write handlers
def _read_lock(arm: Client, rg_id: str) -> dict:
    try:
        lk = arm.get(f"{rg_id}/providers/Microsoft.Authorization/locks/{LOCK_NAME}?api-version={LOCK_API}")
        return {"lock": lk["properties"]["level"]}
    except ApiError as e:
        if e.status == 404:
            return {"lock": None}
        raise


def _sp_id(it):
    return it["id"] if it["category"] == "service-principal" else it["details"]["servicePrincipalId"]


def read(it: dict, graph: Client, arm: Client) -> dict:
    cat, keys = it["category"], (it.get("after") or it.get("before") or {}).keys()
    if cat in ("conditional-access", "group-block"):
        p = strip_odata(graph.get(f"/v1.0/identity/conditionalAccess/policies/{it['details'].get('policyId', it['id'])}"))
        return {"state": p["state"], "conditions": p["conditions"]}
    if cat == "storage":
        p = arm.get(f"{it['id']}?api-version={STORAGE_API}")["properties"]
        cur = {"isSftpEnabled": bool(p.get("isSftpEnabled")), "publicNetworkAccess": p.get("publicNetworkAccess") or "Enabled"}
        return {k: cur[k] for k in keys}
    if cat in ("service-principal", "app-registration"):
        return {"accountEnabled": graph.get(f"/v1.0/servicePrincipals/{_sp_id(it)}?$select=accountEnabled")["accountEnabled"]}
    if cat == "user":
        return {"accountEnabled": graph.get(f"/v1.0/users/{it['id']}?$select=accountEnabled")["accountEnabled"]}
    if cat == "group-members":
        return {"members": sorted(m["id"] for m in graph.get_all(f"/v1.0/groups/{it['id']}/members?$select=id&$top=999"))}
    if cat == "tenant-setting":
        pol = graph.get(AUTHZ)
        return {k: pol.get(k) for k in keys}
    if cat == "keyvault":
        return {"publicNetworkAccess": arm.get(f"{it['id']}?api-version={KV_API}")["properties"].get("publicNetworkAccess") or "Enabled"}
    if cat == "aks":
        p = arm.get(f"{it['id']}?api-version={AKS_API}")["properties"]
        if "powerState" in keys:
            code = (p.get("powerState") or {}).get("code", "Running")
            return {"powerState": {"Stopping": "Stopped", "Starting": "Running"}.get(code, code)}
        return {"authorizedIPRanges": sorted((p.get("apiServerAccessProfile") or {}).get("authorizedIPRanges") or [])}
    if cat == "rg-lock":
        return _read_lock(arm, it["id"])
    raise ValueError(f"no reader for {cat}")


def write(it: dict, state: dict, graph: Client, arm: Client) -> None:
    cat = it["category"]
    if cat in ("conditional-access", "group-block"):
        graph.patch(f"/v1.0/identity/conditionalAccess/policies/{it['details'].get('policyId', it['id'])}", state)
    elif cat == "storage":
        arm.patch(f"{it['id']}?api-version={STORAGE_API}", {"properties": state})
    elif cat in ("service-principal", "app-registration"):
        graph.patch(f"/v1.0/servicePrincipals/{_sp_id(it)}", state)
    elif cat == "user":
        graph.patch(f"/v1.0/users/{it['id']}", state)
    elif cat == "group-members":
        current = set(read(it, graph, arm)["members"])
        target = set(state["members"])
        for m in sorted(target - current):
            graph.post(f"/v1.0/groups/{it['id']}/members/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{m}"})
        for m in sorted(current - target):
            graph.request("DELETE", f"/v1.0/groups/{it['id']}/members/{m}/$ref")
    elif cat == "tenant-setting":
        graph.patch(AUTHZ, state)
    elif cat == "keyvault":
        arm.patch(f"{it['id']}?api-version={KV_API}", {"properties": state})
    elif cat == "aks":
        if "powerState" in state:
            verb = "stop" if state["powerState"] == "Stopped" else "start"
            arm.post(f"{it['id']}/{verb}?api-version={AKS_API}", {})
        else:
            cluster = arm.get(f"{it['id']}?api-version={AKS_API}")
            prof = cluster["properties"].setdefault("apiServerAccessProfile", {})
            prof["authorizedIPRanges"] = state["authorizedIPRanges"]
            arm.request("PUT", f"{it['id']}?api-version={AKS_API}",
                        {k: cluster[k] for k in ("location", "properties", "identity", "sku", "tags") if k in cluster})
    elif cat == "rg-lock":
        url = f"{it['id']}/providers/Microsoft.Authorization/locks/{LOCK_NAME}?api-version={LOCK_API}"
        if state.get("lock"):
            arm.request("PUT", url, {"properties": {"level": state["lock"], "notes": "SHUTTER emergency containment"}})
        else:
            arm.request("DELETE", url)
    else:
        raise ValueError(f"no writer for {cat}")


def fire(it: dict, graph: Client) -> None:
    """Irreversible one-shot actions."""
    if it["category"] == "revoke-sessions":
        graph.post(f"/v1.0/users/{it['id']}/revokeSignInSessions", {})
    else:
        raise ValueError(f"no irreversible action for {it['category']}")
