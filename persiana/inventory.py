"""Read-only discovery. Builds the list of items persiana would act on (also used in dry-run)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .http import ApiError, Client

STORAGE_API = "2023-05-01"
ODATA_JUNK = re.compile(r"@odata\.")
TENANT_SCOPE = re.compile(
    r"^(/|/subscriptions/[^/]+|/providers/microsoft\.management/managementgroups/[^/]+)$", re.I
)

ALL_EXTERNAL_TYPES = (
    "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,"
    "b2bDirectConnectUser,otherExternalUser,serviceProvider"
)


def strip_odata(obj):
    """Remove @odata.* annotations so an object read from Graph can be PATCHed back verbatim."""
    if isinstance(obj, dict):
        return {k: strip_odata(v) for k, v in obj.items() if not ODATA_JUNK.search(k) or k == "@odata.type"}
    if isinstance(obj, list):
        return [strip_odata(v) for v in obj]
    return obj


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _item(category: str, id_: str, name: str, **kw) -> dict:
    base = {
        "key": f"{category}:{id_}", "category": category, "id": id_, "name": name,
        "action": None, "severity": "medium", "reasons": [], "permissions": [], "owners": [],
        "details": {}, "before": None, "after": None, "status": "planned", "error": None,
    }
    base.update(kw)
    return base


# --------------------------------------------------------------------------- helpers
def resolve_principals(graph: Client, ids: set[str]) -> dict[str, dict]:
    """Map object IDs -> {displayName, upn, type} using directoryObjects/getByIds (1000 per call)."""
    out: dict[str, dict] = {}
    ids_l = [i for i in ids if i]
    for i in range(0, len(ids_l), 1000):
        res = graph.post("/v1.0/directoryObjects/getByIds", {"ids": ids_l[i:i + 1000]})
        for o in res.get("value", []):
            out[o["id"]] = {
                "id": o["id"],
                "displayName": o.get("displayName"),
                "upn": o.get("userPrincipalName") or o.get("appId"),
                "type": o.get("@odata.type", "").split(".")[-1],
            }
    return out


def owners_of(graph: Client, path: str) -> list[dict]:
    try:
        rows = graph.get_all(f"{path}/owners?$select=id,displayName,userPrincipalName,appId")
    except ApiError:
        return []
    return [{"id": o["id"], "displayName": o.get("displayName"),
             "upn": o.get("userPrincipalName") or o.get("appId"),
             "type": o.get("@odata.type", "").split(".")[-1]} for o in rows]


def last_sign_in(graph: Client, app_id: str) -> str | None:
    """Best effort: beta servicePrincipalSignInActivities (needs AuditLog.Read.All + P1)."""
    try:
        res = graph.get(f"/beta/reports/servicePrincipalSignInActivities?$filter=appId eq '{app_id}'")
        v = res.get("value") or []
        return (v[0].get("lastSignInActivity") or {}).get("lastSignInDateTime") if v else None
    except ApiError:
        return None


# --------------------------------------------------------------------------- conditional access
def conditional_access(graph: Client, cfg: dict) -> dict:
    pid = cfg["conditional_access"]["policy_id"]
    pol = strip_odata(graph.get(f"/v1.0/identity/conditionalAccess/policies/{pid}"))
    users = pol["conditions"]["users"]
    target_users = dict(users)
    target_users["includeGuestsOrExternalUsers"] = {
        "guestOrExternalUserTypes": ALL_EXTERNAL_TYPES,
        "externalTenants": {"@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants",
                            "membershipKind": "all"},
    }
    excluded = resolve_principals(graph, set(users.get("excludeUsers", [])))
    scope = ((users.get("includeGuestsOrExternalUsers") or {}).get("externalTenants") or {})
    already = pol["state"] == "enabled" and scope.get("membershipKind") == "all"
    it = _item(
        "conditional-access", pid, pol["displayName"],
        action="noop" if already else "widen-to-all-external-tenants",
        severity="critical",
        reasons=["Block sign-in for every guest / external user (all external tenants)"],
        details={
            "currentState": pol["state"],
            "currentExternalTenants": scope,
            "excludedUsers": [excluded.get(u, {"id": u}) for u in users.get("excludeUsers", [])],
            "excludedGroups": users.get("excludeGroups", []),
            "grantControls": pol.get("grantControls"),
            "modifiedDateTime": pol.get("modifiedDateTime"),
        },
        before={"state": pol["state"], "conditions": pol["conditions"]},
        after={"state": "enabled", "conditions": {**pol["conditions"], "users": target_users}},
    )
    if already:
        it["status"] = "skipped"
        it["reasons"].append("Policy already enabled for all external tenants")
    return it


# --------------------------------------------------------------------------- SFTP
def sftp_accounts(arm: Client, graph: Client) -> list[dict]:
    rows = arm.resource_graph("""
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where tobool(properties.isSftpEnabled) == true
| join kind=leftouter (resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name) on subscriptionId
| project id, name, resourceGroup, subscriptionId, subscriptionName, location, tags,
          isLocalUserEnabled = tobool(properties.isLocalUserEnabled),
          publicNetworkAccess = tostring(properties.publicNetworkAccess)
""")
    if not rows:
        return []
    ids = ",".join(f"'{r['id'].lower()}'" for r in rows)
    owners_rows = arm.resource_graph(f"""
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend scope = tolower(tostring(properties.scope)), principalId = tostring(properties.principalId),
         roleGuid = tolower(extract(@'([0-9a-fA-F-]{{36}})$', 1, tostring(properties.roleDefinitionId)))
| where scope in ({ids}) and roleGuid == '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
| project scope, principalId
""")
    principals = resolve_principals(graph, {o["principalId"] for o in owners_rows})
    items = []
    for r in rows:
        tags = r.get("tags") or {}
        owners = [principals.get(o["principalId"], {"id": o["principalId"]})
                  for o in owners_rows if o["scope"] == r["id"].lower()]
        for k in ("owner", "Owner", "createdBy", "CreatedBy", "team", "Team"):
            if k in tags:
                owners.append({"displayName": tags[k], "type": f"tag:{k}"})
        local_users = []
        try:
            lu = arm.get(f"{r['id']}/localUsers?api-version={STORAGE_API}")
            local_users = [u["name"] for u in lu.get("value", [])]
        except ApiError:
            pass
        items.append(_item(
            "sftp", r["id"], r["name"], action="disable-sftp", severity="high", owners=owners,
            reasons=["SFTP endpoint enabled on storage account"],
            details={k: r.get(k) for k in ("subscriptionName", "subscriptionId", "resourceGroup",
                                           "location", "isLocalUserEnabled", "publicNetworkAccess")}
                    | {"localUsers": local_users, "tags": tags},
            before={"isSftpEnabled": True}, after={"isSftpEnabled": False},
        ))
    return items


# --------------------------------------------------------------------------- service principals
def _resource_sps(graph: Client, resource_app_ids: set[str]) -> dict[str, dict]:
    """resource appId -> {id, displayName, roles{id:value}, scopes{id:value}}"""
    out = {}
    for app_id in resource_app_ids:
        try:
            sp = graph.get(f"/v1.0/servicePrincipals(appId='{app_id}')"
                           "?$select=id,appId,displayName,appRoles,oauth2PermissionScopes")
        except ApiError:
            continue
        out[app_id] = {
            "id": sp["id"], "displayName": sp["displayName"],
            "roles": {r["id"]: r["value"] for r in sp.get("appRoles", [])},
            "scopes": {s["id"]: s["value"] for s in sp.get("oauth2PermissionScopes", [])},
        }
    return out


def _severity(perms: list[dict], cfg: dict) -> str:
    low = set(cfg.get("severity", {}).get("low", []))
    if any(p["type"] == "directory-role" and p.get("privileged") for p in perms):
        return "critical"
    if any(p["type"] == "azure-rbac" and p["value"] in ("Owner", "User Access Administrator") for p in perms):
        return "critical"
    if any(p["value"] not in low for p in perms):
        return "high"
    return "medium"


def service_principals(graph: Client, arm: Client, cfg: dict, tenant_id: str,
                       caller_app_id: str | None) -> tuple[list[dict], dict]:
    sp_cfg = cfg["service_principals"]
    danger_roles = sp_cfg.get("dangerous_app_roles", {})
    danger_scopes = sp_cfg.get("dangerous_delegated_scopes", {})
    resources = _resource_sps(graph, set(danger_roles) | set(danger_scopes))
    by_res_sp_id = {r["id"]: (app_id, r) for app_id, r in resources.items()}
    perms: dict[str, list[dict]] = {}

    def add(sp_id: str, p: dict):
        perms.setdefault(sp_id, []).append(p)

    # 1) Application permissions (app role assignments) on Graph / EXO / SPO
    for app_id, res in resources.items():
        wanted = set(danger_roles.get(app_id, []))
        for a in graph.get_all(f"/v1.0/servicePrincipals/{res['id']}/appRoleAssignedTo?$top=999"):
            if a.get("principalType") != "ServicePrincipal":
                continue
            val = res["roles"].get(a["appRoleId"])
            if val in wanted:
                add(a["principalId"], {"type": "application", "resource": res["displayName"], "value": val,
                                       "grantedAt": a.get("createdDateTime")})

    # 2) Tenant-wide delegated consent
    for g in graph.get_all("/v1.0/oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'"):
        app_id, res = by_res_sp_id.get(g["resourceId"], (None, None))
        if not res:
            continue
        for s in (g.get("scope") or "").split():
            if s in danger_scopes.get(app_id, []):
                add(g["clientId"], {"type": "delegated-all-users", "resource": res["displayName"], "value": s})

    # 3) Entra directory roles
    defs = {d["id"]: d for d in graph.get_all(
        "/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isPrivileged,templateId")}
    for ra in graph.get_all("/v1.0/roleManagement/directory/roleAssignments?$top=999"):
        d = defs.get(ra["roleDefinitionId"], {})
        add(ra["principalId"], {"type": "directory-role", "resource": "Entra ID",
                                "value": d.get("displayName", ra["roleDefinitionId"]),
                                "privileged": bool(d.get("isPrivileged")),
                                "scope": ra.get("directoryScopeId")})

    # 4) Azure RBAC at subscription / management group / root
    wanted_rbac = {r.lower() for r in cfg.get("rbac", {}).get("dangerous_roles", [])}
    rbac = arm.resource_graph("""
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| where tostring(properties.principalType) == 'ServicePrincipal'
| extend principalId = tostring(properties.principalId), scope = tostring(properties.scope),
         roleGuid = tolower(extract(@'([0-9a-fA-F-]{36})$', 1, tostring(properties.roleDefinitionId)))
| join kind=inner (authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | extend roleGuid = tolower(name), roleName = tostring(properties.roleName)
    | distinct roleGuid, roleName) on roleGuid
| project principalId, scope, roleName
""")
    subs = {r["subscriptionId"]: r["name"] for r in arm.resource_graph(
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name")}
    for r in rbac:
        if r["roleName"].lower() in wanted_rbac and TENANT_SCOPE.match(r["scope"]):
            sub = r["scope"].split("/")[2] if r["scope"].lower().startswith("/subscriptions/") else None
            add(r["principalId"], {"type": "azure-rbac", "resource": "Azure", "value": r["roleName"],
                                   "scope": r["scope"], "scopeName": subs.get(sub, r["scope"])})

    # Directory roles are only "dangerous" for SPs (users are out of scope) — filter later by SP lookup.
    allow = cfg["allowlist"]
    items, skipped, sp_by_app = [], [], {}
    sel = ("id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,"
           "publisherName,createdDateTime,tags,verifiedPublisher,homepage")
    for sp_id, plist in perms.items():
        try:
            sp = graph.get(f"/v1.0/servicePrincipals/{sp_id}?$select={sel}")
        except ApiError:
            continue  # not a service principal (user / group holding a directory role)
        sp_by_app[sp["appId"]] = sp["id"]
        owners = owners_of(graph, f"/v1.0/servicePrincipals/{sp_id}")
        if sp.get("appOwnerOrganizationId") == tenant_id:
            owners += [o | {"type": f"app-registration {o['type']}"}
                       for o in owners_of(graph, f"/v1.0/applications(appId='{sp['appId']}')")]
        it = _item(
            "service-principal", sp_id, sp["displayName"], action="disable-service-principal",
            permissions=plist, owners=owners, severity=_severity(plist, cfg),
            reasons=sorted({f"{p['type']}: {p['value']}" for p in plist}),
            details={
                "appId": sp["appId"], "servicePrincipalType": sp.get("servicePrincipalType"),
                "publisher": sp.get("publisherName"),
                "verifiedPublisher": (sp.get("verifiedPublisher") or {}).get("displayName"),
                "ownerTenantId": sp.get("appOwnerOrganizationId"),
                "homeTenant": sp.get("appOwnerOrganizationId") == tenant_id,
                "createdDateTime": sp.get("createdDateTime"),
                "lastSignIn": last_sign_in(graph, sp["appId"]),
            },
            before={"accountEnabled": sp.get("accountEnabled", True)}, after={"accountEnabled": False},
        )
        why = None
        if sp.get("appOwnerOrganizationId") in allow["owner_tenant_ids"]:
            why = "Microsoft first-party application"
        elif sp["appId"] in allow["app_ids"] or sp_id in allow["service_principal_ids"]:
            why = "In persiana.toml allowlist"
        elif caller_app_id and sp["appId"] == caller_app_id:
            why = "Identity running persiana"
        elif sp.get("servicePrincipalType") == "ManagedIdentity":
            it["action"] = "report-only"
            it["reasons"].append("Managed identity: cannot be disabled via Graph — remove its role "
                                 "assignments or the identity itself manually")
        elif sp.get("accountEnabled") is False:
            it["action"] = "noop"
            it["status"] = "skipped"
            it["reasons"].append("Already disabled")
        if why:
            it["status"], it["action"] = "skipped-allowlist", "none"
            it["reasons"].append(why)
            skipped.append(it)
        else:
            if it["action"] == "report-only":
                it["status"] = "report-only"
            items.append(it)
    return items + skipped, {"resources": resources, "sp_by_app": sp_by_app}


# --------------------------------------------------------------------------- app registrations
def app_registrations(graph: Client, cfg: dict, ctx: dict, sp_items: list[dict]) -> list[dict]:
    danger_roles = cfg["service_principals"].get("dangerous_app_roles", {})
    danger_scopes = cfg["service_principals"].get("dangerous_delegated_scopes", {})
    resources = ctx["resources"]
    covered = {i["details"]["appId"]: i for i in sp_items if i["category"] == "service-principal"}
    allow = cfg["allowlist"]
    now = _now()
    items = []
    apps = graph.get_all("/v1.0/applications?$top=999&$select=id,appId,displayName,signInAudience,"
                         "requiredResourceAccess,passwordCredentials,keyCredentials,createdDateTime,"
                         "publisherDomain,notes")
    for app in apps:
        plist = []
        for rra in app.get("requiredResourceAccess", []):
            res = resources.get(rra["resourceAppId"])
            if not res:
                continue
            for ra in rra.get("resourceAccess", []):
                if ra["type"] == "Role":
                    v = res["roles"].get(ra["id"])
                    if v in danger_roles.get(rra["resourceAppId"], []):
                        plist.append({"type": "application (requested)", "resource": res["displayName"], "value": v})
                else:
                    v = res["scopes"].get(ra["id"])
                    if v in danger_scopes.get(rra["resourceAppId"], []):
                        plist.append({"type": "delegated (requested)", "resource": res["displayName"], "value": v})
        if not plist:
            continue
        creds = [{"kind": "secret", "name": c.get("displayName"), "hint": c.get("hint"),
                  "start": c.get("startDateTime"), "end": c.get("endDateTime"),
                  "active": (_parse_dt(c.get("endDateTime")) or now) > now}
                 for c in app.get("passwordCredentials", [])]
        creds += [{"kind": "certificate", "name": c.get("displayName"), "start": c.get("startDateTime"),
                   "end": c.get("endDateTime"), "active": (_parse_dt(c.get("endDateTime")) or now) > now}
                  for c in app.get("keyCredentials", [])]
        active = [c for c in creds if c["active"]]
        sp_id = ctx["sp_by_app"].get(app["appId"])
        if not sp_id:
            try:
                sp_id = graph.get(f"/v1.0/servicePrincipals(appId='{app['appId']}')?$select=id,accountEnabled")["id"]
            except ApiError:
                sp_id = None
        it = _item(
            "app-registration", app["id"], app["displayName"], permissions=plist,
            owners=owners_of(graph, f"/v1.0/applications/{app['id']}"),
            severity=_severity(plist, cfg) if active else "medium",
            reasons=sorted({f"{p['type']}: {p['value']}" for p in plist}),
            details={"appId": app["appId"], "signInAudience": app.get("signInAudience"),
                     "multiTenant": app.get("signInAudience") != "AzureADMyOrg",
                     "credentials": creds, "activeCredentials": len(active),
                     "createdDateTime": app.get("createdDateTime"),
                     "publisherDomain": app.get("publisherDomain"), "notes": app.get("notes"),
                     "servicePrincipalId": sp_id},
        )
        if app["appId"] in allow["app_ids"]:
            it.update(status="skipped-allowlist", action="none")
            it["reasons"].append("In persiana.toml allowlist")
        elif app["appId"] in covered:
            it.update(status="covered", action="see-service-principal")
            it["details"]["coveredBy"] = covered[app["appId"]]["key"]
        elif not sp_id:
            it.update(status="report-only", action="report-only")
            it["reasons"].append("No service principal in this tenant: nothing to disable here"
                                 + (" — multi-tenant app may still be used in other tenants" if it["details"]["multiTenant"] else ""))
        else:
            sp = graph.get(f"/v1.0/servicePrincipals/{sp_id}?$select=accountEnabled")
            if sp.get("accountEnabled") is False:
                it.update(status="skipped", action="noop")
                it["reasons"].append("Service principal already disabled")
            else:
                it["action"] = "disable-service-principal"
                it["before"], it["after"] = {"accountEnabled": True}, {"accountEnabled": False}
        if not active and it["status"] == "planned":
            it["reasons"].append("No active credentials (lower risk)")
        items.append(it)
    return items
