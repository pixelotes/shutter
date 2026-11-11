"""In-memory fake of the Graph / ARM endpoints persiana uses, populated with a Contoso tenant.

Used by tests and by examples/generate.py. Nothing here talks to Azure.
"""
from __future__ import annotations

import copy
import re
from urllib.parse import unquote

from persiana.http import ARM, GRAPH, ApiError

TENANT = "8f3c1d2e-4b5a-4c6d-9e8f-0a1b2c3d4e5f"
FABRIKAM = "5e2a9c41-7d3b-4f10-8a66-2c9e1b7d0f33"
NORTHWIND = "a7d1e3f5-9b2c-4d6e-8f0a-1c3e5a7b9d2f"
MSFT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"
EXO_APP = "00000002-0000-0ff1-ce00-000000000000"
SPO_APP = "00000003-0000-0ff1-ce00-000000000000"
CA_ID = "0c1b5d2e-71aa-4e8f-9d3c-2b6f4a8e1c90"
SUB_PROD = "2b7e4c19-5a3d-4e8f-b1c6-9d0a2f4e6b81"
SUB_DEV = "7c3f1e8a-2d4b-4a6c-9e1f-5b8d0c2a4e63"
SENTINEL_PLAYBOOK_APP = "3a9e7c51-0b2d-4f6e-8a1c-5d7e9b3f0a24"


def gid(n: int) -> str:
    return f"{n:08x}-c0de-4c0d-9e00-{n:012x}"


ROLES = {  # Graph app roles we care about: value -> id
    v: gid(1000 + i) for i, v in enumerate([
        "User.ReadWrite.All", "Group.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All",
        "Application.ReadWrite.All", "Directory.ReadWrite.All", "Directory.Read.All",
        "RoleManagement.ReadWrite.Directory", "User.Read.All", "Mail.Send"])
}
SCOPES = {v: gid(2000 + i) for i, v in enumerate(["Directory.AccessAsUser.All", "Mail.Send", "User.Read", "Mail.ReadWrite"])}
SPO_ROLES = {"Sites.FullControl.All": gid(3000)}

USERS = {
    gid(1): {"displayName": "Break Glass 01", "userPrincipalName": "bg-admin01@contoso.onmicrosoft.com"},
    gid(2): {"displayName": "Break Glass 02", "userPrincipalName": "bg-admin02@contoso.onmicrosoft.com"},
    gid(3): {"displayName": "Megan Bowen", "userPrincipalName": "meganb@contoso.com"},
    gid(4): {"displayName": "Adele Vance", "userPrincipalName": "adelev@contoso.com"},
    gid(5): {"displayName": "Lee Gu", "userPrincipalName": "leeg@contoso.com"},
    gid(6): {"displayName": "Alex Wilber", "userPrincipalName": "alexw@contoso.com"},
    gid(7): {"displayName": "Diego Siciliani", "userPrincipalName": "diegos@contoso.com"},
}


def sp(n, name, app_id, owner_tenant, **kw):
    return {"id": gid(n), "appId": app_id, "displayName": name, "accountEnabled": True,
            "appOwnerOrganizationId": owner_tenant, "servicePrincipalType": "Application",
            "publisherName": kw.pop("publisher", "Contoso"), "createdDateTime": kw.pop("created", "2023-03-14T09:12:00Z"),
            "tags": [], "verifiedPublisher": {"displayName": kw.pop("verified", None)}, **kw}


def build_state() -> dict:
    sps = {s["id"]: s for s in [
        sp(100, "Microsoft Graph", GRAPH_APP, MSFT, publisher="Microsoft Services",
           appRoles=[{"id": i, "value": v} for v, i in ROLES.items()],
           oauth2PermissionScopes=[{"id": i, "value": v} for v, i in SCOPES.items()]),
        sp(101, "Office 365 SharePoint Online", SPO_APP, MSFT, publisher="Microsoft Services",
           appRoles=[{"id": i, "value": v} for v, i in SPO_ROLES.items()], oauth2PermissionScopes=[]),
        sp(102, "Office 365 Exchange Online", EXO_APP, MSFT, publisher="Microsoft Services",
           appRoles=[], oauth2PermissionScopes=[]),
        sp(200, "Contoso HR Sync", gid(9200), TENANT, created="2022-06-01T10:00:00Z"),
        sp(201, "Legacy Backup Tool", gid(9201), NORTHWIND, publisher="Northwind Traders",
           created="2019-11-20T16:45:00Z"),
        sp(202, "Terraform Deployer", gid(9202), TENANT, created="2024-01-09T08:30:00Z"),
        sp(203, "Fabrikam Partner Portal", gid(9203), FABRIKAM, publisher="Fabrikam, Inc.",
           verified="Fabrikam, Inc.", created="2025-04-02T12:00:00Z"),
        sp(204, "Sentinel-Playbook-Isolate-User", SENTINEL_PLAYBOOK_APP, TENANT, created="2026-02-11T14:20:00Z"),
        sp(205, "Microsoft Intune PowerShell", gid(9205), MSFT, publisher="Microsoft Services"),
        sp(206, "mi-automation-prod", gid(9206), None, servicePrincipalType="ManagedIdentity",
           publisher=None, created="2024-09-30T07:00:00Z"),
        sp(207, "Contoso Helpdesk Bot", gid(9207), TENANT, created="2025-08-18T11:05:00Z"),
        sp(208, "Contoso Reporting API", gid(9208), TENANT, created="2021-02-03T09:00:00Z"),
    ]}
    apps = {a["id"]: a for a in [
        {"id": gid(300), "appId": gid(9200), "displayName": "Contoso HR Sync", "signInAudience": "AzureADMyOrg",
         "createdDateTime": "2022-06-01T09:58:00Z", "publisherDomain": "contoso.com", "notes": "Workday → Entra user sync",
         "requiredResourceAccess": [{"resourceAppId": GRAPH_APP, "resourceAccess": [
             {"id": ROLES["User.ReadWrite.All"], "type": "Role"}, {"id": ROLES["Group.ReadWrite.All"], "type": "Role"}]}],
         "passwordCredentials": [{"displayName": "prod-2026", "hint": "Q~7", "startDateTime": "2026-01-10T00:00:00Z", "endDateTime": "2027-01-10T00:00:00Z"}],
         "keyCredentials": []},
        {"id": gid(301), "appId": gid(9202), "displayName": "Terraform Deployer", "signInAudience": "AzureADMyOrg",
         "createdDateTime": "2024-01-09T08:29:00Z", "publisherDomain": "contoso.com", "notes": None,
         "requiredResourceAccess": [{"resourceAppId": GRAPH_APP, "resourceAccess": [{"id": ROLES["Application.ReadWrite.All"], "type": "Role"}]}],
         "passwordCredentials": [], "keyCredentials": [{"displayName": "CN=tf-deployer", "startDateTime": "2025-12-01T00:00:00Z", "endDateTime": "2027-12-01T00:00:00Z"}]},
        {"id": gid(302), "appId": gid(9208), "displayName": "Contoso Reporting API", "signInAudience": "AzureADMyOrg",
         "createdDateTime": "2021-02-03T08:55:00Z", "publisherDomain": "contoso.com", "notes": "PowerBI exports",
         "requiredResourceAccess": [{"resourceAppId": GRAPH_APP, "resourceAccess": [{"id": ROLES["Directory.Read.All"], "type": "Role"}]}],
         "passwordCredentials": [{"displayName": "old", "hint": "x9P", "startDateTime": "2021-02-03T00:00:00Z", "endDateTime": "2023-02-03T00:00:00Z"}],
         "keyCredentials": []},
        {"id": gid(303), "appId": gid(9303), "displayName": "Old Migration Script", "signInAudience": "AzureADMultipleOrgs",
         "createdDateTime": "2020-05-12T15:00:00Z", "publisherDomain": "contoso.com", "notes": "Tenant-to-tenant migration 2020",
         "requiredResourceAccess": [{"resourceAppId": GRAPH_APP, "resourceAccess": [
             {"id": ROLES["RoleManagement.ReadWrite.Directory"], "type": "Role"}, {"id": SCOPES["Directory.AccessAsUser.All"], "type": "Scope"}]}],
         "passwordCredentials": [{"displayName": "migration", "hint": "a1B", "startDateTime": "2020-05-12T00:00:00Z", "endDateTime": "2030-05-12T00:00:00Z"}],
         "keyCredentials": []},
        {"id": gid(304), "appId": SENTINEL_PLAYBOOK_APP, "displayName": "Sentinel-Playbook-Isolate-User", "signInAudience": "AzureADMyOrg",
         "createdDateTime": "2026-02-11T14:19:00Z", "publisherDomain": "contoso.com", "notes": None,
         "requiredResourceAccess": [{"resourceAppId": GRAPH_APP, "resourceAccess": [{"id": ROLES["User.ReadWrite.All"], "type": "Role"}]}],
         "passwordCredentials": [], "keyCredentials": []},
    ]}
    def ara(n, sp_n, res_n, role):
        return {"id": gid(n), "principalId": gid(sp_n), "principalType": "ServicePrincipal", "resourceId": gid(res_n),
                "appRoleId": role, "createdDateTime": "2024-05-01T10:00:00Z"}
    return {
        "ca": {
            "id": CA_ID, "displayName": "EXT - Block Fabrikam guests", "state": "enabled",
            "createdDateTime": "2026-10-01T09:00:00Z", "modifiedDateTime": "2026-10-20T17:34:06Z",
            "conditions": {
                "applications": {"includeApplications": ["All"], "excludeApplications": []},
                "clientAppTypes": ["all"],
                "users": {"includeUsers": [], "excludeUsers": [gid(1), gid(2)], "includeGroups": [], "excludeGroups": [],
                          "includeRoles": [], "excludeRoles": [],
                          "includeGuestsOrExternalUsers": {
                              "guestOrExternalUserTypes": "b2bCollaborationGuest,b2bCollaborationMember",
                              "externalTenants": {"@odata.type": "#microsoft.graph.conditionalAccessEnumeratedExternalTenants",
                                                  "membershipKind": "enumerated", "members": [FABRIKAM]}},
                          "excludeGuestsOrExternalUsers": None}},
            "grantControls": {"operator": "OR", "builtInControls": ["block"]},
        },
        "sps": sps, "apps": apps,
        "sp_owners": {gid(200): [gid(4)], gid(202): [gid(5)], gid(207): [gid(7)]},
        "app_owners": {gid(300): [gid(4)], gid(301): [gid(5), gid(6)], gid(302): [], gid(303): [], gid(304): [gid(6)]},
        "app_role_assignments": [
            ara(400, 200, 100, ROLES["User.ReadWrite.All"]), ara(401, 200, 100, ROLES["Group.ReadWrite.All"]),
            ara(402, 201, 100, ROLES["Mail.ReadWrite"]), ara(403, 201, 100, ROLES["Files.ReadWrite.All"]),
            ara(404, 201, 101, SPO_ROLES["Sites.FullControl.All"]),
            ara(405, 202, 100, ROLES["Application.ReadWrite.All"]),
            ara(406, 204, 100, ROLES["User.ReadWrite.All"]),
            ara(407, 205, 100, ROLES["Directory.ReadWrite.All"]),
        ],
        "grants": [{"clientId": gid(203), "resourceId": gid(100), "consentType": "AllPrincipals",
                    "scope": "User.Read Directory.AccessAsUser.All Mail.Send"}],
        "role_defs": [{"id": "fe930be7-5e62-47db-91af-98c3a49a38b1", "displayName": "User Administrator", "isPrivileged": True},
                      {"id": "62e90394-69f5-4237-9190-012177145e10", "displayName": "Global Administrator", "isPrivileged": True}],
        "role_assignments": [{"principalId": gid(207), "roleDefinitionId": "fe930be7-5e62-47db-91af-98c3a49a38b1", "directoryScopeId": "/"},
                             {"principalId": gid(6), "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", "directoryScopeId": "/"}],
        "rbac": [
            {"principalId": gid(202), "scope": f"/subscriptions/{SUB_PROD}", "roleName": "Owner"},
            {"principalId": gid(206), "scope": f"/subscriptions/{SUB_PROD}", "roleName": "Contributor"},
            {"principalId": gid(208), "scope": f"/subscriptions/{SUB_DEV}/resourceGroups/rg-reports", "roleName": "Contributor"},
        ],
        "subs": [{"subscriptionId": SUB_PROD, "name": "Contoso Production"}, {"subscriptionId": SUB_DEV, "name": "Contoso Dev"}],
        "storage": {
            f"/subscriptions/{SUB_PROD}/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stcontososftpprod": {
                "name": "stcontososftpprod", "resourceGroup": "rg-data", "subscriptionId": SUB_PROD, "location": "westeurope",
                "tags": {"owner": "data-platform", "costcenter": "CC-1042"}, "isSftpEnabled": True, "isLocalUserEnabled": True,
                "publicNetworkAccess": "Enabled", "localUsers": ["fabrikam-upload", "payroll-drop"], "owners": [gid(3)]},
            f"/subscriptions/{SUB_PROD}/resourceGroups/rg-partners/providers/Microsoft.Storage/storageAccounts/stpartnerexchange": {
                "name": "stpartnerexchange", "resourceGroup": "rg-partners", "subscriptionId": SUB_PROD, "location": "westeurope",
                "tags": {}, "isSftpEnabled": True, "isLocalUserEnabled": True, "publicNetworkAccess": "Enabled",
                "localUsers": ["northwind"], "owners": []},
            f"/subscriptions/{SUB_DEV}/resourceGroups/rg-dev/providers/Microsoft.Storage/storageAccounts/stcontosodevsftp": {
                "name": "stcontosodevsftp", "resourceGroup": "rg-dev", "subscriptionId": SUB_DEV, "location": "northeurope",
                "tags": {"createdBy": "leeg@contoso.com"}, "isSftpEnabled": True, "isLocalUserEnabled": False,
                "publicNetworkAccess": "Disabled", "localUsers": [], "owners": [gid(5)]},
        },
        "sign_ins": {gid(9200): "2026-11-11T06:02:00Z", gid(9201): "2026-11-10T23:41:00Z", gid(9202): "2026-11-09T15:20:00Z",
                     gid(9203): "2026-11-11T08:55:00Z", gid(9207): "2026-11-11T09:12:00Z", gid(9208): "2024-03-02T10:00:00Z"},
        "fail_patch": {gid(207)},   # SP holding a privileged role → simulated 403
    }


OPERATOR = {"oid": gid(6), "upn": "alexw@contoso.com", "tid": TENANT,
            "scp": "Application.ReadWrite.All AuditLog.Read.All Directory.Read.All Policy.Read.All Policy.ReadWrite.ConditionalAccess"}


class FakeTenant:
    def __init__(self):
        self.s = build_state()

    def client(self, base: str, token=None):
        return FakeClient(self, base)


class FakeClient:
    def __init__(self, tenant: FakeTenant, base: str):
        self.t, self.base = tenant, base
        self.claims = dict(OPERATOR) if base == GRAPH else {"tid": TENANT, "oid": gid(6)}

    # ---------------------------------------------------------------- plumbing
    def get_all(self, url):
        return self.get(url).get("value", [])

    def get(self, url):
        return self.request("GET", url)

    def patch(self, url, body):
        return self.request("PATCH", url, body)

    def post(self, url, body):
        return self.request("POST", url, body)

    def resource_graph(self, query):
        return self.post("/providers/Microsoft.ResourceGraph/resources", {"query": query})["data"]

    def request(self, method, url, body=None):
        url = unquote(url.replace(self.base, ""))
        path = url.split("?")[0]
        s = self.t.s
        fn = self._graph if self.base == GRAPH else self._arm
        res = fn(method, url, path, body, s)
        if res is None:
            raise ApiError(404, method, url, '{"error":{"code":"Request_ResourceNotFound"}}')
        return copy.deepcopy(res)

    # ---------------------------------------------------------------- Graph
    def _graph(self, method, url, path, body, s):
        sps, apps = s["sps"], s["apps"]
        def obj(i, kind):
            if i in USERS:
                return {"id": i, "@odata.type": "#microsoft.graph.user", **USERS[i]}
            if i in sps:
                return {"id": i, "@odata.type": "#microsoft.graph.servicePrincipal", "displayName": sps[i]["displayName"], "appId": sps[i]["appId"]}
            return None
        if path == f"/v1.0/identity/conditionalAccess/policies/{CA_ID}":
            if method == "PATCH":
                s["ca"].update(copy.deepcopy(body))
                return {}
            return {"@odata.context": "x", **s["ca"]}
        if path == "/v1.0/directoryObjects/getByIds":
            return {"value": [o for o in (obj(i, None) for i in body["ids"]) if o]}
        if path == "/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole":
            return {"value": [{"roleTemplateId": "62e90394-69f5-4237-9190-012177145e10", "displayName": "Global Administrator"}]}
        m = re.fullmatch(r"/v1\.0/servicePrincipals\(appId='([^']+)'\)", path)
        if m:
            return next((v for v in sps.values() if v["appId"] == m[1]), None)
        m = re.fullmatch(r"/v1\.0/applications\(appId='([^']+)'\)/owners", path)
        if m:
            app = next((a for a in apps.values() if a["appId"] == m[1]), None)
            return None if not app else {"value": [obj(o, None) for o in s["app_owners"].get(app["id"], [])]}
        m = re.fullmatch(r"/v1\.0/servicePrincipals/([^/]+)/appRoleAssignedTo", path)
        if m:
            return {"value": [a for a in s["app_role_assignments"] if a["resourceId"] == m[1]]}
        m = re.fullmatch(r"/v1\.0/servicePrincipals/([^/]+)/owners", path)
        if m:
            return {"value": [obj(o, None) for o in s["sp_owners"].get(m[1], [])]}
        m = re.fullmatch(r"/v1\.0/servicePrincipals/([^/]+)", path)
        if m:
            if m[1] not in sps:
                return None
            if method == "PATCH":
                if m[1] in s["fail_patch"]:
                    raise ApiError(403, method, url, '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}')
                sps[m[1]].update(body)
                return {}
            return sps[m[1]]
        if path == "/v1.0/oauth2PermissionGrants":
            return {"value": s["grants"]}
        if path == "/v1.0/roleManagement/directory/roleDefinitions":
            return {"value": s["role_defs"]}
        if path == "/v1.0/roleManagement/directory/roleAssignments":
            return {"value": s["role_assignments"]}
        if path == "/beta/reports/servicePrincipalSignInActivities":
            app_id = re.search(r"appId eq '([^']+)'", url)[1]
            ts = s["sign_ins"].get(app_id)
            return {"value": [{"appId": app_id, "lastSignInActivity": {"lastSignInDateTime": ts}}] if ts else []}
        if path == "/v1.0/applications":
            return {"value": list(apps.values())}
        m = re.fullmatch(r"/v1\.0/applications/([^/]+)/owners", path)
        if m:
            return {"value": [obj(o, None) for o in s["app_owners"].get(m[1], [])]}
        return None

    # ---------------------------------------------------------------- ARM
    def _arm(self, method, url, path, body, s):
        st = s["storage"]
        if path == "/providers/Microsoft.ResourceGraph/resources":
            q = body["query"]
            subs = {x["subscriptionId"]: x["name"] for x in s["subs"]}
            if "isSftpEnabled" in q:
                return {"data": [{"id": i, "subscriptionName": subs[v["subscriptionId"]],
                                  **{k: v[k] for k in ("name", "resourceGroup", "subscriptionId", "location", "tags", "isLocalUserEnabled", "publicNetworkAccess")}}
                                 for i, v in st.items() if v["isSftpEnabled"]]}
            if "8e3af657" in q:
                return {"data": [{"scope": i.lower(), "principalId": o} for i, v in st.items() for o in v["owners"]]}
            if "principalType" in q:
                return {"data": s["rbac"]}
            if "resourcecontainers" in q:
                return {"data": s["subs"]}
            return {"data": []}
        if path.endswith("/localUsers"):
            v = st.get(path.rsplit("/localUsers", 1)[0])
            return v and {"value": [{"name": n} for n in v["localUsers"]]}
        if path.endswith("/providers/Microsoft.Authorization/permissions"):
            return {"value": [{"actions": ["*"], "notActions": []}]}
        if path in st:
            if method == "PATCH":
                st[path].update(body["properties"])
                return {}
            return {"id": path, "properties": {"isSftpEnabled": st[path]["isSftpEnabled"]}}
        return None
