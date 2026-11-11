# Design

## Flow

```
preflight (identity) ─▶ inventory (read-only) ─▶ preflight (per resource) ─▶ [--execute] confirmation ─▶ actions ─▶ report.json + report.html
```

- The inventory runs the same way in dry-run and execute. A dry-run HTML report shows exactly what would be done.
- Before writing, each action **re-reads** the state, stores it as `before`, writes, and re-reads the result as `after`. If the object is already in the target state, it is marked `skipped`.
- Errors are recorded on the item itself and execution continues with the next one. The exit code is 1 if anything failed and 2 if the preflight failed.

## Detection criteria

### Conditional Access policy
Identified by ID (`conditional_access.policy_id`), never by name. The action is:
- `includeGuestsOrExternalUsers.externalTenants` is set to `membershipKind: all`, with every guest and external user type.
- `state` is set to `enabled`.
- The rest of the policy is left untouched, including exclusions (break-glass).

### SFTP
A Resource Graph query finds storage accounts with `isSftpEnabled == true` across every visible subscription. Owners come from two sources: RBAC **Owner** assignments on the account and the `owner`, `createdBy` and `team` tags.

### Enterprise apps (service principals)
A service principal is flagged if it meets **any** of these conditions:
1. An **app role assignment** for an application permission listed in `dangerous_app_roles` (Graph, Exchange or SharePoint).
2. An **`oauth2PermissionGrant` with `consentType = AllPrincipals`**, i.e. admin consent for all users, with a scope from `dangerous_delegated_scopes`.
3. An assigned **Entra directory role**. Severity is `critical` if the role is `isPrivileged`.
4. An **Azure RBAC** role listed in `rbac.dangerous_roles` on `/`, a management group or a subscription. Assignments at resource group or resource level are not flagged.

Exclusions are applied in this order: Microsoft first-party (`appOwnerOrganizationId`), allowlist, the identity running the script, and SPs that are already disabled. **Managed identities** are marked `report-only` because they cannot be disabled through Graph.

### App registrations
Applications whose `requiredResourceAccess` **requests** a dangerous permission are flagged, even if it has not been granted. Depending on the case:
- If there is already an item for its SP, it is marked `covered` and points to it.
- If it has a local SP, the SP is disabled.
- If it has no SP in the tenant, it is marked `report-only`. If it is also multi-tenant, the report notes that it may be in use in other tenants.
- If it has no active credentials, severity drops to `medium`.

**Secrets and certificates are never deleted.** A secret's value cannot be restored, so deleting it would break rollback. Disabling the SP already prevents it from getting tokens in this tenant.

## `report.json` format

```jsonc
{
  "schema": 1,
  "tool": {"name": "persiana", "version": "0.1.0"},
  "run": {"id": "uuid", "mode": "dry-run|execute|execute-refused|execute-aborted|rollback-*",
          "startedAt": "...", "finishedAt": "...", "tenantId": "...", "configSha256": "...",
          "operator": {"kind": "user|application", "id": "...", "upn": "..."},
          "sourceRunId": "rollback only"},
  "preflight": {"ok": true, "checks": [{"name": "...", "ok": true, "detail": "...", "blocking": true}]},
  "summary": {"byCategory": {}, "byStatus": {}, "bySeverity": {}, "total": 0},
  "items": [{
    "key": "service-principal:<id>", "category": "conditional-access|sftp|service-principal|app-registration",
    "id": "...", "name": "...", "action": "disable-service-principal|disable-sftp|widen-to-all-external-tenants|report-only|...",
    "severity": "critical|high|medium", "reasons": ["..."],
    "permissions": [{"type": "application|delegated-all-users|directory-role|azure-rbac|...", "resource": "...", "value": "...", "scope": "..."}],
    "owners": [{"id": "...", "displayName": "...", "upn": "...", "type": "..."}],
    "details": {}, "before": {}, "after": {},
    "status": "planned|applied|failed|skipped|skipped-allowlist|covered|report-only|reverted|drift|not-applicable",
    "error": null
  }]
}
```

Rollback only processes items with `status == "applied"`, in reverse order: apps first, the CA policy last. For each one:
- If the current state matches `before`, it is marked `skipped`.
- If it matches `after`, `before` is restored.
- If it matches neither, it is marked `drift` and left untouched, unless `--force` is passed.

## Limitations

- **Tokens already issued.** Disabling an SP prevents it from requesting new tokens, but access tokens already issued (≈1 h) stay valid until they expire. Guests with open sessions depend on CAE.
- **Managed identities and multi-tenant apps without a local SP** are only reported.
- **Storage access keys and SAS tokens** are not rotated, because rotation is not reversible. Rotating them is the next manual step if SFTP was compromised.
- **Local SFTP user accounts** are not handled one by one: disabling SFTP closes the whole endpoint.
- **Not tested live.** All tests run against the simulated tenant in `tests/fake_tenant.py`.
