# Design

## Flow

```
preflight (identity) ─▶ inventory (read-only) ─▶ preflight (per resource) ─▶ [--execute] confirmation ─▶ actions ─▶ report.json + report.html
```

- The inventory runs the same way in dry-run and execute. A dry-run HTML report shows exactly what would be done.
- Before writing, each action **re-reads** the state, stores it as `before`, writes, and re-reads the result as `after`. If the object is already in the target state, it is marked `skipped`.
- Errors are recorded on the item itself and execution continues with the next one. The exit code is 1 if anything failed and 2 if the preflight failed.

## Execution control

### Journal and resume
During `--execute`, `report.json` is rewritten atomically (temp file + rename) **before each write** (item marked `in-progress` with its `before` state) and **after it**. `run.status` is `running` until the run finishes.
- If the process dies, `rollback` accepts the unfinished report. For `in-progress` items it compares live state: if it equals `before` the write never landed (skipped); if it equals `after`, it is reverted.
- `run --resume <report.json>` continues in the same report and run ID. An `in-progress` item whose write already landed becomes `applied` and keeps its original `before`, so it stays revertible.

### Run lock
Execute and rollback hold a lock per tenant:
- With `[control] storage_account`: an infinite **blob lease** on `locks/<tenant>.lock`, shared by every operator. The blob holds the holder's run ID and UPN. A crash leaves the lease held; `shutter unlock` breaks it.
- Without `[control]`: a local `flock` on `~/.shutter-<tenant>.lock` (same machine only).

### Two-person rule (optional)
With `[approval] required = true`:
1. Operator A runs a dry-run.
2. Operator B (a different identity, optionally a member of `approver_group_id`) reviews it and runs `shutter approve <report.json>`. This writes `approvals/<plan-hash>.json` to the control container with B's identity and an expiry (`ttl_minutes`).
3. A runs `run --execute --from-plan <report.json>`. Preflight checks the approval exists for that exact plan hash, has not expired, and was not given by the executor. Any edit to the plan changes its hash and invalidates the approval.

The plan is executed as approved: no re-discovery, so nothing new sneaks in. Each item is still re-read before writing (idempotency).

This is a process control, not cryptography: anyone with write access to the control container could forge an approval. Restrict the container's RBAC to the approver group and keep its diagnostic logs.

### Notifications
`[[notify]]` entries (Teams Workflows webhook, Slack webhook, SMTP email, generic JSON webhook) receive `execute-start`, `execute-end`, `execute-refused`, `rollback-start` and `rollback-end` (and optionally `dry-run`). Messages include tenant, operator, approver, counts, items that need attention and the report hash; email attaches the HTML report. Secrets come from environment variables. Failures are recorded in `report.json` under `notifications` and never stop the run.

### Report integrity
Every report directory gets `report.sha256` (hashes of `report.json` and `report.html`). Execute and rollback reports are uploaded to `reports/<run-id>/` in the control container; enable a time-based immutability policy on it so they cannot be altered.

## Selection

A run is built from switches (see the README table). `None` (switch absent) and `[]` (switch without a list = everything in scope) are different, and the normalised selection is stored in `run.selection`. With no switch at all the run stops: there is no implicit "disable everything"; `--all` must be explicit.

List entries are resolved before anything else: object IDs, UPNs, appIds or full resource IDs are matched exactly; names must match exactly one object or the run stops. `--exclude` and the allowlist then mark matching items `skipped-allowlist`. The `[control]` storage account is always excluded, so the lock, approvals and archive keep working during a storage lockdown.

Execution order (rollback is the reverse): Conditional Access → users → sessions → group members → tenant settings → resource group locks → enterprise apps → app registrations → storage → Key Vault → AKS. Identity-plane blocks go first because they take effect fastest.

## Modules

Every module defines a target state for each object. Before writing, the live state is re-read: if it already matches the target the item is `skipped` (idempotency); otherwise it is recorded as `before`, written, and re-read as `after`. Rollback writes `before` back, unless the live state matches neither (drift).

### Conditional Access: guests (`--disable-guests [DOMAINS]`)
Uses the policy in `conditional_access.policy_id`, identified by ID, never by name. Only `conditions.users` and `state` change; the rest of the policy (including break-glass exclusions) stays as is.
- **No domains:** `includeGuestsOrExternalUsers.externalTenants` becomes `membershipKind: all`, with every guest and external user type.
- **Domains:** Conditional Access targets external users by tenant, not by email domain. Each domain is resolved with `findTenantInformationByDomainName`; domains backed by an Entra tenant go into the enumerated tenant list. Guests whose `mail` / `otherMails` end in a domain **without** a tenant (personal Microsoft accounts, email one-time passcode) are added to the static group `conditional_access.static_group_id`, which the policy includes. A dynamic group is not used: membership processing can take hours.

### Conditional Access: groups (`--disable-groups (GROUPS)`)
Adds the groups to `includeGroups` of a **separate**, pre-created policy (`[groups] block_policy_id`, block all cloud apps, initially disabled) and enables it. Using the guest policy is refused, so the two rollbacks never conflict. Blocking via CA is preferred to emptying groups: synced groups cannot be edited in the cloud and dynamic groups refill themselves.

### Group members (`--remove-group-members (GROUPS)`)
Target membership = current members ∩ (break-glass ∪ `--exclude`). Rollback re-adds exactly the removed members and removes nobody added later by hand (that shows as drift). Synced and dynamic groups are `report-only`.

### Users and sessions (`--disable-users`, `--revoke-sessions`)
`accountEnabled = false`. Users synced from on-prem AD are `report-only` (the next sync would overwrite the change); break-glass accounts are never touched. Session revocation is **irreversible**: it is marked as such in the report, needs a second typed confirmation (`IRREVERSIBLE <tenant[:8]>`, otherwise those items are skipped), and rollback reports it as `irreversible`. It is also not idempotent: running it twice revokes twice, which is harmless.

### Tenant settings (`--disable-guest-invites`, `--disable-user-consent`)
On `/policies/authorizationPolicy`: `allowInvitesFrom = none`, and the `ManagePermissionGrantsForSelf.*` policies removed from `defaultUserRolePermissions.permissionGrantPoliciesAssigned` (other entries, such as owner consent policies, are kept). The whole `defaultUserRolePermissions` object is stored and restored, because it is a complex type.

### Storage (`--disable-storage [ACCOUNTS]`, `--storage-mode`)
`sftp` sets `isSftpEnabled = false`; `public` sets `publicNetworkAccess = Disabled`; `both` (default) does both. Without a list, every account that still needs a change is selected. Owners come from RBAC **Owner** assignments on the account and the `owner`, `createdBy` and `team` tags. Disabling public access also cuts off anything not on a private endpoint or trusted service path: put critical accounts in `allowlist.resource_ids` or `--exclude`.

### Key Vault (`--disable-keyvault-public-access [VAULTS]`)
`publicNetworkAccess = Disabled`. Vaults already closed are not listed unless named.

### AKS (`--disable-aks [CLUSTERS]`, `--aks-mode`)
- `stop` (default): `POST .../stop`; rollback starts the cluster. `Stopping` / `Starting` are read as their final state.
- `restrict-api`: sets `apiServerAccessProfile.authorizedIPRanges` to `[aks] authorized_ip_ranges` (required). Private clusters are `report-only`, since the setting does not apply to them.

### Resource group locks (`--lock-resource-groups (RGS)`)
Creates a `CanNotDelete` lock named `shutter-emergency`; rollback deletes it. The lock does not block configuration changes, so it does not interfere with the other modules.

### Enterprise apps (`--disable-enterprise-apps [APPS]`)
Without a list, the detection below decides. With a list, exactly those service principals are disabled (detection details are reused when available); allowlisted and Microsoft first-party apps stay untouched even if listed.

A service principal is flagged if it meets **any** of these conditions:
1. An **app role assignment** for an application permission listed in `dangerous_app_roles` (Graph, Exchange or SharePoint).
2. An **`oauth2PermissionGrant` with `consentType = AllPrincipals`**, i.e. admin consent for all users, with a scope from `dangerous_delegated_scopes`.
3. An assigned **Entra directory role**. Severity is `critical` if the role is `isPrivileged`.
4. An **Azure RBAC** role listed in `rbac.dangerous_roles` on `/`, a management group or a subscription. Assignments at resource group or resource level are not flagged.

Exclusions are applied in this order: Microsoft first-party (`appOwnerOrganizationId`), allowlist, the identity running the script, and SPs that are already disabled. **Managed identities** are marked `report-only` because they cannot be disabled through Graph.

### App registrations (`--disable-app-registrations [APPS]`)
Without a list, the detection below decides; with a list, exactly those applications.

Applications whose `requiredResourceAccess` **requests** a dangerous permission are flagged, even if it has not been granted. Depending on the case:
- If there is already an item for its SP, it is marked `covered` and points to it.
- If it has a local SP, the SP is disabled.
- If it has no SP in the tenant, it is marked `report-only`. If it is also multi-tenant, the report notes that it may be in use in other tenants.
- If it has no active credentials, severity drops to `medium`.

**Secrets and certificates are never deleted.** A secret's value cannot be restored, so deleting it would break rollback. Disabling the SP already prevents it from getting tokens in this tenant.

## `report.json` format

```jsonc
{
  "schema": 2,
  "tool": {"name": "shutter", "version": "0.1.0"},
  "run": {"id": "uuid", "mode": "dry-run|execute|execute-refused|execute-aborted|rollback-*",
          "startedAt": "...", "finishedAt": "...", "tenantId": "...", "configSha256": "...",
          "operator": {"kind": "user|application", "id": "...", "upn": "..."},
          "status": "running|completed|refused|aborted", "selection": {"disable_guests": [], "...": null},
          "sourceRunId": "rollback only", "planRunId": "--from-plan only", "approval": {}},
  "preflight": {"ok": true, "checks": [{"name": "...", "ok": true, "detail": "...", "blocking": true}]},
  "summary": {"byCategory": {}, "byStatus": {}, "bySeverity": {}, "total": 0},
  "items": [{
    "key": "service-principal:<id>",
    "category": "conditional-access|user|revoke-sessions|group-members|tenant-setting|rg-lock|service-principal|app-registration|storage|keyvault|aks",
    "id": "...", "name": "...", "action": "disable-service-principal|disable-sftp|widen-to-all-external-tenants|report-only|...",
    "severity": "critical|high|medium", "reasons": ["..."],
    "permissions": [{"type": "application|delegated-all-users|directory-role|azure-rbac|...", "resource": "...", "value": "...", "scope": "..."}],
    "owners": [{"id": "...", "displayName": "...", "upn": "...", "type": "..."}],
    "details": {}, "before": {}, "after": {},
    "status": "planned|in-progress|applied|failed|skipped|skipped-allowlist|covered|report-only|reverted|drift|irreversible|not-applicable",
    "irreversible": false,
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
- **Synced users and groups** are only reported: change them in on-prem AD.
- **Session revocation** cannot be undone, and does not stop access tokens already issued (≈1 h) for apps without CAE.
- **Storage access keys and SAS tokens** are not rotated, because rotation is not reversible. Rotating them is the next manual step if SFTP was compromised.
- **Local SFTP user accounts** are not handled one by one: disabling SFTP closes the whole endpoint.
- **Not tested live.** All tests run against the simulated tenant in `tests/fake_tenant.py`.
