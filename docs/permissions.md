# Required permissions

The preflight checks only what the selected switches need. `--execute` will not start if anything is missing. The simplest operator is a **Global Administrator** (active in PIM) with **Contributor** on the subscriptions in scope; the tables list the least-privileged alternatives.

## Microsoft Graph

| Module (switch) | Permission (delegated scope or app role; any of) | **Active** Entra role (if a user; any of) |
|---|---|---|
| Inventory (always) | `Directory.Read.All` | any role with read access |
| Conditional Access (`--disable-guests`, `--disable-groups`) | `Policy.Read.All` + `Policy.ReadWrite.ConditionalAccess` | Global Admin, Conditional Access Admin, Security Admin |
| Group members (`--remove-group-members`, guest static group) | `GroupMember.ReadWrite.All`, `Group.ReadWrite.All` | Global Admin, Groups Admin, User Admin, Privileged Role Admin |
| Users (`--disable-users`) | `User.ReadWrite.All` | Global Admin, User Admin, Privileged Authentication Admin |
| Sessions (`--revoke-sessions`) | `User.RevokeSessions.All`, `User.ReadWrite.All` | Global Admin, User Admin, Privileged Authentication Admin |
| Tenant settings (`--disable-guest-invites`, `--disable-user-consent`) | `Policy.ReadWrite.Authorization` | Global Admin, Privileged Role Admin |
| Apps (`--disable-enterprise-apps`, `--disable-app-registrations`) | `Application.ReadWrite.All` | Global Admin, Cloud Application Admin, Application Admin |
| Last sign-in (optional) | `AuditLog.Read.All` | Reports Reader or Security Reader |

> **PIM:** the preflight only sees **active** roles (`/me/transitiveMemberOf`), not eligible ones.

> **Privileged targets:** disabling an admin user needs Privileged Authentication Admin (or Global Admin); changing members of a role-assignable group needs Privileged Role Admin (or Global Admin); disabling a service principal that holds privileged roles may need more than Cloud Application Admin. Such items show as `failed` with a 403 and must be handled manually.

> **To verify in the test tenant:** the exact role required by each Graph operation in this table. They are taken from Microsoft's documentation and have not been exercised against a real tenant yet.

### `az` CLI token

If the delegated `az` token does not include a scope above (very likely for `Policy.ReadWrite.ConditionalAccess` and `Policy.ReadWrite.Authorization`), there are two options:
- Run with a dedicated emergency app registration, using a certificate and admin consent for the permissions in the table:

```bash
az login --service-principal -u <appId> --certificate <pem> --tenant <tenant>
```

- Use a token from another client that does have the scopes. If Conditional Access blocks device code flow in your tenant, it must be an interactive browser login (see ROADMAP, "Authentication").

That emergency app must be in `allowlist.app_ids`. The script already excludes itself when running as an application.

## Azure (ARM)

| Module | RBAC action evaluated on every affected resource | Typical role |
|---|---|---|
| Inventory (Resource Graph) | `*/read` | Reader on the root management group |
| `--disable-storage` | `Microsoft.Storage/storageAccounts/write` | Storage Account Contributor or Contributor |
| `--disable-keyvault-public-access` | `Microsoft.KeyVault/vaults/write` | Key Vault Contributor or Contributor |
| `--disable-aks` (stop) | `Microsoft.ContainerService/managedClusters/stop/action` | Azure Kubernetes Service Contributor or Contributor |
| `--disable-aks --aks-mode restrict-api` | `Microsoft.ContainerService/managedClusters/write` | Azure Kubernetes Service Contributor or Contributor |
| `--lock-resource-groups` | `Microsoft.Authorization/locks/write` | Owner or User Access Administrator |

The preflight evaluates `Microsoft.Authorization/permissions` on **each** affected resource. It does not rely on the nominal role.

## Control plane (optional)

| Feature | Requirement |
|---|---|
| `[control]` lock, approvals, archive | **Storage Blob Data Contributor** on the control container |
| `[approval] approver_group_id` | Approvers must be members of that Entra group |
