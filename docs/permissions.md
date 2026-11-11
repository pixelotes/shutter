# Required permissions

The preflight checks everything on this page. `--execute` will not start if anything is missing.

## Microsoft Graph

| Needed for | Permission (delegated scope or app role) | **Active** Entra role (if a user) |
|---|---|---|
| Inventory | `Directory.Read.All` | any role with read access |
| CA policy | `Policy.Read.All` + `Policy.ReadWrite.ConditionalAccess` | Conditional Access Admin, Security Admin or Global Admin |
| Service principals | `Application.ReadWrite.All` | Cloud Application Admin, Application Admin or Global Admin |
| Last sign-in (optional) | `AuditLog.Read.All` | Reports Reader or Security Reader |

> **PIM:** the preflight only sees **active** roles (`/me/transitiveMemberOf`), not eligible ones.

> **Service principals with privileged roles:** in some cases, disabling them requires more than Cloud Application Administrator, for example Privileged Role Administrator. If that happens, the item shows as `failed` with a 403 and must be handled manually.

### `az` CLI token

If the delegated `az` token does not include `Policy.ReadWrite.ConditionalAccess`, there are two options:
- Run with a dedicated emergency app registration, using a certificate and admin consent for the permissions in the table:

```bash
az login --service-principal -u <appId> --certificate <pem> --tenant <tenant>
```

- Use a Graph PowerShell token or another client that does have the scope.

That emergency app must be in `allowlist.app_ids`. The script already excludes itself when running as an application.

## Azure (ARM)

| Needed for | RBAC action | Typical role |
|---|---|---|
| Inventory (Resource Graph) | `*/read` | Reader on the root management group |
| Shut down SFTP | `Microsoft.Storage/storageAccounts/write` | Storage Account Contributor or Contributor |

The preflight evaluates `Microsoft.Authorization/permissions` on **each** affected storage account. It does not rely on the nominal role.
