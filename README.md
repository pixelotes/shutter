# SHUTTER — Azure Emergency Containment & Recovery 🚨

An emergency response toolkit for Microsoft Azure and Entra ID environments, designed to rapidly contain security exposure while preserving auditability and recovery capabilities.

You choose what to contain with switches; everything is dry-run until you add `--execute`, and everything except session revocation can be rolled back from the run's JSON report.

## What it can contain

`[LIST]` = optional: omitted means **everything in scope**. `(LIST)` = mandatory.

| Switch | Action | Reversible |
|---|---|---|
| `--disable-guests [DOMAINS]` | Enables the guest CA policy for all external tenants, or only for these domains (Entra tenants by ID; other domains via a static group) | ✅ |
| `--disable-groups (GROUPS)` | Adds the groups to a pre-created emergency CA block policy and enables it | ✅ |
| `--remove-group-members (GROUPS)` | Removes all members (break-glass and `--exclude` kept) | ✅ restores the member list |
| `--disable-users (USERS)` | `accountEnabled = false` | ✅ |
| `--revoke-sessions (USERS)` | Revokes refresh tokens and sessions | ❌ second confirmation |
| `--disable-guest-invites` | Tenant setting: nobody can invite guests | ✅ |
| `--disable-user-consent` | Tenant setting: users cannot consent to apps | ✅ |
| `--disable-enterprise-apps [APPS]` | Disables service principals: those with tenant-wide permissions, or these | ✅ |
| `--disable-app-registrations [APPS]` | Disables the local SP of app registrations requesting tenant-wide permissions, or these | ✅ |
| `--disable-storage [ACCOUNTS]` | SFTP off and/or public network access off (`--storage-mode sftp\|public\|both`) | ✅ |
| `--disable-keyvault-public-access [VAULTS]` | Public network access off | ✅ |
| `--disable-aks [CLUSTERS]` | Stops clusters, or restricts the API server to the SOC ranges (`--aks-mode stop\|restrict-api`) | ✅ |
| `--lock-resource-groups (RGS)` | `CanNotDelete` locks against destruction | ✅ |
| `--exclude (IDS)` | Never touch these (IDs, UPNs, appIds, names, resource IDs) | |
| `--all` | Guests + storage + enterprise apps + app registrations (all defaults) | |

Lists take object IDs (preferred), names, comma-separated values or `@file.txt` (one per line). Unknown or ambiguous names stop the run. Running with no switch at all is an error: there is no implicit "disable everything".

"Tenant-wide" permissions for apps: dangerous application permissions on Graph, Exchange or SharePoint; delegated consent for all users; Entra directory roles; Azure RBAC Owner, Contributor or UAA on a subscription, management group or `/`. The exact list is in [`shutter.example.toml`](shutter.example.toml).

## Safety guarantees

- **Dry-run by default.** Without `--execute`, it only reads.
- **Mandatory preflight.** Permissions, active PIM roles and effective Azure RBAC are checked for the selected modules only; `--execute` refuses to run if anything is missing.
- **Typed confirmation.** `LOCKDOWN <tenant[:8]>`, plus `IRREVERSIBLE <tenant[:8]>` for actions that cannot be rolled back.
- **Allowlist.** Never touches Microsoft first-party apps, the identity running the script, allowlisted apps and resources, break-glass accounts, or the SHUTTER control storage account.
- **Nothing destructive.** It does not delete secrets, apps, users, groups or role assignments.
- **Rollback with drift detection.** It will not overwrite manual changes made after the lockdown unless you pass `--force`.
- **Crash-safe.** The report is journaled during execution; an interrupted run can be resumed (`--resume`) or rolled back.
- **Idempotent.** Running the same lockdown twice changes nothing the second time; rolling back a later run does not undo an earlier one.
- **One run at a time.** A per-tenant lock (shared blob lease, or local file) prevents concurrent executions.
- **Optional two-person rule.** A second operator approves the dry-run plan (`shutter approve`); only that exact plan can be executed.
- **Notifications.** Teams, Slack, email and webhook on start, end, refusal and rollback.
- **Break-glass check.** Every CA policy the run enables must exclude every configured break-glass account.

## Usage

Requirements: Python ≥ 3.11 (stdlib only) and `az login` with the roles **active** in PIM. See [docs/permissions.md](docs/permissions.md).

> **Azure public cloud only.** The Graph, ARM and Storage endpoints are fixed to the global cloud (`graph.microsoft.com`, `management.azure.com`, `*.blob.core.windows.net`). Sovereign clouds (Azure Government, Azure China) are not supported.

Create your configuration from the template (`shutter.toml` is git-ignored) and fill in your tenant ID, Conditional Access policy IDs and break-glass accounts:

```bash
cp shutter.example.toml shutter.toml
```

Plan a lockdown of guests and all storage (dry-run, writes `reports/<date>-dry-run/`):

```bash
python3 -m shutter run --disable-guests --disable-storage
```

Contain a compromised contractor account:

```bash
python3 -m shutter run --disable-users pat@contoso.com --revoke-sessions pat@contoso.com --disable-groups Contractors --execute
```

Block only guests from two partner domains:

```bash
python3 -m shutter run --disable-guests acme.com fabrikam.com --execute
```

The original one-shot behaviour:

```bash
python3 -m shutter run --all --execute
```

Check permissions for a selection without discovering or changing anything else:

```bash
python3 -m shutter preflight --all
```

Simulate the rollback, then revert:

```bash
python3 -m shutter rollback reports/<date>-execute/report.json
```

```bash
python3 -m shutter rollback reports/<date>-execute/report.json --execute
```

Other options and commands:
- `--out <dir>`: change the report directory.
- `--confirm "<phrase>"` / `--confirm-irreversible "<phrase>"`: non-interactive confirmation.
- `--from-plan <report.json>`: execute exactly the planned items of a dry-run (required when approval is on).
- `--resume <report.json>`: finish an interrupted execution.
- `shutter approve <dry-run report.json>`: second operator approval.
- `shutter unlock`: break a stale lock.

Configuration sections in `shutter.toml` (see [`shutter.example.toml`](shutter.example.toml)): `[conditional_access]` (guest policy, static group), `[groups]` (block policy), `[aks]` (SOC IP ranges), `[allowlist]`, `[break_glass]`, `[control]`, `[approval]` and `[[notify]]`. See the commented examples in the file and [docs/design.md](docs/design.md).

Each run produces:
- **`report.json`**: the source of truth. It stores the `before`/`after` state of every object and is the input for rollback. **Keep it safe**: without it there is no automatic rollback.
- **`report.html`**: a self-contained, human-readable report that opens offline and can be attached to the ticket. It shows what was blocked and why, with permissions, owners, credentials, last sign-in and the before/after state.
- **`report.sha256`**: hashes of both files, to prove they were not altered.

## Examples

[`examples/`](examples/) contains sample reports from a fictitious tenant (**Contoso**), generated by running the real code against a simulated tenant:

| Report | Scenario |
|--------|----------|
| [01-dry-run](examples/01-dry-run/report.html) | Plan of a full lockdown (`--all` plus groups, users, sessions, tenant settings, Key Vault, AKS, locks) |
| [02-execute](examples/02-execute/report.html) | That lockdown executed; one SP fails with 403, a synced user is report-only |
| [03-rollback-dry-run](examples/03-rollback-dry-run/report.html) | Rollback plan with drift on the guest CA policy |
| [04-rollback-execute](examples/04-rollback-execute/report.html) | Rollback; the drifted policy is not overwritten, session revocation is irreversible |
| [05-guests-by-domain-dry-run](examples/05-guests-by-domain-dry-run/report.html) | Guests blocked by domain: two Entra tenants plus two domains via the static group |

To regenerate them (no Azure calls):

```bash
python3 examples/generate.py
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Documentation

- [docs/runbook.md](docs/runbook.md): step-by-step emergency procedure.
- [docs/design.md](docs/design.md): detection criteria, modules, execution control, JSON format and limitations.
- [docs/permissions.md](docs/permissions.md): required permissions and roles per module.
- [docs/ROADMAP.md](docs/ROADMAP.md): planned features and known gaps.

> ⚠️ **Status:** never run against a real tenant. Pending validation in a test tenant.

## License

[MIT](LICENSE)
