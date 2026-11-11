# Roadmap

Rough priority order inside each section. Nothing here is committed to a date.

## Done

- ✅ **Containment switches.** Guests (all or by domain), groups (CA block or member removal), users, sessions (irreversible, second confirmation), guest invitations, user consent, enterprise apps, app registrations, storage (SFTP / public access), Key Vault, AKS (stop / restrict API), resource group locks, `--exclude`, `--all`; lists by ID, name, commas or `@file`.
- ✅ **Incremental journal.** `report.json` is written atomically before and after every change during `--execute`; an interrupted run can still be rolled back (`in-progress` items are resolved by comparing live state).
- ✅ **Resume.** `run --resume <report.json>` finishes an interrupted run, keeping ownership of changes that landed before the crash.
- ✅ **Run lock.** Blob lease shared by all operators (`[control]`), local lock file otherwise; `shutter unlock` breaks a stale lock.
- ✅ **Two-person rule (optional).** `shutter approve <dry-run report.json>` by a different identity (optionally restricted to an Entra group, with TTL); `run --execute --from-plan` only executes an approved, unmodified plan.
- ✅ **Notifications.** Teams (Workflows webhook), Slack, email (SMTP, with the HTML report attached) and generic webhook. Never block a run.
- ✅ **Tamper evidence.** `report.sha256` next to every report; execute and rollback reports are archived to the `[control]` container (use an immutability policy).
- ✅ **Break-glass verification.** Preflight refuses unless every account in `[break_glass]` is excluded from the CA policy.

Periodic dry-runs are intentionally not a feature: schedule `shutter run` (dry-run) with cron or a pipeline if you want one.

## 1. Profiles + switches

Switches are implemented (see the README). Remaining:
- `shutter run --profile <name>`: everything the profile enables; switches then **narrow** it and can never widen it beyond its exceptions.
- `--all` without a profile stays as today's oneshot.

## 2. Profiles

A profile stores **decisions, not infrastructure**: the tenant, break-glass accounts, exceptions (users, groups, apps, resources), which modules are enabled and with which conditions. Everything else is discovered live at run time.

```toml
# profiles/contoso-prod.toml
name = "contoso-prod"
tenant_id = "..."

[break_glass]
user_ids = ["...", "..."]

[exceptions]
group_ids = ["<soc-team>"]                   # never blocked, never emptied
app_ids   = ["<sentinel-playbook-appid>", "<backup-appid>"]
resource_ids = ["/subscriptions/.../resourceGroups/rg-sentinel"]

[guests]
enabled = true
policy_id = "<pre-created emergency CA policy, state=disabled or report-only>"
domains = []                                  # empty = all guests; or ["acme.com", "fabrikam.com"]
static_group_id = "<group the policy includes, filled at run time for non-Entra guests>"

[storage]
enabled = true
mode = "both"
subscriptions = ["*"]

[aks]
enabled = false
mode = "restrict-api"
authorized_ip_ranges = ["203.0.113.0/24"]
```

Design decisions:
- **Emergency CA policies are created in peacetime** (by the wizard), disabled or in report-only, and only switched to `enabled` during an incident. Faster, reviewed in advance, fewer write permissions needed, and report-only mode shows in sign-in logs who *would* be blocked: a free rehearsal.
- **Guests by domain:** Conditional Access targets external users by tenant, not by email domain. Domains of Entra organisations resolve to tenant IDs (`findTenantInformationByDomainName`); guests without a tenant go into a **static** group filled at run time. Dynamic groups are not used: processing can take minutes to hours.
- **Profile check at run time:** every ID must still exist; a deleted-and-recreated exception group is no longer the same object.
- The profile hash goes into every report (as `shutter.toml` does today).
- `shutter.toml` keeps global defaults (dangerous permissions, roles); profiles override scope and exceptions.

## 3. Profile wizard

`shutter profile init` / `shutter profile edit`: an interactive TUI that explores the tenant **read-only** and lets you tick what to include or exclude (subscriptions → resource groups → resource types, apps flagged by detection, exception groups and users). It writes the profile TOML, shows a diff before saving, and creates the emergency CA policies in disabled / report-only state.

Run it in peacetime, review the result in a merge request. Nobody should be making these decisions during an incident.

## 4. Authentication for the emergency operator

The intended operator is an Entra Global Administrator plus admin on the Azure resources in scope. Two blockers to solve:
- The Azure CLI token likely lacks `Policy.ReadWrite.ConditionalAccess`.
- Device code flow is often blocked by Conditional Access.

Plan: a dedicated **public client app registration** with the required delegated scopes pre-consented, interactive browser login (MSAL-style auth code + PKCE, stdlib only), and the app itself in the allowlist.

## 5. Idempotency guarantees

Covered by tests today: execute twice is a no-op; rollback of run B does not undo run A; crash → rollback; crash → resume keeps ownership. Still to do:
- Rollback twice, and execute → partial manual revert → execute again, as explicit tests for every new module.
- Never write fields we do not own: the CA PATCH still sends the whole `conditions`; switch to the minimum diff where Graph allows it.

## 6. Testing

There is no official emulator for Graph or ARM (Azurite only covers the storage *data* plane), so a layered approach:

1. **Unit / e2e against the in-memory fake** (`tests/fake_tenant.py`): runs on every commit.
2. **Local mock HTTP server**: put the fake behind `http.server` on localhost and point the client at it (`--graph-url` / `--arm-url`). Exercises the real HTTP client, paging and retries; add fault injection (429 with `Retry-After`, 5xx, timeouts).
3. **Record / replay**: record a real dry-run, sanitize it, replay it in tests. A contract test that fails when Microsoft changes a response shape.
4. **Test tenant**: dedicated Entra tenant + Azure subscription seeded with guests, SFTP storage, risky apps and an AKS cluster. Full `execute` → `rollback` cycle, on demand or nightly.

## 7. Operations

- **Run from a pipeline**: a CI/CD job with a protected emergency identity and manual trigger, so it does not depend on someone's laptop.
- **Packaging**: installable with `pipx`, versioned releases, runnable from Azure Cloud Shell as a fallback.
- **Sentinel integration**: create a Sentinel incident (or comment) when `--execute` runs.
