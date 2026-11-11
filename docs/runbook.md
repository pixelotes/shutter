# Runbook: emergency containment with SHUTTER

**When to use it:** a confirmed or highly likely compromise with a risk of exfiltration or persistence through external users, SFTP or applications (consent phishing, an app with a leaked secret, a compromised partner...).

**Who decides:** the security lead or the incident commander. Record the decision in the incident ticket before step 4.

## 1. Prepare the identity (≈ 5 min)

1. Activate **Conditional Access Administrator** and **Cloud Application Administrator**, or **Global Administrator**, in PIM.
2. Activate **Contributor** or **Storage Account Contributor** on the subscriptions in PIM.
3. Log in:

```bash
az login --tenant <tenant-id>
```

## 2. Decide what to contain

Pick the switches that match the incident (full list in the [README](../README.md#what-it-can-contain)). Typical cases:

| Situation | Switches |
|---|---|
| Compromised partner / guests | `--disable-guests [domains] --disable-guest-invites` |
| Consent phishing / malicious app | `--disable-enterprise-apps <app> --disable-user-consent` |
| Compromised internal account | `--disable-users <upn> --revoke-sessions <upn>` |
| Compromised group of accounts (contractors, a team) | `--disable-groups <group>` |
| Data exfiltration via storage | `--disable-storage [accounts]` (`--storage-mode sftp` to keep public endpoints) |
| Possible destruction / ransomware | `--lock-resource-groups <rgs> --disable-keyvault-public-access` |
| Compromised Kubernetes workload | `--disable-aks <cluster>` |
| Unknown scope, worst case | `--all` plus whatever applies above |

Use `--exclude` for anything that must keep working. Use the same switches in every step below.

## 3. Preflight

```bash
python3 -m shutter preflight <switches>
```

Everything must show ✔. Typical failures:
- A PIM role is not activated or has not propagated yet. Wait 1-2 minutes and run `az login` again.
- The `az` token is missing a Graph scope. See [permissions.md](permissions.md).

## 4. Dry-run and review (≈ 5-10 min)

```bash
python3 -m shutter run <switches>
```

Open `report.html` and review:
- The **Enterprise apps** tab: is there anything business-critical that must not go down, such as the payroll or backup integration? If it must keep working, add it to `allowlist.app_ids` in `shutter.toml`, commit, and run the dry-run again.
- **The CA policy exclusions**: the break-glass accounts must be listed.
- The **report-only** items (managed identities, apps without an SP, synced users and groups): these are handled manually.
- **Storage and Key Vault**: disabling public access cuts off anything not using a private endpoint. Exclude what must stay reachable.
- Items marked **IRREVERSIBLE** (session revocation).

## 5. Execute

```bash
python3 -m shutter run <switches> --execute
```

The script asks for `LOCKDOWN <tenant[:8]>`, and for `IRREVERSIBLE <tenant[:8]>` if session revocations are planned (if you do not confirm, those are skipped and the rest runs).

**If two-person approval is enabled** (`[approval] required = true`), a second operator reviews the dry-run report and approves it:

```bash
python3 -m shutter approve reports/<date>-dry-run/report.json
```

Then the first operator executes exactly that plan:

```bash
python3 -m shutter run --execute --from-plan reports/<date>-dry-run/report.json
```

**If the run is interrupted** (crash, network, Ctrl-C), the report on disk is still valid. Either finish it:

```bash
python3 -m shutter run --resume reports/<date>-execute/report.json
```

or roll back what was applied (step 7). If the shared lock was left held and you are sure no other run is active:

```bash
python3 -m shutter unlock
```

## 6. After execution

- [ ] Attach `report.html` and `report.json` to the incident ticket and store the JSON somewhere safe: it is the key to the rollback. With `[control]` configured it is also archived automatically; `report.sha256` lets you verify it was not altered.
- [ ] Review items in `failed` status and resolve them manually.
- [ ] Review `report-only` items: remove managed identity role assignments where appropriate.
- [ ] Notify the owners listed in the report.
- [ ] Keep in mind that tokens already issued to service principals may remain valid for up to 1 h. See [design.md](design.md#limitations).

## 7. Rollback, full or partial

```bash
python3 -m shutter rollback <report.json>
```

```bash
python3 -m shutter rollback <report.json> --execute
```

- Items marked `drift` were changed manually after the lockdown. Review them, and use `--force` only if you really want to go back to the original state.
- For a partial rollback, edit a copy of the JSON and leave `"status": "applied"` only on the items you want to revert.
