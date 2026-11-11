# Runbook: emergency lockdown

**When to use it:** a confirmed or highly likely compromise with a risk of exfiltration or persistence through external users, SFTP or applications (consent phishing, an app with a leaked secret, a compromised partner...).

**Who decides:** the security lead or the incident commander. Record the decision in the incident ticket before step 4.

## 1. Prepare the identity (≈ 5 min)

1. Activate **Conditional Access Administrator** and **Cloud Application Administrator**, or **Global Administrator**, in PIM.
2. Activate **Contributor** or **Storage Account Contributor** on the subscriptions in PIM.
3. Log in:

```bash
az login --tenant <tenant-id>
```

## 2. Preflight

```bash
python3 -m persiana preflight
```

Everything must show ✔. Typical failures:
- A PIM role is not activated or has not propagated yet. Wait 1-2 minutes and run `az login` again.
- The `az` token is missing a Graph scope. See [permissions.md](permissions.md).

## 3. Dry-run and review (≈ 5-10 min)

```bash
python3 -m persiana run
```

Open `report.html` and review:
- The **Enterprise apps** tab: is there anything business-critical that must not go down, such as the payroll or backup integration? If it must keep working, add it to `allowlist.app_ids` in `persiana.toml`, commit, and run the dry-run again.
- **The CA policy exclusions**: the break-glass accounts must be listed.
- The **report-only** items (managed identities, apps without an SP): these are handled manually.

## 4. Execute

```bash
python3 -m persiana run --execute
```

The script asks for the phrase `LOCKDOWN <tenant[:8]>`. Execution order: CA policy, SFTP, enterprise apps, app registrations.

## 5. After execution

- [ ] Attach `report.html` and `report.json` to the incident ticket and store the JSON somewhere safe: it is the key to the rollback.
- [ ] Review items in `failed` status and resolve them manually.
- [ ] Review `report-only` items: remove managed identity role assignments where appropriate.
- [ ] Notify the owners listed in the report.
- [ ] Keep in mind that tokens already issued to service principals may remain valid for up to 1 h. See [design.md](design.md#limitations).

## 6. Rollback, full or partial

```bash
python3 -m persiana rollback <report.json>
```

```bash
python3 -m persiana rollback <report.json> --execute
```

- Items marked `drift` were changed manually after the lockdown. Review them, and use `--force` only if you really want to go back to the original state.
- For a partial rollback, edit a copy of the JSON and leave `"status": "applied"` only on the items you want to revert.
