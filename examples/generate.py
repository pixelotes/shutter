"""Regenerate the Contoso sample reports by running shutter end-to-end against tests/fake_tenant.py.

    python3 examples/generate.py

No Azure call is made: shutter's HTTP client is swapped for an in-memory fake tenant.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import fake_tenant  # noqa: E402
from shutter import cli  # noqa: E402

OUT = ROOT / "examples"

# A "full" emergency: every default module plus targeted actions on a compromised contractor account.
FULL = [
    "--all",
    "--disable-groups", "Contractors",
    "--remove-group-members", "PIM - Azure Owners",
    "--disable-users", "diegos@contoso.com", "jordan@contoso.com",
    "--revoke-sessions", "diegos@contoso.com",
    "--disable-guest-invites", "--disable-user-consent",
    "--disable-keyvault-public-access",
    "--disable-aks",
    "--lock-resource-groups", fake_tenant.RG_PROD,
]


def contoso_config() -> Path:
    cfg = (ROOT / "shutter.example.toml").read_text()
    cfg = re.sub(r'tenant_id = ".*"', f'tenant_id = "{fake_tenant.TENANT}"', cfg)
    cfg = re.sub(r'^policy_id = ".*?"[^\n]*', f'policy_id = "{fake_tenant.CA_ID}"   # "EXT - Block Fabrikam guests"', cfg, flags=re.M)
    cfg = cfg.replace('# static_group_id = "<group-object-id>"', f'static_group_id = "{fake_tenant.GUEST_GROUP}"')
    cfg = cfg.replace('# block_policy_id = "<policy-id>"', f'block_policy_id = "{fake_tenant.CA_GROUPS_ID}"   # "EMERGENCY - Block listed groups"')
    cfg = cfg.replace("authorized_ip_ranges = []", 'authorized_ip_ranges = ["203.0.113.0/24"]')
    cfg = cfg.replace("app_ids = []", f'app_ids = ["{fake_tenant.SENTINEL_PLAYBOOK_APP}"]  # Sentinel playbook')
    cfg = re.sub(r'user_ids = \[".*?"\]', f'user_ids = ["{fake_tenant.gid(1)}", "{fake_tenant.gid(2)}"]', cfg)
    p = OUT / "shutter.contoso.toml"
    p.write_text(cfg)
    return p


def main() -> None:
    tenant = fake_tenant.FakeTenant()
    cli.Client = tenant.client
    cfg = str(contoso_config())
    phrase = f"LOCKDOWN {fake_tenant.TENANT[:8]}"
    for d in ("01-dry-run", "02-execute", "03-rollback-dry-run", "04-rollback-execute", "05-guests-by-domain-dry-run"):
        shutil.rmtree(OUT / d, ignore_errors=True)

    cli.main(["--config", cfg, "--out", str(OUT / "01-dry-run"), "run", *FULL])
    cli.main(["--config", cfg, "--out", str(OUT / "02-execute"), "run", *FULL, "--execute", "--confirm", phrase,
              "--confirm-irreversible", f"IRREVERSIBLE {fake_tenant.TENANT[:8]}"])

    # During the incident an admin manually excludes a user from the CA policy → rollback must flag
    # drift and refuse to overwrite it (unless --force).
    tenant.s["ca"]["conditions"]["users"]["excludeUsers"].append(fake_tenant.gid(3))
    # ...and someone already re-enabled Terraform Deployer by hand → rollback skips it.
    tenant.s["sps"][fake_tenant.gid(202)]["accountEnabled"] = True
    src = str(OUT / "02-execute" / "report.json")
    cli.main(["--config", cfg, "--out", str(OUT / "03-rollback-dry-run"), "rollback", src])
    cli.main(["--config", cfg, "--out", str(OUT / "04-rollback-execute"), "rollback", src,
              "--execute", "--confirm", f"ROLLBACK {fake_tenant.TENANT[:8]}"])

    # Targeted guest block: two Entra organisations plus domains without a tenant (static group).
    cli.main(["--config", cfg, "--out", str(OUT / "05-guests-by-domain-dry-run"), "run",
              "--disable-guests", "acme.com", "fabrikam.com", "acme-partners.io", "gmail.com"])


if __name__ == "__main__":
    main()
