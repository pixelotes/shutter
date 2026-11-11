"""Regenerate the Contoso sample reports by running persiana end-to-end against tests/fake_tenant.py.

    python3 examples/generate.py

No Azure call is made: persiana's HTTP client is swapped for an in-memory fake tenant.
"""
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import fake_tenant  # noqa: E402
from persiana import cli  # noqa: E402

OUT = ROOT / "examples"


def contoso_config() -> Path:
    cfg = (ROOT / "persiana.toml").read_text()
    cfg = re.sub(r'tenant_id = ".*"', f'tenant_id = "{fake_tenant.TENANT}"', cfg)
    cfg = re.sub(r'policy_id = ".*?"[^\n]*', f'policy_id = "{fake_tenant.CA_ID}"   # "EXT - Block Fabrikam guests"', cfg)
    cfg = cfg.replace("app_ids = []", f'app_ids = ["{fake_tenant.SENTINEL_PLAYBOOK_APP}"]  # Sentinel playbook')
    p = OUT / "persiana.contoso.toml"
    p.write_text(cfg)
    return p


def main() -> None:
    tenant = fake_tenant.FakeTenant()
    cli.Client = tenant.client
    cfg = str(contoso_config())
    phrase = f"LOCKDOWN {fake_tenant.TENANT[:8]}"
    for d in ("01-dry-run", "02-execute", "03-rollback-dry-run", "04-rollback-execute"):
        shutil.rmtree(OUT / d, ignore_errors=True)

    cli.main(["--config", cfg, "--out", str(OUT / "01-dry-run"), "run"])
    cli.main(["--config", cfg, "--out", str(OUT / "02-execute"), "run", "--execute", "--confirm", phrase])

    # During the incident an admin manually excludes a user from the CA policy → rollback must flag
    # drift and refuse to overwrite it (unless --force).
    tenant.s["ca"]["conditions"]["users"]["excludeUsers"].append(fake_tenant.gid(3))
    # ...and someone already re-enabled Terraform Deployer by hand → rollback skips it.
    tenant.s["sps"][fake_tenant.gid(202)]["accountEnabled"] = True
    src = str(OUT / "02-execute" / "report.json")
    cli.main(["--config", cfg, "--out", str(OUT / "03-rollback-dry-run"), "rollback", src])
    cli.main(["--config", cfg, "--out", str(OUT / "04-rollback-execute"), "rollback", src,
              "--execute", "--confirm", f"ROLLBACK {fake_tenant.TENANT[:8]}"])


if __name__ == "__main__":
    main()
