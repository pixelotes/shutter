"""End-to-end tests against the in-memory Contoso tenant. No Azure calls."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(ROOT / "examples")]

import fake_tenant as ft  # noqa: E402
import generate  # noqa: E402
from shutter import cli  # noqa: E402


class E2E(unittest.TestCase):
    def setUp(self):
        self.t = ft.FakeTenant()
        cli.Client = self.t.client
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = str(generate.contoso_config())
        self.phrase = f"LOCKDOWN {ft.TENANT[:8]}"

    def run_cli(self, name, *args):
        out = self.tmp / name
        code = cli.main(["--config", self.cfg, "--out", str(out), *args])
        return code, json.loads((out / "report.json").read_text())

    def by_name(self, rep):
        return {i["name"] + "|" + i["category"]: i for i in rep["items"]}

    def test_dry_run_changes_nothing(self):
        before = json.dumps(self.t.s, sort_keys=True, default=str)
        code, rep = self.run_cli("dry", "run", "--all")
        self.assertEqual(code, 0)
        self.assertEqual(before, json.dumps(self.t.s, sort_keys=True, default=str))
        self.assertTrue(all(i["status"] != "applied" for i in rep["items"]))

    def test_allowlist_and_classification(self):
        _, rep = self.run_cli("dry", "run", "--all")
        i = self.by_name(rep)
        self.assertEqual(i["Sentinel-Playbook-Isolate-User|service-principal"]["status"], "skipped-allowlist")
        self.assertEqual(i["Microsoft Intune PowerShell|service-principal"]["status"], "skipped-allowlist")
        self.assertEqual(i["mi-automation-prod|service-principal"]["status"], "report-only")
        self.assertEqual(i["Contoso HR Sync|app-registration"]["status"], "covered")
        self.assertEqual(i["Old Migration Script|app-registration"]["status"], "report-only")
        self.assertEqual(i["Terraform Deployer|service-principal"]["severity"], "critical")
        self.assertNotIn("Contoso Reporting API|service-principal", i)  # RG-scoped RBAC is not flagged

    def test_wrong_confirmation_aborts(self):
        _, rep = self.run_cli("x", "run", "--all", "--execute", "--confirm", "nope")
        self.assertEqual(rep["run"]["mode"], "execute-aborted")
        self.assertTrue(self.t.s["sps"][ft.gid(200)]["accountEnabled"])

    def test_preflight_refuses_without_roles(self):
        ft.OPERATOR_SAVED = dict(ft.OPERATOR)
        try:
            ft.OPERATOR["scp"] = "Directory.Read.All"
            code, rep = self.run_cli("x", "run", "--all", "--execute", "--confirm", self.phrase)
        finally:
            ft.OPERATOR.update(ft.OPERATOR_SAVED)
        self.assertEqual(code, 2)
        self.assertEqual(rep["run"]["mode"], "execute-refused")
        self.assertTrue(self.t.s["storage"][next(iter(self.t.s["storage"]))]["isSftpEnabled"])

    def test_execute_then_rollback_restores_everything(self):
        original_ca = json.dumps(self.t.s["ca"], sort_keys=True)
        code, rep = self.run_cli("exec", "run", "--all", "--execute", "--confirm", self.phrase)
        self.assertEqual(code, 1)  # Helpdesk Bot fails with 403
        self.assertEqual(self.t.s["ca"]["conditions"]["users"]["includeGuestsOrExternalUsers"]["externalTenants"]["membershipKind"], "all")
        self.assertFalse(any(v["isSftpEnabled"] for v in self.t.s["storage"].values()))
        self.assertFalse(self.t.s["sps"][ft.gid(200)]["accountEnabled"])
        self.assertTrue(self.t.s["sps"][ft.gid(204)]["accountEnabled"])  # allowlisted
        code, rb = self.run_cli("rb", "rollback", str(self.tmp / "exec" / "report.json"),
                                "--execute", "--confirm", f"ROLLBACK {ft.TENANT[:8]}")
        self.assertEqual(code, 0)
        self.assertEqual(original_ca, json.dumps(self.t.s["ca"], sort_keys=True))
        self.assertTrue(all(v["isSftpEnabled"] for v in self.t.s["storage"].values()))
        self.assertTrue(self.t.s["sps"][ft.gid(200)]["accountEnabled"])

    def test_rollback_detects_drift(self):
        self.run_cli("exec", "run", "--all", "--execute", "--confirm", self.phrase)
        self.t.s["ca"]["conditions"]["users"]["excludeUsers"].append(ft.gid(3))
        _, rb = self.run_cli("rb", "rollback", str(self.tmp / "exec" / "report.json"),
                             "--execute", "--confirm", f"ROLLBACK {ft.TENANT[:8]}")
        ca = next(i for i in rb["items"] if i["category"] == "conditional-access")
        self.assertEqual(ca["status"], "drift")
        self.assertEqual(self.t.s["ca"]["state"], "enabled")

    def test_rollback_refuses_dry_run_report(self):
        self.run_cli("dry", "run", "--all")
        code = cli.main(["--config", self.cfg, "rollback", str(self.tmp / "dry" / "report.json")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
