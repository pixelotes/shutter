"""Containment switches: selection, list resolution, every module's apply / rollback, exclusions."""
import copy
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

LOCK = ["--confirm", f"LOCKDOWN {ft.TENANT[:8]}"]
IRREV = ["--confirm-irreversible", f"IRREVERSIBLE {ft.TENANT[:8]}"]
RB = ["--execute", "--confirm", f"ROLLBACK {ft.TENANT[:8]}"]


class Switches(unittest.TestCase):
    def setUp(self):
        self.t = ft.FakeTenant()
        cli.Client = self.t.client
        self.tmp = Path(tempfile.mkdtemp())
        self.cfg = str(generate.contoso_config())
        self.n = 0

    def run_(self, *args, cfg=None):
        self.n += 1
        out = self.tmp / f"r{self.n}"
        code = cli.main(["--config", cfg or self.cfg, "--out", str(out), *args])
        p = out / "report.json"
        return code, (json.loads(p.read_text()) if p.exists() else None), p

    def execute(self, *switches, irreversible=False):
        return self.run_("run", *switches, "--execute", *LOCK, *(IRREV if irreversible else ["--confirm-irreversible", "no"]))

    def rollback(self, path):
        return self.run_("rollback", str(path), *RB)

    def items(self, rep, cat=None):
        return [i for i in rep["items"] if cat is None or i["category"] == cat]

    def snapshot(self):
        s = copy.deepcopy(self.t.s)
        s.pop("revoked")
        return json.dumps(s, sort_keys=True, default=str)

    # ------------------------------------------------------------------ selection
    def test_nothing_selected_is_an_error(self):
        code, rep, _ = self.run_("run")
        self.assertEqual(code, 2)
        self.assertIsNone(rep)

    def test_only_selected_module_runs(self):
        _, rep, _ = self.run_("run", "--disable-guests")
        self.assertEqual({i["category"] for i in rep["items"]}, {"conditional-access"})
        self.assertEqual(rep["run"]["selection"]["disable_guests"], [])

    def test_unknown_and_ambiguous_names_stop_the_run(self):
        self.assertEqual(self.run_("run", "--disable-storage", "nope")[0], 2)
        self.assertEqual(self.run_("run", "--lock-resource-groups", "rg-data")[0], 2)  # exists in two subscriptions
        self.assertEqual(self.run_("run", "--disable-users", "ghost@contoso.com")[0], 2)

    def test_list_from_file_and_commas(self):
        f = self.tmp / "users.txt"
        f.write_text("# compromised\ndiegos@contoso.com\n\n")
        _, rep, _ = self.run_("run", "--disable-users", f"@{f}", "--revoke-sessions", "diegos@contoso.com,leeg@contoso.com")
        self.assertEqual([i["name"] for i in self.items(rep, "user")], ["Diego Siciliani"])
        self.assertEqual(len(self.items(rep, "revoke-sessions")), 2)

    # ------------------------------------------------------------------ guests
    def test_guests_by_domain(self):
        before = self.snapshot()
        code, rep, p = self.execute("--disable-guests", "acme.com", "gmail.com")
        self.assertEqual(code, 0)
        users = self.t.s["ca"]["conditions"]["users"]
        self.assertEqual(users["includeGuestsOrExternalUsers"]["externalTenants"]["members"], [ft.ACME_TENANT])
        self.assertIn(ft.GUEST_GROUP, users["includeGroups"])
        self.assertEqual(self.t.s["groups_full"][ft.GUEST_GROUP]["members"], [ft.gid(10)])  # Sam @gmail.com
        self.rollback(p)
        self.assertEqual(before, self.snapshot())

    def test_domain_without_tenant_needs_static_group(self):
        cfg = Path(self.cfg).read_text().replace(f'static_group_id = "{ft.GUEST_GROUP}"', "")
        alt = self.tmp / "nogroup.toml"
        alt.write_text(cfg)
        self.assertEqual(self.run_("run", "--disable-guests", "gmail.com", cfg=str(alt))[0], 2)

    # ------------------------------------------------------------------ groups
    def test_disable_groups_uses_separate_block_policy(self):
        code, rep, p = self.execute("--disable-groups", "Contractors")
        pol = self.t.s["policies"][ft.CA_GROUPS_ID]
        self.assertEqual(pol["state"], "enabled")
        self.assertEqual(pol["conditions"]["users"]["includeGroups"], [ft.CONTRACTORS_GROUP])
        self.assertEqual(self.t.s["ca"]["state"], "enabled")  # guest policy untouched
        self.rollback(p)
        self.assertEqual(pol["state"], "disabled")
        self.assertEqual(pol["conditions"]["users"]["includeGroups"], [])

    def test_disable_groups_without_policy_refuses(self):
        cfg = Path(self.cfg).read_text().replace(f'block_policy_id = "{ft.CA_GROUPS_ID}"', "")
        alt = self.tmp / "nopolicy.toml"
        alt.write_text(cfg)
        self.assertEqual(self.run_("run", "--disable-groups", "Contractors", cfg=str(alt))[0], 2)

    def test_remove_members_keeps_break_glass_and_excluded(self):
        code, rep, p = self.execute("--remove-group-members", "PIM - Azure Owners", "AD - Finance", "--exclude", "leeg@contoso.com")
        self.assertEqual(sorted(self.t.s["groups_full"][ft.PRIV_GROUP]["members"]), [ft.gid(1), ft.gid(5)])
        synced = next(i for i in self.items(rep, "group-members") if i["name"] == "AD - Finance")
        self.assertEqual(synced["status"], "report-only")
        self.rollback(p)
        self.assertEqual(sorted(self.t.s["groups_full"][ft.PRIV_GROUP]["members"]), [ft.gid(1), ft.gid(5), ft.gid(7)])

    # ------------------------------------------------------------------ users
    def test_users_synced_and_break_glass_are_not_touched(self):
        code, rep, p = self.execute("--disable-users", "diegos@contoso.com", "jordan@contoso.com", "bg-admin01@contoso.onmicrosoft.com")
        st = {i["name"]: i["status"] for i in self.items(rep, "user")}
        self.assertEqual(st, {"Diego Siciliani": "applied", "Jordan (synced)": "report-only", "Break Glass 01": "skipped-allowlist"})
        self.assertFalse(self.t.s["users"][ft.gid(7)]["accountEnabled"])
        self.assertTrue(self.t.s["users"][ft.gid(1)]["accountEnabled"])

    def test_revoke_needs_second_confirmation_and_is_not_rolled_back(self):
        _, rep, _ = self.execute("--revoke-sessions", "diegos@contoso.com")
        self.assertEqual(self.t.s["revoked"], [])
        self.assertEqual(self.items(rep, "revoke-sessions")[0]["status"], "skipped")
        _, rep, p = self.execute("--revoke-sessions", "diegos@contoso.com", irreversible=True)
        self.assertEqual(self.t.s["revoked"], [ft.gid(7)])
        _, rb, _ = self.rollback(p)
        self.assertEqual(self.items(rb, "revoke-sessions")[0]["status"], "irreversible")

    # ------------------------------------------------------------------ tenant settings
    def test_tenant_settings_roundtrip(self):
        before = copy.deepcopy(self.t.s["authz"])
        _, _, p = self.execute("--disable-guest-invites", "--disable-user-consent")
        self.assertEqual(self.t.s["authz"]["allowInvitesFrom"], "none")
        self.assertEqual(self.t.s["authz"]["defaultUserRolePermissions"]["permissionGrantPoliciesAssigned"],
                         ["ManagePermissionGrantsForOwnedResource.contoso"])
        self.rollback(p)
        self.assertEqual(before, self.t.s["authz"])

    # ------------------------------------------------------------------ Azure resources
    def test_storage_modes(self):
        acct = next(iter(self.t.s["storage"]))
        self.execute("--disable-storage", "stcontososftpprod", "--storage-mode", "sftp")
        self.assertFalse(self.t.s["storage"][acct]["isSftpEnabled"])
        self.assertEqual(self.t.s["storage"][acct]["publicNetworkAccess"], "Enabled")
        self.execute("--disable-storage", "--storage-mode", "public")
        self.assertTrue(all(v["publicNetworkAccess"] == "Disabled" for v in self.t.s["storage"].values()))

    def test_keyvault_all_skips_already_closed(self):
        _, rep, _ = self.run_("run", "--disable-keyvault-public-access")
        self.assertEqual([i["name"] for i in self.items(rep, "keyvault")], ["kv-contoso-prod"])

    def test_aks_stop_and_restrict(self):
        _, _, p = self.execute("--disable-aks")
        self.assertEqual(self.t.s["aks"][ft.AKS_PROD]["powerState"], "Stopped")
        self.rollback(p)
        self.assertEqual(self.t.s["aks"][ft.AKS_PROD]["powerState"], "Running")
        _, _, p = self.execute("--disable-aks", "aks-contoso-prod", "--aks-mode", "restrict-api")
        self.assertEqual(self.t.s["aks"][ft.AKS_PROD]["authorizedIPRanges"], ["203.0.113.0/24"])
        self.rollback(p)
        self.assertEqual(self.t.s["aks"][ft.AKS_PROD]["authorizedIPRanges"], [])

    def test_resource_group_lock_roundtrip(self):
        _, _, p = self.execute("--lock-resource-groups", ft.RG_PROD)
        self.assertEqual(self.t.s["rgs"][ft.RG_PROD]["locks"], {"shutter-emergency": "CanNotDelete"})
        self.rollback(p)
        self.assertEqual(self.t.s["rgs"][ft.RG_PROD]["locks"], {})

    # ------------------------------------------------------------------ apps and exclusions
    def test_explicit_enterprise_app_list(self):
        _, rep, _ = self.run_("run", "--disable-enterprise-apps", "Contoso Reporting API", ft.SENTINEL_PLAYBOOK_APP)
        st = {i["name"]: i["status"] for i in self.items(rep, "service-principal")}
        self.assertEqual(st, {"Contoso Reporting API": "planned", "Sentinel-Playbook-Isolate-User": "skipped-allowlist"})

    def test_exclude_by_appid_and_name(self):
        _, rep, _ = self.run_("run", "--all", "--exclude", ft.gid(9200), "stcontosodevsftp")
        st = {i["name"] + "|" + i["category"]: i["status"] for i in rep["items"]}
        self.assertEqual(st["Contoso HR Sync|service-principal"], "skipped-allowlist")
        self.assertEqual(st["stcontosodevsftp|storage"], "skipped-allowlist")

    def test_control_storage_account_is_never_closed(self):
        cfg = Path(self.cfg).read_text() + '\n[control]\nstorage_account = "stcontososftpprod"\n'
        alt = self.tmp / "ctl.toml"
        alt.write_text(cfg)
        _, rep, _ = self.run_("run", "--disable-storage", cfg=str(alt))
        it = next(i for i in self.items(rep, "storage") if i["name"] == "stcontososftpprod")
        self.assertEqual(it["status"], "skipped-allowlist")

    # ------------------------------------------------------------------ whole-run guarantees
    def test_full_run_rollback_restores_everything(self):
        self.t.s["fail_patch"] = set()
        before = self.snapshot()
        code, rep, p = self.execute(*generate.FULL, irreversible=True)
        self.assertEqual(code, 0)
        self.assertNotEqual(before, self.snapshot())
        code, rb, _ = self.rollback(p)
        self.assertEqual(code, 0)
        self.assertEqual(before, self.snapshot())

    def test_full_run_twice_changes_nothing_the_second_time(self):
        self.execute(*generate.FULL)
        _, rep, _ = self.execute(*generate.FULL)
        self.assertEqual([i["name"] for i in rep["items"] if i["status"] == "applied"], [])


if __name__ == "__main__":
    unittest.main()
