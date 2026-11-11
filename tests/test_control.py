"""Journal / resume, run lock, two-person approval, notifications, break-glass and report hashes."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests"), str(ROOT / "examples")]

import fake_tenant as ft  # noqa: E402
import generate  # noqa: E402
from shutter import cli, control, notify  # noqa: E402

LOCK = f"LOCKDOWN {ft.TENANT[:8]}"
ROLLBACK = f"ROLLBACK {ft.TENANT[:8]}"
APPROVE = f"APPROVE {ft.TENANT[:8]}"
APPROVER = {"oid": ft.gid(5), "upn": "leeg@contoso.com"}
APPROVER_GROUP = ft.gid(8000)


class Base(unittest.TestCase):
    extra_cfg = ""

    def setUp(self):
        self.t = ft.FakeTenant()
        self.t.s["groups"] = {APPROVER_GROUP: [ft.gid(5)]}
        cli.Client = self.t.client
        ft.FakeBlobStore.reset()
        control.STORE_FACTORY = ft.FakeBlobStore
        self.sent = []
        self._senders = dict(notify.SENDERS)
        notify.SENDERS["teams"] = lambda ch, s, d: self.sent.append(s["event"])
        self.tmp = Path(tempfile.mkdtemp())
        base = generate.contoso_config().read_text()
        cfg = base + "\n[control]\nstorage_account = \"stfake\"\n" + self.extra_cfg + \
            '\n[[notify]]\ntype = "teams"\nurl_env = "X"\nevents = ["execute-start", "execute-end", "execute-refused", "rollback-start", "rollback-end"]\n'
        cfg = cfg.replace("required = false", "required = true" if self.approval else "required = false")
        cfg = cfg.replace("# approver_group_id", f'approver_group_id = "{APPROVER_GROUP}"\n# x')
        self.cfg = self.tmp / "shutter.toml"
        self.cfg.write_text(cfg)
        self._op = dict(ft.OPERATOR)

    approval = False

    def tearDown(self):
        ft.OPERATOR.clear()
        ft.OPERATOR.update(self._op)
        notify.SENDERS.clear()
        notify.SENDERS.update(self._senders)

    def cli(self, out, *args):
        return cli.main(["--config", str(self.cfg), "--out", str(self.tmp / out), *args])

    def rep(self, out):
        return json.loads((self.tmp / out / "report.json").read_text())

    def as_approver(self):
        ft.OPERATOR.update(APPROVER)


class JournalResume(Base):
    def test_crash_leaves_revertible_journal(self):
        self.t.s["crash_after_patch"] = ft.gid(200)  # Contoso HR Sync
        with self.assertRaises(KeyboardInterrupt):
            self.cli("exec", "run", "--all", "--execute", "--confirm", LOCK)
        j = self.rep("exec")
        self.assertEqual(j["run"]["status"], "running")
        st = {i["name"]: i["status"] for i in j["items"] if i["category"] == "service-principal"}
        self.assertEqual(st["Contoso HR Sync"], "in-progress")
        self.assertFalse(self.t.s["sps"][ft.gid(200)]["accountEnabled"])  # write landed
        ft.FakeBlobStore.reset()  # crashed run never released the lock (equivalent to `shutter unlock`)
        self.assertEqual(self.cli("rb", "rollback", str(self.tmp / "exec" / "report.json"), "--execute", "--confirm", ROLLBACK), 0)
        self.assertTrue(self.t.s["sps"][ft.gid(200)]["accountEnabled"])
        self.assertTrue(self.t.s["storage"][next(iter(self.t.s["storage"]))]["isSftpEnabled"])

    def test_resume_finishes_and_keeps_ownership(self):
        self.t.s["crash_after_patch"] = ft.gid(200)
        with self.assertRaises(KeyboardInterrupt):
            self.cli("exec", "run", "--all", "--execute", "--confirm", LOCK)
        ft.FakeBlobStore.reset()
        self.cli("ignored", "run", "--resume", str(self.tmp / "exec" / "report.json"), "--confirm", LOCK)
        j = self.rep("exec")
        self.assertEqual(j["run"]["status"], "completed")
        hr = next(i for i in j["items"] if i["name"] == "Contoso HR Sync" and i["category"] == "service-principal")
        self.assertEqual(hr["status"], "applied")
        self.assertEqual(hr["before"], {"accountEnabled": True})
        self.assertFalse(self.t.s["sps"][ft.gid(201)]["accountEnabled"])  # items after the crash got applied

    def test_execute_twice_is_noop(self):
        self.cli("a", "run", "--all", "--execute", "--confirm", LOCK)
        self.cli("b", "run", "--all", "--execute", "--confirm", LOCK)
        self.assertFalse(any(i["status"] == "applied" for i in self.rep("b")["items"]))
        # rolling back run B must not undo run A
        self.cli("rb", "rollback", str(self.tmp / "b" / "report.json"), "--execute", "--confirm", ROLLBACK)
        self.assertFalse(self.t.s["sps"][ft.gid(200)]["accountEnabled"])

    def test_report_hash_written(self):
        self.cli("d", "run", "--all")
        lines = (self.tmp / "d" / "report.sha256").read_text().splitlines()
        self.assertTrue(lines[0].endswith("report.json") and len(lines[0].split()[0]) == 64)


class Lock(Base):
    def test_busy_lock_refuses(self):
        store = ft.FakeBlobStore("x", "y")
        store.lease(f"locks/{ft.TENANT}.lock", "acquire")
        code = self.cli("e", "run", "--all", "--execute", "--confirm", LOCK)
        self.assertEqual(code, 2)
        self.assertEqual(self.rep("e")["run"]["mode"], "execute-refused")
        self.assertTrue(self.t.s["sps"][ft.gid(200)]["accountEnabled"])
        self.assertIn("execute-refused", self.sent)

    def test_lock_released_and_archived(self):
        self.cli("e", "run", "--all", "--execute", "--confirm", LOCK)
        self.assertEqual(ft.FakeBlobStore.leases, {})
        rid = self.rep("e")["run"]["id"]
        self.assertIn(f"reports/{rid}/report.json", ft.FakeBlobStore.blobs)
        self.assertEqual(self.sent, ["execute-start", "execute-end"])


class Approval(Base):
    approval = True

    def test_requires_plan(self):
        self.assertEqual(self.cli("e", "run", "--all", "--execute", "--confirm", LOCK), 2)
        self.assertTrue(self.t.s["sps"][ft.gid(200)]["accountEnabled"])

    def test_unapproved_plan_refused(self):
        self.cli("plan", "run", "--all")
        self.assertEqual(self.cli("e", "run", "--execute", "--from-plan", str(self.tmp / "plan" / "report.json"), "--confirm", LOCK), 2)

    def test_self_approval_refused(self):
        self.cli("plan", "run", "--all")
        plan = str(self.tmp / "plan" / "report.json")
        ft.OPERATOR.update(oid=ft.gid(5), upn="leeg@contoso.com")  # Lee plans, approves and executes
        cli.main(["--config", str(self.cfg), "approve", plan, "--confirm", APPROVE])
        self.assertEqual(self.cli("e", "run", "--execute", "--from-plan", plan, "--confirm", LOCK), 2)
        self.assertIn("same identity", json.dumps(self.rep("e")["preflight"]))

    def test_approver_outside_group_refused(self):
        self.cli("plan", "run", "--all")
        ft.OPERATOR.update(oid=ft.gid(7), upn="diegos@contoso.com")
        code = cli.main(["--config", str(self.cfg), "approve", str(self.tmp / "plan" / "report.json"), "--confirm", APPROVE])
        self.assertEqual(code, 2)

    def test_approved_plan_executes(self):
        self.cli("plan", "run", "--all")
        plan = str(self.tmp / "plan" / "report.json")
        self.as_approver()
        self.assertEqual(cli.main(["--config", str(self.cfg), "approve", plan, "--confirm", APPROVE]), 0)
        ft.OPERATOR.update(self._op)
        code = self.cli("e", "run", "--execute", "--from-plan", plan, "--confirm", LOCK)
        self.assertEqual(code, 1)  # Helpdesk Bot 403 as usual
        r = self.rep("e")
        self.assertEqual(r["run"]["approval"]["approver"]["upn"], "leeg@contoso.com")
        self.assertFalse(self.t.s["sps"][ft.gid(200)]["accountEnabled"])

    def test_changed_plan_needs_new_approval(self):
        self.cli("plan", "run", "--all")
        plan_path = self.tmp / "plan" / "report.json"
        self.as_approver()
        cli.main(["--config", str(self.cfg), "approve", str(plan_path), "--confirm", APPROVE])
        ft.OPERATOR.update(self._op)
        plan = json.loads(plan_path.read_text())
        next(i for i in plan["items"] if i["status"] == "skipped-allowlist")["status"] = "planned"  # tamper
        plan_path.write_text(json.dumps(plan))
        self.assertEqual(self.cli("e", "run", "--execute", "--from-plan", str(plan_path), "--confirm", LOCK), 2)


class NotificationsAndSafety(Base):
    def test_failing_channel_does_not_block(self):
        def boom(ch, s, d):
            raise RuntimeError("webhook down")
        notify.SENDERS["teams"] = boom
        self.cli("e", "run", "--all", "--execute", "--confirm", LOCK)
        r = self.rep("e")
        self.assertFalse(self.t.s["sps"][ft.gid(200)]["accountEnabled"])
        self.assertTrue(all(not n["ok"] for n in r["notifications"]))

    def test_break_glass_not_excluded_refuses(self):
        self.t.s["ca"]["conditions"]["users"]["excludeUsers"] = [ft.gid(1)]
        self.assertEqual(self.cli("e", "run", "--all", "--execute", "--confirm", LOCK), 2)
        self.assertIn("NOT excluded", json.dumps(self.rep("e")["preflight"]))


if __name__ == "__main__":
    unittest.main()
