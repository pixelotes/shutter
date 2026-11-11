"""Execution control: run lock, two-person approval and report archive.

Backed by a blob container ([control] in shutter.toml) using Entra ID auth, so it works across
operators and machines. Without that section, the lock falls back to a local lock file (same
machine only) and approvals / archiving are unavailable.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import formatdate
from pathlib import Path

from .http import get_token

STORAGE_RESOURCE = "https://storage.azure.com"


class LockBusy(Exception):
    pass


# --------------------------------------------------------------------------- blob store
class BlobStore:
    """Tiny Azure Blob REST client (Entra ID bearer token)."""

    def __init__(self, account: str, container: str, token: str | None = None):
        self.base = f"https://{account}.blob.core.windows.net/{container}"
        self.token = token or get_token(STORAGE_RESOURCE)

    def _req(self, method: str, name: str, query: str = "", headers: dict | None = None, body: bytes | None = None):
        req = urllib.request.Request(f"{self.base}/{name}{query}", data=body, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("x-ms-version", "2023-11-03")
        req.add_header("x-ms-date", formatdate(usegmt=True))
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def put(self, name: str, data: bytes, lease_id: str | None = None, if_none_match: bool = False,
            content_type: str = "application/json") -> int:
        h = {"x-ms-blob-type": "BlockBlob", "Content-Type": content_type}
        if lease_id:
            h["x-ms-lease-id"] = lease_id
        if if_none_match:
            h["If-None-Match"] = "*"
        return self._req("PUT", name, headers=h, body=data)[0]

    def get(self, name: str) -> bytes | None:
        status, _, body = self._req("GET", name)
        return body if status == 200 else None

    def lease(self, name: str, action: str, lease_id: str | None = None) -> tuple[int, str | None]:
        h = {"x-ms-lease-action": action}
        if action == "acquire":
            h["x-ms-lease-duration"] = "-1"
        if action == "break":
            h["x-ms-lease-break-period"] = "0"
        if lease_id:
            h["x-ms-lease-id"] = lease_id
        status, headers, _ = self._req("PUT", name, "?comp=lease", h)
        return status, headers.get("x-ms-lease-id")


def store_from_cfg(cfg: dict):
    c = cfg.get("control") or {}
    if not c.get("storage_account"):
        return None
    return STORE_FACTORY(c["storage_account"], c.get("container", "shutter"))


STORE_FACTORY = BlobStore  # tests swap this for an in-memory fake


# --------------------------------------------------------------------------- run lock
class RunLock:
    """Prevents two executions (or an execution and a rollback) against the same tenant."""

    def __init__(self, cfg: dict, holder: dict):
        self.store = store_from_cfg(cfg)
        self.name = f"locks/{cfg['tenant_id']}.lock"
        self.holder = holder
        self.lease_id = None
        self._fh = None

    def __enter__(self):
        info = json.dumps(self.holder | {"since": datetime.now(timezone.utc).isoformat()}).encode()
        if self.store is None:
            path = Path.home() / f".shutter-{self.name.split('/')[-1]}"
            self._fh = open(path, "a+")
            try:
                fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LockBusy(f"another shutter run holds {path} on this machine") from None
            return self
        self.store.put(self.name, b"{}", if_none_match=True)
        status, lease = self.store.lease(self.name, "acquire")
        if status != 201:
            held = (self.store.get(self.name) or b"{}").decode()
            raise LockBusy(f"tenant is locked by another run: {held} (use `shutter unlock` if it is stale)")
        self.lease_id = lease
        self.store.put(self.name, info, lease_id=lease)
        return self

    def __exit__(self, *exc):
        if self._fh:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
            self._fh.close()
        elif self.lease_id:
            self.store.lease(self.name, "release", self.lease_id)


def break_lock(cfg: dict) -> bool:
    store = store_from_cfg(cfg)
    if store is None:
        return False
    return store.lease(f"locks/{cfg['tenant_id']}.lock", "break")[0] in (200, 202)


# --------------------------------------------------------------------------- approvals
def plan_hash(plan: dict) -> str:
    """Hash of what a dry-run would change: tenant + (key, action, target state) of planned items."""
    planned = sorted(
        (i["key"], i["action"], json.dumps(i["after"], sort_keys=True))
        for i in plan["items"] if i["status"] == "planned" and i.get("after") is not None
    )
    return hashlib.sha256(json.dumps([plan["run"]["tenantId"], planned]).encode()).hexdigest()


def approve(cfg: dict, plan: dict, approver: dict, ttl_minutes: int) -> dict:
    store = store_from_cfg(cfg)
    if store is None:
        raise RuntimeError("approvals need [control] storage_account in shutter.toml")
    now = datetime.now(timezone.utc)
    rec = {"planHash": plan_hash(plan), "planRunId": plan["run"]["id"], "tenantId": plan["run"]["tenantId"],
           "approver": {k: approver.get(k) for k in ("kind", "id", "upn")},
           "approvedAt": now.isoformat(), "expiresAt": (now + timedelta(minutes=ttl_minutes)).isoformat()}
    store.put(f"approvals/{rec['planHash']}.json", json.dumps(rec, indent=2).encode())
    return rec


def check_approval(cfg: dict, plan: dict, executor: dict, is_member) -> tuple[bool, str, dict | None]:
    """Returns (ok, detail, approval). `is_member(object_id, group_id) -> bool` is checked via Graph."""
    store = store_from_cfg(cfg)
    if store is None:
        return False, "approvals need [control] storage_account", None
    raw = store.get(f"approvals/{plan_hash(plan)}.json")
    if not raw:
        return False, f"no approval found for this plan (hash {plan_hash(plan)[:12]}); run `shutter approve` as a second operator", None
    rec = json.loads(raw)
    if datetime.fromisoformat(rec["expiresAt"]) < datetime.now(timezone.utc):
        return False, f"approval by {rec['approver']['upn']} expired at {rec['expiresAt']}", rec
    if rec["approver"]["id"] == executor.get("id"):
        return False, "approver and executor are the same identity", rec
    group = (cfg.get("approval") or {}).get("approver_group_id")
    if group and not is_member(rec["approver"]["id"], group):
        return False, f"{rec['approver']['upn']} is not in the approver group {group}", rec
    return True, f"approved by {rec['approver']['upn']} at {rec['approvedAt']}", rec


# --------------------------------------------------------------------------- archive
def archive(cfg: dict, run_id: str, out_dir: Path) -> list[str]:
    """Upload the report files. Point [control] at a container with an immutability policy (WORM)."""
    store = store_from_cfg(cfg)
    if store is None or not (cfg.get("control") or {}).get("archive_reports", True):
        return []
    done = []
    for name, ctype in (("report.json", "application/json"), ("report.html", "text/html"), ("report.sha256", "text/plain")):
        p = out_dir / name
        if p.exists():
            blob = f"reports/{run_id}/{name}"
            if store.put(blob, p.read_bytes(), content_type=ctype) in (200, 201):
                done.append(blob)
    return done


def operator_label() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
