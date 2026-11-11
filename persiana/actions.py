"""State-changing operations. Each one records before/after so `rollback` can undo it."""
from __future__ import annotations

from .http import ApiError, Client
from .inventory import STORAGE_API, strip_odata


def _read_state(it: dict, graph: Client, arm: Client) -> dict:
    cat = it["category"]
    if cat == "conditional-access":
        p = strip_odata(graph.get(f"/v1.0/identity/conditionalAccess/policies/{it['id']}"))
        return {"state": p["state"], "conditions": p["conditions"]}
    if cat == "sftp":
        p = arm.get(f"{it['id']}?api-version={STORAGE_API}")
        return {"isSftpEnabled": bool(p["properties"].get("isSftpEnabled"))}
    sp_id = it["id"] if cat == "service-principal" else it["details"]["servicePrincipalId"]
    return {"accountEnabled": graph.get(f"/v1.0/servicePrincipals/{sp_id}?$select=accountEnabled")["accountEnabled"]}


def _write_state(it: dict, state: dict, graph: Client, arm: Client) -> None:
    cat = it["category"]
    if cat == "conditional-access":
        graph.patch(f"/v1.0/identity/conditionalAccess/policies/{it['id']}", state)
    elif cat == "sftp":
        arm.patch(f"{it['id']}?api-version={STORAGE_API}", {"properties": state})
    else:
        sp_id = it["id"] if cat == "service-principal" else it["details"]["servicePrincipalId"]
        graph.patch(f"/v1.0/servicePrincipals/{sp_id}", state)


def _same(a: dict, b: dict) -> bool:
    """Compare only the keys we manage (Graph may add defaults to conditions)."""
    def norm(x):
        if isinstance(x, dict):
            return {k: norm(v) for k, v in x.items() if v not in (None, [], {})}
        return x
    return all(norm(a.get(k)) == norm(b.get(k)) for k in b)


def apply(it: dict, graph: Client, arm: Client) -> None:
    try:
        current = _read_state(it, graph, arm)
        if _same(current, it["after"]):
            it["status"] = "skipped"
            it["reasons"].append("Already in target state at execution time")
            return
        it["before"] = current  # authoritative pre-change state, captured right before the write
        _write_state(it, it["after"], graph, arm)
        it["after"] = _read_state(it, graph, arm)
        it["status"] = "applied"
    except ApiError as e:
        it["status"], it["error"] = "failed", str(e)


def revert(it: dict, graph: Client, arm: Client, execute: bool, force: bool) -> None:
    """Restore `before`. Refuses if someone changed the object after persiana did (drift)."""
    it["revertOf"] = it["status"]
    if it["status"] != "applied":
        it["status"] = "not-applicable"
        return
    try:
        current = _read_state(it, graph, arm)
        if _same(current, it["before"]):
            it["status"] = "skipped"
            it["reasons"].append("Already back to original state")
            return
        if not _same(current, it["after"]) and not force:
            it["status"], it["error"] = "drift", "Current state differs from what persiana set; use --force to overwrite"
            it["details"]["currentState"] = current
            return
        if not execute:
            it["status"] = "planned"
            return
        _write_state(it, it["before"], graph, arm)
        it["status"] = "reverted"
    except ApiError as e:
        it["status"], it["error"] = "failed", str(e)
