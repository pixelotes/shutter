"""State-changing operations. Each one records before/after so `rollback` can undo it."""
from __future__ import annotations

from . import modules
from .http import ApiError, Client


def _read_state(it: dict, graph: Client, arm: Client) -> dict:
    return modules.read(it, graph, arm)


def _write_state(it: dict, state: dict, graph: Client, arm: Client) -> None:
    modules.write(it, state, graph, arm)


def _same(a: dict, b: dict) -> bool:
    """Compare only the keys we manage (Graph may add defaults to conditions)."""
    def norm(x):
        if isinstance(x, dict):
            return {k: norm(v) for k, v in x.items() if v not in (None, [], {})}
        return x
    return all(norm(a.get(k)) == norm(b.get(k)) for k in b)


def apply(it: dict, graph: Client, arm: Client, journal=lambda: None) -> None:
    """Idempotent: re-reads state, skips if already in target state.

    `journal()` is called after `before` is captured and BEFORE the write, so that if the process
    dies mid-write the item is on disk as `in-progress` with its original state, and rollback can
    still undo it.
    """
    if it.get("irreversible"):
        try:
            it["status"] = "in-progress"
            journal()
            modules.fire(it, graph)
            it["status"] = "applied"
        except ApiError as e:
            it["status"], it["error"] = "failed", str(e)
        return
    try:
        current = _read_state(it, graph, arm)
        if _same(current, it["after"]):
            if it["status"] == "in-progress":
                # Resumed run: our write landed before the crash. We still own this change, so it
                # must stay revertible — do NOT overwrite `before` with the current state.
                it["status"] = "applied"
                it["reasons"].append("Write confirmed on resume")
            else:
                it["status"] = "skipped"
                it["reasons"].append("Already in target state at execution time")
            return
        it["before"] = current  # authoritative pre-change state, captured right before the write
        it["status"] = "in-progress"
        journal()
        _write_state(it, it["after"], graph, arm)
        it["after"] = _read_state(it, graph, arm)
        it["status"] = "applied"
    except ApiError as e:
        it["status"], it["error"] = "failed", str(e)


def revert(it: dict, graph: Client, arm: Client, execute: bool, force: bool) -> None:
    """Restore `before`. Refuses if someone changed the object after shutter did (drift)."""
    it["revertOf"] = it["status"]
    # `in-progress` = the run died between capturing `before` and confirming the write. The state
    # comparison below decides whether the write actually landed.
    if it.get("irreversible") and it["status"] in ("applied", "in-progress"):
        it["status"] = "irreversible"
        it["reasons"].append("Cannot be rolled back")
        return
    if it["status"] not in ("applied", "in-progress"):
        it["status"] = "not-applicable"
        return
    try:
        current = _read_state(it, graph, arm)
        if _same(current, it["before"]):
            it["status"] = "skipped"
            it["reasons"].append("Already back to original state")
            return
        if not _same(current, it["after"]) and not force:
            it["status"], it["error"] = "drift", "Current state differs from what shutter set; use --force to overwrite"
            it["details"]["currentState"] = current
            return
        if not execute:
            it["status"] = "planned"
            return
        _write_state(it, it["before"], graph, arm)
        it["status"] = "reverted"
    except ApiError as e:
        it["status"], it["error"] = "failed", str(e)
