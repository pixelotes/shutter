"""Load and hash shutter.toml."""
from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "shutter.toml"


def load(path: str | Path | None = None) -> tuple[dict, str]:
    p = Path(path) if path else DEFAULT_PATH
    raw = p.read_bytes()
    cfg = tomllib.loads(raw.decode())
    cfg.setdefault("allowlist", {})
    for k in ("app_ids", "service_principal_ids", "owner_tenant_ids", "resource_ids"):
        cfg["allowlist"].setdefault(k, [])
    return cfg, hashlib.sha256(raw).hexdigest()
