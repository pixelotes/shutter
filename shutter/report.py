"""Write report.json (source of truth, used by rollback) and a self-contained report.html."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

TEMPLATE = Path(__file__).with_name("template.html")


def summarize(report: dict) -> dict:
    items = report["items"]
    return {
        "byCategory": dict(Counter(i["category"] for i in items)),
        "byStatus": dict(Counter(i["status"] for i in items)),
        "bySeverity": dict(Counter(i["severity"] for i in items if i["status"] not in ("skipped-allowlist",))),
        "total": len(items),
    }


def write_json(report: dict, out_dir: Path) -> Path:
    """Atomic journal write (temp file + rename). Called after every item during --execute."""
    out_dir.mkdir(parents=True, exist_ok=True)
    report["summary"] = summarize(report)
    jp = out_dir / "report.json"
    tmp = jp.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(jp)
    return jp


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(report: dict, out_dir: Path) -> tuple[Path, Path]:
    """Final write: report.json, report.html and report.sha256 (hashes of both)."""
    jp = write_json(report, out_dir)
    embedded = jp.read_text(encoding="utf-8").replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8").replace("/*__REPORT_JSON__*/null", embedded)
    hp = out_dir / "report.html"
    hp.write_text(html, encoding="utf-8")
    (out_dir / "report.sha256").write_text(f"{sha256(jp)}  report.json\n{sha256(hp)}  report.html\n")
    return jp, hp
