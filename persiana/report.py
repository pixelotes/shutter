"""Write report.json (source of truth, used by rollback) and a self-contained report.html."""
from __future__ import annotations

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


def write(report: dict, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report["summary"] = summarize(report)
    data = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    jp = out_dir / "report.json"
    jp.write_text(data, encoding="utf-8")
    embedded = data.replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8").replace("/*__REPORT_JSON__*/null", embedded)
    hp = out_dir / "report.html"
    hp.write_text(html, encoding="utf-8")
    return jp, hp
