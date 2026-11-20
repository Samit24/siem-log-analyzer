"""Write alerts as JSON and as a Markdown report for analysts."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def to_json(alerts, path):
    Path(path).write_text(json.dumps(alerts, indent=2), encoding="utf-8")


def to_markdown(alerts, event_count):
    by_sev = Counter(a["severity"] for a in alerts)
    lines = [
        "# SIEM Log Analyzer report",
        "",
        f"Events analysed: **{event_count}**  ",
        f"Alerts raised: **{len(alerts)}** "
        f"(critical {by_sev['critical']}, high {by_sev['high']}, medium {by_sev['medium']}, low {by_sev['low']})",
        "",
        "| Severity | Rule | MITRE | Time | Host | User | Detail |",
        "|---|---|---|---|---|---|---|",
    ]
    for a in alerts:
        lines.append(f"| {a['severity']} | {a['rule_id']} {a['rule']} | {a['mitre']} | {a['time']} | "
                     f"{a['host']} | {a['user']} | {a['detail']} |")
    if not alerts:
        lines.append("| - | No detections | - | - | - | - | - |")
    return "\n".join(lines) + "\n"
