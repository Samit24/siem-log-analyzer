"""Command line entry point: python -m siem_analyzer samples/security_events.jsonl"""
import argparse
from pathlib import Path

from .parser import load_file
from .report import to_json, to_markdown
from .rules import run_all


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run detection rules over Windows security events (JSON Lines).")
    ap.add_argument("logfile", help="path to a .jsonl file of events")
    ap.add_argument("-o", "--output", default="output", help="folder for alerts.json and report.md")
    args = ap.parse_args(argv)

    events = load_file(args.logfile)
    alerts = run_all(events)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    to_json(alerts, out / "alerts.json")
    (out / "report.md").write_text(to_markdown(alerts, len(events)), encoding="utf-8")

    print(f"Analysed {len(events)} events, raised {len(alerts)} alerts.")
    for a in alerts:
        print(f"  [{a['severity'].upper():8}] {a['rule_id']} {a['rule']:42} {a['host']:12} {a['detail']}")
    print(f"Report written to {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
