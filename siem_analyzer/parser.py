"""Load security events from JSON Lines files into normalised dicts."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

REQUIRED = ("timestamp", "event_id", "host")


def parse_time(value: str) -> datetime:
    """Parse ISO-8601 timestamps, accepting a trailing 'Z'."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalise(raw: dict) -> dict:
    missing = [k for k in REQUIRED if k not in raw]
    if missing:
        raise ValueError(f"event missing fields: {', '.join(missing)}")
    event = {k.lower(): v for k, v in raw.items()}
    event["event_id"] = int(event["event_id"])
    event["time"] = parse_time(str(event["timestamp"]))
    for key in ("user", "src_ip", "process", "parent_process", "command_line", "group", "target_user"):
        event.setdefault(key, "")
    return event


def read_events(lines: Iterable[str]) -> Iterator[dict]:
    """Yield normalised events, skipping blank lines and reporting bad ones."""
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            yield normalise(json.loads(line))
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"[warn] line {number} skipped: {exc}")


def load_file(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        events = list(read_events(handle))
    return sorted(events, key=lambda e: e["time"])
