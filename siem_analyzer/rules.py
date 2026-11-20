"""Detection rules. Each rule takes a time-sorted list of events and returns alerts."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

# Windows Security event IDs used below
LOGON_SUCCESS = 4624
LOGON_FAILURE = 4625
PROCESS_CREATED = 4688
MEMBER_ADDED_LOCAL_GROUP = 4732
LOG_CLEARED = 1102

ENCODED_PS = re.compile(r"\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s", re.I)
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
ADMIN_GROUPS = {"administrators", "domain admins", "enterprise admins"}


def _alert(rule_id, name, severity, technique, event, detail, **extra):
    alert = {
        "rule_id": rule_id,
        "rule": name,
        "severity": severity,
        "mitre": technique,
        "time": event["time"].isoformat(),
        "host": event["host"],
        "user": event.get("user", ""),
        "src_ip": event.get("src_ip", ""),
        "detail": detail,
    }
    alert.update(extra)
    return alert


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path or "")[-1].lower()


def brute_force(events, threshold=5, window=timedelta(minutes=5)):
    """R001: many failed logons for one account from one source in a short window."""
    alerts, buckets, fired = [], defaultdict(list), set()
    for e in events:
        if e["event_id"] != LOGON_FAILURE:
            continue
        key = (e["user"].lower(), e["src_ip"])
        bucket = buckets[key]
        bucket.append(e["time"])
        while bucket and e["time"] - bucket[0] > window:
            bucket.pop(0)
        if len(bucket) >= threshold and key not in fired:
            fired.add(key)
            alerts.append(_alert("R001", "Brute-force logon attempts", "medium", "T1110.001", e,
                                 f"{len(bucket)} failed logons for '{e['user']}' from {e['src_ip']} within {window}"))
    return alerts


def password_spray(events, threshold=5, window=timedelta(minutes=10)):
    """R002: one source failing against many different accounts."""
    alerts, buckets, fired = [], defaultdict(list), set()
    for e in events:
        if e["event_id"] != LOGON_FAILURE or not e["src_ip"]:
            continue
        bucket = buckets[e["src_ip"]]
        bucket.append((e["time"], e["user"].lower()))
        while bucket and e["time"] - bucket[0][0] > window:
            bucket.pop(0)
        users = {u for _, u in bucket}
        if len(users) >= threshold and e["src_ip"] not in fired:
            fired.add(e["src_ip"])
            alerts.append(_alert("R002", "Password spraying", "high", "T1110.003", e,
                                 f"{e['src_ip']} failed against {len(users)} accounts within {window}",
                                 accounts=sorted(users)))
    return alerts


def success_after_failures(events, threshold=5, window=timedelta(minutes=15)):
    """R003: a successful logon right after a burst of failures from the same source."""
    alerts, failures = [], defaultdict(list)
    for e in events:
        if e["event_id"] == LOGON_FAILURE and e["src_ip"]:
            failures[e["src_ip"]].append(e["time"])
        elif e["event_id"] == LOGON_SUCCESS and e["src_ip"]:
            recent = [t for t in failures[e["src_ip"]] if e["time"] - t <= window]
            if len(recent) >= threshold:
                alerts.append(_alert("R003", "Successful logon after repeated failures", "critical", "T1110", e,
                                     f"'{e['user']}' logged on from {e['src_ip']} after {len(recent)} failures"))
                failures[e["src_ip"]].clear()
    return alerts


def encoded_powershell(events):
    """R004: PowerShell started with an encoded command."""
    return [
        _alert("R004", "Encoded PowerShell command", "high", "T1059.001", e,
               f"{e['process']} launched by {e['parent_process'] or 'unknown'} with an encoded command",
               command_line=e["command_line"])
        for e in events
        if e["event_id"] == PROCESS_CREATED
        and _basename(e["process"]) in {"powershell.exe", "pwsh.exe"}
        and ENCODED_PS.search(f" {e['command_line']} ")
    ]


def office_spawns_shell(events):
    """R005: an Office application starting a shell or script host (common in phishing)."""
    return [
        _alert("R005", "Office application spawned a shell", "high", "T1204.002", e,
               f"{_basename(e['parent_process'])} started {_basename(e['process'])}",
               command_line=e["command_line"])
        for e in events
        if e["event_id"] == PROCESS_CREATED
        and _basename(e["parent_process"]) in OFFICE_APPS
        and _basename(e["process"]) in SHELLS
    ]


def admin_group_change(events):
    """R006: an account added to a privileged group."""
    return [
        _alert("R006", "Account added to privileged group", "high", "T1098", e,
               f"'{e['target_user']}' added to '{e['group']}' by '{e['user']}'")
        for e in events
        if e["event_id"] == MEMBER_ADDED_LOCAL_GROUP and e["group"].lower() in ADMIN_GROUPS
    ]


def log_cleared(events):
    """R007: the Security event log was cleared."""
    return [
        _alert("R007", "Security log cleared", "critical", "T1070.001", e,
               f"Security log cleared on {e['host']} by '{e['user']}'")
        for e in events if e["event_id"] == LOG_CLEARED
    ]


ALL_RULES = [brute_force, password_spray, success_after_failures, encoded_powershell,
             office_spawns_shell, admin_group_change, log_cleared]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_all(events):
    alerts = [a for rule in ALL_RULES for a in rule(events)]
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a["severity"]], a["time"]))
