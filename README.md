# SIEM Log Analyzer

A lightweight, rule-based detection engine for **Windows security events**. It reads events in JSON Lines format, runs SIEM-style correlation rules, maps every alert to **MITRE ATT&CK**, and writes a JSON alert file plus a Markdown report an analyst can read.

No dependencies: just Python 3.10+.

## Detections

| ID | Rule | Event IDs | MITRE |
|---|---|---|---|
| R001 | Brute-force logon attempts (5+ failures, same user and source, 5 min) | 4625 | T1110.001 |
| R002 | Password spraying (one source, 5+ accounts, 10 min) | 4625 | T1110.003 |
| R003 | Successful logon after repeated failures | 4625, 4624 | T1110 |
| R004 | PowerShell with an encoded command | 4688 | T1059.001 |
| R005 | Office application spawning a shell or script host | 4688 | T1204.002 |
| R006 | Account added to a privileged group | 4732 | T1098 |
| R007 | Security log cleared | 1102 | T1070.001 |

## Quick start

```bash
git clone https://github.com/Samit24/siem-log-analyzer.git
cd siem-log-analyzer
python -m siem_analyzer samples/security_events.jsonl
```

Output:

```
Analysed 22 events, raised 7 alerts.
  [CRITICAL] R003 Successful logon after repeated failures   DC-01   'administrator' logged on from 185.220.101.7 after 7 failures
  [CRITICAL] R007 Security log cleared                       DC-01   Security log cleared on DC-01 by 'administrator'
  [HIGH    ] R002 Password spraying                          DC-01   45.155.205.33 failed against 5 accounts within 0:10:00
  ...
Report written to output/report.md
```

## Input format

One JSON object per line. Required: `timestamp`, `event_id`, `host`. Optional: `user`, `src_ip`, `process`, `parent_process`, `command_line`, `group`, `target_user`.

```json
{"timestamp": "2026-11-03T09:15:20Z", "event_id": 4688, "host": "WS-014", "user": "r.sharma",
 "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "parent_process": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
 "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA..."}
```

## Project layout

```
siem_analyzer/
  parser.py    load and normalise events
  rules.py     detection rules (add your own to ALL_RULES)
  report.py    JSON and Markdown output
samples/       synthetic attack scenario
tests/         unit tests (python -m unittest discover -s tests)
```

## Adding a rule

Write a function that takes the time-sorted event list and returns a list of alerts (use `_alert(...)`), then add it to `ALL_RULES` in `rules.py` and cover it with a test.

## Author

**Samit Pudasaini**, Security Engineer, Kathmandu, Nepal
[samitpudasaini.com.np](https://www.samitpudasaini.com.np) | [LinkedIn](https://linkedin.com/in/samit-pudasaini)

Licensed under the MIT License. Sample data in `samples/` is synthetic.
