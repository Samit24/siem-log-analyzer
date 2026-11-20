import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from siem_analyzer.parser import load_file, read_events
from siem_analyzer import rules

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "security_events.jsonl"


def make(events):
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    lines = [json.dumps({"timestamp": (t0 + timedelta(seconds=s)).isoformat(), "host": "H1", **e}) for s, e in events]
    return list(read_events(lines))


class RuleTests(unittest.TestCase):
    def test_brute_force_fires_once_at_threshold(self):
        evs = make([(i * 10, {"event_id": 4625, "user": "bob", "src_ip": "1.2.3.4"}) for i in range(8)])
        self.assertEqual(len(rules.brute_force(evs)), 1)

    def test_brute_force_ignores_slow_failures(self):
        evs = make([(i * 120, {"event_id": 4625, "user": "bob", "src_ip": "1.2.3.4"}) for i in range(6)])
        self.assertEqual(rules.brute_force(evs), [])

    def test_password_spray(self):
        evs = make([(i * 5, {"event_id": 4625, "user": f"u{i}", "src_ip": "9.9.9.9"}) for i in range(5)])
        alerts = rules.password_spray(evs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre"], "T1110.003")

    def test_success_after_failures(self):
        evs = make([(i, {"event_id": 4625, "user": "admin", "src_ip": "5.5.5.5"}) for i in range(5)]
                   + [(60, {"event_id": 4624, "user": "admin", "src_ip": "5.5.5.5"})])
        self.assertEqual(rules.success_after_failures(evs)[0]["severity"], "critical")

    def test_encoded_powershell_only_matches_encoded(self):
        evs = make([
            (0, {"event_id": 4688, "process": "C:\\x\\powershell.exe", "command_line": "powershell -enc AAAA"}),
            (1, {"event_id": 4688, "process": "C:\\x\\powershell.exe", "command_line": "powershell -File a.ps1"}),
        ])
        self.assertEqual(len(rules.encoded_powershell(evs)), 1)

    def test_office_spawns_shell(self):
        evs = make([(0, {"event_id": 4688, "process": "C:\\w\\cmd.exe", "parent_process": "C:\\o\\EXCEL.EXE"})])
        self.assertEqual(len(rules.office_spawns_shell(evs)), 1)

    def test_admin_group_change_and_log_cleared(self):
        evs = make([(0, {"event_id": 4732, "group": "Administrators", "target_user": "x"}),
                    (1, {"event_id": 4732, "group": "Users", "target_user": "y"}),
                    (2, {"event_id": 1102})])
        self.assertEqual(len(rules.admin_group_change(evs)), 1)
        self.assertEqual(len(rules.log_cleared(evs)), 1)

    def test_sample_file_end_to_end(self):
        alerts = rules.run_all(load_file(SAMPLE))
        ids = {a["rule_id"] for a in alerts}
        self.assertEqual(ids, {"R001", "R002", "R003", "R004", "R005", "R006", "R007"})
        self.assertEqual(alerts[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
