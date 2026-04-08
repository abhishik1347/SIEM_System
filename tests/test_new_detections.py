import unittest

from backend.normalizer.mitre_mapper import map_to_mitre
from backend.normalizer.ocsf_mapper import to_ocsf
from backend.parser.windows_parser import parse_windows_event
from backend.scorer import risk_engine
from backend.scorer.risk_engine import calculate_risk


class TestNewDetections(unittest.TestCase):
    def setUp(self):
        risk_engine.failed_login_counter.clear()
        risk_engine.recent_suspicious_launcher.clear()
        risk_engine.remote_logon_counter.clear()

    def test_privileged_group_change_parsing_and_scoring(self):
        raw = {
            "event_id": 4728,
            "time": "2026-04-08T10:00:00",
            "data": ["alice", None, "Administrators"],
        }
        parsed = parse_windows_event(raw)

        self.assertEqual(parsed["action"], "privileged_group_change")
        self.assertEqual(parsed["group_name"], "Administrators")

        risk = calculate_risk(parsed)
        self.assertGreaterEqual(risk, 9)
        self.assertEqual(map_to_mitre(4728), "Privilege Escalation - Account Manipulation")

    def test_lateral_movement_logon_type_escalation(self):
        raw = {
            "event_id": 4624,
            "time": "2026-04-08T10:01:00",
            "data": [None, None, None, None, None, "bob", None, None, "10"],
        }
        parsed = parse_windows_event(raw)

        self.assertEqual(parsed["action"], "remote_login_success")
        self.assertEqual(str(parsed["logon_type"]), "10")

        event = {
            "event_id": parsed["event_id"],
            "time": parsed["time"],
            "user": parsed["user"],
            "action": parsed["action"],
            "logon_type": parsed["logon_type"],
        }

        risk1 = calculate_risk(event)
        risk2 = calculate_risk(event)
        risk3 = calculate_risk(event)

        self.assertGreaterEqual(risk1, 4)
        self.assertGreaterEqual(risk3, 6)
        self.assertGreaterEqual(risk3, risk2)

        ocsf = to_ocsf(parsed)
        self.assertEqual(ocsf["activity_name"], "Remote Logon Success")
        self.assertEqual(ocsf["severity"], "medium")

    def test_suspicious_process_chain_escalation(self):
        first = {
            "event_id": 4688,
            "time": "2026-04-08T10:02:00",
            "user": "charlie",
            "process_name": "powershell.exe -enc AAA",
            "action": "process_created",
        }
        second = {
            "event_id": 4688,
            "time": "2026-04-08T10:03:00",
            "user": "charlie",
            "process_name": "cmd.exe /c whoami",
            "action": "process_created",
        }

        risk_first = calculate_risk(first)
        risk_second = calculate_risk(second)

        self.assertGreaterEqual(risk_first, 8)
        self.assertGreaterEqual(risk_second, risk_first)
        self.assertGreaterEqual(risk_second, 9)


if __name__ == "__main__":
    unittest.main()
