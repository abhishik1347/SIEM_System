import importlib
import unittest
from unittest.mock import MagicMock, patch


class TestProcessingService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.processing_service = importlib.import_module("cloud.services.processing_service")
        except Exception as exc:
            raise unittest.SkipTest(f"processing_service import unavailable: {exc}")

    def test_ensure_logs_table_executes_create(self):
        fake_cursor = MagicMock()
        fake_conn = MagicMock()
        fake_conn.cursor.return_value = fake_cursor

        with patch.object(self.processing_service, "get_connection", return_value=fake_conn):
            self.processing_service.ensure_logs_table()

        fake_conn.cursor.assert_called_once()
        fake_cursor.execute.assert_called_once()
        sql = fake_cursor.execute.call_args[0][0]
        self.assertIn("CREATE TABLE IF NOT EXISTS logs", sql)
        fake_conn.commit.assert_called_once()
        fake_cursor.close.assert_called_once()
        fake_conn.close.assert_called_once()

    def test_process_and_store_logs_enriches_and_inserts(self):
        logs = [
            {
                "event_id": "4624",
                "time": "2026-04-08T11:00:00",
                "user": None,
                "action": None,
                "ocsf": {},
            },
            {
                "event_id": 4728,
                "time": "2026-04-08T11:01:00",
                "user": "alice",
                "action": "privileged_group_change",
                "ocsf": {"category": "Account Management"},
            },
            {
                "event_id": None,
                "time": "2026-04-08T11:02:00",
                "user": "bad",
            },
        ]

        with patch.object(self.processing_service, "calculate_risk", side_effect=[4, 9]) as calc_mock, \
            patch.object(self.processing_service, "map_to_mitre", side_effect=["Lateral Movement", "Privilege Escalation"]) as mitre_mock, \
            patch.object(self.processing_service, "aggregate_by_user", return_value={"UNKNOWN_USER": 4, "alice": 9}) as agg_mock, \
            patch.object(self.processing_service, "detect_anomaly", side_effect=[(False, 0, 0), (True, 2.1, 5.3)]) as anomaly_mock, \
            patch.object(self.processing_service, "insert_log") as insert_mock:

            stored = self.processing_service.process_and_store_logs(logs)

        self.assertEqual(stored, 2)
        self.assertEqual(insert_mock.call_count, 2)
        self.assertEqual(calc_mock.call_count, 2)
        self.assertEqual(mitre_mock.call_count, 2)
        agg_mock.assert_called_once()
        self.assertEqual(anomaly_mock.call_count, 2)

        first_inserted = insert_mock.call_args_list[0].args[0]
        second_inserted = insert_mock.call_args_list[1].args[0]

        self.assertEqual(first_inserted["user"], "UNKNOWN_USER")
        self.assertEqual(first_inserted["action"], "other")
        self.assertIn("category", first_inserted["ocsf"])
        self.assertIsInstance(first_inserted["anomaly"], bool)

        self.assertEqual(second_inserted["user"], "alice")
        self.assertEqual(second_inserted["mitre"], "Privilege Escalation")
        self.assertTrue(second_inserted["anomaly"])


if __name__ == "__main__":
    unittest.main()
