
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime

from src.reporter import write_json_report, write_incident_report


class ReporterTests(unittest.TestCase):

    def sample_alert(self):
        return {
            "rule_id": "DET-001",
            "title": "Repeated authentication failures",
            "severity": "high",
            "timestamp": "2026-10-24T10:04:00",
            "description": "Five failed logins from one source IP.",
            "evidence": [
                {
                    "timestamp": datetime(2026, 10, 24, 10, 4),
                    "source_ip": "203.0.113.50",
                    "event_type": "login_failed",
                }
            ],
        }

    def test_json_report_preserves_alert_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "alerts.json"

            write_json_report([self.sample_alert()], str(path))

            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data[0]["rule_id"], "DET-001")
            self.assertEqual(
                data[0]["evidence"][0]["timestamp"],
                "2026-10-24T10:04:00",
            )

    def test_markdown_report_contains_alert_and_recommendations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incident_report.md"

            write_incident_report([self.sample_alert()], str(path))

            report = path.read_text(encoding="utf-8")
            self.assertIn("SentinelSOC Investigation Report", report)
            self.assertIn("DET-001", report)
            self.assertIn("Supporting evidence", report)
            self.assertIn("Recommended investigation", report)
            self.assertIn("Scope and limitations", report)

    def test_empty_alert_list_is_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incident_report.md"

            write_incident_report([], str(path))

            report = path.read_text(encoding="utf-8")
            self.assertIn("Total alerts: 0", report)
            self.assertIn("No configured detection rules triggered", report)


if __name__ == "__main__":
    unittest.main()
