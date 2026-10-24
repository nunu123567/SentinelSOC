
import tempfile
import unittest
from pathlib import Path

from src.parser import parse_auth_logs, parse_network_logs


DATA = Path(__file__).resolve().parents[1] / "data"


class ParserTests(unittest.TestCase):

    def test_auth_logs_are_parsed(self):
        events = parse_auth_logs(str(DATA / "auth_logs.csv"))

        self.assertEqual(len(events), 9)
        self.assertEqual(events[0]["event_type"], "login_success")
        self.assertEqual(events[0]["log_source"], "authentication")

    def test_network_port_is_integer(self):
        events = parse_network_logs(str(DATA / "network_logs.csv"))

        self.assertEqual(len(events), 4)
        self.assertIsInstance(events[0]["destination_port"], int)

    def test_missing_auth_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,username,source_ip\n"
                "2026-10-24T10:00:00,bob,192.0.2.1\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                parse_auth_logs(str(path))

    def test_invalid_network_port_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,source_ip,destination_ip,"
                "destination_port,protocol,action\n"
                "2026-10-24T10:00:00,192.0.2.1,"
                "192.0.2.2,99999,TCP,allowed\n",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                parse_network_logs(str(path))


    def test_invalid_auth_ip_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,username,source_ip,event_type\n"
                "2026-10-24T10:00:00,bob,not-an-ip,login_failed\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "Invalid IP address"):
                parse_auth_logs(str(path))

    def test_invalid_network_protocol_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,source_ip,destination_ip,"
                "destination_port,protocol,action\n"
                "2026-10-24T10:00:00,192.0.2.1,"
                "192.0.2.2,443,UNKNOWN,allowed\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "Unsupported protocol"):
                parse_network_logs(str(path))

    def test_invalid_timestamp_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text(
                "timestamp,username,source_ip,event_type\n"
                "not-a-date,bob,192.0.2.1,login_failed\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "Invalid timestamp"):
                parse_auth_logs(str(path))



if __name__ == "__main__":
    unittest.main()
