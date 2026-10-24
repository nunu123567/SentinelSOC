
import unittest
from datetime import datetime, timedelta

from src.detector import (
    detect_brute_force,
    detect_success_after_failures,
    detect_watchlisted_ports,
    run_detections,
)


def auth_event(minutes, event_type, username="bob",
               source_ip="203.0.113.50"):
    return {
        "timestamp": datetime(2026, 10, 24, 10, 0, 0)
        + timedelta(minutes=minutes),
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "log_source": "authentication",
    }


def network_event(port=4444):
    return {
        "timestamp": datetime(2026, 10, 24, 10, 0, 0),
        "source_ip": "203.0.113.50",
        "destination_ip": "192.168.1.10",
        "destination_port": port,
        "protocol": "TCP",
        "action": "allowed",
        "log_source": "network",
    }


class DetectionTests(unittest.TestCase):

    def test_five_failures_trigger_brute_force_alert(self):
        events = [
            auth_event(i, "login_failed")
            for i in range(5)
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "DET-001")
        self.assertEqual(len(alerts[0]["evidence"]), 5)

    def test_four_failures_do_not_trigger_alert(self):
        events = [
            auth_event(i, "login_failed")
            for i in range(4)
        ]

        self.assertEqual(detect_brute_force(events), [])

    def test_success_after_three_failures_triggers_alert(self):
        events = [
            auth_event(0, "login_failed"),
            auth_event(1, "login_failed"),
            auth_event(2, "login_failed"),
            auth_event(3, "login_success"),
        ]

        alerts = detect_success_after_failures(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "DET-002")
        self.assertEqual(len(alerts[0]["evidence"]), 4)

    def test_success_for_different_ip_does_not_trigger(self):
        events = [
            auth_event(i, "login_failed")
            for i in range(3)
        ]
        events.append(
            auth_event(3, "login_success", source_ip="192.0.2.99")
        )

        self.assertEqual(detect_success_after_failures(events), [])

    def test_watchlisted_port_triggers_alert(self):
        alerts = detect_watchlisted_ports([network_event()])

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "DET-003")

    def test_other_port_does_not_trigger_alert(self):
        alerts = detect_watchlisted_ports([network_event(443)])

        self.assertEqual(alerts, [])

    def test_custom_watchlist(self):
        alerts = detect_watchlisted_ports(
            [network_event(8443)],
            watchlisted_ports={8443},
        )

        self.assertEqual(len(alerts), 1)

    def test_all_rules_run_together(self):
        auth = [
            auth_event(i, "login_failed")
            for i in range(5)
        ]
        auth.append(auth_event(5, "login_success"))

        alerts = run_detections(auth, [network_event()])

        rule_ids = {alert["rule_id"] for alert in alerts}

        self.assertEqual(
            rule_ids,
            {"DET-001", "DET-002", "DET-003"},
        )


    def test_failure_exactly_five_minutes_old_is_included(self):
        events = [
            auth_event(0, "login_failed"),
            auth_event(1, "login_failed"),
            auth_event(2, "login_failed"),
            auth_event(3, "login_failed"),
            auth_event(5, "login_failed"),
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(alerts[0]["evidence"]), 5)


    def test_failure_outside_five_minute_window_is_excluded(self):
        events = [
            auth_event(0, "login_failed"),
            auth_event(1, "login_failed"),
            auth_event(2, "login_failed"),
            auth_event(3, "login_failed"),
            auth_event(6, "login_failed"),
        ]

        alerts = detect_brute_force(events)

        # At minute 6, the minute-0 failure has expired.
        # Only four failures remain within the window.
        self.assertEqual(alerts, [])



if __name__ == "__main__":
    unittest.main()
