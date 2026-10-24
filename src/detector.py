
from collections import defaultdict
from datetime import timedelta


BRUTE_FORCE_THRESHOLD = 5
SUCCESS_AFTER_FAILURE_THRESHOLD = 3
WINDOW_MINUTES = 5
WATCHLISTED_PORTS = {4444}


def detect_brute_force(auth_events: list[dict]) -> list[dict]:
    """Detect repeated failed logins from the same source IP."""
    window = timedelta(minutes=WINDOW_MINUTES)
    events = sorted(auth_events, key=lambda e: e["timestamp"])
    failures_by_ip = defaultdict(list)
    alerts = []

    for event in events:
        if event["event_type"] != "login_failed":
            continue

        source_ip = event["source_ip"]
        previous = failures_by_ip[source_ip]

        previous[:] = [
            failure for failure in previous
            if event["timestamp"] - failure["timestamp"] <= window
        ]
        previous.append(event)

        if len(previous) == BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "rule_id": "DET-001",
                "title": "Repeated authentication failures",
                "severity": "high",
                "timestamp": event["timestamp"].isoformat(),
                "description": (
                    f"{len(previous)} failed logins from {source_ip} "
                    f"within {WINDOW_MINUTES} minutes."
                ),
                "evidence": list(previous),
            })

    return alerts


def detect_success_after_failures(
    auth_events: list[dict],
) -> list[dict]:
    """Detect successful logins following repeated failures."""
    window = timedelta(minutes=WINDOW_MINUTES)
    events = sorted(auth_events, key=lambda e: e["timestamp"])
    failures_by_account = defaultdict(list)
    alerts = []

    for event in events:
        key = (event["username"], event["source_ip"])
        timestamp = event["timestamp"]

        previous = failures_by_account[key]
        previous[:] = [
            failure for failure in previous
            if timestamp - failure["timestamp"] <= window
        ]

        if event["event_type"] == "login_failed":
            previous.append(event)

        elif (
            event["event_type"] == "login_success"
            and len(previous) >= SUCCESS_AFTER_FAILURE_THRESHOLD
        ):
            evidence = list(previous) + [event]

            alerts.append({
                "rule_id": "DET-002",
                "title": "Successful login after repeated failures",
                "severity": "high",
                "timestamp": timestamp.isoformat(),
                "description": (
                    f"Account {event['username']} successfully logged in "
                    f"from {event['source_ip']} after "
                    f"{len(previous)} recent failed attempts."
                ),
                "evidence": evidence,
            })

    return alerts


def detect_watchlisted_ports(
    network_events: list[dict],
    watchlisted_ports: set[int] | None = None,
) -> list[dict]:
    """Detect network connections to configured destination ports."""
    if watchlisted_ports is None:
        watchlisted_ports = WATCHLISTED_PORTS

    alerts = []

    for event in network_events:
        if event["destination_port"] not in watchlisted_ports:
            continue

        alerts.append({
            "rule_id": "DET-003",
            "title": "Connection to watchlisted destination port",
            "severity": "medium",
            "timestamp": event["timestamp"].isoformat(),
            "description": (
                f"Connection from {event['source_ip']} to "
                f"{event['destination_ip']} on destination port "
                f"{event['destination_port']}/{event['protocol']}."
            ),
            "evidence": [event],
        })

    return alerts


def run_detections(
    auth_events: list[dict],
    network_events: list[dict],
) -> list[dict]:
    """Run all enabled detection rules."""
    alerts = []
    alerts.extend(detect_brute_force(auth_events))
    alerts.extend(detect_success_after_failures(auth_events))
    alerts.extend(detect_watchlisted_ports(network_events))

    return sorted(alerts, key=lambda alert: alert["timestamp"])
