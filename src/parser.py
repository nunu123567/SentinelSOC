
import csv
import ipaddress
from datetime import datetime
from pathlib import Path


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-formatted timestamp."""
    try:
        return datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {value!r}") from exc


def validate_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address and return its normalized form."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


def read_csv_logs(file_path: str, required_fields: set[str]) -> list[dict]:
    """Read CSV records and validate required fields."""
    path = Path(file_path)

    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError(f"CSV file has no header: {path}")

        missing = required_fields - set(reader.fieldnames)
        if missing:
            raise ValueError(f"Missing required fields: {sorted(missing)}")

        records = []

        for line_number, row in enumerate(reader, start=2):
            if None in row or any(
                value is None or not value.strip()
                for value in row.values()
            ):
                raise ValueError(
                    f"Missing or extra data at line {line_number}"
                )

            records.append(row)

    return records


def parse_auth_logs(file_path: str) -> list[dict]:
    """Parse and normalize authentication events."""
    required = {"timestamp", "username", "source_ip", "event_type"}
    records = read_csv_logs(file_path, required)
    events = []

    for row in records:
        event_type = row["event_type"].strip().lower()
        username = row["username"].strip()

        if event_type not in {"login_failed", "login_success"}:
            raise ValueError(f"Unknown authentication event: {event_type}")

        if not username:
            raise ValueError("Username cannot be empty")

        events.append({
            "timestamp": parse_timestamp(row["timestamp"]),
            "username": username,
            "source_ip": validate_ip(row["source_ip"]),
            "event_type": event_type,
            "log_source": "authentication",
        })

    return events


def parse_network_logs(file_path: str) -> list[dict]:
    """Parse and normalize network connection events."""
    required = {
        "timestamp", "source_ip", "destination_ip",
        "destination_port", "protocol", "action"
    }
    records = read_csv_logs(file_path, required)
    events = []

    for row in records:
        try:
            port = int(row["destination_port"])
        except ValueError as exc:
            raise ValueError(
                f"Invalid destination port: {row['destination_port']!r}"
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid destination port: {port}")

        protocol = row["protocol"].strip().upper()
        action = row["action"].strip().lower()

        if protocol not in {"TCP", "UDP", "ICMP"}:
            raise ValueError(f"Unsupported protocol: {protocol}")

        if action not in {"allowed", "blocked"}:
            raise ValueError(f"Unsupported network action: {action}")

        events.append({
            "timestamp": parse_timestamp(row["timestamp"]),
            "source_ip": validate_ip(row["source_ip"]),
            "destination_ip": validate_ip(row["destination_ip"]),
            "destination_port": port,
            "protocol": protocol,
            "action": action,
            "log_source": "network",
        })

    return events
