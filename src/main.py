
import argparse
from pathlib import Path

from src.parser import parse_auth_logs, parse_network_logs
from src.detector import run_detections
from src.reporter import write_json_report, write_incident_report


def main():
    parser = argparse.ArgumentParser(
        description="SentinelSOC: a small offline SOC investigation lab"
    )
    parser.add_argument(
        "--auth",
        default="data/auth_logs.csv",
        help="Path to authentication CSV logs",
    )
    parser.add_argument(
        "--network",
        default="data/network_logs.csv",
        help="Path to network CSV logs",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports",
    )

    args = parser.parse_args()
    output_dir = Path(args.output)

    auth_events = parse_auth_logs(args.auth)
    network_events = parse_network_logs(args.network)

    alerts = run_detections(auth_events, network_events)

    write_json_report(alerts, str(output_dir / "alerts.json"))
    write_incident_report(
        alerts,
        str(output_dir / "incident_report.md"),
    )

    print("SentinelSOC investigation completed.")
    print(f"Authentication events: {len(auth_events)}")
    print(f"Network events: {len(network_events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"JSON alerts: {output_dir / 'alerts.json'}")
    print(f"Incident report: {output_dir / 'incident_report.md'}")


if __name__ == "__main__":
    main()
