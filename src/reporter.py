
import json
from pathlib import Path


def json_safe(value):
    """Convert values such as datetimes into JSON-compatible values."""
    if hasattr(value, "isoformat"):
        return value.isoformat()

    raise TypeError(f"Unsupported JSON value: {type(value).__name__}")


def write_json_report(alerts: list[dict], output_path: str) -> None:
    """Save alerts as formatted JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            alerts,
            file,
            indent=2,
            ensure_ascii=False,
            default=json_safe,
        )
        file.write("\n")


def write_incident_report(alerts: list[dict], output_path: str) -> None:
    """Generate a readable Markdown investigation report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# SentinelSOC Investigation Report",
        "",
        "## Executive summary",
        "",
        f"- Total alerts: {len(alerts)}",
        f"- High severity: {sum(a['severity'] == 'high' for a in alerts)}",
        f"- Medium severity: {sum(a['severity'] == 'medium' for a in alerts)}",
        "",
        "This report describes rule-based detections from simulated logs.",
        "Alerts are investigation leads, not proof of malicious activity.",
        "",
        "## Alert details",
        "",
    ]

    if not alerts:
        lines.append("No configured detection rules triggered.")
        lines.append("This does not prove the system is free from threats.")
    else:
        for number, alert in enumerate(alerts, start=1):
            lines.extend([
                f"### {number}. {alert['title']}",
                "",
                f"- **Rule:** {alert['rule_id']}",
                f"- **Severity:** {alert['severity'].upper()}",
                f"- **Observed at:** {alert['timestamp']}",
                f"- **Description:** {alert['description']}",
                f"- **Evidence events:** {len(alert['evidence'])}",
                "",
                "**Supporting evidence:**",
                "",
            ])

            for event in alert["evidence"]:
                evidence = json.dumps(
                    event,
                    ensure_ascii=False,
                    default=json_safe,
                    sort_keys=True,
                )
                lines.append(f"- `{evidence}`")

            lines.extend([
                "",
                "**Recommended investigation:**",
                "",
            ])

            if alert["rule_id"] == "DET-001":
                lines.extend([
                    "- Review authentication records around the alert time.",
                    "- Check whether the source IP is expected or shared.",
                    "- Look for similar attempts against other accounts.",
                ])
            elif alert["rule_id"] == "DET-002":
                lines.extend([
                    "- Confirm whether the successful login was authorized.",
                    "- Review MFA results, device details and session activity "
                    "if those records are available.",
                    "- Check for subsequent suspicious actions.",
                ])
            elif alert["rule_id"] == "DET-003":
                lines.extend([
                    "- Identify the service using the destination port.",
                    "- Confirm whether the connection is expected.",
                    "- Review firewall, endpoint and network records for context.",
                ])
            else:
                lines.append(
                    "- Review the supporting evidence and relevant system logs."
                )

            lines.append("")

    lines.extend([
        "## Scope and limitations",
        "",
        "- The input data is simulated and does not represent a live incident.",
        "- Detection is limited to the configured rules and supplied logs.",
        "- IP reputation, user identity, geolocation and threat intelligence "
        "are not checked.",
        "- No automated blocking or remediation is performed.",
        "- Missing log sources can conceal activity.",
        "- Timestamps are interpreted as provided; timezone offsets are not "
        "inferred.",
        "",
        "## Conclusion",
        "",
        "An analyst must validate each alert using additional evidence before "
        "concluding that an attack or compromise occurred.",
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")
