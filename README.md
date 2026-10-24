
# SentinelSOC — Mini SOC Investigation Lab

A Python-based security monitoring and investigation lab that parses
simulated authentication and network logs, detects suspicious patterns,
and generates evidence-backed alerts and incident reports.

## Overview

SentinelSOC demonstrates foundational Blue Team and Security Operations
Center (SOC) concepts through a small, reproducible offline lab.

The application:
- Parses and normalizes authentication and network events.
- Validates timestamps, IP addresses, protocols, and ports.
- Detects repeated authentication failures.
- Identifies successful logins following repeated failures.
- Flags connections to configurable destination ports.
- Preserves supporting events in every alert.
- Generates JSON alerts and a Markdown investigation report.
- Includes automated tests for parsing, detection, and reporting.

All included events are simulated. This project does not monitor a
live system.

## Technology

- Python 3.10+
- Python standard library
- CSV log processing
- JSON reporting
- Markdown reporting
- unittest automated tests
- Optional pytest test runner
- Git and GitHub

## Project structure

```text
SentinelSOC/
├── src/
│   ├── __init__.py
│   ├── detector.py
│   ├── main.py
│   ├── parser.py
│   └── reporter.py
├── tests/
│   ├── test_detector.py
│   ├── test_parser.py
│   └── test_reporter.py
├── data/
│   ├── auth_logs.csv
│   └── network_logs.csv
├── reports/
│   └── .gitkeep
├── .gitignore
├── requirements-dev.txt
└── README.md
```

## Requirements

- Python 3.10 or later
- PowerShell on Windows, or a compatible terminal
- Git for version control

## Setup on Windows

Clone the repository, then enter the project directory:

```powershell
git clone https://github.com/nunu123567/SentinelSOC.git
cd SentinelSOC
```

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install optional development dependencies:

```powershell
py -m pip install -r requirements-dev.txt
```

The application itself uses only the Python standard library.

## Run the application

From the project root:

```powershell
py -m src.main
```

The program reads:

- `data/auth_logs.csv`
- `data/network_logs.csv`

It writes:

- `reports/alerts.json`
- `reports/incident_report.md`

You can specify alternative input files and an output directory:

```powershell
py -m src.main --auth data/auth_logs.csv --network data/network_logs.csv --output reports
```

## Detection rules

| Rule | Description | Severity |
|---|---|---|
| DET-001 | Five failed logins from one source IP within a rolling five-minute window | High |
| DET-002 | Successful login following at least three failures for the same account and source IP within five minutes | High |
| DET-003 | Connection to a configured watchlisted destination port | Medium |

The initial watchlist contains port `4444`. It can be changed in
`src/detector.py` or supplied to the port detection function.

These rules identify activity that may warrant investigation. They do
not independently establish that an attack or compromise occurred.

## Run the tests

Run the complete test suite using Python's built-in test runner:

```powershell
py -m unittest discover -s tests -v
```

Alternatively, if pytest is installed:

```powershell
py -m pytest -v
```

The test suite covers log parsing, malformed input, detection thresholds,
time-window behaviour, supporting evidence, and report generation.

## Understanding the alerts

Each alert includes:
- Rule identifier and title
- Severity
- Observed timestamp
- Description of the detected behaviour
- Supporting log events

The JSON output is suitable for further processing by other tools.
The Markdown report summarizes the findings and suggests investigation
steps.

## Example investigation workflow

1. Run SentinelSOC against the supplied sample logs.
2. Review the generated alert summaries.
3. Open `reports/incident_report.md`.
4. Examine the supporting events in `reports/alerts.json`.
5. Decide what additional evidence an analyst would need before
   classifying an alert as a true positive or false positive.

## Limitations

- Sample data is simulated and does not represent a real incident.
- Only the configured detection rules are implemented.
- No SIEM integration, threat-intelligence enrichment, or live log
  collection is provided.
- No automated blocking or remediation is performed.
- A flagged port is not inherently malicious.
- Repeated alerts are not fully deduplicated.
- Time-window processing assumes comparable timestamp values and does
  not infer missing timezone information.
- IP validation checks address syntax, not reputation or trustworthiness.
- The tool does not establish user identity or prove account compromise.

## Future improvements

- Add alert deduplication and investigation identifiers.
- Improve timestamp timezone handling and input validation.
- Add configurable detection thresholds.
- Support additional log formats.
- Add alert filtering and summary statistics.
- Explore integration with a SIEM or security automation platform.

## Ethical use

This project is intended for learning, defensive security education,
and analysis of authorized or simulated logs. It does not attempt to
access systems, collect credentials, or automatically take action
against a host.

## Author

Developed as a cybersecurity portfolio project to practise Python,
security event analysis, detection logic, evidence handling, and testing.
