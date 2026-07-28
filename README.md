# Log Analyzer — SOC Incident Detection Dashboard

A web-based security log analysis tool for SOC analysts to detect attacks, identify threat actors, and map findings to MITRE ATT&CK techniques.

## Features

- Supports Apache Combined Log Format and Common Log Format
- Attack detection — SQL Injection, XSS, Path Traversal, Brute Force, Command Injection, Reconnaissance
- Reconnaissance detection via User-Agent header analysis
- Brute force detection — flags IPs with 10+ failed attempts on login endpoints specifically
- MITRE ATT&CK technique mapping for every alert
- Skipped line tracking — shows how many malformed lines were ignored
- Attack timeline visualization grouped by hour
- Top attacker IP tracking
- Clean state — shows stats even when no threats detected
- PDF report export with multi-page support

## Supported Log Formats

Combined Log Format

192.168.1.1 - - [17/Jul/2026:10:00:01 +0000] "GET /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"

Common Log Format

192.168.1.1 - - [17/Jul/2026:10:00:01 +0000] "GET /login HTTP/1.1" 401 512


## Tech Stack

- Python
- Flask
- ReportLab

## Installation

```bash
git clone https://github.com/ashagmp/log-analyzer.git
cd log-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

Then open your browser at `http://127.0.0.1:5000`

## Detection Logic

- **SQL Injection** — T1190 — checks URL path for SQL keywords and operators
- **XSS** — T1059.007 — checks URL path for script tags and JavaScript execution attempts
- **Path Traversal** — T1083 — checks URL path for directory traversal sequences
- **Brute Force** — T1110 — flags login endpoint requests returning 401/403/404
- **Command Injection** — T1059 — checks URL path for shell command patterns
- **Reconnaissance** — T1595 — checks User-Agent header for known scanning tool signatures

## Legal Disclaimer

This tool is intended for defensive security purposes only. Only analyze logs from systems you own or have explicit permission to monitor.

## Author

Ashag M P
