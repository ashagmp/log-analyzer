import re
from datetime import datetime
from collections import defaultdict

# Supports both Common and Combined Log Format
LOG_PATTERNS = [
    # Combined Log Format (with referer and user agent)
    re.compile(
        r'(?P<ip>[\w\.\:]+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>.+?) HTTP/\S+" '
        r'(?P<status>\d+) (?P<size>\S+) '
        r'"(?P<referer>[^"]*)" "(?P<useragent>[^"]*)"'
    ),
    # Common Log Format (no referer/user agent)
    re.compile(
        r'(?P<ip>[\w\.\:]+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>.+?) HTTP/\S+" '
        r'(?P<status>\d+) (?P<size>\S+)'
    ),
]

ATTACK_PATTERNS = [
    {
        "name": "SQL Injection",
        "mitre": "T1190",
        "tactic": "Initial Access",
        "severity": "CRITICAL",
        "patterns": [
            r"union.*select", r"select.*from", r"insert.*into",
            r"drop.*table", r"'.*or.*'", r"1=1", r"or 1=1",
            r"--", r"xp_cmdshell", r"waitfor.*delay", r"benchmark\(",
        ]
    },
    {
        "name": "XSS",
        "mitre": "T1059.007",
        "tactic": "Execution",
        "severity": "HIGH",
        "patterns": [
            r"<script", r"javascript:", r"onerror=",
            r"onload=", r"alert\(", r"document\.cookie",
            r"<iframe", r"src=javascript",
        ]
    },
    {
        "name": "Path Traversal",
        "mitre": "T1083",
        "tactic": "Discovery",
        "severity": "HIGH",
        "patterns": [
            r"\.\./", r"\.\.\\", r"%2e%2e",
            r"etc/passwd", r"etc/shadow", r"win/system32",
            r"%252e", r"\.\.%2f",
        ]
    },
    {
        "name": "Brute Force",
        "mitre": "T1110",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "patterns": [
            r"/login", r"/admin", r"/wp-login",
            r"/wp-admin", r"/administrator", r"/auth",
            r"/signin", r"/account/login",
        ]
    },
    {
        "name": "Command Injection",
        "mitre": "T1059",
        "tactic": "Execution",
        "severity": "CRITICAL",
        "patterns": [
            r";.*ls", r";.*cat", r";.*whoami",
            r"\|.*ls", r"\|.*cat", r"&&.*ls",
            r"cmd=", r"exec\(", r"system\(",
            r"/bin/sh", r"/bin/bash",
        ]
    },
    {
        "name": "Reconnaissance",
        "mitre": "T1595",
        "tactic": "Reconnaissance",
        "severity": "MEDIUM",
        "patterns": [
            r"nikto", r"nmap", r"masscan",
            r"sqlmap", r"dirbuster", r"gobuster",
            r"wfuzz", r"burpsuite", r"zgrab",
        ]
    }
]

def parse_line(line):
    """Try all patterns, return first match or None."""
    line = line.strip()
    if not line:
        return None
    for pattern in LOG_PATTERNS:
        match = pattern.match(line)
        if match:
            return {
                "ip":     match.group("ip"),
                "time":   match.group("time"),
                "method": match.group("method"),
                "path":   match.group("path"),
                "status": int(match.group("status")),
                "size":   match.group("size"),
            }
    return None

def detect_attacks(entry):
    """Check path against all attack patterns."""
    detected = []
    path_lower = entry["path"].lower()
    for attack in ATTACK_PATTERNS:
        for pattern in attack["patterns"]:
            if re.search(pattern, path_lower, re.IGNORECASE):
                detected.append({
                    "name":     attack["name"],
                    "mitre":    attack["mitre"],
                    "tactic":   attack["tactic"],
                    "severity": attack["severity"],
                })
                break
    return detected

def detect_brute_force(ip_requests):
    """Flag IPs with 10+ failed requests as persistent brute force."""
    result = []
    for ip, requests in ip_requests.items():
        failed = [r for r in requests if r["status"] in [401, 403, 404]]
        if len(failed) >= 10:
            result.append({
                "ip":       ip,
                "attempts": len(failed),
                "mitre":    "T1110",
                "tactic":   "Credential Access",
                "severity": "HIGH",
            })
    return result

def analyze_logs(content):
    """Main analysis function. Returns full report dictionary."""
    lines        = content.splitlines()
    parsed       = []
    skipped      = 0
    alerts       = []
    ip_requests  = defaultdict(list)
    ip_counts    = defaultdict(int)
    status_counts= defaultdict(int)
    attack_counts= defaultdict(int)
    timeline     = defaultdict(int)

    for line in lines:
        entry = parse_line(line)
        if not entry:
            skipped += 1
            continue

        parsed.append(entry)
        ip_requests[entry["ip"]].append(entry)
        ip_counts[entry["ip"]]   += 1
        status_counts[entry["status"]] += 1

        # Build hourly timeline
        try:
            dt = datetime.strptime(entry["time"], "%d/%b/%Y:%H:%M:%S %z")
            timeline[dt.strftime("%Y-%m-%d %H:00")] += 1
        except Exception:
            pass

        # Detect attacks
        for attack in detect_attacks(entry):
            alerts.append({
                "ip":       entry["ip"],
                "time":     entry["time"],
                "method":   entry["method"],
                "path":     entry["path"],
                "status":   entry["status"],
                **attack,
            })
            attack_counts[attack["name"]] += 1

    brute_force = detect_brute_force(ip_requests)

    # Unique IPs doing brute force from alerts
    brute_force_unique_ips = len(set(
        a["ip"] for a in alerts if a["name"] == "Brute Force"
    ))

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_lines":           len(parsed),
        "skipped_lines":         skipped,
        "total_alerts":          len(alerts),
        "alerts":                alerts,
        "brute_force":           brute_force,
        "brute_force_unique_ips": brute_force_unique_ips,
        "top_ips":               top_ips,
        "status_counts":         dict(status_counts),
        "attack_counts":         dict(attack_counts),
        "timeline":              dict(sorted(timeline.items())),
    }
