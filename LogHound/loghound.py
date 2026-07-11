#!/usr/bin/env python3
"""
LogHound - Linux Security Log Analyzer
========================================
Sniffs out brute-force attempts, privilege abuse, web attack payloads,
and other suspicious activity buried in Linux log files.

Author : Tanvir
License: MIT
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote

VERSION = "1.0.0"

# ----------------------------------------------------------------------
# Terminal colors
# ----------------------------------------------------------------------
class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"

def colorize(text, color, use_color=True):
    if not use_color:
        return text
    return f"{color}{text}{C.END}"

SEVERITY_COLOR = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.GREEN}

BANNER = r"""
   __                _   _                       _
  / /  ___   __ _   | | | | ___  _   _ _ __   __| |
 / /  / _ \ / _` |  | |_| |/ _ \| | | | '_ \ / _` |
/ /__| (_) | (_| |  |  _  | (_) | |_| | | | | (_| |
\____/\___/ \__, |  |_| |_|\___/ \__,_|_| |_|\__,_|
            |___/      Linux Log Analyzer v{ver}
"""

# ----------------------------------------------------------------------
# Regex patterns
# ----------------------------------------------------------------------

SSH_FAILED_PW = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"
)
SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+)"
)
SSH_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"
)
SUDO_CMD = re.compile(
    r"sudo:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)"
)
USER_ADD = re.compile(r"new user: name=(?P<user>\S+)")
USER_DEL = re.compile(r"delete user '(?P<user>\S+)'")
GROUP_ADD = re.compile(r"new group: name=(?P<group>\S+)")
CRON_MOD = re.compile(r"\((?P<user>\S+)\) (?P<action>REPLACE|BEGIN EDIT|END EDIT)")
SESSION_OPEN = re.compile(r"session opened for user (?P<user>\S+)")
SU_FAIL = re.compile(r"FAILED SU.*for (?P<user>\S+) by (?P<by>\S+)")

# Generic syslog timestamp: "Jan 12 08:22:01" or ISO "2026-01-12T08:22:01"
TS_SYSLOG = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
TS_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")

# Combined / common access log format
ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)

ATTACK_PAYLOAD_PATTERNS = {
    "SQL Injection": re.compile(
        r"(\bunion\s+select\b|\bor\s+1=1\b|--\s|sleep\(\d+\)|benchmark\(|information_schema|'.*or.*'.*=.*')",
        re.I,
    ),
    "XSS": re.compile(r"(<script|onerror=|onload=|javascript:|%3Cscript)", re.I),
    "Path Traversal": re.compile(r"(\.\./|\.\.%2f|/etc/passwd|\.\.\\)", re.I),
    "Command Injection": re.compile(r"(;|\||&&)\s*(cat|ls|wget|curl|nc|bash|sh|whoami|id)\b", re.I),
    "LFI/RFI": re.compile(r"(php://|file=.*http|include\(.*\$_)", re.I),
}

SCANNER_AGENTS = re.compile(
    r"(nikto|sqlmap|nmap|nessus|acunetix|dirbuster|gobuster|wpscan|masscan|zgrab|python-requests|curl/)",
    re.I,
)

SENSITIVE_PATHS = re.compile(
    r"(wp-login\.php|wp-admin|\.env$|\.git/|phpmyadmin|xmlrpc\.php|\.aws/credentials|config\.php)",
    re.I,
)


def parse_ts(line):
    m = TS_ISO.search(line) or TS_SYSLOG.search(line)
    return m.group("ts") if m else None


class Finding:
    __slots__ = ("severity", "category", "message", "source", "count", "meta")

    def __init__(self, severity, category, message, source, count=1, meta=None):
        self.severity = severity
        self.category = category
        self.message = message
        self.source = source
        self.count = count
        self.meta = meta or {}

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "source": self.source,
            "count": self.count,
            "meta": self.meta,
        }


class LogHound:
    def __init__(self, brute_threshold=5, notice_top=10):
        self.brute_threshold = brute_threshold
        self.top_n = notice_top
        self.findings = []
        self.stats = {
            "lines_processed": 0,
            "files_processed": 0,
            "failed_logins": 0,
            "accepted_logins": 0,
            "sudo_commands": 0,
            "web_requests": 0,
            "attack_payloads": 0,
        }
        # working state
        self._failed_by_ip = Counter()
        self._failed_by_user = Counter()
        self._invalid_users = Counter()
        self._accepted_by_ip = defaultdict(list)
        self._sudo_by_user = Counter()
        self._sudo_cmds = Counter()
        self._web_status = Counter()
        self._web_ip = Counter()
        self._web_agent = Counter()
        self._web_attacks = defaultdict(list)  # category -> [(ip, path)]
        self._web_scanner_hits = Counter()
        self._web_sensitive_hits = defaultdict(list)
        self._user_events = []

    # ---------------- AUTH / SYSLOG ----------------
    def analyze_auth_log(self, path):
        self._process_file(path, self._auth_line)

    def _auth_line(self, line, source):
        m = SSH_FAILED_PW.search(line)
        if m:
            ip = m.group("ip")
            user = m.group("user")
            self._failed_by_ip[ip] += 1
            self._failed_by_user[user] += 1
            self.stats["failed_logins"] += 1
            return

        m = SSH_INVALID_USER.search(line)
        if m:
            self._invalid_users[m.group("ip")] += 1
            self.stats["failed_logins"] += 1
            return

        m = SSH_ACCEPTED.search(line)
        if m:
            ip = m.group("ip")
            ts = parse_ts(line)
            self._accepted_by_ip[ip].append({"user": m.group("user"), "method": m.group("method"), "ts": ts})
            self.stats["accepted_logins"] += 1
            return

        m = SU_FAIL.search(line)
        if m:
            self.findings.append(
                Finding("MEDIUM", "Privilege Escalation",
                        f"Failed 'su' attempt: {m.group('by')} -> {m.group('user')}", source)
            )
            return

        m = SUDO_CMD.search(line)
        if m:
            self._sudo_by_user[m.group("user")] += 1
            self._sudo_cmds[m.group("cmd").strip()] += 1
            self.stats["sudo_commands"] += 1
            return

        m = USER_ADD.search(line)
        if m:
            self._user_events.append(("USER_ADDED", m.group("user"), parse_ts(line)))
            return

        m = USER_DEL.search(line)
        if m:
            self._user_events.append(("USER_DELETED", m.group("user"), parse_ts(line)))
            return

        m = GROUP_ADD.search(line)
        if m:
            self._user_events.append(("GROUP_ADDED", m.group("group"), parse_ts(line)))
            return

    # ---------------- WEB ACCESS LOG ----------------
    def analyze_access_log(self, path):
        self._process_file(path, self._access_line)

    def _access_line(self, line, source):
        m = ACCESS_LOG_RE.search(line)
        if not m:
            return
        self.stats["web_requests"] += 1
        ip = m.group("ip")
        status = m.group("status")
        path_q = unquote(m.group("path"))
        agent = m.group("agent") or ""

        self._web_status[status] += 1
        self._web_ip[ip] += 1
        if agent:
            self._web_agent[agent] += 1

        if SCANNER_AGENTS.search(agent):
            self._web_scanner_hits[ip] += 1

        if SENSITIVE_PATHS.search(path_q):
            self._web_sensitive_hits[ip].append(path_q)

        for category, pattern in ATTACK_PAYLOAD_PATTERNS.items():
            if pattern.search(path_q):
                self._web_attacks[category].append((ip, path_q))
                self.stats["attack_payloads"] += 1

    # ---------------- FILE DRIVER ----------------
    def _process_file(self, path, handler):
        if not os.path.isfile(path):
            print(colorize(f"[!] File not found, skipping: {path}", C.YELLOW))
            return
        self.stats["files_processed"] += 1
        with open(path, "r", errors="ignore") as f:
            for line in f:
                self.stats["lines_processed"] += 1
                handler(line.rstrip("\n"), path)

    # ---------------- CORRELATION / SCORING ----------------
    def finalize(self):
        # Brute-force by IP
        for ip, count in self._failed_by_ip.items():
            if count >= self.brute_threshold:
                sev = "CRITICAL" if count >= self.brute_threshold * 4 else "HIGH"
                self.findings.append(Finding(
                    sev, "Brute Force",
                    f"{count} failed SSH password attempts from {ip}",
                    "auth log", count, {"ip": ip}
                ))

        # Invalid user probing
        for ip, count in self._invalid_users.items():
            if count >= self.brute_threshold:
                self.findings.append(Finding(
                    "HIGH", "Account Enumeration",
                    f"{count} invalid-user SSH probes from {ip}",
                    "auth log", count, {"ip": ip}
                ))

        # Successful login from an IP that was also brute-forcing = compromise indicator
        for ip, sessions in self._accepted_by_ip.items():
            if self._failed_by_ip.get(ip, 0) >= self.brute_threshold:
                users = ", ".join(sorted({s["user"] for s in sessions}))
                self.findings.append(Finding(
                    "CRITICAL", "Possible Compromise",
                    f"Successful login from {ip} ({users}) after {self._failed_by_ip[ip]} prior failures",
                    "auth log", len(sessions), {"ip": ip}
                ))

        # Sudo usage on risky commands
        risky_cmd_re = re.compile(r"(passwd|useradd|visudo|/etc/shadow|chmod\s+777|nc\s|wget|curl)", re.I)
        for cmd, count in self._sudo_cmds.items():
            if risky_cmd_re.search(cmd):
                self.findings.append(Finding(
                    "MEDIUM", "Sensitive Sudo Command",
                    f"Sudo command executed {count}x: {cmd[:100]}",
                    "auth log", count
                ))

        # User/group account changes
        for kind, name, ts in self._user_events:
            self.findings.append(Finding(
                "MEDIUM", "Account Change",
                f"{kind.replace('_', ' ').title()}: {name}" + (f" at {ts}" if ts else ""),
                "auth log"
            ))

        # Web: attack payloads
        for category, hits in self._web_attacks.items():
            ip_counter = Counter(ip for ip, _ in hits)
            for ip, count in ip_counter.items():
                self.findings.append(Finding(
                    "HIGH", f"Web Attack: {category}",
                    f"{count} {category} attempt(s) detected from {ip}",
                    "access log", count, {"ip": ip}
                ))

        # Web: scanner tools
        for ip, count in self._web_scanner_hits.items():
            self.findings.append(Finding(
                "MEDIUM", "Automated Scanner",
                f"Requests from known scanner/tool user-agent, IP {ip} ({count} hits)",
                "access log", count, {"ip": ip}
            ))

        # Web: sensitive path probing
        for ip, paths in self._web_sensitive_hits.items():
            if len(paths) >= 3:
                self.findings.append(Finding(
                    "MEDIUM", "Sensitive Path Probing",
                    f"{ip} probed {len(paths)} sensitive paths (e.g. {paths[0]})",
                    "access log", len(paths), {"ip": ip}
                ))

        # Web: 404 flood (directory brute force)
        status_by_ip = Counter()
        # recompute per-ip 404 counts via a second pass stored earlier would be ideal;
        # approximate using overall counter for simplicity when only totals are tracked.
        if self._web_status.get("404", 0) >= 50:
            self.findings.append(Finding(
                "LOW", "Possible Directory Brute Force",
                f"{self._web_status['404']} total 404 responses recorded (check top requesters)",
                "access log", self._web_status["404"]
            ))

        # sort worst first
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.findings.sort(key=lambda f: (order.get(f.severity, 9), -f.count))

    # ---------------- OUTPUT ----------------
    def print_console(self, use_color=True):
        print(colorize(BANNER.format(ver=VERSION), C.CYAN, use_color))
        print(colorize(f"Files analyzed : {self.stats['files_processed']}", C.BOLD, use_color))
        print(colorize(f"Lines processed: {self.stats['lines_processed']}", C.BOLD, use_color))
        print()
        print(colorize("=== SUMMARY ===", C.BOLD, use_color))
        for k, v in self.stats.items():
            print(f"  {k.replace('_', ' '):<20}: {v}")
        print()

        if not self.findings:
            print(colorize("No suspicious activity detected.", C.GREEN, use_color))
            return

        print(colorize(f"=== FINDINGS ({len(self.findings)}) ===", C.BOLD, use_color))
        for f in self.findings:
            color = SEVERITY_COLOR.get(f.severity, C.END)
            print(f"[{colorize(f.severity, color, use_color):<18}] {f.category}: {f.message}")

        print()
        print(colorize("=== TOP OFFENDING IPs (SSH) ===", C.BOLD, use_color))
        for ip, count in self._failed_by_ip.most_common(self.top_n):
            print(f"  {ip:<20} {count} failed attempts")

        if self._web_ip:
            print()
            print(colorize("=== TOP WEB CLIENTS ===", C.BOLD, use_color))
            for ip, count in self._web_ip.most_common(self.top_n):
                print(f"  {ip:<20} {count} requests")

    def to_json(self):
        return json.dumps({
            "generated_at": datetime.now().isoformat(),
            "version": VERSION,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
            "top_failed_ssh_ips": self._failed_by_ip.most_common(self.top_n),
            "top_web_ips": self._web_ip.most_common(self.top_n),
            "top_web_agents": self._web_agent.most_common(self.top_n),
        }, indent=2)

    def to_html(self):
        rows = "\n".join(
            f"<tr class='sev-{f.severity.lower()}'><td>{f.severity}</td><td>{f.category}</td>"
            f"<td>{f.message}</td><td>{f.source}</td><td>{f.count}</td></tr>"
            for f in self.findings
        )
        ssh_rows = "\n".join(
            f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in self._failed_by_ip.most_common(self.top_n)
        )
        web_rows = "\n".join(
            f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in self._web_ip.most_common(self.top_n)
        )
        stats_rows = "\n".join(f"<tr><td>{k.replace('_',' ').title()}</td><td>{v}</td></tr>" for k, v in self.stats.items())

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LogHound Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:32px; }}
h1 {{ color:#4fd1c5; }}
h2 {{ color:#9ae6b4; border-bottom:1px solid #333; padding-bottom:6px; margin-top:36px;}}
table {{ border-collapse: collapse; width:100%; margin-top:12px; }}
th, td {{ border:1px solid #2d2d3a; padding:8px 12px; text-align:left; font-size:14px;}}
th {{ background:#1a1d29; }}
.sev-critical {{ background:#4a1414; }}
.sev-high {{ background:#4a2c14; }}
.sev-medium {{ background:#4a4414; }}
.sev-low {{ background:#14304a; }}
.badge {{ font-weight:bold; padding:2px 8px; border-radius:4px; }}
.meta {{ color:#999; font-size:13px; }}
</style></head>
<body>
<h1>🐾 LogHound Security Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Version {VERSION}</p>

<h2>Summary</h2>
<table><tr><th>Metric</th><th>Value</th></tr>{stats_rows}</table>

<h2>Findings ({len(self.findings)})</h2>
<table><tr><th>Severity</th><th>Category</th><th>Message</th><th>Source</th><th>Count</th></tr>
{rows if rows else "<tr><td colspan='5'>No suspicious activity detected.</td></tr>"}
</table>

<h2>Top Offending IPs (SSH)</h2>
<table><tr><th>IP</th><th>Failed Attempts</th></tr>{ssh_rows if ssh_rows else "<tr><td colspan='2'>None</td></tr>"}</table>

<h2>Top Web Clients</h2>
<table><tr><th>IP</th><th>Requests</th></tr>{web_rows if web_rows else "<tr><td colspan='2'>No web logs analyzed</td></tr>"}</table>

</body></html>"""


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="loghound",
        description="LogHound - Linux Security Log Analyzer. Detects brute force, privilege abuse, and web attack patterns in Linux log files.",
    )
    p.add_argument("--auth", action="append", default=[], metavar="FILE",
                   help="Path to an auth/secure log file (e.g. /var/log/auth.log). Can be passed multiple times.")
    p.add_argument("--syslog", action="append", default=[], metavar="FILE",
                   help="Path to a syslog/messages file. Parsed with the same engine as --auth.")
    p.add_argument("--access", action="append", default=[], metavar="FILE",
                   help="Path to a web server access log (Apache/Nginx combined format). Can be passed multiple times.")
    p.add_argument("--threshold", type=int, default=5,
                   help="Number of failed attempts from a single IP before flagging brute force (default: 5)")
    p.add_argument("--top", type=int, default=10, help="Number of top IPs/agents to show (default: 10)")
    p.add_argument("--output", "-o", metavar="PATH", help="Base output path (without extension) for report files")
    p.add_argument("--format", default="console", choices=["console", "json", "html", "all"],
                   help="Output format (default: console)")
    p.add_argument("--no-color", action="store_true", help="Disable colored console output")
    p.add_argument("--version", action="version", version=f"LogHound {VERSION}")
    return p


def main():
    args = build_arg_parser().parse_args()

    if not (args.auth or args.syslog or args.access):
        print(colorize("[!] No log files supplied. Use --auth, --syslog, and/or --access.", C.RED))
        print("    Example: loghound --auth /var/log/auth.log --access /var/log/nginx/access.log")
        sys.exit(1)

    hound = LogHound(brute_threshold=args.threshold, notice_top=args.top)

    for f in args.auth + args.syslog:
        hound.analyze_auth_log(f)
    for f in args.access:
        hound.analyze_access_log(f)

    hound.finalize()

    use_color = not args.no_color

    if args.format in ("console", "all") or not args.output:
        hound.print_console(use_color=use_color)

    if args.output:
        if args.format in ("json", "all"):
            path = f"{args.output}.json"
            with open(path, "w") as fh:
                fh.write(hound.to_json())
            print(colorize(f"[+] JSON report saved: {path}", C.GREEN, use_color))
        if args.format in ("html", "all"):
            path = f"{args.output}.html"
            with open(path, "w") as fh:
                fh.write(hound.to_html())
            print(colorize(f"[+] HTML report saved: {path}", C.GREEN, use_color))
    elif args.format in ("json", "html"):
        print(colorize("[!] --output is required when using --format json/html", C.YELLOW))


if __name__ == "__main__":
    main()
