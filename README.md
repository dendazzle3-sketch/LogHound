# 🐾 LogHound — Linux Security Log Analyzer

LogHound scans Linux auth logs, syslogs, and web server access logs to detect
brute-force attacks, account abuse, privilege escalation, and web attack
payloads (SQLi, XSS, path traversal, LFI/RFI, command injection). It prints a
color-coded terminal report and can export JSON or HTML reports.

---

## 1. Requirements

- Linux (tested on Ubuntu/Debian/Kali)
- Python 3.6+ (no external pip packages required — standard library only)

Check your Python version:

```bash
python3 --version
```

---

## 2. Installation

### Option A — Run directly

```bash
python3 loghound.py --auth /var/log/auth.log
```

### Option B — Install system-wide as a `loghound` command (recommended)

```bash
chmod +x loghound.py
sudo cp loghound.py /usr/local/bin/loghound
loghound --version
```

Now you can run `loghound` from anywhere, just like any other CLI tool.

---

## 3. Quick Start

```bash
# Analyze SSH/auth log only
loghound --auth /var/log/auth.log

# Analyze SSH log + web server access log together
loghound --auth /var/log/auth.log --access /var/log/nginx/access.log

# On CentOS/RHEL the auth log is usually /var/log/secure
loghound --auth /var/log/secure
```

---

## 4. Full Command Reference

| Flag | Description | Default |
|---|---|---|
| `--auth FILE` | Path to an auth/secure log (e.g. `/var/log/auth.log`, `/var/log/secure`). Repeatable. | — |
| `--syslog FILE` | Path to a syslog/messages file. Uses the same detection engine as `--auth`. Repeatable. | — |
| `--access FILE` | Path to a web server access log (Apache/Nginx **combined** format). Repeatable. | — |
| `--threshold N` | Number of failed attempts from one IP before it's flagged as brute force. | `5` |
| `--top N` | How many top offending IPs / user agents to display. | `10` |
| `--output PATH` | Base file path (no extension) to save the report to. | — |
| `--format {console,json,html,all}` | Output format. | `console` |
| `--no-color` | Disable ANSI colors (useful when piping to a file). | off |
| `--version` | Show version and exit. | — |
| `-h`, `--help` | Show help. | — |

---

## 5. Usage Examples

### 5.1 Basic console scan
```bash
loghound --auth /var/log/auth.log
```

### 5.2 Combine multiple log sources
```bash
loghound \
  --auth /var/log/auth.log \
  --syslog /var/log/syslog \
  --access /var/log/nginx/access.log
```

### 5.3 Lower the brute-force sensitivity (flag after 3 failures instead of 5)
```bash
loghound --auth /var/log/auth.log --threshold 3
```

### 5.4 Save an HTML report you can open in a browser
```bash
loghound --auth /var/log/auth.log --access /var/log/nginx/access.log \
  --output ~/reports/loghound_scan --format html
```
Output: `~/reports/loghound_scan.html`

### 5.5 Save a JSON report (for feeding into SIEM/automation)
```bash
loghound --auth /var/log/auth.log --output ~/reports/scan --format json
```
Output: `~/reports/scan.json`

### 5.6 Generate console + JSON + HTML all at once
```bash
loghound --auth /var/log/auth.log --access /var/log/nginx/access.log \
  --output ~/reports/full_scan --format all
```

### 5.7 Rotate through multiple auth logs (e.g. logrotate archives)
```bash
loghound --auth /var/log/auth.log --auth /var/log/auth.log.1
```

### 5.8 Scheduled daily scan via cron
```bash
# crontab -e
0 6 * * * /usr/local/bin/loghound --auth /var/log/auth.log --access /var/log/nginx/access.log --output /var/reports/daily_$(date +\%F) --format all --no-color
```

---

## 6. What LogHound Detects

**From auth/syslog:**
- 🔴 Brute-force SSH login attempts (grouped by source IP)
- 🔴 Account/username enumeration (invalid user probing)
- 🔴 Successful login from an IP that just brute-forced the box (compromise indicator)
- 🟡 Risky `sudo` command usage (`passwd`, `useradd`, `visudo`, `chmod 777`, etc.)
- 🟡 Failed `su` privilege escalation attempts
- 🟡 User/group creation or deletion events

**From web access logs:**
- 🔴 SQL Injection payloads
- 🔴 Cross-Site Scripting (XSS) payloads
- 🔴 Path traversal attempts
- 🔴 Command injection / LFI-RFI patterns
- 🟡 Known scanner tool signatures (sqlmap, nikto, nmap, dirbuster, wpscan, etc.)
- 🟡 Sensitive path probing (`wp-login.php`, `.env`, `.git/`, `phpmyadmin`, etc.)
- 🟢 Possible directory brute-force (high 404 volume)

Findings are sorted **CRITICAL → HIGH → MEDIUM → LOW** so the worst issues appear first.

---

## 7. Sample Output

```
=== FINDINGS (12) ===
[CRITICAL] Possible Compromise: Successful login from 45.33.12.10 (root) after 8 prior failures
[HIGH    ] Brute Force: 8 failed SSH password attempts from 45.33.12.10
[HIGH    ] Web Attack: SQL Injection: 1 SQL Injection attempt(s) detected from 198.51.100.9
[MEDIUM  ] Sensitive Path Probing: 203.0.113.5 probed 3 sensitive paths (e.g. /wp-login.php)
```

---

## 8. Notes & Limitations

- Web log parsing expects Apache/Nginx **combined** log format. Custom log formats may need regex adjustments.
- LogHound reads log files it has permission to access — run with `sudo` if reading `/var/log/auth.log` as a non-root user.
- This is a **detection/triage** tool, not a replacement for a full SIEM — use findings as a starting point for investigation.

---

## 9. Uninstall

```bash
sudo rm /usr/local/bin/loghound
```
