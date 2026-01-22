# Linux Login Timeline Extractor

A forensic tool for extracting and timelining user login activity, lateral movement indicators, and authentication events from Linux log files.

## Features

- **Multiple Input Sources**
  - UAC (Unix-like Artifacts Collector) tarballs (`.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`)
  - Extracted UAC directories
  - Mounted disk images
  - Live Linux filesystem analysis

- **Log Files Parsed**
  | Log File | Type | Information |
  |----------|------|-------------|
  | `/var/log/btmp*` | Binary | Failed login attempts |
  | `/var/log/utmp` | Binary | Current/active logins |
  | `/var/log/wtmp*` | Binary | Login history & reboots |
  | `/var/log/lastlog` | Binary | Last login for each user |
  | `/var/log/auth.log*` | Text | Authentication (Debian/Ubuntu) |
  | `/var/log/secure*` | Text | Authentication (RHEL/CentOS) |
  | `/var/log/audit/audit.log*` | Text | Audit subsystem logs |
  | `/var/log/messages*` | Text | Syslog messages |
  | `/var/log/syslog*` | Text | System messages |

- **Automatic Features**
  - Auto-detects UAC tarball directory structure
  - Handles `.gz` compressed rotated logs
  - Resolves UIDs to usernames from `/etc/passwd`
  - Sorts events chronologically
  - Batch processing for multiple tarballs

## Requirements

- **Python 3.6+** (standard library only - no pip install needed)

## Installation

No installation required. Simply download and run:

```bash
# Make executable (Linux/Mac)
chmod +x linux_login_timeline.py
```

## Usage

### Basic Usage

```bash
# Parse a UAC tarball
python linux_login_timeline.py -s hostname_2024-12-17.tar.gz -o timeline.csv

# Parse extracted UAC directory
python linux_login_timeline.py -s ./extracted_uac/ -o timeline.csv

# Parse live Linux system (requires root)
sudo python linux_login_timeline.py -o timeline.csv

# Parse mounted disk image
python linux_login_timeline.py -s /mnt/evidence/disk1 -o timeline.csv
```

### Advanced Options

```bash
# With summary statistics
python linux_login_timeline.py -s evidence.tar.gz -o timeline.csv --summary

# Quiet mode (minimal output)
python linux_login_timeline.py -s evidence.tar.gz -o timeline.csv -q

# Batch process all tarballs in a directory
python linux_login_timeline.py --batch ./ExtractedUAC/ -o ./timelines/

# Force tarball mode (if auto-detection fails)
python linux_login_timeline.py -s evidence.tar.gz -o timeline.csv --tarball

# Show version
python linux_login_timeline.py --version
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-s`, `--source` | Source path: UAC tarball, directory, or `/` for live system |
| `-o`, `--output` | Output CSV file path (default: `login_timeline.csv`) |
| `-q`, `--quiet` | Suppress progress output |
| `--summary` | Print summary of collected events |
| `--tarball` | Force tarball mode |
| `--directory` | Force directory mode |
| `--batch DIR` | Batch process all UAC tarballs in directory |
| `-v`, `--version` | Show version |

## Output Format

The script generates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| `timestamp` | Event timestamp (YYYY-MM-DD HH:MM:SS) |
| `event_type` | Event category (see below) |
| `username` | User involved in the event |
| `source_ip` | Remote IP address (lateral movement indicator) |
| `terminal` | TTY/PTY device |
| `pid` | Process ID |
| `description` | Human-readable event description |
| `source_file` | Log file the event came from |
| `raw_data` | Original log line (truncated) |

### Event Types

| Event Type | Description |
|------------|-------------|
| `SSH_LOGIN_PASSWORD` | Successful SSH password authentication |
| `SSH_LOGIN_PUBKEY` | Successful SSH public key authentication |
| `SSH_FAILED_PASSWORD` | Failed SSH password attempt |
| `SSH_INVALID_USER` | SSH attempt with non-existent user |
| `FAILED_LOGIN` | Failed login (from btmp) |
| `USER_LOGIN` | User login (from wtmp) |
| `USER_LOGOUT` | User logout |
| `SUDO_COMMAND` | Sudo command execution |
| `SU_SESSION` | User switch (su) |
| `USER_CREATED` | New user account created |
| `USER_DELETED` | User account deleted |
| `PASSWORD_CHANGED` | Password change |
| `SYSTEM_BOOT` | System boot event |
| `SESSION_OPENED` | Session opened |
| `SESSION_CLOSED` | Session closed |

## Workflow with UAC Extractor

```bash
# Step 1: Extract UAC tarballs from ZIP archives
python uac_extractor.py C:\ZipArchives C:\ExtractedUAC --keep-zips

# Step 2: Generate timelines for all extracted UAC tarballs
python linux_login_timeline.py --batch C:\ExtractedUAC -o C:\Timelines --summary
```

## Security

This tool follows OWASP Top 10 security guidelines:
- **A03/A08**: Path traversal protection (tar slip prevention)
- **A05**: Proper exception handling
- Symlink attacks blocked during extraction

## Examples

### Example Output (Summary)

```
============================================================
  LOGIN/ACTIVITY TIMELINE SUMMARY
============================================================

Hostname: webserver01

Total Events: 1,247
Time Range: 2024-01-15 08:23:45 to 2024-12-17 14:32:11
Duration: 337 days, 6 hours

Event Types:
  SSH_LOGIN_PASSWORD: 423
  SESSION_OPENED: 312
  SUDO_COMMAND: 198
  SSH_FAILED_PASSWORD: 156
  USER_LOGOUT: 98
  ...

Top Users (by activity):
  root: 534
  admin: 312
  deploy: 201

Top Source IPs (lateral movement indicators):
  192.168.1.50: 245
  10.0.0.25: 123
  203.0.113.45: 87 (external)
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No events found | Verify log files exist in `/var/log/` within the source |
| Permission denied | Run with elevated privileges (sudo) for live system |
| Unicode errors | Logs are read with `errors='replace'` - check source encoding |
| Wrong UAC structure | Use `--tarball` flag to force tarball mode |

## License

Internal forensics tool. Handle evidence data according to your organization's policies.


