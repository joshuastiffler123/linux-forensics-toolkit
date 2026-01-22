# Linux Journal Analyzer

Parse and analyze systemd journal logs from UAC tarballs, directories, or exported journal files.

## Version
1.0.0

## Features

- **Multiple Format Support**
  - Text journalctl exports (default `journalctl` output)
  - JSON journalctl exports (`journalctl -o json`)
  - UAC tarball journal collections
  - Binary journal file detection (with export recommendations)

- **Smart Categorization**
  - Authentication events (success/failure)
  - SSH activity
  - Sudo commands
  - User management (useradd, passwd, etc.)
  - Service start/stop events
  - Boot/shutdown events
  - Cron jobs
  - Network changes
  - Firewall activity
  - Kernel messages
  - Audit events
  - Security alerts

- **Flexible Filtering**
  - Time range (`--since`, `--until`)
  - Unit/service (`--unit`)
  - Priority level (`--priority`)
  - Keyword search (`--grep`)
  - Category filter (`--category`)
  - Security-only mode (`--security`)

- **Automatic Output Naming**
  - CSVs named after source hostname
  - Separate security event export

## Installation

No additional dependencies required - uses Python 3 standard library only.

```bash
# Make executable (Linux/macOS)
chmod +x linux_journal_analyzer.py
```

## Usage

### Basic Analysis

```bash
# Analyze a UAC tarball
python linux_journal_analyzer.py -s hostname.tar.gz

# Analyze a directory
python linux_journal_analyzer.py -s /path/to/extracted/uac/

# Custom output directory
python linux_journal_analyzer.py -s hostname.tar.gz -o ./results/
```

### Security-Focused Analysis

```bash
# Export only security-relevant events
python linux_journal_analyzer.py -s hostname.tar.gz --security

# Filter for authentication failures
python linux_journal_analyzer.py -s hostname.tar.gz --category AUTH_FAILURE

# Search for specific patterns
python linux_journal_analyzer.py -s hostname.tar.gz --grep "failed password,invalid user"
```

### Filtering Options

```bash
# Time range filter
python linux_journal_analyzer.py -s hostname.tar.gz --since "2024-12-01" --until "2024-12-17"

# Filter by service/unit
python linux_journal_analyzer.py -s hostname.tar.gz --unit sshd,sudo,cron

# Filter by priority (shows this level and higher)
python linux_journal_analyzer.py -s hostname.tar.gz --priority err

# Combine multiple filters
python linux_journal_analyzer.py -s hostname.tar.gz --unit sshd --priority warning --since "2024-12-01"
```

### Priority Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | EMERG | System is unusable |
| 1 | ALERT | Action must be taken immediately |
| 2 | CRIT | Critical conditions |
| 3 | ERR | Error conditions |
| 4 | WARNING | Warning conditions |
| 5 | NOTICE | Normal but significant |
| 6 | INFO | Informational |
| 7 | DEBUG | Debug-level messages |

### Categories

| Category | Description |
|----------|-------------|
| AUTH_SUCCESS | Successful authentication |
| AUTH_FAILURE | Failed authentication attempts |
| SUDO | Sudo command execution |
| SSH | SSH connection events |
| USER_MGMT | User/group management |
| SERVICE | Service start/stop/reload |
| BOOT_SHUTDOWN | System boot and shutdown |
| CRON | Cron job execution |
| NETWORK | Network configuration changes |
| FIREWALL | Firewall rules and blocks |
| KERNEL | Kernel messages |
| AUDIT | Audit subsystem events |
| SECURITY | Security-related alerts |
| DISK_STORAGE | Disk and filesystem events |
| GENERAL | Other events |

## Output Files

The script generates CSV files named after the source hostname:

| File | Contents |
|------|----------|
| `<hostname>_journal.csv` | All parsed journal entries |
| `<hostname>_journal_security.csv` | Security-relevant events only |

### CSV Columns

- **Timestamp** - Event timestamp
- **Hostname** - Source hostname
- **Unit** - Systemd unit or service name
- **Priority** - Numeric priority (0-7)
- **Priority_Name** - Priority name (EMERG, ALERT, etc.)
- **Category** - Event category
- **Syslog_Identifier** - Syslog identifier
- **PID** - Process ID
- **UID** - User ID
- **Command** - Command name
- **Message** - Log message
- **Source_File** - Source file within tarball
- **Boot_ID** - Boot ID (first 8 chars)

## Exporting Journals for Analysis

For best results, export journals on the source system before collection:

```bash
# Export as JSON (recommended - most complete)
journalctl --no-pager -o json > /tmp/journal_export.json

# Export as text (human-readable)
journalctl --no-pager > /tmp/journal_export.txt

# Export specific time range
journalctl --since "2024-12-01" --until "2024-12-17" -o json > /tmp/journal_export.json

# Export specific unit
journalctl -u sshd -o json > /tmp/sshd_journal.json

# Include all boots
journalctl --no-pager -o json --boot=all > /tmp/all_boots.json
```

## UAC Integration

The script automatically searches for journal data in UAC tarball locations:

- `live_response/process/journal*`
- `live_response/process/journalctl*.txt`
- `live_response/process/journalctl*.json`
- `var/log/journal/` (binary journals)
- `run/log/journal/` (binary journals)

## Example Output

```
============================================================
  Linux Journal Analyzer v1.0.0
============================================================

Source: server01.tar.gz
Hostname: server01
Mode: Tarball

Parsing journal entries...
  Found 15847 entries

Analyzing 15847 journal entries...

============================================================
  Journal Analysis Summary
============================================================

Total Entries: 15847
Security Events: 523
High Priority (ERR+): 89

By Priority:
  ERR: 89
  WARNING: 234
  NOTICE: 1205
  INFO: 14319

By Category:
  GENERAL: 12456
  SERVICE: 1823
  AUTH_SUCCESS: 312
  SSH: 289
  AUTH_FAILURE: 156
  SUDO: 134
  KERNEL: 89
  CRON: 67

Exported 15847 entries to: server01_journal.csv
Exported 523 entries to: server01_journal_security.csv

Analysis complete!
```

## Security Event Detection

The analyzer identifies security-relevant events including:

### Authentication
- Successful/failed password authentication
- SSH key authentication
- PAM authentication events
- Session open/close

### Privilege Escalation
- Sudo command execution
- Su usage
- Pkexec invocations

### User Management
- User creation/modification/deletion
- Group changes
- Password changes

### System Changes
- Service modifications
- Firewall rule changes
- Security policy updates

## Troubleshooting

### No entries found

1. **Binary journals only**: The script detects binary journals but cannot fully parse them. Export as text/JSON on the source system.

2. **Wrong path**: Check that journal exports are in expected locations within the tarball.

3. **Permissions**: Ensure read access to journal files.

### Timestamp issues

- Journal entries without years default to current year
- UTC timestamps are converted to local time zone naive datetimes

## Related Tools

- `linux_login_timeline.py` - Authentication log analysis
- `linux_security_analyzer.py` - Binary and persistence analysis
- `linux_persistence_hunter.py` - Persistence mechanism detection

## License

Part of the Linux Forensics Toolkit


