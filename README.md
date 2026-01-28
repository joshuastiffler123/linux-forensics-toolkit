# Linux Forensics Toolkit

A comprehensive Python toolkit for analyzing Linux forensic collections from UAC (Unix-like Artifacts Collector) tarballs.

## Overview

This toolkit provides a **unified analyzer** that runs multiple forensic analysis tools in parallel, generating comprehensive reports for incident response and threat hunting.

## Tools Included

| Tool | Description |
|------|-------------|
| **linux_analyzer.py** | Main orchestrator - runs all analyzers in parallel |
| **linux_login_timeline.py** | Login/authentication event timeline |
| **linux_journal_analyzer.py** | Systemd journal analysis |
| **linux_persistence_hunter.py** | PANIX-style persistence detection |
| **linux_security_analyzer.py** | Binary/environment security analysis |

## Requirements

- **Python 3.6+**
- **No external dependencies** - uses only Python standard library

## Quick Start

### Run Full Analysis (Recommended)

```bash
# Analyze a UAC tarball
python linux_analyzer.py -s hostname.tar.gz

# Analyze an extracted directory
python linux_analyzer.py -s ./extracted_uac/

# Specify output directory
python linux_analyzer.py -s hostname.tar.gz -o ./analysis_output/
```

This creates a folder `[hostname]_analysis/` containing all CSV reports.

### Run Individual Tools

```bash
# Login timeline only
python linux_login_timeline.py -s hostname.tar.gz -o timeline.csv

# Persistence hunting only
python linux_persistence_hunter.py -s hostname.tar.gz -o persistence.csv

# Journal analysis only
python linux_journal_analyzer.py -s hostname.tar.gz -o journal.csv

# Security/binary analysis only
python linux_security_analyzer.py -s hostname.tar.gz -o security.csv
```

## Output Files

When running `linux_analyzer.py`, these files are generated:

```
[hostname]_analysis/
├── [hostname]_login_timeline.csv      # Login/auth events (UTC timestamps)
├── [hostname]_journal.csv             # All journal entries
├── [hostname]_journal_security.csv    # Security-relevant journal entries
├── [hostname]_persistence.csv         # ALL scheduled tasks + persistence findings
├── [hostname]_security_all.csv        # Combined security findings
├── [hostname]_security_binaries.csv   # Binary analysis
├── [hostname]_security_environment.csv # Environment analysis
└── [hostname]_analysis_summary.txt    # Summary report
```

## What Each Analyzer Detects

### Login Timeline (`linux_login_timeline.py`)

Parses authentication logs and creates a chronological timeline:
- SSH logins (password and key-based)
- Failed login attempts with source IPs
- sudo command execution
- User account changes
- Session activity (wtmp/btmp/lastlog)
- Bash history with timestamps
- System boot events

**Sources:** `auth.log`, `secure`, `syslog`, `wtmp`, `btmp`, `lastlog`, `.bash_history`

### Journal Analyzer (`linux_journal_analyzer.py`)

Analyzes systemd journal logs:
- All journal entries with proper timestamps
- Security-relevant events filtered separately
- Service start/stop events
- Kernel messages
- Authentication events

**Sources:** `/var/log/journal/` binary journals

### Persistence Hunter (`linux_persistence_hunter.py`)

**Extracts ALL scheduled tasks for review** plus detects suspicious persistence:

| Category | What's Checked |
|----------|----------------|
| **Cron Jobs** | `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.daily/`, `/var/spool/cron/` |
| **Systemd** | Services, timers, generators, socket activation |
| **At Jobs** | `/var/spool/at/` |
| **SSH** | `authorized_keys`, `sshd_config` (PermitRootLogin, etc.) |
| **Users** | Backdoor users (UID=0), `/etc/passwd`, `/etc/shadow` |
| **Shell Profiles** | `.bashrc`, `.profile`, `/etc/profile.d/` |
| **Init Scripts** | `/etc/init.d/`, `/etc/rc.local` |
| **LD_PRELOAD** | `/etc/ld.so.preload`, environment hijacking |
| **PAM** | PAM configuration backdoors |
| **Sudoers** | NOPASSWD rules, suspicious entries |
| **Kernel Modules** | `/etc/modprobe.d/`, `/etc/modules-load.d/` |
| **Dracut** | Initramfs persistence |
| **Docker** | Bind mounts, privileged containers |
| **Environment** | `/etc/environment`, `pam_env.conf` |
| **Code Patterns** | curl/wget/nc/bash -i//dev/tcp patterns |
| **NPM/Python** | postinstall hooks, setup.py, sitecustomize.py |
| **Git Hooks** | Active (non-sample) hooks |
| **IP Connections** | Hardcoded IP:port patterns |
| **Web Shells** | PHP/JSP/ASP shells |

All findings mapped to **MITRE ATT&CK** technique IDs.

### Security Analyzer (`linux_security_analyzer.py`)

Combined binary and persistence analysis:
- Programs outside standard directories
- Hidden executables (in .dot directories)
- SUID/SGID files and capabilities
- Rootkit traces
- Environment variable analysis
- Hash matching against IOCs

## Workflow Diagram

```
                    ┌─────────────────────────┐
                    │   UAC Tarball or        │
                    │   Extracted Directory   │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │   linux_analyzer.py     │
                    │   (Main Orchestrator)   │
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Login         │    │ Journal          │    │ Persistence      │
│ Timeline      │    │ Analyzer         │    │ Hunter           │
└───────┬───────┘    └────────┬─────────┘    └────────┬─────────┘
        │                     │                       │
        ▼                     ▼                       ▼
┌───────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ _login_       │    │ _journal.csv     │    │ _persistence.csv │
│ timeline.csv  │    │ _journal_        │    │ (ALL cron/timers │
│               │    │ security.csv     │    │  + suspicious)   │
└───────────────┘    └──────────────────┘    └──────────────────┘
                                │
                                ▼
                    ┌──────────────────┐
                    │ Security         │
                    │ Analyzer         │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ _security_*.csv  │
                    └──────────────────┘
```

## Examples

### Analyze Multiple Systems

```bash
# Process multiple tarballs
for tarball in *.tar.gz; do
    python linux_analyzer.py -s "$tarball" -o ./results/
done
```

### Quick Persistence Check

```bash
# Just check for persistence mechanisms
python linux_persistence_hunter.py -s evidence.tar.gz -o findings.csv -v
```

### Filter High-Severity Findings

After analysis, filter the CSV for critical/high findings:
```bash
# PowerShell
Import-Csv persistence.csv | Where-Object {$_.Severity -in @('CRITICAL','HIGH')}

# Bash
grep -E "CRITICAL|HIGH" persistence.csv
```

## Timestamp Handling

All timestamps are output in **UTC** for forensic accuracy. A secondary `Timestamp_Local` column shows the analysis machine's local time for reference.

## Security Features

- Path traversal prevention (Zip/Tar slip attacks blocked)
- Safe file extraction with path validation
- Symlink attack prevention
- Proper exception handling
- No external dependencies (supply chain security)

## Documentation

- [linux_analyzer.py](README_linux_analyzer.md) - Main orchestrator details
- [linux_login_timeline.py](README_linux_login_timeline.md) - Login timeline details
- [linux_journal_analyzer.py](README_linux_journal_analyzer.md) - Journal analyzer details
- [linux_persistence_hunter.py](README_linux_persistence_hunter.md) - Persistence hunter details

## License

MIT License. Handle all evidence data according to your organization's chain of custody and data handling policies.
