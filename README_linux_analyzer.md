# Linux Unified Security Analyzer

## Overview

`linux_analyzer.py` is an orchestrator script that runs all Linux forensic analysis tools simultaneously and outputs results to a unified analysis folder named `[hostname]_analysis`.

## Features

- **Parallel Execution**: Runs all analyzers concurrently for faster processing
- **Unified Output**: All results stored in a single `[hostname]_analysis` folder
- **Hostname Detection**: Automatically extracts hostname from UAC tarball or filesystem
- **Summary Report**: Generates a comprehensive summary of all findings

## Included Analyzers

| Analyzer | Description | Output File(s) |
|----------|-------------|----------------|
| Login Timeline | Login/authentication events from system logs | `[hostname]_login_timeline.csv` |
| Journal Analyzer | Systemd journal entries and security events | `[hostname]_journal.csv`, `[hostname]_journal_security.csv` |
| Persistence Hunter | ALL scheduled tasks + persistence mechanisms | `[hostname]_persistence.csv` |
| Security Analyzer | Binary/environment security analysis | `[hostname]_security_*.csv` |

## Installation

```bash
# No installation required - standard library only
# Ensure all analyzer scripts are in the same directory
```

## Usage

### Basic Usage

```bash
# Analyze a UAC tarball
python linux_analyzer.py -s hostname.tar.gz

# Analyze an extracted UAC directory
python linux_analyzer.py -s ./extracted_uac/
```

### Output Directory

```bash
# Specify custom output directory
python linux_analyzer.py -s hostname.tar.gz -o ./analysis_results/
```

### Sequential Mode

```bash
# Run analyzers one at a time (not in parallel)
python linux_analyzer.py -s hostname.tar.gz --sequential
```

### Quiet Mode

```bash
# Suppress progress output
python linux_analyzer.py -s hostname.tar.gz -q
```

## Output Structure

```
[hostname]_analysis/
├── [hostname]_login_timeline.csv       # Login/authentication events (UTC)
├── [hostname]_journal.csv              # All journal entries
├── [hostname]_journal_security.csv     # Security-relevant journal entries
├── [hostname]_persistence.csv          # ALL cron/timers + persistence findings
├── [hostname]_security_all.csv         # Combined security findings
├── [hostname]_security_binaries.csv    # Suspicious binary findings
├── [hostname]_security_environment.csv # Environment variable findings
└── [hostname]_analysis_summary.txt     # Summary report
```

## Persistence Output

The `[hostname]_persistence.csv` file now includes **ALL scheduled tasks** for review:

| Severity | Meaning |
|----------|---------|
| INFO | Normal scheduled task (cron job, systemd timer, etc.) - for review |
| LOW/MEDIUM | Potentially suspicious configuration |
| HIGH | Likely malicious pattern detected |
| CRITICAL | Known malicious indicator (reverse shell, rootkit, etc.) |

This allows you to see the complete picture of what's scheduled on the system.

## Command Line Options

```
usage: linux_analyzer.py [-h] -s SOURCE [-o OUTPUT] [--sequential] [-q] [-v]

options:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Source: UAC tarball (.tar.gz) or extracted directory
  -o OUTPUT, --output OUTPUT
                        Output base directory (default: current directory)
  --sequential          Run analyzers sequentially instead of in parallel
  -q, --quiet           Suppress progress output
  -v, --version         show program's version number and exit
```

## Example Output

```
======================================================================
  Linux Unified Security Analyzer v1.0.0
======================================================================

Source: C:\evidence\webserver-uac-20250102.tar.gz
Hostname: webserver
Mode: Tarball
Output Directory: C:\analysis\webserver_analysis

Running 4 analyzers in parallel...
  ✓ Login Timeline (1,247 events)
  ✓ Journal Analyzer (15,832 events)
  ✓ Persistence Hunter (156 findings)  # Includes ALL cron jobs
  ✓ Security Analyzer (8 findings)

Creating summary report...

======================================================================
  Analysis Complete
======================================================================

Duration: 12.34 seconds
Analyzers: 4/4 successful
Total Events: 17,079
Total Findings: 164

Output Directory: C:\analysis\webserver_analysis

Generated Files:
  • webserver_analysis_summary.txt (2.1 KB)
  • webserver_journal.csv (3.8 MB)
  • webserver_journal_security.csv (156.3 KB)
  • webserver_login_timeline.csv (289.4 KB)
  • webserver_persistence.csv (45.2 KB)
  • webserver_security_all.csv (8.4 KB)
  • webserver_security_binaries.csv (4.2 KB)
  • webserver_security_environment.csv (1.8 KB)
```

## Timestamp Handling

All timestamps are output in **UTC** for forensic consistency. A secondary `Timestamp_Local` column is provided for reference showing the analysis machine's local time.

## Requirements

- Python 3.6+
- Standard library only (no external dependencies)
- All analyzer scripts must be in the same directory:
  - `linux_login_timeline.py`
  - `linux_journal_analyzer.py`
  - `linux_persistence_hunter.py`
  - `linux_security_analyzer.py`

## License

MIT License
