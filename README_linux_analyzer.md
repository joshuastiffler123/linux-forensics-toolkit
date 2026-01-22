# Linux Unified Security Analyzer

## Overview

`linux_analyzer.py` is an orchestrator script that runs all Linux forensic analysis tools simultaneously and outputs correlated results to a unified analysis folder named `[hostname]_analysis`.

## Features

- **Parallel Execution**: Runs all analyzers concurrently for faster processing
- **Unified Output**: All results stored in a single `[hostname]_analysis` folder
- **Hostname Detection**: Automatically extracts hostname from UAC tarball or filesystem
- **Correlated Timeline**: Merges events from all analyzers into a single timeline
- **Summary Report**: Generates a comprehensive summary of all findings

## Included Analyzers

| Analyzer | Description | Output File(s) |
|----------|-------------|----------------|
| Login Timeline | Login/authentication events from system logs | `[hostname]_login_timeline.csv` |
| Journal Analyzer | Systemd journal entries and security events | `[hostname]_journal.csv`, `[hostname]_journal_security.csv` |
| Persistence Hunter | MITRE ATT&CK mapped persistence mechanisms | `[hostname]_persistence.csv` |
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
├── [hostname]_login_timeline.csv      # Login/authentication events
├── [hostname]_journal.csv             # All journal entries
├── [hostname]_journal_security.csv    # Security-relevant journal entries
├── [hostname]_persistence.csv         # Persistence mechanism findings
├── [hostname]_security_binaries.csv   # Suspicious binary findings
├── [hostname]_security_environment.csv # Environment variable findings
├── [hostname]_security_persistence.csv # Security-level persistence findings
├── [hostname]_correlated_timeline.csv  # All events merged and sorted
└── [hostname]_analysis_summary.txt     # Summary report
```

## Correlated Timeline

The `[hostname]_correlated_timeline.csv` file merges events from all analyzers into a single chronological view:

| Column | Description |
|--------|-------------|
| Timestamp | Event timestamp (empty for non-timestamped findings) |
| Source | Which analyzer produced this event |
| Event_Type | Type/category of the event |
| Severity | CRITICAL, HIGH, MEDIUM, LOW, or INFO |
| Username | Associated user (if applicable) |
| Source_IP | Source IP address (if applicable) |
| Hostname | System hostname |
| Description | Event description or message |
| Source_File | Source log file |
| Raw_Data | Raw data/content (truncated) |

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
  ✓ Persistence Hunter (23 findings)
  ✓ Security Analyzer (8 findings)

Creating correlated timeline...
  ✓ Created with 17,110 total events

Creating summary report...

======================================================================
  Analysis Complete
======================================================================

Duration: 12.34 seconds
Analyzers: 4/4 successful
Total Events: 17,079
Total Findings: 31

Output Directory: C:\analysis\webserver_analysis

Generated Files:
  • webserver_analysis_summary.txt (2.1 KB)
  • webserver_correlated_timeline.csv (4.2 MB)
  • webserver_journal.csv (3.8 MB)
  • webserver_journal_security.csv (156.3 KB)
  • webserver_login_timeline.csv (289.4 KB)
  • webserver_persistence.csv (12.7 KB)
  • webserver_security_binaries.csv (4.2 KB)
  • webserver_security_environment.csv (1.8 KB)
```

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

