# Linux Forensics Toolkit

A Python toolkit for analyzing Linux forensic collections (UAC tarballs) and memory dumps.

## Setup

### Windows

```powershell
# 1. Clone the repository
git clone https://github.com/joshuastiffler123/linux-forensics-toolkit.git
cd linux-forensics-toolkit

# 2. (Optional) Setup memory analysis - downloads Volatility 3
python linux_memory_analyzer.py --setup

# 3. Verify installation
python linux_memory_analyzer.py --check
```

### Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/joshuastiffler123/linux-forensics-toolkit.git
cd linux-forensics-toolkit

# 2. (Optional) Setup memory analysis - downloads Volatility 3
python3 linux_memory_analyzer.py --setup

# 3. Verify installation
python3 linux_memory_analyzer.py --check
```

### Requirements

| Component | Requirement |
|-----------|-------------|
| **Disk Forensics** | Python 3.8+ (standard library only - no pip install needed) |
| **Memory Forensics** | Python 3.8+, Git (for auto-setup) |

**No external dependencies required for disk analysis** - works out of the box.

## Quick Start

```bash
# Analyze a UAC collection
python linux_analyzer.py -s hostname.tar.gz

# Analyze with memory dump
python linux_analyzer.py -s hostname.tar.gz -m memory.lime --symbols /path/to/symbols
```

## Tools

### Main Orchestrator

**`linux_analyzer.py`** - Runs all analyzers together and outputs to `[hostname]_analysis/`

```bash
python linux_analyzer.py -s <uac_tarball_or_directory> [options]

Options:
  -s, --source      UAC tarball (.tar.gz) or extracted directory (required)
  -o, --output      Output directory (default: current directory)
  -m, --memory      Memory dump file for memory analysis (optional)
  --symbols         Symbol directory for memory analysis
  --quick-memory    Quick memory triage instead of full analysis
  --sequential      Run analyzers one at a time instead of parallel
  -q, --quiet       Suppress progress output
```

### Disk Forensics Tools

| Tool | Purpose | Key Output |
|------|---------|------------|
| **linux_login_timeline.py** | Extracts login/auth events from logs (auth.log, wtmp, btmp, lastlog, bash_history) | `_login_timeline.csv` |
| **linux_journal_analyzer.py** | Parses systemd journal binary logs | `_journal.csv`, `_journal_security.csv` |
| **linux_persistence_hunter.py** | Detects persistence mechanisms (cron, systemd, SSH keys, etc.) with MITRE ATT&CK mapping | `_persistence.csv` |
| **linux_security_analyzer.py** | Scans for suspicious binaries, SUID files, rootkit traces | `_security_*.csv` |

### Memory Forensics

**`linux_memory_analyzer.py`** - Volatility 3 wrapper for Linux memory dumps

```bash
# First-time setup (downloads Volatility 3)
python linux_memory_analyzer.py --setup

# Check installation
python linux_memory_analyzer.py --check

# Identify kernel version
python linux_memory_analyzer.py -i memory.lime --banner

# Run analysis with local symbols
python linux_memory_analyzer.py -i memory.lime -s /path/to/symbols --offline
```

**Note:** Memory analysis requires symbol tables matching the exact kernel version. Use `--banner` to identify the kernel, then obtain/generate matching symbols.

## Output Structure

```
[hostname]_analysis/
├── [hostname]_login_timeline.csv       # Login/authentication events
├── [hostname]_journal.csv              # Journal entries
├── [hostname]_journal_security.csv     # Security-relevant journal entries
├── [hostname]_persistence.csv          # Scheduled tasks + persistence findings
├── [hostname]_security_*.csv           # Security findings
├── [hostname]_analysis_summary.txt     # Summary report
└── memory_analysis/                    # (if -m provided)
    ├── pslist.csv                      # Running processes
    ├── sockstat.csv                    # Network sockets
    ├── bash_history.csv                # Bash history from memory
    └── ...                             # Additional Volatility plugins
```

## Requirements

- **Python 3.8+**
- **Git** (for memory analyzer setup)
- No external dependencies for disk forensics

## Examples

```bash
# Basic UAC analysis
python linux_analyzer.py -s server.tar.gz

# Full analysis with memory
python linux_analyzer.py -s server.tar.gz -m server.lime --symbols ./symbols/

# Individual tools
python linux_login_timeline.py -s server.tar.gz -o timeline.csv
python linux_persistence_hunter.py -s server.tar.gz -o persistence.csv
python linux_journal_analyzer.py -s server.tar.gz -o journal.csv
python linux_security_analyzer.py -s server.tar.gz -o security.csv
```

## Timestamps

All timestamps are output in **UTC**. A `Timestamp_Local` column shows local time for reference.

## Security

This toolkit follows OWASP security guidelines:

- **No data exfiltration** - All output stays local (CSV files only)
- **No external connections** - Only `git clone` during optional setup
- **No code injection** - No eval/exec, subprocess uses arrays (no shell=True)
- **Path traversal protection** - Safe extraction prevents zip/tar slip attacks
- **No dependencies** - Disk forensics uses Python standard library only
- **Read-only analysis** - Scripts only read forensic data, never modify

## License

MIT License
