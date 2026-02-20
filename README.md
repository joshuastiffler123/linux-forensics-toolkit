# Linux Forensics Toolkit

A Python toolkit for incident-response triage of Linux systems. Analyzes
[UAC](https://github.com/tclahr/uac) collections (tarballs or extracted
directories), memory dumps, and standalone forensic artifacts.

**No external dependencies for disk forensics** — pure Python 3.8+ standard
library. Memory forensics uses Volatility 3 (optional, auto-installed on
request).

---

## Quick Install

```bash
# Clone and install — registers the `lfa` CLI command
git clone https://github.com/joshuastiffler123/linux-forensics-toolkit.git
cd linux-forensics-toolkit
./install.sh          # Linux / macOS

# Windows (PowerShell)
pip install -e .
```

After install, `lfa` is available anywhere on your PATH:

```bash
lfa -s hostname.tar.gz
```

### Manual install (no script)

```bash
pip install -e .          # editable — git pull picks up updates automatically
lfa --help
```

### Run without installing

If you prefer not to install, run directly:

```bash
python3 linux_analyzer.py -s hostname.tar.gz
```

---

## Quick Start Examples

```bash
# Basic UAC triage
lfa -s server.tar.gz

# Provide a pre-existing Sleuth Kit bodyfile (skips auto-detection)
lfa -s server.tar.gz --bodyfile server.body

# Cross-reference against a list of known-bad IOCs
lfa -s server.tar.gz --ioc indicators.txt

# Full analysis with memory dump
lfa -s server.tar.gz -m server.lime --symbols ./symbols/

# Batch mode — process every tarball in a directory
lfa -s /cases/tarballs/ -o /cases/results/

# Quiet / scripted mode
lfa -s server.tar.gz -q -o /cases/results/
```

---

## CLI Reference

```
lfa -s <source> [options]

Required:
  -s, --source PATH     UAC tarball (.tar.gz), extracted directory, or a
                        directory containing multiple tarballs (batch mode)

Output:
  -o, --output PATH     Base output directory (default: current directory)
                        Each host creates its own [hostname]_analysis/ folder

Execution:
  --sequential          Run analyzers one at a time (default: parallel)
  -q, --quiet           Suppress all progress output (useful in scripts)

Filesystem timeline:
  --bodyfile PATH       Path to a pre-existing Sleuth Kit bodyfile
                        (MD5|name|inode|...). Bypasses auto-detection and
                        the interactive prompt. Supports .gz bodyfiles.

IOC matching:
  --ioc PATH            Path to an IOC file (one indicator per line).
                        Supported types: IPv4 addresses, domain names,
                        MD5 hashes, SHA-256 hashes, and file paths.
                        Lines starting with # are ignored (comments).

Memory forensics (optional):
  -m, --memory PATH     Memory dump file
  --symbols PATH        Volatility 3 symbol directory (repeatable)
  --quick-memory        Quick triage instead of full memory analysis
```

---

## Analyzers

### Main Orchestrator

**`lfa` / `linux_analyzer.py`** runs all analyzers in parallel and collects
results into a single `[hostname]_analysis/` directory.

---

### Disk Forensics

| Module | What it analyzes | Key output files |
|--------|-----------------|-----------------|
| `linux_login_timeline.py` | auth.log, wtmp, btmp, lastlog, bash\_history, SSH known\_hosts | `_login_timeline.csv` |
| `linux_journal_analyzer.py` | Systemd journal binary logs | `_journal.csv`, `_journal_security.csv` |
| `linux_persistence_hunter.py` | Cron, systemd units, SSH keys, SUID/SGID, startup scripts, sudo rules, at jobs, git hooks, cryptominer indicators — MITRE ATT\&CK tagged | `_persistence.csv` |
| `linux_security_analyzer.py` | Suspicious binaries, rootkit traces, SUID/world-writable files, environment anomalies | `_security_*.csv` |
| `linux_package_analyzer.py` | dpkg, apt, yum, dnf, pacman install/remove logs — flags attacker tooling | `_packages.csv` |
| `linux_network_analyzer.py` | /etc/hosts, resolv.conf, TCP wrappers, UFW logs, ARP cache, Apache/Nginx access logs — flags webshell hits, injection URIs, suspicious UAs | `_network.csv`, `_web_access.csv` |

### Filesystem Timeline (optional)

If a Sleuth Kit bodyfile is found (auto-detected inside the UAC collection,
supplied via `--bodyfile`, or entered at the interactive prompt), the toolkit
generates a full MAC timeline sorted by timestamp:

| Output file | Contents |
|------------|---------|
| `_mac_timeline.csv` | All MAC/B timestamps: Modify, Access, Change, Birth |

### Post-processing

Two post-processing steps run automatically after the main analyzers finish:

| Step | Output |
|------|--------|
| **Log gap detection** | Scans the login timeline for suspicious quiet periods (default threshold: 6 hours) → `_log_gaps.csv` |
| **IOC matching** (`--ioc` required) | Cross-references every generated CSV against supplied indicators → `_ioc_hits.csv` |

### Memory Forensics (optional)

**`linux_memory_analyzer.py`** — Volatility 3 wrapper.

```bash
# First-time Volatility 3 setup
python3 linux_memory_analyzer.py --setup

# Identify kernel version (needed to get symbol tables)
lfa -s collection.tar.gz -m memory.lime --quick-memory

# Full memory analysis
lfa -s collection.tar.gz -m memory.lime --symbols ./symbols/
```

---

## IOC File Format

One indicator per line. Type is auto-detected:

```
# Attacker infrastructure
192.168.1.200
evil-c2.example.com

# Known-bad hashes
d41d8cd98f00b204e9800998ecf8427e
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

# File paths
/tmp/.hidden_backdoor
/usr/local/bin/xmrig
```

Hits are written to `[hostname]_ioc_hits.csv` with columns:
`IOC, IOC_Type, Matched_Value, CSV_File, Row_Number, Full_Row`.

---

## Output Structure

```
[hostname]_analysis/
├── [hostname]_login_timeline.csv     # Login / auth events
├── [hostname]_journal.csv            # All journal entries
├── [hostname]_journal_security.csv   # Security-relevant journal events
├── [hostname]_persistence.csv        # Persistence findings + MITRE tags
├── [hostname]_security_*.csv         # Binary / environment findings
├── [hostname]_packages.csv           # Package install/remove history
├── [hostname]_network.csv            # Network config anomalies
├── [hostname]_web_access.csv         # Scored web access log events
├── [hostname]_mac_timeline.csv       # MAC timeline (if bodyfile available)
├── [hostname]_log_gaps.csv           # Suspicious log quiet periods
├── [hostname]_ioc_hits.csv           # IOC matches (if --ioc provided)
├── [hostname]_analysis_summary.txt   # Human-readable summary report
└── memory_analysis/                  # (if -m provided)
    ├── pslist.csv
    ├── sockstat.csv
    ├── bash_history.csv
    └── ...
```

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| Disk forensics | Python 3.8+ — standard library only |
| Memory forensics | Python 3.8+, Volatility 3, matching kernel symbols |
| Install script | bash, pip |

---

## Individual Tools

Each module can also be run standalone:

```bash
python3 linux_login_timeline.py    -s server.tar.gz -o timeline.csv
python3 linux_persistence_hunter.py -s server.tar.gz -o persistence.csv
python3 linux_journal_analyzer.py  -s server.tar.gz -o journal.csv
python3 linux_security_analyzer.py -s server.tar.gz -o security.csv
python3 linux_package_analyzer.py  -s server.tar.gz -o packages.csv
python3 linux_network_analyzer.py  -s server.tar.gz -o network.csv
```

---

## Security Notes

- **No data exfiltration** — all output stays local (CSV/TXT only)
- **No external connections** — only `git clone` during optional Volatility setup
- **No code injection** — no `eval`/`exec`, subprocess calls use arrays (`shell=False`)
- **Path traversal protection** — safe tarball extraction guards against zip/tar slip
- **Read-only analysis** — scripts only read forensic artifacts, never modify them
- **No mandatory dependencies** — disk forensics uses the Python standard library

---

## License

MIT License
