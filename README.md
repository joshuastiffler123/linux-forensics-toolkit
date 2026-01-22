# Forensics Collection Toolkit

A comprehensive suite of Python tools for processing, sorting, and analyzing forensic collection files from Kaseya IZE collections and UAC (Unix-like Artifacts Collector) tarballs.

## Tools Included

| Tool | Description | Use Case |
|------|-------------|----------|
| [**linux_login_timeline.py**](README_linux_login_timeline.md) | Extract and timeline Linux login/authentication events | Login forensics |
| [**linux_binary_analyzer.py**](README_linux_binary_analyzer.md) | Detect suspicious binaries, SUID files, rootkit traces | Malware hunting |
| [**linux_persistence_hunter.py**](README_linux_persistence_hunter.md) | PANIX-style persistence mechanism detection | Persistence hunting |
| [**uac_extractor.py**](README_uac_extractor.md) | Extract UAC tarballs from nested ZIP archives | Evidence prep |
| [**ize_sorter.py**](README_ize_sorter.md) | Sort IZE and UAC files by hostname mapping | Evidence org |

## Requirements

- **Python 3.6+**
- **No external dependencies** - uses only Python standard library

## Quick Start

### 1. Extract UAC Tarballs from Evidence ZIPs

```bash
python uac_extractor.py C:\Evidence\ZipArchives C:\Evidence\ExtractedUAC --keep-zips
```

### 2. Sort Collections by Hostname

```bash
python ize_sorter.py C:\Evidence C:\Mappings\hosts.csv C:\Evidence\Sorted
```

### 3. Generate Login Timelines

```bash
# Single tarball
python linux_login_timeline.py -s server01.tar.gz -o server01_timeline.csv --summary

# Batch process all tarballs
python linux_login_timeline.py --batch C:\Evidence\ExtractedUAC -o C:\Timelines
```

### 4. Analyze Binaries and System Integrity

```bash
# Analyze a UAC tarball for suspicious binaries
python linux_binary_analyzer.py -s server01.tar.gz -o server01_analysis.csv

# With custom known-bad hash list
python linux_binary_analyzer.py -s server01.tar.gz -o analysis.csv --hashes iocs.txt
```

### 5. Hunt for Persistence Mechanisms

```bash
# Detect PANIX-style persistence
python linux_persistence_hunter.py -s server01.tar.gz -o server01_persistence.csv
```

## Complete Workflow

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                         EVIDENCE PROCESSING WORKFLOW                          │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────┐                                                             │
│  │ ZIP Archives │ ──────┐                                                     │
│  │ (nested)     │       │                                                     │
│  └──────────────┘       ▼                                                     │
│                   ┌─────────────────┐                                         │
│                   │ uac_extractor   │ ─────► UAC Tarballs (.tar.gz)          │
│                   │                 │ ─────► Mapping CSV                      │
│                   └─────────────────┘                                         │
│                           │                                                   │
│                           ▼                                                   │
│  ┌──────────────┐   ┌─────────────────┐                                       │
│  │ hosts.csv    │──►│  ize_sorter     │ ─────► Sorted Folders                │
│  │ (mappings)   │   │                 │ ─────► Results CSV + Log             │
│  └──────────────┘   └─────────────────┘                                       │
│                           │                                                   │
│           ┌───────────────┼───────────────────────────┐                       │
│           ▼               ▼                           ▼                       │
│   ┌────────────────┐ ┌────────────────┐ ┌─────────────────────┐               │
│   │ login_timeline │ │ binary_analyzer│ │ persistence_hunter  │               │
│   │                │ │                │ │ (PANIX detection)   │               │
│   └───────┬────────┘ └───────┬────────┘ └──────────┬──────────┘               │
│           │                  │                     │                          │
│           ▼                  ▼                     ▼                          │
│   Timeline CSV         Analysis CSV          Persistence CSV                  │
│   (login events)       (binaries, SUID)      (backdoors, hooks)               │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

## Example Hostname Mapping CSV

Create a CSV file (`hosts.csv`) to map hostnames to products/clients:

```csv
Hostname,Product
SERVER-DC01,Acme_Corp
SERVER-DC02,Acme_Corp
WORKSTATION-SALES,Acme_Corp
SQL-PROD,Beta_Industries
WEB-FRONTEND,Beta_Industries
```

## Output Files

| Tool | Output |
|------|--------|
| **uac_extractor** | Extracted `.tar` files + `uac_mapping_*.csv` |
| **ize_sorter** | Sorted folders + `ize_sorter_results_*.csv` + `ize_sorter_log_*.txt` |
| **linux_login_timeline** | `*_timeline.csv` with all login events |
| **linux_binary_analyzer** | `*_binaries.csv` + `*_environment.csv` |
| **linux_persistence_hunter** | `persistence_findings.csv` with MITRE ATT&CK mappings |

## Security Features

All tools implement OWASP Top 10 security protections:

- ✅ **Path Traversal Prevention** (Zip/Tar slip attacks blocked)
- ✅ **Safe File Extraction** with path validation
- ✅ **Symlink Attack Prevention** in tar files
- ✅ **Proper Exception Handling**

## Tool Details

### linux_login_timeline.py

Parses Linux authentication logs and creates a chronological timeline of:
- SSH logins (password and key-based)
- Failed login attempts
- sudo command execution
- User account changes
- Session activity
- System boot events

**Input:** UAC tarballs, directories, or live filesystem
**Output:** CSV timeline sorted by timestamp

### linux_binary_analyzer.py

Analyzes Linux systems for suspicious binaries, configurations, and persistence:

**Binary Analysis:**
- Programs outside standard OS binary directories
- Hidden executables (in .dot directories)
- Unexpected SUID/SGID files
- LD_PRELOAD/LD.so.conf hijacking (rootkit traces)
- Environment variable analysis
- Hash matching against known-bad IOCs

**Persistence Detection (v1.1.0+):**
- Systemd units (`/etc/systemd/system/`, `/usr/lib/systemd/system/`)
- Cron jobs (`/etc/crontab`, `/etc/cron.d/`, user crontabs)
- Init scripts (`/etc/init.d/`, `/etc/rc.local`)
- Kernel modules (`/etc/modules`, `/etc/modules-load.d/`)
- Udev rules (`/etc/udev/rules.d/`)

**Input:** UAC tarballs, directories, or live filesystem
**Output:** Two CSVs: binaries findings + environment findings

### linux_persistence_hunter.py

**PANIX-style** persistence detection covering all techniques from [PANIX](https://github.com/Aegrah/PANIX):
- Cron/At jobs, systemd timers
- SSH authorized_keys backdoors
- Backdoor users (UID=0)
- Systemd/init.d/rc.local persistence
- Shell profile backdoors (.bashrc, .profile)
- LD_PRELOAD hijacking
- PAM backdoors
- Sudoers modifications
- SUID/capabilities abuse
- Udev rules, XDG autostart
- Web shells
- Rootkit indicators (LKM, hidden files)
- Container escape configs

All findings mapped to **MITRE ATT&CK** technique IDs.

**Input:** UAC tarballs, directories, or live filesystem
**Output:** CSV with technique, severity, and IOC details

### uac_extractor.py

Extracts UAC collection tarballs from:
- Single ZIP files
- Nested ZIP archives (any depth)
- Multiple TAR formats (.tar, .tar.gz, .tgz, .tar.bz2)

**Input:** Directory containing ZIP files
**Output:** Extracted tarballs + mapping CSV

### ize_sorter.py

Sorts Kaseya IZE and UAC TAR files into folders based on:
- Hostname matching against CSV mappings
- Fuzzy matching for partial hostnames
- Client ID extraction from filenames

**Input:** Directory + hostname mapping CSV
**Output:** Organized folders + detailed results CSV

## Command Reference

```bash
# UAC Extractor - Extract tarballs from ZIP archives
python uac_extractor.py <search_dir> <output_dir> [--dry-run] [--keep-zips] [-v]

# IZE Sorter - Sort files by hostname mapping
python ize_sorter.py <search_path> <csv_file> <output_dir> [--threshold N] [--dry-run]

# Login Timeline - Create authentication timeline
python linux_login_timeline.py -s <source> -o <output.csv> [--batch DIR] [--summary]

# Binary Analyzer - Detect suspicious binaries
python linux_binary_analyzer.py -s <source> -o <output.csv> [--hashes iocs.txt]

# Persistence Hunter - Detect PANIX-style persistence
python linux_persistence_hunter.py -s <source> -o <output.csv> [-q]
```

## Tips

1. **Always do a dry run first** to preview what will happen
2. **Use `--verbose` or `--debug`** flags when troubleshooting
3. **Keep source files** with `--keep-zips` until processing is verified
4. **Check the mapping/results CSVs** for audit trail
5. **Lower match threshold** if hostname matching is too strict

## File Structure After Processing

```
C:\Evidence\
├── ZipArchives\              # Original evidence
│   ├── case001.zip
│   └── case002.zip
│
├── ExtractedUAC\             # From uac_extractor
│   ├── server01-C12345-F0001.tar.gz
│   ├── server02-C12345-F0002.tar.gz
│   └── uac_mapping_20241217.csv
│
├── Sorted\                   # From ize_sorter
│   ├── Acme_Corp\
│   │   ├── SERVER-DC01.ize
│   │   └── SERVER-DC02.ize
│   ├── Beta_Industries\
│   │   └── SQL-PROD.tar
│   ├── ize_sorter_results_20241217.csv
│   └── ize_sorter_log_20241217.txt
│
├── Timelines\                # From linux_login_timeline
│   ├── server01_timeline.csv
│   └── server02_timeline.csv
│
├── Analysis\                 # From linux_binary_analyzer
│   ├── server01_binaries.csv
│   └── server01_environment.csv
│
└── Persistence\              # From linux_persistence_hunter
    ├── server01_persistence.csv
    └── server02_persistence.csv
```

## License

Internal forensics toolkit. Handle all evidence data according to your organization's chain of custody and data handling policies.

## Contributing

When making changes:
1. Maintain OWASP security compliance
2. Use only Python standard library
3. Test with both Windows and Linux paths
4. Update relevant README files

