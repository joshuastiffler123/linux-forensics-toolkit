# Linux Security Analyzer

Comprehensive system security and binary analysis tool for Linux forensics.

## Overview

`linux_security_analyzer.py` combines binary analysis and persistence hunting into a single comprehensive security analyzer. It's automatically run as part of `linux_analyzer.py`.

## Features

### Binary Analysis
- Programs outside standard OS binary directories
- Programs in hidden directories (names starting with ".")
- Unexpected SUID/SGID files and files with capabilities
- Environment variable settings and suspicious modifications
- Hash matches against known-bad indicators
- Rootkit traces (e.g., /etc/ld.so.preload, modified ld.so.conf)

### Persistence Detection
- Systemd units, generators, socket activation
- Cron jobs, at jobs, systemd timers
- Init scripts, rc.local
- SSH authorized_keys backdoors
- Backdoor users (UID=0, suspicious shells)
- Shell profiles (.bashrc, .profile)
- LD_PRELOAD hijacking
- PAM configuration backdoors
- Sudoers modifications
- File capabilities
- Kernel modules (LKM rootkits)
- Udev rules
- XDG autostart entries
- MOTD scripts, Git hooks
- Web shells
- Container escape configurations
- NetworkManager dispatcher, D-Bus services
- Polkit rules, Package manager hooks
- GRUB config, Initramfs hooks
- Shadow file analysis
- eBPF programs, Dynamic linker cache

All findings mapped to **MITRE ATT&CK** technique IDs.

## Usage

### Standalone

```bash
# Analyze a UAC tarball
python linux_security_analyzer.py -s hostname.tar.gz -o findings.csv

# Analyze an extracted directory
python linux_security_analyzer.py -s ./extracted_uac/ -o findings.csv

# With custom IOC hash list
python linux_security_analyzer.py -s hostname.tar.gz -o findings.csv --hashes iocs.txt

# Verbose output
python linux_security_analyzer.py -s hostname.tar.gz -o findings.csv -v
```

### As Part of Main Analyzer

```bash
# Automatically included when running:
python linux_analyzer.py -s hostname.tar.gz
```

## Output

CSV file with columns:
- `Filepath` - Path to the suspicious file
- `Finding_Type` - Type of finding (SUID, hidden, rootkit, etc.)
- `Severity` - CRITICAL, HIGH, MEDIUM, LOW, INFO
- `Description` - Human-readable description
- `MITRE_ATT&CK_ID` - Mapped technique ID
- `Indicator` - Specific IOC found
- `Hash_MD5` / `Hash_SHA256` - File hashes (when applicable)

## What It Checks

### Standard Binary Locations
Files in these locations are expected:
- `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`
- `/usr/local/bin`, `/usr/local/sbin`
- `/opt/*/bin`

Executables found elsewhere are flagged for review.

### SUID/SGID Analysis
Compares against known legitimate SUID files:
- `/usr/bin/passwd`, `/usr/bin/sudo`, `/usr/bin/su`
- `/usr/bin/mount`, `/usr/bin/umount`
- And other standard system binaries

Unknown SUID files are flagged as HIGH severity.

### Rootkit Indicators
Checks for known rootkit artifacts:
- Diamorphine, Reptile, Jynx, Azazel
- Suterusu, Adore-ng, Phalanx
- Hidden kernel modules
- LD_PRELOAD hijacking

## Requirements

- Python 3.6+
- No external dependencies

## License

MIT License
