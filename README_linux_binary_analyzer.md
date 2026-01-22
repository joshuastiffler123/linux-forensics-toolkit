# Linux Binary Analyzer

A comprehensive security analysis tool for detecting suspicious binaries, rootkit traces, and configuration anomalies on Linux systems.

## Features

### 🔍 Detection Capabilities

| Category | What It Detects |
|----------|-----------------|
| **Suspicious Locations** | Executables in `/tmp`, `/var/tmp`, `/dev/shm`, `/run` |
| **Hidden Executables** | Files/directories starting with `.` containing executables |
| **SUID/SGID Files** | Unexpected setuid/setgid binaries outside standard locations |
| **Rootkit Traces** | `/etc/ld.so.preload` entries, suspicious `ld.so.conf` paths |
| **Environment Variables** | `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PATH` manipulation |
| **Known-Bad Hashes** | Match files against MD5/SHA256 IOC lists |
| **Suspicious Names** | Known malware/tool names (cryptominers, backdoors, etc.) |

### 🔴 Persistence Mechanism Detection (v1.1.0+)

| Location | What It Checks |
|----------|----------------|
| **Systemd Units** | `/etc/systemd/system/`, `/usr/lib/systemd/system/` - malicious .service files |
| **Cron Jobs** | `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` - scheduled backdoors |
| **Init Scripts** | `/etc/init.d/`, `/etc/rc.local` - boot persistence |
| **Kernel Modules** | `/etc/modules`, `/etc/modules-load.d/` - LKM rootkits |
| **Udev Rules** | `/etc/udev/rules.d/` - hardware-triggered execution |

### 🛡️ Security Analysis

- **Rootkit Detection**: Checks for library preloading attacks
- **Privilege Escalation**: Identifies unexpected SUID/SGID binaries
- **Persistence Mechanisms**: Analyzes systemd, cron, init, kernel modules, and udev
- **Binary Classification**: Distinguishes ELF binaries from scripts
- **Hash Verification**: Supports custom IOC hash lists
- **Pattern Matching**: Detects reverse shells, download-execute, cryptominers

## Requirements

- Python 3.6+
- Standard library only (no external dependencies)

## Installation

```bash
# No installation required - just download the script
wget https://example.com/linux_binary_analyzer.py
chmod +x linux_binary_analyzer.py
```

## Usage

### Basic Usage

```bash
# Analyze a UAC tarball
python linux_binary_analyzer.py -s hostname.tar.gz -o findings.csv

# Analyze extracted UAC directory
python linux_binary_analyzer.py -s ./extracted_uac/ -o findings.csv

# Analyze mounted disk image
python linux_binary_analyzer.py -s /mnt/evidence/disk1 -o findings.csv

# Analyze live system (requires root for full access)
sudo python linux_binary_analyzer.py -s / -o findings.csv
```

### With Custom Hash List

```bash
# Provide known-bad hashes for matching
python linux_binary_analyzer.py -s evidence.tar.gz -o findings.csv --hashes iocs.txt
```

### Quiet Mode

```bash
# Suppress progress output
python linux_binary_analyzer.py -s evidence.tar.gz -o findings.csv -q
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-s, --source` | Source path (tarball, directory, or `/` for live system) |
| `-o, --output` | Output CSV file base name |
| `--hashes` | Path to file containing known-bad hashes |
| `-q, --quiet` | Suppress progress output |
| `-v, --version` | Show version information |

## Output Files

The analyzer generates two CSV files:

### 1. `*_binaries.csv` - Binary and File Findings

| Column | Description |
|--------|-------------|
| Filepath | Full path to the suspicious file |
| Finding_Type | Category of finding |
| Severity | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| Description | Human-readable description |
| MD5 | MD5 hash of file contents |
| SHA256 | SHA256 hash of file contents |
| File_Size | Size in bytes |
| File_Mode | Permission string (e.g., `-rwsr-xr-x`) |
| Owner | File owner UID |
| Group | File group GID |
| Modified_Time | Last modification timestamp |
| Extra_Info | Additional context |

### 2. `*_environment.csv` - Environment Configuration Findings

| Column | Description |
|--------|-------------|
| Source_File | Configuration file path |
| Finding_Type | Category of finding |
| Severity | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| Variable_Name | Environment variable name |
| Variable_Value | Variable value (truncated for long values) |
| Description | Human-readable description |
| Line_Number | Line number in source file |

## Finding Types

### Binary Findings

| Type | Severity | Description |
|------|----------|-------------|
| `KNOWN_BAD_HASH` | CRITICAL | File hash matches known malware |
| `ROOTKIT_LD_PRELOAD` | CRITICAL | ld.so.preload contains library entries |
| `ROOTKIT_LD_CONF` | HIGH | Suspicious path in ld.so.conf |
| `SUSPICIOUS_LOCATION` | HIGH | Executable in temp/runtime directory |
| `HIDDEN_EXECUTABLE` | HIGH | Executable in hidden directory |
| `UNEXPECTED_SUID` | HIGH/MEDIUM | Unexpected SUID binary |
| `UNEXPECTED_SGID` | MEDIUM | Unexpected SGID binary |
| `SUSPICIOUS_NAME` | MEDIUM | Known malware/tool name |

### Persistence Findings (v1.1.0+)

| Type | Severity | Description |
|------|----------|-------------|
| `SYSTEMD_PERSISTENCE` | CRITICAL | Malicious systemd unit file |
| `SYSTEMD_SUSPICIOUS_EXEC` | HIGH | Systemd executes from suspicious path |
| `CRON_PERSISTENCE` | CRITICAL | Malicious cron job |
| `CRON_SUSPICIOUS_ENTRY` | HIGH | Cron runs from /tmp or downloads |
| `INIT_PERSISTENCE` | CRITICAL | Malicious init script |
| `RC_LOCAL_CONTENT` | MEDIUM | Active commands in rc.local |
| `KERNEL_MODULE_SUSPICIOUS` | CRITICAL | Suspicious kernel module configured |
| `KERNEL_MODULE_UNUSUAL_LOCATION` | HIGH | .ko file outside /lib/modules |
| `UDEV_PERSISTENCE` | CRITICAL | Udev rule triggers malicious execution |

### Environment Findings

| Type | Severity | Description |
|------|----------|-------------|
| `ENV_VARIABLE` | Varies | Security-sensitive variable set |
| `SUSPICIOUS_COMMAND` | CRITICAL | Remote script execution pattern |

## Hash List Format

Create a text file with one hash per line:

```
# Comments start with #
d41d8cd98f00b204e9800998ecf8427e
a1b2c3d4e5f6789012345678abcdef01,Cryptominer variant A
b2c3d4e5f6789012345678abcdef0123|Backdoor.Linux.XYZ
c3d4e5f6789012345678abcdef012345 Known rootkit component
```

Supported formats:
- `<hash>`
- `<hash>,<description>`
- `<hash>|<description>`
- `<hash> <description>`
- `<hash>\t<description>`

Both MD5 (32 characters) and SHA256 (64 characters) are supported.

## Checked Locations

### Binary Directories (Standard)
- `/bin`, `/sbin`
- `/usr/bin`, `/usr/sbin`
- `/usr/local/bin`, `/usr/local/sbin`
- `/opt`

### Suspicious Directories
- `/tmp`, `/var/tmp`
- `/dev/shm`
- `/run`, `/var/run`

### Environment Files
- `/etc/environment`, `/etc/profile`
- `/etc/profile.d/*`
- `/etc/bash.bashrc`, `/etc/bashrc`
- `/root/.bashrc`, `/root/.profile`
- `/home/*/.bashrc`, `/home/*/.profile`

### Rootkit Files
- `/etc/ld.so.preload`
- `/etc/ld.so.conf`
- `/etc/ld.so.conf.d/*`

### Persistence Locations (v1.1.0+)

#### Systemd Units
- `/etc/systemd/system/`
- `/usr/lib/systemd/system/`
- `/lib/systemd/system/`
- `/run/systemd/system/`
- `/run/systemd/generator/`

#### Cron Jobs
- `/etc/crontab`
- `/etc/cron.d/`
- `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`
- `/var/spool/cron/`, `/var/spool/cron/crontabs/`

#### Init Scripts
- `/etc/init.d/`
- `/etc/rc.local`
- `/etc/rc0.d/` through `/etc/rc6.d/`

#### Kernel Modules
- `/etc/modules`
- `/etc/modules-load.d/`
- `/etc/modprobe.d/`
- `/lib/modules/` (checks for .ko files in unusual locations)

#### Udev Rules
- `/etc/udev/rules.d/`
- `/lib/udev/rules.d/`
- `/usr/lib/udev/rules.d/`

## Security Considerations

This tool follows OWASP security guidelines:
- **Path Traversal Protection**: Validates all paths before extraction
- **Safe Archive Extraction**: Prevents tar slip attacks
- **Input Validation**: Sanitizes hash list inputs

## Example Output

```
============================================================
  Linux Binary Analyzer v1.1.0
============================================================

Source: /path/to/evidence.tar.gz
Mode: Tarball

[1/10] Checking for rootkit traces...
  [!] ld.so.preload found with entries!

[2/10] Analyzing environment configuration...
  [+] Found 2 issues in etc/profile

[3/10] Scanning for suspicious binaries...
  Checked 15 potential executables

[4/10] Checking SUID/SGID files...
  Found 3 suspicious SUID/SGID files

[5/10] Scanning for hidden executables...
  Found 1 hidden executables

[6/10] Checking systemd units for persistence...
  Found 2 suspicious systemd units

[7/10] Checking cron jobs for persistence...
  Found 1 suspicious cron entries

[8/10] Checking init scripts for persistence...
  Found 0 suspicious init scripts

[9/10] Checking kernel module configurations...
  Found 0 suspicious kernel module configs

[10/10] Checking udev rules for persistence...
  Found 0 suspicious udev rules

============================================================
  Analysis Summary
============================================================

Findings by Severity:
  CRITICAL: 3
  HIGH: 5
  MEDIUM: 2

Findings by Type:
  ROOTKIT_LD_PRELOAD: 1
  SUSPICIOUS_LOCATION: 2
  HIDDEN_EXECUTABLE: 1
  UNEXPECTED_SUID: 2
  SYSTEMD_PERSISTENCE: 2
  CRON_PERSISTENCE: 1
  ENV_VARIABLE: 1

Total Findings: 10
Binary findings exported to: findings_binaries.csv
Environment findings exported to: findings_environment.csv
```

## Troubleshooting

### Permission Denied
Run with elevated privileges for full system analysis:
```bash
sudo python linux_binary_analyzer.py -s / -o findings.csv
```

### Tarball Format Not Recognized
Ensure the tarball has a supported extension:
- `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tbz2`

### Hash Not Matching
- Verify hash format (MD5: 32 chars, SHA256: 64 chars)
- Ensure hashes are lowercase hex characters
- Check for trailing whitespace in hash file

## Integration with Other Tools

### With linux_login_timeline.py
```bash
# Analyze both login activity and binary anomalies
python linux_login_timeline.py -s evidence.tar.gz -o timeline.csv
python linux_binary_analyzer.py -s evidence.tar.gz -o analysis.csv
```

### Batch Processing
```bash
# Analyze multiple UAC tarballs
for tarball in *.tar.gz; do
    python linux_binary_analyzer.py -s "$tarball" -o "${tarball%.tar.gz}_analysis.csv" -q
done
```

## Version History

- **1.1.0** - Persistence Mechanism Detection
  - Systemd unit file analysis
  - Cron job scanning
  - Init script and rc.local detection
  - Kernel module configuration checks
  - Udev rules analysis
  - Pattern matching for reverse shells, download-execute, cryptominers

- **1.0.0** - Initial release
  - Rootkit trace detection
  - Environment variable analysis
  - Suspicious binary location detection
  - SUID/SGID file analysis
  - Hidden executable detection
  - Known-bad hash matching

## License

MIT License


