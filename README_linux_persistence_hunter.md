# Linux Persistence Hunter

A comprehensive persistence detection tool that identifies all techniques implemented by [PANIX](https://github.com/Aegrah/PANIX) and documented in the [Elastic Security Labs Linux Detection Engineering series](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms), mapping all findings to MITRE ATT&CK.

## Features

### 🔍 Detection Coverage (PANIX Techniques)

| Technique | MITRE ATT&CK | Detection |
|-----------|--------------|-----------|
| **At Jobs** | T1053.002 | ✅ Scheduled task persistence |
| **Authorized Keys** | T1098.004 | ✅ SSH key backdoors with forced commands |
| **Backdoor User** | T1136.001 | ✅ UID=0 users, system user shells |
| **Bind/Reverse Shell** | T1059.004 | ✅ Shell patterns in configs |
| **Capabilities** | T1548 | ✅ Dangerous capabilities on binaries |
| **Cron Jobs** | T1053.003 | ✅ Cron backdoors and persistence |
| **D-Bus** | T1543 | ✅ D-Bus service persistence |
| **Generator** | T1543.002 | ✅ Systemd generator persistence |
| **Git Hooks** | T1546 | ✅ Pre/post hook backdoors, pager exploits |
| **GRUB** | T1542 | ✅ Bootloader persistence |
| **Init.d** | T1037 | ✅ SysVinit script backdoors |
| **Initramfs** | T1542 | ✅ Initramfs hook backdoors |
| **LD_PRELOAD** | T1574.006 | ✅ ld.so.preload, ld.so.conf hijacking |
| **LKM Rootkit** | T1547.006 | ✅ Kernel module indicators |
| **Malicious Container** | T1610 | ✅ Docker socket, privileged containers |
| **Malicious Package** | T1546.016 | ✅ APT/YUM/DNF hook scripts |
| **MOTD** | T1037 | ✅ Message-of-the-day script backdoors |
| **NetworkManager** | T1546 | ✅ Dispatcher script backdoors |
| **Package Manager** | T1546.016 | ✅ Pre/post-install hooks |
| **PAM** | T1556.003 | ✅ PAM bypass, pam_exec hooks |
| **Polkit** | T1556 | ✅ Polkit rule privilege escalation |
| **RC.local** | T1037.004 | ✅ RC script persistence |
| **Rootkit** | T1014 | ✅ Known rootkit file/path indicators |
| **Shell Profile** | T1546.004 | ✅ .bashrc/.profile backdoors |
| **SSH Key** | T1098.004 | ✅ Authorized keys manipulation |
| **Sudoers** | T1548.003 | ✅ NOPASSWD, authentication bypass |
| **SUID** | T1548.001 | ✅ Unexpected SUID/SGID binaries |
| **Systemd** | T1543.002 | ✅ Service file persistence |
| **Systemd Timer** | T1053.006 | ✅ Timer-based persistence |
| **Udev** | T1546.017 | ✅ Udev rule persistence |
| **Web Shell** | T1505.003 | ✅ PHP/JSP/Python web shells |
| **XDG Autostart** | T1547.013 | ✅ Desktop autostart entries |
| **Systemd Generators** | T1543.002 | ✅ Generator persistence (from Elastic series) |
| **Socket Activation** | T1543.002 | ✅ Systemd socket triggers |
| **Trap Commands** | T1546.005 | ✅ Shell trap persistence |
| **Message Queues** | T1559 | ✅ IPC-based persistence |
| **eBPF Programs** | T1014 | ✅ eBPF/BPF persistence |
| **Shadow File** | T1098 | ✅ Password hash analysis |
| **LD Cache** | T1574.006 | ✅ Dynamic linker cache |

### 🛡️ Pattern Detection

The tool detects various malicious patterns including:

**Reverse/Bind Shells:**
- Bash TCP redirects (`/dev/tcp/`)
- Netcat/Ncat shells
- Python/Perl/Ruby/PHP sockets
- Socat exec shells
- Named pipe shells

**Obfuscated Commands:**
- Base64 decode piped to shell
- Eval with encoded content
- Remote script execution (curl/wget | bash)

**Web Shells:**
- PHP: eval, assert, system, passthru, shell_exec
- PHP: preg_replace /e modifier, create_function
- JSP: Runtime.getRuntime().exec
- Python: os.system with request parameters

## Requirements

- Python 3.6+
- Standard library only (no external dependencies)

## Installation

```bash
# No installation required
wget https://example.com/linux_persistence_hunter.py
chmod +x linux_persistence_hunter.py
```

## Usage

### Basic Usage

```bash
# Hunt for persistence in a UAC tarball
python linux_persistence_hunter.py -s hostname.tar.gz -o findings.csv

# Hunt in extracted UAC directory
python linux_persistence_hunter.py -s ./extracted_uac/ -o findings.csv

# Hunt on mounted disk image
python linux_persistence_hunter.py -s /mnt/evidence/disk1 -o findings.csv

# Hunt on live system (requires root)
sudo python linux_persistence_hunter.py -s / -o findings.csv
```

### Quiet Mode

```bash
python linux_persistence_hunter.py -s evidence.tar.gz -o findings.csv -q
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-s, --source` | Source path (tarball, directory, or `/` for live) |
| `-o, --output` | Output CSV file path |
| `-q, --quiet` | Suppress progress output |
| `-v, --version` | Show version information |

## Output Format

The CSV output includes:

| Column | Description |
|--------|-------------|
| Filepath | Location of the suspicious file |
| Technique | MITRE ATT&CK technique name |
| MITRE_ATT&CK_ID | MITRE ATT&CK technique ID |
| Severity | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| Description | Human-readable finding description |
| Indicator | Specific IOC or pattern matched |
| Line_Number | Line number in source file |
| Raw_Content | Snippet of suspicious content |
| MD5/SHA256 | File hashes (where applicable) |
| File_Mode | File permissions |
| Extra_Info | Additional context |

## Detection Categories

### 1. Scheduled Tasks
- **Cron**: `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`
- **At Jobs**: `/var/spool/at/*`
- **Systemd Timers**: `*.timer` files with suspicious services

### 2. Account Manipulation
- **Backdoor Users**: UID=0 non-root users, system users with shells
- **SSH Keys**: Forced commands, environment modifications
- **Password Files**: Password hashes in /etc/passwd

### 3. Boot Persistence
- **Init.d**: `/etc/init.d/*` scripts with backdoors
- **RC.local**: Non-trivial content in `/etc/rc.local`
- **Systemd Services**: Suspicious ExecStart commands
- **GRUB**: init= overrides, kernel parameter manipulation
- **Initramfs**: Hook script backdoors

### 4. Shell Configuration
- **Profiles**: `.bashrc`, `.profile`, `.zshrc`
- **System-wide**: `/etc/profile`, `/etc/bash.bashrc`
- **Profile.d**: `/etc/profile.d/*` scripts

### 5. Library Hijacking
- **LD_PRELOAD**: `/etc/ld.so.preload` entries
- **LD.so.conf**: Suspicious library paths
- **Capabilities**: Dangerous caps on binaries

### 6. Authentication
- **PAM**: pam_permit.so, pam_exec.so hooks
- **Sudoers**: NOPASSWD:ALL, authentication bypass
- **Polkit**: Automatic approval rules

### 7. Privilege Escalation
- **SUID/SGID**: Unexpected setuid binaries
- **Capabilities**: CAP_SETUID, CAP_SYS_ADMIN, etc.

### 8. Event-Triggered
- **Udev**: RUN= commands in rules
- **XDG Autostart**: Desktop file Exec= commands
- **Git Hooks**: Pre/post commit hooks, pager exploits
- **Package Hooks**: APT/YUM pre/post-invoke scripts

### 9. Rootkits
- **LKM**: Known rootkit module names
- **Hidden Paths**: Common rootkit file locations
- **Library Trojans**: Size anomalies in system libraries

### 10. Network Services
- **Web Shells**: PHP/JSP/Python shells in web directories
- **D-Bus**: Service files with suspicious paths
- **NetworkManager**: Dispatcher script backdoors
- **Container Escape**: Docker socket exposure, privileged mode

## Severity Levels

| Level | Description |
|-------|-------------|
| **CRITICAL** | Confirmed malicious (rootkit, UID=0 backdoor, ld.so.preload) |
| **HIGH** | Likely malicious (reverse shells, suspicious SUID, web shells) |
| **MEDIUM** | Potentially malicious (unusual configs, review needed) |
| **LOW** | Informational (unusual but may be legitimate) |
| **INFO** | Context for investigation |

## Example Output

```
============================================================
  Linux Persistence Hunter v1.0.0
  PANIX-Style Persistence Detection
============================================================

Source: /path/to/evidence.tar.gz

[1/28] Checking Cron Jobs...
  Found 2 suspicious items
[2/28] Checking At Jobs...
[3/28] Checking Systemd Timers...
...
[11/28] Checking LD_PRELOAD Hijacking...
  Found 1 suspicious items
...

============================================================
  Detection Summary
============================================================

Findings by Severity:
  CRITICAL: 3
  HIGH: 8
  MEDIUM: 4

Findings by Technique:
  Scheduled Task/Job: Cron (T1053.003): 2
  Hijack Execution Flow: Dynamic Linker Hijacking (T1574.006): 1
  Create Account: Local Account (T1136.001): 1
  Event Triggered Execution: Unix Shell Configuration (T1546.004): 3
  ...

Total Findings: 15
Findings exported to: persistence_findings.csv
```

## Integration with Other Tools

### Complete Forensic Workflow

```bash
# 1. Extract login timeline
python linux_login_timeline.py -s evidence.tar.gz -o timeline.csv

# 2. Analyze binaries and system integrity
python linux_binary_analyzer.py -s evidence.tar.gz -o analysis.csv --hashes iocs.txt

# 3. Hunt for persistence mechanisms
python linux_persistence_hunter.py -s evidence.tar.gz -o persistence.csv
```

### Batch Processing

```bash
for tarball in *.tar.gz; do
    echo "Processing $tarball..."
    python linux_persistence_hunter.py -s "$tarball" -o "${tarball%.tar.gz}_persistence.csv" -q
done
```

## References

### Primary Sources
- **PANIX**: https://github.com/Aegrah/PANIX
- **MITRE ATT&CK**: https://attack.mitre.org/

### Elastic Security Labs - Linux Detection Engineering Series
1. **Primer**: https://www.elastic.co/security-labs/primer-on-persistence-mechanisms
2. **Sequel**: https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms
3. **Continuation**: https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms
4. **Approaching Summit**: https://www.elastic.co/security-labs/approaching-the-summit-on-persistence
5. **Grand Finale**: https://www.elastic.co/security-labs/the-grand-finale-on-linux-persistence

### Author Blog
- **Ruben Groenewoud**: https://www.rgrosec.com/

## Security Considerations

- **Path Traversal Protection**: Validates all extracted paths
- **Safe Archive Extraction**: Prevents tar slip attacks
- **Pattern Matching**: Uses compiled regex for efficiency

## Troubleshooting

### Permission Denied
```bash
# Run with elevated privileges for full access
sudo python linux_persistence_hunter.py -s / -o findings.csv
```

### Too Many Findings
Focus on CRITICAL and HIGH severity first:
```bash
# Filter in your CSV viewer or use grep
grep -E "CRITICAL|HIGH" persistence.csv
```

### False Positives
Some findings may be legitimate configurations:
- Review Raw_Content column for context
- Check if paths are expected for your environment
- Correlate with timeline and binary analysis

## Version History

- **1.1.0** - Elastic Security Labs Integration
  - Added techniques from all 5 parts of the Linux Detection Engineering series
  - New detection: Systemd generators
  - New detection: Socket activation persistence
  - New detection: Trap command persistence
  - New detection: Message queue persistence
  - New detection: eBPF/BPF program detection
  - New detection: Shadow file analysis
  - New detection: Dynamic linker cache
  - Enhanced reverse/bind shell patterns
  - Enhanced rootkit indicators
  - Now 35+ detection categories

- **1.0.0** - Initial release
  - Full PANIX technique coverage
  - MITRE ATT&CK mapping
  - UAC tarball and directory support
  - 28 detection categories

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing and incident response only. Misuse of this tool is not condoned and is entirely at the user's own risk.

