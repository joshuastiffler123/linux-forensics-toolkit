#!/usr/bin/env python3
"""
Linux Unified Security Analyzer - Orchestrator Script

Runs all Linux forensic analysis tools in parallel and outputs
results to a unified analysis folder named [hostname]_analysis.

Included Analyzers:
- linux_login_timeline.py       - Login/authentication timeline
- linux_journal_analyzer.py     - Systemd journal analysis
- linux_persistence_hunter.py   - Persistence mechanism detection
- linux_security_analyzer.py    - Binary/environment security analysis
- linux_filesystem_timeline.py  - Filesystem timeline (bodyfile/mactime)
- linux_string_analyzer.py      - Log carving & string extraction
- linux_misc_artifacts.py       - Archive files, hidden dirs, scheduled tasks
- linux_ioc_scanner.py          - IOC string matching (optional, requires IOC file)
- linux_memory_analyzer.py      - Memory forensics (optional, requires memory dump)

Author: Security Tools
Version: 2.0.0
License: MIT

Requirements: Python 3.6+ (standard library only)
             Volatility 3 (optional, for memory analysis)
"""

import argparse
import csv
import os
import re
import sys
import tarfile
import tempfile
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "2.0.0"


# Ensure sibling modules are importable (direct execution & editable installs)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lft_style import Style
from lft_uac import UACHandler


# ============================================================================
# Forensic Audit Logger
# ============================================================================

# Metadata for every analyzer: what it does, what it examines, what analysts
# should look for.  Written to [hostname]_audit.log alongside the CSVs.

ANALYZER_METADATA = {
    "Login Timeline": {
        "purpose": (
            "Extract authentication and login events to build a user activity "
            "timeline.  Essential for identifying unauthorized access, lateral "
            "movement, and privilege escalation."
        ),
        "examines": [
            "/var/log/auth.log*          — SSH logins, sudo, PAM events",
            "/var/log/secure*            — RHEL/CentOS equivalent of auth.log",
            "/var/log/wtmp               — Successful logins (binary utmp format)",
            "/var/log/btmp               — Failed login attempts (binary)",
            "/var/log/lastlog            — Last login timestamp per user",
            "/var/log/audit/audit.log*   — Linux Audit Framework events",
            "/var/log/syslog*            — General system log (Debian/Ubuntu)",
            "/var/log/messages*          — General system log (RHEL/CentOS)",
            "/home/*/.bash_history       — Per-user command history",
            "/root/.bash_history         — Root command history",
        ],
        "searches_for": [
            "SSH session open/close (sshd Accepted/Failed/Invalid user)",
            "sudo/su privilege escalation attempts",
            "Failed authentication patterns (brute force indicators)",
            "User/group creation or modification (useradd, usermod, passwd)",
            "Account lockouts and PAM failures",
        ],
        "analyst_guidance": [
            "Look for logins outside normal business hours",
            "SSH from unexpected source IPs or countries",
            "Multiple failed attempts followed by a success (brute force)",
            "sudo/su usage by non-administrative accounts",
            "Commands run as root that don't match normal admin activity",
            "Gaps in bash_history (may indicate history clearing)",
        ],
    },
    "Journal Analyzer": {
        "purpose": (
            "Parse systemd journal binary logs for service events, kernel "
            "messages, and security-relevant entries that may not appear in "
            "traditional syslog files."
        ),
        "examines": [
            "/var/log/journal/           — Systemd binary journal files",
            "/run/log/journal/           — Volatile journal (lost on reboot)",
            "Exported journalctl text/JSON output (if present in UAC)",
        ],
        "searches_for": [
            "Service start/stop/crash events (systemctl)",
            "Kernel messages (OOM killer, segfaults, module loads)",
            "Security-relevant events (authentication, authorization)",
            "Boot/shutdown sequences",
            "Failed unit activations",
        ],
        "analyst_guidance": [
            "Services started or stopped near incident time",
            "Kernel module load events (potential rootkit)",
            "OOM kills or segfaults in critical services",
            "Entries at EMERG/ALERT/CRIT priority levels",
            "Journal entries reference the security-filtered CSV for high-signal events",
        ],
    },
    "Persistence Hunter": {
        "purpose": (
            "Detect attacker persistence mechanisms across 30+ techniques, "
            "each mapped to MITRE ATT&CK.  This is often the highest-value "
            "output for IR because persistence survives reboots."
        ),
        "examines": [
            "/etc/cron.*  /var/spool/cron/   — Scheduled tasks (cron)",
            "/var/spool/at/                  — At job queue",
            "/etc/systemd/system/            — Systemd services and timers",
            "/etc/init.d/  /etc/rc.local     — Init scripts",
            "~/.ssh/authorized_keys          — SSH public keys",
            "~/.bashrc ~/.profile ~/.zshrc   — Shell profile persistence",
            "/etc/ld.so.preload              — LD_PRELOAD hijacking",
            "/etc/pam.d/                     — PAM configuration (backdoors)",
            "/etc/sudoers  /etc/sudoers.d/   — Sudo rule modifications",
            "/etc/udev/rules.d/             — Udev rule persistence",
            "~/.config/autostart/           — XDG autostart entries",
            ".git/hooks/                    — Git hook persistence",
            "/etc/update-motd.d/            — MOTD execution on login",
            "/etc/polkit-1/                 — Polkit privilege rules",
            "APT/DNF/YUM hooks              — Package manager hook persistence",
            "/lib/modules/                  — Kernel module (LKM rootkit)",
            "Web-accessible directories     — Webshell detection",
            "Process list (UAC live_response) — Running cryptominers",
        ],
        "searches_for": [
            "Known miner binaries (xmrig, cpuminer, ethminer, etc.)",
            "Mining pool stratum:// URLs and pool domains",
            "Cryptocurrency wallet addresses (XMR, ETH, BTC)",
            "Reverse shell patterns (bash -i, /dev/tcp/, nc -e)",
            "Curl/wget one-liners downloading to /tmp",
            "SUID/SGID bits on unexpected binaries",
            "UID=0 backdoor accounts",
            "Authorized SSH keys not matching known users",
            "LD_PRELOAD/LD_LIBRARY_PATH environment hijacking",
            "Suspicious cron entries running scripts from /tmp or /dev/shm",
        ],
        "analyst_guidance": [
            "CRITICAL severity findings need immediate investigation",
            "Any unknown cron job or systemd service warrants review",
            "SSH authorized_keys with unfamiliar key comments",
            "Cryptominer hits indicate resource hijacking (T1496)",
            "Check raw_scheduled_tasks/ subdirectory for full file contents",
            "Cross-reference persistence timestamps with login timeline",
        ],
    },
    "Security Analyzer": {
        "purpose": (
            "Scan for suspicious binaries, SUID files, rootkit indicators, "
            "and environment anomalies.  Focuses on the filesystem state "
            "rather than log history."
        ),
        "examines": [
            "/tmp/ /var/tmp/ /dev/shm/      — World-writable temp directories",
            "/usr/local/bin/ /usr/local/sbin/ — Non-packaged binaries",
            "/etc/systemd/  /etc/init.d/     — Service configurations",
            "/etc/cron.*  /var/spool/cron/   — Scheduled task files",
            "/lib/modules/  /etc/modprobe.d/ — Kernel module configs",
            "/etc/udev/rules.d/             — Udev rules",
        ],
        "searches_for": [
            "SUID/SGID binaries outside standard locations",
            "World-writable directories with executables",
            "LD_PRELOAD hijacking (/etc/ld.so.preload)",
            "Hidden files/directories in system paths",
            "Binaries in /tmp or /dev/shm",
            "Rootkit file/directory indicators",
            "Suspicious file permissions (e.g. chmod 4755 in /tmp)",
        ],
        "analyst_guidance": [
            "SUID files in /tmp or /home are almost always malicious",
            "Any binary in /dev/shm is highly suspicious",
            "LD_PRELOAD entries can hide processes and files (userland rootkit)",
            "Cross-reference suspicious binaries with hash IOCs",
        ],
    },
    "Package Analyzer": {
        "purpose": (
            "Parse package manager logs (dpkg, apt, yum, dnf, pacman) to "
            "identify software installations, especially attacker tooling "
            "installed post-compromise."
        ),
        "examines": [
            "/var/log/dpkg.log*             — Debian/Ubuntu package operations",
            "/var/log/apt/history.log*       — APT install/remove history",
            "/var/log/apt/term.log*          — APT terminal output",
            "/var/log/yum.log*               — CentOS/RHEL 6-7 packages",
            "/var/log/dnf.log*               — CentOS/RHEL 8+, Fedora packages",
            "/var/log/pacman.log*            — Arch Linux packages",
            "/var/log/zypper.log*            — openSUSE packages",
        ],
        "searches_for": [
            "Known attacker tools: nmap, masscan, nikto, gobuster, sqlmap",
            "Post-exploitation kits: metasploit, linpeas, pspy",
            "Tunneling tools: chisel, ligolo, ngrok, socat",
            "Cryptominer packages: xmrig, cpuminer",
            "Keyword fragments: rootkit, backdoor, exploit, keylogger",
            "Package installs close to incident timestamp",
        ],
        "analyst_guidance": [
            "Sort by timestamp — packages installed near incident time are key",
            "Suspicious=Yes entries flag known attacker tooling",
            "Package removals may indicate anti-forensic cleanup",
            "Check 'Requested_By' column for which user installed what",
        ],
    },
    "Network Analyzer": {
        "purpose": (
            "Audit network configuration files and parse web server access "
            "logs for signs of compromise — DNS poisoning, firewall changes, "
            "webshell access, and injection attempts."
        ),
        "examines": [
            "/etc/hosts                     — Local DNS overrides",
            "/etc/resolv.conf               — DNS resolver configuration",
            "/etc/hosts.allow /etc/hosts.deny — TCP wrapper ACLs",
            "/var/log/ufw.log*              — UFW firewall logs",
            "/var/log/firewalld*            — Firewalld logs",
            "UAC live_response: ARP cache, connections, routing table",
            "/var/log/apache2/ /var/log/httpd/ — Apache access/error logs",
            "/var/log/nginx/                — Nginx access/error logs",
        ],
        "searches_for": [
            "Non-standard DNS resolvers (potential DNS hijacking)",
            "Hosts file entries pointing domains to attacker IPs",
            "Webshell filenames: c99.php, r57.php, shell.php, cmd.jsp",
            "URI injection: directory traversal, SQLi, XSS, PHP eval",
            "Suspicious user-agents: sqlmap, nmap, masscan, metasploit",
            "POST requests to unusual paths with small responses (C2)",
        ],
        "analyst_guidance": [
            "Non-RFC1918 entries in /etc/hosts are almost always malicious",
            "Unknown DNS resolvers may indicate DNS hijacking or exfiltration",
            "Web access log entries with high suspicion scores need review",
            "POST to .php files in upload dirs may be webshell communication",
        ],
    },
    "Filesystem Timeline": {
        "purpose": (
            "Build a full filesystem MAC (Modify/Access/Change/Birth) timeline "
            "from a Sleuth Kit bodyfile or tarball metadata.  This is the "
            "backbone of filesystem-level forensic analysis."
        ),
        "examines": [
            "Bodyfile (bodyfile.txt, body, *.body) inside UAC collection",
            "Tarball member metadata (mtime) when no bodyfile present",
            "wtmp login records for timeline correlation",
            "Audit logs for authentication events",
        ],
        "searches_for": [
            "All file MAC timestamps (sorted chronologically)",
            "File creation/modification in temp directories",
            "Timestamp patterns indicating mass file modification (timestomping)",
            "Deleted files (prefixed with * in bodyfile name field)",
        ],
        "analyst_guidance": [
            "Focus on the time window around the suspected incident",
            "Files modified in /tmp, /dev/shm, /var/tmp are high-priority",
            "Clusters of file modifications in short time spans may indicate tooling",
            "Deleted files (Is_Deleted=True) may be attacker cleanup",
            "Cross-reference with login timeline to attribute file changes to users",
        ],
    },
    "String Analyzer": {
        "purpose": (
            "Carve and extract structured log entries from text files, "
            "including compressed logs.  Provides parsed versions of "
            "audit, syslog, and web logs for easier analysis."
        ),
        "examines": [
            "/var/log/audit/                — Linux Audit Framework logs",
            "/var/log/messages /var/log/syslog — System logs",
            "/var/log/auth.log /var/log/secure — Auth logs",
            "/var/log/apache2/ /var/log/httpd/ /var/log/nginx/ — Web logs",
            "Compressed variants (.gz, .bz2, .xz)",
        ],
        "searches_for": [
            "Audit events: USER_AUTH, USER_END, EXECVE, SYSCALL",
            "Syslog security processes: sshd, sudo, su, useradd, login",
            "Security keywords: Accepted, Failed, Invalid user, COMMAND=",
            "Apache/Nginx combined log format entries",
        ],
        "analyst_guidance": [
            "Use the extracted CSVs for structured searching of raw logs",
            "Audit logs contain system call data not found elsewhere",
            "Web logs may reveal exploitation attempts pre-dating persistence",
        ],
    },
    "Misc Artifacts": {
        "purpose": (
            "Detect archive files, hidden directories, and scheduled task "
            "artifacts that may indicate data staging, exfiltration prep, "
            "or attacker tool storage."
        ),
        "examines": [
            "Full file tree for archive magic bytes (ZIP, GZIP, TAR, RAR, 7z)",
            "Hidden directories (names starting with .) in all paths",
            "/etc/cron.*, /var/spool/cron/, /var/spool/at/ — Task files",
            "/etc/systemd/system/ — Systemd timer/service files",
        ],
        "searches_for": [
            "Archive files in unexpected locations (data staging)",
            "Hidden directories in /tmp, /var/tmp, /dev/shm",
            "Scheduled task content with suspicious keywords",
            "Magic byte detection: ZIP, GZIP, BZIP2, XZ, 7Z, RAR, TAR",
        ],
        "analyst_guidance": [
            "Archives in /tmp or /dev/shm may be exfiltration staging",
            "Hidden directories in world-writable paths are high-priority",
            "Scheduled tasks with curl/wget/base64/python are suspicious",
        ],
    },
    "IOC Scanner": {
        "purpose": (
            "Scan the entire UAC collection and all generated CSV output "
            "for matches against a supplied list of known-bad indicators "
            "(IPs, domains, hashes, file paths)."
        ),
        "examines": [
            "All text files in the UAC collection (log, conf, sh, py, etc.)",
            "All generated CSV output files from other analyzers",
            "Max file size: 50 MB per file",
        ],
        "searches_for": [
            "Exact string matches of each IOC against every line",
            "IOC types: IPv4 addresses, domains, MD5/SHA256 hashes, file paths",
        ],
        "analyst_guidance": [
            "Any IOC hit is high-priority — investigate the source file and context",
            "Cross-reference IOC hits with the login and persistence timelines",
            "Multiple hits for the same IOC across files confirms compromise scope",
        ],
    },
    "IOC Matcher": {
        "purpose": (
            "Cross-reference supplied IOC indicators against all generated "
            "CSV files using type-aware column matching (IP columns for IPs, "
            "hash columns for hashes, etc.)."
        ),
        "examines": [
            "All *_*.csv files in the output directory",
        ],
        "searches_for": [
            "IP addresses in Source_IP, Dest_IP, Client_IP columns",
            "Domains in hostname, domain, URL columns",
            "MD5/SHA256 hashes in hash and checksum columns",
            "File paths in filepath, filename, URI columns",
        ],
        "analyst_guidance": [
            "Hits include the full CSV row for context — review surrounding events",
            "IP hits in login timeline confirm attacker source addresses",
            "Hash hits in persistence CSV confirm known-bad files deployed",
        ],
    },
    "Log Gap Detection": {
        "purpose": (
            "Identify suspicious time gaps in the login/auth timeline where "
            "no events were recorded.  Log gaps may indicate log tampering, "
            "log rotation during an incident, or service disruption."
        ),
        "examines": [
            "Login timeline CSV (timestamp column)",
        ],
        "searches_for": [
            "Time periods >= 6 hours with zero recorded events",
            "Gap severity: 6-24h = MEDIUM, 24-72h = HIGH, 72h+ = CRITICAL",
        ],
        "analyst_guidance": [
            "CRITICAL gaps (72h+) strongly suggest log clearing",
            "Compare gap windows with other log sources (journal, packages)",
            "If logs exist in other sources during a gap, it confirms tampering",
            "Check if the gap aligns with the suspected incident window",
        ],
    },
    "Memory Analyzer": {
        "purpose": (
            "Analyze a memory dump using Volatility 3 to extract running "
            "processes, network connections, and in-memory artifacts that "
            "aren't visible on disk."
        ),
        "examines": [
            "Memory dump file (.lime, .raw, .vmem, .dmp)",
            "Kernel symbol tables (ISF/JSON format)",
        ],
        "searches_for": [
            "Running processes (including hidden — pslist vs psscan)",
            "Open network connections and listening sockets",
            "Command line arguments of all processes",
            "Loaded kernel modules (potential LKM rootkit)",
            "In-memory bash history (survives history -c)",
        ],
        "analyst_guidance": [
            "Processes in psscan but NOT pslist may be hidden (rootkit)",
            "Network connections to C2 IPs visible only in memory",
            "Bash history in memory may contain commands the attacker cleared",
            "Loaded kernel modules not matching installed packages = LKM rootkit",
        ],
    },
}


class ForensicLogger:
    """
    Write a human-readable audit log documenting exactly what the toolkit
    examined, what it searched for, what it found, and what analysts should
    prioritise.  Written incrementally so partial logs survive interrupted runs.
    """

    SECTION_WIDTH = 78

    def __init__(self, log_path: str):
        self._path = log_path
        self._fh = open(log_path, 'w', encoding='utf-8')
        self._start = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    # -- internal helpers -------------------------------------------------- #

    def _w(self, text: str = ''):
        self._fh.write(text + '\n')
        self._fh.flush()

    def _header(self, title: str):
        self._w()
        self._w('=' * self.SECTION_WIDTH)
        self._w(f'  {title}')
        self._w('=' * self.SECTION_WIDTH)

    def _subheader(self, title: str):
        self._w()
        self._w(f'--- {title} ' + '-' * max(0, self.SECTION_WIDTH - len(title) - 5))

    # -- public API -------------------------------------------------------- #

    def write_preamble(self, source: str, output_dir: str, hostname: str,
                       bodyfile: Optional[str], ioc_path: Optional[str],
                       memory_path: Optional[str], parallel: bool):
        """Opening block with run metadata."""
        self._w('=' * self.SECTION_WIDTH)
        self._w('  LINUX FORENSICS TOOLKIT — ANALYSIS AUDIT LOG')
        self._w('=' * self.SECTION_WIDTH)
        self._w()
        self._w('This log documents exactly what the toolkit examined, what')
        self._w('patterns and indicators it searched for, what it found, and')
        self._w('what you should focus on when reviewing the results.')
        self._w()
        self._w(f'  Tool Version   : {__version__}')
        self._w(f'  Analysis Start : {self._start.strftime("%Y-%m-%d %H:%M:%S")} UTC')
        self._w(f'  Hostname       : {hostname}')
        self._w(f'  Source         : {source}')
        self._w(f'  Output Dir     : {output_dir}')
        self._w(f'  Execution      : {"Parallel" if parallel else "Sequential"}')
        self._w(f'  Bodyfile       : {bodyfile or "(auto-detect / none)"}')
        self._w(f'  IOC File       : {ioc_path or "(not provided)"}')
        self._w(f'  Memory Dump    : {memory_path or "(not provided)"}')

    def write_analyzer_start(self, name: str):
        """Write the pre-analysis section explaining what the analyzer does."""
        meta = ANALYZER_METADATA.get(name)
        if not meta:
            self._header(f'ANALYZER: {name}')
            self._w('  (no metadata registered for this analyzer)')
            return

        self._header(f'ANALYZER: {name}')

        self._subheader('Purpose')
        self._w(f'  {meta["purpose"]}')

        self._subheader('Files & Paths Examined')
        for path in meta.get('examines', []):
            self._w(f'  • {path}')

        self._subheader('What It Searches For')
        for pattern in meta.get('searches_for', []):
            self._w(f'  • {pattern}')

    def write_analyzer_result(self, name: str, result: Dict):
        """Write the post-analysis section with findings and guidance."""
        meta = ANALYZER_METADATA.get(name, {})

        self._subheader('Results')
        success = result.get('success', False)
        error   = result.get('error')

        if not success and error:
            self._w(f'  Status  : FAILED — {error}')
            return
        if not success:
            self._w(f'  Status  : SKIPPED')
            return

        events   = result.get('event_count', 0) or 0
        findings = result.get('finding_count', 0) or 0
        self._w(f'  Status  : OK')
        if events and findings:
            self._w(f'  Events  : {events:,}')
            self._w(f'  Findings: {findings:,}')
        elif events:
            self._w(f'  Events  : {events:,}')
        elif findings:
            self._w(f'  Findings: {findings:,}')
        else:
            self._w(f'  Findings: 0')

        for f in result.get('output_files', []):
            self._w(f'  Output  : {os.path.basename(f)}')

        if meta.get('analyst_guidance'):
            self._subheader('What To Look For In This Output')
            for tip in meta['analyst_guidance']:
                self._w(f'  >> {tip}')

    def write_summary(self, results: List[Dict]):
        """Final summary with prioritised review order."""
        end = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        elapsed = (end - self._start).total_seconds()

        self._header('ANALYSIS COMPLETE')
        self._w()
        self._w(f'  Finished : {end.strftime("%Y-%m-%d %H:%M:%S")} UTC')
        self._w(f'  Duration : {elapsed:.1f} seconds')

        # Tally
        ok   = [r for r in results if r.get('success')]
        fail = [r for r in results if not r.get('success') and r.get('error')]
        skip = [r for r in results if not r.get('success') and not r.get('error')]

        self._w(f'  Succeeded: {len(ok)}')
        if fail:
            self._w(f'  Failed   : {len(fail)}')
            for r in fail:
                self._w(f'             - {r["name"]}: {r.get("error", "unknown")}')
        if skip:
            self._w(f'  Skipped  : {len(skip)}')

        # Prioritised review guidance
        self._header('RECOMMENDED REVIEW ORDER')
        self._w()
        self._w('  1. Persistence Hunter CSV  — CRITICAL/HIGH findings first.')
        self._w('     These survive reboots and are the clearest sign of compromise.')
        self._w()
        self._w('  2. IOC Hits CSV            — Any match = confirmed indicator.')
        self._w('     Investigate every hit; cross-reference with login timeline.')
        self._w()
        self._w('  3. Login Timeline CSV      — Sort by timestamp around the')
        self._w('     incident window.  Look for unusual IPs, brute force, sudo.')
        self._w()
        self._w('  4. Log Gaps CSV            — Gaps during the incident window')
        self._w('     suggest log tampering.  Compare with journal entries.')
        self._w()
        self._w('  5. Package CSV             — Installs near incident time,')
        self._w('     especially Suspicious=Yes entries (attacker tooling).')
        self._w()
        self._w('  6. Network CSV + Web Access — Webshell hits, DNS poisoning,')
        self._w('     unusual firewall events, injection attempts in web logs.')
        self._w()
        self._w('  7. Security CSVs           — SUID files, rootkit traces,')
        self._w('     binaries in /tmp or /dev/shm.')
        self._w()
        self._w('  8. Filesystem Timeline     — Narrow to the incident window.')
        self._w('     Look for file creation in temp dirs and config changes.')
        self._w()
        self._w('  9. Journal CSV             — Service start/stop events,')
        self._w('     kernel module loads, crash patterns.')
        self._w()
        self._w('  10. Memory Analysis        — Hidden processes, in-memory')
        self._w('      connections, cleared bash history, LKM rootkits.')
        self._w()
        self._w('-' * self.SECTION_WIDTH)
        self._w('  All timestamps in output CSVs are UTC.')
        self._w('  This log file: intended for analyst reference and chain-of-custody.')
        self._w('-' * self.SECTION_WIDTH)

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


# ============================================================================
# Hostname Extraction
# ============================================================================

def extract_hostname_from_tarball(tarball_path: str) -> str:
    """Extract hostname from UAC tarball name or contents."""
    hostname = "unknown"
    
    # Try to get hostname from tarball filename
    # UAC format: uac-hostname-timestamp.tar.gz (hostname comes AFTER uac-)
    basename = os.path.basename(tarball_path)
    for ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar'):
        if basename.lower().endswith(ext):
            basename = basename[:-len(ext)]
            break
    
    # UAC naming pattern: uac-hostname-timestamp or uac_hostname_timestamp
    # Hostname is the part AFTER "uac-" or "uac_"
    lower_basename = basename.lower()
    if lower_basename.startswith('uac-') or lower_basename.startswith('uac_'):
        # Remove the "uac-" or "uac_" prefix
        after_uac = basename[4:]  # Skip "uac-" or "uac_"
        # Hostname is typically the next segment before the timestamp
        # Format: hostname-YYYYMMDD or hostname_YYYYMMDD
        parts = re.split(r'[-_]', after_uac)
        if parts:
            # Find the hostname (non-timestamp parts at the beginning)
            hostname_parts = []
            for part in parts:
                # Stop if we hit a timestamp-like segment (all digits, 6+ chars)
                if re.match(r'^\d{6,}$', part):
                    break
                hostname_parts.append(part)
            if hostname_parts:
                hostname = '-'.join(hostname_parts)
    
    # Fallback: check for old format (hostname-uac-timestamp)
    if hostname == "unknown":
        for sep in ['-uac', '_uac', '-UAC', '_UAC']:
            if sep in basename:
                hostname = basename.split(sep)[0]
                break
    
    if hostname == "unknown":
        # Try first segment before common separators
        for sep in ['-', '_', '.']:
            if sep in basename:
                hostname = basename.split(sep)[0]
                break
        if hostname == "unknown":
            hostname = basename
    
    # Try to read hostname from tarball contents
    try:
        if tarball_path.endswith('.gz') or tarball_path.endswith('.tgz'):
            tar = tarfile.open(tarball_path, 'r:gz')
        elif tarball_path.endswith('.bz2'):
            tar = tarfile.open(tarball_path, 'r:bz2')
        elif tarball_path.endswith('.xz'):
            tar = tarfile.open(tarball_path, 'r:xz')
        else:
            tar = tarfile.open(tarball_path, 'r')
        
        # Look for etc/hostname file
        for member in tar.getmembers()[:500]:
            if member.name.endswith('etc/hostname') and member.isfile():
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode('utf-8', errors='replace').strip()
                    if content and len(content) < 64:
                        hostname = content
                        break
        tar.close()
    except Exception:
        pass
    
    # Sanitize hostname for filesystem
    hostname = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', hostname)
    return hostname


def extract_hostname_from_directory(dir_path: str) -> str:
    """Extract hostname from extracted UAC directory."""
    hostname = "unknown"
    
    # Try to read etc/hostname
    hostname_file = os.path.join(dir_path, 'etc', 'hostname')
    if os.path.exists(hostname_file):
        try:
            with open(hostname_file, 'r') as f:
                content = f.read().strip()
                if content and len(content) < 64:
                    hostname = content
        except Exception:
            pass
    
    # Also check nested UAC structure
    if hostname == "unknown":
        for root, dirs, files in os.walk(dir_path):
            if 'hostname' in files:
                try:
                    with open(os.path.join(root, 'hostname'), 'r') as f:
                        content = f.read().strip()
                        if content and len(content) < 64:
                            hostname = content
                            break
                except Exception:
                    pass
            # Limit search depth
            if root.count(os.sep) - dir_path.count(os.sep) > 3:
                break
    
    # Fallback to directory name
    if hostname == "unknown":
        hostname = os.path.basename(dir_path.rstrip('/\\'))
    
    # Sanitize hostname for filesystem
    hostname = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', hostname)
    return hostname


# ============================================================================
# Analyzer Wrappers
# ============================================================================

def run_login_timeline(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the login timeline analyzer."""
    result = {
        "name": "Login Timeline",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None
    }

    try:
        # Import the module
        import linux_login_timeline as llt

        # Create timeline object
        timeline = llt.LinuxLoginTimeline(source_path)

        # Collect events (verbose=False for parallel execution)
        if timeline.is_tarball:
            timeline._collect_from_tarball(verbose=False)
        else:
            timeline._collect_from_directory(verbose=False)

        if timeline.events:
            # Export to CSV
            output_file = os.path.join(output_dir, f"{hostname}_login_timeline.csv")
            timeline.export_csv(output_file)
            result["output_files"].append(output_file)
            result["event_count"] = len(timeline.events)
            result["success"] = True
        else:
            result["error"] = "No events found"
            result["success"] = True  # Not a failure, just no data

        # Close tarball handler if used
        if timeline.tarball_handler:
            timeline.tarball_handler.close()

    except Exception as e:
        result["error"] = str(e)

    # Coverage probe
    result["coverage"] = probe_coverage(source_path, "Login Timeline",
                                        LOGIN_TIMELINE_ARTIFACTS)
    return result


def run_journal_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the journal analyzer."""
    result = {
        "name": "Journal Analyzer",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None
    }
    
    try:
        # Import the module
        import linux_journal_analyzer as lja
        
        # Create handler and parser
        handler = lja.UACHandler(source_path)
        
        # Get reference date for year inference
        reference_date = None
        if os.path.isfile(source_path):
            try:
                mtime = os.path.getmtime(source_path)
                reference_date = datetime.fromtimestamp(mtime, tz=timezone.utc).replace(tzinfo=None)
            except (OSError, ValueError):
                pass
        
        if reference_date is None:
            reference_date = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        
        parser = lja.JournalParser(handler, reference_date=reference_date)
        entries = parser.parse_all()
        
        if entries:
            # Export all entries
            all_path = os.path.join(output_dir, f"{hostname}_journal.csv")
            lja.export_csv(entries, all_path)
            result["output_files"].append(all_path)
            
            # Export security events
            sec_path = os.path.join(output_dir, f"{hostname}_journal_security.csv")
            lja.export_security_report(entries, sec_path)
            if os.path.exists(sec_path):
                result["output_files"].append(sec_path)
            
            result["event_count"] = len(entries)
            result["success"] = True
        else:
            result["error"] = "No entries found"
            result["success"] = True
        
        handler.close()
        
    except Exception as e:
        result["error"] = str(e)

    result["coverage"] = probe_coverage(source_path, "Journal Analyzer",
                                        JOURNAL_ANALYZER_ARTIFACTS)
    return result


def run_persistence_hunter(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the persistence hunter."""
    result = {
        "name": "Persistence Hunter",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None
    }

    try:
        import linux_persistence_hunter as lph
        hunter = lph.PersistenceHunter(source_path)
        hunter.hunt(verbose=False)

        if hunter.findings:
            output_file = os.path.join(output_dir, f"{hostname}_persistence.csv")
            hunter.export_csv(output_file)
            result["output_files"].append(output_file)
            result["finding_count"] = len(hunter.findings)

        result["success"] = True
        hunter.close()

    except Exception as e:
        result["error"] = str(e)

    result["coverage"] = probe_coverage(source_path, "Persistence Hunter",
                                        PERSISTENCE_HUNTER_ARTIFACTS)
    return result


def run_security_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the security analyzer."""
    result = {
        "name": "Security Analyzer",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None
    }
    
    try:
        # Import the module
        import linux_security_analyzer as lsa
        
        # Run the analyzer - it will use its own hostname from the handler
        analyzer = lsa.LinuxSecurityAnalyzer(source_path, output_dir)
        analyzer.analyze(verbose=False)
        
        # Count findings
        result["finding_count"] = len(analyzer.findings)
        
        if analyzer.findings:
            # Export findings - the analyzer uses its own hostname
            exported_files = analyzer.export_csv()
            
            # Rename files to use our consistent hostname prefix format
            for category, old_path in exported_files.items():
                if old_path and os.path.exists(old_path):
                    new_name = f"{hostname}_security_{category}.csv"
                    new_path = os.path.join(output_dir, new_name)
                    if old_path != new_path:
                        try:
                            shutil.move(old_path, new_path)
                        except Exception:
                            new_path = old_path  # Keep original if rename fails
                    result["output_files"].append(new_path)
        
        result["success"] = True
        analyzer.close()

    except Exception as e:
        result["error"] = str(e)

    result["coverage"] = probe_coverage(source_path, "Security Analyzer",
                                        SECURITY_ANALYZER_ARTIFACTS)
    return result


def run_memory_analyzer(memory_path: str, output_dir: str, hostname: str,
                        symbol_dirs: List[str] = None, quick: bool = False) -> Dict:
    """Run the memory analyzer (Volatility 3 wrapper)."""
    result = {
        "name": "Memory Analyzer",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None
    }
    
    try:
        # Import the module
        import linux_memory_analyzer as lma
        
        # Check if Volatility is installed
        installed, msg = lma.check_volatility_installed()
        if not installed:
            result["error"] = f"Volatility 3 not installed. Run: python linux_memory_analyzer.py --setup"
            return result
        
        # Create memory-specific output subdirectory
        memory_output_dir = os.path.join(output_dir, "memory_analysis")
        os.makedirs(memory_output_dir, exist_ok=True)
        
        # Create analyzer (online by default to allow ISF symbol downloads)
        analyzer = lma.LinuxMemoryAnalyzer(
            image_path=memory_path,
            output_dir=memory_output_dir,
            symbol_dirs=symbol_dirs,
        )

        # Validate
        valid, msg = analyzer.validate()
        if not valid:
            result["error"] = msg
            return result

        # Run analysis
        if quick:
            # Quick triage mode
            lma.quick_triage(memory_path, symbol_dirs=symbol_dirs, verbose=False)
        else:
            analyzer.analyze(include_optional=False, verbose=False)
        
        # Count output files
        if os.path.exists(memory_output_dir):
            for filename in os.listdir(memory_output_dir):
                if filename.endswith('.csv'):
                    filepath = os.path.join(memory_output_dir, filename)
                    result["output_files"].append(filepath)
                    # Count rows in CSV
                    try:
                        with open(filepath, 'r') as f:
                            lines = sum(1 for _ in f) - 1  # Subtract header
                            result["finding_count"] += max(0, lines)
                    except:
                        pass
        
        result["success"] = True
        
    except ImportError:
        result["error"] = "linux_memory_analyzer.py not found"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def run_package_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the package manager log analyzer."""
    result: Dict = {
        "name": "Package Analyzer",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None,
    }
    try:
        import linux_package_analyzer as lpa
        analyzer = lpa.PackageAnalyzer(source_path)
        analyzer.analyze(verbose=False)
        if analyzer.events:
            out = os.path.join(output_dir, f"{hostname}_packages.csv")
            analyzer.export_csv(out)
            result["output_files"].append(out)
            result["event_count"] = len(analyzer.events)
        result["success"] = True
        analyzer.close()
    except ImportError:
        result["error"] = "linux_package_analyzer.py not found"
    except Exception as exc:
        result["error"] = str(exc)

    result["coverage"] = probe_coverage(source_path, "Package Analyzer",
                                        PACKAGE_ANALYZER_ARTIFACTS)
    return result


def run_network_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the network artifact analyzer."""
    result: Dict = {
        "name": "Network Analyzer",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None,
    }
    try:
        import linux_network_analyzer as lna
        analyzer = lna.NetworkAnalyzer(source_path)
        analyzer.analyze(verbose=False)
        if analyzer.findings:
            out = os.path.join(output_dir, f"{hostname}_network.csv")
            analyzer.export_findings_csv(out)
            result["output_files"].append(out)
            result["finding_count"] += len(analyzer.findings)
        if analyzer.web_events:
            out = os.path.join(output_dir, f"{hostname}_web_access.csv")
            analyzer.export_web_access_csv(out)
            result["output_files"].append(out)
            result["finding_count"] += len(analyzer.web_events)
        result["success"] = True
        analyzer.close()
    except ImportError:
        result["error"] = "linux_network_analyzer.py not found"
    except Exception as exc:
        result["error"] = str(exc)

    result["coverage"] = probe_coverage(source_path, "Network Analyzer",
                                        NETWORK_ANALYZER_ARTIFACTS)
    return result


# ============================================================================
# Post-Processing: IOC Matching
# ============================================================================

_RE_IPV4   = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_RE_MD5    = re.compile(r'^[0-9a-fA-F]{32}$')
_RE_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')
_RE_DOMAIN = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')


def _classify_ioc(raw: str) -> Tuple[str, str]:
    """Return (ioc_type, normalised_value) for a raw IOC string."""
    raw = raw.strip()
    if ':' in raw:
        prefix, val = raw.split(':', 1)
        prefix = prefix.lower()
        if prefix in ('ip', 'domain', 'md5', 'sha256', 'sha1', 'path', 'hash'):
            return prefix if prefix != 'hash' else 'md5', val.strip()
    if _RE_IPV4.match(raw):
        return 'ip', raw
    if _RE_SHA256.match(raw):
        return 'sha256', raw.lower()
    if _RE_MD5.match(raw):
        return 'md5', raw.lower()
    if raw.startswith('/') or raw.startswith('\\'):
        return 'path', raw
    if _RE_DOMAIN.match(raw):
        return 'domain', raw.lower()
    return 'unknown', raw


def load_ioc_file(ioc_path: str) -> List[Tuple[str, str]]:
    """
    Load IOC indicators from a plain-text file.
    Returns list of (ioc_type, value) tuples.
    Lines starting with '#' are comments; blank lines are ignored.
    """
    iocs: List[Tuple[str, str]] = []
    try:
        with open(ioc_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                ioc_type, value = _classify_ioc(line)
                if ioc_type != 'unknown' and value:
                    iocs.append((ioc_type, value))
    except Exception:
        pass
    return iocs


def run_ioc_matcher(output_dir: str, hostname: str,
                    ioc_path: str) -> Dict:
    """
    Cross-reference IOC indicators against all generated CSVs.

    Searches:
      - _login_timeline.csv  : source_ip  → IP match
      - _network.csv         : Source_IP, Dest_IP, Description → IP / domain
      - _persistence.csv     : MD5, SHA256, Filepath, Indicator → hash / path
      - _security_*.csv      : MD5, SHA256, Filepath → hash / path
      - _packages.csv        : Package → keyword match
      - _mac_timeline.csv    : Filename, MD5 → path / hash
    """
    result: Dict = {
        "name": "IOC Matcher",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None,
    }
    try:
        iocs = load_ioc_file(ioc_path)
        if not iocs:
            result["error"] = "No valid IOCs loaded from file"
            result["success"] = True
            return result

        ip_iocs     = {v for t, v in iocs if t == 'ip'}
        domain_iocs = {v for t, v in iocs if t == 'domain'}
        md5_iocs    = {v for t, v in iocs if t == 'md5'}
        sha256_iocs = {v for t, v in iocs if t == 'sha256'}
        path_iocs   = [v for t, v in iocs if t == 'path']

        hits: List[Dict] = []

        # Columns to search per CSV type
        search_map = {
            f"{hostname}_login_timeline.csv": {
                'ip': ['source_ip'],
            },
            f"{hostname}_network.csv": {
                'ip':     ['Source_IP', 'Dest_IP'],
                'domain': ['Description', 'Raw_Entry'],
            },
            f"{hostname}_web_access.csv": {
                'ip':     ['Client_IP'],
                'domain': ['URI', 'Referrer'],
            },
            f"{hostname}_persistence.csv": {
                'md5':    ['MD5'],
                'sha256': ['SHA256'],
                'path':   ['Filepath', 'Indicator'],
                'domain': ['Indicator', 'Raw_Content'],
            },
            f"{hostname}_mac_timeline.csv": {
                'md5':  ['MD5'],
                'path': ['Filename'],
            },
        }
        # Security CSVs: glob pattern
        for fname in os.listdir(output_dir):
            if re.match(rf'^{re.escape(hostname)}_security_.*\.csv$', fname):
                search_map[fname] = {
                    'md5':    ['MD5'],
                    'sha256': ['SHA256'],
                    'path':   ['Filepath'],
                }
            if re.match(rf'^{re.escape(hostname)}_packages\.csv$', fname):
                search_map[fname] = {
                    'domain': ['Package', 'Raw_Entry'],
                }

        for csv_name, col_map in search_map.items():
            csv_path = os.path.join(output_dir, csv_name)
            if not os.path.isfile(csv_path):
                continue
            try:
                with open(csv_path, newline='', encoding='utf-8',
                          errors='replace') as f:
                    reader = csv.DictReader(f)
                    for row_num, row in enumerate(reader, 2):
                        for ioc_type, columns in col_map.items():
                            for col in columns:
                                if col not in row:
                                    continue
                                cell = (row[col] or '').strip()
                                if not cell:
                                    continue

                                matched_val = ''
                                if ioc_type == 'ip' and ip_iocs:
                                    if cell in ip_iocs:
                                        matched_val = cell
                                    else:
                                        for ip in ip_iocs:
                                            if ip in cell:
                                                matched_val = ip
                                                break
                                elif ioc_type == 'domain' and domain_iocs:
                                    cell_lower = cell.lower()
                                    for d in domain_iocs:
                                        if d in cell_lower:
                                            matched_val = d
                                            break
                                elif ioc_type == 'md5' and md5_iocs:
                                    if cell.lower() in md5_iocs:
                                        matched_val = cell.lower()
                                elif ioc_type == 'sha256' and sha256_iocs:
                                    if cell.lower() in sha256_iocs:
                                        matched_val = cell.lower()
                                elif ioc_type == 'path' and path_iocs:
                                    for p in path_iocs:
                                        if p in cell:
                                            matched_val = p
                                            break

                                if matched_val:
                                    hits.append({
                                        'IOC_Value':      matched_val,
                                        'IOC_Type':       ioc_type.upper(),
                                        'Source_CSV':     csv_name,
                                        'CSV_Row':        row_num,
                                        'Matched_Column': col,
                                        'Matched_Value':  cell[:200],
                                        'Context':        str(row)[:300],
                                    })
            except Exception:
                continue

        if hits:
            out = os.path.join(output_dir, f"{hostname}_ioc_hits.csv")
            fieldnames = [
                'IOC_Value', 'IOC_Type', 'Source_CSV',
                'CSV_Row', 'Matched_Column', 'Matched_Value', 'Context',
            ]
            with open(out, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(hits)
            result["output_files"].append(out)
            result["finding_count"] = len(hits)

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)

def run_filesystem_timeline(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the filesystem timeline generator."""
    result = {
        "name": "Filesystem Timeline",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "error": None
    }

    try:
        import linux_filesystem_timeline as lft

        gen = lft.FilesystemTimelineGenerator(source_path)
        try:
            gen.generate(verbose=False)

            # Export bodyfile
            bf_path = os.path.join(output_dir, f"{hostname}_bodyfile.txt")
            gen.export_bodyfile(bf_path)
            result["output_files"].append(bf_path)

            # Export full timeline CSV
            tl_path = os.path.join(output_dir, f"{hostname}_filesystem_timeline.csv")
            gen.export_timeline_csv(tl_path)
            result["output_files"].append(tl_path)

            # Export merged login timeline
            if gen.login_entries:
                login_path = os.path.join(output_dir, f"{hostname}_login_timeline_merged.csv")
                gen.export_login_csv(login_path)
                result["output_files"].append(login_path)

            result["event_count"] = len(gen.bodyfile_entries) + len(gen.login_entries)
            result["success"] = True
        finally:
            gen.close()

    except Exception as e:
        result["error"] = str(e)

    return result


# ============================================================================
# Post-Processing: Log Gap Detection
# ============================================================================

def run_log_gap_detection(output_dir: str, hostname: str,
                           gap_threshold_hours: float = 6.0) -> Dict:
    """
    Identify suspicious time-gaps in the login/auth event timeline.

    Reads the generated login timeline CSV, computes inter-event gaps,
    and flags gaps exceeding *gap_threshold_hours*.  Large gaps during
    an otherwise active period may indicate log-file clearing or deletion.

    Returns a result dict with gap statistics; does NOT write a separate
    file – findings are added to the summary report section instead.
    """
    result: Dict = {
        "name": "Log Gap Detection",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None,
        "gap_summary": [],        # list of (start, end, hours) for display
    }

    timeline_csv = os.path.join(output_dir, f"{hostname}_login_timeline.csv")
    if not os.path.isfile(timeline_csv):
        result["error"] = "Login timeline CSV not found; gap detection skipped"
        result["success"] = True
        return result

    try:
        timestamps: List[datetime] = []
        with open(timeline_csv, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts_val = row.get('Timestamp_UTC') or row.get('Timestamp') or ''
                if not ts_val:
                    continue
                try:
                    ts = datetime.strptime(ts_val.strip(), '%Y-%m-%d %H:%M:%S')
                    timestamps.append(ts)
                except ValueError:
                    pass

        if len(timestamps) < 2:
            result["error"] = "Insufficient events for gap analysis"
            result["success"] = True
            return result

        timestamps.sort()
        gaps: List[Tuple[datetime, datetime, float]] = []

        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds() / 3600.0
            if delta >= gap_threshold_hours:
                gaps.append((timestamps[i - 1], timestamps[i], delta))

        # Sort by largest gap first
        gaps.sort(key=lambda x: -x[2])

        # Write a gaps CSV if any significant gaps found
        if gaps:
            out = os.path.join(output_dir, f"{hostname}_log_gaps.csv")
            fieldnames = [
                'Gap_Start_UTC', 'Gap_End_UTC',
                'Gap_Duration_Hours', 'Severity',
            ]
            with open(out, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for start, end, hours in gaps:
                    sev = 'HIGH' if hours >= 48 else ('MEDIUM' if hours >= 12 else 'LOW')
                    writer.writerow({
                        'Gap_Start_UTC':       start.strftime('%Y-%m-%d %H:%M:%S'),
                        'Gap_End_UTC':         end.strftime('%Y-%m-%d %H:%M:%S'),
                        'Gap_Duration_Hours':  f"{hours:.1f}",
                        'Severity':            sev,
                    })
            result["output_files"].append(out)
            result["finding_count"] = len(gaps)

            # Store top-5 for summary display
            result["gap_summary"] = [
                (s.strftime('%Y-%m-%d %H:%M'),
                 e.strftime('%Y-%m-%d %H:%M'),
                 h)
                for s, e, h in gaps[:5]
            ]

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)

    return result


def run_string_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the string/log extraction analyzer."""
    result = {
        "name": "String Analyzer",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None
    }

    try:
        import linux_string_analyzer as lsa_str

        analyzer = lsa_str.StringAnalyzer(source_path)
        try:
            counts = analyzer.analyze(verbose=False)

            files = analyzer.export_csv(output_dir, hostname)
            result["output_files"] = files

            total = sum(v for k, v in counts.items() if k != 'security_total')
            result["event_count"] = total
            result["finding_count"] = counts.get('security_total', 0)
            result["success"] = True
        finally:
            analyzer.close()

    except Exception as e:
        result["error"] = str(e)

    result["coverage"] = probe_coverage(source_path, "String Analyzer",
                                        STRING_ANALYZER_ARTIFACTS)
    return result


def run_misc_artifacts(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the miscellaneous artifacts collector."""
    result = {
        "name": "Misc Artifacts",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "finding_count": 0,
        "coverage": [],
        "error": None
    }

    try:
        import linux_misc_artifacts as lma_misc

        collector = lma_misc.MiscArtifactsCollector(source_path)
        try:
            counts = collector.collect(verbose=False)

            files = collector.export_csv(output_dir, hostname)
            result["output_files"] = files
            result["finding_count"] = sum(counts.values())
            result["success"] = True
        finally:
            collector.close()

    except Exception as e:
        result["error"] = str(e)

    result["coverage"] = probe_coverage(source_path, "Misc Artifacts",
                                        MISC_ARTIFACTS_EXPECTED)
    return result


def run_ioc_scanner(source_path: str, output_dir: str, hostname: str,
                    ioc_file: str = None) -> Dict:
    """Run the IOC scanner."""
    result = {
        "name": "IOC Scanner",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None
    }

    if not ioc_file:
        result["error"] = "No IOC file specified"
        result["success"] = True  # Not a failure, just not requested
        return result

    if not os.path.isfile(ioc_file):
        result["error"] = f"IOC file not found: {ioc_file}"
        return result

    try:
        import linux_ioc_scanner as lis

        scanner = lis.IOCScanner(source_path, ioc_file)
        try:
            total = scanner.scan(verbose=False)

            # Also scan the output directory for hits in analysis results
            scanner.scan_output_directory(output_dir, verbose=False)

            path = scanner.export_csv(output_dir, hostname)
            if path:
                result["output_files"].append(path)

            result["finding_count"] = len(scanner.matches)
            result["success"] = True
        finally:
            scanner.close()

    except Exception as e:
        result["error"] = str(e)

    return result


# ============================================================================
# Correlation and Summary
# ============================================================================

def create_summary_report(output_dir: str, hostname: str, results: List[Dict],
                         start_time: datetime, end_time: datetime,
                         bodyfile_path: Optional[str] = None) -> str:
    """Create a summary report of all analysis results."""
    summary_path = os.path.join(output_dir, f"{hostname}_analysis_summary.txt")

    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(f"  Linux Unified Security Analysis Summary\n")
        f.write(f"  Hostname: {hostname}\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"Analysis Start:  {start_time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"Analysis End:    {end_time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"Duration:        {(end_time - start_time).total_seconds():.2f} seconds\n")
        f.write(f"Tool Version:    {__version__}\n")
        if bodyfile_path:
            f.write(f"Bodyfile:        {bodyfile_path}\n")
        else:
            f.write(f"Bodyfile:        not provided (MAC timeline skipped)\n")
        f.write("\n")
        
        f.write("-" * 70 + "\n")
        f.write("  Analyzer Results\n")
        f.write("-" * 70 + "\n\n")
        
        total_events = 0
        total_findings = 0
        all_files = []
        
        for result in results:
            status = "SUCCESS" if result["success"] else "FAILED"
            f.write(f"[{status}] {result['name']}\n")
            
            if result.get("event_count"):
                f.write(f"         Events: {result['event_count']}\n")
                total_events += result["event_count"]
            
            if result.get("finding_count"):
                f.write(f"         Findings: {result['finding_count']}\n")
                total_findings += result["finding_count"]
            
            if result.get("error"):
                f.write(f"         Note: {result['error']}\n")
            
            if result.get("output_files"):
                for output_file in result["output_files"]:
                    f.write(f"         Output: {os.path.basename(output_file)}\n")
                    all_files.append(output_file)
            
            f.write("\n")
        
        f.write("-" * 70 + "\n")
        f.write("  Summary Statistics\n")
        f.write("-" * 70 + "\n\n")
        f.write(f"Total Timeline Events:     {total_events}\n")
        f.write(f"Total Security Findings:   {total_findings}\n")
        f.write(f"Output Files Generated:    {len(all_files)}\n")

        # IOC hits
        ioc_result = next((r for r in results if r.get("name") == "IOC Matcher"), None)
        if ioc_result and ioc_result.get("finding_count"):
            f.write(f"IOC Hits:                  {ioc_result['finding_count']}\n")

        # Log gap summary
        gap_result = next((r for r in results if r.get("name") == "Log Gap Detection"), None)
        if gap_result and gap_result.get("gap_summary"):
            f.write(f"\n")
            f.write("-" * 70 + "\n")
            f.write("  Notable Log Gaps (possible log tampering)\n")
            f.write("-" * 70 + "\n\n")
            for start_s, end_s, hours in gap_result["gap_summary"]:
                sev = "HIGH" if hours >= 48 else ("MEDIUM" if hours >= 12 else "LOW")
                f.write(f"  [{sev:6}] {start_s} → {end_s}  ({hours:.1f} h)\n")
        f.write("\n")

        # ── Artifact Summary ─────────────────────────────────────────────────
        f.write("-" * 70 + "\n")
        f.write("  Artifact Summary\n")
        f.write("-" * 70 + "\n\n")

        _SKIP_VALS = frozenset({'', '0.0.0.0', '::', '::1', 'n/a', '-', 'unknown', 'none'})

        def _skip_ip(ip: str) -> bool:
            v = ip.lower()
            return v in _SKIP_VALS or v.startswith('127.') or v == '::1'

        unique_users: set = set()
        unique_ips: set = set()

        # Login timeline – users and source IPs
        login_csv = os.path.join(output_dir, f"{hostname}_login_timeline.csv")
        if os.path.isfile(login_csv):
            try:
                with open(login_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        u = (_row.get('username') or '').strip()
                        if u and u.lower() not in _SKIP_VALS:
                            unique_users.add(u)
                        ip = (_row.get('source_ip') or '').strip()
                        if ip and not _skip_ip(ip):
                            unique_ips.add(ip)
            except Exception:
                pass

        # Network findings – source and dest IPs
        net_csv = os.path.join(output_dir, f"{hostname}_network.csv")
        if os.path.isfile(net_csv):
            try:
                with open(net_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        for _col in ('Source_IP', 'Dest_IP'):
                            ip = (_row.get(_col) or '').strip()
                            if ip and not _skip_ip(ip):
                                unique_ips.add(ip)
            except Exception:
                pass

        # Web access – client IPs
        web_csv = os.path.join(output_dir, f"{hostname}_web_access.csv")
        if os.path.isfile(web_csv):
            try:
                with open(web_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        ip = (_row.get('Client_IP') or '').strip()
                        if ip and not _skip_ip(ip):
                            unique_ips.add(ip)
            except Exception:
                pass

        def _ip_sort_key(ip: str):
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    return (0, tuple(int(p) for p in parts))
                except ValueError:
                    pass
            return (1, (ip,))

        if unique_users:
            f.write(f"  Unique Users ({len(unique_users)}):\n")
            for _u in sorted(unique_users):
                f.write(f"    {_u}\n")
            f.write("\n")

        if unique_ips:
            f.write(f"  Unique IP Addresses ({len(unique_ips)}):\n")
            for _ip in sorted(unique_ips, key=_ip_sort_key):
                f.write(f"    {_ip}\n")
            f.write("\n")

        # Top persistence findings (CRITICAL / HIGH)
        persist_csv = os.path.join(output_dir, f"{hostname}_persistence.csv")
        top_findings: List[Tuple] = []
        if os.path.isfile(persist_csv):
            try:
                with open(persist_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        sev = (_row.get('Severity') or '').upper()
                        if sev in ('CRITICAL', 'HIGH'):
                            top_findings.append((
                                sev,
                                _row.get('Technique', ''),
                                _row.get('Description', ''),
                                _row.get('Filepath', ''),
                            ))
            except Exception:
                pass

        if top_findings:
            _sev_order = {'CRITICAL': 0, 'HIGH': 1}
            top_findings.sort(key=lambda x: _sev_order.get(x[0], 9))
            f.write(f"  Critical/High Persistence Findings ({len(top_findings)}):\n")
            for _sev, _tech, _desc, _fp in top_findings[:20]:
                f.write(f"    [{_sev}] {_tech}: {_desc}\n")
                if _fp:
                    f.write(f"           {_fp}\n")
            if len(top_findings) > 20:
                f.write(f"    ... and {len(top_findings) - 20} more (see persistence CSV)\n")
            f.write("\n")

        if not unique_users and not unique_ips and not top_findings:
            f.write("  No artifact data collected.\n\n")

        f.write("-" * 70 + "\n")
        f.write("  Output Files\n")
        f.write("-" * 70 + "\n\n")

        for filepath in sorted(all_files):
            basename = os.path.basename(filepath)
            try:
                size = os.path.getsize(filepath)
                size_str = f"{size:,} bytes"
            except:
                size_str = "unknown size"
            f.write(f"  {basename} ({size_str})\n")

    return summary_path


# ============================================================================
# Tarball Discovery
# ============================================================================

TARBALL_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')


def find_tarballs_in_directory(dir_path: str) -> List[str]:
    """
    Find all UAC tarballs in a directory (non-recursive, top-level only).
    
    Args:
        dir_path: Directory to search
        
    Returns:
        List of tarball paths found
    """
    tarballs = []
    try:
        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)
            if os.path.isfile(item_path):
                if any(item.lower().endswith(ext) for ext in TARBALL_EXTENSIONS):
                    tarballs.append(item_path)
    except PermissionError:
        pass
    return sorted(tarballs)


def is_extracted_uac_directory(dir_path: str) -> bool:
    """
    Check if a directory appears to be an extracted UAC collection.
    
    Looks for typical UAC structure: var/log, etc/passwd, home/, etc.
    
    Args:
        dir_path: Directory to check
        
    Returns:
        True if this looks like an extracted UAC directory
    """
    # Check for common UAC artifacts
    indicators = [
        os.path.join(dir_path, "var", "log"),
        os.path.join(dir_path, "etc", "passwd"),
        os.path.join(dir_path, "etc", "hostname"),
    ]
    
    # Also check for nested structure (hostname/var/log)
    try:
        for subdir in os.listdir(dir_path):
            subdir_path = os.path.join(dir_path, subdir)
            if os.path.isdir(subdir_path):
                nested_indicators = [
                    os.path.join(subdir_path, "var", "log"),
                    os.path.join(subdir_path, "etc", "passwd"),
                ]
                if any(os.path.exists(p) for p in nested_indicators):
                    return True
    except PermissionError:
        pass
    
    return any(os.path.exists(p) for p in indicators)


# ============================================================================
# Bodyfile Support
# ============================================================================

#: Bodyfile names that UAC or other collection tools typically produce.
_BODYFILE_NAMES = frozenset({
    'body', 'bodyfile',
    'body.gz', 'bodyfile.gz',
    'body.txt', 'bodyfile.txt',
})

#: Human-readable labels for each MAC timestamp type.
_MAC_LABELS = {
    'M': 'Modification',
    'A': 'Access',
    'C': 'Change (metadata)',
    'B': 'Birth (creation)',
}


def find_bodyfile_in_source(source_path: str) -> Tuple[Optional[str], bool]:
    """
    Auto-detect a Sleuth Kit bodyfile within a UAC tarball or directory.

    UAC typically stores a bodyfile at paths such as:
      [hostname]/[date]/body
      [hostname]/[date]/bodyfile
      body  (flat)
      live_response/body

    Args:
        source_path: Path to UAC tarball or extracted directory.

    Returns:
        Tuple of (bodyfile_path, is_temp).
        ``is_temp`` is True when the file was extracted to a temporary
        location and must be deleted after use.
    """
    # ---- Tarball source -------------------------------------------------- #
    if os.path.isfile(source_path):
        try:
            if source_path.lower().endswith('.gz') or source_path.lower().endswith('.tgz'):
                tar = tarfile.open(source_path, 'r:gz')
            elif source_path.lower().endswith('.bz2'):
                tar = tarfile.open(source_path, 'r:bz2')
            elif source_path.lower().endswith('.xz'):
                tar = tarfile.open(source_path, 'r:xz')
            else:
                tar = tarfile.open(source_path, 'r')

            for member in tar.getmembers():
                if not member.isfile():
                    continue
                basename = os.path.basename(member.name).lower()
                if basename in _BODYFILE_NAMES:
                    suffix = '.body.gz' if basename.endswith('.gz') else '.body'
                    tmp = tempfile.NamedTemporaryFile(
                        delete=False, suffix=suffix, prefix='lft_body_'
                    )
                    fobj = tar.extractfile(member)
                    if fobj:
                        tmp.write(fobj.read())
                        tmp.close()
                        tar.close()
                        return tmp.name, True
            tar.close()
        except Exception:
            pass

    # ---- Directory source ------------------------------------------------- #
    elif os.path.isdir(source_path):
        base_depth = source_path.count(os.sep)
        for root, dirs, files in os.walk(source_path):
            if root.count(os.sep) - base_depth > 6:
                dirs.clear()
                continue
            for fname in files:
                if fname.lower() in _BODYFILE_NAMES:
                    return os.path.join(root, fname), False

    return None, False


def prompt_for_bodyfile(quiet: bool = False) -> Optional[str]:
    """
    Interactively prompt the analyst for an existing Sleuth Kit bodyfile.

    Sets up readline tab-completion for file paths on Unix.  On Windows
    (where readline is absent) the prompt still works, just without
    completion.  Returns ``None`` if the analyst presses Enter without
    entering a path, or if running non-interactively.

    Args:
        quiet: When True, skip the prompt entirely and return None.

    Returns:
        Absolute path to the bodyfile, or None.
    """
    if quiet or not sys.stdin.isatty():
        return None

    # Set up path tab-completion where supported
    try:
        import readline
        import glob as _glob

        def _path_completer(text, state):
            expanded = os.path.expanduser(text)
            matches = _glob.glob(expanded + '*')
            results = [m + os.sep if os.path.isdir(m) else m for m in matches]
            try:
                return results[state]
            except IndexError:
                return None

        readline.set_completer(_path_completer)
        readline.set_completer_delims('\t\n ')
        readline.parse_and_bind('tab: complete')
    except ImportError:
        pass  # Windows – proceed without tab completion

    print(
        f"\n{Style.INFO}Bodyfile (Sleuth Kit MAC timeline):{Style.RESET}",
        file=sys.stderr,
    )
    print(
        f"{Style.DIM}  Provide an existing bodyfile to use for filesystem timeline analysis.{Style.RESET}",
        file=sys.stderr,
    )
    print(
        f"{Style.DIM}  Format: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime{Style.RESET}",
        file=sys.stderr,
    )
    print(
        f"{Style.DIM}  Press Enter to auto-detect from the UAC collection (or skip if absent).{Style.RESET}",
        file=sys.stderr,
    )

    try:
        answer = input("  Bodyfile path [Enter to auto-detect]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return None

    if not answer:
        return None

    expanded = os.path.expanduser(answer)
    abs_path = os.path.abspath(expanded)

    if not os.path.isfile(abs_path):
        print(
            f"{Style.WARNING}  Warning: bodyfile not found: {abs_path}. "
            f"Will attempt auto-detection instead.{Style.RESET}",
            file=sys.stderr,
        )
        return None

    return abs_path


def run_bodyfile_analysis(bodyfile_path: str, output_dir: str, hostname: str) -> Dict:
    """
    Parse a Sleuth Kit bodyfile and produce a chronological MAC timeline CSV.

    Bodyfile format (11 pipe-separated fields):
        MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

    One output row is emitted per (file, timestamp_type) pair where the
    timestamp is non-zero and within a plausible range (1970–2100).

    MAC type legend
    ---------------
    M – Modification time (file content last changed)
    A – Access time      (file last read)
    C – Change time      (metadata last changed, e.g. permissions/owner)
    B – Birth/creation   (not available on all filesystems; may be 0)
    """
    result: Dict = {
        "name": "MAC Timeline (Bodyfile)",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "error": None,
    }

    try:
        import gzip as _gzip

        events: List[Dict] = []
        parse_errors = 0
        total_lines = 0

        # Support gzip-compressed bodyfiles
        is_gz = bodyfile_path.lower().endswith('.gz')
        try:
            if is_gz:
                fh = _gzip.open(bodyfile_path, 'rt', encoding='utf-8', errors='replace')
            else:
                fh = open(bodyfile_path, 'r', encoding='utf-8', errors='replace')
        except Exception as exc:
            result["error"] = f"Cannot open bodyfile: {exc}"
            return result

        def _parse_epoch(s: str) -> int:
            """Convert a bodyfile timestamp string to integer epoch seconds."""
            s = s.strip()
            if not s or s in ('0', '-1'):
                return 0
            try:
                return int(float(s))
            except (ValueError, OverflowError):
                return 0

        with fh:
            for raw_line in fh:
                line = raw_line.rstrip('\n\r')
                if not line or line.startswith('#'):
                    continue
                total_lines += 1

                parts = line.split('|')
                if len(parts) < 11:
                    parse_errors += 1
                    continue

                # The name field (position 1) may itself contain '|'.
                # The last 9 fields are always fixed; everything between
                # field 0 (MD5) and those 9 is the name.
                md5_hash  = parts[0]
                crtime_s  = parts[-1]
                ctime_s   = parts[-2]
                mtime_s   = parts[-3]
                atime_s   = parts[-4]
                size      = parts[-5]
                gid       = parts[-6]
                uid       = parts[-7]
                mode      = parts[-8]
                inode     = parts[-9]
                name      = '|'.join(parts[1:-9])

                atime  = _parse_epoch(atime_s)
                mtime  = _parse_epoch(mtime_s)
                ctime  = _parse_epoch(ctime_s)
                crtime = _parse_epoch(crtime_s)

                is_deleted = (
                    '(deleted)' in name
                    or name.startswith('$OrphanFiles')
                )

                # Plausible epoch range: 1970-01-01 through 2100-01-01
                _MAX_EPOCH = 4102444800

                for mac_type, ts in (('M', mtime), ('A', atime),
                                     ('C', ctime),  ('B', crtime)):
                    if ts <= 0 or ts > _MAX_EPOCH:
                        continue
                    try:
                        dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
                    except (OSError, OverflowError, ValueError):
                        continue

                    events.append({
                        'Timestamp_UTC':   dt_utc.strftime('%Y-%m-%d %H:%M:%S'),
                        'Unix_Epoch':      ts,
                        'MAC_Type':        mac_type,
                        'MAC_Description': _MAC_LABELS[mac_type],
                        'Filename':        name,
                        'Inode':           inode,
                        'Mode':            mode,
                        'UID':             uid,
                        'GID':             gid,
                        'Size_Bytes':      size,
                        'MD5':             md5_hash if md5_hash not in ('0', '') else '',
                        'Is_Deleted':      'Yes' if is_deleted else '',
                    })

        if total_lines == 0:
            result["error"] = "Bodyfile appears empty"
            result["success"] = True
            return result

        if not events:
            result["error"] = (
                f"No valid timestamps found "
                f"({parse_errors} malformed lines out of {total_lines})"
            )
            result["success"] = True
            return result

        # Sort chronologically
        events.sort(key=lambda x: x['Unix_Epoch'])

        output_file = os.path.join(output_dir, f"{hostname}_mac_timeline.csv")
        fieldnames = [
            'Timestamp_UTC', 'Unix_Epoch', 'MAC_Type', 'MAC_Description',
            'Filename', 'Inode', 'Mode', 'UID', 'GID',
            'Size_Bytes', 'MD5', 'Is_Deleted',
        ]
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(events)

        result["output_files"].append(output_file)
        result["event_count"] = len(events)
        result["success"] = True

        if parse_errors:
            result["error"] = (
                f"{parse_errors} lines skipped (malformed)"
            )

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================================
# Coverage Manifest
# ============================================================================

def probe_coverage(source_path: str, analyzer_name: str,
                   expected_artifacts: List[Tuple[str, str, List[str]]]) -> List[Dict]:
    """
    Probe a UAC source for expected artifacts and return coverage entries.

    Args:
        source_path: Path to UAC tarball or directory
        analyzer_name: Name of the analyzer (for context only)
        expected_artifacts: List of (category, description, [path_patterns])
            Each path_pattern is checked; FOUND if any match, NOT_FOUND if none.

    Returns:
        List of coverage dicts with keys: category, expected, status, actual, details
    """
    coverage = []
    try:
        handler = UACHandler(source_path)
        for category, description, patterns in expected_artifacts:
            found_files = []
            for pattern in patterns:
                # Try suffix-based search (quick)
                matches = handler.find_files_by_suffix([pattern])
                if matches:
                    found_files.extend(m[0] for m in matches)
                else:
                    # Try pattern-based search
                    matches = handler.find_files_by_pattern([pattern])
                    if matches:
                        found_files.extend(m[0] for m in matches)

            if found_files:
                # Deduplicate
                unique = sorted(set(found_files))
                detail = f"{len(unique)} file(s)"
                actual = unique[0] if len(unique) == 1 else f"{unique[0]} (+{len(unique)-1} more)"
                coverage.append({
                    "category": category,
                    "expected": description,
                    "status": "FOUND",
                    "actual": actual,
                    "details": detail,
                })
            else:
                coverage.append({
                    "category": category,
                    "expected": description,
                    "status": "NOT_FOUND",
                    "actual": "",
                    "details": "",
                })
        handler.close()
    except Exception:
        pass  # Coverage probe failure should never break analysis
    return coverage


# Per-analyzer expected artifact definitions
# Format: (category, expected_path_description, [search_patterns])
LOGIN_TIMELINE_ARTIFACTS = [
    ("Authentication Log", "/var/log/auth.log*", ["**/auth.log"]),
    ("Authentication Log", "/var/log/secure*", ["**/secure"]),
    ("Login Records", "/var/log/wtmp", ["**/wtmp"]),
    ("Failed Logins", "/var/log/btmp", ["**/btmp"]),
    ("Last Login", "/var/log/lastlog", ["**/lastlog"]),
    ("Audit Log", "/var/log/audit/audit.log*", ["**/audit.log"]),
    ("System Log", "/var/log/syslog*", ["**/syslog"]),
    ("System Messages", "/var/log/messages*", ["**/messages"]),
    ("Shell History", "/root/.bash_history", ["**/.bash_history"]),
]

PERSISTENCE_HUNTER_ARTIFACTS = [
    ("Cron Jobs", "/etc/cron.d/*", ["**/cron.d"]),
    ("Cron Spool", "/var/spool/cron/*", ["**/spool/cron"]),
    ("Crontab", "/etc/crontab", ["**/crontab"]),
    ("Systemd Services", "/etc/systemd/system/*", ["**/systemd/system"]),
    ("Systemd User Units", "~/.config/systemd/user/*", ["**/systemd/user"]),
    ("SSH Authorized Keys", "~/.ssh/authorized_keys", ["**/authorized_keys"]),
    ("Shell Profiles", "/etc/profile.d/*", ["**/profile.d"]),
    ("Bashrc Files", "/etc/bash.bashrc", ["**/bash.bashrc"]),
    ("Init.d Scripts", "/etc/init.d/*", ["**/init.d"]),
    ("RC Local", "/etc/rc.local", ["**/rc.local"]),
    ("LD Preload", "/etc/ld.so.preload", ["**/ld.so.preload"]),
    ("PAM Configuration", "/etc/pam.d/*", ["**/pam.d"]),
    ("Sudoers", "/etc/sudoers*", ["**/sudoers"]),
    ("Udev Rules", "/etc/udev/rules.d/*", ["**/udev/rules.d"]),
    ("Passwd", "/etc/passwd", ["**/etc/passwd"]),
    ("Shadow", "/etc/shadow", ["**/etc/shadow"]),
]

SECURITY_ANALYZER_ARTIFACTS = [
    ("Temp Files", "/tmp/*", ["**/tmp"]),
    ("Dev SHM", "/dev/shm/*", ["**/dev/shm"]),
    ("Var Tmp", "/var/tmp/*", ["**/var/tmp"]),
    ("Environment", "/etc/environment", ["**/etc/environment"]),
    ("LD Library Config", "/etc/ld.so.conf", ["**/ld.so.conf"]),
    ("Capabilities", "/proc/*/status or getcap output", ["**/getcap"]),
]

JOURNAL_ANALYZER_ARTIFACTS = [
    ("Journal Binary", "/var/log/journal/*", ["**/journal"]),
    ("Journal Text Export", "journal text exports", [r"\.journal$"]),
    ("Syslog", "/var/log/syslog*", ["**/syslog"]),
    ("Messages", "/var/log/messages*", ["**/messages"]),
]

NETWORK_ANALYZER_ARTIFACTS = [
    ("Hosts File", "/etc/hosts", ["**/etc/hosts"]),
    ("DNS Config", "/etc/resolv.conf", ["**/resolv.conf"]),
    ("Firewall Logs", "iptables/nftables/ufw logs", ["**/ufw.log", "**/firewalld"]),
    ("Web Access Logs", "Apache/Nginx access logs", ["**/access.log", "**/access_log"]),
    ("Web Error Logs", "Apache/Nginx error logs", ["**/error.log", "**/error_log"]),
]

PACKAGE_ANALYZER_ARTIFACTS = [
    ("DPKG Log", "/var/log/dpkg.log*", ["**/dpkg.log"]),
    ("APT History", "/var/log/apt/history.log*", ["**/apt/history.log"]),
    ("YUM Log", "/var/log/yum.log*", ["**/yum.log"]),
    ("DNF Log", "/var/log/dnf.log*", ["**/dnf.log"]),
    ("Pacman Log", "/var/log/pacman.log*", ["**/pacman.log"]),
    ("Zypper Log", "/var/log/zypper.log*", ["**/zypper.log"]),
]

STRING_ANALYZER_ARTIFACTS = [
    ("Compressed Logs", "*.xz, *.bz2, *.gz log files", ["**/var/log"]),
]

MISC_ARTIFACTS_EXPECTED = [
    ("Archive Files", "Embedded archives (.zip, .7z, .rar, .tar.gz)", ["**/tmp", "**/var/tmp"]),
    ("Hidden Directories", "Directories starting with .", ["**/tmp"]),
    ("Scheduled Tasks", "at/cron/systemd timer configs", ["**/cron", "**/at"]),
]


def write_coverage_csv(output_dir: str, hostname: str, results: List[Dict]) -> Optional[str]:
    """
    Write a coverage manifest CSV showing what each analyzer examined.

    Analysts use this to verify that all expected artifacts were checked and
    to identify gaps in collection coverage.

    Columns:
        Analyzer, Category, Expected_Path, Status, Actual_Path, Details
    """
    rows = []
    for result in results:
        name = result.get("name", "Unknown")
        for entry in result.get("coverage", []):
            rows.append({
                "Analyzer": name,
                "Category": entry.get("category", ""),
                "Expected_Path": entry.get("expected", ""),
                "Status": entry.get("status", ""),
                "Actual_Path": entry.get("actual", ""),
                "Details": entry.get("details", ""),
            })

    if not rows:
        return None

    output_file = os.path.join(output_dir, f"{hostname}_coverage.csv")
    fieldnames = ["Analyzer", "Category", "Expected_Path", "Status",
                  "Actual_Path", "Details"]
    try:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return output_file
    except Exception:
        return None


# ============================================================================
# Main Orchestrator
# ============================================================================

def run_analysis(source_path: str, output_base: str = None, parallel: bool = True,
                verbose: bool = True, memory_path: str = None,
                symbol_dirs: List[str] = None, quick_memory: bool = False,
                bodyfile_path: str = None,
                ioc_path: str = None) -> Tuple[str, List[Dict]]:
    """
    Run all analyzers on the source and output to a unified directory.

    Args:
        source_path: Path to UAC tarball, extracted directory, or directory containing tarballs
        output_base: Base directory for output (default: current directory)
        parallel: Whether to run analyzers in parallel
        verbose: Whether to print progress
        memory_path: Optional path to memory dump for memory analysis
        symbol_dirs: Optional list of symbol directories for memory analysis
        quick_memory: Run quick memory triage instead of full analysis
        bodyfile_path: Optional path to an existing Sleuth Kit bodyfile.
            When provided, this file is used directly for MAC timeline
            analysis and auto-detection is skipped.  When None, the
            function will attempt to locate a bodyfile inside the UAC
            source automatically.

        ioc_path: Optional path to IOC file for scanning and CSV cross-reference

    Returns:
        Tuple of (output_directory, results_list)
    """
    Style.enable_windows_ansi()
    start_time = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    
    # Resolve source path
    source_path = os.path.abspath(source_path)
    
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source not found: {source_path}")
    
    # Determine source type
    is_tarball = any(source_path.lower().endswith(ext) for ext in TARBALL_EXTENSIONS)
    
    # If it's a directory, check if it contains tarballs or is an extracted UAC
    if not is_tarball and os.path.isdir(source_path):
        tarballs_found = find_tarballs_in_directory(source_path)
        is_extracted = is_extracted_uac_directory(source_path)
        
        if tarballs_found and not is_extracted:
            # Directory contains tarballs - run batch analysis
            if verbose:
                print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
                print(f"{Style.HEADER}{Style.BOLD}  Linux Unified Security Analyzer v{__version__}{Style.RESET}", file=sys.stderr)
                print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
                print(f"\n{Style.INFO}Found {len(tarballs_found)} tarball(s) in directory:{Style.RESET}", file=sys.stderr)
                for tb in tarballs_found:
                    print(f"  - {os.path.basename(tb)}", file=sys.stderr)
            
            # Process each tarball
            all_results = []
            output_dirs = []
            for tarball in tarballs_found:
                if verbose:
                    print(f"\n{Style.HEADER}{'='*50}{Style.RESET}", file=sys.stderr)
                    print(f"{Style.INFO}Processing:{Style.RESET} {os.path.basename(tarball)}", file=sys.stderr)
                
                out_dir, results = run_analysis(
                    tarball, output_base, parallel, verbose,
                    memory_path, symbol_dirs, quick_memory,
                    bodyfile_path=None,  # auto-detect per tarball in batch mode
                    ioc_path=ioc_path,
                )
                output_dirs.append(out_dir)
                all_results.extend(results)
            
            if verbose:
                print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
                print(f"{Style.SUCCESS}Batch analysis complete!{Style.RESET}", file=sys.stderr)
                print(f"{Style.INFO}Processed {len(tarballs_found)} tarball(s){Style.RESET}", file=sys.stderr)
                for out_dir in output_dirs:
                    print(f"  - {out_dir}", file=sys.stderr)
            
            return output_dirs[0] if len(output_dirs) == 1 else output_base, all_results
        
        elif tarballs_found and is_extracted:
            # Has both tarballs and extracted content - warn user
            if verbose:
                print(f"\n{Style.WARNING}Warning: Directory contains both tarballs and extracted UAC content.{Style.RESET}", file=sys.stderr)
                print(f"{Style.INFO}Analyzing as extracted directory. To analyze tarballs, specify them directly.{Style.RESET}", file=sys.stderr)
    
    # Extract hostname
    if is_tarball:
        hostname = extract_hostname_from_tarball(source_path)
    else:
        hostname = extract_hostname_from_directory(source_path)
    
    if verbose:
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Linux Unified Security Analyzer v{__version__}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"\n{Style.INFO}Source:{Style.RESET} {source_path}", file=sys.stderr)
        print(f"{Style.INFO}Hostname:{Style.RESET} {hostname}", file=sys.stderr)
        print(f"{Style.INFO}Mode:{Style.RESET} {'Tarball' if is_tarball else 'Directory'}", file=sys.stderr)

    # Create output directory: [hostname]_analysis
    output_base = output_base or os.getcwd()
    output_dir = os.path.join(output_base, f"{hostname}_analysis")
    os.makedirs(output_dir, exist_ok=True)

    if verbose:
        print(f"{Style.INFO}Output Directory:{Style.RESET} {output_dir}", file=sys.stderr)

    # ---- Forensic audit log ---------------------------------------------- #
    audit_log_path = os.path.join(output_dir, f"{hostname}_audit.log")
    audit = ForensicLogger(audit_log_path)

    # ---- Bodyfile resolution --------------------------------------------- #
    # Track whether we extracted the bodyfile to a temp path so we can clean
    # it up after analysis.
    bodyfile_is_temp = False

    if bodyfile_path and os.path.isfile(bodyfile_path):
        # Caller supplied an explicit bodyfile – use it directly.
        if verbose:
            print(
                f"{Style.INFO}Bodyfile:{Style.RESET} {bodyfile_path} (user-supplied)",
                file=sys.stderr,
            )
    else:
        # Try to locate a bodyfile inside the UAC collection.
        detected, bodyfile_is_temp = find_bodyfile_in_source(source_path)
        if detected:
            bodyfile_path = detected
            if verbose:
                print(
                    f"{Style.INFO}Bodyfile:{Style.RESET} auto-detected in UAC collection",
                    file=sys.stderr,
                )
        else:
            bodyfile_path = None
            if verbose:
                print(
                    f"{Style.DIM}Bodyfile: none found – MAC timeline will be skipped{Style.RESET}",
                    file=sys.stderr,
                )

    # Write audit log preamble (now that all options are resolved)
    audit.write_preamble(
        source=source_path, output_dir=output_dir, hostname=hostname,
        bodyfile=bodyfile_path, ioc_path=ioc_path,
        memory_path=memory_path, parallel=parallel,
    )

    # Define analyzers to run
    analyzers = [
        ("Login Timeline",   run_login_timeline),
        ("Journal Analyzer", run_journal_analyzer),
        ("Persistence Hunter", run_persistence_hunter),
        ("Security Analyzer",  run_security_analyzer),
        ("Package Analyzer",   run_package_analyzer),
        ("Network Analyzer",   run_network_analyzer),
        ("Filesystem Timeline", run_filesystem_timeline),
        ("String Analyzer", run_string_analyzer),
        ("Misc Artifacts", run_misc_artifacts),
    ]

    # Prepend bodyfile analyzer when a bodyfile is available.
    if bodyfile_path and os.path.isfile(bodyfile_path):
        _bf_path = bodyfile_path  # capture for closure

        def _run_mac_timeline(src, out_dir, host):
            return run_bodyfile_analysis(_bf_path, out_dir, host)

        analyzers.insert(0, ("MAC Timeline", _run_mac_timeline))
    
    results = []
    
    # Log what each analyzer will examine (written before execution)
    for name, _func in analyzers:
        audit.write_analyzer_start(name)

    if parallel:
        if verbose:
            print(f"\n{Style.INFO}Running {len(analyzers)} analyzers in parallel...{Style.RESET}", file=sys.stderr)

        with ThreadPoolExecutor(max_workers=len(analyzers)) as executor:
            futures = {}
            for name, func in analyzers:
                future = executor.submit(func, source_path, output_dir, hostname)
                futures[future] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    audit.write_analyzer_result(name, result)

                    if verbose:
                        status = Style.SUCCESS + "✓" if result["success"] else Style.ERROR + "✗"
                        counts = []
                        if result.get("event_count"):
                            counts.append(f"{result['event_count']} events")
                        if result.get("finding_count"):
                            counts.append(f"{result['finding_count']} findings")
                        count_str = f" ({', '.join(counts)})" if counts else ""
                        print(f"  {status} {name}{count_str}{Style.RESET}", file=sys.stderr)
                        if not result["success"] and result.get("error"):
                            print(f"       {Style.DIM}{result['error']}{Style.RESET}", file=sys.stderr)

                except Exception as e:
                    err_result = {
                        "name": name,
                        "success": False,
                        "output_files": [],
                        "error": str(e)
                    }
                    results.append(err_result)
                    audit.write_analyzer_result(name, err_result)
                    if verbose:
                        print(f"  {Style.ERROR}✗ {name}: {e}{Style.RESET}", file=sys.stderr)
    else:
        for name, func in analyzers:
            if verbose:
                print(f"\n{Style.INFO}Running {name}...{Style.RESET}", file=sys.stderr)

            try:
                result = func(source_path, output_dir, hostname)
                results.append(result)
                audit.write_analyzer_result(name, result)

                if verbose:
                    if result["success"]:
                        counts = []
                        if result.get("event_count"):
                            counts.append(f"{result['event_count']} events")
                        if result.get("finding_count"):
                            counts.append(f"{result['finding_count']} findings")
                        count_str = f": {', '.join(counts)}" if counts else ""
                        print(f"  {Style.SUCCESS}✓ Complete{count_str}{Style.RESET}", file=sys.stderr)
                    elif result.get("error"):
                        print(f"  {Style.ERROR}✗ Failed: {result['error']}{Style.RESET}", file=sys.stderr)

            except Exception as e:
                err_result = {
                    "name": name,
                    "success": False,
                    "output_files": [],
                    "error": str(e)
                }
                results.append(err_result)
                audit.write_analyzer_result(name, err_result)
                if verbose:
                    print(f"  {Style.ERROR}✗ Error: {e}{Style.RESET}", file=sys.stderr)
    
    # Run memory analyzer if memory path provided
    if memory_path and os.path.exists(memory_path):
        audit.write_analyzer_start("Memory Analyzer")
        if verbose:
            print(f"\n{Style.INFO}Running Memory Analyzer...{Style.RESET}", file=sys.stderr)
            print(f"  {Style.DIM}Image: {memory_path}{Style.RESET}", file=sys.stderr)
            if symbol_dirs:
                print(f"  {Style.DIM}Symbols: {', '.join(symbol_dirs)}{Style.RESET}", file=sys.stderr)
        
        try:
            mem_result = run_memory_analyzer(
                memory_path=memory_path,
                output_dir=output_dir,
                hostname=hostname,
                symbol_dirs=symbol_dirs,
                quick=quick_memory
            )
            results.append(mem_result)
            audit.write_analyzer_result("Memory Analyzer", mem_result)
            
            if verbose:
                if mem_result["success"]:
                    count_str = f" ({mem_result['finding_count']} entries)" if mem_result.get('finding_count') else ""
                    print(f"  {Style.SUCCESS}[OK] Memory Analyzer{count_str}{Style.RESET}", file=sys.stderr)
                else:
                    print(f"  {Style.ERROR}[FAILED] Memory Analyzer: {mem_result.get('error', 'Unknown error')}{Style.RESET}", file=sys.stderr)
        except Exception as e:
            results.append({
                "name": "Memory Analyzer",
                "success": False,
                "output_files": [],
                "error": str(e)
            })
            if verbose:
                print(f"  {Style.ERROR}[FAILED] Memory Analyzer: {e}{Style.RESET}", file=sys.stderr)
    
    # ---- Post-processing: log gap detection --------------------------------- #
    audit.write_analyzer_start("Log Gap Detection")
    if verbose:
        print(f"\n{Style.INFO}Running log gap detection...{Style.RESET}", file=sys.stderr)
    try:
        gap_result = run_log_gap_detection(output_dir, hostname)
        results.append(gap_result)
        audit.write_analyzer_result("Log Gap Detection", gap_result)
        if verbose:
            if gap_result["finding_count"]:
                print(
                    f"  {Style.WARNING}⚠ {gap_result['finding_count']} "
                    f"gap(s) ≥ 6 h in auth timeline{Style.RESET}",
                    file=sys.stderr,
                )
            else:
                print(f"  {Style.SUCCESS}✓ No significant log gaps{Style.RESET}",
                      file=sys.stderr)
    except Exception as exc:
        results.append({"name": "Log Gap Detection", "success": False,
                        "output_files": [], "error": str(exc)})

    # ---- Post-processing: IOC matching -------------------------------------- #
    if ioc_path and os.path.isfile(ioc_path):
        audit.write_analyzer_start("IOC Matcher")
        if verbose:
            print(f"\n{Style.INFO}Running IOC matching...{Style.RESET}",
                  file=sys.stderr)
            print(f"  {Style.DIM}IOC file: {ioc_path}{Style.RESET}", file=sys.stderr)
        try:
            ioc_result = run_ioc_matcher(output_dir, hostname, ioc_path)
            results.append(ioc_result)
            audit.write_analyzer_result("IOC Matcher", ioc_result)
            if verbose:
                if ioc_result["finding_count"]:
                    print(
                        f"  {Style.CRITICAL}!! {ioc_result['finding_count']} "
                        f"IOC hit(s) found{Style.RESET}",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"  {Style.SUCCESS}✓ No IOC matches{Style.RESET}",
                        file=sys.stderr,
                    )
        except Exception as exc:
            results.append({"name": "IOC Matcher", "success": False,
                            "output_files": [], "error": str(exc)})

    # Run IOC scanner if IOC file provided (runs last to also scan analysis output)
    if ioc_path:
        audit.write_analyzer_start("IOC Scanner")
        if verbose:
            print(f"\n{Style.INFO}Running IOC Scanner...{Style.RESET}", file=sys.stderr)
            print(f"  {Style.DIM}IOC File: {ioc_path}{Style.RESET}", file=sys.stderr)

        try:
            ioc_result = run_ioc_scanner(
                source_path=source_path,
                output_dir=output_dir,
                hostname=hostname,
                ioc_file=ioc_path
            )
            results.append(ioc_result)
            audit.write_analyzer_result("IOC Scanner", ioc_result)

            if verbose:
                if ioc_result["success"]:
                    count_str = f" ({ioc_result['finding_count']} matches)" if ioc_result.get('finding_count') else ""
                    print(f"  {Style.SUCCESS}[OK] IOC Scanner{count_str}{Style.RESET}", file=sys.stderr)
                else:
                    print(f"  {Style.ERROR}[FAILED] IOC Scanner: {ioc_result.get('error', 'Unknown error')}{Style.RESET}", file=sys.stderr)
        except Exception as e:
            err_result = {
                "name": "IOC Scanner",
                "success": False,
                "output_files": [],
                "error": str(e)
            }
            results.append(err_result)
            audit.write_analyzer_result("IOC Scanner", err_result)
            if verbose:
                print(f"  {Style.ERROR}[FAILED] IOC Scanner: {e}{Style.RESET}", file=sys.stderr)

    # Write the final audit log summary and close the log file
    audit.write_summary(results)
    audit.close()

    # Write coverage manifest CSV
    coverage_file = write_coverage_csv(output_dir, hostname, results)
    if coverage_file and verbose:
        cov_found = sum(
            1 for r in results for e in r.get("coverage", [])
            if e.get("status") == "FOUND"
        )
        cov_missing = sum(
            1 for r in results for e in r.get("coverage", [])
            if e.get("status") == "NOT_FOUND"
        )
        print(
            f"\n{Style.INFO}Coverage Manifest:{Style.RESET} "
            f"{cov_found} artifacts found, {cov_missing} not found",
            file=sys.stderr,
        )

    end_time = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    # Create summary report
    if verbose:
        print(f"\n{Style.INFO}Creating summary report...{Style.RESET}", file=sys.stderr)
    
    summary_file = create_summary_report(
        output_dir, hostname, results, start_time, end_time,
        bodyfile_path=bodyfile_path if not bodyfile_is_temp else None,
    )
    
    # Print final summary
    if verbose:
        duration = (end_time - start_time).total_seconds()
        
        total_events = sum(r.get("event_count", 0) for r in results)
        total_findings = sum(r.get("finding_count", 0) for r in results)
        successful = sum(1 for r in results if r["success"])
        
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Analysis Complete{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"\n{Style.INFO}Duration:{Style.RESET} {duration:.2f} seconds", file=sys.stderr)
        print(f"{Style.INFO}Analyzers:{Style.RESET} {successful}/{len(results)} successful", file=sys.stderr)
        print(f"{Style.INFO}Total Events:{Style.RESET} {total_events}", file=sys.stderr)
        print(f"{Style.INFO}Total Findings:{Style.RESET} {total_findings}", file=sys.stderr)
        print(f"\n{Style.SUCCESS}Output Directory:{Style.RESET} {output_dir}", file=sys.stderr)
        
        # List output files
        print(f"\n{Style.INFO}Generated Files:{Style.RESET}", file=sys.stderr)
        for filename in sorted(os.listdir(output_dir)):
            filepath = os.path.join(output_dir, filename)
            try:
                size = os.path.getsize(filepath)
                if size > 1024 * 1024:
                    size_str = f"{size / (1024*1024):.1f} MB"
                elif size > 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size} bytes"
            except:
                size_str = ""
            print(f"  • {filename} ({size_str})", file=sys.stderr)

    # Clean up any temporary bodyfile extracted from the tarball
    if bodyfile_is_temp and bodyfile_path and os.path.isfile(bodyfile_path):
        try:
            os.unlink(bodyfile_path)
        except OSError:
            pass

    return output_dir, results


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Linux Unified Security Analyzer - Run all forensic tools together",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

This script runs all Linux forensic analysis tools in parallel and outputs
results to a unified analysis folder named [hostname]_analysis.

Included Analyzers:
  • Login Timeline       - Authentication/login events from logs
  • Journal Analyzer     - Systemd journal entries
  • Persistence Hunter   - MITRE ATT&CK mapped persistence mechanisms
  • Security Analyzer    - Binary/environment security issues
  • Package Analyzer     - Package manager log analysis (dpkg, apt, yum, etc.)
  • Network Analyzer     - Network artifacts (hosts, DNS, firewall, web logs)
  • Filesystem Timeline  - Bodyfile/mactime filesystem timeline generation
  • String Analyzer      - Log carving & string extraction (audit, syslog, web)
  • Misc Artifacts       - Archive files, hidden dirs, scheduled tasks
  • IOC Scanner          - IOC string matching (optional, requires -i flag)
  • Memory Analyzer      - Volatility 3 memory forensics (optional)

Output includes a coverage manifest ([hostname]_coverage.csv) showing
exactly which artifacts were found and which were missing from the collection.

Supported Input Types:
  • UAC tarball (.tar.gz, .tar, .tgz, .tar.bz2, .tar.xz)
  • Extracted UAC directory
  • Directory containing multiple tarballs (batch mode)
  • Live system (use -s /)

Bodyfile / MAC Timeline:
  A Sleuth Kit bodyfile (MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime)
  provides a full filesystem MAC timeline.  You can supply one explicitly
  with --bodyfile; otherwise the tool will auto-detect a bodyfile inside the
  UAC collection.  When running interactively (without --quiet), you will be
  prompted to enter a path (Tab-completion is supported on Unix).

Examples:
  # Analyze a UAC tarball (bodyfile auto-detected if present)
  python linux_analyzer.py -s uac-hostname-20250115.tar.gz

  # Supply an existing bodyfile explicitly
  python linux_analyzer.py -s uac-hostname-20250115.tar.gz --bodyfile /evidence/hostname.body

  # Analyze an extracted UAC directory
  python linux_analyzer.py -s ./extracted_uac/

  # Batch analyze all tarballs in a directory
  python linux_analyzer.py -s ./collections/

  # Analyze with IOC scanning
  python linux_analyzer.py -s hostname.tar.gz -i iocs.txt

  # Analyze with memory dump included
  python linux_analyzer.py -s hostname.tar.gz -m memory.lime --symbols /path/to/symbols

  # Analyze to specific output directory
  python linux_analyzer.py -s hostname.tar.gz -o ./analysis_results/

  # Run analyzers sequentially (not parallel)
  python linux_analyzer.py -s hostname.tar.gz --sequential

IOC Scanning:
  Provide a text file with one IOC string per line (fixed strings, not regex).
  Lines starting with '#' are treated as comments.
  The scanner searches all log files, configs, histories, and analysis output.

Memory Analysis:
  To include memory analysis, you need:
  1. A memory dump file (.lime, .raw, etc.)
  2. Matching symbol files for the kernel

  First-time setup: python linux_memory_analyzer.py --setup
  Identify kernel:  python linux_memory_analyzer.py -i memory.lime --banner

Output:
  Creates directory: [hostname]_analysis/

  Files generated:
    [hostname]_mac_timeline.csv         - Filesystem M/A/C/B timeline (if bodyfile present)
    [hostname]_login_timeline.csv       - Login/auth events
    [hostname]_journal.csv              - Journal entries
    [hostname]_journal_security.csv     - Security-relevant journal entries
    [hostname]_persistence.csv          - ALL scheduled tasks + persistence findings
    [hostname]_security_*.csv           - Security analyzer findings
    [hostname]_analysis_summary.txt     - Summary report
    memory_analysis/*.csv               - Memory forensics results (if -m provided)

    [hostname]_login_timeline.csv              - Login/auth events
    [hostname]_journal.csv                     - Journal entries
    [hostname]_journal_security.csv            - Security-relevant journal entries
    [hostname]_persistence.csv                 - ALL scheduled tasks + persistence findings
    [hostname]_security_*.csv                  - Security analyzer findings
    [hostname]_bodyfile.txt                    - Raw bodyfile (mactime format)
    [hostname]_filesystem_timeline.csv         - Full filesystem timeline CSV
    [hostname]_login_timeline_merged.csv       - Merged login events from all sources
    [hostname]_audit_logs.csv                  - Extracted audit log entries
    [hostname]_syslog_extracted.csv            - Extracted syslog entries
    [hostname]_web_logs.csv                    - Extracted web server logs
    [hostname]_security_events_extracted.csv   - All security-relevant log entries
    [hostname]_archive_files.csv               - Archive files found
    [hostname]_hidden_directories.csv          - Hidden directories
    [hostname]_scheduled_tasks.csv             - Cron, systemd timer, at job configs
    [hostname]_ioc_matches.csv                 - IOC matches (if -i provided)
    [hostname]_analysis_summary.txt            - Summary report
    memory_analysis/*.csv                      - Memory forensics results (if -m provided)
        """
    )
    
    parser.add_argument(
        '-s', '--source',
        required=True,
        help='Source: UAC tarball (.tar.gz) or extracted directory'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='.',
        help='Output base directory (default: current directory)'
    )
    
    parser.add_argument(
        '--sequential',
        action='store_true',
        help='Run analyzers sequentially instead of in parallel'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output'
    )
    
    # IOC scanning options
    parser.add_argument(
        '-i', '--ioc',
        default=None,
        metavar='PATH',
        help=(
            'Path to an IOC file (one indicator per line: IPs, domains, '
            'MD5/SHA256 hashes, file paths). Runs both string-match scanning '
            'and CSV cross-reference after analysis. Lines starting with # '
            'are comments.'
        )
    )

    # Memory analysis options
    parser.add_argument(
        '-m', '--memory',
        default=None,
        help='Path to memory dump file (.lime, .raw, etc.) for memory analysis'
    )
    
    parser.add_argument(
        '--symbols',
        action='append',
        default=[],
        help='Path to symbol directory for memory analysis (can be specified multiple times)'
    )
    
    parser.add_argument(
        '--quick-memory',
        action='store_true',
        help='Run quick memory triage instead of full analysis'
    )

    # Bodyfile option
    parser.add_argument(
        '--bodyfile',
        default=None,
        metavar='PATH',
        help=(
            'Path to an existing Sleuth Kit bodyfile '
            '(MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime). '
            'Bypasses auto-detection from the UAC collection and skips the '
            'interactive prompt.  Supports .gz compressed bodyfiles.'
        )
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    args = parser.parse_args()

    # Resolve paths
    source_path = os.path.abspath(args.source)
    output_base = os.path.abspath(args.output)

    if not os.path.exists(source_path):
        print(f"{Style.ERROR}Error: Source not found: {source_path}{Style.RESET}", file=sys.stderr)
        print(f"{Style.DIM}  Expected: UAC tarball (.tar.gz, .tgz, .tar.bz2, .tar.xz),{Style.RESET}", file=sys.stderr)
        print(f"{Style.DIM}  extracted UAC directory, or directory containing tarballs.{Style.RESET}", file=sys.stderr)
        sys.exit(1)

    # Resolve memory path if provided
    memory_path = os.path.abspath(args.memory) if args.memory else None
    if memory_path and not os.path.exists(memory_path):
        print(f"{Style.ERROR}Error: Memory image not found: {memory_path}{Style.RESET}", file=sys.stderr)
        print(f"{Style.DIM}  Expected: .lime, .raw, .vmem, or other memory dump format.{Style.RESET}", file=sys.stderr)
        sys.exit(1)

    # Resolve bodyfile path
    # Priority: --bodyfile flag > interactive prompt > auto-detection inside run_analysis()
    bodyfile_path: Optional[str] = None
    if args.bodyfile:
        bp = os.path.abspath(os.path.expanduser(args.bodyfile))
        if not os.path.isfile(bp):
            print(
                f"{Style.ERROR}Error: Bodyfile not found: {bp}{Style.RESET}",
                file=sys.stderr,
            )
            print(
                f"{Style.DIM}  Expected: Sleuth Kit bodyfile (MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime).{Style.RESET}",
                file=sys.stderr,
            )
            print(
                f"{Style.DIM}  Generate with: fls -r -m / /dev/sdX > bodyfile.txt{Style.RESET}",
                file=sys.stderr,
            )
            sys.exit(1)
        bodyfile_path = bp
    else:
        # Interactively prompt the analyst (skipped when --quiet or non-TTY)
        bodyfile_path = prompt_for_bodyfile(quiet=args.quiet)

    # Resolve IOC path
    ioc_path: Optional[str] = None
    if args.ioc:
        ioc_path = os.path.abspath(os.path.expanduser(args.ioc))
        if not os.path.isfile(ioc_path):
            print(
                f"{Style.ERROR}Error: IOC file not found: {ioc_path}{Style.RESET}",
                file=sys.stderr,
            )
            print(
                f"{Style.DIM}  Expected: Plain text, one IOC per line (IPs, domains, MD5/SHA256 hashes, paths).{Style.RESET}",
                file=sys.stderr,
            )
            sys.exit(1)

    try:
        output_dir, results = run_analysis(
            source_path=source_path,
            output_base=output_base,
            parallel=not args.sequential,
            verbose=not args.quiet,
            memory_path=memory_path,
            symbol_dirs=args.symbols if args.symbols else None,
            quick_memory=args.quick_memory,
            bodyfile_path=bodyfile_path,
            ioc_path=ioc_path,
        )
        
        # Exit with error code if any analyzer failed completely
        failures = [r for r in results if not r["success"]]
        if failures:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Analysis interrupted{Style.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

