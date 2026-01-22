#!/usr/bin/env python3
"""
Linux Security Analyzer - Comprehensive System Security and Persistence Detection Tool

This script combines binary analysis and persistence hunting into a single comprehensive
security analyzer for Linux systems (live, mounted images, or UAC tarballs).

BINARY ANALYSIS:
- Programs outside standard OS binary directories
- Programs in hidden directories (names starting with ".")
- Unexpected SUID/SGID files and files with capabilities
- Environment variable settings and suspicious modifications
- Hash matches against known-bad indicators
- Rootkit traces (e.g., /etc/ld.so.preload, modified ld.so.conf)

PERSISTENCE MECHANISM DETECTION:
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

All findings mapped to MITRE ATT&CK technique IDs.

Author: Security Tools
Version: 2.0.0
License: MIT

Requirements: Python 3.6+ (standard library only)
"""

import argparse
import csv
import gzip
import hashlib
import io
import os
import re
import stat
import struct
import sys
import tarfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Set, Tuple

__version__ = "2.0.0"


# ============================================================================
# Console Styling
# ============================================================================

class Style:
    """ANSI escape codes for console styling."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    
    ERROR = RED
    SUCCESS = GREEN
    WARNING = YELLOW
    INFO = CYAN
    HEADER = MAGENTA
    CRITICAL = f"{RED}{BOLD}"
    
    @staticmethod
    def enable_windows_ansi():
        """Enable ANSI escape codes on Windows."""
        if sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass


# ============================================================================
# MITRE ATT&CK Technique Mapping
# ============================================================================

MITRE_TECHNIQUES = {
    "cron": ("Scheduled Task/Job: Cron", "T1053.003"),
    "at": ("Scheduled Task/Job: At", "T1053.002"),
    "systemd_timer": ("Scheduled Task/Job: Systemd Timers", "T1053.006"),
    "systemd_service": ("Create or Modify System Process: Systemd Service", "T1543.002"),
    "systemd_generator": ("Boot or Logon Autostart: Systemd", "T1547.013"),
    "init_script": ("Boot or Logon Initialization Scripts: RC Scripts", "T1037.004"),
    "rc_local": ("Boot or Logon Initialization Scripts: RC Scripts", "T1037.004"),
    "shell_profile": ("Event Triggered Execution: Unix Shell Configuration", "T1546.004"),
    "ssh_authorized_keys": ("Account Manipulation: SSH Authorized Keys", "T1098.004"),
    "backdoor_user": ("Create Account: Local Account", "T1136.001"),
    "ld_preload": ("Hijack Execution Flow: LD_PRELOAD", "T1574.006"),
    "pam_backdoor": ("Modify Authentication Process: PAM", "T1556.003"),
    "sudoers": ("Abuse Elevation Control: Sudo and Sudo Caching", "T1548.003"),
    "suid_sgid": ("Abuse Elevation Control: Setuid and Setgid", "T1548.001"),
    "capabilities": ("Abuse Elevation Control: Setuid and Setgid", "T1548.001"),
    "kernel_module": ("Boot or Logon Autostart: Kernel Modules", "T1547.006"),
    "udev": ("Event Triggered Execution: Udev Rules", "T1546.014"),
    "xdg_autostart": ("Boot or Logon Autostart: XDG Autostart", "T1547.013"),
    "motd": ("Boot or Logon Initialization Scripts: RC Scripts", "T1037.004"),
    "git_hook": ("Event Triggered Execution: Git Hooks", "T1546"),
    "web_shell": ("Server Software Component: Web Shell", "T1505.003"),
    "rootkit": ("Rootkit", "T1014"),
    "container_escape": ("Escape to Host", "T1611"),
    "network_manager": ("Event Triggered Execution", "T1546"),
    "dbus": ("Inter-Process Communication: D-Bus", "T1559"),
    "polkit": ("Abuse Elevation Control", "T1548"),
    "package_hook": ("Event Triggered Execution: Package Managers", "T1546"),
    "grub": ("Pre-OS Boot: Bootkit", "T1542.003"),
    "initramfs": ("Pre-OS Boot", "T1542"),
    "socket_activation": ("Create or Modify System Process", "T1543"),
    "shadow_file": ("OS Credential Dumping: /etc/shadow", "T1003.008"),
    "trap_command": ("Event Triggered Execution: Trap", "T1546.005"),
    "message_queue": ("Inter-Process Communication", "T1559"),
    "ebpf": ("Rootkit", "T1014"),
    "ld_cache": ("Hijack Execution Flow: Dynamic Linker", "T1574.006"),
    "env_variable": ("Hijack Execution Flow: Path Interception", "T1574.007"),
    "suspicious_binary": ("Masquerading", "T1036"),
    "hidden_file": ("Hide Artifacts: Hidden Files", "T1564.001"),
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SecurityFinding:
    """Represents a security finding (binary or persistence)."""
    filepath: str
    finding_type: str
    technique: str
    technique_id: str  # MITRE ATT&CK ID
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    indicator: str = ""
    line_number: int = 0
    raw_content: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""
    file_size: int = 0
    file_mode: str = ""
    extra_info: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for CSV export."""
        return {
            "Filepath": self.filepath,
            "Finding_Type": self.finding_type,
            "Technique": self.technique,
            "MITRE_ATT&CK_ID": self.technique_id,
            "Severity": self.severity,
            "Description": self.description,
            "Indicator": self.indicator[:500] if self.indicator else "",
            "Line_Number": self.line_number,
            "Raw_Content": self.raw_content[:1000] if self.raw_content else "",
            "MD5": self.hash_md5,
            "SHA256": self.hash_sha256,
            "File_Size": self.file_size,
            "File_Mode": self.file_mode,
            "Extra_Info": str(self.extra_info) if self.extra_info else ""
        }


# ============================================================================
# Suspicious Patterns and Indicators
# ============================================================================

SUSPICIOUS_PATHS = ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/var/run/"]

STANDARD_BIN_DIRS = {
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", 
    "/usr/local/bin", "/usr/local/sbin", "/opt"
}

# Suspicious binary names commonly associated with malware
SUSPICIOUS_BINARY_NAMES = {
    "xmrig", "xmr-stak", "minerd", "cpuminer",  # Cryptominers
    "ld-linux.so", "libselinux.so",  # If found in unusual locations
    "backdoor", "rootkit", "payload",
    ".hide", ".hidden", ".cache",  # Hidden binaries
    "ncat", "nc.traditional",  # If unexpected
    "wget2", "curl2",  # Fake/trojanized tools
    "sshd2", "ssh2",  # Fake SSH
}

# Environment variables that are security-sensitive
SENSITIVE_ENV_VARS = {
    "LD_PRELOAD": "CRITICAL",
    "LD_LIBRARY_PATH": "HIGH",
    "LD_AUDIT": "CRITICAL",
    "LD_DEBUG": "MEDIUM",
    "LD_PROFILE": "MEDIUM",
    "PATH": "MEDIUM",
    "PYTHONPATH": "MEDIUM",
    "PERL5LIB": "MEDIUM",
    "RUBYLIB": "MEDIUM",
    "NODE_PATH": "MEDIUM",
    "CLASSPATH": "MEDIUM",
    "http_proxy": "LOW",
    "https_proxy": "LOW",
}

# Persistence location paths
SYSTEMD_PATHS = [
    "etc/systemd/system/", "usr/lib/systemd/system/", "lib/systemd/system/",
    "etc/systemd/user/", "usr/lib/systemd/user/", "run/systemd/system/",
    "run/systemd/generator/", "run/systemd/generator.early/", "run/systemd/generator.late/",
]

CRON_PATHS = [
    "etc/crontab", "etc/cron.d/", "etc/cron.daily/", "etc/cron.hourly/",
    "etc/cron.weekly/", "etc/cron.monthly/", "var/spool/cron/", "var/spool/cron/crontabs/",
]

INIT_PATHS = [
    "etc/init.d/", "etc/rc.local", "etc/rc.d/",
    "etc/rc0.d/", "etc/rc1.d/", "etc/rc2.d/", "etc/rc3.d/",
    "etc/rc4.d/", "etc/rc5.d/", "etc/rc6.d/",
]

KERNEL_MODULE_PATHS = [
    "etc/modules", "etc/modules-load.d/", "etc/modprobe.d/",
    "lib/modules/", "usr/lib/modules/",
]

UDEV_PATHS = [
    "etc/udev/rules.d/", "lib/udev/rules.d/", "usr/lib/udev/rules.d/", "run/udev/rules.d/",
]

# Known legitimate systemd services (reduce false positives)
KNOWN_LEGITIMATE_SERVICES = {
    'sshd.service', 'ssh.service', 'systemd-journald.service',
    'systemd-logind.service', 'systemd-udevd.service', 'cron.service',
    'rsyslog.service', 'NetworkManager.service', 'dbus.service',
    'polkit.service', 'snapd.service', 'docker.service', 'containerd.service',
    'multipathd.service', 'auditd.service', 'firewalld.service',
}

# Comprehensive persistence patterns
PERSISTENCE_SUSPICIOUS_PATTERNS = [
    # Reverse shells
    (r'/bin/bash\s+-i\s+>&\s*/dev/tcp/', "Reverse shell pattern"),
    (r'nc\s+-e\s+/bin/', "Netcat reverse shell"),
    (r'ncat\s+.*-e', "Ncat reverse shell"),
    (r'python.*socket.*connect', "Python reverse shell"),
    (r'perl.*socket.*connect', "Perl reverse shell"),
    (r'ruby.*TCPSocket', "Ruby reverse shell"),
    (r'socat.*exec:', "Socat reverse shell"),
    # Download and execute
    (r'curl.*\|\s*(?:ba)?sh', "Curl pipe to shell"),
    (r'wget.*\|\s*(?:ba)?sh', "Wget pipe to shell"),
    (r'curl.*-o.*/tmp/', "Download to /tmp"),
    (r'wget.*-O.*/tmp/', "Download to /tmp"),
    # Base64 encoded commands
    (r'base64\s+-d', "Base64 decode execution"),
    (r'echo.*\|.*base64', "Base64 encoded payload"),
    # Suspicious binary locations
    (r'/tmp/[a-zA-Z0-9]+', "Binary in /tmp"),
    (r'/var/tmp/[a-zA-Z0-9]+', "Binary in /var/tmp"),
    (r'/dev/shm/[a-zA-Z0-9]+', "Binary in /dev/shm"),
    # Cryptominer indicators
    (r'xmrig|xmr-stak|minerd|cpuminer', "Cryptominer detected"),
    (r'stratum\+tcp://', "Mining pool connection"),
    # Backdoor indicators
    (r'ExecStart=.*\.(sh|py|pl)\s*$', "Script execution in systemd"),
    (r'chmod\s+[0-7]*[4-7][0-7]*\s+/tmp/', "Setting executable in /tmp"),
]

KNOWN_SUID_BINARIES = {
    '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/newgrp',
    '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/gpasswd', '/bin/ping',
    '/usr/bin/ping', '/bin/mount', '/bin/umount', '/usr/bin/mount',
    '/usr/bin/umount', '/usr/lib/openssh/ssh-keysign',
    '/usr/libexec/openssh/ssh-keysign', '/usr/bin/pkexec',
}

SHELL_BACKDOOR_PATTERNS = [
    (r'/dev/tcp/', "Bash /dev/tcp reverse shell"),
    (r'bash\s+-i\s+>&', "Interactive bash reverse shell"),
    (r'nc\s+.*-e\s+/bin/', "Netcat reverse shell"),
    (r'ncat\s+.*-e', "Ncat reverse shell"),
    (r'socat\s+.*exec:', "Socat reverse shell"),
    (r'python.*socket.*connect', "Python reverse shell"),
    (r'perl.*socket.*connect', "Perl reverse shell"),
    (r'ruby.*TCPSocket', "Ruby reverse shell"),
    (r'php.*fsockopen', "PHP reverse shell"),
    (r'curl.*\|\s*(?:ba)?sh', "Curl pipe to shell"),
    (r'wget.*\|\s*(?:ba)?sh', "Wget pipe to shell"),
    (r'base64\s+-d.*\|.*(?:ba)?sh', "Base64 decode to shell"),
    (r'eval\s*\$\(.*base64', "Base64 eval execution"),
    (r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', "Hex encoded payload"),
    (r'mkfifo\s+.*nc\s+', "Named pipe reverse shell"),
    (r'0<&\d+-\s*;exec\s+\d+<>/dev/tcp', "File descriptor reverse shell"),
    (r'exec\s+\d+<>/dev/tcp', "Exec reverse shell"),
    (r'zsh\s+-c.*zsocket', "Zsh socket reverse shell"),
    (r'openssl\s+s_client', "OpenSSL reverse shell"),
    (r'xterm\s+-display', "Xterm reverse shell"),
    (r'telnet\s+.*\|\s*/bin/', "Telnet reverse shell"),
]

CRON_SUSPICIOUS_PATTERNS = [
    (r'@reboot\s+.*(/tmp/|/var/tmp/|/dev/shm/)', "Reboot persistence in temp dir"),
    (r'\*/\d+\s+\*\s+\*\s+\*\s+\*.*curl', "Frequent curl execution"),
    (r'\*/\d+\s+\*\s+\*\s+\*\s+\*.*wget', "Frequent wget execution"),
    (r'.*>\s*/dev/null\s+2>&1\s*$', "Output suppression (potential stealth)"),
]

WEB_SHELL_PATTERNS = [
    (r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', "PHP eval injection"),
    (r'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)', "PHP base64 decode injection"),
    (r'system\s*\(\s*\$_(GET|POST|REQUEST)', "PHP system command injection"),
    (r'exec\s*\(\s*\$_(GET|POST|REQUEST)', "PHP exec command injection"),
    (r'passthru\s*\(\s*\$_(GET|POST|REQUEST)', "PHP passthru injection"),
    (r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)', "PHP shell_exec injection"),
    (r'assert\s*\(\s*\$_(GET|POST|REQUEST)', "PHP assert injection"),
    (r'preg_replace.*\/e', "PHP preg_replace code execution"),
    (r'create_function\s*\(.*\$_(GET|POST)', "PHP create_function injection"),
    (r'<\?php.*\$_(GET|POST|REQUEST)\[.*\].*\?>', "Simple PHP web shell"),
    (r'c99|r57|b374k|weevely|wso|alfa', "Known web shell signature"),
]

PAM_BACKDOOR_PATTERNS = [
    (r'pam_permit\.so', "pam_permit allows all authentication"),
    (r'pam_exec\.so.*seteuid', "pam_exec with seteuid"),
    (r'auth\s+sufficient.*pam_permit', "Sufficient pam_permit (auth bypass)"),
    (r'auth\s+optional.*pam_exec', "Optional pam_exec (potential backdoor)"),
]

ROOTKIT_INDICATORS = [
    (r'diamorphine', "Diamorphine LKM rootkit"),
    (r'reptile', "Reptile LKM rootkit"),
    (r'bdvl', "BDVL rootkit"),
    (r'jynx', "Jynx rootkit"),
    (r'azazel', "Azazel rootkit"),
    (r'vlany', "Vlany rootkit"),
    (r'libprocesshider', "Process hider library"),
    (r'xhide', "Process hiding"),
    (r'/dev/\.', "Hidden device file"),
    (r'LD_PRELOAD.*hide', "LD_PRELOAD hiding"),
]

DANGEROUS_CAPABILITIES = [
    'cap_setuid', 'cap_setgid', 'cap_dac_override', 'cap_dac_read_search',
    'cap_fowner', 'cap_chown', 'cap_sys_admin', 'cap_sys_ptrace',
    'cap_sys_module', 'cap_net_admin', 'cap_net_raw', 'cap_sys_rawio',
]


# ============================================================================
# Path Security Functions
# ============================================================================

def is_safe_path(base_path: str, target_path: str) -> bool:
    """Validate that target_path is within base_path (prevent path traversal)."""
    try:
        base = os.path.abspath(base_path)
        target = os.path.abspath(target_path)
        common = os.path.commonpath([base, target])
        return common == base
    except ValueError:
        return False


def calculate_hashes(data: bytes) -> Tuple[str, str]:
    """Calculate MD5 and SHA256 hashes of data."""
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


def is_elf_binary(data: bytes) -> bool:
    """Check if data is an ELF binary."""
    return len(data) >= 4 and data[:4] == b'\x7fELF'


def is_script(data: bytes) -> bool:
    """Check if data is a script (starts with shebang)."""
    return len(data) >= 2 and data[:2] == b'#!'


def is_executable(data: bytes) -> bool:
    """Check if data appears to be executable."""
    return is_elf_binary(data) or is_script(data)


def is_hidden_path(path: str) -> bool:
    """Check if any component of the path is hidden (starts with .)."""
    parts = PurePosixPath(path).parts
    for part in parts:
        if part.startswith('.') and part not in ('.', '..'):
            return True
    return False


# ============================================================================
# UAC Tarball Handler
# ============================================================================

class UACHandler:
    """Handler for reading files from UAC tarballs or directories."""
    
    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2')
    
    def __init__(self, source_path: str):
        self.source_path = source_path
        self.is_tarball = self._is_tarball(source_path)
        self.tar = None
        self.root_prefix = ""
        self.hostname = ""
        self._members_cache = None
        
        if self.is_tarball:
            self._open_tarball()
    
    def _is_tarball(self, path: str) -> bool:
        return any(path.lower().endswith(ext) for ext in self.TAR_EXTENSIONS)
    
    def _open_tarball(self):
        """Open the tarball and detect structure."""
        try:
            if self.source_path.endswith('.gz') or self.source_path.endswith('.tgz'):
                self.tar = tarfile.open(self.source_path, 'r:gz')
            elif self.source_path.endswith('.bz2') or self.source_path.endswith('.tbz2'):
                self.tar = tarfile.open(self.source_path, 'r:bz2')
            else:
                self.tar = tarfile.open(self.source_path, 'r:')
            
            self._members_cache = self.tar.getmembers()
            self._detect_structure()
        except Exception as e:
            raise RuntimeError(f"Failed to open tarball: {e}")
    
    def _detect_structure(self):
        """Detect UAC directory structure and hostname."""
        if not self._members_cache:
            return
        
        for member in self._members_cache[:100]:
            name = member.name.replace("\\", "/")
            if '/var/log/' in name or '/etc/' in name:
                idx = name.find('/var/') if '/var/' in name else name.find('/etc/')
                if idx > 0:
                    self.root_prefix = name[:idx]
                    parts = self.root_prefix.strip('/').split('/')
                    if parts:
                        self.hostname = parts[0]
                break
        
        # Try to extract hostname from tarball filename
        if not self.hostname:
            basename = os.path.basename(self.source_path)
            for ext in self.TAR_EXTENSIONS:
                if basename.lower().endswith(ext):
                    basename = basename[:-len(ext)]
                    break
            # Take first part before common separators
            for sep in ['-', '_', '.']:
                if sep in basename:
                    self.hostname = basename.split(sep)[0]
                    break
            if not self.hostname:
                self.hostname = basename
    
    def close(self):
        if self.tar:
            self.tar.close()
    
    def get_file(self, path: str) -> Optional[bytes]:
        """Get file contents from tarball or directory."""
        if self.is_tarball:
            return self._get_file_tarball(path)
        else:
            return self._get_file_directory(path)
    
    def _get_file_tarball(self, path: str) -> Optional[bytes]:
        """Extract file from tarball."""
        paths_to_try = [path, path.lstrip('/')]
        if self.root_prefix:
            paths_to_try.append(f"{self.root_prefix}/{path.lstrip('/')}")
            paths_to_try.append(f"{self.root_prefix}{path}")
        
        for try_path in paths_to_try:
            try:
                member = self.tar.getmember(try_path)
                f = self.tar.extractfile(member)
                if f:
                    data = f.read()
                    f.close()
                    if try_path.endswith('.gz'):
                        try:
                            data = gzip.decompress(data)
                        except:
                            pass
                    return data
            except KeyError:
                continue
        return None
    
    def _get_file_directory(self, path: str) -> Optional[bytes]:
        """Read file from directory."""
        full_path = os.path.join(self.source_path, path.lstrip('/'))
        if not os.path.isfile(full_path):
            return None
        try:
            if full_path.endswith('.gz'):
                with gzip.open(full_path, 'rb') as f:
                    return f.read()
            else:
                with open(full_path, 'rb') as f:
                    return f.read()
        except Exception:
            return None
    
    def get_members(self) -> List:
        """Get all members (for tarball) or walk directory."""
        if self.is_tarball and self._members_cache:
            return self._members_cache
        return []
    
    def find_files(self, patterns: List[str]) -> List[Tuple[str, Optional[tarfile.TarInfo]]]:
        """Find files matching patterns."""
        if self.is_tarball:
            return self._find_files_tarball(patterns)
        else:
            return self._find_files_directory(patterns)
    
    def _find_files_tarball(self, patterns: List[str]) -> List[Tuple[str, tarfile.TarInfo]]:
        matches = []
        for member in self._members_cache or []:
            if member.isdir():
                continue
            name = member.name.replace("\\", "/")
            for pattern in patterns:
                if pattern in name:
                    matches.append((name, member))
                    break
        return matches
    
    def _find_files_directory(self, patterns: List[str]) -> List[Tuple[str, None]]:
        matches = []
        for root, dirs, files in os.walk(self.source_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, self.source_path)
                for pattern in patterns:
                    if pattern in rel_path:
                        matches.append((rel_path, None))
                        break
        return matches
    
    def list_directory(self, path: str) -> List[str]:
        """List files in a directory."""
        if self.is_tarball:
            return self._list_dir_tarball(path)
        else:
            return self._list_dir_directory(path)
    
    def _list_dir_tarball(self, path: str) -> List[str]:
        results = []
        path = path.rstrip('/') + '/'
        paths_to_check = [path]
        if self.root_prefix:
            paths_to_check.append(f"{self.root_prefix}/{path.lstrip('/')}")
        
        for member in self._members_cache or []:
            name = member.name.replace("\\", "/")
            for check_path in paths_to_check:
                if name.startswith(check_path) and not member.isdir():
                    results.append(name)
                    break
        return results
    
    def _list_dir_directory(self, path: str) -> List[str]:
        full_path = os.path.join(self.source_path, path.lstrip('/'))
        if not os.path.isdir(full_path):
            return []
        try:
            return [os.path.join(path, f) for f in os.listdir(full_path)]
        except (PermissionError, OSError):
            return []


# ============================================================================
# Main Security Analyzer Class
# ============================================================================

class LinuxSecurityAnalyzer:
    """Comprehensive Linux security analyzer combining binary and persistence checks."""
    
    def __init__(self, source_path: str, output_dir: str = None, known_hashes: Dict[str, str] = None):
        self.source_path = os.path.abspath(source_path) if source_path != "/" else "/"
        self.output_dir = output_dir or os.getcwd()
        self.known_hashes = known_hashes or {}
        
        self.handler = UACHandler(source_path)
        self.hostname = self.handler.hostname or "unknown"
        
        self.findings: List[SecurityFinding] = []
        self.stats = defaultdict(int)
    
    def close(self):
        self.handler.close()
    
    def _add_finding(self, filepath: str, finding_type: str, technique_key: str,
                     severity: str, description: str, indicator: str = "",
                     line_number: int = 0, raw_content: str = "",
                     hash_md5: str = "", hash_sha256: str = "",
                     file_size: int = 0, file_mode: str = "",
                     extra_info: Dict = None):
        """Add a security finding."""
        technique, technique_id = MITRE_TECHNIQUES.get(
            technique_key, ("Unknown", "N/A")
        )
        
        self.findings.append(SecurityFinding(
            filepath=filepath,
            finding_type=finding_type,
            technique=technique,
            technique_id=technique_id,
            severity=severity,
            description=description,
            indicator=indicator,
            line_number=line_number,
            raw_content=raw_content,
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
            file_size=file_size,
            file_mode=file_mode,
            extra_info=extra_info or {}
        ))
        self.stats[finding_type] += 1
    
    def _check_patterns(self, filepath: str, content: str, 
                        patterns: List[Tuple[str, str]], 
                        technique_key: str, finding_type: str,
                        severity: str = "HIGH") -> int:
        """Check content against patterns and add findings."""
        count = 0
        for pattern, description in patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self._add_finding(
                    filepath=filepath,
                    finding_type=finding_type,
                    technique_key=technique_key,
                    severity=severity,
                    description=description,
                    indicator=match.group(0)[:200],
                    line_number=line_num,
                    raw_content=content[max(0, match.start()-50):match.end()+50]
                )
                count += 1
        return count
    
    # ========================================================================
    # Main Analysis Entry Point
    # ========================================================================
    
    def analyze(self, verbose: bool = True) -> None:
        """Run all security checks."""
        Style.enable_windows_ansi()
        
        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}  Linux Security Analyzer v{__version__}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
            print(f"\n{Style.INFO}Source:{Style.RESET} {self.source_path}", file=sys.stderr)
            print(f"{Style.INFO}Hostname:{Style.RESET} {self.hostname}", file=sys.stderr)
            print(f"{Style.INFO}Mode:{Style.RESET} {'Tarball' if self.handler.is_tarball else 'Directory'}", file=sys.stderr)
        
        checks = [
            ("Rootkit traces", self._check_rootkit_traces),
            ("Environment variables", self._check_environment),
            ("Suspicious binaries", self._check_suspicious_binaries),
            ("SUID/SGID files", self._check_suid_sgid),
            ("Hidden executables", self._check_hidden_executables),
            ("Cron jobs", self._check_cron),
            ("Systemd services", self._check_systemd),
            ("Init scripts", self._check_init_scripts),
            ("SSH authorized_keys", self._check_ssh_keys),
            ("Backdoor users", self._check_backdoor_users),
            ("Shell profiles", self._check_shell_profiles),
            ("LD_PRELOAD hijacking", self._check_ld_preload),
            ("PAM configuration", self._check_pam),
            ("Sudoers", self._check_sudoers),
            ("File capabilities", self._check_capabilities),
            ("Kernel modules", self._check_kernel_modules),
            ("Udev rules", self._check_udev),
            ("XDG autostart", self._check_xdg_autostart),
            ("Web shells", self._check_web_shells),
            ("Container escape", self._check_container_escape),
            ("Shadow file", self._check_shadow),
        ]
        
        total = len(checks)
        for i, (name, check_func) in enumerate(checks, 1):
            if verbose:
                print(f"\n{Style.INFO}[{i}/{total}] Checking {name}...{Style.RESET}", file=sys.stderr)
            try:
                count = check_func()
                if verbose and count > 0:
                    print(f"  {Style.WARNING}Found {count} issues{Style.RESET}", file=sys.stderr)
                elif verbose:
                    print(f"  {Style.SUCCESS}Clean{Style.RESET}", file=sys.stderr)
            except Exception as e:
                if verbose:
                    print(f"  {Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        
        if verbose:
            self._print_summary()
    
    # ========================================================================
    # Binary Analysis Checks
    # ========================================================================
    
    def _check_rootkit_traces(self) -> int:
        """Check for rootkit indicators."""
        count = 0
        
        # Check ld.so.preload
        data = self.handler.get_file("etc/ld.so.preload")
        if data:
            content = data.decode('utf-8', errors='replace')
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
            if lines:
                self._add_finding(
                    filepath="/etc/ld.so.preload",
                    finding_type="ROOTKIT_LD_PRELOAD",
                    technique_key="ld_preload",
                    severity="CRITICAL",
                    description=f"ld.so.preload contains {len(lines)} entries",
                    indicator=", ".join(lines[:5]),
                    extra_info={"entries": lines}
                )
                count += 1
        
        # Check ld.so.conf for suspicious paths
        data = self.handler.get_file("etc/ld.so.conf")
        if data:
            content = data.decode('utf-8', errors='replace')
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('include'):
                    if any(susp in line for susp in ['/tmp', '/var/tmp', '/dev/shm', '/home']):
                        self._add_finding(
                            filepath="/etc/ld.so.conf",
                            finding_type="ROOTKIT_LD_CONF",
                            technique_key="ld_cache",
                            severity="HIGH",
                            description=f"Suspicious library path: {line}",
                            indicator=line
                        )
                        count += 1
        
        # Check for rootkit patterns in various files
        for filepath, member in self.handler.find_files(['etc/', 'lib/']):
            data = self.handler.get_file(filepath)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    count += self._check_patterns(
                        filepath, content, ROOTKIT_INDICATORS,
                        "rootkit", "ROOTKIT_INDICATOR", "CRITICAL"
                    )
                except:
                    pass
        
        return count
    
    def _check_environment(self) -> int:
        """Check environment configuration files for suspicious settings."""
        count = 0
        env_files = [
            "etc/environment", "etc/profile", "etc/bash.bashrc", "etc/bashrc",
            "etc/zshrc", "etc/csh.cshrc", "etc/csh.login",
            "root/.bashrc", "root/.bash_profile", "root/.profile", "root/.zshrc"
        ]
        
        # Also check profile.d directory
        for filepath in self.handler.list_directory("etc/profile.d/"):
            env_files.append(filepath)
        
        # Check user home directories
        for filepath, _ in self.handler.find_files(['.bashrc', '.bash_profile', '.profile', '.zshrc']):
            if filepath not in env_files:
                env_files.append(filepath)
        
        for env_file in env_files:
            data = self.handler.get_file(env_file)
            if not data:
                continue
            
            content = data.decode('utf-8', errors='replace')
            
            # Check for backdoor patterns in environment files
            count += self._check_patterns(f"/{env_file}", content, SHELL_BACKDOOR_PATTERNS, "shell_profile", "ENV_BACKDOOR", "CRITICAL")
            
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                match = re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
                if match:
                    var_name, var_value = match.groups()
                    var_value = var_value.strip('"\'')
                    
                    if var_name in SENSITIVE_ENV_VARS:
                        severity = SENSITIVE_ENV_VARS[var_name]
                        
                        # Additional severity checks
                        if var_name == "LD_PRELOAD":
                            severity = "CRITICAL"
                            description = "LD_PRELOAD set - can inject libraries"
                        elif var_name == "LD_LIBRARY_PATH" and any(p in var_value for p in SUSPICIOUS_PATHS):
                            severity = "CRITICAL"
                            description = "LD_LIBRARY_PATH includes suspicious directory"
                        elif var_name == "PATH" and any(p in var_value for p in SUSPICIOUS_PATHS):
                            severity = "HIGH"
                            description = "PATH includes suspicious directory"
                        elif var_name == "PATH":
                            continue  # Normal PATH without suspicious dirs
                        else:
                            description = f"Security-sensitive variable {var_name} set"
                        
                        self._add_finding(
                            filepath=f"/{env_file}",
                            finding_type="ENV_VARIABLE",
                            technique_key="env_variable",
                            severity=severity,
                            description=description,
                            indicator=f"{var_name}={var_value[:200]}",
                            line_number=line_num
                        )
                        count += 1
                
                # Check for curl/wget piped to shell
                if re.search(r'(curl|wget).*\|\s*(bash|sh|python|perl)', line, re.IGNORECASE):
                    self._add_finding(
                        filepath=f"/{env_file}",
                        finding_type="ENV_REMOTE_EXEC",
                        technique_key="env_variable",
                        severity="CRITICAL",
                        description="Remote script execution pattern detected",
                        indicator=line[:200],
                        line_number=line_num
                    )
                    count += 1
        
        return count
    
    def _check_suspicious_binaries(self) -> int:
        """Check for binaries in suspicious locations and with suspicious names."""
        count = 0
        
        if self.handler.is_tarball:
            for member in self.handler.get_members():
                if not member.isfile():
                    continue
                
                path = '/' + member.name.lstrip('/')
                filename = os.path.basename(path)
                
                is_suspicious_loc = any(susp in path for susp in SUSPICIOUS_PATHS)
                is_suspicious_name = any(sus_name in filename.lower() for sus_name in SUSPICIOUS_BINARY_NAMES)
                is_outside_standard = not any(path.startswith(d) for d in STANDARD_BIN_DIRS)
                
                # Skip if not suspicious by any criteria
                should_check = is_suspicious_loc or is_suspicious_name
                
                if should_check:
                    data = self.handler.get_file(member.name)
                    if data and is_executable(data):
                        md5, sha256 = calculate_hashes(data)
                        known_bad = md5 in self.known_hashes or sha256 in self.known_hashes
                        
                        # Determine severity
                        if known_bad:
                            severity = "CRITICAL"
                            desc = self.known_hashes.get(md5) or self.known_hashes.get(sha256)
                        elif is_suspicious_name:
                            severity = "CRITICAL"
                            desc = f"Suspicious binary name: {filename}"
                        elif is_suspicious_loc:
                            severity = "HIGH"
                            desc = f"Executable in suspicious location: {path}"
                        else:
                            severity = "MEDIUM"
                            desc = "Executable outside standard directories"
                        
                        self._add_finding(
                            filepath=path,
                            finding_type="SUSPICIOUS_BINARY",
                            technique_key="suspicious_binary",
                            severity=severity,
                            description=desc,
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=member.size,
                            file_mode=stat.filemode(member.mode) if member.mode else ""
                        )
                        count += 1
                
                # Also check for executables with suspicious names anywhere
                elif is_suspicious_name:
                    data = self.handler.get_file(member.name)
                    if data and is_executable(data):
                        md5, sha256 = calculate_hashes(data)
                        self._add_finding(
                            filepath=path,
                            finding_type="SUSPICIOUS_BINARY",
                            technique_key="suspicious_binary",
                            severity="HIGH",
                            description=f"Binary with suspicious name: {filename}",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=member.size,
                            file_mode=stat.filemode(member.mode) if member.mode else ""
                        )
                        count += 1
        else:
            # Directory scan - check suspicious locations
            for susp_dir in SUSPICIOUS_PATHS:
                full_path = os.path.join(self.source_path, susp_dir.lstrip('/'))
                if not os.path.isdir(full_path):
                    continue
                
                for root, dirs, files in os.walk(full_path):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'rb') as f:
                                data = f.read(1024)
                            if is_executable(data):
                                with open(filepath, 'rb') as f:
                                    full_data = f.read()
                                md5, sha256 = calculate_hashes(full_data)
                                file_stat = os.stat(filepath)
                                
                                known_bad = md5 in self.known_hashes or sha256 in self.known_hashes
                                is_suspicious_name = any(sus in filename.lower() for sus in SUSPICIOUS_BINARY_NAMES)
                                
                                severity = "CRITICAL" if known_bad or is_suspicious_name else "HIGH"
                                desc = self.known_hashes.get(md5) or self.known_hashes.get(sha256) or "Executable in suspicious location"
                                
                                self._add_finding(
                                    filepath=filepath,
                                    finding_type="SUSPICIOUS_BINARY",
                                    technique_key="suspicious_binary",
                                    severity=severity,
                                    description=desc,
                                    hash_md5=md5,
                                    hash_sha256=sha256,
                                    file_size=file_stat.st_size,
                                    file_mode=stat.filemode(file_stat.st_mode)
                                )
                                count += 1
                        except (IOError, OSError, PermissionError):
                            pass
            
            # Scan all directories for suspicious binary names
            for root, dirs, files in os.walk(self.source_path):
                for filename in files:
                    if any(sus in filename.lower() for sus in SUSPICIOUS_BINARY_NAMES):
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'rb') as f:
                                data = f.read()
                            if is_executable(data):
                                md5, sha256 = calculate_hashes(data)
                                file_stat = os.stat(filepath)
                                
                                self._add_finding(
                                    filepath=filepath,
                                    finding_type="SUSPICIOUS_BINARY",
                                    technique_key="suspicious_binary",
                                    severity="HIGH",
                                    description=f"Binary with suspicious name: {filename}",
                                    hash_md5=md5,
                                    hash_sha256=sha256,
                                    file_size=file_stat.st_size,
                                    file_mode=stat.filemode(file_stat.st_mode)
                                )
                                count += 1
                        except (IOError, OSError, PermissionError):
                            pass
        
        return count
    
    def _check_suid_sgid(self) -> int:
        """Check for unexpected SUID/SGID files."""
        count = 0
        
        if self.handler.is_tarball:
            for member in self.handler.get_members():
                if not member.isfile():
                    continue
                
                is_suid = bool(member.mode & stat.S_ISUID)
                is_sgid = bool(member.mode & stat.S_ISGID)
                
                if is_suid or is_sgid:
                    path = '/' + member.name.lstrip('/')
                    # Remove UAC prefix if present
                    for pattern in ['/var/', '/etc/', '/usr/', '/bin/', '/sbin/']:
                        if pattern in path:
                            idx = path.find(pattern)
                            path = path[idx:]
                            break
                    
                    is_known = path in KNOWN_SUID_BINARIES
                    is_suspicious_loc = any(s in path for s in SUSPICIOUS_PATHS)
                    
                    if not is_known or is_suspicious_loc:
                        severity = "CRITICAL" if is_suspicious_loc else ("HIGH" if not is_known else "MEDIUM")
                        suid_type = []
                        if is_suid:
                            suid_type.append("SUID")
                        if is_sgid:
                            suid_type.append("SGID")
                        
                        data = self.handler.get_file(member.name)
                        md5, sha256 = calculate_hashes(data) if data else ("", "")
                        
                        self._add_finding(
                            filepath=path,
                            finding_type=f"UNEXPECTED_{'+'.join(suid_type)}",
                            technique_key="suid_sgid",
                            severity=severity,
                            description=f"{'+'.join(suid_type)} binary: {path}",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=member.size,
                            file_mode=stat.filemode(member.mode)
                        )
                        count += 1
        
        return count
    
    def _check_hidden_executables(self) -> int:
        """Check for hidden executable files."""
        count = 0
        
        if self.handler.is_tarball:
            for member in self.handler.get_members():
                if not member.isfile():
                    continue
                
                if is_hidden_path(member.name):
                    data = self.handler.get_file(member.name)
                    if data and is_executable(data):
                        md5, sha256 = calculate_hashes(data)
                        self._add_finding(
                            filepath='/' + member.name.lstrip('/'),
                            finding_type="HIDDEN_EXECUTABLE",
                            technique_key="hidden_file",
                            severity="HIGH",
                            description="Executable in hidden location",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=member.size
                        )
                        count += 1
        
        return count
    
    # ========================================================================
    # Persistence Mechanism Checks
    # ========================================================================
    
    def _check_cron(self) -> int:
        """Check cron jobs for suspicious entries."""
        count = 0
        
        for cron_path in CRON_PATHS:
            files = self.handler.list_directory(cron_path) if cron_path.endswith('/') else [cron_path]
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                content = data.decode('utf-8', errors='replace')
                
                # Check for shell backdoor patterns
                count += self._check_patterns(f"/{filepath}", content, SHELL_BACKDOOR_PATTERNS, "cron", "CRON_BACKDOOR", "CRITICAL")
                
                # Check for cron-specific suspicious patterns
                count += self._check_patterns(f"/{filepath}", content, CRON_SUSPICIOUS_PATTERNS, "cron", "CRON_SUSPICIOUS", "HIGH")
                
                # Check for persistence patterns
                count += self._check_patterns(f"/{filepath}", content, PERSISTENCE_SUSPICIOUS_PATTERNS, "cron", "CRON_PERSISTENCE", "HIGH")
                
                # Check for suspicious cron timing (every minute, reboot)
                for line_num, line in enumerate(content.split('\n'), 1):
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    # Every minute cron job
                    if re.match(r'^\*\s+\*\s+\*\s+\*\s+\*\s+', line):
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="CRON_EVERY_MINUTE",
                            technique_key="cron",
                            severity="MEDIUM",
                            description="Cron job runs every minute",
                            indicator=line[:200],
                            line_number=line_num
                        )
                        count += 1
                    
                    # Reboot cron job
                    if '@reboot' in line.lower():
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="CRON_AT_REBOOT",
                            technique_key="cron",
                            severity="MEDIUM",
                            description="Cron job runs at system reboot",
                            indicator=line[:200],
                            line_number=line_num
                        )
                        count += 1
                    
                    # Check for suspicious binary locations
                    if any(s in line for s in SUSPICIOUS_PATHS):
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="CRON_SUSPICIOUS_PATH",
                            technique_key="cron",
                            severity="HIGH",
                            description="Cron job references suspicious path",
                            indicator=line[:200],
                            line_number=line_num
                        )
                        count += 1
        return count
    
    def _check_systemd(self) -> int:
        """Check systemd units for malicious content."""
        count = 0
        
        for sd_path in SYSTEMD_PATHS:
            for filepath in self.handler.list_directory(sd_path):
                basename = os.path.basename(filepath)
                
                # Check for suspicious filenames
                is_suspicious_name = basename.startswith('.') or any(s in basename.lower() for s in ['backdoor', 'shell', 'mine', 'xmr'])
                
                if not any(filepath.endswith(ext) for ext in ['.service', '.timer', '.socket', '.path', '.target']) and not is_suspicious_name:
                    continue
                
                # Skip known legitimate services if not suspicious
                if basename in KNOWN_LEGITIMATE_SERVICES and not is_suspicious_name:
                    continue
                    
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                    
                content = data.decode('utf-8', errors='replace')
                
                # Check for shell backdoor patterns
                count += self._check_patterns(f"/{filepath}", content, SHELL_BACKDOOR_PATTERNS, "systemd_service", "SYSTEMD_BACKDOOR", "CRITICAL")
                
                # Check for persistence-specific patterns
                count += self._check_patterns(f"/{filepath}", content, PERSISTENCE_SUSPICIOUS_PATTERNS, "systemd_service", "SYSTEMD_SUSPICIOUS_PATTERN", "HIGH")
                
                # Check Exec directives for suspicious paths and commands
                for match in re.finditer(r'(Exec(?:Start|Stop|Reload|StartPre|StartPost|StopPost)?)\s*=\s*(.+)', content):
                    exec_type, exec_cmd = match.groups()
                    exec_cmd = exec_cmd.strip()
                    
                    # Suspicious if executing from /tmp, /var/tmp, /dev/shm, etc
                    if any(s in exec_cmd for s in SUSPICIOUS_PATHS):
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="SYSTEMD_SUSPICIOUS_EXEC",
                            technique_key="systemd_service",
                            severity="HIGH",
                            description=f"{exec_type} runs binary from suspicious path",
                            indicator=exec_cmd[:200]
                        )
                        count += 1
                    
                    # Suspicious if running scripts directly
                    if re.search(r'\.(sh|py|pl|rb)\s*$', exec_cmd):
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="SYSTEMD_SCRIPT_EXEC",
                            technique_key="systemd_service",
                            severity="MEDIUM",
                            description=f"{exec_type} runs script directly",
                            indicator=exec_cmd[:200]
                        )
                        count += 1
                    
                    # Check for base64 decoded execution
                    if 'base64' in exec_cmd.lower() and ('|' in exec_cmd or 'sh' in exec_cmd):
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="SYSTEMD_BASE64_EXEC",
                            technique_key="systemd_service",
                            severity="CRITICAL",
                            description="Base64-encoded command execution",
                            indicator=exec_cmd[:200]
                        )
                        count += 1
                
                # Check for suspicious service properties
                if re.search(r'User\s*=\s*root', content) and re.search(r'WorkingDirectory\s*=\s*(/tmp|/var/tmp|/dev/shm)', content):
                    self._add_finding(
                        filepath=f"/{filepath}",
                        finding_type="SYSTEMD_ROOT_TEMP_DIR",
                        technique_key="systemd_service",
                        severity="HIGH",
                        description="Root service working in temp directory",
                        indicator=filepath
                    )
                    count += 1
                    
        return count
    
    def _check_init_scripts(self) -> int:
        """Check init scripts and rc.local for malicious content."""
        count = 0
        
        # Check rc.local specifically
        data = self.handler.get_file("etc/rc.local")
        if data:
            content = data.decode('utf-8', errors='replace')
            count += self._check_patterns("/etc/rc.local", content, SHELL_BACKDOOR_PATTERNS, "rc_local", "RC_LOCAL_BACKDOOR", "CRITICAL")
            count += self._check_patterns("/etc/rc.local", content, PERSISTENCE_SUSPICIOUS_PATTERNS, "rc_local", "RC_LOCAL_SUSPICIOUS", "HIGH")
            
            # Check if rc.local has been recently modified or is executable
            for line in content.split('\n'):
                if line.strip() and not line.strip().startswith('#'):
                    # Has actual content besides comments
                    self._add_finding(
                        filepath="/etc/rc.local",
                        finding_type="RC_LOCAL_ACTIVE",
                        technique_key="rc_local",
                        severity="MEDIUM",
                        description="rc.local contains active commands",
                        indicator=line[:200]
                    )
                    count += 1
                    break
        
        # Check all init.d scripts
        for filepath in self.handler.list_directory("etc/init.d/"):
            data = self.handler.get_file(filepath)
            if data:
                content = data.decode('utf-8', errors='replace')
                count += self._check_patterns(f"/{filepath}", content, SHELL_BACKDOOR_PATTERNS, "init_script", "INIT_BACKDOOR", "CRITICAL")
                count += self._check_patterns(f"/{filepath}", content, PERSISTENCE_SUSPICIOUS_PATTERNS, "init_script", "INIT_SUSPICIOUS", "HIGH")
        
        # Check all rc.d directories
        for init_path in INIT_PATHS:
            if not init_path.endswith('/'):
                continue
            for filepath in self.handler.list_directory(init_path):
                if filepath.endswith('.sh') or not '.' in os.path.basename(filepath):
                    data = self.handler.get_file(filepath)
                    if data:
                        content = data.decode('utf-8', errors='replace')
                        count += self._check_patterns(f"/{filepath}", content, SHELL_BACKDOOR_PATTERNS, "init_script", "RC_BACKDOOR", "CRITICAL")
                        count += self._check_patterns(f"/{filepath}", content, PERSISTENCE_SUSPICIOUS_PATTERNS, "init_script", "RC_SUSPICIOUS", "HIGH")
        
        return count
    
    def _check_ssh_keys(self) -> int:
        """Check SSH authorized_keys for backdoors."""
        count = 0
        for filepath, _ in self.handler.find_files(['authorized_keys']):
            data = self.handler.get_file(filepath)
            if not data:
                continue
            content = data.decode('utf-8', errors='replace')
            for line_num, line in enumerate(content.split('\n'), 1):
                if 'command=' in line.lower():
                    cmd_match = re.search(r'command="([^"]*)"', line, re.IGNORECASE)
                    if cmd_match and any(p in cmd_match.group(1).lower() for p in ['nc ', 'bash -i', '/dev/tcp', 'curl', 'wget']):
                        self._add_finding(filepath=f"/{filepath}", finding_type="SSH_KEY_BACKDOOR", technique_key="ssh_authorized_keys", severity="CRITICAL", description="SSH key with malicious command", indicator=cmd_match.group(1)[:200], line_number=line_num)
                        count += 1
        return count
    
    def _check_backdoor_users(self) -> int:
        """Check for backdoor users."""
        count = 0
        data = self.handler.get_file("etc/passwd")
        if data:
            content = data.decode('utf-8', errors='replace')
            for line_num, line in enumerate(content.split('\n'), 1):
                parts = line.split(':')
                if len(parts) >= 7:
                    username, uid = parts[0], parts[2]
                    if uid == '0' and username != 'root':
                        self._add_finding(filepath="/etc/passwd", finding_type="BACKDOOR_USER_UID0", technique_key="backdoor_user", severity="CRITICAL", description=f"Non-root user with UID=0: {username}", indicator=line, line_number=line_num)
                        count += 1
        return count
    
    def _check_shell_profiles(self) -> int:
        """Check shell profiles for backdoors."""
        count = 0
        profiles = ["etc/profile", "etc/bash.bashrc", "root/.bashrc", "root/.profile"]
        for filepath, _ in self.handler.find_files(['.bashrc', '.profile', '.zshrc']):
            profiles.append(filepath)
        for profile in profiles:
            data = self.handler.get_file(profile)
            if data:
                content = data.decode('utf-8', errors='replace')
                count += self._check_patterns(f"/{profile}", content, SHELL_BACKDOOR_PATTERNS, "shell_profile", "SHELL_PROFILE_BACKDOOR", "CRITICAL")
        return count
    
    def _check_ld_preload(self) -> int:
        """Check for LD_PRELOAD hijacking."""
        count = 0
        data = self.handler.get_file("etc/ld.so.preload")
        if data:
            content = data.decode('utf-8', errors='replace')
            for line in content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    self._add_finding(filepath="/etc/ld.so.preload", finding_type="LD_PRELOAD_HIJACK", technique_key="ld_preload", severity="CRITICAL", description=f"LD_PRELOAD library", indicator=line.strip())
                    count += 1
        return count
    
    def _check_pam(self) -> int:
        """Check PAM configuration for backdoors."""
        count = 0
        for filepath in self.handler.list_directory("etc/pam.d/"):
            data = self.handler.get_file(filepath)
            if data:
                content = data.decode('utf-8', errors='replace')
                count += self._check_patterns(f"/{filepath}", content, PAM_BACKDOOR_PATTERNS, "pam_backdoor", "PAM_BACKDOOR", "CRITICAL")
        return count
    
    def _check_sudoers(self) -> int:
        """Check sudoers for dangerous configurations."""
        count = 0
        sudoers_files = ["etc/sudoers"] + self.handler.list_directory("etc/sudoers.d/")
        for filepath in sudoers_files:
            data = self.handler.get_file(filepath)
            if not data:
                continue
            content = data.decode('utf-8', errors='replace')
            for line_num, line in enumerate(content.split('\n'), 1):
                if 'NOPASSWD' in line and not line.strip().startswith('#'):
                    severity = "CRITICAL" if 'ALL' in line else "HIGH"
                    self._add_finding(filepath=f"/{filepath}", finding_type="SUDOERS_NOPASSWD", technique_key="sudoers", severity=severity, description="NOPASSWD sudo entry", indicator=line[:200], line_number=line_num)
                    count += 1
        return count
    
    def _check_capabilities(self) -> int:
        """Check for dangerous file capabilities."""
        count = 0
        data = self.handler.get_file("live_response/process/capabilities.txt")
        if data:
            content = data.decode('utf-8', errors='replace')
            for line in content.split('\n'):
                for cap in DANGEROUS_CAPABILITIES:
                    if cap in line.lower():
                        self._add_finding(filepath=line.split()[0] if line.split() else "unknown", finding_type="DANGEROUS_CAPABILITY", technique_key="capabilities", severity="HIGH", description=f"Dangerous capability: {cap}", indicator=line.strip())
                        count += 1
                        break
        return count
    
    def _check_kernel_modules(self) -> int:
        """Check kernel module configuration for suspicious entries."""
        count = 0
        
        suspicious_modules = [
            'diamorphine', 'reptile', 'rootkit', 'hide', 'stealth', 'backdoor',
            'azazel', 'jynx', 'khook', 'suterusu', 'kbeast', 'enyelkm', 'adore'
        ]
        
        for km_path in KERNEL_MODULE_PATHS:
            files = self.handler.list_directory(km_path) if km_path.endswith('/') else [km_path]
            for filepath in files:
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                    
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                for line_num, line in enumerate(content.split('\n'), 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    module_name = line.split()[0] if line.split() else ""
                    
                    # Check for known rootkit modules
                    if any(susp in module_name.lower() for susp in suspicious_modules):
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="KERNEL_MODULE_ROOTKIT",
                            technique_key="kernel_module",
                            severity="CRITICAL",
                            description=f"Potential rootkit kernel module: {module_name}",
                            indicator=line,
                            line_number=line_num
                        )
                        count += 1
                    
                    # Check modprobe.d for suspicious blacklist removals or insmod options
                    if 'modprobe.d' in filepath:
                        if re.search(r'install\s+\w+\s+/bin/', line):
                            self._add_finding(
                                filepath=f"/{filepath}",
                                finding_type="MODPROBE_INSTALL_HOOK",
                                technique_key="kernel_module",
                                severity="HIGH",
                                description="Module install command hooking",
                                indicator=line,
                                line_number=line_num
                            )
                            count += 1
        
        # Check for suspicious .ko files in /tmp or other unusual locations
        for susp_path in SUSPICIOUS_PATHS:
            for filepath in self.handler.list_directory(susp_path):
                if filepath.endswith('.ko'):
                    data = self.handler.get_file(filepath)
                    if data:
                        md5, sha256 = calculate_hashes(data)
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="KERNEL_MODULE_SUSPICIOUS_LOC",
                            technique_key="kernel_module",
                            severity="CRITICAL",
                            description=f"Kernel module in suspicious location",
                            hash_md5=md5,
                            hash_sha256=sha256
                        )
                        count += 1
        
        return count
    
    def _check_udev(self) -> int:
        """Check udev rules for persistence."""
        count = 0
        
        udev_patterns = [
            (r'RUN\+?="[^"]*(/tmp/|/var/tmp/|/dev/shm/)', "Udev runs from suspicious location"),
            (r'RUN\+?="[^"]*curl', "Udev downloads content"),
            (r'RUN\+?="[^"]*wget', "Udev downloads content"),
            (r'RUN\+?="[^"]*nc\s', "Udev uses netcat"),
            (r'RUN\+?="[^"]*bash\s+-c', "Udev runs bash command"),
            (r'RUN\+?="[^"]*python', "Udev runs Python"),
            (r'RUN\+?="[^"]*perl', "Udev runs Perl"),
            (r'RUN\+?="[^"]*base64', "Udev decodes base64"),
        ]
        
        for udev_path in UDEV_PATHS:
            for filepath in self.handler.list_directory(udev_path):
                data = self.handler.get_file(filepath)
                if not data:
                    continue
                    
                try:
                    content = data.decode('utf-8', errors='replace')
                except Exception:
                    continue
                
                # Check for suspicious udev patterns
                count += self._check_patterns(f"/{filepath}", content, udev_patterns, "udev", "UDEV_SUSPICIOUS", "HIGH")
                count += self._check_patterns(f"/{filepath}", content, SHELL_BACKDOOR_PATTERNS, "udev", "UDEV_BACKDOOR", "CRITICAL")
                
                # Check for ACTION=="add" with suspicious RUN
                for line_num, line in enumerate(content.split('\n'), 1):
                    if 'RUN' in line and any(p in line for p in SUSPICIOUS_PATHS):
                        self._add_finding(
                            filepath=f"/{filepath}",
                            finding_type="UDEV_SUSPICIOUS_PATH",
                            technique_key="udev",
                            severity="HIGH",
                            description="Udev RUN references suspicious path",
                            indicator=line[:200],
                            line_number=line_num
                        )
                        count += 1
        
        return count
    
    def _check_xdg_autostart(self) -> int:
        """Check XDG autostart entries."""
        count = 0
        for filepath, _ in self.handler.find_files(['.config/autostart/']):
            data = self.handler.get_file(filepath)
            if data:
                content = data.decode('utf-8', errors='replace')
                count += self._check_patterns(f"/{filepath}", content, SHELL_BACKDOOR_PATTERNS, "xdg_autostart", "XDG_AUTOSTART_BACKDOOR", "HIGH")
        return count
    
    def _check_web_shells(self) -> int:
        """Check for web shells."""
        count = 0
        for filepath, _ in self.handler.find_files(['.php', '.jsp', '.asp']):
            data = self.handler.get_file(filepath)
            if data:
                try:
                    content = data.decode('utf-8', errors='replace')
                    count += self._check_patterns(f"/{filepath}", content, WEB_SHELL_PATTERNS, "web_shell", "WEB_SHELL", "CRITICAL")
                except:
                    pass
        return count
    
    def _check_container_escape(self) -> int:
        """Check for container escape configurations."""
        count = 0
        for filepath, _ in self.handler.find_files(['.yml', '.yaml', 'docker-compose']):
            data = self.handler.get_file(filepath)
            if data:
                content = data.decode('utf-8', errors='replace')
                if '/var/run/docker.sock' in content:
                    self._add_finding(filepath=f"/{filepath}", finding_type="CONTAINER_DOCKER_SOCKET", technique_key="container_escape", severity="HIGH", description="Docker socket exposed", indicator="/var/run/docker.sock")
                    count += 1
        return count
    
    def _check_shadow(self) -> int:
        """Check shadow file for weak configurations."""
        count = 0
        data = self.handler.get_file("etc/shadow")
        if data:
            content = data.decode('utf-8', errors='replace')
            for line_num, line in enumerate(content.split('\n'), 1):
                parts = line.split(':')
                if len(parts) >= 2 and parts[1].startswith('$1$'):
                    self._add_finding(filepath="/etc/shadow", finding_type="SHADOW_WEAK_HASH", technique_key="shadow_file", severity="MEDIUM", description=f"User {parts[0]} uses weak MD5 hash", indicator=f"{parts[0]}:$1$...", line_number=line_num)
                    count += 1
        return count
    
    # ========================================================================
    # Summary and Export
    # ========================================================================
    
    def _print_summary(self) -> None:
        """Print analysis summary."""
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Analysis Summary - {self.hostname}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        
        severity_counts = defaultdict(int)
        for finding in self.findings:
            severity_counts[finding.severity] += 1
        
        print(f"\n{Style.INFO}Findings by Severity:{Style.RESET}", file=sys.stderr)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = Style.CRITICAL if severity == "CRITICAL" else (Style.ERROR if severity == "HIGH" else (Style.WARNING if severity == "MEDIUM" else Style.INFO))
                print(f"  {color}{severity}: {count}{Style.RESET}", file=sys.stderr)
        
        print(f"\n{Style.INFO}Findings by Type:{Style.RESET}", file=sys.stderr)
        for ftype, count in sorted(self.stats.items(), key=lambda x: -x[1])[:15]:
            print(f"  {ftype}: {count}", file=sys.stderr)
        
        print(f"\n{Style.SUCCESS}Total Findings: {len(self.findings)}{Style.RESET}", file=sys.stderr)
    
    def export_csv(self) -> Dict[str, str]:
        """Export findings to multiple CSV files by category with hostname-based naming."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Categorize findings
        binary_types = {"SUSPICIOUS_BINARY", "UNEXPECTED_SUID", "UNEXPECTED_SGID", "UNEXPECTED_SUID+SGID", 
                       "HIDDEN_EXECUTABLE", "KNOWN_BAD_HASH", "CAPABILITIES"}
        env_types = {"ENV_VARIABLE", "ENV_BACKDOOR", "ENV_REMOTE_EXEC", "ROOTKIT_LD_PRELOAD", 
                    "ROOTKIT_LD_CONF", "LD_PRELOAD_HIJACK", "LD_LIBRARY_HIJACK"}
        persistence_types = {"CRON", "SYSTEMD", "INIT", "SSH", "PAM", "SUDOERS", "KERNEL_MODULE", 
                           "UDEV", "XDG_AUTOSTART", "WEB_SHELL", "CONTAINER", "SHADOW", "SHELL_PROFILE",
                           "RC_LOCAL", "BACKDOOR_USER"}
        
        # Separate findings into categories
        binary_findings = []
        env_findings = []
        persistence_findings = []
        
        for finding in self.findings:
            ftype = finding.finding_type
            # Check if finding type matches any category prefix
            is_binary = any(ftype.startswith(bt.replace('_', '')) or bt in ftype for bt in binary_types)
            is_env = any(ftype.startswith(et.replace('_', '')) or et in ftype for et in env_types)
            is_persistence = any(pt in ftype for pt in persistence_types)
            
            if finding.hash_md5 or finding.hash_sha256 or 'BINARY' in ftype or 'SUID' in ftype or 'SGID' in ftype or 'HIDDEN' in ftype or 'CAPABILITIES' in ftype:
                binary_findings.append(finding)
            elif 'ENV' in ftype or 'LD_PRELOAD' in ftype or 'LD_LIBRARY' in ftype:
                env_findings.append(finding)
            else:
                persistence_findings.append(finding)
        
        output_files = {}
        fieldnames = [
            "Filepath", "Finding_Type", "Technique", "MITRE_ATT&CK_ID",
            "Severity", "Description", "Indicator", "Line_Number",
            "Raw_Content", "MD5", "SHA256", "File_Size", "File_Mode", "Extra_Info"
        ]
        
        def write_findings(findings: List[SecurityFinding], suffix: str) -> str:
            if not findings:
                return None
            output_path = os.path.join(self.output_dir, f"{self.hostname}_{suffix}.csv")
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for finding in sorted(findings, key=lambda x: (
                    {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.severity, 5),
                    x.filepath
                )):
                    writer.writerow(finding.to_dict())
            return output_path
        
        # Write category-specific files
        if binary_findings:
            path = write_findings(binary_findings, "binaries")
            output_files["binaries"] = path
            print(f"{Style.SUCCESS}Binary findings ({len(binary_findings)}) exported to:{Style.RESET} {path}", file=sys.stderr)
        
        if env_findings:
            path = write_findings(env_findings, "environment")
            output_files["environment"] = path
            print(f"{Style.SUCCESS}Environment findings ({len(env_findings)}) exported to:{Style.RESET} {path}", file=sys.stderr)
        
        if persistence_findings:
            path = write_findings(persistence_findings, "persistence")
            output_files["persistence"] = path
            print(f"{Style.SUCCESS}Persistence findings ({len(persistence_findings)}) exported to:{Style.RESET} {path}", file=sys.stderr)
        
        # Also write a combined file
        all_findings_path = os.path.join(self.output_dir, f"{self.hostname}_all_findings.csv")
        with open(all_findings_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in sorted(self.findings, key=lambda x: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.severity, 5),
                x.filepath
            )):
                writer.writerow(finding.to_dict())
        output_files["all"] = all_findings_path
        print(f"{Style.SUCCESS}All findings ({len(self.findings)}) exported to:{Style.RESET} {all_findings_path}", file=sys.stderr)
        
        return output_files


# ============================================================================
# Hash List Loading
# ============================================================================

def load_hash_list(filepath: str) -> Dict[str, str]:
    """Load known-bad hashes from file."""
    hashes = {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',', 1) if ',' in line else line.split(' ', 1) if ' ' in line else [line, "Known bad"]
                hash_val = parts[0].strip().lower()
                desc = parts[1].strip() if len(parts) > 1 else "Known bad"
                if len(hash_val) in (32, 64) and all(c in '0123456789abcdef' for c in hash_val):
                    hashes[hash_val] = desc
    except Exception as e:
        print(f"{Style.WARNING}Warning: Could not load hash list: {e}{Style.RESET}", file=sys.stderr)
    return hashes


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Comprehensive Linux Security Analyzer - Binary Analysis + Persistence Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

Examples:
  # Analyze a UAC tarball (output to current directory)
  python linux_security_analyzer.py -s hostname.tar.gz
  
  # Analyze with custom output directory
  python linux_security_analyzer.py -s hostname.tar.gz -o ./results/
  
  # Analyze with known-bad hash list
  python linux_security_analyzer.py -s hostname.tar.gz --hashes iocs.txt
  
  # Batch analyze multiple tarballs
  python linux_security_analyzer.py --batch ./tarballs/ -o ./results/

Output:
  Creates multiple CSV files named after the source hostname:
    <hostname>_binaries.csv     - Binary/executable findings (SUID, hidden, suspicious)
    <hostname>_environment.csv  - Environment variable findings (LD_PRELOAD, etc.)
    <hostname>_persistence.csv  - Persistence mechanism findings (cron, systemd, etc.)
    <hostname>_all_findings.csv - Combined file with all findings
  
  All findings include MITRE ATT&CK mappings, severity levels,
  file hashes, and detailed indicators.
        """
    )
    
    parser.add_argument("-s", "--source", help="Source: UAC tarball, directory, or '/' for live system")
    parser.add_argument("-o", "--output", default=".", help="Output directory for CSV files (default: current directory)")
    parser.add_argument("--hashes", help="Path to known-bad hash file")
    parser.add_argument("--batch", metavar="DIR", help="Batch mode: analyze all tarballs in directory")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    
    args = parser.parse_args()
    
    # Load hashes
    known_hashes = load_hash_list(args.hashes) if args.hashes else {}
    
    # Resolve output directory
    output_dir = os.path.abspath(args.output)
    
    # Batch mode
    if args.batch:
        batch_dir = os.path.abspath(args.batch)
        if not os.path.isdir(batch_dir):
            print(f"{Style.ERROR}Error: Batch directory does not exist: {batch_dir}{Style.RESET}", file=sys.stderr)
            sys.exit(1)
        
        tarballs = []
        for ext in UACHandler.TAR_EXTENSIONS:
            import glob
            tarballs.extend(glob.glob(os.path.join(batch_dir, f"*{ext}")))
        
        if not tarballs:
            print(f"{Style.WARNING}No tarballs found in {batch_dir}{Style.RESET}", file=sys.stderr)
            sys.exit(1)
        
        print(f"\n{Style.HEADER}Batch processing {len(tarballs)} tarballs...{Style.RESET}", file=sys.stderr)
        
        for i, tarball in enumerate(sorted(tarballs), 1):
            print(f"\n{Style.INFO}[{i}/{len(tarballs)}] {os.path.basename(tarball)}{Style.RESET}", file=sys.stderr)
            try:
                analyzer = LinuxSecurityAnalyzer(tarball, output_dir, known_hashes)
                analyzer.analyze(verbose=not args.quiet)
                analyzer.export_csv()
                analyzer.close()
            except Exception as e:
                print(f"{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        
        print(f"\n{Style.SUCCESS}Batch processing complete. Results in: {output_dir}{Style.RESET}", file=sys.stderr)
        return 0
    
    # Single file mode
    if not args.source:
        parser.print_help()
        sys.exit(1)
    
    source_path = args.source if args.source == "/" else os.path.abspath(args.source)
    
    if not os.path.exists(source_path):
        print(f"{Style.ERROR}Error: Source does not exist: {source_path}{Style.RESET}", file=sys.stderr)
        sys.exit(1)
    
    try:
        analyzer = LinuxSecurityAnalyzer(source_path, output_dir, known_hashes)
        analyzer.analyze(verbose=not args.quiet)
        analyzer.export_csv()
        analyzer.close()
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Interrupted{Style.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        sys.exit(1)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
