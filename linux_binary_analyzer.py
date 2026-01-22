#!/usr/bin/env python3
"""
Linux Binary Analyzer - System Integrity and Malware Hunting Tool

This script analyzes Linux systems (live, mounted images, or UAC tarballs) for:
- Programs outside standard OS binary directories
- Programs in hidden directories (names starting with ".")
- Unexpected SUID/SGID files and files with capabilities
- Environment variable settings and suspicious modifications
- Hash matches against known-bad indicators
- Rootkit traces (e.g., /etc/ld.so.preload, modified ld.so.conf)

PERSISTENCE MECHANISM DETECTION (v1.1.0+):
- Systemd units (/etc/systemd/system/, /usr/lib/systemd/system/)
- Cron jobs (/etc/crontab, /etc/cron.d/, /var/spool/cron/)
- Init scripts (/etc/init.d/, /etc/rc.local, /etc/rc*.d/)
- Kernel modules (/etc/modules, /etc/modules-load.d/)
- Udev rules (/etc/udev/rules.d/, /lib/udev/rules.d/)

Author: Security Tools
Version: 1.1.0
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
from typing import BinaryIO, Dict, Iterator, List, Optional, Set, Tuple, Union

__version__ = "1.1.0"


# ============================================================================
# Console Styling
# ============================================================================

class Style:
    """ANSI escape codes for console styling."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    
    # Colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Semantic aliases
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
# Data Classes
# ============================================================================

@dataclass
class BinaryFinding:
    """Represents a suspicious binary or file finding."""
    filepath: str
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    hash_md5: str = ""
    hash_sha256: str = ""
    file_size: int = 0
    file_mode: str = ""
    file_owner: str = ""
    file_group: str = ""
    mtime: Optional[datetime] = None
    atime: Optional[datetime] = None
    ctime: Optional[datetime] = None
    extra_info: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for CSV export."""
        return {
            "Filepath": self.filepath,
            "Finding_Type": self.finding_type,
            "Severity": self.severity,
            "Description": self.description,
            "MD5": self.hash_md5,
            "SHA256": self.hash_sha256,
            "File_Size": self.file_size,
            "File_Mode": self.file_mode,
            "Owner": self.file_owner,
            "Group": self.file_group,
            "Modified_Time": self.mtime.isoformat() if self.mtime else "",
            "Access_Time": self.atime.isoformat() if self.atime else "",
            "Change_Time": self.ctime.isoformat() if self.ctime else "",
            "Extra_Info": str(self.extra_info) if self.extra_info else ""
        }


@dataclass
class EnvironmentFinding:
    """Represents an environment variable or configuration finding."""
    source_file: str
    finding_type: str
    severity: str
    variable_name: str
    variable_value: str
    description: str
    line_number: int = 0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for CSV export."""
        return {
            "Source_File": self.source_file,
            "Finding_Type": self.finding_type,
            "Severity": self.severity,
            "Variable_Name": self.variable_name,
            "Variable_Value": self.variable_value,
            "Description": self.description,
            "Line_Number": self.line_number
        }


# ============================================================================
# Known-Bad Hashes and Indicators
# ============================================================================

# Common rootkit/malware hashes (MD5 and SHA256)
# This is a sample list - in production, load from an external file
KNOWN_BAD_HASHES = {
    # Example rootkit hashes (these are examples, not real malware hashes)
    # Add real IOCs from threat intel sources
    # "d41d8cd98f00b204e9800998ecf8427e": "Empty file - suspicious if executable",
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

# Suspicious paths for binaries
SUSPICIOUS_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/",
    "/var/run/",
]

# Standard binary directories
STANDARD_BIN_DIRS = {
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",  # Some legitimate software installs here
}

# Environment variables that are security-sensitive
SENSITIVE_ENV_VARS = {
    "LD_PRELOAD": "HIGH",
    "LD_LIBRARY_PATH": "MEDIUM",
    "LD_AUDIT": "HIGH",
    "LD_DEBUG": "LOW",
    "LD_PROFILE": "LOW",
    "PATH": "MEDIUM",
    "PYTHONPATH": "MEDIUM",
    "PERL5LIB": "MEDIUM",
    "RUBYLIB": "MEDIUM",
    "NODE_PATH": "MEDIUM",
    "CLASSPATH": "MEDIUM",
    "http_proxy": "LOW",
    "https_proxy": "LOW",
    "HTTP_PROXY": "LOW",
    "HTTPS_PROXY": "LOW",
    "ftp_proxy": "LOW",
}

# ============================================================================
# Persistence Locations (Critical for Threat Hunting)
# ============================================================================

# Systemd unit file locations
SYSTEMD_PATHS = [
    "etc/systemd/system/",
    "usr/lib/systemd/system/",
    "lib/systemd/system/",
    "etc/systemd/user/",
    "usr/lib/systemd/user/",
    "run/systemd/system/",
    "run/systemd/generator/",
    "run/systemd/generator.early/",
    "run/systemd/generator.late/",
]

# Cron job locations
CRON_PATHS = [
    "etc/crontab",
    "etc/cron.d/",
    "etc/cron.daily/",
    "etc/cron.hourly/",
    "etc/cron.weekly/",
    "etc/cron.monthly/",
    "var/spool/cron/",
    "var/spool/cron/crontabs/",
]

# Init script locations
INIT_PATHS = [
    "etc/init.d/",
    "etc/rc.local",
    "etc/rc.d/",
    "etc/rc0.d/",
    "etc/rc1.d/",
    "etc/rc2.d/",
    "etc/rc3.d/",
    "etc/rc4.d/",
    "etc/rc5.d/",
    "etc/rc6.d/",
]

# Kernel module locations
KERNEL_MODULE_PATHS = [
    "etc/modules",
    "etc/modules-load.d/",
    "etc/modprobe.d/",
    "lib/modules/",
    "usr/lib/modules/",
]

# Udev rules locations
UDEV_PATHS = [
    "etc/udev/rules.d/",
    "lib/udev/rules.d/",
    "usr/lib/udev/rules.d/",
    "run/udev/rules.d/",
]

# Suspicious patterns in persistence files
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

# Known legitimate systemd services to reduce false positives
KNOWN_LEGITIMATE_SERVICES = {
    'sshd.service', 'ssh.service', 'systemd-journald.service',
    'systemd-logind.service', 'systemd-udevd.service', 'cron.service',
    'rsyslog.service', 'NetworkManager.service', 'dbus.service',
    'polkit.service', 'snapd.service', 'docker.service', 'containerd.service',
    'multipathd.service', 'auditd.service', 'firewalld.service',
}


# ============================================================================
# Path Security Functions
# ============================================================================

def is_safe_path(base_path: str, target_path: str) -> bool:
    """
    Check if target_path is safely within base_path (prevent path traversal).
    
    Args:
        base_path: The base directory that should contain the target
        target_path: The path to validate
        
    Returns:
        True if the path is safe, False otherwise
    """
    try:
        base_resolved = os.path.realpath(base_path)
        target_resolved = os.path.realpath(os.path.join(base_path, target_path))
        return target_resolved.startswith(base_resolved + os.sep) or target_resolved == base_resolved
    except (OSError, ValueError):
        return False


def safe_extract_member(tar: tarfile.TarFile, member: tarfile.TarInfo, 
                        extract_path: str) -> Optional[bytes]:
    """
    Safely extract a tarfile member, preventing path traversal attacks.
    
    Args:
        tar: The tarfile object
        member: The member to extract
        extract_path: Base path for extraction validation
        
    Returns:
        File contents as bytes, or None if unsafe/error
    """
    # Check for path traversal
    member_path = os.path.normpath(member.name)
    if member_path.startswith('..') or member_path.startswith('/'):
        # Normalize the path
        member_path = member_path.lstrip('/')
        while member_path.startswith('../'):
            member_path = member_path[3:]
    
    # Validate the final path
    full_path = os.path.join(extract_path, member_path)
    if not is_safe_path(extract_path, member_path):
        return None
    
    try:
        f = tar.extractfile(member)
        if f is None:
            return None
        return f.read()
    except Exception:
        return None


# ============================================================================
# UAC Tarball Handler
# ============================================================================

class UACTarballHandler:
    """Handler for reading files from UAC tarballs."""
    
    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2')
    
    def __init__(self, tarball_path: str):
        self.tarball_path = tarball_path
        self.tar = None
        self.root_prefix = ""
        self._member_cache = {}
        self._open_tarball()
    
    def _open_tarball(self):
        """Open the tarball and detect the root structure."""
        try:
            if self.tarball_path.endswith('.gz') or self.tarball_path.endswith('.tgz'):
                self.tar = tarfile.open(self.tarball_path, 'r:gz')
            elif self.tarball_path.endswith('.bz2') or self.tarball_path.endswith('.tbz2'):
                self.tar = tarfile.open(self.tarball_path, 'r:bz2')
            else:
                self.tar = tarfile.open(self.tarball_path, 'r:')
            
            # Detect root prefix
            members = self.tar.getmembers()
            if members:
                first_path = members[0].name
                parts = first_path.split('/')
                if len(parts) > 1:
                    # Check if first part looks like a UAC root directory
                    potential_root = parts[0]
                    # Look for common UAC directories
                    for member in members[:100]:
                        if '/var/log/' in member.name or '/etc/' in member.name:
                            idx = member.name.find('/var/') if '/var/' in member.name else member.name.find('/etc/')
                            if idx > 0:
                                self.root_prefix = member.name[:idx]
                            break
                        
        except Exception as e:
            raise RuntimeError(f"Failed to open tarball: {e}")
    
    def close(self):
        """Close the tarball."""
        if self.tar:
            self.tar.close()
    
    def get_members(self) -> List[tarfile.TarInfo]:
        """Get all members of the tarball."""
        if self.tar:
            return self.tar.getmembers()
        return []
    
    def extract_file(self, member_path: str) -> Optional[bytes]:
        """Extract a file from the tarball."""
        if not self.tar:
            return None
        
        # Try with and without root prefix
        paths_to_try = [member_path]
        if self.root_prefix:
            paths_to_try.append(f"{self.root_prefix}/{member_path.lstrip('/')}")
        
        for path in paths_to_try:
            try:
                member = self.tar.getmember(path)
                return safe_extract_member(self.tar, member, "/tmp")
            except KeyError:
                continue
        
        return None
    
    def find_files(self, pattern: str) -> List[tarfile.TarInfo]:
        """Find files matching a pattern."""
        matches = []
        if not self.tar:
            return matches
        
        pattern_lower = pattern.lower()
        for member in self.tar.getmembers():
            if pattern_lower in member.name.lower():
                matches.append(member)
        
        return matches
    
    def get_file_info(self, member: tarfile.TarInfo) -> Dict:
        """Get file information from a tarball member."""
        return {
            "mode": stat.filemode(member.mode),
            "uid": member.uid,
            "gid": member.gid,
            "size": member.size,
            "mtime": datetime.fromtimestamp(member.mtime) if member.mtime else None,
            "is_file": member.isfile(),
            "is_dir": member.isdir(),
            "is_symlink": member.issym(),
            "linkname": member.linkname if member.issym() else "",
        }


# ============================================================================
# Hash Calculation
# ============================================================================

def calculate_hashes(data: bytes) -> Tuple[str, str]:
    """Calculate MD5 and SHA256 hashes of data."""
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


def calculate_file_hashes(filepath: str) -> Tuple[str, str]:
    """Calculate hashes of a file."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        return calculate_hashes(data)
    except Exception:
        return "", ""


# ============================================================================
# Binary Analysis Functions
# ============================================================================

def is_elf_binary(data: bytes) -> bool:
    """Check if data is an ELF binary."""
    if len(data) < 4:
        return False
    return data[:4] == b'\x7fELF'


def is_script(data: bytes) -> bool:
    """Check if data is a script (starts with shebang)."""
    if len(data) < 2:
        return False
    return data[:2] == b'#!'


def is_executable(data: bytes) -> bool:
    """Check if data appears to be executable."""
    return is_elf_binary(data) or is_script(data)


def parse_elf_info(data: bytes) -> Dict:
    """Parse basic ELF header information."""
    info = {
        "type": "ELF",
        "bits": 0,
        "endian": "",
        "machine": "",
    }
    
    if len(data) < 20:
        return info
    
    # ELF class (32 or 64 bit)
    ei_class = data[4]
    info["bits"] = 32 if ei_class == 1 else (64 if ei_class == 2 else 0)
    
    # Endianness
    ei_data = data[5]
    info["endian"] = "little" if ei_data == 1 else ("big" if ei_data == 2 else "unknown")
    
    # Machine type (at offset 18)
    if info["endian"] == "little":
        machine = struct.unpack('<H', data[18:20])[0]
    else:
        machine = struct.unpack('>H', data[18:20])[0]
    
    machine_types = {
        0x03: "x86",
        0x3E: "x86_64",
        0x28: "ARM",
        0xB7: "AArch64",
        0x08: "MIPS",
    }
    info["machine"] = machine_types.get(machine, f"unknown({machine})")
    
    return info


def check_suid_sgid(mode: int) -> Tuple[bool, bool]:
    """Check if file has SUID or SGID bits set."""
    is_suid = bool(mode & stat.S_ISUID)
    is_sgid = bool(mode & stat.S_ISGID)
    return is_suid, is_sgid


def is_hidden_path(path: str) -> bool:
    """Check if any component of the path is hidden (starts with .)."""
    parts = PurePosixPath(path).parts
    for part in parts:
        if part.startswith('.') and part not in ('.', '..'):
            return True
    return False


def is_standard_binary_location(path: str) -> bool:
    """Check if path is in a standard binary directory."""
    normalized = path.lstrip('/')
    for std_dir in STANDARD_BIN_DIRS:
        std_normalized = std_dir.lstrip('/')
        if normalized.startswith(std_normalized + '/') or normalized.startswith(std_normalized):
            return True
    return False


def is_suspicious_location(path: str) -> bool:
    """Check if path is in a suspicious location."""
    for susp_path in SUSPICIOUS_PATHS:
        if path.startswith(susp_path):
            return True
    return False


# ============================================================================
# Environment Analysis
# ============================================================================

def parse_environment_file(filepath: str, data: bytes) -> List[EnvironmentFinding]:
    """Parse an environment configuration file for suspicious settings."""
    findings = []
    
    try:
        content = data.decode('utf-8', errors='replace')
    except Exception:
        return findings
    
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        
        # Parse export VAR=value or VAR=value
        match = re.match(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
        if match:
            var_name = match.group(1)
            var_value = match.group(2).strip('"\'')
            
            # Check for sensitive variables
            if var_name in SENSITIVE_ENV_VARS:
                severity = SENSITIVE_ENV_VARS[var_name]
                description = f"Security-sensitive environment variable set"
                
                # Additional checks for specific variables
                if var_name == "LD_PRELOAD":
                    severity = "CRITICAL"
                    description = "LD_PRELOAD set - can be used to inject libraries"
                elif var_name == "LD_LIBRARY_PATH" and any(p in var_value for p in ["/tmp", "/var/tmp", "/dev/shm"]):
                    severity = "HIGH"
                    description = "LD_LIBRARY_PATH includes suspicious directory"
                elif var_name == "PATH" and any(p in var_value for p in ["/tmp", "/var/tmp", "/dev/shm"]):
                    severity = "HIGH"
                    description = "PATH includes suspicious directory"
                
                findings.append(EnvironmentFinding(
                    source_file=filepath,
                    finding_type="ENV_VARIABLE",
                    severity=severity,
                    variable_name=var_name,
                    variable_value=var_value[:500],  # Truncate long values
                    description=description,
                    line_number=line_num
                ))
        
        # Check for suspicious shell commands
        if 'eval' in line and ('base64' in line or 'decode' in line):
            findings.append(EnvironmentFinding(
                source_file=filepath,
                finding_type="SUSPICIOUS_COMMAND",
                severity="HIGH",
                variable_name="",
                variable_value=line[:500],
                description="Potential obfuscated command execution",
                line_number=line_num
            ))
        
        # Check for curl/wget piped to shell
        if re.search(r'(curl|wget).*\|\s*(bash|sh|python|perl)', line, re.IGNORECASE):
            findings.append(EnvironmentFinding(
                source_file=filepath,
                finding_type="SUSPICIOUS_COMMAND",
                severity="CRITICAL",
                variable_name="",
                variable_value=line[:500],
                description="Remote script execution pattern detected",
                line_number=line_num
            ))
    
    return findings


# ============================================================================
# Rootkit Detection
# ============================================================================

def check_ld_preload(filepath: str, data: bytes) -> List[BinaryFinding]:
    """Check /etc/ld.so.preload for suspicious entries."""
    findings = []
    
    try:
        content = data.decode('utf-8', errors='replace')
    except Exception:
        return findings
    
    lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
    
    if lines:
        findings.append(BinaryFinding(
            filepath=filepath,
            finding_type="ROOTKIT_LD_PRELOAD",
            severity="CRITICAL",
            description=f"ld.so.preload contains entries: {', '.join(lines[:5])}",
            extra_info={"entries": lines}
        ))
    
    return findings


def check_ld_so_conf(filepath: str, data: bytes) -> List[BinaryFinding]:
    """Check ld.so.conf for suspicious library paths."""
    findings = []
    suspicious_paths = ["/tmp", "/var/tmp", "/dev/shm", "/home"]
    
    try:
        content = data.decode('utf-8', errors='replace')
    except Exception:
        return findings
    
    lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
    
    for line in lines:
        if line.startswith('include'):
            continue
        for susp in suspicious_paths:
            if line.startswith(susp):
                findings.append(BinaryFinding(
                    filepath=filepath,
                    finding_type="ROOTKIT_LD_CONF",
                    severity="HIGH",
                    description=f"Suspicious library path in ld.so.conf: {line}",
                    extra_info={"path": line}
                ))
    
    return findings


# ============================================================================
# Main Analyzer Class
# ============================================================================

class LinuxBinaryAnalyzer:
    """Main class for analyzing Linux binaries and system configuration."""
    
    # Environment files to check
    ENV_FILES = [
        "etc/environment",
        "etc/profile",
        "etc/profile.d/",
        "etc/bash.bashrc",
        "etc/bashrc",
        "etc/zshrc",
        "etc/csh.cshrc",
        "etc/csh.login",
        "root/.bashrc",
        "root/.bash_profile",
        "root/.profile",
        "root/.zshrc",
    ]
    
    # Rootkit-related files
    ROOTKIT_FILES = [
        "etc/ld.so.preload",
        "etc/ld.so.conf",
        "etc/ld.so.conf.d/",
    ]
    
    def __init__(self, source_path: str, known_bad_hashes: Dict[str, str] = None):
        """
        Initialize the analyzer.
        
        Args:
            source_path: Path to UAC tarball, extracted directory, or '/' for live system
            known_bad_hashes: Dictionary of hash -> description for known-bad files
        """
        self.source_path = os.path.abspath(source_path) if source_path != "/" else "/"
        self.is_tarball = self._is_tarball(source_path)
        self.handler = None
        self.known_bad_hashes = known_bad_hashes or KNOWN_BAD_HASHES
        
        self.binary_findings: List[BinaryFinding] = []
        self.env_findings: List[EnvironmentFinding] = []
        self.stats = defaultdict(int)
        self.hostname = ""
        
        if self.is_tarball:
            self.handler = UACTarballHandler(source_path)
    
    def _is_tarball(self, path: str) -> bool:
        """Check if path is a tarball."""
        return any(path.lower().endswith(ext) for ext in UACTarballHandler.TAR_EXTENSIONS)
    
    def close(self):
        """Clean up resources."""
        if self.handler:
            self.handler.close()
    
    def analyze(self, verbose: bool = True) -> None:
        """Run all analysis checks."""
        Style.enable_windows_ansi()
        
        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}  Linux Binary Analyzer v{__version__}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"\n{Style.INFO}Source:{Style.RESET} {self.source_path}", file=sys.stderr)
            print(f"{Style.INFO}Mode:{Style.RESET} {'Tarball' if self.is_tarball else 'Directory'}", file=sys.stderr)
        
        if self.is_tarball:
            self._analyze_tarball(verbose)
        else:
            self._analyze_directory(verbose)
        
        if verbose:
            self._print_summary()
    
    def _analyze_tarball(self, verbose: bool) -> None:
        """Analyze a UAC tarball."""
        if not self.handler:
            return
        
        members = self.handler.get_members()
        
        if verbose:
            print(f"\n{Style.INFO}Analyzing {len(members)} files in tarball...{Style.RESET}", file=sys.stderr)
        
        # Check for rootkit files
        if verbose:
            print(f"\n{Style.INFO}[1/10] Checking for rootkit traces...{Style.RESET}", file=sys.stderr)
        self._check_rootkit_files_tarball(verbose)
        
        # Check environment files
        if verbose:
            print(f"\n{Style.INFO}[2/10] Analyzing environment configuration...{Style.RESET}", file=sys.stderr)
        self._check_env_files_tarball(verbose)
        
        # Analyze binaries
        if verbose:
            print(f"\n{Style.INFO}[3/10] Scanning for suspicious binaries...{Style.RESET}", file=sys.stderr)
        self._analyze_binaries_tarball(members, verbose)
        
        # Check SUID/SGID files
        if verbose:
            print(f"\n{Style.INFO}[4/10] Checking SUID/SGID files...{Style.RESET}", file=sys.stderr)
        self._check_suid_files_tarball(members, verbose)
        
        # Check for hidden files
        if verbose:
            print(f"\n{Style.INFO}[5/10] Scanning for hidden executables...{Style.RESET}", file=sys.stderr)
        self._check_hidden_files_tarball(members, verbose)
        
        # Check systemd units (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[6/10] Checking systemd units for persistence...{Style.RESET}", file=sys.stderr)
        self._check_systemd_units_tarball(members, verbose)
        
        # Check cron jobs (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[7/10] Checking cron jobs for persistence...{Style.RESET}", file=sys.stderr)
        self._check_cron_jobs_tarball(members, verbose)
        
        # Check init scripts (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[8/10] Checking init scripts for persistence...{Style.RESET}", file=sys.stderr)
        self._check_init_scripts_tarball(members, verbose)
        
        # Check kernel modules (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[9/10] Checking kernel module configurations...{Style.RESET}", file=sys.stderr)
        self._check_kernel_modules_tarball(members, verbose)
        
        # Check udev rules (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[10/10] Checking udev rules for persistence...{Style.RESET}", file=sys.stderr)
        self._check_udev_rules_tarball(members, verbose)
    
    def _analyze_directory(self, verbose: bool) -> None:
        """Analyze a directory (extracted UAC or live system)."""
        if verbose:
            print(f"\n{Style.INFO}[1/10] Checking for rootkit traces...{Style.RESET}", file=sys.stderr)
        self._check_rootkit_files_directory(verbose)
        
        if verbose:
            print(f"\n{Style.INFO}[2/10] Analyzing environment configuration...{Style.RESET}", file=sys.stderr)
        self._check_env_files_directory(verbose)
        
        if verbose:
            print(f"\n{Style.INFO}[3/10] Scanning for suspicious binaries...{Style.RESET}", file=sys.stderr)
        self._analyze_binaries_directory(verbose)
        
        if verbose:
            print(f"\n{Style.INFO}[4/10] Checking SUID/SGID files...{Style.RESET}", file=sys.stderr)
        self._check_suid_files_directory(verbose)
        
        if verbose:
            print(f"\n{Style.INFO}[5/10] Scanning for hidden executables...{Style.RESET}", file=sys.stderr)
        self._check_hidden_files_directory(verbose)
        
        # Check systemd units (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[6/10] Checking systemd units for persistence...{Style.RESET}", file=sys.stderr)
        self._check_systemd_units_directory(verbose)
        
        # Check cron jobs (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[7/10] Checking cron jobs for persistence...{Style.RESET}", file=sys.stderr)
        self._check_cron_jobs_directory(verbose)
        
        # Check init scripts (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[8/10] Checking init scripts for persistence...{Style.RESET}", file=sys.stderr)
        self._check_init_scripts_directory(verbose)
        
        # Check kernel modules (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[9/10] Checking kernel module configurations...{Style.RESET}", file=sys.stderr)
        self._check_kernel_modules_directory(verbose)
        
        # Check udev rules (PERSISTENCE)
        if verbose:
            print(f"\n{Style.INFO}[10/10] Checking udev rules for persistence...{Style.RESET}", file=sys.stderr)
        self._check_udev_rules_directory(verbose)
    
    def _check_rootkit_files_tarball(self, verbose: bool) -> None:
        """Check rootkit-related files in tarball."""
        # Check ld.so.preload
        preload_data = self.handler.extract_file("etc/ld.so.preload")
        if preload_data:
            findings = check_ld_preload("etc/ld.so.preload", preload_data)
            self.binary_findings.extend(findings)
            if verbose and findings:
                print(f"  {Style.CRITICAL}[!] ld.so.preload found with entries!{Style.RESET}", file=sys.stderr)
        
        # Check ld.so.conf
        conf_data = self.handler.extract_file("etc/ld.so.conf")
        if conf_data:
            findings = check_ld_so_conf("etc/ld.so.conf", conf_data)
            self.binary_findings.extend(findings)
            if verbose and findings:
                for f in findings:
                    print(f"  {Style.WARNING}[!] Suspicious ld.so.conf entry{Style.RESET}", file=sys.stderr)
        
        # Check ld.so.conf.d/ files
        for member in self.handler.get_members():
            if "etc/ld.so.conf.d/" in member.name and member.isfile():
                data = self.handler.extract_file(member.name)
                if data:
                    findings = check_ld_so_conf(member.name, data)
                    self.binary_findings.extend(findings)
    
    def _check_rootkit_files_directory(self, verbose: bool) -> None:
        """Check rootkit-related files in directory."""
        base = self.source_path
        
        # Check ld.so.preload
        preload_path = os.path.join(base, "etc/ld.so.preload")
        if os.path.exists(preload_path):
            try:
                with open(preload_path, 'rb') as f:
                    data = f.read()
                findings = check_ld_preload(preload_path, data)
                self.binary_findings.extend(findings)
                if verbose and findings:
                    print(f"  {Style.CRITICAL}[!] ld.so.preload found with entries!{Style.RESET}", file=sys.stderr)
            except Exception:
                pass
        
        # Check ld.so.conf
        conf_path = os.path.join(base, "etc/ld.so.conf")
        if os.path.exists(conf_path):
            try:
                with open(conf_path, 'rb') as f:
                    data = f.read()
                findings = check_ld_so_conf(conf_path, data)
                self.binary_findings.extend(findings)
            except Exception:
                pass
        
        # Check ld.so.conf.d/
        conf_d = os.path.join(base, "etc/ld.so.conf.d")
        if os.path.isdir(conf_d):
            for filename in os.listdir(conf_d):
                filepath = os.path.join(conf_d, filename)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, 'rb') as f:
                            data = f.read()
                        findings = check_ld_so_conf(filepath, data)
                        self.binary_findings.extend(findings)
                    except Exception:
                        pass
    
    def _check_env_files_tarball(self, verbose: bool) -> None:
        """Check environment files in tarball."""
        for env_path in self.ENV_FILES:
            if env_path.endswith('/'):
                # It's a directory, find all files
                for member in self.handler.get_members():
                    if env_path in member.name and member.isfile():
                        data = self.handler.extract_file(member.name)
                        if data:
                            findings = parse_environment_file(member.name, data)
                            self.env_findings.extend(findings)
                            if verbose and findings:
                                print(f"  {Style.WARNING}[+] Found {len(findings)} issues in {member.name}{Style.RESET}", file=sys.stderr)
            else:
                data = self.handler.extract_file(env_path)
                if data:
                    findings = parse_environment_file(env_path, data)
                    self.env_findings.extend(findings)
                    if verbose and findings:
                        print(f"  {Style.WARNING}[+] Found {len(findings)} issues in {env_path}{Style.RESET}", file=sys.stderr)
        
        # Also check home directories
        for member in self.handler.get_members():
            if '/home/' in member.name and member.isfile():
                basename = os.path.basename(member.name)
                if basename in ['.bashrc', '.bash_profile', '.profile', '.zshrc', '.cshrc']:
                    data = self.handler.extract_file(member.name)
                    if data:
                        findings = parse_environment_file(member.name, data)
                        self.env_findings.extend(findings)
    
    def _check_env_files_directory(self, verbose: bool) -> None:
        """Check environment files in directory."""
        base = self.source_path
        
        for env_path in self.ENV_FILES:
            full_path = os.path.join(base, env_path)
            
            if env_path.endswith('/'):
                if os.path.isdir(full_path):
                    for filename in os.listdir(full_path):
                        filepath = os.path.join(full_path, filename)
                        if os.path.isfile(filepath):
                            try:
                                with open(filepath, 'rb') as f:
                                    data = f.read()
                                findings = parse_environment_file(filepath, data)
                                self.env_findings.extend(findings)
                            except Exception:
                                pass
            elif os.path.isfile(full_path):
                try:
                    with open(full_path, 'rb') as f:
                        data = f.read()
                    findings = parse_environment_file(full_path, data)
                    self.env_findings.extend(findings)
                    if verbose and findings:
                        print(f"  {Style.WARNING}[+] Found {len(findings)} issues in {env_path}{Style.RESET}", file=sys.stderr)
                except Exception:
                    pass
        
        # Check home directories
        home_base = os.path.join(base, "home")
        if os.path.isdir(home_base):
            for user_dir in os.listdir(home_base):
                user_path = os.path.join(home_base, user_dir)
                if os.path.isdir(user_path):
                    for dotfile in ['.bashrc', '.bash_profile', '.profile', '.zshrc']:
                        dotpath = os.path.join(user_path, dotfile)
                        if os.path.isfile(dotpath):
                            try:
                                with open(dotpath, 'rb') as f:
                                    data = f.read()
                                findings = parse_environment_file(dotpath, data)
                                self.env_findings.extend(findings)
                            except Exception:
                                pass
    
    def _analyze_binaries_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Analyze binaries in tarball for suspicious characteristics."""
        checked = 0
        
        for member in members:
            if not member.isfile():
                continue
            
            # Skip non-executable files by extension
            if member.name.endswith(('.txt', '.log', '.conf', '.cfg', '.xml', '.json', 
                                      '.html', '.css', '.js', '.md', '.rst', '.png', 
                                      '.jpg', '.gif', '.pdf', '.doc', '.csv')):
                continue
            
            # Check for suspicious location
            normalized_path = '/' + member.name.lstrip('/')
            
            # Remove UAC prefix if present
            for prefix in ['uac-', 'UAC-']:
                if prefix in normalized_path:
                    idx = normalized_path.find(prefix)
                    end_idx = normalized_path.find('/', idx)
                    if end_idx > 0:
                        normalized_path = normalized_path[end_idx:]
                    break
            
            # Check if in suspicious location and executable
            if is_suspicious_location(normalized_path):
                data = self.handler.extract_file(member.name)
                if data and is_executable(data):
                    md5, sha256 = calculate_hashes(data)
                    
                    finding = BinaryFinding(
                        filepath=normalized_path,
                        finding_type="SUSPICIOUS_LOCATION",
                        severity="HIGH",
                        description=f"Executable found in suspicious location",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        file_mode=stat.filemode(member.mode),
                        mtime=datetime.fromtimestamp(member.mtime) if member.mtime else None
                    )
                    
                    # Check against known-bad hashes
                    if md5 in self.known_bad_hashes:
                        finding.severity = "CRITICAL"
                        finding.finding_type = "KNOWN_BAD_HASH"
                        finding.description = f"Known malicious file: {self.known_bad_hashes[md5]}"
                    elif sha256 in self.known_bad_hashes:
                        finding.severity = "CRITICAL"
                        finding.finding_type = "KNOWN_BAD_HASH"
                        finding.description = f"Known malicious file: {self.known_bad_hashes[sha256]}"
                    
                    self.binary_findings.append(finding)
                    self.stats["suspicious_location"] += 1
                    checked += 1
            
            # Check for non-standard binary locations
            basename = os.path.basename(member.name)
            if basename in SUSPICIOUS_BINARY_NAMES:
                data = self.handler.extract_file(member.name)
                if data:
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath=normalized_path,
                        finding_type="SUSPICIOUS_NAME",
                        severity="MEDIUM",
                        description=f"Binary with suspicious name: {basename}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        file_mode=stat.filemode(member.mode)
                    ))
                    self.stats["suspicious_name"] += 1
        
        if verbose:
            print(f"  {Style.SUCCESS}Checked {checked} potential executables{Style.RESET}", file=sys.stderr)
    
    def _analyze_binaries_directory(self, verbose: bool) -> None:
        """Analyze binaries in directory."""
        checked = 0
        base = self.source_path
        
        # Check suspicious locations
        for susp_dir in SUSPICIOUS_PATHS:
            full_path = os.path.join(base, susp_dir.lstrip('/'))
            if not os.path.isdir(full_path):
                continue
            
            for root, dirs, files in os.walk(full_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        if not os.path.isfile(filepath):
                            continue
                        
                        # Check if executable
                        file_stat = os.stat(filepath)
                        if not (file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                            # Check file content
                            with open(filepath, 'rb') as f:
                                header = f.read(4)
                            if not (is_elf_binary(header) or is_script(header)):
                                continue
                        
                        # Read file for hashing
                        with open(filepath, 'rb') as f:
                            data = f.read()
                        
                        if not is_executable(data):
                            continue
                        
                        md5, sha256 = calculate_hashes(data)
                        relative_path = os.path.relpath(filepath, base)
                        
                        finding = BinaryFinding(
                            filepath='/' + relative_path,
                            finding_type="SUSPICIOUS_LOCATION",
                            severity="HIGH",
                            description="Executable found in suspicious location",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=file_stat.st_size,
                            file_mode=stat.filemode(file_stat.st_mode),
                            mtime=datetime.fromtimestamp(file_stat.st_mtime)
                        )
                        
                        # Check against known-bad
                        if md5 in self.known_bad_hashes:
                            finding.severity = "CRITICAL"
                            finding.finding_type = "KNOWN_BAD_HASH"
                            finding.description = f"Known malicious: {self.known_bad_hashes[md5]}"
                        
                        self.binary_findings.append(finding)
                        self.stats["suspicious_location"] += 1
                        checked += 1
                        
                    except (PermissionError, OSError):
                        pass
        
        if verbose:
            print(f"  {Style.SUCCESS}Checked {checked} files in suspicious locations{Style.RESET}", file=sys.stderr)
    
    def _check_suid_files_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Check for SUID/SGID files in tarball."""
        suid_count = 0
        
        # Known legitimate SUID binaries
        KNOWN_SUID = {
            '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/newgrp',
            '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/gpasswd', '/bin/ping',
            '/usr/bin/ping', '/bin/mount', '/bin/umount', '/usr/bin/mount',
            '/usr/bin/umount', '/usr/lib/openssh/ssh-keysign',
            '/usr/libexec/openssh/ssh-keysign', '/usr/bin/pkexec',
        }
        
        for member in members:
            if not member.isfile():
                continue
            
            is_suid, is_sgid = check_suid_sgid(member.mode)
            
            if is_suid or is_sgid:
                # Normalize path
                normalized_path = '/' + member.name.lstrip('/')
                for prefix in ['uac-', 'UAC-']:
                    if prefix in normalized_path:
                        idx = normalized_path.find(prefix)
                        end_idx = normalized_path.find('/', idx)
                        if end_idx > 0:
                            normalized_path = normalized_path[end_idx:]
                        break
                
                # Check if known legitimate
                is_known = any(normalized_path.endswith(k) for k in KNOWN_SUID)
                
                if not is_known or is_suspicious_location(normalized_path):
                    data = self.handler.extract_file(member.name)
                    md5, sha256 = "", ""
                    if data:
                        md5, sha256 = calculate_hashes(data)
                    
                    suid_type = []
                    if is_suid:
                        suid_type.append("SUID")
                    if is_sgid:
                        suid_type.append("SGID")
                    
                    severity = "CRITICAL" if is_suspicious_location(normalized_path) else "MEDIUM"
                    if not is_known:
                        severity = "HIGH"
                    
                    self.binary_findings.append(BinaryFinding(
                        filepath=normalized_path,
                        finding_type=f"UNEXPECTED_{'+'.join(suid_type)}",
                        severity=severity,
                        description=f"{'+'.join(suid_type)} file: {normalized_path}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        file_mode=stat.filemode(member.mode)
                    ))
                    suid_count += 1
        
        self.stats["suid_sgid"] = suid_count
        if verbose:
            print(f"  {Style.WARNING if suid_count else Style.SUCCESS}Found {suid_count} suspicious SUID/SGID files{Style.RESET}", file=sys.stderr)
    
    def _check_suid_files_directory(self, verbose: bool) -> None:
        """Check for SUID/SGID files in directory."""
        suid_count = 0
        base = self.source_path
        
        KNOWN_SUID = {
            '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/newgrp',
            '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/gpasswd', '/bin/ping',
            '/usr/bin/ping', '/bin/mount', '/bin/umount', '/usr/bin/mount',
            '/usr/bin/umount', '/usr/lib/openssh/ssh-keysign',
        }
        
        for root, dirs, files in os.walk(base):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    file_stat = os.stat(filepath)
                    is_suid, is_sgid = check_suid_sgid(file_stat.st_mode)
                    
                    if is_suid or is_sgid:
                        relative_path = os.path.relpath(filepath, base)
                        normalized_path = '/' + relative_path
                        
                        is_known = any(normalized_path.endswith(k) for k in KNOWN_SUID)
                        
                        if not is_known or is_suspicious_location(normalized_path):
                            md5, sha256 = calculate_file_hashes(filepath)
                            
                            suid_type = []
                            if is_suid:
                                suid_type.append("SUID")
                            if is_sgid:
                                suid_type.append("SGID")
                            
                            severity = "CRITICAL" if is_suspicious_location(normalized_path) else "MEDIUM"
                            if not is_known:
                                severity = "HIGH"
                            
                            self.binary_findings.append(BinaryFinding(
                                filepath=normalized_path,
                                finding_type=f"UNEXPECTED_{'+'.join(suid_type)}",
                                severity=severity,
                                description=f"{'+'.join(suid_type)} file: {normalized_path}",
                                hash_md5=md5,
                                hash_sha256=sha256,
                                file_size=file_stat.st_size,
                                file_mode=stat.filemode(file_stat.st_mode)
                            ))
                            suid_count += 1
                            
                except (PermissionError, OSError):
                    pass
        
        self.stats["suid_sgid"] = suid_count
        if verbose:
            print(f"  {Style.WARNING if suid_count else Style.SUCCESS}Found {suid_count} suspicious SUID/SGID files{Style.RESET}", file=sys.stderr)
    
    def _check_hidden_files_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Check for hidden executable files in tarball."""
        hidden_count = 0
        
        for member in members:
            if not member.isfile():
                continue
            
            if is_hidden_path(member.name):
                # Check if it's executable
                data = self.handler.extract_file(member.name)
                if data and is_executable(data):
                    md5, sha256 = calculate_hashes(data)
                    
                    normalized_path = '/' + member.name.lstrip('/')
                    
                    self.binary_findings.append(BinaryFinding(
                        filepath=normalized_path,
                        finding_type="HIDDEN_EXECUTABLE",
                        severity="HIGH",
                        description=f"Executable in hidden location: {normalized_path}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        file_mode=stat.filemode(member.mode)
                    ))
                    hidden_count += 1
        
        self.stats["hidden_executables"] = hidden_count
        if verbose:
            print(f"  {Style.WARNING if hidden_count else Style.SUCCESS}Found {hidden_count} hidden executables{Style.RESET}", file=sys.stderr)
    
    def _check_hidden_files_directory(self, verbose: bool) -> None:
        """Check for hidden executable files in directory."""
        hidden_count = 0
        base = self.source_path
        
        for root, dirs, files in os.walk(base):
            for filename in files:
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, base)
                
                if is_hidden_path(relative_path):
                    try:
                        file_stat = os.stat(filepath)
                        
                        # Check if executable
                        is_exec = file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                        
                        if is_exec or filepath.endswith(('.sh', '.py', '.pl', '.rb')):
                            with open(filepath, 'rb') as f:
                                data = f.read()
                            
                            if is_executable(data):
                                md5, sha256 = calculate_hashes(data)
                                
                                self.binary_findings.append(BinaryFinding(
                                    filepath='/' + relative_path,
                                    finding_type="HIDDEN_EXECUTABLE",
                                    severity="HIGH",
                                    description=f"Executable in hidden location",
                                    hash_md5=md5,
                                    hash_sha256=sha256,
                                    file_size=file_stat.st_size,
                                    file_mode=stat.filemode(file_stat.st_mode)
                                ))
                                hidden_count += 1
                                
                    except (PermissionError, OSError):
                        pass
        
        self.stats["hidden_executables"] = hidden_count
        if verbose:
            print(f"  {Style.WARNING if hidden_count else Style.SUCCESS}Found {hidden_count} hidden executables{Style.RESET}", file=sys.stderr)
    
    # ========================================================================
    # Persistence Location Checks
    # ========================================================================
    
    def _check_systemd_units_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Check systemd unit files for suspicious content in tarball."""
        suspicious_count = 0
        
        for member in members:
            if not member.isfile():
                continue
            
            # Check if in systemd paths
            is_systemd = any(path in member.name for path in SYSTEMD_PATHS)
            if not is_systemd:
                continue
            
            # Skip known legitimate services
            basename = os.path.basename(member.name)
            if basename in KNOWN_LEGITIMATE_SERVICES:
                continue
            
            data = self.handler.extract_file(member.name)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Check for suspicious patterns
            for pattern, description in PERSISTENCE_SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="SYSTEMD_PERSISTENCE",
                        severity="CRITICAL",
                        description=f"Suspicious systemd unit: {description}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        file_mode=stat.filemode(member.mode),
                        extra_info={"pattern": description}
                    ))
                    suspicious_count += 1
                    break
            
            # Check for non-standard ExecStart paths
            exec_match = re.search(r'ExecStart\s*=\s*(.+)', content)
            if exec_match:
                exec_path = exec_match.group(1).strip()
                if any(susp in exec_path for susp in ['/tmp/', '/var/tmp/', '/dev/shm/', '/home/']):
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="SYSTEMD_SUSPICIOUS_EXEC",
                        severity="HIGH",
                        description=f"Systemd unit executes from suspicious path: {exec_path[:100]}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        extra_info={"exec_path": exec_path}
                    ))
                    suspicious_count += 1
        
        self.stats["systemd_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious systemd units{Style.RESET}", file=sys.stderr)
    
    def _check_systemd_units_directory(self, verbose: bool) -> None:
        """Check systemd unit files for suspicious content in directory."""
        suspicious_count = 0
        base = self.source_path
        
        for systemd_path in SYSTEMD_PATHS:
            full_path = os.path.join(base, systemd_path)
            if not os.path.exists(full_path):
                continue
            
            if os.path.isfile(full_path):
                files_to_check = [full_path]
            else:
                try:
                    files_to_check = [os.path.join(full_path, f) for f in os.listdir(full_path)]
                except (PermissionError, OSError):
                    continue
            
            for filepath in files_to_check:
                if not os.path.isfile(filepath):
                    continue
                
                basename = os.path.basename(filepath)
                if basename in KNOWN_LEGITIMATE_SERVICES:
                    continue
                
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    content = data.decode('utf-8', errors='replace')
                except (PermissionError, OSError, UnicodeDecodeError):
                    continue
                
                for pattern, description in PERSISTENCE_SUSPICIOUS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        md5, sha256 = calculate_hashes(data)
                        file_stat = os.stat(filepath)
                        self.binary_findings.append(BinaryFinding(
                            filepath=filepath,
                            finding_type="SYSTEMD_PERSISTENCE",
                            severity="CRITICAL",
                            description=f"Suspicious systemd unit: {description}",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=file_stat.st_size,
                            file_mode=stat.filemode(file_stat.st_mode),
                            extra_info={"pattern": description}
                        ))
                        suspicious_count += 1
                        break
        
        self.stats["systemd_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious systemd units{Style.RESET}", file=sys.stderr)
    
    def _check_cron_jobs_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Check cron jobs for suspicious content in tarball."""
        suspicious_count = 0
        
        for member in members:
            if not member.isfile():
                continue
            
            is_cron = any(path in member.name for path in CRON_PATHS)
            if not is_cron:
                continue
            
            data = self.handler.extract_file(member.name)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for pattern, description in PERSISTENCE_SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="CRON_PERSISTENCE",
                        severity="CRITICAL",
                        description=f"Suspicious cron job: {description}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        extra_info={"pattern": description}
                    ))
                    suspicious_count += 1
                    break
            
            # Check for cron entries running from /tmp or downloading
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if any(susp in line for susp in ['/tmp/', '/var/tmp/', '/dev/shm/', 'curl ', 'wget ']):
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="CRON_SUSPICIOUS_ENTRY",
                        severity="HIGH",
                        description=f"Suspicious cron entry: {line[:100]}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        extra_info={"entry": line}
                    ))
                    suspicious_count += 1
                    break
        
        self.stats["cron_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious cron entries{Style.RESET}", file=sys.stderr)
    
    def _check_cron_jobs_directory(self, verbose: bool) -> None:
        """Check cron jobs for suspicious content in directory."""
        suspicious_count = 0
        base = self.source_path
        
        for cron_path in CRON_PATHS:
            full_path = os.path.join(base, cron_path)
            if not os.path.exists(full_path):
                continue
            
            if os.path.isfile(full_path):
                files_to_check = [full_path]
            else:
                try:
                    files_to_check = [os.path.join(full_path, f) for f in os.listdir(full_path)]
                except (PermissionError, OSError):
                    continue
            
            for filepath in files_to_check:
                if not os.path.isfile(filepath):
                    continue
                
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    content = data.decode('utf-8', errors='replace')
                except (PermissionError, OSError, UnicodeDecodeError):
                    continue
                
                for pattern, description in PERSISTENCE_SUSPICIOUS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        md5, sha256 = calculate_hashes(data)
                        self.binary_findings.append(BinaryFinding(
                            filepath=filepath,
                            finding_type="CRON_PERSISTENCE",
                            severity="CRITICAL",
                            description=f"Suspicious cron job: {description}",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=os.path.getsize(filepath),
                            extra_info={"pattern": description}
                        ))
                        suspicious_count += 1
                        break
        
        self.stats["cron_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious cron entries{Style.RESET}", file=sys.stderr)
    
    def _check_init_scripts_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Check init scripts and rc.local for suspicious content in tarball."""
        suspicious_count = 0
        
        for member in members:
            if not member.isfile():
                continue
            
            is_init = any(path in member.name for path in INIT_PATHS)
            if not is_init:
                continue
            
            data = self.handler.extract_file(member.name)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            for pattern, description in PERSISTENCE_SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="INIT_PERSISTENCE",
                        severity="CRITICAL",
                        description=f"Suspicious init script: {description}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        extra_info={"pattern": description}
                    ))
                    suspicious_count += 1
                    break
            
            # Special check for rc.local
            if 'rc.local' in member.name:
                # Any non-trivial rc.local content is suspicious on modern systems
                non_comment_lines = [l for l in content.split('\n') 
                                    if l.strip() and not l.strip().startswith('#') 
                                    and l.strip() != 'exit 0']
                if non_comment_lines:
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="RC_LOCAL_CONTENT",
                        severity="MEDIUM",
                        description=f"rc.local has {len(non_comment_lines)} active commands",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        extra_info={"commands": non_comment_lines[:5]}
                    ))
                    suspicious_count += 1
        
        self.stats["init_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious init scripts{Style.RESET}", file=sys.stderr)
    
    def _check_init_scripts_directory(self, verbose: bool) -> None:
        """Check init scripts and rc.local for suspicious content in directory."""
        suspicious_count = 0
        base = self.source_path
        
        for init_path in INIT_PATHS:
            full_path = os.path.join(base, init_path)
            if not os.path.exists(full_path):
                continue
            
            if os.path.isfile(full_path):
                files_to_check = [full_path]
            else:
                try:
                    files_to_check = [os.path.join(full_path, f) for f in os.listdir(full_path)]
                except (PermissionError, OSError):
                    continue
            
            for filepath in files_to_check:
                if not os.path.isfile(filepath):
                    continue
                
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    content = data.decode('utf-8', errors='replace')
                except (PermissionError, OSError, UnicodeDecodeError):
                    continue
                
                for pattern, description in PERSISTENCE_SUSPICIOUS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        md5, sha256 = calculate_hashes(data)
                        self.binary_findings.append(BinaryFinding(
                            filepath=filepath,
                            finding_type="INIT_PERSISTENCE",
                            severity="CRITICAL",
                            description=f"Suspicious init script: {description}",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=os.path.getsize(filepath),
                            extra_info={"pattern": description}
                        ))
                        suspicious_count += 1
                        break
        
        self.stats["init_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious init scripts{Style.RESET}", file=sys.stderr)
    
    def _check_kernel_modules_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Check kernel module configuration for suspicious entries in tarball."""
        suspicious_count = 0
        
        # Check /etc/modules and /etc/modules-load.d/
        for member in members:
            if not member.isfile():
                continue
            
            is_module_conf = any(path in member.name for path in ['etc/modules', 'etc/modules-load.d/'])
            if not is_module_conf:
                continue
            
            data = self.handler.extract_file(member.name)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Check for suspicious module names
            suspicious_modules = ['rootkit', 'hide', 'stealth', 'backdoor', 'diamorphine', 'reptile']
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                module_name = line.split()[0] if line.split() else ""
                if any(susp in module_name.lower() for susp in suspicious_modules):
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="KERNEL_MODULE_SUSPICIOUS",
                        severity="CRITICAL",
                        description=f"Suspicious kernel module configured: {module_name}",
                        extra_info={"module": module_name}
                    ))
                    suspicious_count += 1
        
        # Check for .ko files in unusual locations
        for member in members:
            if not member.isfile():
                continue
            
            if member.name.endswith('.ko') or member.name.endswith('.ko.xz') or member.name.endswith('.ko.gz'):
                # Check if in unusual location (not in lib/modules/)
                if 'lib/modules/' not in member.name:
                    data = self.handler.extract_file(member.name)
                    md5, sha256 = "", ""
                    if data:
                        md5, sha256 = calculate_hashes(data)
                    
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="KERNEL_MODULE_UNUSUAL_LOCATION",
                        severity="HIGH",
                        description=f"Kernel module in unusual location",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size
                    ))
                    suspicious_count += 1
        
        self.stats["kernel_module_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious kernel module configs{Style.RESET}", file=sys.stderr)
    
    def _check_kernel_modules_directory(self, verbose: bool) -> None:
        """Check kernel module configuration for suspicious entries in directory."""
        suspicious_count = 0
        base = self.source_path
        
        module_conf_paths = ['etc/modules', 'etc/modules-load.d/']
        suspicious_modules = ['rootkit', 'hide', 'stealth', 'backdoor', 'diamorphine', 'reptile']
        
        for conf_path in module_conf_paths:
            full_path = os.path.join(base, conf_path)
            if not os.path.exists(full_path):
                continue
            
            if os.path.isfile(full_path):
                files_to_check = [full_path]
            else:
                try:
                    files_to_check = [os.path.join(full_path, f) for f in os.listdir(full_path)]
                except (PermissionError, OSError):
                    continue
            
            for filepath in files_to_check:
                if not os.path.isfile(filepath):
                    continue
                
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                except (PermissionError, OSError):
                    continue
                
                for line in content.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    module_name = line.split()[0] if line.split() else ""
                    if any(susp in module_name.lower() for susp in suspicious_modules):
                        self.binary_findings.append(BinaryFinding(
                            filepath=filepath,
                            finding_type="KERNEL_MODULE_SUSPICIOUS",
                            severity="CRITICAL",
                            description=f"Suspicious kernel module configured: {module_name}",
                            extra_info={"module": module_name}
                        ))
                        suspicious_count += 1
        
        self.stats["kernel_module_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious kernel module configs{Style.RESET}", file=sys.stderr)
    
    def _check_udev_rules_tarball(self, members: List[tarfile.TarInfo], verbose: bool) -> None:
        """Check udev rules for suspicious content in tarball."""
        suspicious_count = 0
        
        for member in members:
            if not member.isfile():
                continue
            
            is_udev = any(path in member.name for path in UDEV_PATHS)
            if not is_udev:
                continue
            
            data = self.handler.extract_file(member.name)
            if not data:
                continue
            
            try:
                content = data.decode('utf-8', errors='replace')
            except Exception:
                continue
            
            # Check for RUN commands that execute scripts
            run_patterns = [
                (r'RUN\+?="[^"]*(/tmp/|/var/tmp/|/dev/shm/)', "Udev runs from suspicious location"),
                (r'RUN\+?="[^"]*curl', "Udev downloads content"),
                (r'RUN\+?="[^"]*wget', "Udev downloads content"),
                (r'RUN\+?="[^"]*nc\s', "Udev uses netcat"),
                (r'RUN\+?="[^"]*bash\s+-c', "Udev runs bash command"),
            ]
            
            for pattern, description in run_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    md5, sha256 = calculate_hashes(data)
                    self.binary_findings.append(BinaryFinding(
                        filepath='/' + member.name.lstrip('/'),
                        finding_type="UDEV_PERSISTENCE",
                        severity="CRITICAL",
                        description=f"Suspicious udev rule: {description}",
                        hash_md5=md5,
                        hash_sha256=sha256,
                        file_size=member.size,
                        extra_info={"pattern": description}
                    ))
                    suspicious_count += 1
                    break
        
        self.stats["udev_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious udev rules{Style.RESET}", file=sys.stderr)
    
    def _check_udev_rules_directory(self, verbose: bool) -> None:
        """Check udev rules for suspicious content in directory."""
        suspicious_count = 0
        base = self.source_path
        
        run_patterns = [
            (r'RUN\+?="[^"]*(/tmp/|/var/tmp/|/dev/shm/)', "Udev runs from suspicious location"),
            (r'RUN\+?="[^"]*curl', "Udev downloads content"),
            (r'RUN\+?="[^"]*wget', "Udev downloads content"),
            (r'RUN\+?="[^"]*nc\s', "Udev uses netcat"),
            (r'RUN\+?="[^"]*bash\s+-c', "Udev runs bash command"),
        ]
        
        for udev_path in UDEV_PATHS:
            full_path = os.path.join(base, udev_path)
            if not os.path.isdir(full_path):
                continue
            
            try:
                files = os.listdir(full_path)
            except (PermissionError, OSError):
                continue
            
            for filename in files:
                filepath = os.path.join(full_path, filename)
                if not os.path.isfile(filepath):
                    continue
                
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    content = data.decode('utf-8', errors='replace')
                except (PermissionError, OSError, UnicodeDecodeError):
                    continue
                
                for pattern, description in run_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        md5, sha256 = calculate_hashes(data)
                        self.binary_findings.append(BinaryFinding(
                            filepath=filepath,
                            finding_type="UDEV_PERSISTENCE",
                            severity="CRITICAL",
                            description=f"Suspicious udev rule: {description}",
                            hash_md5=md5,
                            hash_sha256=sha256,
                            file_size=os.path.getsize(filepath),
                            extra_info={"pattern": description}
                        ))
                        suspicious_count += 1
                        break
        
        self.stats["udev_persistence"] = suspicious_count
        if verbose:
            print(f"  {Style.WARNING if suspicious_count else Style.SUCCESS}Found {suspicious_count} suspicious udev rules{Style.RESET}", file=sys.stderr)
    
    def _print_summary(self) -> None:
        """Print analysis summary."""
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Analysis Summary{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
        
        # Count by severity
        severity_counts = defaultdict(int)
        for finding in self.binary_findings:
            severity_counts[finding.severity] += 1
        for finding in self.env_findings:
            severity_counts[finding.severity] += 1
        
        print(f"\n{Style.INFO}Findings by Severity:{Style.RESET}", file=sys.stderr)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = Style.CRITICAL if severity == "CRITICAL" else (
                    Style.ERROR if severity == "HIGH" else (
                        Style.WARNING if severity == "MEDIUM" else Style.INFO
                    )
                )
                print(f"  {color}{severity}: {count}{Style.RESET}", file=sys.stderr)
        
        print(f"\n{Style.INFO}Findings by Type:{Style.RESET}", file=sys.stderr)
        type_counts = defaultdict(int)
        for finding in self.binary_findings:
            type_counts[finding.finding_type] += 1
        for finding in self.env_findings:
            type_counts[finding.finding_type] += 1
        
        for ftype, count in sorted(type_counts.items()):
            print(f"  {ftype}: {count}", file=sys.stderr)
        
        print(f"\n{Style.SUCCESS}Total Findings: {len(self.binary_findings) + len(self.env_findings)}{Style.RESET}", file=sys.stderr)
    
    def export_csv(self, output_path: str) -> None:
        """Export findings to CSV file."""
        # Export binary findings
        binary_output = output_path.replace('.csv', '_binaries.csv') if output_path.endswith('.csv') else f"{output_path}_binaries.csv"
        env_output = output_path.replace('.csv', '_environment.csv') if output_path.endswith('.csv') else f"{output_path}_environment.csv"
        
        if self.binary_findings:
            with open(binary_output, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ["Filepath", "Finding_Type", "Severity", "Description", 
                             "MD5", "SHA256", "File_Size", "File_Mode", "Owner", 
                             "Group", "Modified_Time", "Access_Time", "Change_Time", "Extra_Info"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for finding in sorted(self.binary_findings, key=lambda x: (
                    {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.severity, 5),
                    x.filepath
                )):
                    writer.writerow(finding.to_dict())
            print(f"{Style.SUCCESS}Binary findings exported to:{Style.RESET} {binary_output}", file=sys.stderr)
        
        if self.env_findings:
            with open(env_output, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ["Source_File", "Finding_Type", "Severity", "Variable_Name",
                             "Variable_Value", "Description", "Line_Number"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for finding in sorted(self.env_findings, key=lambda x: (
                    {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.severity, 5),
                    x.source_file
                )):
                    writer.writerow(finding.to_dict())
            print(f"{Style.SUCCESS}Environment findings exported to:{Style.RESET} {env_output}", file=sys.stderr)


# ============================================================================
# Hash List Loading
# ============================================================================

def load_hash_list(filepath: str) -> Dict[str, str]:
    """
    Load a hash list from a file.
    
    Supports formats:
    - One hash per line
    - hash,description
    - hash description
    - hash|description
    
    Args:
        filepath: Path to hash list file
        
    Returns:
        Dictionary of hash -> description
    """
    hashes = {}
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Try different formats
                if ',' in line:
                    parts = line.split(',', 1)
                elif '|' in line:
                    parts = line.split('|', 1)
                elif '\t' in line:
                    parts = line.split('\t', 1)
                elif ' ' in line:
                    parts = line.split(' ', 1)
                else:
                    parts = [line, "Known bad"]
                
                hash_val = parts[0].strip().lower()
                description = parts[1].strip() if len(parts) > 1 else "Known bad"
                
                # Validate hash format (MD5: 32 chars, SHA256: 64 chars)
                if len(hash_val) in (32, 64) and all(c in '0123456789abcdef' for c in hash_val):
                    hashes[hash_val] = description
                    
    except Exception as e:
        print(f"{Style.WARNING}Warning: Could not load hash list {filepath}: {e}{Style.RESET}", file=sys.stderr)
    
    return hashes


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Analyze Linux systems for suspicious binaries and configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

Examples:
  # Analyze a UAC tarball
  python linux_binary_analyzer.py -s hostname.tar.gz -o findings.csv
  
  # Analyze extracted UAC directory
  python linux_binary_analyzer.py -s ./extracted_uac/ -o findings.csv
  
  # Analyze with custom hash list
  python linux_binary_analyzer.py -s evidence.tar.gz -o findings.csv --hashes known_bad.txt
  
  # Analyze live system (requires root)
  sudo python linux_binary_analyzer.py -s / -o findings.csv

Checks Performed:
  1. Rootkit traces (ld.so.preload, ld.so.conf modifications)
  2. Environment variable analysis (LD_PRELOAD, PATH manipulation)
  3. Executables in suspicious locations (/tmp, /dev/shm, etc.)
  4. SUID/SGID files outside standard locations
  5. Hidden executables (in .dotfile directories)
  6. Hash matching against known-bad indicators
  
  PERSISTENCE MECHANISMS (v1.1.0+):
  7. Systemd units - Malicious .service files in /etc/systemd/system/
  8. Cron jobs - /etc/crontab, /etc/cron.d/, user crontabs
  9. Init scripts - /etc/init.d/, /etc/rc.local
  10. Kernel modules - /etc/modules, suspicious .ko files
  11. Udev rules - /etc/udev/rules.d/ execution triggers

Hash List Format:
  The hash list file should contain one entry per line:
  - <hash>
  - <hash>,<description>
  - <hash>|<description>
  - <hash> <description>
  
  Supports both MD5 (32 chars) and SHA256 (64 chars) hashes.

Output:
  Generates two CSV files:
  - *_binaries.csv - Binary and file findings
  - *_environment.csv - Environment configuration findings
        """
    )
    
    parser.add_argument(
        "-s", "--source",
        default="/",
        help="Source path: UAC tarball, extracted directory, or '/' for live system"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="analysis_findings.csv",
        help="Output CSV file base name (default: analysis_findings.csv)"
    )
    
    parser.add_argument(
        "--hashes",
        help="Path to file containing known-bad hashes (one per line)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output"
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    
    args = parser.parse_args()
    
    # Load custom hash list if provided
    known_hashes = dict(KNOWN_BAD_HASHES)
    if args.hashes:
        custom_hashes = load_hash_list(args.hashes)
        known_hashes.update(custom_hashes)
        if not args.quiet:
            print(f"{Style.INFO}Loaded {len(custom_hashes)} hashes from {args.hashes}{Style.RESET}", file=sys.stderr)
    
    # Resolve source path
    source_path = args.source
    if source_path != "/" and not os.path.isabs(source_path):
        source_path = os.path.abspath(source_path)
    
    # Validate source exists
    if not os.path.exists(source_path):
        print(f"{Style.ERROR}Error: Source path does not exist: {source_path}{Style.RESET}", file=sys.stderr)
        sys.exit(1)
    
    try:
        analyzer = LinuxBinaryAnalyzer(source_path, known_hashes)
        analyzer.analyze(verbose=not args.quiet)
        
        # Export results
        output_path = args.output
        if not os.path.isabs(output_path):
            output_path = os.path.abspath(output_path)
        
        analyzer.export_csv(output_path)
        analyzer.close()
        
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Analysis interrupted by user{Style.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


