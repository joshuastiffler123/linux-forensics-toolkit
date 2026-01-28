#!/usr/bin/env python3
"""
Linux Journal Analyzer - Parse and analyze systemd journal logs

This script extracts and analyzes systemd journal entries from:
- UAC tarballs (text exports or binary journal files)
- Live systems (via journalctl command)
- Exported journal files (JSON or text format)

Features:
- Parse multiple journal export formats (text, JSON, short, verbose)
- Parse binary journal files with LZ4/XZ decompression support
- Filter by time range, unit, priority, or keyword
- Extract security-relevant events (auth, sudo, ssh, service changes)
- Timeline events to CSV with severity classification
- Support for UAC tarball analysis
- Multi-language pattern support for localized systems

Optional Dependencies:
- lz4: For LZ4-compressed binary journals (pip install lz4)
- lzma: For XZ-compressed journals (usually built into Python)

Author: Linux Forensics Toolkit
Version: 1.1.0
"""

import argparse
import csv
import gzip
import io
import json
import lzma
import os
import re
import struct
import sys
import tarfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple, Any

__version__ = "1.1.0"

# Optional LZ4 support for compressed binary journals
try:
    import lz4.block
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

# Default message truncation limit (can be overridden via --max-message-length)
DEFAULT_MAX_MESSAGE_LENGTH = 50000  # 50KB - enough for base64 payloads


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
    WHITE = "\033[37m"
    
    HEADER = "\033[95m"
    SUCCESS = GREEN
    WARNING = YELLOW
    ERROR = RED
    INFO = CYAN
    CRITICAL = "\033[91m"
    
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
class JournalEntry:
    """Represents a single journal entry."""
    timestamp: datetime
    hostname: str
    unit: str
    priority: int
    priority_name: str
    message: str
    pid: int = 0
    uid: int = -1
    gid: int = -1
    comm: str = ""  # Command name
    exe: str = ""   # Executable path
    cmdline: str = ""
    boot_id: str = ""
    machine_id: str = ""
    transport: str = ""
    syslog_identifier: str = ""
    syslog_facility: int = -1
    source_file: str = ""
    category: str = "GENERAL"
    extra: Dict = field(default_factory=dict)
    
    # Priority levels
    PRIORITIES = {
        0: "EMERG",
        1: "ALERT", 
        2: "CRIT",
        3: "ERR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFO",
        7: "DEBUG"
    }
    
    def clean_message(self, message: str) -> str:
        """Clean up message by removing redundant info already in other columns."""
        if not message:
            return ""
        
        msg = message.strip()
        
        # Remove leading timestamp patterns (various formats)
        # "Dec 18 10:15:30" or "2024-12-18T10:15:30" etc.
        msg = re.sub(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*', '', msg)
        msg = re.sub(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4}|Z)?)\s*', '', msg)
        
        # Remove hostname if it appears at the start
        if self.hostname and msg.lower().startswith(self.hostname.lower()):
            msg = msg[len(self.hostname):].lstrip()
        
        # Remove unit/identifier prefix like "sshd[1234]:" or "kernel:"
        unit_pattern = rf'^{re.escape(self.syslog_identifier or self.unit.split("[")[0])}(?:\[\d+\])?:\s*'
        if self.syslog_identifier or self.unit:
            msg = re.sub(unit_pattern, '', msg, flags=re.IGNORECASE)
        
        # Remove generic service prefix patterns (with PID)
        msg = re.sub(r'^[\w\-\.]+\[\d+\]:\s*', '', msg)
        
        # Remove simple unit prefix (without PID) only if it exactly matches our unit
        # Be careful not to strip things like "Error:" or "Warning:"
        if self.unit and '[' not in self.unit and len(self.unit) > 2:
            # Only strip if it looks like a service name (lowercase, contains common service chars)
            if re.match(r'^[a-z][a-z0-9_\-\.]+$', self.unit):
                msg = re.sub(rf'^{re.escape(self.unit)}:\s*', '', msg, flags=re.IGNORECASE)
        
        # Remove priority prefixes like "<6>", "[INFO]" (bracketed only - keep natural language like "Error:")
        msg = re.sub(r'^<\d+>\s*', '', msg)  # Syslog priority like <6>
        msg = re.sub(r'^\[(EMERG|ALERT|CRIT|ERR|ERROR|WARN|WARNING|NOTICE|INFO|DEBUG)\]\s*', '', msg, flags=re.IGNORECASE)
        
        # Clean up PAM messages - make them more readable
        # "pam_unix(sshd:session): session opened for user root by (uid=0)"
        # -> "session opened for user root by (uid=0)"
        msg = re.sub(r'^pam_\w+\([^)]+\):\s*', '', msg)
        
        # Clean up systemd messages
        # "systemd[1]: Started OpenSSH server daemon." -> "Started OpenSSH server daemon."
        msg = re.sub(r'^systemd\[\d+\]:\s*', '', msg)
        
        # Remove repeated hostname in message
        if self.hostname:
            msg = re.sub(rf'\b{re.escape(self.hostname)}\b\s*', '', msg, count=1)
        
        # Clean up audit messages - extract the meaningful part
        # "type=USER_AUTH msg=audit(123456.789:100): pid=1234 ..."
        audit_match = re.match(r'type=(\w+)\s+msg=audit\([^)]+\):\s*(.*)', msg)
        if audit_match:
            audit_type, audit_content = audit_match.groups()
            # Extract key info from audit message
            audit_info = []
            for field in ['acct', 'exe', 'hostname', 'addr', 'terminal', 'res']:
                field_match = re.search(rf'{field}="?([^"\s]+)"?', audit_content)
                if field_match:
                    value = field_match.group(1)
                    if value and value != '?' and value != '(null)':
                        audit_info.append(f"{field}={value}")
            if audit_info:
                msg = f"{audit_type}: {' '.join(audit_info)}"
            else:
                msg = f"{audit_type}: {audit_content[:200]}"
        
        # Simplify common verbose messages
        # "Accepted publickey for user from 192.168.1.1 port 12345 ssh2: RSA SHA256:xxx"
        # -> "Accepted publickey for user from 192.168.1.1"
        msg = re.sub(r'\s+port\s+\d+\s+ssh2.*$', '', msg)  # With ssh2 and anything after
        msg = re.sub(r'\s+port\s+\d+$', '', msg)  # Just port number at end
        
        # Clean up disconnect messages
        msg = re.sub(r'Disconnected from (authenticating )?user\s+', 'Disconnected: ', msg)
        msg = re.sub(r'Connection closed by (authenticating )?user\s+', 'Connection closed by ', msg)
        
        # Remove redundant "for user" when we have username
        # Keep it readable though
        
        # Clean multiple spaces
        msg = re.sub(r'\s+', ' ', msg).strip()
        
        return msg
    
    def to_dict(self, max_message_length: int = None) -> Dict:
        """Convert to dictionary for CSV export."""
        max_len = max_message_length or DEFAULT_MAX_MESSAGE_LENGTH
        cleaned_msg = self.clean_message(self.message)
        
        # Calculate timestamps - UTC and local
        # Note: Timestamp is stored in UTC, Timestamp_Local is analysis machine's local time
        timestamp_utc = ""
        timestamp_local = ""
        if self.timestamp:
            timestamp_utc = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            try:
                from datetime import timezone
                utc_aware = self.timestamp.replace(tzinfo=timezone.utc)
                local_dt = utc_aware.astimezone()
                timestamp_local = local_dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp_local = timestamp_utc
        
        return {
            "Timestamp": timestamp_utc,
            "Timestamp_Local": timestamp_local,
            "Hostname": self.hostname,
            "Unit": self.unit.split('[')[0] if self.unit else "",  # Remove PID from unit
            "Priority": self.priority_name,  # Use name instead of number for readability
            "Category": self.category,
            "PID": self.pid if self.pid else "",
            "UID": self.uid if self.uid >= 0 else "",
            "User": self._extract_user_from_message(),
            "Source_IP": self._extract_ip_from_message(),
            "Message": cleaned_msg[:max_len] if cleaned_msg else "",
            "Source_File": os.path.basename(self.source_file) if self.source_file else "",
        }
    
    def _extract_user_from_message(self) -> str:
        """Extract username from message if present."""
        if not self.message:
            return ""
        
        # Common patterns for usernames in log messages
        patterns = [
            r'for user[= ](\w+)',
            r'for (\w+) from',
            r'user[= ](\w+)',
            r'USER=(\w+)',
            r'acct="?(\w+)"?',
            r'session opened for user (\w+)',
            r'Accepted \w+ for (\w+)',
            r'Failed \w+ for (?:invalid user )?(\w+)',
            r'Invalid user (\w+)',
            r'su for (\w+)',
            r'Successful su for (\w+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, self.message, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _extract_ip_from_message(self) -> str:
        """Extract IP address from message if present."""
        if not self.message:
            return ""
        
        # IPv4 pattern
        ipv4_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.message)
        if ipv4_match:
            return ipv4_match.group(1)
        
        # General IP pattern
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', self.message)
        if ip_match:
            return ip_match.group(1)
        
        # IPv6 (simplified)
        ipv6_match = re.search(r'from\s+([0-9a-fA-F:]+::[0-9a-fA-F:]+)', self.message)
        if ipv6_match:
            return ipv6_match.group(1)
        
        return ""


# ============================================================================
# Security Event Categories
# ============================================================================

# Patterns to categorize journal entries
# NOTE: Includes multi-language patterns for localized Linux systems
# German (de), French (fr), Spanish (es), Portuguese (pt), Italian (it),
# Russian (ru), Chinese (zh), Japanese (ja), Korean (ko)
CATEGORY_PATTERNS = {
    "AUTH_SUCCESS": [
        # English
        r"Accepted\s+(password|publickey|keyboard-interactive|gssapi)",
        r"session opened for user",
        r"pam_unix.*session opened",
        r"New session \d+ of user",
        r"Successful su for",
        r"Successful login",
        r"authentication\s+success",
        r"logged\s+in",
        # PAM/systemd specific (language-independent)
        r"pam_succeed_if.*success",
        r"USER_LOGIN.*res=success",
        r"USER_AUTH.*res=success",
        r"type=USER_LOGIN.*success",
        # German
        r"Sitzung.*ge[öo]ffnet",
        r"Anmeldung.*erfolgreich",
        r"Authentifizierung.*erfolgreich",
        # French
        r"session ouverte",
        r"authentification r[ée]ussie",
        r"connexion r[ée]ussie",
        # Spanish
        r"sesi[óo]n abierta",
        r"autenticaci[óo]n exitosa",
        # Portuguese
        r"sess[ãa]o aberta",
        r"autentica[çc][ãa]o bem.sucedida",
        # Generic patterns (work across languages)
        r"pam_.*\(.*\):\s*session\s+opened",
        r"USER_START.*res=success",
    ],
    "AUTH_FAILURE": [
        # English
        r"authentication failure",
        r"Failed password",
        r"Failed publickey",
        r"FAILED SU",
        r"FAILED LOGIN",
        r"pam_unix.*authentication failure",
        r"Invalid user",
        r"Connection closed by.*\[preauth\]",
        r"maximum authentication attempts exceeded",
        r"Too many authentication failures",
        r"password check failed",
        r"bad password",
        r"incorrect password",
        r"access denied",
        r"permission denied",
        r"not allowed",
        r"refused connect",
        # PAM/audit specific (language-independent)
        r"USER_AUTH.*res=failed",
        r"USER_LOGIN.*res=failed",
        r"type=USER_AUTH.*fail",
        r"pam_.*authentication\s+failure",
        r"CRED_ACQ.*res=failed",
        # German
        r"Authentifizierung.*fehlgeschlagen",
        r"Anmeldung.*fehlgeschlagen",
        r"Passwort.*falsch",
        r"Zugriff verweigert",
        # French
        r"[ée]chec.*authentification",
        r"mot de passe.*incorrect",
        r"acc[eè]s refus[ée]",
        # Spanish
        r"autenticaci[óo]n.*fallida",
        r"contrase[ñn]a.*incorrecta",
        r"acceso denegado",
        # Portuguese  
        r"autentica[çc][ãa]o.*falhou",
        r"senha.*incorreta",
        r"acesso negado",
        # Generic failure patterns
        r"error.*auth",
        r"auth.*error",
        r"login.*fail",
        r"fail.*login",
    ],
    "SUDO": [
        r"sudo:",
        r"COMMAND=",
        r"pam_unix\(sudo:",
        r"sudo\[\d+\]:",
        r"TTY=.*PWD=.*USER=.*COMMAND=",  # Standard sudo log format
        r"SUDO.*USER=",
        r"pkexec",  # Polkit equivalent
        r"doas:",   # OpenBSD doas
    ],
    "SSH": [
        r"sshd\[\d+\]:",
        r"ssh connection",
        r"Received disconnect",
        r"Disconnected from",
        r"Connection reset by",
        r"Server listening on",
        r"Did not receive identification string",
        r"Bad protocol version",
        r"Connection from.*port",
        r"Received signal 15",  # sshd termination
        r"session.*sshd",
        r"Starting session:",
        r"pam_unix\(sshd:",
        r"subsystem.*sftp",
        r"channel \d+:",
    ],
    "USER_MGMT": [
        # Commands (language-independent)
        r"useradd",
        r"usermod",
        r"userdel",
        r"groupadd",
        r"groupmod",
        r"groupdel",
        r"passwd",
        r"chage",
        r"chpasswd",
        r"pwck",
        r"grpck",
        r"vipw",
        r"vigr",
        # Audit events
        r"ADD_USER",
        r"DEL_USER",
        r"ADD_GROUP",
        r"DEL_GROUP",
        r"USER_CHAUTHTOK",
        r"CHGRP_ID",
        # English
        r"new user:",
        r"new group:",
        r"delete user",
        r"delete group",
        r"password changed",
        r"account.*created",
        r"account.*deleted",
        # German
        r"neuer Benutzer",
        r"neue Gruppe",
        r"Benutzer.*gel[öo]scht",
        r"Passwort.*ge[äa]ndert",
        # French
        r"nouvel utilisateur",
        r"nouveau groupe",
        r"utilisateur.*supprim",
        # Spanish
        r"nuevo usuario",
        r"nuevo grupo",
        r"usuario.*eliminado",
    ],
    "SERVICE": [
        # Systemd (universal)
        r"Started\s+",
        r"Stopped\s+",
        r"Starting\s+",
        r"Stopping\s+",
        r"Reloading\s+",
        r"systemd\[\d+\]:",
        r"\.service",
        r"Unit .* entered",
        r"Reached target",
        r"Activating",
        r"Deactivating",
        r"Activated",
        r"Failed to start",
        r"Main process exited",
        r"Service hold-off time over",
        # German
        r"Gestartet",
        r"Gestoppt",
        r"Wird gestartet",
        r"Wird gestoppt",
        # French
        r"D[ée]marr[ée]",
        r"Arr[êe]t[ée]",
        # Spanish
        r"Iniciado",
        r"Detenido",
    ],
    "BOOT_SHUTDOWN": [
        r"System is powering",
        r"Startup finished",
        r"systemd.*Shutting down",
        r"Reached target Shutdown",
        r"Reached target Reboot",
        r"Linux version",
        r"Booting paravirtualized kernel",
        r"kernel: Command line:",
        r"BOOT_ID=",
        r"Journal started",
        r"System boot",
        r"System shutdown",
        r"Watchdog",
        r"Hardware Watchdog",
        r"Powering off",
        r"Rebooting",
        r"Suspending",
        r"Lid (opened|closed)",
    ],
    "CRON": [
        r"CRON\[\d+\]:",
        r"cron\[\d+\]:",
        r"crond\[\d+\]:",
        r"anacron",
        r"run-parts",
        r"CMD\s*\(",
        r"atd\[\d+\]:",
        r"systemd-timer",
        r"\.timer",
    ],
    "NETWORK": [
        r"NetworkManager",
        r"dhclient",
        r"dhcpcd",
        r"wpa_supplicant",
        r"network interface",
        r"link is (up|down)",
        r"carrier (acquired|lost)",
        r"connected to",
        r"addresses changed",
        r"renamed\s+\w+\s+to",
        r"enp\d+s\d+",
        r"eth\d+",
        r"wlan\d+",
        r"bond\d+",
        r"br\d+",
        r"DHCPACK",
        r"DHCPREQUEST",
        r"DNS.*server",
        r"route.*added",
    ],
    "FIREWALL": [
        r"iptables",
        r"ip6tables",
        r"nftables",
        r"firewalld",
        r"ufw",
        r"DROP",
        r"REJECT",
        r"ACCEPT",
        r"SRC=.*DST=",
        r"PROTO=.*DPT=",
        r"IN=.*OUT=",
        r"firewall.*rule",
        r"zone.*changed",
    ],
    "KERNEL": [
        r"kernel:",
        r"segfault at",
        r"Out of memory",
        r"oom-killer",
        r"Call Trace:",
        r"BUG:",
        r"WARNING:",
        r"usb \d+-\d+:",
    ],
    "AUDIT": [
        r"audit\[\d+\]:",
        r"auditd\[\d+\]:",
        r"type=\w+.*msg=audit",
        r"AVC.*denied",
        r"USER_AUTH",
        r"USER_ACCT",
        r"USER_LOGIN",
        r"USER_START",
        r"USER_END",
        r"CRED_ACQ",
        r"CRED_DISP",
    ],
    "SECURITY": [
        r"apparmor",
        r"selinux",
        r"denied",
        r"blocked",
        r"violation",
        r"attack",
        r"intrusion",
        r"malware",
        r"virus",
        r"trojan",
    ],
    "DISK_STORAGE": [
        r"disk error",
        r"I/O error",
        r"filesystem",
        r"mounted",
        r"unmounted",
        r"fsck",
        r"LVM",
        r"mdadm",
        r"smartd",
    ],
}

# Units that are security-relevant
SECURITY_UNITS = {
    "sshd", "ssh", "sudo", "su", "login", "gdm", "lightdm", "sddm",
    "auditd", "audit", "rsyslog", "syslog-ng", "systemd-logind",
    "polkit", "pkexec", "dbus", "firewalld", "iptables", "nftables",
    "apparmor", "selinux", "fail2ban", "crowdsec",
    "cron", "crond", "anacron", "atd",
    "docker", "containerd", "podman",
    "vsftpd", "proftpd", "pure-ftpd",
    "apache", "apache2", "httpd", "nginx",
    "named", "bind", "unbound",
    "smbd", "nmbd", "winbind",
}


# ============================================================================
# UAC Tarball Handler
# ============================================================================

class UACHandler:
    """Handle UAC tarball extraction and file access."""
    
    TAR_EXTENSIONS = ('.tar.gz', '.tgz', '.tar.bz2', '.tar', '.tar.xz')
    
    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path) if source_path else None
        self.is_tarball = False
        self.tar = None
        self.hostname = None
        self._member_cache = {}
        self._prefix = ""
        
        if source_path and os.path.isfile(source_path):
            if any(source_path.lower().endswith(ext) for ext in self.TAR_EXTENSIONS):
                self.is_tarball = True
                self._open_tarball()
        
        # Extract hostname
        self._extract_hostname()
    
    def _open_tarball(self):
        """Open the tarball for reading."""
        try:
            if self.source_path.endswith('.tar.gz') or self.source_path.endswith('.tgz'):
                self.tar = tarfile.open(self.source_path, 'r:gz')
            elif self.source_path.endswith('.tar.bz2'):
                self.tar = tarfile.open(self.source_path, 'r:bz2')
            elif self.source_path.endswith('.tar.xz'):
                self.tar = tarfile.open(self.source_path, 'r:xz')
            else:
                self.tar = tarfile.open(self.source_path, 'r')
            
            # Cache members and find prefix
            members = self.tar.getmembers()
            for member in members:
                self._member_cache[member.name] = member
                # Detect UAC-style prefix
                if '/var/log/' in member.name and not self._prefix:
                    idx = member.name.find('/var/log/')
                    self._prefix = member.name[:idx+1] if idx > 0 else ""
                    
        except Exception as e:
            print(f"{Style.ERROR}Error opening tarball: {e}{Style.RESET}", file=sys.stderr)
            self.tar = None
    
    def _extract_hostname(self):
        """Extract hostname from tarball name or system files."""
        if self.is_tarball and self.source_path:
            basename = os.path.basename(self.source_path)
            for ext in self.TAR_EXTENSIONS:
                if basename.lower().endswith(ext):
                    basename = basename[:-len(ext)]
                    break
            # UAC format often: hostname-uac-timestamp
            for sep in ['-uac', '_uac', '-', '_']:
                if sep in basename.lower():
                    self.hostname = basename.split(sep)[0]
                    break
            if not self.hostname:
                self.hostname = basename
        elif self.source_path and os.path.isdir(self.source_path):
            # Try to read from hostname file
            hostname_file = os.path.join(self.source_path, 'etc', 'hostname')
            if os.path.exists(hostname_file):
                try:
                    with open(hostname_file, 'r') as f:
                        self.hostname = f.read().strip()
                except:
                    pass
            if not self.hostname:
                self.hostname = os.path.basename(self.source_path.rstrip('/\\'))
        
        if not self.hostname:
            self.hostname = "unknown"
    
    def get_file(self, filepath: str) -> Optional[bytes]:
        """Get file contents from tarball or directory."""
        if self.is_tarball and self.tar:
            # Try various path combinations
            paths_to_try = [
                filepath,
                self._prefix + filepath,
                self._prefix + filepath.lstrip('/'),
                filepath.lstrip('/'),
            ]
            
            for path in paths_to_try:
                if path in self._member_cache:
                    try:
                        f = self.tar.extractfile(self._member_cache[path])
                        if f:
                            return f.read()
                    except:
                        pass
            return None
        elif self.source_path:
            full_path = os.path.join(self.source_path, filepath.lstrip('/'))
            if os.path.isfile(full_path):
                try:
                    with open(full_path, 'rb') as f:
                        return f.read()
                except:
                    pass
        return None
    
    def find_files(self, patterns: List[str]) -> Iterator[Tuple[str, Any]]:
        """Find files matching patterns."""
        if self.is_tarball and self.tar:
            for name, member in self._member_cache.items():
                if member.isfile():
                    for pattern in patterns:
                        if pattern in name or re.search(pattern, name):
                            yield name, member
                            break
        elif self.source_path and os.path.isdir(self.source_path):
            for root, dirs, files in os.walk(self.source_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    rel_path = os.path.relpath(filepath, self.source_path)
                    for pattern in patterns:
                        if pattern in rel_path or re.search(pattern, rel_path):
                            yield rel_path, filepath
                            break
    
    def list_directory(self, dirpath: str) -> List[str]:
        """List files in a directory."""
        files = []
        dirpath = dirpath.rstrip('/')
        
        if self.is_tarball and self.tar:
            for name in self._member_cache:
                # Check various path formats
                check_paths = [dirpath, self._prefix + dirpath, self._prefix + dirpath.lstrip('/')]
                for check_path in check_paths:
                    if name.startswith(check_path + '/') or name.startswith(check_path.lstrip('/') + '/'):
                        if self._member_cache[name].isfile():
                            files.append(name)
                        break
        elif self.source_path:
            full_path = os.path.join(self.source_path, dirpath.lstrip('/'))
            if os.path.isdir(full_path):
                try:
                    for item in os.listdir(full_path):
                        item_path = os.path.join(full_path, item)
                        if os.path.isfile(item_path):
                            files.append(os.path.join(dirpath, item))
                except:
                    pass
        
        return files
    
    def close(self):
        """Close the tarball if open."""
        if self.tar:
            self.tar.close()
            self.tar = None


# ============================================================================
# Journal Parsers
# ============================================================================

class JournalParser:
    """Parse various journal export formats."""
    
    def __init__(self, handler: UACHandler, reference_date: datetime = None):
        self.handler = handler
        self.entries: List[JournalEntry] = []
        self.stats = defaultdict(int)
        # Reference date for year inference on syslog-style timestamps (no year)
        # For forensic analysis, this should be set based on file mtimes or other context,
        # not datetime.now() which would be incorrect for historical evidence.
        self.reference_date = reference_date
    
    def parse_all(self) -> List[JournalEntry]:
        """Parse all available journal sources."""
        self.entries = []
        
        # Look for journal exports in common locations
        journal_sources = [
            # UAC journal exports
            ("live_response/process/journal", "text"),
            ("live_response/process/journalctl*.txt", "text"),
            ("live_response/process/journalctl*.json", "json"),
            # Manual exports
            ("var/log/journal_export.txt", "text"),
            ("var/log/journal_export.json", "json"),
            ("var/log/journalctl.txt", "text"),
            ("var/log/journalctl.json", "json"),
            # Binary journals
            ("var/log/journal/", "binary"),
            ("run/log/journal/", "binary"),
        ]
        
        # Find and parse journal files
        for pattern, fmt in journal_sources:
            if fmt == "binary":
                # Look for binary journal files
                for filepath, _ in self.handler.find_files([r'\.journal$', pattern]):
                    self._parse_binary_journal(filepath)
            else:
                for filepath, _ in self.handler.find_files([pattern]):
                    data = self.handler.get_file(filepath)
                    if data:
                        if fmt == "json":
                            self._parse_json_journal(data, filepath)
                        else:
                            self._parse_text_journal(data, filepath)
        
        # Sort by timestamp
        self.entries.sort(key=lambda x: x.timestamp if x.timestamp else datetime.min)
        return self.entries
    
    def _parse_text_journal(self, data: bytes, source_file: str = "") -> None:
        """Parse text format journal export."""
        try:
            content = data.decode('utf-8', errors='replace')
        except:
            return
        
        # Detect format type
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            entry = self._parse_text_line(line, source_file)
            if entry:
                self.entries.append(entry)
                self.stats["text_entries"] += 1
    
    def _parse_text_line(self, line: str, source_file: str = "") -> Optional[JournalEntry]:
        """Parse a single text journal line."""
        # Format 1: Short format (default journalctl output)
        # "Dec 17 10:15:30 hostname sshd[1234]: Accepted password for user"
        short_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
        
        # Format 2: ISO timestamp format
        # "2024-12-17T10:15:30.123456+0000 hostname sshd[1234]: message"
        iso_pattern = r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4}|Z)?)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
        
        # Format 3: Verbose format with priority
        # "Dec 17 10:15:30.123456 hostname kernel: message"
        verbose_pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
        
        # Try each pattern
        for pattern in [iso_pattern, short_pattern, verbose_pattern]:
            match = re.match(pattern, line)
            if match:
                ts_str, hostname, unit, pid, message = match.groups()
                
                timestamp = self._parse_timestamp(ts_str)
                if not timestamp:
                    continue
                
                # Extract syslog identifier from unit
                syslog_id = unit.split('[')[0] if '[' in unit else unit
                
                # Determine priority from message content
                priority, priority_name = self._guess_priority(message, syslog_id)
                
                # Categorize the entry
                category = self._categorize_entry(message, syslog_id)
                
                return JournalEntry(
                    timestamp=timestamp,
                    hostname=hostname,
                    unit=unit,
                    priority=priority,
                    priority_name=priority_name,
                    message=message,
                    pid=int(pid) if pid else 0,
                    syslog_identifier=syslog_id,
                    source_file=source_file,
                    category=category
                )
        
        return None
    
    def _parse_json_journal(self, data: bytes, source_file: str = "") -> None:
        """Parse JSON format journal export."""
        try:
            content = data.decode('utf-8', errors='replace')
        except:
            return
        
        # JSON export can be newline-delimited JSON objects
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                obj = json.loads(line)
                entry = self._parse_json_entry(obj, source_file)
                if entry:
                    self.entries.append(entry)
                    self.stats["json_entries"] += 1
            except json.JSONDecodeError:
                continue
    
    def _parse_json_entry(self, obj: Dict, source_file: str = "") -> Optional[JournalEntry]:
        """Parse a single JSON journal entry."""
        # Extract timestamp
        timestamp = None
        if '__REALTIME_TIMESTAMP' in obj:
            # Microseconds since epoch - use UTC for forensic consistency
            try:
                ts_us = int(obj['__REALTIME_TIMESTAMP'])
                timestamp = datetime.utcfromtimestamp(ts_us / 1000000)
            except:
                pass
        elif '_SOURCE_REALTIME_TIMESTAMP' in obj:
            try:
                ts_us = int(obj['_SOURCE_REALTIME_TIMESTAMP'])
                timestamp = datetime.utcfromtimestamp(ts_us / 1000000)
            except:
                pass
        
        if not timestamp:
            return None
        
        # Extract priority
        priority = int(obj.get('PRIORITY', 6))
        priority_name = JournalEntry.PRIORITIES.get(priority, "INFO")
        
        # Extract message
        message = obj.get('MESSAGE', '')
        if isinstance(message, list):
            # Binary data stored as byte array
            try:
                message = bytes(message).decode('utf-8', errors='replace')
            except:
                message = str(message)
        
        # Extract unit/identifier
        unit = obj.get('_SYSTEMD_UNIT', '') or obj.get('SYSLOG_IDENTIFIER', '') or obj.get('_COMM', '')
        syslog_id = obj.get('SYSLOG_IDENTIFIER', '') or obj.get('_COMM', '')
        
        # Categorize
        category = self._categorize_entry(message, syslog_id)
        
        return JournalEntry(
            timestamp=timestamp,
            hostname=obj.get('_HOSTNAME', ''),
            unit=unit,
            priority=priority,
            priority_name=priority_name,
            message=message,
            pid=int(obj.get('_PID', 0)) if obj.get('_PID') else 0,
            uid=int(obj.get('_UID', -1)) if obj.get('_UID') else -1,
            gid=int(obj.get('_GID', -1)) if obj.get('_GID') else -1,
            comm=obj.get('_COMM', ''),
            exe=obj.get('_EXE', ''),
            cmdline=obj.get('_CMDLINE', ''),
            boot_id=obj.get('_BOOT_ID', ''),
            machine_id=obj.get('_MACHINE_ID', ''),
            transport=obj.get('_TRANSPORT', ''),
            syslog_identifier=syslog_id,
            syslog_facility=int(obj.get('SYSLOG_FACILITY', -1)) if obj.get('SYSLOG_FACILITY') else -1,
            source_file=source_file,
            category=category,
            extra={k: v for k, v in obj.items() if not k.startswith('_') and k not in 
                   ['MESSAGE', 'PRIORITY', 'SYSLOG_IDENTIFIER', 'SYSLOG_FACILITY']}
        )
    
    def _parse_binary_journal(self, filepath: str) -> None:
        """
        Parse binary systemd journal files.
        
        The journal format consists of:
        - Header (with signature LPKSHHRH)
        - Object headers (DATA, FIELD, ENTRY, etc.)
        - Entry arrays pointing to data objects
        """
        data = self.handler.get_file(filepath)
        if not data:
            return
        
        # Check journal signature
        if not data.startswith(b'LPKSHHRH'):
            return
        
        self.stats["binary_journals"] += 1
        
        try:
            entries_parsed = self._parse_journal_binary_format(data, filepath)
            self.stats["binary_entries"] += entries_parsed
            if entries_parsed == 0:
                self.stats["binary_needs_export"] = True
        except Exception as e:
            self.stats["binary_parse_errors"] += 1
            self.stats["binary_needs_export"] = True
    
    def _parse_journal_binary_format(self, data: bytes, source_file: str) -> int:
        """
        Parse the systemd journal binary format.
        
        Journal file structure:
        - Bytes 0-7: Signature "LPKSHHRH"
        - Header with various offsets
        - Objects: DATA, FIELD, ENTRY, HASH_TABLE, etc.
        """
        if len(data) < 256:
            return 0
        
        entries_parsed = 0
        
        # Header structure (simplified)
        # Offset 8-11: compatible_flags
        # Offset 12-15: incompatible_flags  
        # Offset 88-95: n_objects
        # Offset 96-103: n_entries
        # etc.
        
        try:
            # Read header fields
            header_size = struct.unpack('<Q', data[24:32])[0] if len(data) > 32 else 0
            n_entries = struct.unpack('<Q', data[96:104])[0] if len(data) > 104 else 0
            
            if n_entries == 0 or header_size == 0:
                # Try alternative parsing - scan for entry patterns
                return self._scan_journal_for_entries(data, source_file)
            
            # Object types
            OBJECT_UNUSED = 0
            OBJECT_DATA = 1
            OBJECT_FIELD = 2
            OBJECT_ENTRY = 3
            OBJECT_DATA_HASH_TABLE = 4
            OBJECT_FIELD_HASH_TABLE = 5
            OBJECT_ENTRY_ARRAY = 6
            OBJECT_TAG = 7
            
            # Scan for ENTRY objects
            offset = header_size if header_size > 0 else 256
            max_offset = len(data) - 64
            
            while offset < max_offset and entries_parsed < 100000:
                # Object header: type(1), flags(1), reserved(6), size(8)
                if offset + 16 > len(data):
                    break
                    
                obj_type = data[offset]
                obj_size = struct.unpack('<Q', data[offset+8:offset+16])[0]
                
                if obj_size < 16 or obj_size > 10000000 or obj_type > 7:
                    offset += 8
                    continue
                
                if obj_type == OBJECT_ENTRY:
                    entry = self._parse_binary_entry(data, offset, obj_size, source_file)
                    if entry:
                        self.entries.append(entry)
                        entries_parsed += 1
                
                # Align to 8 bytes
                offset += (obj_size + 7) & ~7
            
            # If we didn't find entries via objects, try scanning
            if entries_parsed == 0:
                entries_parsed = self._scan_journal_for_entries(data, source_file)
                
        except Exception:
            # Fall back to scanning
            entries_parsed = self._scan_journal_for_entries(data, source_file)
        
        return entries_parsed
    
    def _parse_binary_entry(self, data: bytes, offset: int, size: int, source_file: str) -> Optional[JournalEntry]:
        """Parse a binary ENTRY object."""
        try:
            # Entry object structure:
            # Offset 0-15: Object header
            # Offset 16-23: seqnum
            # Offset 24-31: realtime (microseconds since epoch)
            # Offset 32-39: monotonic
            # Offset 40-55: boot_id (128-bit)
            # Offset 56-63: xor_hash
            # Offset 64+: item array (field offset + hash pairs)
            
            if offset + 64 > len(data):
                return None
            
            realtime_us = struct.unpack('<Q', data[offset+24:offset+32])[0]
            boot_id_bytes = data[offset+40:offset+56]
            
            # Convert timestamp
            if realtime_us == 0 or realtime_us > 2000000000000000:  # Sanity check
                return None
            
            timestamp = datetime.utcfromtimestamp(realtime_us / 1000000)  # UTC for consistency
            boot_id = boot_id_bytes.hex()
            
            # Parse entry items to get field data
            fields = self._extract_entry_fields(data, offset, size)
            
            message = fields.get('MESSAGE', '')
            hostname = fields.get('_HOSTNAME', '')
            unit = fields.get('_SYSTEMD_UNIT', '') or fields.get('SYSLOG_IDENTIFIER', '') or fields.get('_COMM', '')
            syslog_id = fields.get('SYSLOG_IDENTIFIER', '') or fields.get('_COMM', '')
            priority = int(fields.get('PRIORITY', 6))
            priority_name = JournalEntry.PRIORITIES.get(priority, "INFO")
            
            if not message and not unit:
                return None
            
            category = self._categorize_entry(message, syslog_id)
            
            return JournalEntry(
                timestamp=timestamp,
                hostname=hostname,
                unit=unit,
                priority=priority,
                priority_name=priority_name,
                message=message,
                pid=int(fields.get('_PID', 0)) if fields.get('_PID', '').isdigit() else 0,
                uid=int(fields.get('_UID', -1)) if fields.get('_UID', '').lstrip('-').isdigit() else -1,
                gid=int(fields.get('_GID', -1)) if fields.get('_GID', '').lstrip('-').isdigit() else -1,
                comm=fields.get('_COMM', ''),
                exe=fields.get('_EXE', ''),
                boot_id=boot_id,
                syslog_identifier=syslog_id,
                source_file=source_file,
                category=category
            )
        except Exception:
            return None
    
    def _extract_entry_fields(self, data: bytes, entry_offset: int, entry_size: int) -> Dict[str, str]:
        """Extract fields from an entry by following data object references."""
        fields = {}
        
        # Entry items start at offset 64 within the entry
        items_offset = entry_offset + 64
        items_end = entry_offset + entry_size
        
        # Each item is 16 bytes: object_offset(8) + hash(8)
        while items_offset + 16 <= items_end:
            try:
                data_offset = struct.unpack('<Q', data[items_offset:items_offset+8])[0]
                
                if data_offset > 0 and data_offset < len(data) - 32:
                    field_name, field_value = self._read_data_object(data, data_offset)
                    if field_name:
                        fields[field_name] = field_value
                
                items_offset += 16
            except Exception:
                break
        
        return fields
    
    def _read_data_object(self, data: bytes, offset: int) -> Tuple[str, str]:
        """Read a DATA object and return field name and value."""
        try:
            # Check this is a DATA object (type 1)
            if offset + 64 > len(data):
                return None, None
            
            obj_type = data[offset]
            obj_flags = data[offset + 1]
            
            if obj_type != 1:  # Not a DATA object
                return None, None
            
            obj_size = struct.unpack('<Q', data[offset+8:offset+16])[0]
            
            if obj_size < 64 or obj_size > 10000000:
                return None, None
            
            # Data payload starts at offset 64 within DATA object
            payload_start = offset + 64
            payload_size = obj_size - 64
            
            if payload_start + payload_size > len(data):
                return None, None
            
            payload = data[payload_start:payload_start + min(payload_size, 100000)]
            
            # Check compression flags (bit 0 = XZ, bit 1 = LZ4)
            # Object flags are in byte 1 of the object header
            is_compressed_xz = bool(obj_flags & 1)
            is_compressed_lz4 = bool(obj_flags & 2)
            
            if is_compressed_lz4:
                payload = self._decompress_lz4(payload, payload_size)
                if payload is None:
                    return None, None
            elif is_compressed_xz:
                payload = self._decompress_xz(payload)
                if payload is None:
                    return None, None
            
            # Field format: NAME=VALUE
            try:
                text = payload.decode('utf-8', errors='replace')
                if '=' in text:
                    name, value = text.split('=', 1)
                    # Clean up null bytes and control chars
                    value = value.rstrip('\x00').replace('\x00', '')
                    return name, value
            except Exception:
                pass
            
            return None, None
        except Exception:
            return None, None
    
    def _decompress_lz4(self, compressed_data: bytes, uncompressed_size: int = 0) -> Optional[bytes]:
        """Decompress LZ4-compressed data from journal."""
        if not HAS_LZ4:
            self.stats["lz4_not_available"] = True
            return None
        
        try:
            # Journal uses LZ4 block format
            # First 8 bytes are the uncompressed size (little-endian)
            if len(compressed_data) < 8:
                return None
            
            # Try to get uncompressed size from the data itself
            stored_size = struct.unpack('<Q', compressed_data[:8])[0]
            actual_compressed = compressed_data[8:]
            
            if stored_size > 0 and stored_size < 10000000:
                try:
                    return lz4.block.decompress(actual_compressed, uncompressed_size=stored_size)
                except Exception:
                    pass
            
            # Try without size hint
            try:
                return lz4.block.decompress(actual_compressed, uncompressed_size=uncompressed_size * 10)
            except Exception:
                pass
            
            # Try raw data
            try:
                return lz4.block.decompress(compressed_data, uncompressed_size=uncompressed_size * 10)
            except Exception:
                pass
            
            return None
        except Exception:
            return None
    
    def _decompress_xz(self, compressed_data: bytes) -> Optional[bytes]:
        """Decompress XZ/LZMA-compressed data from journal."""
        try:
            # Journal XZ format: first 8 bytes are uncompressed size
            if len(compressed_data) < 8:
                return None
            
            actual_compressed = compressed_data[8:]
            
            # Try LZMA decompression
            try:
                return lzma.decompress(actual_compressed)
            except Exception:
                pass
            
            # Try raw data
            try:
                return lzma.decompress(compressed_data)
            except Exception:
                pass
            
            return None
        except Exception:
            return None
    
    def _scan_journal_for_entries(self, data: bytes, source_file: str) -> int:
        """
        Fallback method: scan journal data for recognizable patterns.
        This is less accurate but can extract some entries from corrupted or
        unusual journal files.
        """
        entries_parsed = 0
        
        # Look for common journal field patterns in the binary data
        patterns = [
            (b'MESSAGE=', b'MESSAGE'),
            (b'_HOSTNAME=', b'_HOSTNAME'),
            (b'SYSLOG_IDENTIFIER=', b'SYSLOG_IDENTIFIER'),
            (b'_SYSTEMD_UNIT=', b'_SYSTEMD_UNIT'),
        ]
        
        # Find MESSAGE= occurrences and try to extract entries
        message_pattern = b'MESSAGE='
        offset = 0
        
        while offset < len(data) - 100 and entries_parsed < 50000:
            idx = data.find(message_pattern, offset)
            if idx == -1:
                break
            
            # Try to extract a message
            msg_start = idx + len(message_pattern)
            msg_end = data.find(b'\x00', msg_start)
            if msg_end == -1 or msg_end - msg_start > 10000:
                msg_end = min(msg_start + 500, len(data))
            
            try:
                message = data[msg_start:msg_end].decode('utf-8', errors='replace')
                message = message.strip()
                
                if message and len(message) > 5:
                    # Try to find associated fields nearby
                    context_start = max(0, idx - 1000)
                    context_end = min(len(data), idx + 2000)
                    context = data[context_start:context_end]
                    
                    # Extract hostname
                    hostname = self._extract_field_from_context(context, b'_HOSTNAME=')
                    unit = self._extract_field_from_context(context, b'SYSLOG_IDENTIFIER=')
                    if not unit:
                        unit = self._extract_field_from_context(context, b'_SYSTEMD_UNIT=')
                    if not unit:
                        unit = self._extract_field_from_context(context, b'_COMM=')
                    
                    priority_str = self._extract_field_from_context(context, b'PRIORITY=')
                    priority = int(priority_str) if priority_str and priority_str.isdigit() else 6
                    
                    # Try multiple methods to get timestamp
                    timestamp = None
                    
                    # Method 1: Look for __REALTIME_TIMESTAMP text field (JSON exports)
                    ts_idx = context.find(b'__REALTIME_TIMESTAMP=')
                    if ts_idx != -1:
                        ts_start = ts_idx + len(b'__REALTIME_TIMESTAMP=')
                        ts_end = context.find(b'\x00', ts_start)
                        if ts_end != -1 and ts_end - ts_start < 20:
                            try:
                                ts_str = context[ts_start:ts_end].decode('utf-8', errors='replace')
                                ts_us = int(ts_str)
                                if 1000000000000 < ts_us < 2000000000000000:
                                    timestamp = datetime.utcfromtimestamp(ts_us / 1000000)
                            except:
                                pass
                    
                    # Method 2: Try to find binary timestamp near the message
                    # In binary journals, realtime is stored at offset 24 in entry objects
                    # Look backwards for a valid timestamp pattern
                    if not timestamp:
                        for back_offset in range(8, min(512, idx), 8):
                            check_pos = idx - back_offset
                            if check_pos >= 0 and check_pos + 8 <= len(data):
                                try:
                                    potential_ts = struct.unpack('<Q', data[check_pos:check_pos+8])[0]
                                    # Microseconds since epoch, should be between ~2010 and ~2030
                                    # 2010: 1262304000000000, 2030: 1893456000000000
                                    if 1262304000000000 < potential_ts < 1900000000000000:
                                        timestamp = datetime.utcfromtimestamp(potential_ts / 1000000)
                                        break
                                except:
                                    pass
                    
                    # Method 3: Extract epoch timestamp from message content
                    # Many log messages include timestamps like [1762301950.6998]
                    if not timestamp:
                        # Look for patterns like [1234567890.123] or (1234567890)
                        epoch_patterns = [
                            r'\[(\d{10})\.?\d*\]',      # [1762301950.6998]
                            r'\((\d{10})\.?\d*\)',      # (1762301950)
                            r'timestamp[=:]?\s*(\d{10})', # timestamp=1762301950
                        ]
                        for pattern in epoch_patterns:
                            match = re.search(pattern, message, re.IGNORECASE)
                            if match:
                                try:
                                    epoch_sec = int(match.group(1))
                                    # Sanity check: between 2010 and 2030
                                    if 1262304000 < epoch_sec < 1900000000:
                                        timestamp = datetime.utcfromtimestamp(epoch_sec)
                                        break
                                except:
                                    pass
                    
                    if not timestamp:
                        # Skip entries without valid timestamps for forensic accuracy
                        # Rather than assign an incorrect date, we exclude these entries
                        self.stats["entries_skipped_no_timestamp"] = self.stats.get("entries_skipped_no_timestamp", 0) + 1
                        offset = idx + 1
                        continue
                    
                    syslog_id = unit.split('[')[0] if unit else ''
                    category = self._categorize_entry(message, syslog_id)
                    priority_name = JournalEntry.PRIORITIES.get(priority, "INFO")
                    
                    entry = JournalEntry(
                        timestamp=timestamp,
                        hostname=hostname or '',
                        unit=unit or '',
                        priority=priority,
                        priority_name=priority_name,
                        message=message,
                        syslog_identifier=syslog_id,
                        source_file=source_file,
                        category=category
                    )
                    self.entries.append(entry)
                    entries_parsed += 1
                    
            except Exception:
                pass
            
            offset = idx + 1
        
        return entries_parsed
    
    def _extract_field_from_context(self, context: bytes, field_prefix: bytes) -> str:
        """Extract a field value from binary context."""
        idx = context.find(field_prefix)
        if idx == -1:
            return ''
        
        value_start = idx + len(field_prefix)
        value_end = context.find(b'\x00', value_start)
        if value_end == -1 or value_end - value_start > 500:
            value_end = min(value_start + 100, len(context))
        
        try:
            return context[value_start:value_end].decode('utf-8', errors='replace').strip()
        except:
            return ''
    
    def _parse_timestamp(self, ts_str: str, reference_date: datetime = None) -> Optional[datetime]:
        """
        Parse various timestamp formats.
        
        For syslog-style timestamps that don't include a year, uses the reference_date
        to infer the correct year. This is critical for forensic analysis where the
        evidence may be historical.
        
        Args:
            ts_str: Timestamp string to parse
            reference_date: Reference date for year inference. If None, uses self.reference_date
                           or falls back to datetime.now() (not recommended for forensics).
        
        Returns:
            datetime object or None
        """
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]
        
        # Handle short format (no year) - common in syslog
        short_match = re.match(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?:\.(\d+))?$', ts_str)
        if short_match:
            month_str, day, time_str, microsec = short_match.groups()
            months = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                     'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
            month = months.get(month_str, 1)
            
            # Determine reference date for year inference (use UTC)
            if reference_date is None:
                reference_date = self.reference_date if self.reference_date else datetime.utcnow()
            
            reference_year = reference_date.year
            
            try:
                timestamp = datetime.strptime(f"{reference_year}-{month:02d}-{int(day):02d} {time_str}", "%Y-%m-%d %H:%M:%S")
                if microsec:
                    timestamp = timestamp.replace(microsecond=int(microsec[:6].ljust(6, '0')))
                
                # Handle year rollover for forensic analysis:
                # If the parsed month is significantly ahead of the reference month,
                # it likely belongs to the previous year.
                months_difference = (timestamp.month - reference_date.month)
                if months_difference > 6:
                    timestamp = timestamp.replace(year=reference_year - 1)
                elif months_difference < -6:
                    timestamp = timestamp.replace(year=reference_year + 1)
                
                return timestamp
            except:
                pass
        
        # Try standard formats (these include year, so no inference needed)
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str.replace('Z', '+0000'), fmt)
                # Convert to naive datetime
                if dt.tzinfo:
                    dt = dt.replace(tzinfo=None)
                return dt
            except ValueError:
                continue
        
        return None
    
    def _guess_priority(self, message: str, unit: str) -> Tuple[int, str]:
        """Guess priority level from message content."""
        message_lower = message.lower()
        
        if any(w in message_lower for w in ['emerg', 'panic', 'fatal']):
            return 0, "EMERG"
        elif any(w in message_lower for w in ['alert']):
            return 1, "ALERT"
        elif any(w in message_lower for w in ['crit', 'critical']):
            return 2, "CRIT"
        elif any(w in message_lower for w in ['error', 'err:', 'failed', 'failure']):
            return 3, "ERR"
        elif any(w in message_lower for w in ['warn', 'warning']):
            return 4, "WARNING"
        elif any(w in message_lower for w in ['notice']):
            return 5, "NOTICE"
        elif unit.lower() in ['kernel', 'audit']:
            return 5, "NOTICE"
        else:
            return 6, "INFO"
    
    def _categorize_entry(self, message: str, unit: str) -> str:
        """Categorize journal entry based on content."""
        message_lower = message.lower()
        unit_lower = unit.lower()
        
        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    return category
                if re.search(pattern, unit, re.IGNORECASE):
                    return category
        
        # Check by unit name
        unit_base = unit_lower.split('[')[0].split('.')[0]
        if unit_base in SECURITY_UNITS:
            return "SECURITY_SERVICE"
        
        return "GENERAL"


# ============================================================================
# Journal Analyzer
# ============================================================================

class JournalAnalyzer:
    """Analyze parsed journal entries."""
    
    def __init__(self, entries: List[JournalEntry]):
        self.entries = entries
        self.summary = defaultdict(int)
        self.security_events = []
        self.timeline = []
    
    def analyze(self, verbose: bool = True) -> None:
        """Run analysis on journal entries."""
        if verbose:
            print(f"\n{Style.INFO}Analyzing {len(self.entries)} journal entries...{Style.RESET}", file=sys.stderr)
        
        for entry in self.entries:
            self.summary["total"] += 1
            self.summary[f"priority_{entry.priority_name}"] += 1
            self.summary[f"category_{entry.category}"] += 1
            
            # Flag security-relevant events
            if entry.category in ["AUTH_SUCCESS", "AUTH_FAILURE", "SUDO", "USER_MGMT", 
                                  "AUDIT", "SECURITY", "FIREWALL"]:
                self.security_events.append(entry)
                self.summary["security_events"] += 1
            
            # Flag high-priority events
            if entry.priority <= 3:  # ERR or higher
                self.summary["high_priority"] += 1
    
    def filter_entries(self, 
                      start_time: datetime = None,
                      end_time: datetime = None,
                      categories: Set[str] = None,
                      units: Set[str] = None,
                      min_priority: int = None,
                      keywords: List[str] = None,
                      security_only: bool = False) -> List[JournalEntry]:
        """Filter entries based on criteria."""
        filtered = []
        
        for entry in self.entries:
            # Time filter
            if start_time and entry.timestamp and entry.timestamp < start_time:
                continue
            if end_time and entry.timestamp and entry.timestamp > end_time:
                continue
            
            # Category filter
            if categories and entry.category not in categories:
                continue
            
            # Unit filter
            if units:
                unit_base = entry.unit.split('[')[0].split('.')[0].lower()
                if not any(u.lower() in unit_base or unit_base in u.lower() for u in units):
                    continue
            
            # Priority filter
            if min_priority is not None and entry.priority > min_priority:
                continue
            
            # Keyword filter
            if keywords:
                if not any(kw.lower() in entry.message.lower() for kw in keywords):
                    continue
            
            # Security filter
            if security_only and entry.category not in ["AUTH_SUCCESS", "AUTH_FAILURE", 
                                                        "SUDO", "USER_MGMT", "AUDIT", 
                                                        "SECURITY", "SSH"]:
                continue
            
            filtered.append(entry)
        
        return filtered
    
    def print_summary(self) -> None:
        """Print analysis summary."""
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Journal Analysis Summary{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
        
        print(f"\n{Style.INFO}Total Entries:{Style.RESET} {self.summary['total']}", file=sys.stderr)
        print(f"{Style.WARNING}Security Events:{Style.RESET} {self.summary['security_events']}", file=sys.stderr)
        print(f"{Style.ERROR}High Priority (ERR+):{Style.RESET} {self.summary['high_priority']}", file=sys.stderr)
        
        print(f"\n{Style.INFO}By Priority:{Style.RESET}", file=sys.stderr)
        for priority in ["EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"]:
            count = self.summary.get(f"priority_{priority}", 0)
            if count > 0:
                color = Style.CRITICAL if priority in ["EMERG", "ALERT", "CRIT"] else (
                        Style.ERROR if priority == "ERR" else (
                        Style.WARNING if priority == "WARNING" else Style.INFO))
                print(f"  {color}{priority}: {count}{Style.RESET}", file=sys.stderr)
        
        print(f"\n{Style.INFO}By Category:{Style.RESET}", file=sys.stderr)
        category_counts = [(k.replace("category_", ""), v) for k, v in self.summary.items() 
                          if k.startswith("category_") and v > 0]
        for cat, count in sorted(category_counts, key=lambda x: -x[1])[:15]:
            color = Style.WARNING if cat in ["AUTH_FAILURE", "SECURITY"] else Style.INFO
            print(f"  {color}{cat}: {count}{Style.RESET}", file=sys.stderr)


# ============================================================================
# Export Functions
# ============================================================================

def export_csv(entries: List[JournalEntry], output_path: str, max_message_length: int = None) -> None:
    """Export entries to CSV."""
    if not entries:
        print(f"{Style.WARNING}No entries to export{Style.RESET}", file=sys.stderr)
        return
    
    fieldnames = ["Timestamp", "Timestamp_Local", "Hostname", "Unit", "Priority", "Category", 
                  "User", "Source_IP", "PID", "UID", "Message", "Source_File"]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry.to_dict(max_message_length))
    
    print(f"{Style.SUCCESS}Exported {len(entries)} entries to:{Style.RESET} {output_path}", file=sys.stderr)


def export_security_report(entries: List[JournalEntry], output_path: str, max_message_length: int = None) -> None:
    """Export security-focused report."""
    security_categories = {"AUTH_SUCCESS", "AUTH_FAILURE", "SUDO", "USER_MGMT", 
                          "AUDIT", "SECURITY", "SSH", "FIREWALL"}
    
    security_entries = [e for e in entries if e.category in security_categories]
    
    if not security_entries:
        print(f"{Style.WARNING}No security events to export{Style.RESET}", file=sys.stderr)
        return
    
    export_csv(security_entries, output_path, max_message_length)


# ============================================================================
# Main Function
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Linux Journal Analyzer - Parse and analyze systemd journal logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

Examples:
  # Analyze a UAC tarball
  python linux_journal_analyzer.py -s hostname.tar.gz
  
  # Analyze with custom output
  python linux_journal_analyzer.py -s hostname.tar.gz -o ./results/
  
  # Filter for security events only
  python linux_journal_analyzer.py -s hostname.tar.gz --security
  
  # Filter by time range
  python linux_journal_analyzer.py -s hostname.tar.gz --since "2024-12-01" --until "2024-12-17"
  
  # Filter by unit
  python linux_journal_analyzer.py -s hostname.tar.gz --unit sshd,sudo
  
  # Filter by keyword
  python linux_journal_analyzer.py -s hostname.tar.gz --grep "failed password"
  
  # Filter by priority
  python linux_journal_analyzer.py -s hostname.tar.gz --priority err

Output:
  Creates CSV files named after the source hostname:
    <hostname>_journal.csv          - All journal entries
    <hostname>_journal_security.csv - Security-relevant events only

Supported Formats:
  - Text journalctl exports (default format)
  - JSON journalctl exports (-o json)
  - UAC tarball journal collections
        """
    )
    
    parser.add_argument('-s', '--source', help='Source: UAC tarball or directory')
    parser.add_argument('-o', '--output', help='Output directory (default: current)')
    parser.add_argument('--security', action='store_true', help='Export security events only')
    parser.add_argument('--since', help='Start time (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--until', help='End time (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--unit', help='Filter by unit(s), comma-separated')
    parser.add_argument('--priority', help='Minimum priority (emerg,alert,crit,err,warning,notice,info,debug)')
    parser.add_argument('--grep', help='Filter by keyword(s), comma-separated')
    parser.add_argument('--category', help='Filter by category, comma-separated')
    parser.add_argument('--max-message-length', type=int, default=DEFAULT_MAX_MESSAGE_LENGTH,
                       help=f'Max message length in CSV output (default: {DEFAULT_MAX_MESSAGE_LENGTH})')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress progress output')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    if not args.source:
        parser.print_help()
        return 1
    
    # Validate source
    if not os.path.exists(args.source):
        print(f"{Style.ERROR}Error: Source not found: {args.source}{Style.RESET}", file=sys.stderr)
        return 1
    
    output_dir = args.output or os.getcwd()
    os.makedirs(output_dir, exist_ok=True)
    
    verbose = not args.quiet
    
    try:
        # Initialize handler
        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}  Linux Journal Analyzer v{__version__}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"\n{Style.INFO}Source:{Style.RESET} {args.source}", file=sys.stderr)
        
        handler = UACHandler(args.source)
        hostname = handler.hostname
        
        if verbose:
            print(f"{Style.INFO}Hostname:{Style.RESET} {hostname}", file=sys.stderr)
            print(f"{Style.INFO}Mode:{Style.RESET} {'Tarball' if handler.is_tarball else 'Directory'}", file=sys.stderr)
        
        # Parse journal entries
        if verbose:
            print(f"\n{Style.INFO}Parsing journal entries...{Style.RESET}", file=sys.stderr)
        
        # Determine reference date for year inference on syslog-style timestamps
        # For forensic analysis, use file mtime rather than datetime.now()
        reference_date = None
        if os.path.isfile(args.source):
            try:
                mtime = os.path.getmtime(args.source)
                reference_date = datetime.utcfromtimestamp(mtime)
                if verbose:
                    print(f"{Style.INFO}Reference date (from file mtime, UTC):{Style.RESET} {reference_date.strftime('%Y-%m-%d')}", file=sys.stderr)
            except (OSError, ValueError):
                pass
        elif os.path.isdir(args.source):
            # For directories, try to get mtime from a log file within
            # Search recursively to handle nested UAC structures like [root]/var/log/
            log_patterns = ['syslog', 'messages', 'auth.log', 'journal']
            try:
                # First try direct paths
                for log_pattern in ['var/log/syslog', 'var/log/messages', 'var/log/auth.log']:
                    log_path = os.path.join(args.source, log_pattern)
                    if os.path.exists(log_path):
                        mtime = os.path.getmtime(log_path)
                        reference_date = datetime.utcfromtimestamp(mtime)
                        if verbose:
                            print(f"{Style.INFO}Reference date (from {log_pattern}, UTC):{Style.RESET} {reference_date.strftime('%Y-%m-%d')}", file=sys.stderr)
                        break
                
                # If not found, search recursively for var/log
                if reference_date is None:
                    for root, dirs, files in os.walk(args.source):
                        # Look for var/log directory
                        if 'var' in dirs:
                            var_log = os.path.join(root, 'var', 'log')
                            if os.path.isdir(var_log):
                                # Found var/log, get mtime from a log file
                                for log_name in log_patterns:
                                    log_path = os.path.join(var_log, log_name)
                                    if os.path.exists(log_path):
                                        mtime = os.path.getmtime(log_path)
                                        reference_date = datetime.utcfromtimestamp(mtime)
                                        rel_path = os.path.relpath(log_path, args.source)
                                        if verbose:
                                            print(f"{Style.INFO}Reference date (from {rel_path}):{Style.RESET} {reference_date.strftime('%Y-%m-%d')}", file=sys.stderr)
                                        break
                                if reference_date:
                                    break
                        if reference_date:
                            break
            except (OSError, ValueError):
                pass
        
        if reference_date is None:
            reference_date = datetime.utcnow()
            if verbose:
                print(f"{Style.WARNING}Reference date (using current UTC - may be inaccurate):{Style.RESET} {reference_date.strftime('%Y-%m-%d')}", file=sys.stderr)
        
        parser_obj = JournalParser(handler, reference_date=reference_date)
        entries = parser_obj.parse_all()
        
        if verbose:
            print(f"  Found {len(entries)} entries", file=sys.stderr)
            
            # Report on binary journal parsing
            if parser_obj.stats.get("binary_journals", 0) > 0:
                binary_count = parser_obj.stats.get("binary_journals", 0)
                binary_entries = parser_obj.stats.get("binary_entries", 0)
                print(f"  Binary journals found: {binary_count}", file=sys.stderr)
                print(f"  Entries from binary: {binary_entries}", file=sys.stderr)
            
            if parser_obj.stats.get("entries_skipped_no_timestamp", 0) > 0:
                skipped = parser_obj.stats.get("entries_skipped_no_timestamp", 0)
                print(f"  {Style.WARNING}Skipped {skipped} entries without extractable timestamps{Style.RESET}", file=sys.stderr)
            
            if parser_obj.stats.get("binary_needs_export"):
                print(f"\n{Style.WARNING}Note: Some binary journals could not be fully parsed.{Style.RESET}", file=sys.stderr)
                if parser_obj.stats.get("lz4_not_available"):
                    print(f"  {Style.ERROR}LZ4 compression detected but lz4 library not installed!{Style.RESET}", file=sys.stderr)
                    print(f"  Install with: pip install lz4", file=sys.stderr)
                print(f"  For more complete data, export on the source system:", file=sys.stderr)
                print(f"  journalctl --no-pager -o json > journal_export.json", file=sys.stderr)
            
            if not HAS_LZ4 and parser_obj.stats.get("binary_journals", 0) > 0:
                print(f"\n{Style.INFO}Tip: Install lz4 for better binary journal parsing:{Style.RESET}", file=sys.stderr)
                print(f"  pip install lz4", file=sys.stderr)
        
        if not entries:
            print(f"\n{Style.WARNING}No journal entries found{Style.RESET}", file=sys.stderr)
            handler.close()
            return 0
        
        # Analyze
        analyzer = JournalAnalyzer(entries)
        analyzer.analyze(verbose)
        
        # Apply filters
        filtered_entries = entries
        
        # Time filters
        start_time = None
        end_time = None
        if args.since:
            try:
                start_time = datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S") if ' ' in args.since else datetime.strptime(args.since, "%Y-%m-%d")
            except ValueError:
                print(f"{Style.WARNING}Invalid --since format, using all entries{Style.RESET}", file=sys.stderr)
        
        if args.until:
            try:
                end_time = datetime.strptime(args.until, "%Y-%m-%d %H:%M:%S") if ' ' in args.until else datetime.strptime(args.until, "%Y-%m-%d") + timedelta(days=1)
            except ValueError:
                print(f"{Style.WARNING}Invalid --until format, using all entries{Style.RESET}", file=sys.stderr)
        
        # Unit filter
        units = set(args.unit.split(',')) if args.unit else None
        
        # Priority filter
        priority_map = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
        min_priority = priority_map.get(args.priority.lower()) if args.priority else None
        
        # Keyword filter
        keywords = args.grep.split(',') if args.grep else None
        
        # Category filter
        categories = set(args.category.upper().split(',')) if args.category else None
        
        # Apply all filters
        if any([start_time, end_time, units, min_priority is not None, keywords, categories, args.security]):
            filtered_entries = analyzer.filter_entries(
                start_time=start_time,
                end_time=end_time,
                units=units,
                min_priority=min_priority,
                keywords=keywords,
                categories=categories,
                security_only=args.security
            )
            if verbose:
                print(f"\n{Style.INFO}Filtered to {len(filtered_entries)} entries{Style.RESET}", file=sys.stderr)
        
        # Print summary
        if verbose:
            analyzer.print_summary()
        
        # Export
        max_msg_len = args.max_message_length
        if args.security:
            output_path = os.path.join(output_dir, f"{hostname}_journal_security.csv")
            export_csv(filtered_entries, output_path, max_msg_len)
        else:
            # Export all
            all_path = os.path.join(output_dir, f"{hostname}_journal.csv")
            export_csv(filtered_entries, all_path, max_msg_len)
            
            # Also export security events
            sec_path = os.path.join(output_dir, f"{hostname}_journal_security.csv")
            export_security_report(entries, sec_path, max_msg_len)
        
        handler.close()
        
        if verbose:
            print(f"\n{Style.SUCCESS}Analysis complete!{Style.RESET}", file=sys.stderr)
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Interrupted{Style.RESET}", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\n{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

