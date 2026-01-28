#!/usr/bin/env python3
"""
Linux Login/Lateral Movement Timeline Extractor

Parses various Linux authentication and login log files to create a 
unified timeline CSV for forensic analysis.

Supports:
- UAC (Unix-like Artifacts Collector) triage tarballs (.tar, .tar.gz)
- Extracted UAC directories
- Live system analysis
- Mounted disk images

Supported log files:
- /var/log/btmp* (Failed Logins) - binary
- /var/log/utmp (Current/last Login) - binary  
- /var/log/wtmp* (Logins and reboots) - binary
- /var/log/lastlog (Last login for each user) - binary
- /var/log/auth.log* (Authentication logs - Debian/Ubuntu)
- /var/log/secure* (Authentication logs - RHEL/CentOS)
- /var/log/audit/audit.log* (Audit logs)
- /var/log/messages* (Default syslog messages)
- /var/log/syslog* (System messages)

Handles .gz compressed versions automatically.

Requirements: Python 3.6+ (standard library only, no pip install needed)
"""

__version__ = "1.0.0"
__author__ = "Forensics Team"

import os
import sys
import csv
import gzip
import struct
import re
import argparse
import tarfile
import tempfile
import shutil
import io
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Generator, Any, Union
import glob


def resolve_path(path: str) -> str:
    """
    Resolve a path to an absolute path.
    
    Handles:
    - Relative paths (resolved from current working directory)
    - Home directory expansion (~)
    - Environment variables
    - Absolute paths (returned as-is)
    
    Args:
        path: Input path string
        
    Returns:
        Absolute path string
    """
    # Expand ~ and environment variables
    expanded = os.path.expanduser(os.path.expandvars(path))
    
    # Convert to absolute path
    absolute = os.path.abspath(expanded)
    
    return absolute


def is_safe_path(base_path: str, target_path: str) -> bool:
    """
    OWASP A03/A08: Validate that target_path is within base_path.
    Prevents path traversal attacks (zip slip, tar slip).
    
    Args:
        base_path: The allowed base directory
        target_path: The path to validate
        
    Returns:
        True if target_path is safely within base_path
    """
    # Resolve both paths to absolute paths
    base = os.path.abspath(base_path)
    target = os.path.abspath(target_path)
    
    # Ensure the target starts with the base path
    # Use os.path.commonpath for cross-platform safety
    try:
        common = os.path.commonpath([base, target])
        return common == base
    except ValueError:
        # On Windows, paths on different drives raise ValueError
        return False


def safe_extract_member(tar: tarfile.TarFile, member: tarfile.TarInfo, dest_dir: str) -> Optional[str]:
    """
    OWASP A08: Safely extract a tar member, preventing tar slip attacks.
    
    Args:
        tar: Open tarfile object
        member: Member to extract
        dest_dir: Destination directory
        
    Returns:
        Path to extracted file or None if unsafe
    """
    # Get the intended extraction path
    member_path = os.path.join(dest_dir, member.name)
    abs_dest = os.path.abspath(dest_dir)
    abs_member = os.path.abspath(member_path)
    
    # Validate the path stays within destination
    if not is_safe_path(abs_dest, abs_member):
        raise ValueError(f"Attempted path traversal in tar: {member.name}")
    
    # Check for suspicious member attributes
    if member.issym() or member.islnk():
        # Skip symbolic links to prevent symlink attacks
        return None
    
    tar.extract(member, dest_dir)
    return member_path


# ============================================================================
# CONSOLE STYLING (matches uac_extractor.py style)
# ============================================================================

class Style:
    """ANSI color codes for terminal output."""
    
    ENABLED = sys.stdout.isatty()
    
    RESET = '\033[0m' if ENABLED else ''
    BOLD = '\033[1m' if ENABLED else ''
    DIM = '\033[2m' if ENABLED else ''
    
    RED = '\033[91m' if ENABLED else ''
    GREEN = '\033[92m' if ENABLED else ''
    YELLOW = '\033[93m' if ENABLED else ''
    BLUE = '\033[94m' if ENABLED else ''
    MAGENTA = '\033[95m' if ENABLED else ''
    CYAN = '\033[96m' if ENABLED else ''
    
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN
    HEADER = MAGENTA

    @classmethod
    def enable_windows_ansi(cls):
        """Enable ANSI escape sequences on Windows."""
        if os.name == 'nt':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                cls.ENABLED = True
            except (AttributeError, OSError, ValueError):
                # OWASP A05: Specify exception types instead of bare except
                pass


# ============================================================================
# UAC TARBALL HANDLER
# ============================================================================

class UACTarballHandler:
    """
    Handles reading files from UAC (Unix-like Artifacts Collector) tarballs.
    
    UAC creates tarballs with various directory structures:
    - <hostname>/<date>/var/log/...
    - <hostname>/collected/var/log/...
    - var/log/...
    - live_response/...
    
    This class auto-detects the structure and provides unified access.
    """
    
    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')
    
    def __init__(self, tarball_path: str, verbose: bool = True):
        """
        Initialize the tarball handler.
        
        Args:
            tarball_path: Path to the UAC tarball
            verbose: Print progress information
        """
        self.tarball_path = tarball_path
        self.verbose = verbose
        self.tar = None
        self.var_log_prefix = None
        self.hostname = None
        self.temp_dir = None
        self._members_cache = None
        
    def __enter__(self):
        self.open()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        
    def open(self):
        """Open the tarball and detect structure."""
        if self.verbose:
            print(f"{Style.INFO}Opening UAC tarball:{Style.RESET} {self.tarball_path}", file=sys.stderr)
        
        # Determine compression mode
        mode = "r:*"  # Auto-detect compression
        
        try:
            self.tar = tarfile.open(self.tarball_path, mode)
        except tarfile.ReadError:
            # Try uncompressed
            self.tar = tarfile.open(self.tarball_path, "r:")
        
        # Cache member list for efficiency
        self._members_cache = self.tar.getmembers()
        
        # Detect UAC structure
        self._detect_structure()
        
        if self.verbose:
            print(f"{Style.SUCCESS}Detected var/log at:{Style.RESET} {self.var_log_prefix or 'root'}", file=sys.stderr)
            if self.hostname:
                print(f"{Style.INFO}Hostname:{Style.RESET} {self.hostname}", file=sys.stderr)
    
    def close(self):
        """Close the tarball and cleanup."""
        if self.tar:
            self.tar.close()
            self.tar = None
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _detect_structure(self):
        """
        Detect the directory structure inside the UAC tarball.
        
        Looks for var/log directory to determine the prefix path.
        """
        var_log_patterns = [
            # Direct paths
            "var/log/",
            # UAC standard patterns
            r".*/var/log/",
            r".*/collected/var/log/",
            r".*/live_response/.*",
        ]
        
        # Get all member names
        member_names = [m.name for m in self._members_cache]
        
        # Find var/log path
        for name in member_names:
            # Normalize path separators
            normalized = name.replace("\\", "/")
            
            # Check for var/log
            if "/var/log/" in normalized or normalized.startswith("var/log/"):
                # Extract the prefix before var/log
                idx = normalized.find("var/log/")
                self.var_log_prefix = normalized[:idx] if idx > 0 else ""
                
                # Try to extract hostname from path
                if self.var_log_prefix:
                    parts = self.var_log_prefix.strip("/").split("/")
                    if parts:
                        self.hostname = parts[0]
                break
        
        # If var/log not found, check for common UAC artifacts
        if self.var_log_prefix is None:
            for name in member_names:
                normalized = name.replace("\\", "/")
                # Look for any log files that indicate structure
                if "auth.log" in normalized or "secure" in normalized or "wtmp" in normalized:
                    # Found a log file, extract its path prefix
                    parts = normalized.split("/")
                    if "log" in parts:
                        log_idx = parts.index("log")
                        if log_idx >= 1 and parts[log_idx - 1] == "var":
                            self.var_log_prefix = "/".join(parts[:log_idx - 1])
                            if self.var_log_prefix:
                                self.var_log_prefix += "/"
                            break
            
            # Default to empty prefix if still not found
            if self.var_log_prefix is None:
                self.var_log_prefix = ""
    
    def get_var_log_path(self, relative_path: str) -> str:
        """
        Get the full path within the tarball for a var/log relative path.
        
        Args:
            relative_path: Path relative to var/log (e.g., "auth.log")
            
        Returns:
            Full path within tarball
        """
        return f"{self.var_log_prefix}var/log/{relative_path}"
    
    def list_log_files(self, pattern: str = "") -> List[str]:
        """
        List all log files matching a pattern.
        
        Args:
            pattern: Optional pattern to filter files (e.g., "auth.log")
            
        Returns:
            List of full paths within tarball
        """
        matches = []
        var_log_path = f"{self.var_log_prefix}var/log/"
        
        for member in self._members_cache:
            name = member.name.replace("\\", "/")
            if name.startswith(var_log_path) or f"/var/log/" in name:
                if not pattern or pattern in os.path.basename(name):
                    if not member.isdir():
                        matches.append(name)
        
        return sorted(matches)
    
    def find_log_files(self, base_pattern: str) -> List[str]:
        """
        Find all log files matching a base pattern (including rotated/gzipped).
        
        Args:
            base_pattern: Base filename pattern (e.g., "auth.log", "wtmp")
            
        Returns:
            List of matching file paths
        """
        matches = []
        var_log_path = f"{self.var_log_prefix}var/log/"
        
        for member in self._members_cache:
            if member.isdir():
                continue
                
            name = member.name.replace("\\", "/")
            basename = os.path.basename(name)
            
            # Check if this is in var/log (or a subdirectory)
            if var_log_path in name or "/var/log/" in name:
                # Match base pattern (including rotated versions)
                if basename == base_pattern or basename.startswith(f"{base_pattern}."):
                    matches.append(name)
        
        return sorted(matches)
    
    def find_audit_logs(self) -> List[str]:
        """Find all audit log files."""
        matches = []
        
        for member in self._members_cache:
            if member.isdir():
                continue
            
            name = member.name.replace("\\", "/")
            
            # Look for audit logs in various locations
            if "/audit/audit.log" in name or name.endswith("/audit.log"):
                matches.append(name)
            elif "/audit/audit.log." in name:
                matches.append(name)
        
        return sorted(matches)
    
    def extract_file(self, member_path: str) -> Optional[bytes]:
        """
        Extract a file's contents from the tarball.
        
        Args:
            member_path: Path within the tarball
            
        Returns:
            File contents as bytes, or None if not found
        """
        try:
            # Handle .gz files within the tarball
            member = self.tar.getmember(member_path)
            f = self.tar.extractfile(member)
            if f:
                data = f.read()
                f.close()
                
                # If the file is gzipped, decompress it
                if member_path.endswith('.gz'):
                    try:
                        data = gzip.decompress(data)
                    except gzip.BadGzipFile:
                        pass  # Not actually gzipped, use raw data
                
                return data
        except KeyError:
            pass
        except Exception as e:
            if self.verbose:
                print(f"{Style.WARNING}Warning: Could not extract {member_path}: {e}{Style.RESET}", file=sys.stderr)
        
        return None
    
    def extract_file_to_temp(self, member_path: str) -> Optional[str]:
        """
        Extract a file to a temporary location.
        
        OWASP A08: Uses safe extraction to prevent tar slip attacks.
        
        Args:
            member_path: Path within the tarball
            
        Returns:
            Path to extracted file, or None if failed
        """
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="uac_timeline_")
        
        try:
            member = self.tar.getmember(member_path)
            
            # OWASP A08: Safe extraction with path validation
            extracted_path = safe_extract_member(self.tar, member, self.temp_dir)
            return extracted_path
            
        except ValueError as e:
            # Path traversal attempt detected
            if self.verbose:
                print(f"{Style.ERROR}Security: Blocked path traversal attempt: {member_path}{Style.RESET}", file=sys.stderr)
        except (KeyError, tarfile.TarError, OSError) as e:
            if self.verbose:
                print(f"{Style.WARNING}Warning: Could not extract {member_path}: {e}{Style.RESET}", file=sys.stderr)
        
        return None
    
    def get_file_handle(self, member_path: str, binary: bool = False) -> Optional[io.IOBase]:
        """
        Get a file-like object for reading a file from the tarball.
        
        Args:
            member_path: Path within the tarball
            binary: Whether to return binary mode
            
        Returns:
            File-like object or None
        """
        data = self.extract_file(member_path)
        if data is None:
            return None
        
        if binary:
            return io.BytesIO(data)
        else:
            return io.StringIO(data.decode('utf-8', errors='replace'))

    @staticmethod
    def is_tarball(path: str) -> bool:
        """Check if a path is a UAC tarball."""
        lower_path = path.lower()
        return any(lower_path.endswith(ext) for ext in UACTarballHandler.TAR_EXTENSIONS)


# ============================================================================
# UTMP/WTMP/BTMP Binary Structure Definitions
# ============================================================================

# Linux utmp record types
UTMP_TYPES = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING"
}

# utmp structure for Linux (x86_64)
# struct utmp {
#     short   ut_type;              /* Type of record */
#     pid_t   ut_pid;               /* PID of login process */
#     char    ut_line[UT_LINESIZE]; /* Device name of tty - "/dev/" */
#     char    ut_id[4];             /* Terminal name suffix, or inittab(5) ID */
#     char    ut_user[UT_NAMESIZE]; /* Username */
#     char    ut_host[UT_HOSTSIZE]; /* Hostname for remote login */
#     struct  exit_status ut_exit;  /* Exit status of a process marked as DEAD_PROCESS */
#     int32_t ut_session;           /* Session ID */
#     struct timeval ut_tv;         /* Time entry was made */
#     int32_t ut_addr_v6[4];        /* Internet address of remote host */
#     char __unused[20];            /* Reserved for future use */
# };

# Linux x86_64 utmp structure size and format
UTMP_STRUCT_SIZE = 384
UTMP_STRUCT_FORMAT = (
    "h"      # ut_type (short, 2 bytes)
    "h"      # padding (2 bytes)
    "i"      # ut_pid (int, 4 bytes)
    "32s"    # ut_line (char[32])
    "4s"     # ut_id (char[4])
    "32s"    # ut_user (char[32])
    "256s"   # ut_host (char[256])
    "h"      # ut_exit.e_termination (short)
    "h"      # ut_exit.e_exit (short)
    "i"      # ut_session (int32_t)
    "i"      # ut_tv.tv_sec (int32_t)
    "i"      # ut_tv.tv_usec (int32_t)
    "4i"     # ut_addr_v6 (int32_t[4])
    "20s"    # __unused (char[20])
)

# lastlog structure
# struct lastlog {
#     int32_t ll_time;
#     char    ll_line[UT_LINESIZE];
#     char    ll_host[UT_HOSTSIZE];
# };
LASTLOG_STRUCT_SIZE = 292
LASTLOG_STRUCT_FORMAT = "i32s256s"


# ============================================================================
# Event Class for Timeline Entries
# ============================================================================

class TimelineEvent:
    """Represents a single event in the timeline."""
    
    def __init__(
        self,
        timestamp: datetime,
        event_type: str,
        source_file: str,
        username: str = "",
        source_ip: str = "",
        terminal: str = "",
        pid: int = 0,
        description: str = "",
        raw_data: str = ""
    ):
        self.timestamp = timestamp
        self.event_type = event_type
        self.source_file = source_file
        self.username = username
        self.source_ip = source_ip
        self.terminal = terminal
        self.pid = pid
        self.description = description
        self.raw_data = raw_data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for CSV output."""
        # Calculate local timestamp from UTC
        # Note: Timestamp is stored in UTC, Timestamp_Local is analysis machine's local time
        timestamp_utc = ""
        timestamp_local = ""
        if self.timestamp:
            timestamp_utc = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            # Convert UTC to local time for reference
            try:
                from datetime import timezone
                # Create UTC-aware datetime, then convert to local
                utc_aware = self.timestamp.replace(tzinfo=timezone.utc)
                local_dt = utc_aware.astimezone()  # Converts to local timezone
                timestamp_local = local_dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp_local = timestamp_utc  # Fallback to UTC if conversion fails
        
        return {
            "Timestamp": timestamp_utc,
            "Timestamp_Local": timestamp_local,
            "event_type": self.event_type,
            "username": self.username,
            "source_ip": self.source_ip,
            "terminal": self.terminal,
            "pid": str(self.pid) if self.pid else "",
            "description": self.description,
            "source_file": self.source_file,
            "raw_data": self.raw_data[:500] if self.raw_data else ""  # Truncate raw data
        }


# ============================================================================
# File Handling Utilities
# ============================================================================

def open_file(filepath: str, binary: bool = False, data: bytes = None):
    """
    Open a file, handling .gz compression automatically.
    
    Args:
        filepath: Path to the file
        binary: Whether to open in binary mode
        data: Optional raw data (if reading from tarball)
        
    Returns:
        File handle
    """
    # If raw data is provided (from tarball extraction)
    if data is not None:
        # Decompress if gzipped
        if filepath.endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except gzip.BadGzipFile:
                pass  # Not actually gzipped
        
        if binary:
            return io.BytesIO(data)
        else:
            return io.StringIO(data.decode('utf-8', errors='replace'))
    
    # Standard file open
    mode = "rb" if binary else "rt"
    
    if filepath.endswith(".gz"):
        return gzip.open(filepath, mode, encoding=None if binary else "utf-8", errors="replace")
    else:
        if binary:
            return open(filepath, mode)
        else:
            return open(filepath, mode, encoding="utf-8", errors="replace")


def find_log_files(base_path: str, pattern: str) -> List[str]:
    """
    Find all log files matching a pattern, including rotated and gzipped versions.
    
    Handles paths with special glob characters like [root] by using glob.escape().
    
    Args:
        base_path: Base directory to search
        pattern: File pattern (e.g., "auth.log")
        
    Returns:
        List of matching file paths
    """
    files = []
    
    # Use glob.escape() to handle special characters in base path (like [root])
    # This was added in Python 3.4
    escaped_base = glob.escape(base_path)
    
    # Search for exact match
    search_pattern = os.path.join(escaped_base, pattern)
    files.extend(glob.glob(search_pattern))
    
    # Also look for rotated versions (e.g., auth.log.1, auth.log.2.gz)
    search_pattern_rotated = os.path.join(escaped_base, f"{pattern}.*")
    files.extend(glob.glob(search_pattern_rotated))
    
    # Also look for numbered versions with glob pattern
    search_pattern_numbered = os.path.join(escaped_base, f"{pattern}.[0-9]*")
    files.extend(glob.glob(search_pattern_numbered))
    
    # If glob didn't work (can happen on some systems), fall back to os.listdir
    if not files and os.path.isdir(base_path):
        try:
            for filename in os.listdir(base_path):
                if filename == pattern or filename.startswith(f"{pattern}."):
                    files.append(os.path.join(base_path, filename))
        except OSError:
            pass
    
    # Remove duplicates and sort
    files = sorted(set(files))
    
    return files


def decode_string(data: bytes) -> str:
    """Decode a null-terminated string from bytes."""
    try:
        # Find null terminator
        null_pos = data.find(b'\x00')
        if null_pos != -1:
            data = data[:null_pos]
        return data.decode('utf-8', errors='replace').strip()
    except Exception:
        return ""


# Valid username pattern: Linux usernames are typically alphanumeric with underscores/hyphens
# Max 32 chars, must start with letter or underscore (not hyphen or digit for most systems)
VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$')

# Valid IPv4 pattern: Must have 4 octets separated by dots
VALID_IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# Valid IPv6 pattern: Simplified - must have at least 2 colons and hex digits
VALID_IPV6_PATTERN = re.compile(
    r'^[a-fA-F0-9:]+$'
)


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip_str: Potential IP address string
        
    Returns:
        True if it looks like a valid IP address
    """
    if not ip_str:
        return False
    
    # Must be at least 7 chars for shortest IPv4 (1.1.1.1)
    if len(ip_str) < 7:
        return False
    
    # Check IPv4
    if '.' in ip_str:
        # Must have exactly 3 dots for IPv4
        if ip_str.count('.') != 3:
            return False
        return bool(VALID_IPV4_PATTERN.match(ip_str))
    
    # Check IPv6
    if ':' in ip_str:
        # Must have at least 2 colons for valid IPv6
        if ip_str.count(':') < 2:
            return False
        # Simple validation - proper hex chars and colons only
        return bool(VALID_IPV6_PATTERN.match(ip_str)) and len(ip_str) >= 3
    
    return False


def extract_ip_from_message(message: str) -> str:
    """
    Extract a valid IP address from a log message.
    
    Args:
        message: Log message to search
        
    Returns:
        Valid IP address or empty string
    """
    # Try to find IPv4 addresses first (more common in logs)
    ipv4_pattern = re.compile(
        r'(?:from|addr[= ]|address[= ]|src[= ]|source[= ]|client[= ])\s*'
        r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',
        re.IGNORECASE
    )
    match = ipv4_pattern.search(message)
    if match:
        return match.group(1)
    
    # Try standalone IPv4 (less reliable but useful)
    standalone_ipv4 = re.compile(
        r'\b((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b'
    )
    match = standalone_ipv4.search(message)
    if match:
        return match.group(1)
    
    # Try IPv6 with prefix
    ipv6_pattern = re.compile(
        r'(?:from|addr[= ]|address[= ]|src[= ]|source[= ])\s*'
        r'([a-fA-F0-9:]{7,})',  # At least 7 chars (e.g., ::1 is 3, but realistic ones are longer)
        re.IGNORECASE
    )
    match = ipv6_pattern.search(message)
    if match:
        candidate = match.group(1)
        if is_valid_ip(candidate):
            return candidate
    
    return ""

# Words that look like usernames but are actually log message fragments
INVALID_USERNAME_WORDS = frozenset([
    # Common log message words that get incorrectly captured
    'runtime', 'manager', 'message', 'slice', 'target', 'methods',
    'session', 'service', 'system', 'scope', 'socket', 'mount', 'path',
    'device', 'timer', 'swap', 'snapshot', 'automount',
    # Systemd-related
    'systemd', 'logind', 'journald', 'udevd', 'networkd', 'resolved',
    'timesyncd', 'tmpfiles', 'sysusers', 'modules', 'generators',
    # Command words/fragments
    'command', 'continued', 'starting', 'started', 'stopping', 'stopped',
    'failed', 'success', 'error', 'warning', 'info', 'debug', 'notice',
    'reached', 'listening', 'running', 'exited', 'killed', 'finished',
    # Common false positives
    'the', 'for', 'from', 'with', 'and', 'not', 'was', 'has', 'had',
    'new', 'old', 'all', 'any', 'none', 'null', 'true', 'false',
    # Networking terms
    'port', 'address', 'connection', 'connected', 'disconnected',
    'accepted', 'rejected', 'denied', 'allowed', 'blocked',
])


def is_valid_username(username: str) -> bool:
    """
    Check if a string looks like a valid Linux username.
    
    This helps filter out false positives from log parsing where
    command arguments or log message words are incorrectly captured.
    
    Args:
        username: Potential username string
        
    Returns:
        True if it looks like a valid username
    """
    if not username:
        return False
    
    # Strip common trailing punctuation from log parsing
    username = username.rstrip(',:;)>]}"\'')
    
    if not username:
        return False
    
    # Reject if it starts with a dash (command flag like -o, --help)
    if username.startswith('-'):
        return False
    
    # Reject if it starts with a slash (path)
    if username.startswith('/'):
        return False
    
    # Reject if it starts with a digit (unlikely username, probably a number)
    if username[0].isdigit():
        return False
    
    # Reject if it contains path separators
    if '/' in username or '\\' in username:
        return False
    
    # Reject if it contains equals (likely key=value)
    if '=' in username:
        return False
    
    # Reject if it contains parentheses or brackets
    if any(c in username for c in '()[]{}'):
        return False
    
    # Reject known non-username words (case-insensitive)
    if username.lower() in INVALID_USERNAME_WORDS:
        return False
    
    # Reject if too long (Linux max is 32)
    if len(username) > 32:
        return False
    
    # Reject if too short and not a common short username
    if len(username) == 1 and username.lower() not in ('r', 's', 'u'):  # rare but possible
        return False
    
    # Check against valid username pattern
    if not VALID_USERNAME_PATTERN.match(username):
        return False
    
    return True


def sanitize_username(username: str) -> str:
    """
    Clean and validate a username extracted from logs.
    
    Args:
        username: Raw extracted username
        
    Returns:
        Cleaned username if valid, empty string otherwise
    """
    if not username:
        return ""
    
    # Strip common trailing punctuation
    cleaned = username.rstrip(',:;)>]}"\'')
    
    # Validate
    if is_valid_username(cleaned):
        return cleaned
    
    return ""


def ip_from_int(addr: int) -> str:
    """Convert integer IP address to dotted notation."""
    if addr == 0:
        return ""
    try:
        return f"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"
    except Exception:
        return ""


# ============================================================================
# Binary Log Parsers (utmp, wtmp, btmp, lastlog)
# ============================================================================

def parse_utmp_record(data: bytes) -> Optional[Dict]:
    """
    Parse a single utmp/wtmp/btmp record.
    
    Args:
        data: Raw bytes of the record
        
    Returns:
        Dictionary with parsed fields or None if invalid
    """
    if len(data) < UTMP_STRUCT_SIZE:
        return None
    
    try:
        unpacked = struct.unpack(UTMP_STRUCT_FORMAT, data[:UTMP_STRUCT_SIZE])
        
        ut_type = unpacked[0]
        ut_pid = unpacked[2]
        ut_line = decode_string(unpacked[3])
        ut_id = decode_string(unpacked[4])
        ut_user = decode_string(unpacked[5])
        ut_host = decode_string(unpacked[6])
        ut_exit_term = unpacked[7]
        ut_exit_exit = unpacked[8]
        ut_session = unpacked[9]
        ut_tv_sec = unpacked[10]
        ut_tv_usec = unpacked[11]
        ut_addr_v6 = unpacked[12:16]
        
        # Get IP address
        if ut_addr_v6[0] != 0:
            source_ip = ip_from_int(ut_addr_v6[0])
        else:
            source_ip = ut_host if ut_host and not ut_host.startswith(":") else ""
        
        # Convert timestamp to UTC (ensure offset-naive for comparability)
        # Use utcfromtimestamp to avoid local timezone conversion
        try:
            timestamp = datetime.utcfromtimestamp(ut_tv_sec) if ut_tv_sec > 0 else None
        except (OSError, ValueError, OverflowError):
            timestamp = None
        
        return {
            "type": ut_type,
            "type_name": UTMP_TYPES.get(ut_type, f"UNKNOWN({ut_type})"),
            "pid": ut_pid,
            "line": ut_line,
            "id": ut_id,
            "user": ut_user,
            "host": ut_host,
            "source_ip": source_ip,
            "exit_status": ut_exit_exit,
            "session": ut_session,
            "timestamp": timestamp
        }
    except struct.error:
        return None


def parse_utmp_file(filepath: str, log_type: str = "utmp", data: bytes = None) -> List[TimelineEvent]:
    """
    Parse utmp/wtmp/btmp binary file.
    
    Args:
        filepath: Path to the binary file
        log_type: Type of log (utmp, wtmp, btmp)
        data: Optional raw data (if reading from tarball)
        
    Returns:
        List of TimelineEvent objects
    """
    events = []
    
    try:
        with open_file(filepath, binary=True, data=data) as f:
            while True:
                data = f.read(UTMP_STRUCT_SIZE)
                if not data or len(data) < UTMP_STRUCT_SIZE:
                    break
                
                record = parse_utmp_record(data)
                if not record or not record["timestamp"]:
                    continue
                
                # Filter based on record type and log type
                ut_type = record["type"]
                
                # Determine event type and description based on record type
                if ut_type == 7:  # USER_PROCESS (login)
                    if log_type == "btmp":
                        event_type = "FAILED_LOGIN"
                        description = f"Failed login attempt for user '{record['user']}' from {record['host'] or 'local'}"
                    else:
                        event_type = "USER_LOGIN"
                        description = f"User '{record['user']}' logged in on {record['line']}"
                        if record['host']:
                            description += f" from {record['host']}"
                
                elif ut_type == 8:  # DEAD_PROCESS (logout)
                    event_type = "USER_LOGOUT"
                    description = f"Session ended on {record['line']}"
                
                elif ut_type == 2:  # BOOT_TIME
                    event_type = "SYSTEM_BOOT"
                    description = "System boot"
                
                elif ut_type == 1:  # RUN_LVL
                    event_type = "RUNLEVEL_CHANGE"
                    description = f"Runlevel change to '{record['user']}'"
                
                elif ut_type == 6:  # LOGIN_PROCESS
                    event_type = "LOGIN_PROCESS"
                    description = f"Login process on {record['line']}"
                
                else:
                    # Skip other record types
                    continue
                
                event = TimelineEvent(
                    timestamp=record["timestamp"],
                    event_type=event_type,
                    source_file=filepath,
                    username=record["user"],
                    source_ip=record["source_ip"],
                    terminal=record["line"],
                    pid=record["pid"],
                    description=description
                )
                events.append(event)
                
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)
    
    return events


def parse_lastlog(filepath: str, data: bytes = None, passwd_data: bytes = None) -> List[TimelineEvent]:
    """
    Parse lastlog binary file.
    
    Args:
        filepath: Path to lastlog file
        data: Optional raw data (if reading from tarball)
        passwd_data: Optional passwd file data for username resolution
        
    Returns:
        List of TimelineEvent objects
    """
    events = []
    
    try:
        # Get list of users from passwd
        users = {}
        
        # Try to parse provided passwd data first
        if passwd_data:
            try:
                passwd_text = passwd_data.decode('utf-8', errors='replace')
                for line in passwd_text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) >= 3:
                        users[int(parts[2])] = parts[0]
            except Exception:
                pass
        
        # Fall back to local passwd
        if not users:
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) >= 3:
                            users[int(parts[2])] = parts[0]
            except Exception:
                # If we can't read passwd, we'll use UID as username
                pass
        
        with open_file(filepath, binary=True, data=data) as f:
            uid = 0
            while True:
                data = f.read(LASTLOG_STRUCT_SIZE)
                if not data or len(data) < LASTLOG_STRUCT_SIZE:
                    break
                
                try:
                    unpacked = struct.unpack(LASTLOG_STRUCT_FORMAT, data)
                    ll_time = unpacked[0]
                    ll_line = decode_string(unpacked[1])
                    ll_host = decode_string(unpacked[2])
                    
                    if ll_time > 0:
                        try:
                            timestamp = datetime.utcfromtimestamp(ll_time)  # UTC for consistency
                        except (OSError, ValueError, OverflowError):
                            timestamp = None
                            
                        if timestamp:
                            username = users.get(uid, f"UID:{uid}")
                            
                            description = f"Last login for '{username}' on {ll_line}"
                            if ll_host:
                                description += f" from {ll_host}"
                            
                            event = TimelineEvent(
                                timestamp=timestamp,
                                event_type="LAST_LOGIN",
                                source_file=filepath,
                                username=username,
                                source_ip=ll_host if ll_host and not ll_host.startswith(":") else "",
                                terminal=ll_line,
                                description=description
                            )
                            events.append(event)
                except struct.error:
                    pass
                
                uid += 1
                
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)
    
    return events


# ============================================================================
# Text Log Parsers (auth.log, secure, audit.log, syslog, messages)
# ============================================================================

# Common regex patterns for log parsing
SYSLOG_TIMESTAMP_PATTERN = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$'
)

ISO_TIMESTAMP_PATTERN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+(\S+)\s+(.+)$'
)

# Auth.log patterns - comprehensive list for login/lateral movement detection
AUTH_PATTERNS = {
    # SSH Authentication - use proper IPv4 pattern to avoid false matches
    "accepted_password": re.compile(
        r'sshd\[(\d+)\]:\s+Accepted password for (\S+) from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)',
        re.IGNORECASE
    ),
    "accepted_publickey": re.compile(
        r'sshd\[(\d+)\]:\s+Accepted publickey for (\S+) from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)',
        re.IGNORECASE
    ),
    "accepted_keyboard": re.compile(
        r'sshd\[(\d+)\]:\s+Accepted keyboard-interactive.*for (\S+) from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)',
        re.IGNORECASE
    ),
    "failed_password": re.compile(
        r'sshd\[(\d+)\]:\s+Failed password for (?:invalid user )?(\S+) from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)',
        re.IGNORECASE
    ),
    "failed_publickey": re.compile(
        r'sshd\[(\d+)\]:\s+Failed publickey for (?:invalid user )?(\S+) from ((?:\d{1,3}\.){3}\d{1,3})',
        re.IGNORECASE
    ),
    "invalid_user": re.compile(
        r'sshd\[(\d+)\]:\s+Invalid user (\S+) from ((?:\d{1,3}\.){3}\d{1,3})',
        re.IGNORECASE
    ),
    "connection_closed": re.compile(
        r'sshd\[(\d+)\]:\s+Connection closed by (?:authenticating user (\S+) )?((?:\d{1,3}\.){3}\d{1,3}) port (\d+)',
        re.IGNORECASE
    ),
    "disconnected": re.compile(
        r'sshd\[(\d+)\]:\s+Disconnected from (?:(?:authenticating )?user (\S+) )?((?:\d{1,3}\.){3}\d{1,3}) port (\d+)',
        re.IGNORECASE
    ),
    "ssh_connection": re.compile(
        r'sshd\[(\d+)\]:\s+Connection from ((?:\d{1,3}\.){3}\d{1,3}) port (\d+)',
        re.IGNORECASE
    ),
    "ssh_received_disconnect": re.compile(
        r'sshd\[(\d+)\]:\s+Received disconnect from ((?:\d{1,3}\.){3}\d{1,3})',
        re.IGNORECASE
    ),
    
    # PAM Authentication (covers many services)
    "pam_session_opened": re.compile(
        r'pam_unix\((\S+):session\):\s+session opened for user (\S+)',
        re.IGNORECASE
    ),
    "pam_session_closed": re.compile(
        r'pam_unix\((\S+):session\):\s+session closed for user (\S+)',
        re.IGNORECASE
    ),
    "pam_auth_failure": re.compile(
        r'pam_unix\((\S+):auth\):\s+authentication failure.*user=(\S+)',
        re.IGNORECASE
    ),
    "pam_auth_success": re.compile(
        r'pam_unix\((\S+):auth\):\s+.*authentication.*user=(\S+)',
        re.IGNORECASE
    ),
    
    # Generic session events
    "session_opened": re.compile(
        r'(\S+)\[(\d+)\]:\s+.*session opened for user (\S+)',
        re.IGNORECASE
    ),
    "session_closed": re.compile(
        r'(\S+)\[(\d+)\]:\s+.*session closed for user (\S+)',
        re.IGNORECASE
    ),
    
    # Sudo
    "sudo_command": re.compile(
        r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)$',
        re.IGNORECASE
    ),
    "sudo_auth_failure": re.compile(
        r'sudo:\s+(\S+)\s+:.*authentication failure',
        re.IGNORECASE
    ),
    "sudo_incorrect_password": re.compile(
        r'sudo:\s+(\S+)\s+:.*(\d+) incorrect password attempt',
        re.IGNORECASE
    ),
    
    # Su
    "su_session": re.compile(
        r'su\[(\d+)\]:\s+.*\(to (\S+)\) (\S+) on',
        re.IGNORECASE
    ),
    "su_successful": re.compile(
        r'su\[(\d+)\]:\s+Successful su for (\S+) by (\S+)',
        re.IGNORECASE
    ),
    "su_failed": re.compile(
        r'su\[(\d+)\]:\s+FAILED su for (\S+) by (\S+)',
        re.IGNORECASE
    ),
    "su_pam": re.compile(
        r'su:\s+pam_unix.*session opened for user (\S+) by (\S+)',
        re.IGNORECASE
    ),
    
    # Authentication failures (generic)
    "authentication_failure": re.compile(
        r'(\S+)\[?(\d*)\]?:.*authentication failure.*(?:user=|ruser=|acct=)(\S+)',
        re.IGNORECASE
    ),
    "auth_failure_logname": re.compile(
        r'(\S+)\[?(\d*)\]?:.*authentication failure.*logname=(\S+)',
        re.IGNORECASE
    ),
    
    # User management
    "new_user": re.compile(
        r'useradd\[(\d+)\]:\s+new user: name=(\S+)',
        re.IGNORECASE
    ),
    "user_deleted": re.compile(
        r'userdel\[(\d+)\]:\s+delete user \'?(\S+?)\'?',
        re.IGNORECASE
    ),
    "password_changed": re.compile(
        r'passwd\[(\d+)\]:\s+password changed for (\S+)',
        re.IGNORECASE
    ),
    "password_change_failed": re.compile(
        r'passwd\[(\d+)\]:\s+password change failed for (\S+)',
        re.IGNORECASE
    ),
    "new_group": re.compile(
        r'groupadd\[(\d+)\]:\s+.*group.*\'?(\S+?)\'?',
        re.IGNORECASE
    ),
    "user_added_to_group": re.compile(
        r'usermod\[(\d+)\]:\s+add \'?(\S+?)\'? to group \'?(\S+?)\'?',
        re.IGNORECASE
    ),
    "user_modified": re.compile(
        r'usermod\[(\d+)\]:\s+change user \'?(\S+?)\'?',
        re.IGNORECASE
    ),
    "chage_changed": re.compile(
        r'chage\[(\d+)\]:\s+changed.*for (\S+)',
        re.IGNORECASE
    ),
    
    # Cron
    "cron_session": re.compile(
        r'CRON\[(\d+)\]:\s+pam_unix.*session opened for user (\S+)',
        re.IGNORECASE
    ),
    "cron_command": re.compile(
        r'CRON\[(\d+)\]:\s+\((\S+)\)\s+CMD\s+\((.+)\)',
        re.IGNORECASE
    ),
    
    # Systemd
    "systemd_session_new": re.compile(
        r'systemd-logind\[(\d+)\]:\s+New session (\S+) of user (\S+)',
        re.IGNORECASE
    ),
    "systemd_session_removed": re.compile(
        r'systemd-logind\[(\d+)\]:\s+Removed session (\S+)',
        re.IGNORECASE
    ),
    "systemd_user_login": re.compile(
        r'systemd\[(\d+)\]:\s+.*user-(\d+)\.slice.*Started',
        re.IGNORECASE
    ),
    
    # Login/getty
    "login_session": re.compile(
        r'login\[(\d+)\]:\s+.*LOGIN.*(\S+).*tty',
        re.IGNORECASE
    ),
    "login_root": re.compile(
        r'login\[(\d+)\]:\s+ROOT LOGIN.*tty(\S+)',
        re.IGNORECASE
    ),
    "login_failed": re.compile(
        r'login\[(\d+)\]:\s+FAILED LOGIN.*FOR (\S+)',
        re.IGNORECASE
    ),
    
    # Polkit
    "polkit_auth": re.compile(
        r'polkitd\[(\d+)\]:\s+Registered Authentication Agent for.*user (\S+)',
        re.IGNORECASE
    ),
    
    # Pkexec
    "pkexec_command": re.compile(
        r'pkexec\[(\d+)\]:\s+(\S+):\s+Executing command.*as user (\S+)',
        re.IGNORECASE
    ),
}

# Audit log patterns - comprehensive list
AUDIT_PATTERNS = {
    # User authentication events
    "user_auth": re.compile(
        r'type=USER_AUTH.*acct="([^"]*)".*(?:addr=([\d\.a-fA-F:]+))?.*res=(\w+)',
        re.IGNORECASE
    ),
    "user_login": re.compile(
        r'type=USER_LOGIN.*acct="([^"]*)".*(?:addr=([\d\.a-fA-F:]+))?.*res=(\w+)',
        re.IGNORECASE
    ),
    "user_logout": re.compile(
        r'type=USER_LOGOUT.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    "user_start": re.compile(
        r'type=USER_START.*acct="([^"]*)".*(?:addr=([\d\.a-fA-F:]+))?',
        re.IGNORECASE
    ),
    "user_end": re.compile(
        r'type=USER_END.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    "user_acct": re.compile(
        r'type=USER_ACCT.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "user_chauthtok": re.compile(
        r'type=USER_CHAUTHTOK.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    
    # Credential events
    "cred_acq": re.compile(
        r'type=CRED_ACQ.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "cred_disp": re.compile(
        r'type=CRED_DISP.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "cred_refr": re.compile(
        r'type=CRED_REFR.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    
    # Command execution
    "user_cmd": re.compile(
        r'type=USER_CMD.*acct="([^"]*)".*cmd="?([^"]*)"?',
        re.IGNORECASE
    ),
    "execve": re.compile(
        r'type=EXECVE.*a0="?([^"]*)"?',
        re.IGNORECASE
    ),
    
    # System calls
    "syscall": re.compile(
        r'type=SYSCALL.*comm="([^"]*)".*exe="([^"]*)"',
        re.IGNORECASE
    ),
    
    # Session management
    "user_role_change": re.compile(
        r'type=USER_ROLE_CHANGE.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    "role_assign": re.compile(
        r'type=ROLE_ASSIGN.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    
    # User management  
    "add_user": re.compile(
        r'type=ADD_USER.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "del_user": re.compile(
        r'type=DEL_USER.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "add_group": re.compile(
        r'type=ADD_GROUP.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "del_group": re.compile(
        r'type=DEL_GROUP.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "grp_mgmt": re.compile(
        r'type=GRP_MGMT.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    
    # Authentication failures
    "user_err": re.compile(
        r'type=USER_ERR.*acct="([^"]*)".*res=(\w+)',
        re.IGNORECASE
    ),
    "anom_login_failures": re.compile(
        r'type=ANOM_LOGIN_FAILURES.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    "anom_login_location": re.compile(
        r'type=ANOM_LOGIN_LOCATION.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    "anom_login_sessions": re.compile(
        r'type=ANOM_LOGIN_SESSIONS.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    "anom_login_time": re.compile(
        r'type=ANOM_LOGIN_TIME.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    
    # TTY/Terminal
    "tty": re.compile(
        r'type=TTY.*data="?([^"]*)"?',
        re.IGNORECASE
    ),
    "user_tty": re.compile(
        r'type=USER_TTY.*acct="([^"]*)"',
        re.IGNORECASE
    ),
    
    # Generic audit event with acct
    "generic_acct": re.compile(
        r'type=(\w+).*acct="([^"]*)".*(?:res=(\w+))?',
        re.IGNORECASE
    ),
}


def make_naive(dt: datetime) -> datetime:
    """
    Convert an offset-aware datetime to offset-naive (UTC).
    This ensures all datetimes can be compared.
    
    Args:
        dt: datetime object (aware or naive)
        
    Returns:
        Offset-naive datetime
    """
    if dt is None:
        return None
    if dt.tzinfo is not None:
        # Convert to UTC then remove timezone info
        try:
            from datetime import timezone
            utc_dt = dt.astimezone(timezone.utc)
            return utc_dt.replace(tzinfo=None)
        except Exception:
            # Fallback: just strip timezone
            return dt.replace(tzinfo=None)
    return dt


def parse_syslog_timestamp(timestamp_str: str, reference_date: datetime = None) -> Optional[datetime]:
    """
    Parse syslog-style timestamp (e.g., "Dec 17 10:30:45").
    
    Syslog timestamps don't include a year, so we must infer it from context.
    For forensic analysis, we use a reference date (typically from the file's
    modification time or from binary logs that include full timestamps) rather
    than datetime.now(), since the evidence may be historical.
    
    Args:
        timestamp_str: Timestamp string (e.g., "Dec 17 10:30:45")
        reference_date: Reference datetime for year inference. If None, uses
                       datetime.now() as fallback (not recommended for forensics).
        
    Returns:
        datetime object or None (always offset-naive)
    """
    if reference_date is None:
        reference_date = datetime.utcnow()
    
    reference_year = reference_date.year
    
    try:
        # Add year to timestamp (parsed timestamps are assumed to be in UTC)
        dt = datetime.strptime(f"{reference_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        
        # Handle year rollover for forensic analysis:
        # If the parsed timestamp's month is significantly ahead of the reference date's month,
        # it likely belongs to the previous year. This handles the common case where logs
        # span a December→January boundary.
        # 
        # For example: Reference is Feb 15, 2024, and we see "Dec 20 10:30:45"
        # That Dec 20 is likely from 2023, not a future date in 2024.
        #
        # We use a threshold of 6 months to avoid edge cases.
        months_difference = (dt.month - reference_date.month)
        if months_difference > 6:
            # Log entry appears to be from the previous year
            dt = dt.replace(year=reference_year - 1)
        elif months_difference < -6:
            # Log entry appears to be from the next year (rare but possible if reference is old)
            dt = dt.replace(year=reference_year + 1)
        
        return dt
    except ValueError:
        return None


def parse_iso_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse ISO 8601 timestamp.
    
    Args:
        timestamp_str: ISO timestamp string
        
    Returns:
        datetime object or None (always offset-naive)
    """
    try:
        # Handle various ISO formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str.replace("Z", "+0000"), fmt)
                # Convert to offset-naive to ensure comparability
                return make_naive(dt)
            except ValueError:
                continue
        
        return None
    except Exception:
        return None


def parse_audit_timestamp(line: str) -> Optional[datetime]:
    """
    Parse audit log timestamp (msg=audit(epoch:serial)).
    
    Args:
        line: Audit log line
        
    Returns:
        datetime object or None (always offset-naive)
    """
    match = re.search(r'msg=audit\((\d+)\.(\d+):\d+\)', line)
    if match:
        try:
            epoch = int(match.group(1))
            dt = datetime.utcfromtimestamp(epoch)  # UTC for forensic consistency
            return dt
        except (OSError, ValueError, OverflowError):
            pass
    return None


def parse_auth_log(filepath: str, data: bytes = None, reference_date: datetime = None) -> List[TimelineEvent]:
    """
    Parse auth.log or secure log file.
    
    Args:
        filepath: Path to log file
        data: Optional raw data (if reading from tarball)
        reference_date: Reference datetime for year inference on syslog timestamps.
                       If None, attempts to use file mtime, then falls back to datetime.now().
        
    Returns:
        List of TimelineEvent objects
    """
    events = []
    
    # Determine reference date for year inference (use UTC for consistency)
    if reference_date is None:
        # Try to get file modification time as reference
        if data is None and os.path.exists(filepath):
            try:
                mtime = os.path.getmtime(filepath)
                reference_date = datetime.utcfromtimestamp(mtime)
            except (OSError, ValueError):
                reference_date = datetime.utcnow()
        else:
            # Data was provided (from tarball), use datetime.utcnow() as fallback
            # Note: Caller should provide reference_date for accurate forensic analysis
            reference_date = datetime.utcnow()
    
    # Helper to safely get group or empty string
    def safe_group(groups, idx, default=""):
        try:
            return groups[idx] if groups[idx] else default
        except (IndexError, TypeError):
            return default
    
    # Helper to safely parse int
    def safe_int(val, default=0):
        try:
            return int(val) if val else default
        except (ValueError, TypeError):
            return default
    
    # Event type mapping for pattern names
    EVENT_TYPE_MAP = {
        # SSH events
        "accepted_password": "SSH_LOGIN_PASSWORD",
        "accepted_publickey": "SSH_LOGIN_PUBKEY",
        "accepted_keyboard": "SSH_LOGIN_KEYBOARD",
        "failed_password": "SSH_FAILED_PASSWORD",
        "failed_publickey": "SSH_FAILED_PUBKEY",
        "invalid_user": "SSH_INVALID_USER",
        "connection_closed": "SSH_CONNECTION_CLOSED",
        "disconnected": "SSH_DISCONNECT",
        "ssh_connection": "SSH_CONNECTION",
        "ssh_received_disconnect": "SSH_RECV_DISCONNECT",
        
        # PAM events
        "pam_session_opened": "PAM_SESSION_OPEN",
        "pam_session_closed": "PAM_SESSION_CLOSE",
        "pam_auth_failure": "PAM_AUTH_FAILURE",
        "pam_auth_success": "PAM_AUTH_SUCCESS",
        
        # Generic session
        "session_opened": "SESSION_OPENED",
        "session_closed": "SESSION_CLOSED",
        
        # Sudo
        "sudo_command": "SUDO_COMMAND",
        "sudo_auth_failure": "SUDO_AUTH_FAILURE",
        "sudo_incorrect_password": "SUDO_INCORRECT_PASSWORD",
        
        # Su
        "su_session": "SU_SESSION",
        "su_successful": "SU_SUCCESS",
        "su_failed": "SU_FAILED",
        "su_pam": "SU_PAM_SESSION",
        
        # Auth failures
        "authentication_failure": "AUTH_FAILURE",
        "auth_failure_logname": "AUTH_FAILURE",
        
        # User management
        "new_user": "USER_CREATED",
        "user_deleted": "USER_DELETED",
        "password_changed": "PASSWORD_CHANGED",
        "password_change_failed": "PASSWORD_CHANGE_FAILED",
        "new_group": "GROUP_CREATED",
        "user_added_to_group": "USER_ADDED_TO_GROUP",
        "user_modified": "USER_MODIFIED",
        "chage_changed": "USER_CHAGE_MODIFIED",
        
        # Cron
        "cron_session": "CRON_SESSION",
        "cron_command": "CRON_COMMAND",
        
        # Systemd
        "systemd_session_new": "SYSTEMD_SESSION_NEW",
        "systemd_session_removed": "SYSTEMD_SESSION_REMOVED",
        "systemd_user_login": "SYSTEMD_USER_LOGIN",
        
        # Login
        "login_session": "LOGIN_SESSION",
        "login_root": "LOGIN_ROOT",
        "login_failed": "LOGIN_FAILED",
        
        # Polkit/pkexec
        "polkit_auth": "POLKIT_AUTH",
        "pkexec_command": "PKEXEC_COMMAND",
    }
    
    try:
        with open_file(filepath, binary=False, data=data) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parse timestamp
                timestamp = None
                hostname = ""
                message = line
                
                # Try syslog format
                match = SYSLOG_TIMESTAMP_PATTERN.match(line)
                if match:
                    timestamp = parse_syslog_timestamp(match.group(1), reference_date)
                    hostname = match.group(2)
                    message = match.group(3)
                else:
                    # Try ISO format
                    match = ISO_TIMESTAMP_PATTERN.match(line)
                    if match:
                        timestamp = parse_iso_timestamp(match.group(1))
                        hostname = match.group(2)
                        message = match.group(3)
                
                if not timestamp:
                    continue
                
                # Match against auth patterns
                matched = False
                for pattern_name, pattern in AUTH_PATTERNS.items():
                    match = pattern.search(message)
                    if match:
                        groups = match.groups()
                        event_type = EVENT_TYPE_MAP.get(pattern_name, pattern_name.upper())
                        
                        # Build event based on pattern type
                        username = ""
                        source_ip = ""
                        pid = 0
                        description = message[:200]  # Truncate long messages
                        
                        # SSH patterns (pid, user, ip, port)
                        if pattern_name in ("accepted_password", "accepted_publickey", "accepted_keyboard"):
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            source_ip = safe_group(groups, 2)
                            port = safe_group(groups, 3)
                            description = f"SSH auth successful for '{username}' from {source_ip}:{port}"
                        
                        elif pattern_name in ("failed_password", "failed_publickey"):
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            source_ip = safe_group(groups, 2)
                            port = safe_group(groups, 3, "")
                            description = f"SSH auth failed for '{username}' from {source_ip}"
                        
                        elif pattern_name == "invalid_user":
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            source_ip = safe_group(groups, 2)
                            description = f"Invalid user '{username}' from {source_ip}"
                        
                        elif pattern_name in ("connection_closed", "disconnected"):
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            source_ip = safe_group(groups, 2)
                            description = f"SSH connection closed from {source_ip}"
                        
                        elif pattern_name == "ssh_connection":
                            pid = safe_int(safe_group(groups, 0))
                            source_ip = safe_group(groups, 1)
                            description = f"SSH connection from {source_ip}"
                        
                        # PAM patterns
                        elif pattern_name in ("pam_session_opened", "pam_session_closed"):
                            service = safe_group(groups, 0)
                            username = safe_group(groups, 1)
                            description = f"PAM {pattern_name.split('_')[-1]} for '{username}' via {service}"
                        
                        elif pattern_name in ("pam_auth_failure", "pam_auth_success"):
                            service = safe_group(groups, 0)
                            username = safe_group(groups, 1)
                            description = f"PAM auth for '{username}' via {service}"
                        
                        # Session patterns
                        elif pattern_name in ("session_opened", "session_closed"):
                            service = safe_group(groups, 0)
                            pid = safe_int(safe_group(groups, 1))
                            username = safe_group(groups, 2)
                            description = f"Session {pattern_name.split('_')[-1]} for '{username}'"
                        
                        # Sudo patterns
                        elif pattern_name == "sudo_command":
                            username = safe_group(groups, 0)
                            cmd = safe_group(groups, 1)
                            description = f"Sudo command by '{username}': {cmd[:100]}"
                        
                        elif pattern_name in ("sudo_auth_failure", "sudo_incorrect_password"):
                            username = safe_group(groups, 0)
                            description = f"Sudo auth failure for '{username}'"
                        
                        # Su patterns
                        elif pattern_name == "su_session":
                            pid = safe_int(safe_group(groups, 0))
                            target_user = safe_group(groups, 1)
                            username = safe_group(groups, 2)
                            description = f"Su session: '{username}' -> '{target_user}'"
                        
                        elif pattern_name in ("su_successful", "su_failed"):
                            pid = safe_int(safe_group(groups, 0))
                            target_user = safe_group(groups, 1)
                            username = safe_group(groups, 2)
                            description = f"Su {pattern_name.split('_')[-1]}: '{username}' -> '{target_user}'"
                        
                        elif pattern_name == "su_pam":
                            target_user = safe_group(groups, 0)
                            username = safe_group(groups, 1)
                            description = f"Su PAM session: '{username}' -> '{target_user}'"
                        
                        # Auth failure patterns
                        elif pattern_name in ("authentication_failure", "auth_failure_logname"):
                            service = safe_group(groups, 0)
                            pid = safe_int(safe_group(groups, 1))
                            username = safe_group(groups, 2)
                            description = f"Auth failure for '{username}' via {service}"
                        
                        # User management
                        elif pattern_name in ("new_user", "user_deleted", "user_modified"):
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            description = f"User {pattern_name.replace('_', ' ')}: '{username}'"
                        
                        elif pattern_name in ("password_changed", "password_change_failed"):
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            description = f"Password {pattern_name.replace('password_', '')}: '{username}'"
                        
                        elif pattern_name == "new_group":
                            pid = safe_int(safe_group(groups, 0))
                            group = safe_group(groups, 1)
                            description = f"New group created: '{group}'"
                        
                        elif pattern_name == "user_added_to_group":
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            group = safe_group(groups, 2)
                            description = f"User '{username}' added to group '{group}'"
                        
                        # Cron patterns
                        elif pattern_name == "cron_session":
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            description = f"Cron session for '{username}'"
                        
                        elif pattern_name == "cron_command":
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            cmd = safe_group(groups, 2)
                            description = f"Cron job by '{username}': {cmd[:100]}"
                        
                        # Systemd patterns
                        elif pattern_name == "systemd_session_new":
                            pid = safe_int(safe_group(groups, 0))
                            session = safe_group(groups, 1)
                            username = safe_group(groups, 2)
                            description = f"Systemd new session {session} for '{username}'"
                        
                        elif pattern_name == "systemd_session_removed":
                            pid = safe_int(safe_group(groups, 0))
                            session = safe_group(groups, 1)
                            description = f"Systemd removed session {session}"
                        
                        # Login patterns
                        elif pattern_name in ("login_session", "login_root", "login_failed"):
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1, "root" if pattern_name == "login_root" else "")
                            description = f"Login {pattern_name.replace('login_', '')}"
                        
                        # Polkit/pkexec
                        elif pattern_name == "polkit_auth":
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            description = f"Polkit auth agent for '{username}'"
                        
                        elif pattern_name == "pkexec_command":
                            pid = safe_int(safe_group(groups, 0))
                            username = safe_group(groups, 1)
                            target_user = safe_group(groups, 2)
                            description = f"Pkexec by '{username}' as '{target_user}'"
                        
                        # Validate and sanitize the extracted username
                        validated_username = sanitize_username(username) if username else ""
                        
                        event = TimelineEvent(
                            timestamp=timestamp,
                            event_type=event_type,
                            source_file=filepath,
                            username=validated_username,
                            source_ip=source_ip,
                            pid=pid,
                            description=description,
                            raw_data=line
                        )
                        events.append(event)
                        matched = True
                        break
                
                # Fallback: capture any line with login-related keywords
                if not matched:
                    # Skip continuation lines (these are fragments of previous commands)
                    if '(command continued)' in message:
                        continue
                    
                    keywords = ['login', 'auth', 'session', 'password', 'sudo', 'su:', 
                               'accepted', 'failed', 'invalid', 'sshd', 'pam']
                    # Note: removed 'user' as standalone keyword - too many false positives
                    if any(kw in message.lower() for kw in keywords):
                        # Extract username if possible - use more precise patterns
                        username = ""
                        # Try specific patterns in order of reliability
                        user_patterns = [
                            r'(?:^|\s)user[=:][\s"]*([a-zA-Z_][a-zA-Z0-9_-]*)',  # user=name or user: name
                            r'for user [\'""]?([a-zA-Z_][a-zA-Z0-9_-]*)[\'""]?',  # for user 'name'
                            r'(?:^|\s)for ([a-zA-Z_][a-zA-Z0-9_-]*)(?:\s|$|,)',  # for name (word boundary)
                            r'session opened for ([a-zA-Z_][a-zA-Z0-9_-]*)',  # session opened for name
                            r'session closed for ([a-zA-Z_][a-zA-Z0-9_-]*)',  # session closed for name
                        ]
                        for pattern in user_patterns:
                            user_match = re.search(pattern, message, re.IGNORECASE)
                            if user_match:
                                potential_user = user_match.group(1)
                                if is_valid_username(potential_user):
                                    username = sanitize_username(potential_user)
                                    break
                        
                        # Extract IP if possible - use validated extraction
                        source_ip = extract_ip_from_message(message)
                        
                        event = TimelineEvent(
                            timestamp=timestamp,
                            event_type="AUTH_EVENT",
                            source_file=filepath,
                            username=username,
                            source_ip=source_ip,
                            description=message[:200],
                            raw_data=line
                        )
                        events.append(event)
                        
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)
    
    return events


def parse_audit_log(filepath: str, data: bytes = None) -> List[TimelineEvent]:
    """
    Parse audit.log file.
    
    Args:
        filepath: Path to audit log file
        data: Optional raw data (if reading from tarball)
        
    Returns:
        List of TimelineEvent objects
    """
    events = []
    
    # Helper to safely get group value
    def safe_group(groups, idx, default=""):
        try:
            return groups[idx] if groups[idx] else default
        except (IndexError, TypeError):
            return default
    
    # Event type mapping for audit patterns
    AUDIT_EVENT_MAP = {
        "user_auth": "AUDIT_USER_AUTH",
        "user_login": "AUDIT_USER_LOGIN",
        "user_logout": "AUDIT_USER_LOGOUT",
        "user_start": "AUDIT_SESSION_START",
        "user_end": "AUDIT_SESSION_END",
        "user_acct": "AUDIT_USER_ACCT",
        "user_chauthtok": "AUDIT_PASSWORD_CHANGE",
        "cred_acq": "AUDIT_CRED_ACQ",
        "cred_disp": "AUDIT_CRED_DISP",
        "cred_refr": "AUDIT_CRED_REFR",
        "user_cmd": "AUDIT_USER_CMD",
        "execve": "AUDIT_EXECVE",
        "syscall": "AUDIT_SYSCALL",
        "user_role_change": "AUDIT_ROLE_CHANGE",
        "role_assign": "AUDIT_ROLE_ASSIGN",
        "add_user": "AUDIT_ADD_USER",
        "del_user": "AUDIT_DEL_USER",
        "add_group": "AUDIT_ADD_GROUP",
        "del_group": "AUDIT_DEL_GROUP",
        "grp_mgmt": "AUDIT_GRP_MGMT",
        "user_err": "AUDIT_USER_ERR",
        "anom_login_failures": "AUDIT_ANOM_LOGIN_FAILURES",
        "anom_login_location": "AUDIT_ANOM_LOGIN_LOCATION",
        "anom_login_sessions": "AUDIT_ANOM_LOGIN_SESSIONS",
        "anom_login_time": "AUDIT_ANOM_LOGIN_TIME",
        "tty": "AUDIT_TTY",
        "user_tty": "AUDIT_USER_TTY",
        "generic_acct": "AUDIT_EVENT",
    }
    
    try:
        with open_file(filepath, binary=False, data=data) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parse timestamp
                timestamp = parse_audit_timestamp(line)
                if not timestamp:
                    continue
                
                # Match against audit patterns
                matched = False
                for pattern_name, pattern in AUDIT_PATTERNS.items():
                    match = pattern.search(line)
                    if match:
                        groups = match.groups()
                        
                        # Get event type with success/failure suffix where applicable
                        base_event_type = AUDIT_EVENT_MAP.get(pattern_name, "AUDIT_EVENT")
                        username = ""
                        source_ip = ""
                        description = ""
                        
                        # Authentication events with result
                        if pattern_name == "user_auth":
                            username = safe_group(groups, 0)
                            source_ip = safe_group(groups, 1)
                            result = safe_group(groups, 2, "unknown")
                            event_type = "AUDIT_AUTH_SUCCESS" if result.lower() == "success" else "AUDIT_AUTH_FAILURE"
                            description = f"User authentication: '{username}' - {result}"
                        
                        elif pattern_name == "user_login":
                            username = safe_group(groups, 0)
                            source_ip = safe_group(groups, 1)
                            result = safe_group(groups, 2, "unknown")
                            event_type = "AUDIT_LOGIN_SUCCESS" if result.lower() == "success" else "AUDIT_LOGIN_FAILURE"
                            description = f"User login: '{username}' - {result}"
                        
                        elif pattern_name == "user_logout":
                            username = safe_group(groups, 0)
                            event_type = base_event_type
                            description = f"User logout: '{username}'"
                        
                        elif pattern_name == "user_start":
                            username = safe_group(groups, 0)
                            source_ip = safe_group(groups, 1)
                            event_type = base_event_type
                            description = f"Session started for user '{username}'"
                        
                        elif pattern_name == "user_end":
                            username = safe_group(groups, 0)
                            event_type = base_event_type
                            description = f"Session ended for user '{username}'"
                        
                        elif pattern_name == "user_acct":
                            username = safe_group(groups, 0)
                            result = safe_group(groups, 1, "unknown")
                            event_type = base_event_type
                            description = f"Account access: '{username}' - {result}"
                        
                        elif pattern_name == "user_chauthtok":
                            username = safe_group(groups, 0)
                            result = safe_group(groups, 1, "unknown")
                            event_type = base_event_type
                            description = f"Password change for '{username}' - {result}"
                        
                        # Credential events
                        elif pattern_name in ("cred_acq", "cred_disp", "cred_refr"):
                            username = safe_group(groups, 0)
                            result = safe_group(groups, 1, "unknown")
                            event_type = base_event_type
                            action = pattern_name.replace("cred_", "")
                            description = f"Credential {action} for '{username}' - {result}"
                        
                        # Command execution
                        elif pattern_name == "user_cmd":
                            username = safe_group(groups, 0)
                            cmd = safe_group(groups, 1)
                            event_type = base_event_type
                            description = f"User '{username}' executed: {cmd[:100]}"
                        
                        elif pattern_name == "execve":
                            cmd = safe_group(groups, 0)
                            event_type = base_event_type
                            description = f"Execve: {cmd[:100]}"
                        
                        elif pattern_name == "syscall":
                            comm = safe_group(groups, 0)
                            exe = safe_group(groups, 1)
                            event_type = base_event_type
                            description = f"Syscall: {comm} ({exe})"
                        
                        # Role changes
                        elif pattern_name in ("user_role_change", "role_assign"):
                            username = safe_group(groups, 0)
                            event_type = base_event_type
                            description = f"Role change for '{username}'"
                        
                        # User/group management
                        elif pattern_name in ("add_user", "del_user"):
                            username = safe_group(groups, 0)
                            result = safe_group(groups, 1, "unknown")
                            event_type = base_event_type
                            action = "created" if "add" in pattern_name else "deleted"
                            description = f"User {action}: '{username}' - {result}"
                        
                        elif pattern_name in ("add_group", "del_group"):
                            group = safe_group(groups, 0)
                            result = safe_group(groups, 1, "unknown")
                            event_type = base_event_type
                            action = "created" if "add" in pattern_name else "deleted"
                            description = f"Group {action}: '{group}' - {result}"
                        
                        elif pattern_name == "grp_mgmt":
                            username = safe_group(groups, 0)
                            event_type = base_event_type
                            description = f"Group management for '{username}'"
                        
                        # Error and anomaly events
                        elif pattern_name == "user_err":
                            username = safe_group(groups, 0)
                            result = safe_group(groups, 1, "unknown")
                            event_type = base_event_type
                            description = f"User error for '{username}' - {result}"
                        
                        elif pattern_name.startswith("anom_"):
                            username = safe_group(groups, 0)
                            event_type = base_event_type
                            anom_type = pattern_name.replace("anom_login_", "")
                            description = f"Login anomaly ({anom_type}) for '{username}'"
                        
                        # TTY events
                        elif pattern_name == "tty":
                            data = safe_group(groups, 0)
                            event_type = base_event_type
                            description = f"TTY data: {data[:50]}"
                        
                        elif pattern_name == "user_tty":
                            username = safe_group(groups, 0)
                            event_type = base_event_type
                            description = f"User TTY for '{username}'"
                        
                        # Generic fallback
                        elif pattern_name == "generic_acct":
                            audit_type = safe_group(groups, 0)
                            username = safe_group(groups, 1)
                            result = safe_group(groups, 2, "")
                            event_type = f"AUDIT_{audit_type}"
                            description = f"Audit event {audit_type} for '{username}'"
                            if result:
                                description += f" - {result}"
                        
                        else:
                            event_type = base_event_type
                            description = line[:200]
                        
                        event = TimelineEvent(
                            timestamp=timestamp,
                            event_type=event_type,
                            source_file=filepath,
                            username=username,
                            source_ip=source_ip,
                            description=description,
                            raw_data=line
                        )
                        events.append(event)
                        matched = True
                        break
                
                # Fallback for unmatched audit lines with user info
                if not matched:
                    # Try to extract account and type info from any audit line
                    type_match = re.search(r'type=(\w+)', line)
                    acct_match = re.search(r'acct="([^"]*)"', line)
                    res_match = re.search(r'res=(\w+)', line)
                    addr_match = re.search(r'addr=([\d\.a-fA-F:]+)', line)
                    
                    if type_match and (acct_match or 'acct=' in line or 'uid=' in line):
                        audit_type = type_match.group(1)
                        username = acct_match.group(1) if acct_match else ""
                        result = res_match.group(1) if res_match else ""
                        source_ip = addr_match.group(1) if addr_match else ""
                        
                        description = f"Audit {audit_type}"
                        if username:
                            description += f" for '{username}'"
                        if result:
                            description += f" - {result}"
                        
                        event = TimelineEvent(
                            timestamp=timestamp,
                            event_type=f"AUDIT_{audit_type}",
                            source_file=filepath,
                            username=username,
                            source_ip=source_ip,
                            description=description,
                            raw_data=line
                        )
                        events.append(event)
                        
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)
    
    return events


def parse_syslog_messages(filepath: str, data: bytes = None, reference_date: datetime = None) -> List[TimelineEvent]:
    """
    Parse syslog/messages file for login-related events.
    
    Args:
        filepath: Path to syslog or messages file
        data: Optional raw data (if reading from tarball)
        reference_date: Reference datetime for year inference on syslog timestamps.
                       If None, attempts to use file mtime, then falls back to datetime.now().
        
    Returns:
        List of TimelineEvent objects
    """
    events = []
    
    # Determine reference date for year inference (use UTC for consistency)
    if reference_date is None:
        # Try to get file modification time as reference
        if data is None and os.path.exists(filepath):
            try:
                mtime = os.path.getmtime(filepath)
                reference_date = datetime.utcfromtimestamp(mtime)
            except (OSError, ValueError):
                reference_date = datetime.utcnow()
        else:
            # Data was provided (from tarball), use datetime.utcnow() as fallback
            # Note: Caller should provide reference_date for accurate forensic analysis
            reference_date = datetime.utcnow()
    
    # Keywords that indicate login/user activity
    LOGIN_KEYWORDS = [
        'login', 'logout', 'session', 'authenticated', 'authentication',
        'password', 'sudo', 'su:', 'pam', 'sshd', 'gdm', 'lightdm', 'sddm',
        'user', 'failed', 'accepted', 'invalid', 'opened', 'closed',
        'systemd-logind', 'polkit', 'pkexec', 'cron', 'at'
    ]
    
    # Specific event patterns
    syslog_patterns = {
        "new_session": re.compile(r'New session (\S+) of user (\S+)', re.IGNORECASE),
        "removed_session": re.compile(r'Removed session (\S+)', re.IGNORECASE),
        "user_logged_in": re.compile(r'User (\S+) logged in', re.IGNORECASE),
        "user_logged_out": re.compile(r'User (\S+) logged out', re.IGNORECASE),
        "session_opened": re.compile(r'session opened for user (\S+)', re.IGNORECASE),
        "session_closed": re.compile(r'session closed for user (\S+)', re.IGNORECASE),
        "accepted_connection": re.compile(r'Accepted (\S+) for (\S+) from ((?:\d{1,3}\.){3}\d{1,3})', re.IGNORECASE),
        "failed_connection": re.compile(r'Failed (\S+) for (\S+) from ((?:\d{1,3}\.){3}\d{1,3})', re.IGNORECASE),
        "invalid_user": re.compile(r'Invalid user (\S+) from ((?:\d{1,3}\.){3}\d{1,3})', re.IGNORECASE),
        "connection_from": re.compile(r'Connection from ((?:\d{1,3}\.){3}\d{1,3})', re.IGNORECASE),
        "disconnected_from": re.compile(r'Disconnected from (?:(?:authenticating )?user \S+ )?((?:\d{1,3}\.){3}\d{1,3})', re.IGNORECASE),
        "authentication_failure": re.compile(r'authentication failure.*user=(\S+)', re.IGNORECASE),
        "sudo_command": re.compile(r'(\S+)\s*:.*COMMAND=(.+)$', re.IGNORECASE),
        "cron_session": re.compile(r'CRON\[(\d+)\].*\((\S+)\)', re.IGNORECASE),
        "power_key": re.compile(r'Power key pressed', re.IGNORECASE),
        "lid_closed": re.compile(r'Lid closed', re.IGNORECASE),
        "lid_opened": re.compile(r'Lid opened', re.IGNORECASE),
        "seat_new": re.compile(r'New seat (\S+)', re.IGNORECASE),
        "seat_removed": re.compile(r'Removed seat (\S+)', re.IGNORECASE),
    }
    
    try:
        with open_file(filepath, binary=False, data=data) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parse timestamp
                timestamp = None
                hostname = ""
                message = line
                
                match = SYSLOG_TIMESTAMP_PATTERN.match(line)
                if match:
                    timestamp = parse_syslog_timestamp(match.group(1), reference_date)
                    hostname = match.group(2)
                    message = match.group(3)
                else:
                    match = ISO_TIMESTAMP_PATTERN.match(line)
                    if match:
                        timestamp = parse_iso_timestamp(match.group(1))
                        hostname = match.group(2)
                        message = match.group(3)
                
                if not timestamp:
                    continue
                
                # Check if line contains any login-related keywords
                message_lower = message.lower()
                if not any(kw in message_lower for kw in LOGIN_KEYWORDS):
                    continue
                
                # Try to match specific patterns
                matched = False
                for pattern_name, pattern in syslog_patterns.items():
                    match = pattern.search(message)
                    if match:
                        groups = match.groups()
                        username = ""
                        source_ip = ""
                        description = message[:200]
                        
                        if pattern_name == "new_session":
                            username = groups[1]
                            description = f"New session {groups[0]} for user '{username}'"
                            event_type = "SYSLOG_SESSION_START"
                        
                        elif pattern_name == "removed_session":
                            description = f"Session {groups[0]} removed"
                            event_type = "SYSLOG_SESSION_END"
                        
                        elif pattern_name in ("user_logged_in", "user_logged_out"):
                            username = groups[0]
                            action = "in" if "in" in pattern_name else "out"
                            description = f"User '{username}' logged {action}"
                            event_type = f"SYSLOG_USER_LOG{'IN' if action == 'in' else 'OUT'}"
                        
                        elif pattern_name == "session_opened":
                            username = groups[0]
                            description = f"Session opened for user '{username}'"
                            event_type = "SYSLOG_SESSION_OPEN"
                        
                        elif pattern_name == "session_closed":
                            username = groups[0]
                            description = f"Session closed for user '{username}'"
                            event_type = "SYSLOG_SESSION_CLOSE"
                        
                        elif pattern_name == "accepted_connection":
                            auth_type = groups[0]
                            username = groups[1]
                            source_ip = groups[2]
                            description = f"Accepted {auth_type} for '{username}' from {source_ip}"
                            event_type = "SYSLOG_AUTH_SUCCESS"
                        
                        elif pattern_name == "failed_connection":
                            auth_type = groups[0]
                            username = groups[1]
                            source_ip = groups[2]
                            description = f"Failed {auth_type} for '{username}' from {source_ip}"
                            event_type = "SYSLOG_AUTH_FAILURE"
                        
                        elif pattern_name == "invalid_user":
                            username = groups[0]
                            source_ip = groups[1]
                            description = f"Invalid user '{username}' from {source_ip}"
                            event_type = "SYSLOG_INVALID_USER"
                        
                        elif pattern_name == "connection_from":
                            source_ip = groups[0]
                            description = f"Connection from {source_ip}"
                            event_type = "SYSLOG_CONNECTION"
                        
                        elif pattern_name == "disconnected_from":
                            source_ip = groups[0]
                            description = f"Disconnected from {source_ip}"
                            event_type = "SYSLOG_DISCONNECT"
                        
                        elif pattern_name == "authentication_failure":
                            username = groups[0]
                            description = f"Authentication failure for '{username}'"
                            event_type = "SYSLOG_AUTH_FAILURE"
                        
                        elif pattern_name == "sudo_command":
                            username = groups[0]
                            cmd = groups[1]
                            description = f"Sudo by '{username}': {cmd[:100]}"
                            event_type = "SYSLOG_SUDO"
                        
                        elif pattern_name == "cron_session":
                            username = groups[1] if len(groups) > 1 else ""
                            description = f"Cron session for '{username}'"
                            event_type = "SYSLOG_CRON"
                        
                        elif pattern_name in ("power_key", "lid_closed", "lid_opened"):
                            description = pattern_name.replace("_", " ").title()
                            event_type = "SYSLOG_POWER_EVENT"
                        
                        elif pattern_name in ("seat_new", "seat_removed"):
                            seat = groups[0]
                            action = "new" if "new" in pattern_name else "removed"
                            description = f"Seat {seat} {action}"
                            event_type = "SYSLOG_SEAT_EVENT"
                        
                        else:
                            event_type = "SYSLOG_EVENT"
                        
                        # Validate the extracted username before creating event
                        validated_username = sanitize_username(username) if username else ""
                        
                        event = TimelineEvent(
                            timestamp=timestamp,
                            event_type=event_type,
                            source_file=filepath,
                            username=validated_username,
                            source_ip=source_ip,
                            description=description,
                            raw_data=line
                        )
                        events.append(event)
                        matched = True
                        break
                
                # Fallback: capture any relevant line with user/auth info
                if not matched:
                    # Skip continuation lines
                    if '(command continued)' in message:
                        continue
                    
                    # Extract username if possible - use precise patterns
                    username = ""
                    user_patterns = [
                        r'(?:^|\s)user[=:][\s"]*([a-zA-Z_][a-zA-Z0-9_-]*)',
                        r'for user [\'""]?([a-zA-Z_][a-zA-Z0-9_-]*)[\'""]?',
                        r'session (?:opened|closed) for ([a-zA-Z_][a-zA-Z0-9_-]*)',
                    ]
                    for pattern in user_patterns:
                        user_match = re.search(pattern, message, re.IGNORECASE)
                        if user_match:
                            potential_user = user_match.group(1)
                            if is_valid_username(potential_user):
                                username = sanitize_username(potential_user)
                                break
                    
                    # Extract IP if possible - use validated extraction
                    source_ip = extract_ip_from_message(message)
                    
                    event = TimelineEvent(
                        timestamp=timestamp,
                        event_type="SYSLOG_EVENT",
                        source_file=filepath,
                        username=username,
                        source_ip=source_ip,
                        description=message[:200],
                        raw_data=line
                    )
                    events.append(event)
                        
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)
    
    return events


# ============================================================================
# Bash History Parser
# ============================================================================

def parse_bash_history(filepath: str, data: bytes = None, username: str = "", 
                       file_mtime: datetime = None) -> List[TimelineEvent]:
    """
    Parse bash_history file for command execution timeline.
    
    Bash history can contain timestamps if HISTTIMEFORMAT was enabled.
    Timestamps appear as #<epoch> lines before each command.
    
    Args:
        filepath: Path to bash_history file
        data: Optional raw data (if reading from tarball)
        username: Username who owns this history file
        file_mtime: File modification time (used for undated entries)
        
    Returns:
        List of TimelineEvent objects
    """
    events = []
    
    # If no mtime provided, use current time as fallback
    if file_mtime is None:
        file_mtime = datetime.now()
    
    try:
        with open_file(filepath, binary=False, data=data) as f:
            lines = f.readlines()
        
        current_timestamp = None
        command_index = 0
        total_commands = sum(1 for line in lines if not line.startswith('#'))
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            # Check for timestamp line (#<epoch>)
            if line.startswith('#') and len(line) > 1:
                try:
                    epoch = int(line[1:])
                    # Validate epoch is reasonable (after 2000, before 2100)
                    if 946684800 < epoch < 4102444800:
                        current_timestamp = datetime.utcfromtimestamp(epoch)  # UTC for consistency
                except (ValueError, OSError, OverflowError):
                    # Not a valid timestamp, might be a comment
                    pass
                continue
            
            # This is a command line
            command_index += 1
            
            # Determine timestamp for this command
            if current_timestamp:
                timestamp = current_timestamp
                timestamp_source = "exact"
                # Reset for next command (each command gets its own timestamp)
                current_timestamp = None
            else:
                # No timestamp available - estimate based on position in file
                # Assume commands span from file_mtime back some period
                # This is approximate but provides rough ordering
                timestamp = None
                timestamp_source = "none"
            
            # Skip very short or empty commands
            if len(line) < 2:
                continue
            
            # Determine if command is security-relevant
            security_keywords = [
                'sudo', 'su ', 'chmod', 'chown', 'passwd', 'useradd', 'userdel',
                'usermod', 'groupadd', 'wget', 'curl', 'nc ', 'netcat', 'ncat',
                'ssh ', 'scp ', 'rsync', 'tar ', 'zip', 'unzip', 'base64',
                'python', 'perl', 'ruby', 'bash', '/bin/sh', 'eval', 'exec',
                'crontab', 'at ', 'nohup', '&>', '/dev/null', '/dev/tcp',
                'iptables', 'firewall', 'ufw', 'setenforce', 'rm -rf',
                'dd if=', 'mkfs', 'mount', 'umount', 'fdisk', 'cryptsetup',
                'gpg', 'openssl', 'ssh-keygen', 'authorized_keys',
                '.ssh/', '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                'history', 'export ', 'alias ', 'source ', 'eval ',
            ]
            
            is_security_relevant = any(kw in line.lower() for kw in security_keywords)
            
            # Create event
            description = f"Command: {line[:150]}"
            if len(line) > 150:
                description += "..."
            
            if timestamp_source == "none":
                description = f"[undated] {description}"
            
            event = TimelineEvent(
                timestamp=timestamp if timestamp else file_mtime,
                event_type="BASH_HISTORY" if timestamp else "BASH_HISTORY_UNDATED",
                source_file=filepath,
                username=username,
                description=description,
                raw_data=line[:500]
            )
            events.append(event)
            
    except Exception as e:
        print(f"[!] Error parsing bash_history {filepath}: {e}", file=sys.stderr)
    
    return events


def find_history_files_in_tarball(handler) -> List[Tuple[str, str, Optional[datetime]]]:
    """
    Find all shell history files in a UAC tarball.
    
    Args:
        handler: UACTarballHandler instance
        
    Returns:
        List of tuples: (filepath, username, file_mtime)
    """
    history_files = []
    history_patterns = [
        '.bash_history',
        '.sh_history', 
        '.zsh_history',
        '.history',
        '.python_history',
        '.mysql_history',
        '.psql_history',
    ]
    
    for member in handler._members_cache:
        if member.isdir():
            continue
        
        name = member.name.replace("\\", "/")
        basename = os.path.basename(name)
        
        # Check if this is a history file
        if basename in history_patterns or basename.endswith('_history'):
            # Try to extract username from path
            # Typical paths: /root/.bash_history or /home/username/.bash_history
            username = ""
            parts = name.split("/")
            
            for j, part in enumerate(parts):
                if part == "root":
                    username = "root"
                    break
                elif part == "home" and j + 1 < len(parts):
                    username = parts[j + 1]
                    break
            
            # Get file modification time in UTC
            try:
                mtime = datetime.utcfromtimestamp(member.mtime)
            except (OSError, ValueError, OverflowError):
                mtime = None
            
            history_files.append((name, username, mtime))
    
    return history_files


# ============================================================================
# Main Timeline Generator
# ============================================================================

class LinuxLoginTimeline:
    """Main class to generate login/activity timeline from Linux logs."""
    
    def __init__(self, source_path: str = "/", is_tarball: bool = None):
        """
        Initialize the timeline generator.
        
        Args:
            source_path: Path to log files (directory, UAC tarball, or "/" for live system)
            is_tarball: Force tarball mode (auto-detected if None)
        """
        self.source_path = source_path
        self.events: List[TimelineEvent] = []
        self.stats = defaultdict(int)
        self.hostname = None
        
        # Auto-detect if source is a tarball
        if is_tarball is None:
            self.is_tarball = UACTarballHandler.is_tarball(source_path)
        else:
            self.is_tarball = is_tarball
        
        self.tarball_handler = None
        self.passwd_data = None
    
    def get_log_path(self, relative_path: str) -> str:
        """Get full path to a log file (directory mode only)."""
        # Handle both Unix and Windows paths
        if self.source_path.startswith("/"):
            return os.path.join(self.source_path, relative_path.lstrip("/"))
        else:
            # Windows path - convert forward slashes
            clean_path = relative_path.replace("/", os.sep).lstrip(os.sep)
            return os.path.join(self.source_path, clean_path)
    
    def _collect_from_tarball(self, verbose: bool = True) -> None:
        """
        Collect events from a UAC tarball.
        
        Args:
            verbose: Whether to print progress information
        """
        Style.enable_windows_ansi()
        
        with UACTarballHandler(self.source_path, verbose=verbose) as handler:
            self.tarball_handler = handler
            self.hostname = handler.hostname
            
            # Try to get passwd file for username resolution
            passwd_paths = [
                f"{handler.var_log_prefix}etc/passwd",
                "etc/passwd",
            ]
            for passwd_path in passwd_paths:
                self.passwd_data = handler.extract_file(passwd_path)
                if self.passwd_data:
                    if verbose:
                        print(f"{Style.INFO}Found passwd file for username resolution{Style.RESET}", file=sys.stderr)
                    break
            
            # Define log sources with their parser functions
            log_sources = [
                # (base_pattern, parser_factory, description, is_binary)
                ("btmp", lambda: "btmp", "btmp (failed logins)", True),
                ("utmp", lambda: "utmp", "utmp (current logins)", True),
                ("wtmp", lambda: "wtmp", "wtmp (login history)", True),
                ("lastlog", lambda: "lastlog", "lastlog", True),
                ("auth.log", lambda: "auth", "auth.log", False),
                ("secure", lambda: "auth", "secure", False),
                ("audit.log", lambda: "audit", "audit.log", False),
                ("messages", lambda: "syslog", "messages", False),
                ("syslog", lambda: "syslog", "syslog", False),
            ]
            
            for base_pattern, log_type_factory, description, is_binary in log_sources:
                if verbose:
                    print(f"\n{Style.INFO}Processing {description}...{Style.RESET}", file=sys.stderr)
                
                # Find matching files
                if base_pattern == "audit.log":
                    files = handler.find_audit_logs()
                else:
                    files = handler.find_log_files(base_pattern)
                
                if not files:
                    if verbose:
                        print(f"  {Style.DIM}No files found{Style.RESET}", file=sys.stderr)
                    continue
                
                for filepath in files:
                    if verbose:
                        print(f"  {Style.SUCCESS}[+] Parsing:{Style.RESET} {os.path.basename(filepath)}", file=sys.stderr)
                    
                    try:
                        # Extract file data
                        data = handler.extract_file(filepath)
                        if data is None:
                            continue
                        
                        # Parse based on log type
                        log_type = log_type_factory()
                        
                        if log_type in ("btmp", "utmp", "wtmp"):
                            file_events = parse_utmp_file(filepath, log_type, data=data)
                        elif log_type == "lastlog":
                            file_events = parse_lastlog(filepath, data=data, passwd_data=self.passwd_data)
                        elif log_type == "auth":
                            file_events = parse_auth_log(filepath, data=data)
                        elif log_type == "audit":
                            file_events = parse_audit_log(filepath, data=data)
                        elif log_type == "syslog":
                            file_events = parse_syslog_messages(filepath, data=data)
                        else:
                            continue
                        
                        self.events.extend(file_events)
                        self.stats[description] += len(file_events)
                        
                        if verbose:
                            print(f"      Found {Style.GREEN}{len(file_events)}{Style.RESET} events", file=sys.stderr)
                            
                    except Exception as e:
                        print(f"  {Style.ERROR}[!] Error:{Style.RESET} {e}", file=sys.stderr)
            
            # Process bash history files
            if verbose:
                print(f"\n{Style.INFO}Processing bash_history files...{Style.RESET}", file=sys.stderr)
            
            history_files = find_history_files_in_tarball(handler)
            
            if not history_files:
                if verbose:
                    print(f"  {Style.DIM}No history files found{Style.RESET}", file=sys.stderr)
            else:
                for filepath, username, mtime in history_files:
                    if verbose:
                        user_info = f" ({username})" if username else ""
                        print(f"  {Style.SUCCESS}[+] Parsing:{Style.RESET} {os.path.basename(filepath)}{user_info}", file=sys.stderr)
                    
                    try:
                        data = handler.extract_file(filepath)
                        if data is None:
                            continue
                        
                        file_events = parse_bash_history(
                            filepath, 
                            data=data, 
                            username=username,
                            file_mtime=mtime
                        )
                        
                        # Only count events with timestamps as "bash_history"
                        dated_events = [e for e in file_events if e.event_type == "BASH_HISTORY"]
                        undated_events = [e for e in file_events if e.event_type == "BASH_HISTORY_UNDATED"]
                        
                        self.events.extend(file_events)
                        self.stats["bash_history (dated)"] += len(dated_events)
                        self.stats["bash_history (undated)"] += len(undated_events)
                        
                        if verbose:
                            if dated_events:
                                print(f"      Found {Style.GREEN}{len(dated_events)}{Style.RESET} dated commands", file=sys.stderr)
                            if undated_events:
                                print(f"      Found {Style.YELLOW}{len(undated_events)}{Style.RESET} undated commands", file=sys.stderr)
                                
                    except Exception as e:
                        print(f"  {Style.ERROR}[!] Error:{Style.RESET} {e}", file=sys.stderr)
        
        # Sort events by timestamp
        self.events.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min)
        
        if verbose:
            print(f"\n{Style.HEADER}{'='*50}{Style.RESET}", file=sys.stderr)
            print(f"{Style.SUCCESS}Total events collected: {len(self.events)}{Style.RESET}", file=sys.stderr)
            print(f"\n{Style.INFO}Events by source:{Style.RESET}", file=sys.stderr)
            for source, count in sorted(self.stats.items()):
                print(f"  {source}: {count}", file=sys.stderr)
    
    def _collect_from_directory(self, verbose: bool = True) -> None:
        """
        Collect events from a directory (extracted UAC or live system).
        
        Args:
            verbose: Whether to print progress information
        """
        Style.enable_windows_ansi()
        
        var_log = self.get_log_path("var/log")
        
        # Also check if this is an extracted UAC with nested structure
        # Try to find var/log in subdirectories
        if not os.path.exists(var_log):
            for root, dirs, files in os.walk(self.source_path):
                if "var" in dirs:
                    potential_var_log = os.path.join(root, "var", "log")
                    if os.path.exists(potential_var_log):
                        var_log = potential_var_log
                        if verbose:
                            print(f"{Style.INFO}Found var/log at:{Style.RESET} {var_log}", file=sys.stderr)
                        break
        
        # Try to get passwd for username resolution
        passwd_path = self.get_log_path("etc/passwd")
        if os.path.exists(passwd_path):
            try:
                with open(passwd_path, 'rb') as f:
                    self.passwd_data = f.read()
                if verbose:
                    print(f"{Style.INFO}Found passwd file for username resolution{Style.RESET}", file=sys.stderr)
            except Exception:
                pass
        
        # Define log sources and their parsers
        log_sources = [
            # Binary logs
            ("btmp", lambda f, d=None: parse_utmp_file(f, "btmp", data=d), "btmp (failed logins)"),
            ("utmp", lambda f, d=None: parse_utmp_file(f, "utmp", data=d), "utmp (current logins)"),
            ("wtmp", lambda f, d=None: parse_utmp_file(f, "wtmp", data=d), "wtmp (login history)"),
            ("lastlog", lambda f, d=None: parse_lastlog(f, data=d, passwd_data=self.passwd_data), "lastlog"),
            
            # Text logs
            ("auth.log", lambda f, d=None: parse_auth_log(f, data=d), "auth.log"),
            ("secure", lambda f, d=None: parse_auth_log(f, data=d), "secure"),
            ("audit/audit.log", lambda f, d=None: parse_audit_log(f, data=d), "audit.log"),
            ("messages", lambda f, d=None: parse_syslog_messages(f, data=d), "messages"),
            ("syslog", lambda f, d=None: parse_syslog_messages(f, data=d), "syslog"),
        ]
        
        for base_pattern, parser, description in log_sources:
            if verbose:
                print(f"\n{Style.INFO}Processing {description}...{Style.RESET}", file=sys.stderr)
            
            # Find matching files
            if "/" in base_pattern:
                subdir, file_pattern = base_pattern.rsplit("/", 1)
                search_path = os.path.join(var_log, subdir)
            else:
                search_path = var_log
                file_pattern = base_pattern
            
            files = find_log_files(search_path, file_pattern) if os.path.exists(search_path) else []
            
            # Also check for exact match
            exact_path = os.path.join(var_log, base_pattern)
            if os.path.exists(exact_path) and exact_path not in files:
                files.insert(0, exact_path)
            
            if not files:
                if verbose:
                    print(f"  {Style.DIM}No files found{Style.RESET}", file=sys.stderr)
                continue
            
            for filepath in files:
                if not os.path.exists(filepath):
                    continue
                    
                if verbose:
                    print(f"  {Style.SUCCESS}[+] Parsing:{Style.RESET} {filepath}", file=sys.stderr)
                
                try:
                    file_events = parser(filepath)
                    self.events.extend(file_events)
                    self.stats[description] += len(file_events)
                    
                    if verbose:
                        print(f"      Found {Style.GREEN}{len(file_events)}{Style.RESET} events", file=sys.stderr)
                except Exception as e:
                    print(f"  {Style.ERROR}[!] Error:{Style.RESET} {e}", file=sys.stderr)
        
        # Sort events by timestamp
        self.events.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min)
        
        if verbose:
            print(f"\n{Style.HEADER}{'='*50}{Style.RESET}", file=sys.stderr)
            print(f"{Style.SUCCESS}Total events collected: {len(self.events)}{Style.RESET}", file=sys.stderr)
            print(f"\n{Style.INFO}Events by source:{Style.RESET}", file=sys.stderr)
            for source, count in sorted(self.stats.items()):
                print(f"  {source}: {count}", file=sys.stderr)
    
    def collect_events(self, verbose: bool = True) -> None:
        """
        Collect events from all log sources.
        
        Args:
            verbose: Whether to print progress information
        """
        Style.enable_windows_ansi()
        
        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}  Linux Login Timeline Extractor{Style.RESET}", file=sys.stderr)
            print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
            print(f"\n{Style.INFO}Source:{Style.RESET} {self.source_path}", file=sys.stderr)
            print(f"{Style.INFO}Mode:{Style.RESET} {'UAC Tarball' if self.is_tarball else 'Directory/Filesystem'}", file=sys.stderr)
        
        if self.is_tarball:
            self._collect_from_tarball(verbose)
        else:
            self._collect_from_directory(verbose)
    
    def export_csv(self, output_path: str) -> None:
        """
        Export timeline to CSV file.
        
        Args:
            output_path: Path to output CSV file
        """
        fieldnames = [
            "Timestamp",
            "Timestamp_Local",
            "event_type",
            "username",
            "source_ip",
            "terminal",
            "pid",
            "description",
            "source_file",
            "raw_data"
        ]
        
        # Create output directory if needed
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # If output_path is a directory, create a filename inside it
        if os.path.isdir(output_path):
            if self.hostname:
                filename = f"{self.hostname}_login_timeline.csv"
            else:
                filename = "login_timeline.csv"
            output_path = os.path.join(output_path, filename)
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for event in self.events:
                writer.writerow(event.to_dict())
        
        print(f"\n{Style.SUCCESS}Timeline exported to:{Style.RESET} {output_path}", file=sys.stderr)
        print(f"{Style.INFO}Total events:{Style.RESET} {len(self.events)}", file=sys.stderr)
    
    def print_summary(self) -> None:
        """Print a summary of collected events."""
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
        print(f"{Style.HEADER}{Style.BOLD}  LOGIN/ACTIVITY TIMELINE SUMMARY{Style.RESET}")
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
        
        # Event type counts
        event_types = defaultdict(int)
        users = defaultdict(int)
        source_ips = defaultdict(int)
        
        for event in self.events:
            event_types[event.event_type] += 1
            if event.username:
                users[event.username] += 1
            if event.source_ip:
                source_ips[event.source_ip] += 1
        
        if self.hostname:
            print(f"\n{Style.INFO}Hostname:{Style.RESET} {self.hostname}")
        
        print(f"\n{Style.INFO}Total Events:{Style.RESET} {Style.GREEN}{len(self.events)}{Style.RESET}")
        
        if self.events:
            first_ts = self.events[0].timestamp
            last_ts = self.events[-1].timestamp
            print(f"{Style.INFO}Time Range:{Style.RESET} {first_ts} to {last_ts}")
            if first_ts and last_ts:
                duration = last_ts - first_ts
                print(f"{Style.INFO}Duration:{Style.RESET} {duration.days} days, {duration.seconds // 3600} hours")
        
        print(f"\n{Style.CYAN}Event Types:{Style.RESET}")
        for event_type, count in sorted(event_types.items(), key=lambda x: -x[1])[:15]:
            # Color-code certain event types
            if "FAIL" in event_type or "INVALID" in event_type:
                print(f"  {Style.RED}{event_type}: {count}{Style.RESET}")
            elif "LOGIN" in event_type or "SUCCESS" in event_type:
                print(f"  {Style.GREEN}{event_type}: {count}{Style.RESET}")
            elif "SUDO" in event_type or "SU_" in event_type:
                print(f"  {Style.YELLOW}{event_type}: {count}{Style.RESET}")
            else:
                print(f"  {event_type}: {count}")
        
        if len(event_types) > 15:
            print(f"  {Style.DIM}... and {len(event_types) - 15} more types{Style.RESET}")
        
        print(f"\n{Style.CYAN}Top Users (by activity):{Style.RESET}")
        for user, count in sorted(users.items(), key=lambda x: -x[1])[:10]:
            # Highlight root/admin users
            if user in ("root", "admin", "administrator"):
                print(f"  {Style.RED}{user}: {count}{Style.RESET}")
            else:
                print(f"  {user}: {count}")
        
        if source_ips:
            print(f"\n{Style.CYAN}Top Source IPs (lateral movement indicators):{Style.RESET}")
            for ip, count in sorted(source_ips.items(), key=lambda x: -x[1])[:10]:
                # Highlight external IPs
                if not ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", 
                                      "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                                      "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                                      "172.29.", "172.30.", "172.31.", "127.")):
                    print(f"  {Style.YELLOW}{ip}: {count} (external){Style.RESET}")
                else:
                    print(f"  {ip}: {count}")
        
        print(f"\n{Style.HEADER}{'='*60}{Style.RESET}")


# ============================================================================
# Batch Processing
# ============================================================================

def process_batch(
    source_dir: str, 
    output_dir: str, 
    verbose: bool = True,
    summary: bool = False
) -> Dict[str, int]:
    """
    Process all UAC tarballs in a directory.
    
    Args:
        source_dir: Directory containing UAC tarballs
        output_dir: Directory to write timeline CSVs
        verbose: Print progress
        summary: Print summary for each tarball
        
    Returns:
        Dictionary with processing statistics
    """
    Style.enable_windows_ansi()
    
    # Resolve paths
    source_dir = resolve_path(source_dir)
    output_dir = resolve_path(output_dir)
    
    stats = {
        "processed": 0,
        "failed": 0,
        "total_events": 0
    }
    
    # Find all tarballs
    tarballs = []
    for ext in UACTarballHandler.TAR_EXTENSIONS:
        tarballs.extend(glob.glob(os.path.join(source_dir, f"*{ext}")))
    
    if not tarballs:
        print(f"{Style.WARNING}No UAC tarballs found in {source_dir}{Style.RESET}", file=sys.stderr)
        return stats
    
    print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
    print(f"{Style.HEADER}{Style.BOLD}  Batch Processing {len(tarballs)} UAC Tarballs{Style.RESET}", file=sys.stderr)
    print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    for i, tarball_path in enumerate(sorted(tarballs), 1):
        tarball_name = os.path.basename(tarball_path)
        print(f"\n{Style.INFO}[{i}/{len(tarballs)}] Processing:{Style.RESET} {tarball_name}", file=sys.stderr)
        
        try:
            # Create timeline
            timeline = LinuxLoginTimeline(source_path=tarball_path)
            timeline.collect_events(verbose=verbose)
            
            # Generate output filename
            base_name = tarball_name
            for ext in UACTarballHandler.TAR_EXTENSIONS:
                if base_name.lower().endswith(ext):
                    base_name = base_name[:-len(ext)]
                    break
            
            if timeline.hostname:
                output_name = f"{timeline.hostname}_timeline.csv"
            else:
                output_name = f"{base_name}_timeline.csv"
            
            output_path = os.path.join(output_dir, output_name)
            
            # Export
            timeline.export_csv(output_path)
            
            if summary:
                timeline.print_summary()
            
            stats["processed"] += 1
            stats["total_events"] += len(timeline.events)
            
        except Exception as e:
            print(f"{Style.ERROR}[!] Failed to process {tarball_name}: {e}{Style.RESET}", file=sys.stderr)
            stats["failed"] += 1
    
    # Print batch summary
    print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
    print(f"{Style.HEADER}{Style.BOLD}  Batch Processing Complete{Style.RESET}", file=sys.stderr)
    print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}", file=sys.stderr)
    print(f"\n  {Style.SUCCESS}Processed:{Style.RESET} {stats['processed']}", file=sys.stderr)
    print(f"  {Style.ERROR}Failed:{Style.RESET} {stats['failed']}", file=sys.stderr)
    print(f"  {Style.INFO}Total events:{Style.RESET} {stats['total_events']}", file=sys.stderr)
    print(f"  {Style.INFO}Output directory:{Style.RESET} {output_dir}", file=sys.stderr)
    
    return stats


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Extract and timeline Linux login/authentication events from UAC tarballs or directories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

Examples:
  # Parse logs from a UAC tarball (auto-detected)
  python linux_login_timeline.py -s hostname_2024-12-17.tar.gz -o timeline.csv
  
  # Parse logs from extracted UAC directory
  python linux_login_timeline.py -s ./extracted_uac/ -o timeline.csv
  
  # Parse logs from live Linux system
  python linux_login_timeline.py -o timeline.csv
  
  # Parse logs from mounted disk image
  python linux_login_timeline.py -s /mnt/evidence/disk1 -o timeline.csv
  
  # Parse with summary statistics
  python linux_login_timeline.py -s evidence.tar.gz -o timeline.csv --summary
  
  # Batch process all UAC tarballs in a directory
  python linux_login_timeline.py --batch ./extracted_uac/ -o ./timelines/

Supported Input:
  - UAC (Unix-like Artifacts Collector) tarballs (.tar, .tar.gz, .tgz, .tar.bz2)
  - Extracted UAC directories
  - Mounted disk images
  - Live Linux filesystem

Supported log files:
  - /var/log/btmp*        Failed login attempts (binary)
  - /var/log/utmp         Current logins (binary)
  - /var/log/wtmp*        Login history (binary)
  - /var/log/lastlog      Last login for each user (binary)
  - /var/log/auth.log*    Authentication logs (Debian/Ubuntu)
  - /var/log/secure*      Authentication logs (RHEL/CentOS)
  - /var/log/audit/audit.log*  Audit logs
  - /var/log/messages*    Syslog messages
  - /var/log/syslog*      System log
  
All rotated logs (*.1, *.2, etc.) and gzipped versions (*.gz) are automatically included.

Note: This script can be run from any directory. All relative paths are resolved
from your current working directory. Uses Python standard library only (no pip install).
        """
    )
    
    parser.add_argument(
        "-s", "--source",
        default="/",
        help="Source path: UAC tarball (.tar, .tar.gz), extracted directory, or '/' for live system"
    )
    
    # Keep -b as alias for backwards compatibility
    parser.add_argument(
        "-b", "--base-path",
        dest="source",
        help=argparse.SUPPRESS  # Hidden, use -s instead
    )
    
    parser.add_argument(
        "-o", "--output",
        default="login_timeline.csv",
        help="Output CSV file path (default: login_timeline.csv)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output"
    )
    
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary of collected events"
    )
    
    parser.add_argument(
        "--tarball",
        action="store_true",
        help="Force tarball mode (auto-detected by default)"
    )
    
    parser.add_argument(
        "--directory",
        action="store_true",
        help="Force directory mode (auto-detected by default)"
    )
    
    parser.add_argument(
        "--batch",
        metavar="DIR",
        help="Batch mode: process all UAC tarballs in specified directory"
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    
    args = parser.parse_args()
    
    # Handle batch mode
    if args.batch:
        batch_dir = resolve_path(args.batch)
        if not os.path.isdir(batch_dir):
            print(f"{Style.ERROR}Error: Batch directory does not exist:{Style.RESET} {batch_dir}", file=sys.stderr)
            return 1
        
        # In batch mode, -o specifies output directory
        output_dir = resolve_path(args.output) if args.output != "login_timeline.csv" else resolve_path("./timelines")
        
        stats = process_batch(
            source_dir=batch_dir,
            output_dir=output_dir,
            verbose=not args.quiet,
            summary=args.summary
        )
        
        return 0 if stats["failed"] == 0 else 1
    
    # Resolve source path (handle relative paths from anywhere)
    source_path = args.source
    if source_path != "/":
        source_path = resolve_path(source_path)
    
    # Validate source exists
    if source_path != "/" and not os.path.exists(source_path):
        print(f"{Style.ERROR}Error: Source path does not exist:{Style.RESET} {source_path}", file=sys.stderr)
        return 1
    
    # Determine mode
    is_tarball = None
    if args.tarball:
        is_tarball = True
    elif args.directory:
        is_tarball = False
    
    # Create timeline generator
    timeline = LinuxLoginTimeline(source_path=source_path, is_tarball=is_tarball)
    
    # Collect events
    timeline.collect_events(verbose=not args.quiet)
    
    # Generate output filename with hostname if available
    output_path = args.output
    if timeline.hostname and output_path == "login_timeline.csv":
        output_path = f"{timeline.hostname}_login_timeline.csv"
    
    # Resolve output path (handle relative paths)
    output_path = resolve_path(output_path)
    
    # Export to CSV
    timeline.export_csv(output_path)
    
    # Print summary if requested
    if args.summary:
        timeline.print_summary()
    
    return 0


if __name__ == "__main__":
    # Verify Python version
    if sys.version_info < (3, 6):
        print("Error: This script requires Python 3.6 or higher.", file=sys.stderr)
        print(f"Current version: {sys.version}", file=sys.stderr)
        sys.exit(1)
    
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        import traceback
        print(f"\nUnexpected error: {e}", file=sys.stderr)
        print("\nFull traceback:", file=sys.stderr)
        traceback.print_exc()
        print("\nPlease report this issue with the full error message.", file=sys.stderr)
        sys.exit(1)

