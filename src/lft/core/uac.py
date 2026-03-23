"""
Shared UAC (Unix-like Artifacts Collector) handler for the Linux Forensics Toolkit.

Provides uniform read-only access to forensic collections stored as:
  - .tar.gz / .tgz / .tar.bz2 / .tbz2 / .tar.xz / .tar files
  - Extracted directories

Includes built-in coverage tracking so analysts can see exactly which
files and paths were examined during analysis.

Zero external dependencies (stdlib only).
"""

import gzip
import hashlib
import io
import logging
import os
import re
import shutil
import tarfile
import tempfile
import csv
from typing import Any, Dict, Iterator, List, Optional, Tuple

from lft.core.errors import SourceCorruptError

logger = logging.getLogger(__name__)

__version__ = "2.1.0"


# ============================================================================
# Unmatched Line Capture
# ============================================================================

class UnmatchedWriter:
    """Collects log lines that fail regex parsing, exports as CSV.

    Ensures nothing is invisible — every line that doesn't match a known
    format is captured so analysts can review what was skipped.
    """

    def __init__(self):
        self._lines: List[Tuple[str, int, str]] = []

    def add(self, source_file: str, line_number: int, raw_line: str):
        """Record a line that didn't match any expected pattern."""
        self._lines.append((source_file, line_number, raw_line))

    def export_csv(self, output_path: str) -> Optional[str]:
        """Write unmatched lines to CSV.  Returns path or None if empty."""
        if not self._lines:
            return None
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["Source_File", "Line_Number", "Raw_Line"])
            w.writeheader()
            for src, num, raw in self._lines:
                w.writerow({"Source_File": src, "Line_Number": num,
                            "Raw_Line": raw[:2000]})
        return output_path

    @property
    def count(self) -> int:
        return len(self._lines)


# ============================================================================
# Path Security
# ============================================================================

def is_safe_path(base_path: str, target_path: str) -> bool:
    """
    OWASP A03/A08: Validate that target_path is within base_path.
    Prevents path traversal attacks (zip slip, tar slip).
    """
    try:
        base = os.path.abspath(base_path)
        target = os.path.abspath(target_path)
        common = os.path.commonpath([base, target])
        return common == base
    except ValueError:
        return False


def safe_extract_member(tar: tarfile.TarFile, member: tarfile.TarInfo,
                        dest_dir: str) -> Optional[str]:
    """
    OWASP A08: Safely extract a tar member to disk, preventing tar slip.

    Returns:
        Path to extracted file, or None if unsafe/skipped.
    """
    member_path = os.path.join(dest_dir, member.name)
    abs_dest = os.path.abspath(dest_dir)
    abs_member = os.path.abspath(member_path)

    if not is_safe_path(abs_dest, abs_member):
        raise ValueError(f"Attempted path traversal in tar: {member.name}")

    if member.issym() or member.islnk():
        return None

    tar.extract(member, dest_dir)
    return member_path


def safe_read_member(tar: tarfile.TarFile, member: tarfile.TarInfo,
                     extract_path: str = "/tmp") -> Optional[bytes]:
    """
    OWASP A08: Safely read a tar member into memory (no disk extraction).

    Returns:
        File contents as bytes, or None if unsafe/unreadable.
    """
    member_path = os.path.normpath(member.name)
    if member_path.startswith('..') or member_path.startswith('/'):
        member_path = member_path.lstrip('/')
        while member_path.startswith('../'):
            member_path = member_path[3:]

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


def calculate_hashes(data: bytes) -> Tuple[str, str]:
    """Calculate MD5 and SHA256 hashes. Returns (md5_hex, sha256_hex)."""
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


# ============================================================================
# Coverage Tracking
# ============================================================================

class CoverageEntry:
    """A single coverage record: what was searched for and what was found."""

    __slots__ = ('category', 'expected', 'status', 'actual', 'details')

    def __init__(self, category: str, expected: str, status: str,
                 actual: str = "", details: str = ""):
        self.category = category
        self.expected = expected
        self.status = status      # FOUND / NOT_FOUND / ERROR / PARTIAL
        self.actual = actual
        self.details = details

    def to_dict(self) -> Dict[str, str]:
        return {
            "category": self.category,
            "expected": self.expected,
            "status": self.status,
            "actual": self.actual,
            "details": self.details,
        }


# ============================================================================
# Unified UAC Handler
# ============================================================================

class UACHandler:
    """
    Unified handler for UAC tarballs and extracted directories.

    Supports three usage patterns used across the toolkit:

    **Family A** (journal, persistence, security analyzers):
        handler = UACHandler(source)
        data = handler.get_file("/etc/passwd")
        for path, member in handler.find_files_by_pattern([r"/var/log/", "auth.log"]):
            ...
        entries = handler.list_directory("/etc/cron.d")

    **Family B** (network, package analyzers):
        handler = UACHandler(source)
        for path, text in handler.find_files_by_suffix(["**/resolv.conf", "*/hosts"]):
            ...

    **Family C** (login timeline — context manager, temp files):
        with UACHandler(source, verbose=True) as handler:
            files = handler.find_log_files("auth.log")
            data = handler.extract_file(files[0])
            handle = handler.get_file_handle(files[0])
    """

    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz')

    def __init__(self, source_path: str, verbose: bool = False):
        self.source_path = os.path.abspath(source_path) if source_path else ""
        self.verbose = verbose
        self.is_tarball = self._check_tarball(source_path)
        self.tar: Optional[tarfile.TarFile] = None
        self.hostname: Optional[str] = None

        # Internal state
        self._root_prefix = ""
        self._var_log_prefix: Optional[str] = None
        self._members_cache: Optional[List[tarfile.TarInfo]] = None
        self._member_dict: Dict[str, tarfile.TarInfo] = {}
        self._temp_dir: Optional[str] = None

        # Coverage tracking
        self._coverage: List[CoverageEntry] = []

        # Auto-open (Family A/B pattern — open in __init__)
        if self.is_tarball and os.path.isfile(source_path):
            self._open_tarball()
        elif source_path and os.path.isdir(source_path):
            self._detect_hostname_from_dir()

    # ------------------------------------------------------------------
    # Context manager support (Family C)
    # ------------------------------------------------------------------

    def __enter__(self):
        if self.is_tarball and self.tar is None:
            self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        """Open the tarball and detect structure (Family C explicit open)."""
        if self.tar is not None:
            return
        if self.is_tarball:
            self._open_tarball()

    def close(self):
        """Close the tarball and clean up temp files."""
        if self.tar:
            try:
                self.tar.close()
            except Exception:
                pass
            self.tar = None
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    # ------------------------------------------------------------------
    # Coverage API
    # ------------------------------------------------------------------

    def add_coverage(self, category: str, expected: str, status: str,
                     actual: str = "", details: str = ""):
        """Record a coverage entry (called by analyzers for semantic context)."""
        self._coverage.append(CoverageEntry(category, expected, status, actual, details))

    def get_coverage(self) -> List[Dict[str, str]]:
        """Return all coverage entries as a list of dicts."""
        return [e.to_dict() for e in self._coverage]

    # ------------------------------------------------------------------
    # Family A: get_file / find_files_by_pattern / list_directory
    # ------------------------------------------------------------------

    def get_file(self, filepath: str) -> Optional[bytes]:
        """
        Get raw file contents by path.

        Tries multiple path combinations to handle varying UAC structures.
        Automatically decompresses .gz files.
        """
        if self.is_tarball and self.tar:
            return self._get_file_tarball(filepath)
        elif os.path.isdir(self.source_path):
            return self._get_file_directory(filepath)
        return None

    def find_files_by_pattern(self, patterns: List[str]
                              ) -> List[Tuple[str, Any]]:
        """
        Find files matching substring or regex patterns.

        Returns list of (normalized_path, tarinfo_or_filepath).
        For tarballs: (path, TarInfo). For directories: (rel_path, abs_path).
        """
        if self.is_tarball and self.tar:
            return self._find_pattern_tarball(patterns)
        elif os.path.isdir(self.source_path):
            return self._find_pattern_directory(patterns)
        return []

    # Convenience alias — several analyzers use the shorter name.
    find_files = find_files_by_pattern

    def list_directory(self, dirpath: str) -> List[str]:
        """List immediate children of a directory."""
        dirpath = dirpath.rstrip('/')
        if self.is_tarball:
            return self._list_dir_tarball(dirpath)
        else:
            return self._list_dir_directory(dirpath)

    def get_members(self) -> List:
        """Get all tarball members (empty list for directories)."""
        if self.is_tarball and self._members_cache is not None:
            return self._members_cache
        return []

    # ------------------------------------------------------------------
    # Family B: find_files_by_suffix (returns text content)
    # ------------------------------------------------------------------

    def find_files_by_suffix(self, suffixes: List[str]) -> List[Tuple[str, str]]:
        """
        Find files by suffix/glob pattern and return text content.

        Supports patterns like:
          "**/resolv.conf"  — match anywhere in path
          "*/hosts"         — match with one directory prefix
          "dpkg.log"        — exact filename match

        Returns list of (relative_path, text_content).
        """
        if self.is_tarball:
            return self._find_suffix_tarball(suffixes)
        return self._find_suffix_directory(suffixes)

    # ------------------------------------------------------------------
    # Family C: log-file operations (login timeline)
    # ------------------------------------------------------------------

    @property
    def var_log_prefix(self) -> str:
        """The detected prefix path before var/log/ in the tarball."""
        if self._var_log_prefix is None:
            self._var_log_prefix = ""
        return self._var_log_prefix

    def get_var_log_path(self, relative_path: str) -> str:
        """Get the full tarball path for a var/log relative path."""
        return f"{self.var_log_prefix}var/log/{relative_path}"

    def list_log_files(self, pattern: str = "") -> List[str]:
        """List all log files matching a pattern under var/log/."""
        matches = []
        if not self._members_cache:
            return matches

        var_log_path = f"{self.var_log_prefix}var/log/"
        for member in self._members_cache:
            name = member.name.replace("\\", "/")
            if name.startswith(var_log_path) or "/var/log/" in name:
                if not pattern or pattern in os.path.basename(name):
                    if not member.isdir():
                        matches.append(name)
        return sorted(matches)

    def find_log_files(self, base_pattern: str) -> List[str]:
        """
        Find all log files matching a base pattern (including rotated/gzipped).

        Example: find_log_files("auth.log") matches auth.log, auth.log.1,
        auth.log.2.gz, etc.
        """
        matches = []
        if not self._members_cache:
            return matches

        var_log_path = f"{self.var_log_prefix}var/log/"
        for member in self._members_cache:
            if member.isdir():
                continue
            name = member.name.replace("\\", "/")
            basename = os.path.basename(name)
            if var_log_path in name or "/var/log/" in name:
                if basename == base_pattern or basename.startswith(f"{base_pattern}."):
                    matches.append(name)
        return sorted(matches)

    def find_audit_logs(self) -> List[str]:
        """Find all audit log files."""
        matches = []
        if not self._members_cache:
            return matches

        for member in self._members_cache:
            if member.isdir():
                continue
            name = member.name.replace("\\", "/")
            if "/audit/audit.log" in name or name.endswith("/audit.log"):
                matches.append(name)
            elif "/audit/audit.log." in name:
                matches.append(name)
        return sorted(matches)

    def extract_file(self, member_path: str) -> Optional[bytes]:
        """
        Extract a file's contents from the tarball by member path.

        Automatically decompresses .gz files.
        """
        if not self.tar:
            return None
        try:
            member = self.tar.getmember(member_path)
            f = self.tar.extractfile(member)
            if f:
                data = f.read()
                f.close()
                if member_path.endswith('.gz'):
                    try:
                        data = gzip.decompress(data)
                    except gzip.BadGzipFile:
                        pass
                return data
        except KeyError:
            pass
        except Exception as e:
            logger.warning("Could not extract %s: %s", member_path, e)
        return None

    def extract_file_to_temp(self, member_path: str) -> Optional[str]:
        """
        Extract a file to a temporary directory on disk.

        OWASP A08: Uses safe extraction to prevent tar slip attacks.

        Returns:
            Path to extracted file, or None if failed.
        """
        if not self.tar:
            return None

        if not self._temp_dir:
            self._temp_dir = tempfile.mkdtemp(prefix="lft_uac_")

        try:
            member = self.tar.getmember(member_path)
            return safe_extract_member(self.tar, member, self._temp_dir)
        except ValueError:
            logger.error("Security: Blocked path traversal: %s", member_path)
        except (KeyError, tarfile.TarError, OSError) as e:
            logger.warning("Could not extract %s: %s", member_path, e)
        return None

    def get_file_handle(self, member_path: str, binary: bool = False) -> Optional[io.IOBase]:
        """Get a file-like object for reading from the tarball."""
        data = self.extract_file(member_path)
        if data is None:
            return None
        if binary:
            return io.BytesIO(data)
        return io.StringIO(data.decode('utf-8', errors='replace'))

    @staticmethod
    def is_tarball_path(path: str) -> bool:
        """Check if a path looks like a UAC tarball by extension."""
        return any(path.lower().endswith(ext) for ext in UACHandler.TAR_EXTENSIONS)

    # ------------------------------------------------------------------
    # Internal: tarball opening and structure detection
    # ------------------------------------------------------------------

    @staticmethod
    def _check_tarball(path: str) -> bool:
        if not path:
            return False
        return any(path.lower().endswith(ext) for ext in UACHandler.TAR_EXTENSIONS)

    def _open_tarball(self):
        """Open the tarball file and detect internal structure."""
        try:
            sp = self.source_path.lower()
            if sp.endswith(('.gz', '.tgz')):
                self.tar = tarfile.open(self.source_path, 'r:gz')
            elif sp.endswith(('.bz2', '.tbz2')):
                self.tar = tarfile.open(self.source_path, 'r:bz2')
            elif sp.endswith('.xz'):
                self.tar = tarfile.open(self.source_path, 'r:xz')
            else:
                self.tar = tarfile.open(self.source_path, 'r:')

            self._members_cache = self.tar.getmembers()
            self._member_dict = {m.name: m for m in self._members_cache}
            self._detect_structure()
        except tarfile.ReadError:
            # Fallback: try auto-detect compression
            try:
                self.tar = tarfile.open(self.source_path, 'r:*')
                self._members_cache = self.tar.getmembers()
                self._member_dict = {m.name: m for m in self._members_cache}
                self._detect_structure()
            except Exception as e:
                raise SourceCorruptError(f"Failed to open tarball: {e}") from e
        except Exception as e:
            raise SourceCorruptError(f"Failed to open tarball: {e}") from e

    def _detect_structure(self):
        """Detect the UAC directory structure, root prefix, and hostname."""
        if not self._members_cache:
            return

        # Find var/log prefix
        for member in self._members_cache:
            name = member.name.replace("\\", "/")
            if "/var/log/" in name or name.startswith("var/log/"):
                idx = name.find("var/log/")
                self._var_log_prefix = name[:idx] if idx > 0 else ""
                break

        # Find root prefix (for /var/ or /etc/)
        for member in self._members_cache[:200]:
            name = member.name.replace("\\", "/")
            if '/var/' in name or '/etc/' in name:
                idx = name.find('/var/') if '/var/' in name else name.find('/etc/')
                if idx > 0:
                    self._root_prefix = name[:idx]
                break

        # If var_log_prefix not found, try auth.log / secure / wtmp
        if self._var_log_prefix is None:
            for member in self._members_cache:
                name = member.name.replace("\\", "/")
                if "auth.log" in name or "secure" in name or "wtmp" in name:
                    parts = name.split("/")
                    if "log" in parts:
                        log_idx = parts.index("log")
                        if log_idx >= 1 and parts[log_idx - 1] == "var":
                            self._var_log_prefix = "/".join(parts[:log_idx - 1])
                            if self._var_log_prefix:
                                self._var_log_prefix += "/"
                            break
            if self._var_log_prefix is None:
                self._var_log_prefix = ""

        # Extract hostname
        self._detect_hostname()

    def _detect_hostname(self):
        """Extract hostname from tarball structure or filename."""
        # Try from path prefix
        prefix = self._root_prefix or self._var_log_prefix or ""
        if prefix:
            parts = prefix.strip('/').split('/')
            if parts and parts[0]:
                self.hostname = parts[0]
                return

        # Try from tarball filename
        if self.source_path:
            basename = os.path.basename(self.source_path)
            for ext in self.TAR_EXTENSIONS:
                if basename.lower().endswith(ext):
                    basename = basename[:-len(ext)]
                    break
            for sep in ['-uac', '_uac', '-', '_', '.']:
                if sep in basename.lower():
                    self.hostname = basename.split(sep)[0]
                    return
            self.hostname = basename

    def _detect_hostname_from_dir(self):
        """Extract hostname from an extracted directory."""
        hostname_file = os.path.join(self.source_path, 'etc', 'hostname')
        if os.path.exists(hostname_file):
            try:
                with open(hostname_file, 'r') as f:
                    self.hostname = f.read().strip()
            except Exception:
                pass
        if not self.hostname:
            self.hostname = os.path.basename(self.source_path.rstrip('/\\'))
        if not self.hostname:
            self.hostname = "unknown"

    # ------------------------------------------------------------------
    # Internal: Family A helpers
    # ------------------------------------------------------------------

    def _get_file_tarball(self, filepath: str) -> Optional[bytes]:
        paths_to_try = [
            filepath,
            filepath.lstrip('/'),
        ]
        if self._root_prefix:
            paths_to_try.append(f"{self._root_prefix}/{filepath.lstrip('/')}")
            paths_to_try.append(f"{self._root_prefix}{filepath}")
        if self._var_log_prefix and self._var_log_prefix != self._root_prefix:
            paths_to_try.append(f"{self._var_log_prefix}{filepath.lstrip('/')}")

        for path in paths_to_try:
            if path in self._member_dict:
                try:
                    f = self.tar.extractfile(self._member_dict[path])
                    if f:
                        data = f.read()
                        if path.endswith('.gz'):
                            try:
                                data = gzip.decompress(data)
                            except Exception:
                                pass
                        return data
                except Exception:
                    pass
        return None

    def _get_file_directory(self, filepath: str) -> Optional[bytes]:
        full_path = os.path.join(self.source_path, filepath.lstrip('/'))
        if not os.path.isfile(full_path):
            return None
        try:
            if full_path.endswith('.gz'):
                with gzip.open(full_path, 'rb') as f:
                    return f.read()
            with open(full_path, 'rb') as f:
                return f.read()
        except Exception:
            return None

    def _find_pattern_tarball(self, patterns: List[str]) -> List[Tuple[str, Any]]:
        results = []
        if not self._members_cache:
            return results
        for member in self._members_cache:
            if not member.isfile():
                continue
            name = member.name.replace("\\", "/")
            for pattern in patterns:
                if pattern in name:
                    normalized = name
                    if self._root_prefix and normalized.startswith(self._root_prefix):
                        normalized = normalized[len(self._root_prefix):]
                    results.append((normalized, member))
                    break
                try:
                    if re.search(pattern, name):
                        normalized = name
                        if self._root_prefix and normalized.startswith(self._root_prefix):
                            normalized = normalized[len(self._root_prefix):]
                        results.append((normalized, member))
                        break
                except re.error:
                    pass
        return results

    def _find_pattern_directory(self, patterns: List[str]) -> List[Tuple[str, None]]:
        results = []
        if not os.path.isdir(self.source_path):
            return results
        for root, dirs, files in os.walk(self.source_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                relative = os.path.relpath(filepath, self.source_path)
                for pattern in patterns:
                    if pattern in relative:
                        results.append(('/' + relative, None))
                        break
                    try:
                        if re.search(pattern, relative):
                            results.append(('/' + relative, None))
                            break
                    except re.error:
                        pass
        return results

    def _list_dir_tarball(self, dirpath: str) -> List[str]:
        results = []
        if not self._members_cache:
            return results

        path = dirpath.lstrip('/').rstrip('/') + '/'
        for member in self._members_cache:
            member_path = member.name
            if self._root_prefix and member_path.startswith(self._root_prefix):
                member_path = member_path[len(self._root_prefix):]
            member_path = member_path.lstrip('/')

            if member_path.startswith(path):
                remainder = member_path[len(path):]
                if remainder and '/' not in remainder.rstrip('/'):
                    results.append(member_path)
        return results

    def _list_dir_directory(self, dirpath: str) -> List[str]:
        results = []
        full_path = os.path.join(self.source_path, dirpath.lstrip('/'))
        if os.path.isdir(full_path):
            for item in os.listdir(full_path):
                results.append(os.path.join(dirpath, item))
        return results

    # ------------------------------------------------------------------
    # Internal: Family B helpers
    # ------------------------------------------------------------------

    def _find_suffix_tarball(self, suffixes: List[str]) -> List[Tuple[str, str]]:
        if not self.tar:
            return []
        results = []
        for member in self._members_cache or []:
            if not member.isfile():
                continue
            norm = member.name.lstrip('./')
            for suf in suffixes:
                if self._match_suffix(norm, suf):
                    content = self._read_tar_member_text(member)
                    if content is not None:
                        results.append((norm, content))
                    break
        return results

    def _find_suffix_directory(self, suffixes: List[str]) -> List[Tuple[str, str]]:
        results = []
        if not os.path.isdir(self.source_path):
            return results
        base = self.source_path
        base_depth = base.count(os.sep)
        for root, dirs, files in os.walk(base):
            if root.count(os.sep) - base_depth > 10:
                dirs.clear()
                continue
            for fname in files:
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, base).replace('\\', '/')
                for suf in suffixes:
                    if self._match_suffix(rel, suf):
                        content = self._read_file_text(full)
                        if content is not None:
                            results.append((rel, content))
                        break
        return results

    @staticmethod
    def _match_suffix(path: str, suffix: str) -> bool:
        """Match a path against a suffix pattern.

        Supports: "**/foo" (anywhere), "*/foo" (one dir), "foo" (exact tail).
        """
        path = path.replace('\\', '/')
        if suffix.startswith('**/'):
            sub = suffix[3:]
            return path.endswith(sub) or ('/' + sub) in path
        if suffix.startswith('*'):
            return path.endswith(suffix[1:])
        return path == suffix or path.endswith('/' + suffix)

    def _read_tar_member_text(self, member: tarfile.TarInfo) -> Optional[str]:
        if not self.tar:
            return None
        try:
            fobj = self.tar.extractfile(member)
            if fobj is None:
                return None
            raw = fobj.read()
            if member.name.endswith('.gz'):
                raw = gzip.decompress(raw)
            return raw.decode('utf-8', errors='replace')
        except Exception:
            return None

    @staticmethod
    def _read_file_text(path: str) -> Optional[str]:
        try:
            if path.endswith('.gz'):
                with gzip.open(path, 'rt', encoding='utf-8', errors='replace') as f:
                    return f.read()
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Raw file extraction (Layer 1 — complete forensic data dump)
    # ------------------------------------------------------------------

    RAW_EXPORT_CATEGORIES: Dict[str, List[str]] = {
        "logs":        ["var/log/"],
        "configs":     ["etc/"],
        "network":     ["etc/hosts", "etc/resolv.conf", "etc/hosts.allow",
                        "etc/hosts.deny", "etc/network/", "etc/netplan/",
                        "etc/sysconfig/network-scripts/"],
        "persistence": ["etc/cron", "var/spool/cron", "etc/systemd/",
                        "etc/init.d/", "etc/rc", "etc/profile",
                        "etc/bash", "etc/ld.so"],
        "packages":    ["var/log/dpkg", "var/log/apt/", "var/log/yum",
                        "var/log/dnf", "var/log/pacman",
                        "etc/apt/sources", "etc/yum.repos.d/"],
    }

    def export_raw_files(self, output_base: str) -> Dict[str, List[str]]:
        """Extract key forensic files to disk, organised by category.

        Creates ``{output_base}/raw/{category}/{relative_path}`` for every
        file that matches a category prefix.  Returns a dict mapping each
        category name to the list of files extracted.
        """
        result: Dict[str, List[str]] = {cat: [] for cat in self.RAW_EXPORT_CATEGORIES}
        raw_root = os.path.join(output_base, "raw")

        if self.is_tarball and self.tar:
            members = self._members_cache or self.tar.getmembers()
            for member in members:
                if not member.isfile():
                    if member.issym() or member.islnk():
                        logger.debug("raw export: skipping symlink %s", member.name)
                    continue
                rel = member.name
                if self._root_prefix and rel.startswith(self._root_prefix):
                    rel = rel[len(self._root_prefix):]
                rel = rel.lstrip("/")

                cat = self._categorise_path(rel)
                if cat is None:
                    continue

                dest = os.path.join(raw_root, cat, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    src = self.tar.extractfile(member)
                    if src is None:
                        continue
                    with open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
                    result[cat].append(dest)
                except Exception as exc:
                    logger.debug("raw export: failed to extract %s: %s",
                                 member.name, exc)
        else:
            # Directory source
            base = self.source_path
            for dirpath, _dirs, files in os.walk(base):
                for fname in files:
                    full = os.path.join(dirpath, fname)
                    rel = os.path.relpath(full, base).replace("\\", "/")
                    # strip leading hostname dir if present
                    if self._root_prefix:
                        prefix = self._root_prefix.strip("/")
                        if rel.startswith(prefix + "/"):
                            rel = rel[len(prefix) + 1:]
                    cat = self._categorise_path(rel)
                    if cat is None:
                        continue
                    dest = os.path.join(raw_root, cat, rel)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    try:
                        shutil.copy2(full, dest)
                        result[cat].append(dest)
                    except Exception as exc:
                        logger.debug("raw export: failed to copy %s: %s",
                                     full, exc)

        total = sum(len(v) for v in result.values())
        logger.info("Raw extraction: %d files across %d categories",
                     total, sum(1 for v in result.values() if v))
        return result

    def _categorise_path(self, rel_path: str) -> Optional[str]:
        """Return the first matching export category for *rel_path*, or None."""
        for cat, prefixes in self.RAW_EXPORT_CATEGORIES.items():
            for prefix in prefixes:
                if rel_path.startswith(prefix):
                    return cat
        return None
