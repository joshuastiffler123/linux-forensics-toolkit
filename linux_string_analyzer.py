#!/usr/bin/env python3
"""
Linux String Analyzer - Log Carving and String Extraction

Extracts and categorizes log entries from raw strings, carved data, and
compressed logs within UAC collections or mounted Linux filesystems.

Inspired by ptt.sh's bulk_extractor string processing:
- Extracts audit log entries from raw strings
- Extracts traditional syslog entries (Mon DD HH:MM:SS format)
- Extracts new-style syslog entries (ISO timestamp format)
- Extracts Apache/Nginx-style web log entries
- Processes compressed logs (.xz, .bz2) for security events
- Deduplicates and sorts extracted entries

Unlike ptt.sh which requires bulk_extractor, this tool operates in pure
Python and works directly on files within UAC collections.

Author: Security Tools
Version: 1.0.0
License: MIT

Requirements: Python 3.6+ (standard library only)
"""

__version__ = "1.0.0"

import argparse
import bz2
import csv
import gzip
import io
import lzma
import os
import re
import sys
import tarfile
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple


# ============================================================================
# Console Styling
# ============================================================================

class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    ERROR = "\033[31m"
    SUCCESS = "\033[32m"
    WARNING = "\033[33m"
    INFO = "\033[36m"
    HEADER = "\033[35m"

    @staticmethod
    def enable_windows_ansi():
        if sys.platform == "win32":
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except Exception:
                pass


# ============================================================================
# Log Entry Types
# ============================================================================

class LogEntry:
    """A single extracted log entry."""

    __slots__ = ('category', 'timestamp', 'raw_line', 'source_file',
                 'hostname', 'process', 'message')

    def __init__(self, category: str, timestamp: str, raw_line: str,
                 source_file: str = "", hostname: str = "",
                 process: str = "", message: str = ""):
        self.category = category
        self.timestamp = timestamp
        self.raw_line = raw_line
        self.source_file = source_file
        self.hostname = hostname
        self.process = process
        self.message = message


# ============================================================================
# Pattern Matchers
# ============================================================================

# Audit log: type=XXXX msg=audit(EPOCH.xxx:yyy): ...
AUDIT_LOG_RE = re.compile(
    r'type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)')

# Traditional syslog: Mon DD HH:MM:SS hostname proc[PID]: message
TRAD_SYSLOG_RE = re.compile(
    r'([A-Z][a-z]{2})\s+(\s?\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+'
    r'([-.\w]+)\s+(\S+?):\s+(.*)')

# New-style syslog: YYYY-MM-DDTHH:MM:SS.usec+HH:MM fac.pri hostname proc: msg
NEWSYSLOG_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+'
    r'(\w+\.\w+)\s+([-.\w]+)\s+(\S+?):\s+(.*)')

# Apache/Nginx combined log format
# IP - user [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "REQUEST" status size "referer" "ua"
WEBLOG_RE = re.compile(
    r'([-.\w]+)\s+-\s+(\S+)\s+\[(\d+/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}'
    r'\s+[-+]\d{4})\]\s+"(.*?)"')

# Security-relevant process names for syslog filtering
SECURITY_PROCS = re.compile(
    r'(sshd|sudo|su|useradd|usermod|groupadd|groupmod|passwd|chsh|chfn|'
    r'login|systemd-logind|polkitd|pkexec)')

# Security-relevant message patterns
SECURITY_MSG_RE = re.compile(
    r'(Accepted|Failed|Invalid user|session opened|session closed|'
    r'COMMAND=|authentication failure|pam_unix|new user|new group|'
    r'password changed|account added|account modified)')


# ============================================================================
# String Analyzer
# ============================================================================

class StringAnalyzer:
    """
    Extract and categorize log entries from UAC collections.

    Processes:
    1. Audit logs (/var/log/audit/)
    2. Traditional syslog files (/var/log/messages, syslog, etc.)
    3. Auth logs (/var/log/auth.log, secure)
    4. Web server logs (/var/log/apache2, nginx, httpd)
    5. Compressed logs (.gz, .bz2, .xz)
    """

    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')

    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path)
        self.is_tarball = any(source_path.lower().endswith(ext)
                              for ext in self.TAR_EXTENSIONS)
        self.tar = None
        self.root_prefix = ""
        self.hostname = "unknown"

        self.audit_entries: List[LogEntry] = []
        self.syslog_entries: List[LogEntry] = []
        self.weblog_entries: List[LogEntry] = []
        self.security_entries: List[LogEntry] = []

        if self.is_tarball:
            self._open_tarball()

    def _open_tarball(self):
        try:
            if self.source_path.endswith('.gz') or self.source_path.endswith('.tgz'):
                self.tar = tarfile.open(self.source_path, 'r:gz')
            elif self.source_path.endswith('.bz2'):
                self.tar = tarfile.open(self.source_path, 'r:bz2')
            elif self.source_path.endswith('.xz'):
                self.tar = tarfile.open(self.source_path, 'r:xz')
            else:
                self.tar = tarfile.open(self.source_path, 'r:')

            for member in self.tar.getmembers()[:200]:
                for marker in ('/var/', '/etc/'):
                    idx = member.name.find(marker)
                    if idx > 0:
                        self.root_prefix = member.name[:idx]
                        break
                if self.root_prefix:
                    break
        except Exception as e:
            raise RuntimeError(f"Failed to open tarball: {e}")

    def _find_root_dir(self) -> str:
        if os.path.isdir(os.path.join(self.source_path, 'var', 'log')):
            return self.source_path
        root_dir = os.path.join(self.source_path, '[root]')
        if os.path.isdir(root_dir):
            return root_dir
        try:
            for item in os.listdir(self.source_path):
                sub = os.path.join(self.source_path, item)
                if os.path.isdir(sub) and os.path.isdir(
                        os.path.join(sub, 'var', 'log')):
                    return sub
        except PermissionError:
            pass
        return self.source_path

    def _get_hostname(self) -> str:
        if self.is_tarball and self.tar:
            for prefix in ['', self.root_prefix + '/'] if self.root_prefix else ['']:
                try:
                    member = self.tar.getmember(prefix + 'etc/hostname')
                    if member.isfile():
                        f = self.tar.extractfile(member)
                        if f:
                            name = f.read().decode('utf-8', errors='replace').strip()
                            if name and len(name) < 64:
                                return name
                except (KeyError, Exception):
                    continue
        else:
            root = self._find_root_dir()
            hpath = os.path.join(root, 'etc', 'hostname')
            if os.path.isfile(hpath):
                try:
                    with open(hpath, 'r') as f:
                        name = f.read().strip()
                        if name and len(name) < 64:
                            return name
                except Exception:
                    pass
        return "unknown"

    def close(self):
        if self.tar:
            self.tar.close()
            self.tar = None

    # ------------------------------------------------------------------
    # File collection helpers
    # ------------------------------------------------------------------

    def _read_file(self, member_or_path, is_tar: bool = False) -> Optional[bytes]:
        """Read a file, decompressing if needed."""
        try:
            if is_tar and self.tar:
                f = self.tar.extractfile(member_or_path)
                if not f:
                    return None
                data = f.read()
                name = member_or_path.name
            else:
                with open(member_or_path, 'rb') as f:
                    data = f.read()
                name = member_or_path

            # Decompress if needed
            if name.endswith('.gz'):
                data = gzip.decompress(data)
            elif name.endswith('.bz2'):
                data = bz2.decompress(data)
            elif name.endswith('.xz'):
                data = lzma.decompress(data)

            return data
        except Exception:
            return None

    def _collect_log_files(self, path_patterns: List[str]) -> List[Tuple[str, bytes]]:
        """Collect log files matching patterns."""
        results = []

        if self.is_tarball and self.tar:
            for member in self.tar.getmembers():
                if not member.isfile():
                    continue
                name = member.name
                if self.root_prefix and name.startswith(self.root_prefix):
                    rel_name = name[len(self.root_prefix):]
                else:
                    rel_name = name
                rel_name = rel_name.lstrip('/')

                if any(rel_name.startswith(p.lstrip('/')) for p in path_patterns):
                    data = self._read_file(member, is_tar=True)
                    if data:
                        results.append((rel_name, data))
        else:
            root = self._find_root_dir()
            for pattern in path_patterns:
                dir_path = os.path.join(root, pattern.lstrip('/'))
                parent = os.path.dirname(dir_path)
                base_pattern = os.path.basename(dir_path)

                if os.path.isdir(parent):
                    for fname in sorted(os.listdir(parent)):
                        if fname.startswith(base_pattern.rstrip('*')):
                            fpath = os.path.join(parent, fname)
                            if os.path.isfile(fpath):
                                data = self._read_file(fpath)
                                if data:
                                    rel = os.path.relpath(fpath, root)
                                    results.append((rel, data))

        return results

    # ------------------------------------------------------------------
    # Audit log extraction
    # ------------------------------------------------------------------

    def _extract_audit_logs(self, verbose: bool = True) -> int:
        """Extract and parse audit log entries."""
        files = self._collect_log_files([
            'var/log/audit/audit.log',
            'var/log/audit/audit.log.',
        ])

        count = 0
        seen: Set[str] = set()

        for source_file, data in files:
            text = data.decode('utf-8', errors='replace')
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue

                m = AUDIT_LOG_RE.match(line)
                if m:
                    audit_type = m.group(1)
                    epoch_str = m.group(2)
                    serial = m.group(3)
                    message = m.group(4)

                    # Dedup
                    key = f"{epoch_str}:{serial}"
                    if key in seen:
                        continue
                    seen.add(key)

                    try:
                        epoch = float(epoch_str)
                        ts = datetime.fromtimestamp(
                            epoch, tz=timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ")
                    except (ValueError, OSError, OverflowError):
                        ts = epoch_str

                    entry = LogEntry(
                        category="audit",
                        timestamp=ts,
                        raw_line=line,
                        source_file=source_file,
                        process=audit_type,
                        message=message
                    )
                    self.audit_entries.append(entry)

                    # Also flag as security if relevant
                    if audit_type in ('USER_AUTH', 'USER_END', 'USER_LOGIN',
                                      'USER_START', 'CRED_ACQ', 'CRED_DISP',
                                      'USER_ACCT', 'ANOM_LOGIN_FAILURES',
                                      'EXECVE', 'SYSCALL'):
                        self.security_entries.append(entry)

                    count += 1

        if verbose:
            print(f"  {Style.INFO}[+] Extracted {count} audit log entries "
                  f"from {len(files)} file(s){Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Syslog extraction (traditional + new-style)
    # ------------------------------------------------------------------

    def _extract_syslog_entries(self, verbose: bool = True) -> int:
        """Extract syslog entries (both traditional and new-style)."""
        files = self._collect_log_files([
            'var/log/auth.log',
            'var/log/secure',
            'var/log/syslog',
            'var/log/messages',
        ])

        count = 0
        seen: Set[str] = set()

        for source_file, data in files:
            text = data.decode('utf-8', errors='replace')
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue

                # Dedup
                if line in seen:
                    continue
                seen.add(line)

                # Try new-style first
                m = NEWSYSLOG_RE.match(line)
                if m:
                    ts = m.group(1)
                    hostname = m.group(3)
                    process = m.group(4)
                    message = m.group(5)

                    # Try to normalize timestamp
                    try:
                        ts_clean = ts
                        if '.' in ts_clean:
                            base, rest = ts_clean.split('.', 1)
                            tz_m = re.search(r'[+-]\d{2}:\d{2}$', rest)
                            tz_part = tz_m.group(0) if tz_m else '+00:00'
                            ts_clean = base + tz_part
                        dt = datetime.fromisoformat(ts_clean)
                        ts_norm = dt.astimezone(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ")
                    except (ValueError, OSError):
                        ts_norm = ts

                    entry = LogEntry(
                        category="syslog_new",
                        timestamp=ts_norm,
                        raw_line=line,
                        source_file=source_file,
                        hostname=hostname,
                        process=process,
                        message=message
                    )
                    self.syslog_entries.append(entry)

                    # Check if security-relevant
                    if (SECURITY_PROCS.search(process) or
                            SECURITY_MSG_RE.search(message)):
                        self.security_entries.append(entry)

                    count += 1
                    continue

                # Try traditional syslog
                m = TRAD_SYSLOG_RE.match(line)
                if m:
                    month = m.group(1)
                    day = m.group(2).strip()
                    time_str = m.group(3)
                    hostname = m.group(4)
                    process = m.group(5)
                    message = m.group(6)

                    ts = f"{month} {day:>2} {time_str}"

                    entry = LogEntry(
                        category="syslog_traditional",
                        timestamp=ts,
                        raw_line=line,
                        source_file=source_file,
                        hostname=hostname,
                        process=process,
                        message=message
                    )
                    self.syslog_entries.append(entry)

                    if (SECURITY_PROCS.search(process) or
                            SECURITY_MSG_RE.search(message)):
                        self.security_entries.append(entry)

                    count += 1

        if verbose:
            print(f"  {Style.INFO}[+] Extracted {count} syslog entries "
                  f"from {len(files)} file(s){Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Web log extraction
    # ------------------------------------------------------------------

    def _extract_web_logs(self, verbose: bool = True) -> int:
        """Extract Apache/Nginx web log entries."""
        files = self._collect_log_files([
            'var/log/apache2/',
            'var/log/httpd/',
            'var/log/nginx/',
        ])

        # For web logs we need to look for files in directories
        if self.is_tarball and self.tar:
            web_dirs = ['var/log/apache2', 'var/log/httpd', 'var/log/nginx']
            for member in self.tar.getmembers():
                if not member.isfile():
                    continue
                name = member.name
                if self.root_prefix and name.startswith(self.root_prefix):
                    rel_name = name[len(self.root_prefix):].lstrip('/')
                else:
                    rel_name = name.lstrip('/')
                if any(rel_name.startswith(d) for d in web_dirs):
                    # Check we haven't already collected this
                    if not any(f[0] == rel_name for f in files):
                        data = self._read_file(member, is_tar=True)
                        if data:
                            files.append((rel_name, data))
        else:
            root = self._find_root_dir()
            for web_dir in ['var/log/apache2', 'var/log/httpd', 'var/log/nginx']:
                full_dir = os.path.join(root, web_dir)
                if os.path.isdir(full_dir):
                    for fname in sorted(os.listdir(full_dir)):
                        fpath = os.path.join(full_dir, fname)
                        if os.path.isfile(fpath):
                            rel = os.path.relpath(fpath, root)
                            if not any(f[0] == rel for f in files):
                                data = self._read_file(fpath)
                                if data:
                                    files.append((rel, data))

        count = 0
        seen: Set[str] = set()

        for source_file, data in files:
            text = data.decode('utf-8', errors='replace')
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue

                m = WEBLOG_RE.match(line)
                if m:
                    if line in seen:
                        continue
                    seen.add(line)

                    ip = m.group(1)
                    user = m.group(2)
                    ts = m.group(3)
                    request = m.group(4)

                    # Parse timestamp
                    try:
                        dt = datetime.strptime(
                            ts, "%d/%b/%Y:%H:%M:%S %z")
                        ts_norm = dt.astimezone(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ")
                    except (ValueError, OSError):
                        ts_norm = ts

                    entry = LogEntry(
                        category="weblog",
                        timestamp=ts_norm,
                        raw_line=line,
                        source_file=source_file,
                        hostname=ip,
                        process="webserver",
                        message=f"{request} (user={user})"
                    )
                    self.weblog_entries.append(entry)
                    count += 1

        if verbose:
            print(f"  {Style.INFO}[+] Extracted {count} web log entries "
                  f"from {len(files)} file(s){Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Compressed log processing
    # ------------------------------------------------------------------

    def _extract_compressed_logs(self, verbose: bool = True) -> int:
        """Process compressed logs that may be missed by other extractors."""
        compressed_exts = ('.bz2', '.xz')
        files: List[Tuple[str, bytes]] = []

        if self.is_tarball and self.tar:
            for member in self.tar.getmembers():
                if not member.isfile():
                    continue
                if not any(member.name.endswith(ext) for ext in compressed_exts):
                    continue
                if '/var/log/' not in member.name:
                    continue
                data = self._read_file(member, is_tar=True)
                if data:
                    rel_name = member.name
                    if self.root_prefix and rel_name.startswith(self.root_prefix):
                        rel_name = rel_name[len(self.root_prefix):].lstrip('/')
                    files.append((rel_name, data))
        else:
            root = self._find_root_dir()
            log_dir = os.path.join(root, 'var', 'log')
            if os.path.isdir(log_dir):
                for dirpath, _, filenames in os.walk(log_dir):
                    for fname in filenames:
                        if any(fname.endswith(ext) for ext in compressed_exts):
                            fpath = os.path.join(dirpath, fname)
                            data = self._read_file(fpath)
                            if data:
                                rel = os.path.relpath(fpath, root)
                                files.append((rel, data))

        count = 0
        for source_file, data in files:
            text = data.decode('utf-8', errors='replace')
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue

                # Check for security-relevant content
                if not SECURITY_MSG_RE.search(line):
                    continue

                # Try to extract timestamp and categorize
                m = NEWSYSLOG_RE.match(line)
                if m:
                    ts = m.group(1)
                    try:
                        ts_clean = ts
                        if '.' in ts_clean:
                            base, rest = ts_clean.split('.', 1)
                            tz_m = re.search(r'[+-]\d{2}:\d{2}$', rest)
                            tz_part = tz_m.group(0) if tz_m else '+00:00'
                            ts_clean = base + tz_part
                        dt = datetime.fromisoformat(ts_clean)
                        ts_norm = dt.astimezone(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ")
                    except (ValueError, OSError):
                        ts_norm = ts

                    entry = LogEntry(
                        category="compressed_log",
                        timestamp=ts_norm,
                        raw_line=line,
                        source_file=source_file,
                        process=m.group(4),
                        message=m.group(5)
                    )
                    self.security_entries.append(entry)
                    count += 1
                    continue

                m = TRAD_SYSLOG_RE.match(line)
                if m:
                    ts = f"{m.group(1)} {m.group(2).strip():>2} {m.group(3)}"
                    entry = LogEntry(
                        category="compressed_log",
                        timestamp=ts,
                        raw_line=line,
                        source_file=source_file,
                        process=m.group(5),
                        message=m.group(6)
                    )
                    self.security_entries.append(entry)
                    count += 1

        if verbose:
            print(f"  {Style.INFO}[+] Extracted {count} security entries from "
                  f"{len(files)} compressed log(s){Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def analyze(self, verbose: bool = True) -> Dict[str, int]:
        """
        Run all string extraction and analysis.

        Returns:
            Dict of category -> count
        """
        self.hostname = self._get_hostname()

        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}String Analyzer{Style.RESET}",
                  file=sys.stderr)
            print(f"  {Style.INFO}Source:{Style.RESET} {self.source_path}",
                  file=sys.stderr)

        results = {}
        results['audit'] = self._extract_audit_logs(verbose)
        results['syslog'] = self._extract_syslog_entries(verbose)
        results['weblog'] = self._extract_web_logs(verbose)
        results['compressed'] = self._extract_compressed_logs(verbose)
        results['security_total'] = len(self.security_entries)

        if verbose:
            total = sum(v for k, v in results.items() if k != 'security_total')
            print(f"\n  {Style.SUCCESS}Total: {total} log entries extracted, "
                  f"{results['security_total']} security-relevant"
                  f"{Style.RESET}", file=sys.stderr)

        return results

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self, output_dir: str, hostname: str = None) -> List[str]:
        """
        Export extracted entries to CSV files.

        Returns:
            List of output file paths
        """
        hostname = hostname or self.hostname
        output_files = []

        # Audit logs
        if self.audit_entries:
            path = os.path.join(output_dir, f"{hostname}_audit_logs.csv")
            self._write_entries_csv(path, self.audit_entries)
            output_files.append(path)

        # Syslog entries
        if self.syslog_entries:
            path = os.path.join(output_dir, f"{hostname}_syslog_extracted.csv")
            self._write_entries_csv(path, self.syslog_entries)
            output_files.append(path)

        # Web logs
        if self.weblog_entries:
            path = os.path.join(output_dir, f"{hostname}_web_logs.csv")
            self._write_entries_csv(path, self.weblog_entries)
            output_files.append(path)

        # Security events (merged)
        if self.security_entries:
            path = os.path.join(output_dir,
                                f"{hostname}_security_events_extracted.csv")
            self._write_entries_csv(path, self.security_entries)
            output_files.append(path)

        return output_files

    @staticmethod
    def _write_entries_csv(path: str, entries: List[LogEntry]):
        """Write log entries to a CSV file."""
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Category', 'Source File',
                             'Hostname', 'Process', 'Message', 'Raw Line'])
            for entry in sorted(entries, key=lambda e: e.timestamp):
                writer.writerow([
                    entry.timestamp, entry.category, entry.source_file,
                    entry.hostname, entry.process, entry.message,
                    entry.raw_line
                ])


# ============================================================================
# CLI
# ============================================================================

def main():
    Style.enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Linux String Analyzer - Log Carving and Extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python linux_string_analyzer.py -s uac-host-20250115.tar.gz -o ./output/
  python linux_string_analyzer.py -s ./extracted_uac/ -o ./output/

Output Files:
  [hostname]_audit_logs.csv                - Extracted audit log entries
  [hostname]_syslog_extracted.csv          - Extracted syslog entries
  [hostname]_web_logs.csv                  - Extracted web server logs
  [hostname]_security_events_extracted.csv - All security-relevant entries
        """
    )

    parser.add_argument('-s', '--source', required=True,
                        help='Source: UAC tarball or extracted directory')
    parser.add_argument('-o', '--output', default='.',
                        help='Output directory')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress progress output')
    parser.add_argument('-v', '--version', action='version',
                        version=f'%(prog)s {__version__}')

    args = parser.parse_args()

    source = os.path.abspath(args.source)
    if not os.path.exists(source):
        print(f"{Style.ERROR}Error: Source not found: {source}{Style.RESET}",
              file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    analyzer = StringAnalyzer(source)
    try:
        analyzer.analyze(verbose=not args.quiet)
        files = analyzer.export_csv(output_dir)

        if not args.quiet:
            print(f"\n{Style.SUCCESS}Output files:{Style.RESET}",
                  file=sys.stderr)
            for f in files:
                print(f"  {f}", file=sys.stderr)
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()
