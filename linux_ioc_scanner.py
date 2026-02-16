#!/usr/bin/env python3
"""
Linux IOC Scanner - Indicator of Compromise String Matching

Searches for Indicators of Compromise (IOCs) across all forensic data
collected from UAC collections or mounted Linux filesystems.

Inspired by ptt.sh's IOC scanning capabilities:
- Accepts a file containing IOC strings (one per line)
- Performs fixed-string matching (not regex) across:
  - Raw log files (audit, syslog, auth, messages)
  - Systemd journal exports
  - Web server logs
  - Compressed logs (.gz, .bz2, .xz)
  - Shell history files
  - Configuration files
- Reports matches with source file context
- Can also scan previously generated analysis CSV output

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
# IOC Match
# ============================================================================

class IOCMatch:
    """A single IOC match result."""

    __slots__ = ('ioc', 'source_file', 'line_number', 'line_content',
                 'context')

    def __init__(self, ioc: str, source_file: str, line_number: int,
                 line_content: str, context: str = ""):
        self.ioc = ioc
        self.source_file = source_file
        self.line_number = line_number
        self.line_content = line_content
        self.context = context


# ============================================================================
# IOC Scanner
# ============================================================================

# Paths to scan for IOC matches
SCAN_PATHS = [
    'var/log/',
    'root/',
    'home/',
    'etc/',
    'tmp/',
    'var/tmp/',
    'var/spool/',
    'opt/',
    'usr/local/',
]


class IOCScanner:
    """
    Scan forensic collections for IOC matches.

    Supports:
    - Fixed-string IOC matching (like grep -F)
    - Scanning raw log files, shell histories, config files
    - Scanning compressed files (.gz, .bz2, .xz)
    - Scanning previously generated analysis output
    """

    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')

    # Text file extensions to scan
    TEXT_EXTENSIONS = {
        '.log', '.txt', '.conf', '.cfg', '.ini', '.json', '.xml', '.yml',
        '.yaml', '.csv', '.sh', '.bash', '.py', '.pl', '.rb', '.php',
        '.html', '.htm', '.js', '.service', '.timer', '.socket', '.rules',
        '.env', '.history', '.bash_history', '.zsh_history',
    }

    # File types that are definitely not text
    BINARY_EXTENSIONS = {
        '.so', '.o', '.a', '.bin', '.exe', '.dll', '.pyc', '.pyo',
        '.class', '.jar', '.war', '.ear', '.deb', '.rpm',
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
        '.mp3', '.mp4', '.avi', '.mkv', '.flac', '.ogg',
        '.db', '.sqlite', '.sqlite3',
    }

    # Max file size to scan (50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024

    def __init__(self, source_path: str, ioc_file: str):
        self.source_path = os.path.abspath(source_path)
        self.ioc_file = os.path.abspath(ioc_file)
        self.is_tarball = any(source_path.lower().endswith(ext)
                              for ext in self.TAR_EXTENSIONS)
        self.tar = None
        self.root_prefix = ""
        self.hostname = "unknown"

        self.iocs: List[str] = []
        self.matches: List[IOCMatch] = []
        self.files_scanned = 0
        self.files_matched = 0

        self._load_iocs()

        if self.is_tarball:
            self._open_tarball()

    def _load_iocs(self):
        """Load IOC strings from the IOC file."""
        try:
            with open(self.ioc_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.iocs.append(line)
        except Exception as e:
            raise RuntimeError(f"Failed to load IOC file: {e}")

        if not self.iocs:
            raise ValueError(f"No IOCs found in {self.ioc_file}")

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

    def _rel_path(self, name: str) -> str:
        if self.root_prefix and name.startswith(self.root_prefix):
            name = name[len(self.root_prefix):]
        return '/' + name.lstrip('/')

    def _should_scan_file(self, name: str, size: int) -> bool:
        """Decide whether a file should be scanned."""
        if size > self.MAX_FILE_SIZE or size == 0:
            return False

        lower = name.lower()

        # Skip known binary extensions
        for ext in self.BINARY_EXTENSIONS:
            if lower.endswith(ext):
                return False

        # Check if it's in a scannable path
        rel = self._rel_path(name).lstrip('/')
        if any(rel.startswith(p) for p in SCAN_PATHS):
            return True

        # Check extension
        for ext in self.TEXT_EXTENSIONS:
            if lower.endswith(ext):
                return True

        # Files without extensions in interesting directories
        if '/' in rel:
            parent = rel.rsplit('/', 1)[0]
            if any(parent.startswith(p.rstrip('/')) for p in SCAN_PATHS):
                return True

        return False

    def _scan_text(self, text: str, source_file: str) -> int:
        """Scan text for IOC matches. Returns match count."""
        count = 0
        for line_num, line in enumerate(text.splitlines(), 1):
            for ioc in self.iocs:
                if ioc in line:
                    self.matches.append(IOCMatch(
                        ioc=ioc,
                        source_file=source_file,
                        line_number=line_num,
                        line_content=line[:1024]  # Limit line length
                    ))
                    count += 1
        return count

    # ------------------------------------------------------------------
    # Scan from tarball
    # ------------------------------------------------------------------

    def _scan_tarball(self, verbose: bool = True) -> int:
        """Scan tarball contents for IOC matches."""
        if not self.tar:
            return 0

        total_matches = 0
        for member in self.tar.getmembers():
            if not member.isfile():
                continue
            if not self._should_scan_file(member.name, member.size):
                continue

            try:
                f = self.tar.extractfile(member)
                if not f:
                    continue
                data = f.read()

                # Handle compression
                lower_name = member.name.lower()
                if lower_name.endswith('.gz'):
                    try:
                        data = gzip.decompress(data)
                    except Exception:
                        pass
                elif lower_name.endswith('.bz2'):
                    try:
                        data = bz2.decompress(data)
                    except Exception:
                        pass
                elif lower_name.endswith('.xz'):
                    try:
                        data = lzma.decompress(data)
                    except Exception:
                        pass

                text = data.decode('utf-8', errors='replace')
                self.files_scanned += 1
                rel = self._rel_path(member.name)
                matches = self._scan_text(text, rel)
                if matches:
                    self.files_matched += 1
                    total_matches += matches

            except Exception:
                continue

        return total_matches

    # ------------------------------------------------------------------
    # Scan from directory
    # ------------------------------------------------------------------

    def _scan_directory(self, verbose: bool = True) -> int:
        """Scan directory contents for IOC matches."""
        root = self._find_root_dir()
        total_matches = 0

        for dirpath, _, filenames in os.walk(root, followlinks=False):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)

                try:
                    size = os.path.getsize(fpath)
                except (OSError, PermissionError):
                    continue

                rel = os.path.relpath(fpath, root).replace('\\', '/')
                if not self._should_scan_file(rel, size):
                    continue

                try:
                    # Handle compression
                    lower = fname.lower()
                    if lower.endswith('.gz'):
                        with gzip.open(fpath, 'rb') as f:
                            data = f.read()
                    elif lower.endswith('.bz2'):
                        with open(fpath, 'rb') as f:
                            data = bz2.decompress(f.read())
                    elif lower.endswith('.xz'):
                        with lzma.open(fpath, 'rb') as f:
                            data = f.read()
                    else:
                        with open(fpath, 'rb') as f:
                            data = f.read()

                    text = data.decode('utf-8', errors='replace')
                    self.files_scanned += 1
                    matches = self._scan_text(text, '/' + rel)
                    if matches:
                        self.files_matched += 1
                        total_matches += matches

                except (OSError, PermissionError, Exception):
                    continue

        return total_matches

    # ------------------------------------------------------------------
    # Scan analysis output
    # ------------------------------------------------------------------

    def scan_output_directory(self, output_dir: str,
                              verbose: bool = True) -> int:
        """Scan previously generated analysis CSV files for IOC matches."""
        total_matches = 0

        if not os.path.isdir(output_dir):
            return 0

        for fname in os.listdir(output_dir):
            fpath = os.path.join(output_dir, fname)
            if not os.path.isfile(fpath):
                continue
            if not fname.endswith('.csv') and not fname.endswith('.txt'):
                continue

            try:
                with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                    text = f.read()

                self.files_scanned += 1
                matches = self._scan_text(text, f"[output]/{fname}")
                if matches:
                    self.files_matched += 1
                    total_matches += matches
            except Exception:
                continue

        if verbose and total_matches:
            print(f"  {Style.WARNING}[!] Found {total_matches} IOC hits in "
                  f"analysis output{Style.RESET}", file=sys.stderr)

        return total_matches

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    def scan(self, verbose: bool = True) -> int:
        """
        Run IOC scan across the forensic collection.

        Returns:
            Total number of matches found
        """
        self.hostname = self._get_hostname()

        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}IOC Scanner{Style.RESET}",
                  file=sys.stderr)
            print(f"  {Style.INFO}Source:{Style.RESET} {self.source_path}",
                  file=sys.stderr)
            print(f"  {Style.INFO}IOC File:{Style.RESET} {self.ioc_file}",
                  file=sys.stderr)
            print(f"  {Style.INFO}IOCs Loaded:{Style.RESET} {len(self.iocs)}",
                  file=sys.stderr)

        if self.is_tarball:
            total = self._scan_tarball(verbose)
        else:
            total = self._scan_directory(verbose)

        if verbose:
            color = Style.WARNING if total > 0 else Style.SUCCESS
            print(f"\n  {color}Results: {total} IOC matches in "
                  f"{self.files_matched}/{self.files_scanned} files scanned"
                  f"{Style.RESET}", file=sys.stderr)

            if total > 0:
                # Show summary by IOC
                ioc_counts: Dict[str, int] = defaultdict(int)
                for match in self.matches:
                    ioc_counts[match.ioc] += 1
                print(f"\n  {Style.WARNING}IOC Hit Summary:{Style.RESET}",
                      file=sys.stderr)
                for ioc, count in sorted(ioc_counts.items(),
                                          key=lambda x: -x[1]):
                    print(f"    {count:>4} hits: {ioc[:80]}",
                          file=sys.stderr)

        return total

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self, output_dir: str, hostname: str = None) -> Optional[str]:
        """Export IOC matches to CSV."""
        if not self.matches:
            return None

        hostname = hostname or self.hostname
        path = os.path.join(output_dir, f"{hostname}_ioc_matches.csv")

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IOC', 'Source File', 'Line Number',
                             'Line Content'])
            for match in sorted(self.matches,
                                key=lambda m: (m.ioc, m.source_file)):
                writer.writerow([
                    match.ioc, match.source_file, match.line_number,
                    match.line_content
                ])

        return path


# ============================================================================
# CLI
# ============================================================================

def main():
    Style.enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Linux IOC Scanner - Indicator of Compromise Matching",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
The IOC file should contain one indicator per line (fixed strings, not regex).
Lines starting with '#' are treated as comments.

Examples:
  # Scan UAC tarball for IOCs
  python linux_ioc_scanner.py -s uac-host.tar.gz -i iocs.txt -o ./output/

  # Scan extracted directory
  python linux_ioc_scanner.py -s ./extracted_uac/ -i iocs.txt -o ./output/

  # Also scan analysis output
  python linux_ioc_scanner.py -s host.tar.gz -i iocs.txt -o ./output/ --scan-output ./host_analysis/

Output:
  [hostname]_ioc_matches.csv - All IOC matches with context
        """
    )

    parser.add_argument('-s', '--source', required=True,
                        help='Source: UAC tarball or extracted directory')
    parser.add_argument('-i', '--iocs', required=True,
                        help='Path to IOC file (one string per line)')
    parser.add_argument('-o', '--output', default='.',
                        help='Output directory')
    parser.add_argument('--scan-output', default=None,
                        help='Also scan analysis output directory for IOCs')
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

    ioc_file = os.path.abspath(args.iocs)
    if not os.path.isfile(ioc_file):
        print(f"{Style.ERROR}Error: IOC file not found: {ioc_file}"
              f"{Style.RESET}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    scanner = IOCScanner(source, ioc_file)
    try:
        scanner.scan(verbose=not args.quiet)

        if args.scan_output:
            scanner.scan_output_directory(os.path.abspath(args.scan_output),
                                          verbose=not args.quiet)

        path = scanner.export_csv(output_dir)

        if not args.quiet:
            if path:
                print(f"\n{Style.SUCCESS}Output: {path}{Style.RESET}",
                      file=sys.stderr)
            else:
                print(f"\n{Style.SUCCESS}No IOC matches found{Style.RESET}",
                      file=sys.stderr)
    finally:
        scanner.close()


if __name__ == "__main__":
    main()
