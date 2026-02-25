#!/usr/bin/env python3
"""
Linux Miscellaneous Artifacts Collector

Collects miscellaneous forensic artifacts from UAC collections or
mounted Linux filesystems.

Inspired by ptt.sh's do_misc_tasks():
- Detects archive files (.zip, .7z, .rar, .tar.gz, etc.) by magic bytes
- Lists hidden directories (names starting with ".")
- Collects scheduled task configurations (cron, systemd timers, at jobs)
- Detects compressed logs for awareness

Author: Security Tools
Version: 1.0.0
License: MIT

Requirements: Python 3.6+ (standard library only)
"""

__version__ = "1.0.0"

import argparse
import csv
import gzip
import io
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
# Archive Magic Bytes
# ============================================================================

ARCHIVE_MAGIC = {
    b'PK\x03\x04': 'zip',
    b'PK\x05\x06': 'zip (empty)',
    b'PK\x07\x08': 'zip (spanned)',
    b'\x1f\x8b': 'gzip',
    b'BZh': 'bzip2',
    b'\xfd7zXZ\x00': 'xz',
    b'7z\xbc\xaf\x27\x1c': '7z',
    b'Rar!\x1a\x07': 'rar',
    b'\x1f\x9d': 'compress (.Z)',
    b'\x1f\xa0': 'compress (.Z, LZH)',
    b'\x04\x22\x4d\x18': 'lz4',
    b'\x28\xb5\x2f\xfd': 'zstd',
}

# Tar files have magic at offset 257
TAR_MAGIC = b'ustar'
TAR_MAGIC_OFFSET = 257

# Archive file extensions (fallback)
ARCHIVE_EXTENSIONS = {
    '.zip', '.7z', '.rar', '.tar', '.tar.gz', '.tgz', '.tar.bz2',
    '.tbz2', '.tar.xz', '.txz', '.gz', '.bz2', '.xz', '.lz4',
    '.zst', '.Z', '.cpio', '.rpm', '.deb', '.jar', '.war', '.ear',
    '.apk', '.iso', '.img', '.dmg',
}


# ============================================================================
# Scheduled Task Paths
# ============================================================================

CRON_PATHS = [
    'etc/crontab',
    'etc/cron.d/',
    'etc/cron.daily/',
    'etc/cron.hourly/',
    'etc/cron.weekly/',
    'etc/cron.monthly/',
    'var/cron/',
    'var/spool/cron/',
    'var/spool/cron/crontabs/',
    'var/spool/anacron/',
    'etc/anacrontab',
]

SYSTEMD_TIMER_PATTERNS = [
    'usr/lib/systemd/system/',
    'etc/systemd/system/',
    'run/',
]

AT_JOB_PATHS = [
    'var/spool/at/',
    'var/spool/atjobs/',
]

HOMEDIR_TIMER_PATTERN = re.compile(
    r'home/[^/]+/\.config/systemd/.*\.timer$')


# ============================================================================
# Misc Artifacts Collector
# ============================================================================

class MiscArtifactsCollector:
    """
    Collects miscellaneous forensic artifacts.

    Capabilities:
    - Archive file detection (magic bytes + extensions)
    - Hidden directory enumeration
    - Scheduled task config collection (cron, systemd timers, at jobs)
    """

    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')

    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path)
        self.is_tarball = any(source_path.lower().endswith(ext)
                              for ext in self.TAR_EXTENSIONS)
        self.tar = None
        self.root_prefix = ""
        self.hostname = "unknown"

        self.archive_files: List[Dict] = []
        self.hidden_dirs: List[str] = []
        self.scheduled_tasks: List[Dict] = []

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

    def _rel_path(self, name: str) -> str:
        """Strip root prefix from a path."""
        if self.root_prefix and name.startswith(self.root_prefix):
            name = name[len(self.root_prefix):]
        return '/' + name.lstrip('/')

    # ------------------------------------------------------------------
    # Archive file detection
    # ------------------------------------------------------------------

    def _detect_archive_magic(self, data: bytes) -> Optional[str]:
        """Check if data starts with known archive magic bytes."""
        for magic, fmt in ARCHIVE_MAGIC.items():
            if data[:len(magic)] == magic:
                return fmt
        # Check for tar magic at offset 257
        if len(data) > TAR_MAGIC_OFFSET + len(TAR_MAGIC):
            if data[TAR_MAGIC_OFFSET:TAR_MAGIC_OFFSET + len(TAR_MAGIC)] == TAR_MAGIC:
                return 'tar'
        return None

    def _collect_archive_files(self, verbose: bool = True) -> int:
        """Detect archive files in the collection."""
        count = 0

        if self.is_tarball and self.tar:
            for member in self.tar.getmembers():
                if not member.isfile() or member.size == 0:
                    continue

                rel_path = self._rel_path(member.name)
                archive_type = None

                # Check extension first (fast)
                lower_name = member.name.lower()
                for ext in ARCHIVE_EXTENSIONS:
                    if lower_name.endswith(ext):
                        archive_type = ext.lstrip('.')
                        break

                # Try magic bytes for confirmation
                if archive_type or member.size > 6:
                    try:
                        f = self.tar.extractfile(member)
                        if f:
                            header = f.read(512)
                            magic_type = self._detect_archive_magic(header)
                            if magic_type:
                                archive_type = magic_type
                    except Exception:
                        pass

                if archive_type:
                    self.archive_files.append({
                        'path': rel_path,
                        'size': member.size,
                        'type': archive_type,
                        'mtime': datetime.fromtimestamp(
                            member.mtime, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S") if member.mtime else ""
                    })
                    count += 1
        else:
            root = self._find_root_dir()
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    rel = '/' + os.path.relpath(fpath, root).replace('\\', '/')
                    archive_type = None

                    # Check extension
                    lower_name = fname.lower()
                    for ext in ARCHIVE_EXTENSIONS:
                        if lower_name.endswith(ext):
                            archive_type = ext.lstrip('.')
                            break

                    # Try magic bytes
                    try:
                        with open(fpath, 'rb') as f:
                            header = f.read(512)
                        magic_type = self._detect_archive_magic(header)
                        if magic_type:
                            archive_type = magic_type
                    except (OSError, PermissionError):
                        pass

                    if archive_type:
                        try:
                            st = os.lstat(fpath)
                            size = st.st_size
                            mtime = datetime.fromtimestamp(
                                st.st_mtime, tz=timezone.utc).strftime(
                                "%Y-%m-%d %H:%M:%S")
                        except (OSError, PermissionError):
                            size = 0
                            mtime = ""

                        self.archive_files.append({
                            'path': rel,
                            'size': size,
                            'type': archive_type,
                            'mtime': mtime
                        })
                        count += 1

        if verbose:
            print(f"  {Style.INFO}[+] Found {count} archive files"
                  f"{Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Hidden directory detection
    # ------------------------------------------------------------------

    def _collect_hidden_dirs(self, verbose: bool = True) -> int:
        """Find hidden directories (name starts with '.')."""
        count = 0

        if self.is_tarball and self.tar:
            seen = set()
            for member in self.tar.getmembers():
                if not member.isdir():
                    continue
                rel_path = self._rel_path(member.name)
                basename = os.path.basename(rel_path.rstrip('/'))
                if basename.startswith('.') and basename != '.' and basename != '..':
                    if rel_path not in seen:
                        seen.add(rel_path)
                        self.hidden_dirs.append(rel_path)
                        count += 1
        else:
            root = self._find_root_dir()
            for dirpath, dirnames, _ in os.walk(root, followlinks=False):
                for dname in dirnames:
                    if dname.startswith('.'):
                        rel = '/' + os.path.relpath(
                            os.path.join(dirpath, dname), root).replace('\\', '/')
                        self.hidden_dirs.append(rel)
                        count += 1

        self.hidden_dirs.sort()

        if verbose:
            print(f"  {Style.INFO}[+] Found {count} hidden directories"
                  f"{Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Scheduled task collection
    # ------------------------------------------------------------------

    def _collect_scheduled_tasks(self, verbose: bool = True) -> int:
        """Collect cron, systemd timer, and at job configurations."""
        count = 0

        if self.is_tarball and self.tar:
            for member in self.tar.getmembers():
                if not member.isfile() or member.size == 0:
                    continue

                rel = self._rel_path(member.name).lstrip('/')

                task_type = self._classify_scheduled_task(rel)
                if not task_type:
                    continue

                # Read content
                content = ""
                try:
                    f = self.tar.extractfile(member)
                    if f:
                        raw = f.read()
                        content = raw.decode('utf-8', errors='replace')
                except Exception:
                    pass

                self.scheduled_tasks.append({
                    'path': '/' + rel,
                    'type': task_type,
                    'size': member.size,
                    'content': content,  # Store full content for raw export
                    'mtime': datetime.fromtimestamp(
                        member.mtime, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S") if member.mtime else "",
                    'exported_file': ""
                })
                count += 1
        else:
            root = self._find_root_dir()
            for dirpath, _, filenames in os.walk(root, followlinks=False):
                for fname in filenames:
                    if fname == '.placeholder':
                        continue
                    fpath = os.path.join(dirpath, fname)
                    rel = os.path.relpath(fpath, root).replace('\\', '/')

                    task_type = self._classify_scheduled_task(rel)
                    if not task_type:
                        continue

                    content = ""
                    try:
                        with open(fpath, 'r', errors='replace') as f:
                            content = f.read()  # Read full content for raw export
                    except (OSError, PermissionError):
                        pass

                    try:
                        st = os.lstat(fpath)
                        size = st.st_size
                        mtime = datetime.fromtimestamp(
                            st.st_mtime, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S")
                    except (OSError, PermissionError):
                        size = 0
                        mtime = ""

                    self.scheduled_tasks.append({
                        'path': '/' + rel,
                        'type': task_type,
                        'size': size,
                        'content': content,
                        'mtime': mtime,
                        'exported_file': ""
                    })
                    count += 1

        if verbose:
            print(f"  {Style.INFO}[+] Collected {count} scheduled task "
                  f"configurations{Style.RESET}", file=sys.stderr)
        return count

    @staticmethod
    def _classify_scheduled_task(rel_path: str) -> Optional[str]:
        """Classify a file as a scheduled task type, or None."""
        rel = rel_path.lstrip('/')

        # Cron
        for cron_path in CRON_PATHS:
            if rel.startswith(cron_path):
                return "cron"

        # Anacron
        if 'anacrontab' in rel:
            return "anacron"

        # Systemd timers
        if rel.endswith('.timer'):
            return "systemd_timer"

        # Systemd timer service (collect the .service paired with timers)
        # Only if in systemd directories
        if rel.endswith('.service'):
            for sd_path in SYSTEMD_TIMER_PATTERNS:
                if rel.startswith(sd_path):
                    return "systemd_service"

        # At jobs
        for at_path in AT_JOB_PATHS:
            if rel.startswith(at_path):
                return "at_job"

        # User timers
        if HOMEDIR_TIMER_PATTERN.match(rel):
            return "user_systemd_timer"

        return None

    # ------------------------------------------------------------------
    # Main collection
    # ------------------------------------------------------------------

    def collect(self, verbose: bool = True) -> Dict[str, int]:
        """
        Run all artifact collection.

        Returns:
            Dict of category -> count
        """
        self.hostname = self._get_hostname()

        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}Miscellaneous Artifacts "
                  f"Collector{Style.RESET}", file=sys.stderr)
            print(f"  {Style.INFO}Source:{Style.RESET} {self.source_path}",
                  file=sys.stderr)

        results = {}
        results['archive_files'] = self._collect_archive_files(verbose)
        results['hidden_dirs'] = self._collect_hidden_dirs(verbose)
        results['scheduled_tasks'] = self._collect_scheduled_tasks(verbose)

        if verbose:
            total = sum(results.values())
            print(f"\n  {Style.SUCCESS}Total: {total} artifacts collected"
                  f"{Style.RESET}", file=sys.stderr)

        return results

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self, output_dir: str, hostname: str = None) -> List[str]:
        """Export collected artifacts to CSV files."""
        hostname = hostname or self.hostname
        output_files = []

        # Archive files
        if self.archive_files:
            path = os.path.join(output_dir, f"{hostname}_archive_files.csv")
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Path', 'Type', 'Size', 'Modified'])
                for entry in sorted(self.archive_files,
                                    key=lambda e: e['path']):
                    writer.writerow([entry['path'], entry['type'],
                                     entry['size'], entry['mtime']])
            output_files.append(path)

        # Hidden directories
        if self.hidden_dirs:
            path = os.path.join(output_dir, f"{hostname}_hidden_directories.csv")
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Path'])
                for d in self.hidden_dirs:
                    writer.writerow([d])
            output_files.append(path)

        # Scheduled tasks
        if self.scheduled_tasks:
            # Export full raw scheduled task files to a subdirectory
            raw_dir = os.path.join(output_dir, "raw_scheduled_tasks")
            os.makedirs(raw_dir, exist_ok=True)
            RAW_CONTENT_THRESHOLD = 500  # chars

            for entry in self.scheduled_tasks:
                content = entry.get('content', '')
                if not content:
                    continue

                # Sanitize path into a safe filename
                safe_name = entry['path'].replace('/', '_').replace(
                    '\\', '_').lstrip('_')
                if not safe_name:
                    safe_name = 'unknown_task'
                export_path = os.path.join(raw_dir, safe_name)

                # Handle duplicate filenames
                if os.path.exists(export_path):
                    base, ext = os.path.splitext(export_path)
                    counter = 1
                    while os.path.exists(f"{base}_{counter}{ext}"):
                        counter += 1
                    export_path = f"{base}_{counter}{ext}"

                try:
                    with open(export_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    entry['exported_file'] = export_path
                except OSError:
                    pass

            exported_count = sum(1 for e in self.scheduled_tasks
                                if e.get('exported_file'))
            if exported_count:
                print(f"  {Style.INFO}[+] Exported {exported_count} raw "
                      f"scheduled task file(s) to: {raw_dir}{Style.RESET}",
                      file=sys.stderr)

            # Write CSV with Exported_File column
            path = os.path.join(output_dir,
                                f"{hostname}_scheduled_tasks.csv")
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Path', 'Type', 'Size', 'Modified',
                                 'Content Preview', 'Exported_File'])
                for entry in sorted(self.scheduled_tasks,
                                    key=lambda e: e['path']):
                    content = entry.get('content', '')
                    exported = entry.get('exported_file', '')

                    # If content is too large, truncate and reference export
                    if len(content) > RAW_CONTENT_THRESHOLD and exported:
                        preview = (
                            f"[Content too large for CSV - see "
                            f"Exported_File for full contents] "
                            f"{content[:200].replace(chr(10), ' | ')}..."
                        )
                    else:
                        preview = content[:500].replace('\n', ' | ')

                    writer.writerow([entry['path'], entry['type'],
                                     entry['size'], entry['mtime'],
                                     preview, exported])
            output_files.append(path)

        return output_files


# ============================================================================
# CLI
# ============================================================================

def main():
    Style.enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Linux Miscellaneous Artifacts Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python linux_misc_artifacts.py -s uac-host-20250115.tar.gz -o ./output/
  python linux_misc_artifacts.py -s ./extracted_uac/ -o ./output/

Output Files:
  [hostname]_archive_files.csv       - Archive files found in the image
  [hostname]_hidden_directories.csv  - Hidden directories (name starts with '.')
  [hostname]_scheduled_tasks.csv     - Cron, systemd timer, at job configs
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

    collector = MiscArtifactsCollector(source)
    try:
        collector.collect(verbose=not args.quiet)
        files = collector.export_csv(output_dir)

        if not args.quiet:
            print(f"\n{Style.SUCCESS}Output files:{Style.RESET}",
                  file=sys.stderr)
            for f in files:
                print(f"  {f}", file=sys.stderr)
    finally:
        collector.close()


if __name__ == "__main__":
    main()
