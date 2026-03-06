#!/usr/bin/env python3
"""
Linux Filesystem Timeline Generator

Generates mactime-format bodyfiles and CSV timelines from UAC tarballs,
extracted UAC directories, or mounted Linux filesystems.

Inspired by ptt.sh's filesystem timeline capabilities:
- Creates bodyfile (mactime format) from file metadata
- Generates CSV timelines with MACB timestamps
- Supports UAC bodyfile.txt if present
- Extracts login bodyfiles from wtmp, audit logs, journal security events
- Merges all bodyfiles into a unified timeline

Output format (bodyfile):
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

Output format (CSV timeline):
    Date,Size,Type,Mode,UID,GID,Meta,File Name

Author: Security Tools
Version: 1.0.0
License: MIT

Requirements: Python 3.6+ (standard library only)
"""

__version__ = "2.0.0"

import argparse
import csv
import gzip
import io
import os
import re
import struct
import sys
import tarfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Tuple, Set


from lft_style import Style


# ============================================================================
# Bodyfile Entry
# ============================================================================

class BodyfileEntry:
    """Represents a single bodyfile (mactime format) entry."""

    __slots__ = ('md5', 'name', 'inode', 'mode_str', 'uid', 'gid',
                 'size', 'atime', 'mtime', 'ctime', 'crtime')

    def __init__(self, md5: str = "0", name: str = "", inode: int = 0,
                 mode_str: str = "----------", uid: int = 0, gid: int = 0,
                 size: int = 0, atime: int = 0, mtime: int = 0,
                 ctime: int = 0, crtime: int = 0):
        self.md5 = md5
        self.name = name
        self.inode = inode
        self.mode_str = mode_str
        self.uid = uid
        self.gid = gid
        self.size = size
        self.atime = atime
        self.mtime = mtime
        self.ctime = ctime
        self.crtime = crtime

    def to_bodyfile_line(self) -> str:
        """Format as a mactime bodyfile line."""
        return (f"{self.md5}|{self.name}|{self.inode}|{self.mode_str}|"
                f"{self.uid}|{self.gid}|{self.size}|"
                f"{self.atime}|{self.mtime}|{self.ctime}|{self.crtime}")

    @staticmethod
    def from_bodyfile_line(line: str) -> Optional['BodyfileEntry']:
        """Parse a bodyfile line into a BodyfileEntry."""
        parts = line.strip().split('|')
        if len(parts) < 11:
            return None
        try:
            return BodyfileEntry(
                md5=parts[0],
                name=parts[1],
                inode=int(parts[2]) if parts[2].isdigit() else 0,
                mode_str=parts[3],
                uid=int(parts[4]) if parts[4].isdigit() else 0,
                gid=int(parts[5]) if parts[5].isdigit() else 0,
                size=int(parts[6]) if parts[6].isdigit() else 0,
                atime=int(parts[7]) if parts[7].lstrip('-').isdigit() else 0,
                mtime=int(parts[8]) if parts[8].lstrip('-').isdigit() else 0,
                ctime=int(parts[9]) if parts[9].lstrip('-').isdigit() else 0,
                crtime=int(parts[10]) if parts[10].lstrip('-').isdigit() else 0,
            )
        except (ValueError, IndexError):
            return None


# ============================================================================
# Mode String Conversion
# ============================================================================

def tarinfo_to_mode_string(info: tarfile.TarInfo) -> str:
    """Convert a TarInfo object's mode to a ls-style mode string."""
    mode = info.mode
    if info.isdir():
        ftype = 'd'
    elif info.issym():
        ftype = 'l'
    elif info.ischr():
        ftype = 'c'
    elif info.isblk():
        ftype = 'b'
    elif info.isfifo():
        ftype = 'p'
    else:
        ftype = '-'

    perms = ''
    for shift in (6, 3, 0):
        perms += 'r' if mode & (4 << shift) else '-'
        perms += 'w' if mode & (2 << shift) else '-'
        if shift == 6 and mode & 0o4000:
            perms += 's' if mode & (1 << shift) else 'S'
        elif shift == 3 and mode & 0o2000:
            perms += 's' if mode & (1 << shift) else 'S'
        elif shift == 0 and mode & 0o1000:
            perms += 't' if mode & (1 << shift) else 'T'
        else:
            perms += 'x' if mode & (1 << shift) else '-'

    return ftype + perms


def stat_to_mode_string(st_mode: int) -> str:
    """Convert os.stat st_mode to ls-style mode string."""
    import stat
    if stat.S_ISDIR(st_mode):
        ftype = 'd'
    elif stat.S_ISLNK(st_mode):
        ftype = 'l'
    elif stat.S_ISCHR(st_mode):
        ftype = 'c'
    elif stat.S_ISBLK(st_mode):
        ftype = 'b'
    elif stat.S_ISFIFO(st_mode):
        ftype = 'p'
    elif stat.S_ISSOCK(st_mode):
        ftype = 's'
    else:
        ftype = '-'

    perms = ''
    for shift in (6, 3, 0):
        perms += 'r' if st_mode & (4 << shift) else '-'
        perms += 'w' if st_mode & (2 << shift) else '-'
        if shift == 6 and st_mode & 0o4000:
            perms += 's' if st_mode & (1 << shift) else 'S'
        elif shift == 3 and st_mode & 0o2000:
            perms += 's' if st_mode & (1 << shift) else 'S'
        elif shift == 0 and st_mode & 0o1000:
            perms += 't' if st_mode & (1 << shift) else 'T'
        else:
            perms += 'x' if st_mode & (1 << shift) else '-'

    return ftype + perms


# ============================================================================
# Timeline Entry (CSV output)
# ============================================================================

class TimelineEntry:
    """A single event in the mactime CSV timeline."""

    __slots__ = ('timestamp', 'size', 'macb', 'mode', 'uid', 'gid',
                 'inode', 'name')

    def __init__(self, timestamp: str, size: int, macb: str, mode: str,
                 uid: int, gid: int, inode: int, name: str):
        self.timestamp = timestamp
        self.size = size
        self.macb = macb
        self.mode = mode
        self.uid = uid
        self.gid = gid
        self.inode = inode
        self.name = name


# ============================================================================
# Bodyfile to Timeline Conversion
# ============================================================================

def bodyfile_to_timeline(entries: List[BodyfileEntry],
                         min_date: str = "2001-01-01") -> List[TimelineEntry]:
    """
    Convert bodyfile entries to a sorted mactime CSV timeline.

    Each bodyfile entry can produce up to 4 timeline events (M, A, C, B).
    Events before min_date are excluded.
    """
    min_epoch = 0
    try:
        min_epoch = int(datetime.strptime(min_date, "%Y-%m-%d").replace(
            tzinfo=timezone.utc).timestamp())
    except ValueError:
        pass

    events: List[Tuple[int, str, BodyfileEntry]] = []

    for entry in entries:
        for epoch, label in [(entry.mtime, 'm'), (entry.atime, 'a'),
                             (entry.ctime, 'c'), (entry.crtime, 'b')]:
            if epoch and epoch > min_epoch:
                events.append((epoch, label, entry))

    # Group by (epoch, entry) to merge MACB flags
    grouped: Dict[Tuple[int, str], Tuple[Set[str], BodyfileEntry]] = {}
    for epoch, label, entry in events:
        key = (epoch, entry.name)
        if key not in grouped:
            grouped[key] = (set(), entry)
        grouped[key][0].add(label)

    timeline: List[TimelineEntry] = []
    for (epoch, _name), (flags, entry) in grouped.items():
        macb = ('m' if 'm' in flags else '.') + \
               ('a' if 'a' in flags else '.') + \
               ('c' if 'c' in flags else '.') + \
               ('b' if 'b' in flags else '.')
        try:
            ts = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S")
        except (OSError, ValueError, OverflowError):
            continue
        timeline.append(TimelineEntry(
            timestamp=ts, size=entry.size, macb=macb,
            mode=entry.mode_str, uid=entry.uid, gid=entry.gid,
            inode=entry.inode, name=entry.name))

    timeline.sort(key=lambda e: e.timestamp)
    return timeline


# ============================================================================
# Filesystem Timeline Generator
# ============================================================================

class FilesystemTimelineGenerator:
    """
    Generate filesystem timelines from UAC collections or directories.

    Capabilities (inspired by ptt.sh):
    - Parse UAC bodyfile.txt if available
    - Generate bodyfile from tarball member metadata
    - Generate bodyfile from directory file stats
    - Parse wtmp records into bodyfile entries
    - Extract security events from audit logs into bodyfile entries
    - Extract security events from journal data into bodyfile entries
    - Merge all bodyfiles into a unified timeline CSV
    """

    TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')

    # Security-relevant commands for syslog/journal bodyfile extraction
    SECURITY_COMMANDS = re.compile(
        r'(sshd\S*:\s*((Accepted|Failed)\s.*\sfor\s|Invalid user\s)|'
        r'sudo\S*:\s.*\sCOMMAND=|'
        r'(useradd|usermod|groupadd|groupmod|passwd|chsh|chfn)\S*:\s)')

    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path)
        self.is_tarball = any(source_path.lower().endswith(ext)
                              for ext in self.TAR_EXTENSIONS)
        self.tar = None
        self.root_prefix = ""
        self.bodyfile_entries: List[BodyfileEntry] = []
        self.login_entries: List[BodyfileEntry] = []
        self.hostname = "unknown"

        if self.is_tarball:
            self._open_tarball()

    # ------------------------------------------------------------------
    # Tarball helpers
    # ------------------------------------------------------------------

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

    def _get_tar_file(self, path: str) -> Optional[bytes]:
        """Read a file from the tarball."""
        if not self.tar:
            return None
        for prefix in ['', self.root_prefix + '/'] if self.root_prefix else ['']:
            try:
                member = self.tar.getmember(prefix + path.lstrip('/'))
                if member.isfile():
                    f = self.tar.extractfile(member)
                    if f:
                        return f.read()
            except (KeyError, Exception):
                continue
        return None

    def _find_root_dir(self) -> str:
        """For extracted directories, find the filesystem root."""
        # Direct structure: source_path/var/log, source_path/etc
        if os.path.isdir(os.path.join(self.source_path, 'var', 'log')):
            return self.source_path
        # Nested: source_path/[root]/var/log (UAC style)
        root_dir = os.path.join(self.source_path, '[root]')
        if os.path.isdir(root_dir) and os.path.isdir(
                os.path.join(root_dir, 'var', 'log')):
            return root_dir
        # Try subdirectories
        try:
            for item in os.listdir(self.source_path):
                sub = os.path.join(self.source_path, item)
                if os.path.isdir(sub) and os.path.isdir(
                        os.path.join(sub, 'var', 'log')):
                    return sub
        except PermissionError:
            pass
        return self.source_path

    def close(self):
        if self.tar:
            self.tar.close()
            self.tar = None

    # ------------------------------------------------------------------
    # Hostname extraction
    # ------------------------------------------------------------------

    def _get_hostname(self) -> str:
        """Extract hostname from the collection."""
        if self.is_tarball:
            data = self._get_tar_file('etc/hostname')
            if data:
                name = data.decode('utf-8', errors='replace').strip()
                if name and len(name) < 64:
                    return name
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

    # ------------------------------------------------------------------
    # Bodyfile from UAC bodyfile.txt
    # ------------------------------------------------------------------

    def _load_uac_bodyfile(self, verbose: bool = True) -> bool:
        """Load pre-existing UAC bodyfile.txt if present."""
        data = None
        if self.is_tarball:
            # Try common UAC bodyfile locations
            for path in ['bodyfile/bodyfile.txt', 'bodyfile.txt']:
                data = self._get_tar_file(path)
                if data:
                    break
        else:
            for rel in ['bodyfile/bodyfile.txt', 'bodyfile.txt']:
                fpath = os.path.join(self.source_path, rel)
                if os.path.isfile(fpath):
                    try:
                        with open(fpath, 'rb') as f:
                            data = f.read()
                    except Exception:
                        pass
                    break

        if not data:
            return False

        if verbose:
            print(f"  {Style.INFO}[+] Loading UAC bodyfile.txt{Style.RESET}",
                  file=sys.stderr)

        count = 0
        for line in data.decode('utf-8', errors='replace').splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                entry = BodyfileEntry.from_bodyfile_line(line)
                if entry:
                    self.bodyfile_entries.append(entry)
                    count += 1

        if verbose:
            print(f"  {Style.SUCCESS}    Loaded {count} entries from "
                  f"bodyfile.txt{Style.RESET}", file=sys.stderr)
        return count > 0

    # ------------------------------------------------------------------
    # Bodyfile from tarball member metadata
    # ------------------------------------------------------------------

    def _generate_bodyfile_from_tarball(self, verbose: bool = True) -> int:
        """Generate bodyfile entries from tarball member metadata."""
        if not self.tar:
            return 0

        if verbose:
            print(f"  {Style.INFO}[+] Generating bodyfile from tarball "
                  f"metadata{Style.RESET}", file=sys.stderr)

        count = 0
        prefix_len = len(self.root_prefix) if self.root_prefix else 0

        for member in self.tar.getmembers():
            name = member.name
            if prefix_len and name.startswith(self.root_prefix):
                name = name[prefix_len:]
            if not name.startswith('/'):
                name = '/' + name

            mode_str = tarinfo_to_mode_string(member)
            entry = BodyfileEntry(
                md5="0",
                name=name,
                inode=0,
                mode_str=mode_str,
                uid=member.uid,
                gid=member.gid,
                size=member.size,
                atime=int(member.mtime),  # tar only stores mtime
                mtime=int(member.mtime),
                ctime=int(member.mtime),
                crtime=0
            )
            self.bodyfile_entries.append(entry)
            count += 1

        if verbose:
            print(f"  {Style.SUCCESS}    Generated {count} entries from "
                  f"tarball{Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Bodyfile from directory walk
    # ------------------------------------------------------------------

    def _generate_bodyfile_from_directory(self, verbose: bool = True) -> int:
        """Generate bodyfile entries by walking the filesystem."""
        root = self._find_root_dir()

        if verbose:
            print(f"  {Style.INFO}[+] Generating bodyfile from directory: "
                  f"{root}{Style.RESET}", file=sys.stderr)

        count = 0
        root_len = len(root)

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for entries_list in [dirnames, filenames]:
                for name in entries_list:
                    full_path = os.path.join(dirpath, name)
                    try:
                        st = os.lstat(full_path)
                    except (OSError, PermissionError):
                        continue

                    rel_path = full_path[root_len:]
                    if not rel_path.startswith('/'):
                        rel_path = '/' + rel_path

                    mode_str = stat_to_mode_string(st.st_mode)
                    entry = BodyfileEntry(
                        md5="0",
                        name=rel_path,
                        inode=st.st_ino,
                        mode_str=mode_str,
                        uid=st.st_uid,
                        gid=st.st_gid,
                        size=st.st_size,
                        atime=int(st.st_atime),
                        mtime=int(st.st_mtime),
                        ctime=int(st.st_ctime),
                        crtime=0
                    )
                    self.bodyfile_entries.append(entry)
                    count += 1

        if verbose:
            print(f"  {Style.SUCCESS}    Generated {count} entries from "
                  f"directory{Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Login bodyfile from wtmp
    # ------------------------------------------------------------------

    UTMP_STRUCT_SIZE_64 = 384   # Common x86_64 utmp size
    UTMP_STRUCT_SIZE_32 = 380   # Some 32-bit variants

    def _parse_wtmp_bodyfile(self, data: bytes) -> List[BodyfileEntry]:
        """Parse wtmp binary data into bodyfile entries for login events."""
        results = []
        record_size = self.UTMP_STRUCT_SIZE_64
        if len(data) % record_size != 0:
            record_size = self.UTMP_STRUCT_SIZE_32
        if len(data) % record_size != 0:
            return results

        offset = 0
        while offset + record_size <= len(data):
            try:
                ut_type = struct.unpack_from('<i', data, offset)[0]
                ut_pid = struct.unpack_from('<i', data, offset + 4)[0]
                ut_line = data[offset + 8:offset + 40].split(b'\x00')[0].decode(
                    'utf-8', errors='replace')
                ut_user = data[offset + 44:offset + 76].split(b'\x00')[0].decode(
                    'utf-8', errors='replace')
                ut_host = data[offset + 76:offset + 332].split(b'\x00')[0].decode(
                    'utf-8', errors='replace')
                ut_tv_sec = struct.unpack_from('<i', data, offset + 340)[0]

                if ut_type in (7, 8):  # USER_PROCESS, DEAD_PROCESS
                    action = "LOGIN" if ut_type == 7 else "LOGOUT"
                    desc = f"{action} {ut_user}"
                    if ut_host:
                        desc += f" from {ut_host}"
                    desc += f" on {ut_line} (pid {ut_pid})"

                    results.append(BodyfileEntry(
                        md5="0",
                        name=desc,
                        inode=0,
                        mode_str="----------",
                        uid=0, gid=0, size=0,
                        atime=ut_tv_sec, mtime=ut_tv_sec,
                        ctime=ut_tv_sec, crtime=ut_tv_sec
                    ))
                elif ut_type == 1:  # RUN_LVL
                    results.append(BodyfileEntry(
                        md5="0",
                        name=f"RUNLEVEL {ut_user} on {ut_line}",
                        inode=0, mode_str="----------",
                        uid=0, gid=0, size=0,
                        atime=ut_tv_sec, mtime=ut_tv_sec,
                        ctime=ut_tv_sec, crtime=ut_tv_sec
                    ))
                elif ut_type == 2:  # BOOT_TIME
                    results.append(BodyfileEntry(
                        md5="0",
                        name="BOOT",
                        inode=0, mode_str="----------",
                        uid=0, gid=0, size=0,
                        atime=ut_tv_sec, mtime=ut_tv_sec,
                        ctime=ut_tv_sec, crtime=ut_tv_sec
                    ))
            except (struct.error, UnicodeDecodeError):
                pass
            offset += record_size

        return results

    def _collect_wtmp_bodyfile(self, verbose: bool = True) -> int:
        """Collect login bodyfile entries from wtmp files."""
        count = 0

        if self.is_tarball and self.tar:
            for member in self.tar.getmembers():
                if '/var/log/wtmp' in member.name and member.isfile():
                    try:
                        f = self.tar.extractfile(member)
                        if f:
                            data = f.read()
                            # Handle gzip-compressed wtmp
                            if member.name.endswith('.gz'):
                                data = gzip.decompress(data)
                            entries = self._parse_wtmp_bodyfile(data)
                            self.login_entries.extend(entries)
                            count += len(entries)
                    except Exception:
                        pass
        else:
            root = self._find_root_dir()
            log_dir = os.path.join(root, 'var', 'log')
            if os.path.isdir(log_dir):
                for fname in os.listdir(log_dir):
                    if fname.startswith('wtmp'):
                        fpath = os.path.join(log_dir, fname)
                        if not os.path.isfile(fpath):
                            continue
                        try:
                            if fname.endswith('.gz'):
                                with gzip.open(fpath, 'rb') as f:
                                    data = f.read()
                            else:
                                with open(fpath, 'rb') as f:
                                    data = f.read()
                            entries = self._parse_wtmp_bodyfile(data)
                            self.login_entries.extend(entries)
                            count += len(entries)
                        except Exception:
                            pass

        if verbose and count:
            print(f"  {Style.INFO}[+] Extracted {count} login events from "
                  f"wtmp{Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Login bodyfile from audit logs
    # ------------------------------------------------------------------

    _AUDIT_LOGIN_RE = re.compile(
        r'type=(USER_AUTH|USER_END)\s+msg=audit\((\d+)\.\d+:\d+\).*?'
        r'pid=(\d+).*?acct="([^"]*)".*?addr=(\S+).*?terminal=(\S+).*?res=(\S+)')

    def _collect_audit_bodyfile(self, verbose: bool = True) -> int:
        """Extract login events from audit logs into bodyfile entries."""
        count = 0
        audit_files: List[Tuple[str, bytes]] = []

        if self.is_tarball and self.tar:
            for member in self.tar.getmembers():
                if '/var/log/audit/audit.log' in member.name and member.isfile():
                    try:
                        f = self.tar.extractfile(member)
                        if f:
                            data = f.read()
                            if member.name.endswith('.gz'):
                                data = gzip.decompress(data)
                            audit_files.append((member.name, data))
                    except Exception:
                        pass
        else:
            root = self._find_root_dir()
            audit_dir = os.path.join(root, 'var', 'log', 'audit')
            if os.path.isdir(audit_dir):
                for fname in sorted(os.listdir(audit_dir)):
                    if fname.startswith('audit.log'):
                        fpath = os.path.join(audit_dir, fname)
                        if not os.path.isfile(fpath):
                            continue
                        try:
                            if fname.endswith('.gz'):
                                with gzip.open(fpath, 'rb') as f:
                                    data = f.read()
                            else:
                                with open(fpath, 'rb') as f:
                                    data = f.read()
                            audit_files.append((fpath, data))
                        except Exception:
                            pass

        for path, data in audit_files:
            text = data.decode('utf-8', errors='replace')
            for m in self._AUDIT_LOGIN_RE.finditer(text):
                action_type = m.group(1)
                epoch = int(m.group(2))
                pid = m.group(3)
                user = m.group(4)
                addr = m.group(5)
                terminal = m.group(6)
                result = m.group(7)

                if 'terminal=cron' in m.group(0):
                    continue

                action = "LOGIN" if action_type == "USER_AUTH" else "LOGOUT"
                desc = (f"{action} {result} for {user} from {addr} via "
                        f"{terminal} (pid {pid})")

                self.login_entries.append(BodyfileEntry(
                    md5="0", name=desc, inode=0,
                    mode_str="----------",
                    uid=0, gid=0, size=0,
                    atime=epoch, mtime=epoch,
                    ctime=epoch, crtime=epoch
                ))
                count += 1

        if verbose and count:
            print(f"  {Style.INFO}[+] Extracted {count} login events from "
                  f"audit logs{Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Login bodyfile from syslog security events
    # ------------------------------------------------------------------

    # New-style syslog: 2024-01-15T10:30:45.123456+00:00 ...
    _NEWSYSLOG_RE = re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+'
        r'\S+\s+\S+\s+(\S+:.*)')

    def _collect_syslog_bodyfile(self, verbose: bool = True) -> int:
        """Extract security events from syslog files into bodyfile entries."""
        count = 0
        log_files: List[bytes] = []

        # Collect relevant log files
        if self.is_tarball and self.tar:
            for member in self.tar.getmembers():
                name = member.name
                if not member.isfile():
                    continue
                if not any(x in name for x in
                           ['/var/log/auth.log', '/var/log/secure',
                            '/var/log/syslog', '/var/log/messages']):
                    continue
                try:
                    f = self.tar.extractfile(member)
                    if f:
                        data = f.read()
                        if name.endswith('.gz'):
                            data = gzip.decompress(data)
                        log_files.append(data)
                except Exception:
                    pass
        else:
            root = self._find_root_dir()
            log_dir = os.path.join(root, 'var', 'log')
            if os.path.isdir(log_dir):
                for fname in sorted(os.listdir(log_dir)):
                    if not any(fname.startswith(p)
                               for p in ('auth.log', 'secure', 'syslog',
                                         'messages')):
                        continue
                    fpath = os.path.join(log_dir, fname)
                    if not os.path.isfile(fpath):
                        continue
                    try:
                        if fname.endswith('.gz'):
                            with gzip.open(fpath, 'rb') as f:
                                data = f.read()
                        else:
                            with open(fpath, 'rb') as f:
                                data = f.read()
                        log_files.append(data)
                    except Exception:
                        pass

        for data in log_files:
            text = data.decode('utf-8', errors='replace')
            for line in text.splitlines():
                if not self.SECURITY_COMMANDS.search(line):
                    continue
                # Try new-style timestamp
                m = self._NEWSYSLOG_RE.match(line)
                if m:
                    ts_str = m.group(1)
                    message = m.group(2).replace('|', '(pipe)')
                    try:
                        # Parse ISO timestamp
                        ts_str_clean = ts_str
                        if '.' in ts_str_clean:
                            # Truncate microseconds for fromisoformat compat
                            base, rest = ts_str_clean.split('.', 1)
                            # Find timezone offset
                            tz_match = re.search(r'[+-]\d{2}:\d{2}$', rest)
                            tz_part = tz_match.group(0) if tz_match else '+00:00'
                            ts_str_clean = base + tz_part
                        dt = datetime.fromisoformat(ts_str_clean)
                        epoch = int(dt.timestamp())
                    except (ValueError, OSError):
                        continue

                    self.login_entries.append(BodyfileEntry(
                        md5="0", name=message, inode=0,
                        mode_str="----------",
                        uid=0, gid=0, size=0,
                        atime=epoch, mtime=epoch,
                        ctime=epoch, crtime=epoch
                    ))
                    count += 1

        if verbose and count:
            print(f"  {Style.INFO}[+] Extracted {count} security events from "
                  f"syslog{Style.RESET}", file=sys.stderr)
        return count

    # ------------------------------------------------------------------
    # Main generation
    # ------------------------------------------------------------------

    def generate(self, verbose: bool = True) -> Tuple[
            List[BodyfileEntry], List[BodyfileEntry]]:
        """
        Generate all bodyfile entries.

        Returns:
            Tuple of (filesystem_entries, login_entries)
        """
        self.hostname = self._get_hostname()

        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}Filesystem Timeline Generator"
                  f"{Style.RESET}", file=sys.stderr)
            print(f"  {Style.INFO}Source:{Style.RESET} {self.source_path}",
                  file=sys.stderr)
            print(f"  {Style.INFO}Hostname:{Style.RESET} {self.hostname}",
                  file=sys.stderr)

        # 1. Try loading UAC bodyfile first
        has_bodyfile = self._load_uac_bodyfile(verbose)

        # 2. If no bodyfile, generate from metadata
        if not has_bodyfile:
            if self.is_tarball:
                self._generate_bodyfile_from_tarball(verbose)
            else:
                self._generate_bodyfile_from_directory(verbose)

        # 3. Collect login bodyfiles
        self._collect_wtmp_bodyfile(verbose)
        self._collect_audit_bodyfile(verbose)
        self._collect_syslog_bodyfile(verbose)

        if verbose:
            print(f"\n  {Style.SUCCESS}Total: {len(self.bodyfile_entries)} "
                  f"filesystem entries, {len(self.login_entries)} login "
                  f"entries{Style.RESET}", file=sys.stderr)

        return self.bodyfile_entries, self.login_entries

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_bodyfile(self, output_path: str):
        """Export bodyfile entries to a file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            for entry in self.bodyfile_entries:
                f.write(entry.to_bodyfile_line() + '\n')
            for entry in self.login_entries:
                f.write(entry.to_bodyfile_line() + '\n')

    def export_timeline_csv(self, output_path: str,
                            min_date: str = "2001-01-01"):
        """Export a mactime-style CSV timeline."""
        all_entries = self.bodyfile_entries + self.login_entries
        timeline = bodyfile_to_timeline(all_entries, min_date)

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Date', 'Size', 'Type', 'Mode', 'UID', 'GID',
                             'Meta', 'File Name'])
            for entry in timeline:
                writer.writerow([entry.timestamp, entry.size, entry.macb,
                                 entry.mode, entry.uid, entry.gid,
                                 entry.inode, entry.name])

    def export_login_csv(self, output_path: str):
        """Export only login/security events as a CSV timeline."""
        if not self.login_entries:
            return

        min_epoch = 978307200  # 2001-01-01 UTC
        rows: List[Tuple[int, str]] = []
        for entry in self.login_entries:
            epoch = entry.mtime or entry.atime or entry.ctime or entry.crtime
            if epoch and epoch > min_epoch:
                rows.append((epoch, entry.name))
        rows.sort(key=lambda r: r[0])

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Event'])
            for epoch, name in rows:
                try:
                    ts = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ")
                except (OSError, ValueError, OverflowError):
                    continue
                writer.writerow([ts, name])


# ============================================================================
# CLI
# ============================================================================

def main():
    Style.enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Linux Filesystem Timeline Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate timeline from UAC tarball
  python linux_filesystem_timeline.py -s uac-host-20250115.tar.gz -o ./output/

  # Generate timeline from extracted directory
  python linux_filesystem_timeline.py -s ./extracted_uac/ -o ./output/

Output Files:
  [hostname]_bodyfile.txt            - Raw bodyfile (mactime format)
  [hostname]_filesystem_timeline.csv - Full timeline CSV
  [hostname]_login_timeline_merged.csv - Login/security events only
        """
    )

    parser.add_argument('-s', '--source', required=True,
                        help='Source: UAC tarball or extracted directory')
    parser.add_argument('-o', '--output', default='.',
                        help='Output directory (default: current directory)')
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

    gen = FilesystemTimelineGenerator(source)
    try:
        gen.generate(verbose=not args.quiet)
        hostname = gen.hostname

        # Export bodyfile
        bf_path = os.path.join(output_dir, f"{hostname}_bodyfile.txt")
        gen.export_bodyfile(bf_path)

        # Export full timeline
        tl_path = os.path.join(output_dir,
                               f"{hostname}_filesystem_timeline.csv")
        gen.export_timeline_csv(tl_path)

        # Export login timeline
        if gen.login_entries:
            login_path = os.path.join(
                output_dir, f"{hostname}_login_timeline_merged.csv")
            gen.export_login_csv(login_path)

        if not args.quiet:
            print(f"\n{Style.SUCCESS}Output:{Style.RESET}", file=sys.stderr)
            print(f"  {bf_path}", file=sys.stderr)
            print(f"  {tl_path}", file=sys.stderr)
            if gen.login_entries:
                print(f"  {os.path.join(output_dir, f'{hostname}_login_timeline_merged.csv')}",
                      file=sys.stderr)
    finally:
        gen.close()


if __name__ == "__main__":
    main()
