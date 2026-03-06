#!/usr/bin/env python3
"""
Linux Package Manager Log Analyzer

Parses package manager logs from UAC tarballs or extracted directories to
build a chronological timeline of software installation, upgrade, and
removal activity.  For IR triage: reveals attacker-installed tooling, and
correlates installation timestamps against other forensic artifacts.

Supported package managers
--------------------------
  dpkg / apt   – Debian, Ubuntu
  yum          – CentOS 6/7, RHEL 7
  dnf          – Fedora, CentOS 8+, RHEL 8+
  pacman       – Arch Linux, Manjaro
  zypper       – openSUSE, SLES (basic)

Author: Security Tools
Version: 1.0.0
License: MIT
"""

import argparse
import csv
import gzip
import os
import re
import sys
import tarfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from lft_uac import UACHandler

__version__ = "2.0.0"


# ============================================================================
# Suspicious Package Watchlist
# ============================================================================

# Packages that merit immediate analyst attention when installed.
# Intentionally conservative to minimise false-positive fatigue.
SUSPICIOUS_PACKAGES: frozenset = frozenset({
    # Network scanners / recon
    'nmap', 'masscan', 'zmap', 'rustscan', 'unicornscan',
    'nikto', 'dirb', 'gobuster', 'feroxbuster', 'ffuf', 'wfuzz',
    'enum4linux', 'smbmap', 'crackmapexec', 'impacket',

    # Network utilities abused by attackers
    'netcat', 'ncat', 'ncrack', 'socat', 'cryptcat', 'telnet',

    # Tunnelling / pivoting
    'chisel', 'ligolo', 'sshuttle', 'proxychains', 'proxychains4',
    'proxychains-ng', 'redsocks', 'frp', 'ngrok', 'cloudflared',
    'iodine', 'dns2tcp',

    # Credential attacks
    'hydra', 'medusa', 'john', 'hashcat', 'crunch', 'cewl',
    'wordlists', 'thc-hydra',

    # Exploitation
    'metasploit-framework', 'beef-xss', 'sqlmap', 'exploitdb',
    'armitage', 'msfconsole',

    # Post-exploitation
    'pspy', 'linpeas', 'linenum',

    # Data exfiltration
    'rclone', 'megacmd',

    # Anonymisation / evasion
    'tor', 'torsocks', 'obfs4proxy',

    # Packet capture
    'tcpdump', 'wireshark', 'tshark', 'termshark',

    # Cryptominers
    'xmrig', 'cpuminer', 'minerd', 'cgminer', 'bfgminer',
    'xmr-stak', 'ethminer', 'nbminer', 't-rex-miner',
})

# Suspicious keyword fragments (matched as substrings of package names)
_SUSPICIOUS_FRAGMENTS: Tuple[str, ...] = (
    'xmrig', 'miner', 'cryptominer', 'coinhive',
    'rootkit', 'backdoor', 'keylogger', 'rat-',
    'exploit', 'payload', 'shellcode',
)

# Actions that represent meaningful package changes
_ACTIONABLE = frozenset({'install', 'upgrade', 'remove', 'purge',
                         'downgrade', 'disappear', 'erased', 'reinstalled'})


# ============================================================================
# Data Classes
# ============================================================================

class PackageEvent:
    """A single package-manager action extracted from a log."""

    __slots__ = (
        'timestamp', 'action', 'package_name', 'version',
        'previous_version', 'commandline', 'requested_by',
        'source', 'log_file', 'raw_entry',
        'is_suspicious', 'suspicion_reason',
    )

    def __init__(
        self,
        timestamp: Optional[datetime],
        action: str,
        package_name: str,
        version: str,
        previous_version: str = '',
        commandline: str = '',
        requested_by: str = '',
        source: str = '',
        log_file: str = '',
        raw_entry: str = '',
        is_suspicious: bool = False,
        suspicion_reason: str = '',
    ):
        self.timestamp = timestamp
        self.action = action
        self.package_name = package_name
        self.version = version
        self.previous_version = previous_version
        self.commandline = commandline
        self.requested_by = requested_by
        self.source = source
        self.log_file = log_file
        self.raw_entry = raw_entry
        self.is_suspicious = is_suspicious
        self.suspicion_reason = suspicion_reason

    def to_dict(self) -> Dict:
        return {
            'Timestamp_UTC':    self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                                if self.timestamp else '',
            'Action':           self.action,
            'Package':          self.package_name,
            'Version':          self.version,
            'Previous_Version': self.previous_version,
            'Commandline':      self.commandline,
            'Requested_By':     self.requested_by,
            'Source':           self.source,
            'Log_File':         self.log_file,
            'Suspicious':       'Yes' if self.is_suspicious else '',
            'Suspicion_Reason': self.suspicion_reason,
            'Raw_Entry':        self.raw_entry[:400],
        }


# ============================================================================
# Suspicion Checker
# ============================================================================

def _is_suspicious(package_name: str) -> Tuple[bool, str]:
    name = package_name.lower()
    if name in SUSPICIOUS_PACKAGES:
        return True, f"'{package_name}' commonly used in intrusions"
    for frag in _SUSPICIOUS_FRAGMENTS:
        if frag in name:
            return True, f"Package name contains suspicious keyword '{frag}'"
    return False, ""


# ============================================================================
# Log Format Parsers
# ============================================================================

# ---- dpkg.log ---------------------------------------------------------------

_RE_DPKG = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'   # timestamp
    r'\s+(install|upgrade|remove|purge|disappear)' # action
    r'\s+([^:\s]+)(?::[^:\s]+)?'                  # package[:arch]
    r'\s+(\S+)'                                    # old-version
    r'\s+(\S+)'                                    # new-version
)


def parse_dpkg_log(content: str, log_file: str) -> List[PackageEvent]:
    """Parse Debian/Ubuntu dpkg.log."""
    events: List[PackageEvent] = []
    for line in content.splitlines():
        m = _RE_DPKG.match(line.strip())
        if not m:
            continue
        ts_s, action, pkg, old_v, new_v = m.groups()
        try:
            ts = datetime.strptime(ts_s, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            ts = None
        prev = '' if old_v in ('<none>', 'none', '-') else old_v
        cur  = '' if new_v in ('<none>', 'none', '-') else new_v
        sus, reason = _is_suspicious(pkg)
        events.append(PackageEvent(
            timestamp=ts, action=action, package_name=pkg,
            version=cur, previous_version=prev,
            source='dpkg', log_file=log_file, raw_entry=line.strip()[:300],
            is_suspicious=sus, suspicion_reason=reason,
        ))
    return events


# ---- apt/history.log --------------------------------------------------------

_RE_APT_DATE = re.compile(
    r'^Start-Date:\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})', re.MULTILINE)
_RE_APT_CMD  = re.compile(r'^Commandline:\s*(.+)$', re.MULTILINE)
_RE_APT_REQ  = re.compile(r'^Requested-By:\s*(.+)$', re.MULTILINE)
_RE_APT_PKGS = re.compile(
    r'^(Install|Upgrade|Remove|Purge|Downgrade):\s*(.+)$', re.MULTILINE)


def parse_apt_history(content: str, log_file: str) -> List[PackageEvent]:
    """Parse Ubuntu/Debian apt/history.log (block-based format)."""
    events: List[PackageEvent] = []
    for block in re.split(r'\n\s*\n', content):
        block = block.strip()
        dm = _RE_APT_DATE.search(block)
        if not dm:
            continue
        try:
            ts = datetime.strptime(f"{dm.group(1)} {dm.group(2)}", '%Y-%m-%d %H:%M:%S')
        except ValueError:
            ts = None
        cm = _RE_APT_CMD.search(block)
        rm = _RE_APT_REQ.search(block)
        cmdline   = cm.group(1).strip() if cm else ''
        requested = rm.group(1).strip() if rm else ''

        for pm in _RE_APT_PKGS.finditer(block):
            action = pm.group(1).lower()
            for entry in pm.group(2).split('),'):
                entry = entry.strip().rstrip(')')
                if not entry:
                    continue
                parts = entry.split('(')
                pkg_part = parts[0].strip().split(':')[0].strip()
                ver_part = parts[1].strip() if len(parts) > 1 else ''
                if ',' in ver_part:
                    segs = [v.strip() for v in ver_part.split(',')]
                    prev_ver, new_ver = segs[0], segs[-1]
                else:
                    prev_ver, new_ver = '', ver_part
                if not pkg_part:
                    continue
                sus, reason = _is_suspicious(pkg_part)
                events.append(PackageEvent(
                    timestamp=ts, action=action, package_name=pkg_part,
                    version=new_ver, previous_version=prev_ver,
                    commandline=cmdline, requested_by=requested,
                    source='apt', log_file=log_file, raw_entry=entry[:300],
                    is_suspicious=sus, suspicion_reason=reason,
                ))
    return events


# ---- yum.log ----------------------------------------------------------------

_RE_YUM = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'      # Mon DD HH:MM:SS (no year)
    r'\s+(Installed|Updated|Erased|Downgraded|Obsoleted):\s*'
    r'(\S+?)(?:\.\w+)?$'                             # package[.arch]
)
_YUM_ACTION_MAP = {
    'Installed': 'install', 'Updated': 'upgrade', 'Erased': 'remove',
    'Downgraded': 'downgrade', 'Obsoleted': 'remove',
}


def parse_yum_log(content: str, log_file: str,
                  reference_year: int = 0) -> List[PackageEvent]:
    """Parse CentOS/RHEL yum.log (no year in timestamp)."""
    if not reference_year:
        reference_year = datetime.now().year
    events: List[PackageEvent] = []
    for line in content.splitlines():
        m = _RE_YUM.match(line.strip())
        if not m:
            continue
        date_s, action_raw, pkg = m.groups()
        try:
            ts = datetime.strptime(f"{date_s} {reference_year}", '%b %d %H:%M:%S %Y')
            # If parsed month is far in the future, assume previous year
            if ts > datetime.now().replace(month=12, day=31):
                ts = ts.replace(year=reference_year - 1)
        except ValueError:
            ts = None
        action = _YUM_ACTION_MAP.get(action_raw, action_raw.lower())
        sus, reason = _is_suspicious(pkg)
        events.append(PackageEvent(
            timestamp=ts, action=action, package_name=pkg,
            version='', previous_version='',
            source='yum', log_file=log_file, raw_entry=line.strip()[:300],
            is_suspicious=sus, suspicion_reason=reason,
        ))
    return events


# ---- dnf.log / dnf.rpm.log --------------------------------------------------

_RE_DNF = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'   # ISO timestamp (no tz)
    r'[+\-]\d{2}:\d{2}'                            # tz offset (discard)
    r'\s+\w+\s+'                                   # log level
    r'(?:rpm:\s*)?'
    r'(Installed|Upgraded|Removed|Downgraded|Cleanup):\s*'
    r'(.+)$'
)
_DNF_ACTION_MAP = {
    'Installed': 'install', 'Upgraded': 'upgrade', 'Removed': 'remove',
    'Downgraded': 'downgrade', 'Cleanup': 'remove',
}


def parse_dnf_log(content: str, log_file: str) -> List[PackageEvent]:
    """Parse Fedora/RHEL 8+ dnf.log or dnf.rpm.log."""
    events: List[PackageEvent] = []
    for line in content.splitlines():
        m = _RE_DNF.match(line.strip())
        if not m:
            continue
        ts_s, action_raw, pkg_str = m.groups()
        try:
            ts = datetime.fromisoformat(ts_s)
        except (ValueError, AttributeError):
            ts = None
        action = _DNF_ACTION_MAP.get(action_raw, action_raw.lower())
        pkg_str = pkg_str.strip()
        if ' -> ' in pkg_str:
            old_p, new_p = pkg_str.split(' -> ', 1)
            # Extract bare package name from NVR (name-ver-rel.arch)
            nm = re.match(r'^(.+?)-\d', old_p.strip())
            pkg_name = nm.group(1) if nm else old_p.strip()
            prev_ver, new_ver = old_p.strip(), new_p.strip()
        else:
            nm = re.match(r'^(.+?)-(\d+\..+)$', pkg_str)
            if nm:
                pkg_name = nm.group(1)
                new_ver  = nm.group(2)
            else:
                pkg_name = pkg_str
                new_ver  = ''
            prev_ver = ''
        if not pkg_name:
            continue
        sus, reason = _is_suspicious(pkg_name)
        events.append(PackageEvent(
            timestamp=ts, action=action, package_name=pkg_name,
            version=new_ver, previous_version=prev_ver,
            source='dnf', log_file=log_file, raw_entry=line.strip()[:300],
            is_suspicious=sus, suspicion_reason=reason,
        ))
    return events


# ---- pacman.log -------------------------------------------------------------

_RE_PACMAN = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})[^\]]*\]'
    r'\s+\[PACMAN\]\s+'
    r'(installed|upgraded|removed|downgraded|reinstalled)\s+'
    r'(\S+)\s+\(([^)]+)\)'
)


def parse_pacman_log(content: str, log_file: str) -> List[PackageEvent]:
    """Parse Arch Linux pacman.log."""
    events: List[PackageEvent] = []
    for line in content.splitlines():
        m = _RE_PACMAN.match(line.strip())
        if not m:
            continue
        ts_s, action, pkg, ver_part = m.groups()
        try:
            ts = datetime.strptime(ts_s.replace('T', ' '), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            ts = None
        if ' -> ' in ver_part:
            segs = ver_part.split(' -> ', 1)
            prev_ver, new_ver = segs[0].strip(), segs[1].strip()
        else:
            prev_ver, new_ver = '', ver_part.strip()
        sus, reason = _is_suspicious(pkg)
        events.append(PackageEvent(
            timestamp=ts, action=action, package_name=pkg,
            version=new_ver, previous_version=prev_ver,
            source='pacman', log_file=log_file, raw_entry=line.strip()[:300],
            is_suspicious=sus, suspicion_reason=reason,
        ))
    return events


# ============================================================================
# Main Analyzer Class
# ============================================================================

class PackageAnalyzer:
    """
    Orchestrates package-log discovery and parsing across a UAC source.

    Usage::

        analyzer = PackageAnalyzer(source_path)
        analyzer.analyze()
        analyzer.export_csv('/output/hostname_packages.csv')
        analyzer.close()
    """

    # (source_type_tag, file_suffix_for_matching)
    _PATTERNS: List[Tuple[str, str]] = [
        # dpkg – Debian/Ubuntu
        ('dpkg',   'var/log/dpkg.log'),
        ('dpkg',   'var/log/dpkg.log.1'),
        ('dpkg',   '*dpkg.log'),
        ('dpkg',   '*dpkg.log.gz'),
        ('dpkg',   '*dpkg.log.1.gz'),
        # apt history – Debian/Ubuntu
        ('apt',    'var/log/apt/history.log'),
        ('apt',    '*apt/history.log'),
        ('apt',    '*apt/history.log.gz'),
        ('apt',    '*apt/history.log.1.gz'),
        # yum – CentOS 6/7, RHEL 7
        ('yum',    'var/log/yum.log'),
        ('yum',    '*yum.log'),
        ('yum',    '*yum.log.gz'),
        # dnf – Fedora, RHEL 8+
        ('dnf',    'var/log/dnf.log'),
        ('dnf',    'var/log/dnf.rpm.log'),
        ('dnf',    '*dnf.log'),
        ('dnf',    '*dnf.rpm.log'),
        ('dnf',    '*dnf.log.gz'),
        ('dnf',    '*dnf.rpm.log.gz'),
        # pacman – Arch
        ('pacman', 'var/log/pacman.log'),
        ('pacman', '*pacman.log'),
        ('pacman', '*pacman.log.gz'),
    ]

    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path)
        self.handler = UACHandler(self.source_path)
        self.events: List[PackageEvent] = []

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(self, verbose: bool = True) -> List[PackageEvent]:
        """Locate all package-manager logs and parse them."""
        ref_year = self._reference_year()

        # Gather unique (source_type, path, content) items
        seen: Dict[str, str] = {}  # path → source_type
        pairs: List[Tuple[str, str, str]] = []  # (source, path, content)

        for src_type, pattern in self._PATTERNS:
            for path, content in self.handler.find_files_by_suffix([pattern]):
                if path not in seen and content.strip():
                    seen[path] = src_type
                    pairs.append((src_type, path, content))

        if verbose:
            print(f"  Found {len(pairs)} package log file(s)", file=sys.stderr)

        parse_dispatch = {
            'dpkg':   parse_dpkg_log,
            'apt':    parse_apt_history,
            'yum':    lambda c, lf: parse_yum_log(c, lf, ref_year),
            'dnf':    parse_dnf_log,
            'pacman': parse_pacman_log,
        }

        for src_type, path, content in pairs:
            if verbose:
                print(f"  Parsing [{src_type}] {path}", file=sys.stderr)
            try:
                fn = parse_dispatch.get(src_type)
                if fn:
                    self.events.extend(fn(content, path))
            except Exception as exc:
                if verbose:
                    print(f"    Warning: {exc}", file=sys.stderr)

        # Sort chronologically; events with no timestamp sort to the end
        self.events.sort(key=lambda e: e.timestamp or datetime.max)

        if verbose:
            sus = sum(1 for e in self.events if e.is_suspicious)
            print(f"  Total events: {len(self.events)}", file=sys.stderr)
            if sus:
                print(f"  Suspicious packages flagged: {sus}", file=sys.stderr)

        return self.events

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self, output_path: str) -> str:
        """Write all events to a CSV file sorted chronologically."""
        fieldnames = [
            'Timestamp_UTC', 'Action', 'Package', 'Version',
            'Previous_Version', 'Commandline', 'Requested_By',
            'Source', 'Log_File', 'Suspicious', 'Suspicion_Reason',
            'Raw_Entry',
        ]
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(e.to_dict() for e in self.events)
        return output_path

    def close(self):
        self.handler.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _reference_year(self) -> int:
        """Infer a year for log files that omit it (e.g. yum.log)."""
        try:
            return datetime.fromtimestamp(
                os.path.getmtime(self.source_path)
            ).year
        except OSError:
            return datetime.now().year


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Linux Package Manager Log Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

Parses dpkg, apt, yum, dnf, and pacman logs from a UAC tarball or
extracted directory and exports a chronological package-event timeline.

Suspicious packages (commonly installed by attackers) are flagged in the
Suspicious column for quick triage.

Examples:
  python linux_package_analyzer.py -s uac-hostname.tar.gz
  python linux_package_analyzer.py -s ./extracted_uac/ -o ./results/
        """
    )
    parser.add_argument('-s', '--source', required=True,
                        help='UAC tarball or extracted directory')
    parser.add_argument('-o', '--output', default='.',
                        help='Output directory (default: current directory)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress progress output')
    parser.add_argument('-v', '--version', action='version',
                        version=f'%(prog)s {__version__}')
    args = parser.parse_args()

    source = os.path.abspath(args.source)
    if not os.path.exists(source):
        print(f"Error: Source not found: {source}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    analyzer = PackageAnalyzer(source)
    try:
        analyzer.analyze(verbose=not args.quiet)
        if analyzer.events:
            out = os.path.join(output_dir, 'package_timeline.csv')
            analyzer.export_csv(out)
            if not args.quiet:
                print(f"Output: {out}", file=sys.stderr)
        else:
            if not args.quiet:
                print("No package events found.", file=sys.stderr)
    finally:
        analyzer.close()


if __name__ == '__main__':
    main()
