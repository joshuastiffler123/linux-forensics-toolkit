#!/usr/bin/env python3
"""
Linux Network Artifact Analyzer

Parses network-related artifacts from UAC tarballs or extracted directories.
For IR triage: reveals C2 infrastructure, firewall tampering, web-shell
access patterns, and suspicious network configuration changes.

Artifact sources
----------------
  /etc/hosts           – Custom DNS overrides (C2 persistence indicator)
  /etc/resolv.conf     – DNS server configuration (DNS-hijack indicator)
  /etc/hosts.allow/deny – TCP-wrappers access controls
  /etc/network/        – Interface configuration
  /var/log/ufw.log*    – UFW firewall events
  /var/log/firewalld*  – firewalld events
  live_response/       – ARP cache, active connections, routing table
  /var/log/apache2/    – Apache access/error logs
  /var/log/httpd/      – Apache access/error logs (RHEL path)
  /var/log/nginx/      – Nginx access/error logs

Author: Security Tools
Version: 1.0.0
License: MIT
"""

import argparse
import csv
import gzip
import logging
import os
import re
import sys
import tarfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from lft.core.logging import setup_logging
from lft.core.uac import UACHandler, UnmatchedWriter

logger = logging.getLogger(__name__)

__version__ = "2.1.0"


# ============================================================================
# Constants
# ============================================================================

# Known-good DNS servers; anything else in resolv.conf is flagged
_WELL_KNOWN_DNS = frozenset({
    '8.8.8.8', '8.8.4.4',           # Google
    '1.1.1.1', '1.0.0.1',           # Cloudflare
    '9.9.9.9', '149.112.112.112',    # Quad9
    '208.67.222.222', '208.67.220.220',  # OpenDNS
    '4.4.4.4',                        # Level3
})

# RFC 1918 / link-local / loopback prefixes (not suspicious in resolv.conf)
_PRIVATE_PREFIXES = ('10.', '172.', '192.168.', '127.', '::1', 'fe80::')

# Standard /etc/hosts entries that are expected
_STANDARD_HOSTS_ENTRIES = frozenset({
    '127.0.0.1', '127.0.1.1', '::1',
    'ff02::1', 'ff02::2', 'ff02::3',
    'fe00::0', 'fe00::1', 'fe00::2',
})

# Web-shell filenames (exact basename matches, case-insensitive)
_WEBSHELL_NAMES = frozenset({
    'c99.php', 'r57.php', 'shell.php', 'cmd.php', 'b374k.php',
    'wso.php', 'alfa.php', 'webadmin.php', 'bypass.php',
    'webshell.php', 'sh.php', 'mini.php', 'adminer.php',
    'phpinfo.php', 'upload.php', 'file_manager.php',
    'terminals.php', 'indoxploit.php', 'jackhammer.php',
    'k2ll33d.php', 'locus7shell.php', 'phpspy.php',
    'asp.asp', 'cmd.asp', 'shell.asp',
    'shell.jsp', 'cmd.jsp',
})

# Suspicious URI fragment patterns (used in web-log analysis)
_SUSPICIOUS_URI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'/(?:c99|r57|b374k|wso|alfa|webshell|shell)\b', re.I),
     'Known webshell filename in URI'),
    (re.compile(r'(?:cmd|command|exec|system|passthru|eval)\s*=', re.I),
     'Shell-command parameter in URI'),
    (re.compile(r'(?:\.\./){2,}', re.I),
     'Directory traversal attempt'),
    (re.compile(r'(?:UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE)', re.I),
     'SQL injection pattern in URI'),
    (re.compile(r'(?:<script|javascript:|onerror=|onload=)', re.I),
     'XSS pattern in URI'),
    (re.compile(r'(?:base64_decode|eval\(|system\(|passthru\(|shell_exec\()', re.I),
     'PHP code injection pattern'),
    (re.compile(r'/(?:wp-login|xmlrpc|phpmyadmin|myadmin|pma|dbadmin)', re.I),
     'Common attack target path'),
]

# User-agents that suggest automated/attacker tooling
_SUSPICIOUS_UA_FRAGMENTS = (
    'python-requests', 'python-urllib', 'go-http-client', 'ruby net',
    'masscan', 'zgrab', 'nmap', 'sqlmap', 'nikto', 'dirbuster',
    'gobuster', 'feroxbuster', 'nuclei', 'metasploit', 'hydra',
    'curl/', 'libwww-perl', 'java/', 'wget/', 'powershell',
    'xmrig', 'stratum',
)

# Apache / Common Log Format timestamp pattern
_RE_CLF_TS = re.compile(
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\]'
)
_CLF_MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}


# ============================================================================
# Data Classes
# ============================================================================

class NetworkFinding:
    """A notable network artifact finding."""

    __slots__ = (
        'timestamp', 'finding_type', 'severity',
        'description', 'source_ip', 'dest_ip', 'dest_port',
        'protocol', 'action', 'log_file', 'raw_entry',
    )

    def __init__(
        self,
        finding_type: str,
        description: str,
        severity: str = 'INFO',
        timestamp: Optional[datetime] = None,
        source_ip: str = '',
        dest_ip: str = '',
        dest_port: str = '',
        protocol: str = '',
        action: str = '',
        log_file: str = '',
        raw_entry: str = '',
    ):
        self.timestamp    = timestamp
        self.finding_type = finding_type
        self.severity     = severity
        self.description  = description
        self.source_ip    = source_ip
        self.dest_ip      = dest_ip
        self.dest_port    = dest_port
        self.protocol     = protocol
        self.action       = action
        self.log_file     = log_file
        self.raw_entry    = raw_entry

    def to_dict(self) -> Dict:
        return {
            'Timestamp_UTC':  self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                              if self.timestamp else '',
            'Finding_Type':   self.finding_type,
            'Severity':       self.severity,
            'Description':    self.description,
            'Source_IP':      self.source_ip,
            'Dest_IP':        self.dest_ip,
            'Dest_Port':      self.dest_port,
            'Protocol':       self.protocol,
            'Action':         self.action,
            'Log_File':       self.log_file,
            'Raw_Entry':      self.raw_entry[:400] + ' [TRUNCATED]' if len(self.raw_entry) > 400 else self.raw_entry,
        }


class WebAccessEvent:
    """A single web-server access log entry."""

    __slots__ = (
        'timestamp', 'client_ip', 'method', 'uri',
        'status_code', 'response_bytes', 'referrer', 'user_agent',
        'log_file', 'is_suspicious', 'suspicion_reason',
    )

    def __init__(
        self,
        timestamp: Optional[datetime],
        client_ip: str,
        method: str,
        uri: str,
        status_code: int,
        response_bytes: int,
        referrer: str,
        user_agent: str,
        log_file: str,
        is_suspicious: bool = False,
        suspicion_reason: str = '',
    ):
        self.timestamp       = timestamp
        self.client_ip       = client_ip
        self.method          = method
        self.uri             = uri
        self.status_code     = status_code
        self.response_bytes  = response_bytes
        self.referrer        = referrer
        self.user_agent      = user_agent
        self.log_file        = log_file
        self.is_suspicious   = is_suspicious
        self.suspicion_reason = suspicion_reason

    def to_dict(self) -> Dict:
        return {
            'Timestamp_UTC':     self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                                 if self.timestamp else '',
            'Client_IP':         self.client_ip,
            'Method':            self.method,
            'URI':               self.uri[:500] + ' [TRUNCATED]' if len(self.uri) > 500 else self.uri,
            'Status_Code':       self.status_code,
            'Response_Bytes':    self.response_bytes,
            'Referrer':          self.referrer[:200] + ' [TRUNCATED]' if len(self.referrer) > 200 else self.referrer,
            'User_Agent':        self.user_agent[:200] + ' [TRUNCATED]' if len(self.user_agent) > 200 else self.user_agent,
            'Log_File':          self.log_file,
            'Suspicious':        'Yes' if self.is_suspicious else '',
            'Suspicion_Reason':  self.suspicion_reason,
        }

# ============================================================================
# Timestamp Helpers
# ============================================================================

def _parse_clf_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse Apache/Nginx Combined-Log-Format timestamp."""
    # 15/Jan/2024:10:23:45
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', ts_str)
    if not m:
        return None
    day, mon_s, year, h, mi, s = m.groups()
    mon = _CLF_MONTHS.get(mon_s)
    if not mon:
        return None
    try:
        return datetime(int(year), mon, int(day), int(h), int(mi), int(s))
    except ValueError:
        return None


def _parse_syslog_timestamp(ts_str: str,
                             reference_year: int = 0) -> Optional[datetime]:
    """Parse syslog-format timestamp (no year): 'Jan 15 10:23:45'."""
    if not reference_year:
        reference_year = datetime.now().year
    try:
        ts = datetime.strptime(f"{ts_str} {reference_year}", '%b %d %H:%M:%S %Y')
        if ts > datetime.now():
            ts = ts.replace(year=reference_year - 1)
        return ts
    except ValueError:
        return None


# ============================================================================
# Log Parsers
# ============================================================================

# ---- /etc/hosts -------------------------------------------------------------

_RE_HOST_LINE = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+(.+?)(?:\s*#.*)?$'
)


def parse_hosts_file(content: str, log_file: str) -> List[NetworkFinding]:
    findings: List[NetworkFinding] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = _RE_HOST_LINE.match(line)
        if not m:
            continue
        ip, hosts_part = m.groups()
        if ip in _STANDARD_HOSTS_ENTRIES:
            continue
        hostnames = hosts_part.split()
        # Public IP in hosts file → suspicious
        is_public = not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)
        sev = 'HIGH' if is_public else 'INFO'
        desc = (
            f"{'Public' if is_public else 'Private'} IP {ip} maps "
            f"{', '.join(hostnames)} in /etc/hosts"
        )
        if is_public:
            desc += " – possible C2 DNS override"
        findings.append(NetworkFinding(
            finding_type='hosts_entry', description=desc,
            severity=sev, dest_ip=ip, log_file=log_file, raw_entry=line,
        ))
    return findings


# ---- /etc/resolv.conf -------------------------------------------------------

_RE_NAMESERVER = re.compile(r'^nameserver\s+(\S+)', re.MULTILINE)


def parse_resolv_conf(content: str, log_file: str) -> List[NetworkFinding]:
    findings: List[NetworkFinding] = []
    for ns in _RE_NAMESERVER.findall(content):
        is_private = any(ns.startswith(p) for p in _PRIVATE_PREFIXES)
        is_known   = ns in _WELL_KNOWN_DNS
        if is_private or is_known:
            sev = 'INFO'
            desc = f"DNS server {ns} ({('private/internal' if is_private else 'well-known')})"
        else:
            sev = 'MEDIUM'
            desc = f"Unusual DNS server {ns} – verify this is authorised"
        findings.append(NetworkFinding(
            finding_type='dns_server', description=desc,
            severity=sev, dest_ip=ns, log_file=log_file, raw_entry=f"nameserver {ns}",
        ))
    return findings


# ---- /etc/hosts.allow / hosts.deny -----------------------------------------

def parse_tcp_wrappers(content: str, log_file: str,
                        allow: bool = True) -> List[NetworkFinding]:
    findings: List[NetworkFinding] = []
    file_type = 'hosts.allow' if allow else 'hosts.deny'
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Any ALL entry is worth flagging
        if 'ALL' in line.upper():
            sev = 'MEDIUM' if allow else 'LOW'
            desc = f"{file_type}: broad wildcard rule '{line}'"
            findings.append(NetworkFinding(
                finding_type='tcp_wrappers', description=desc,
                severity=sev, log_file=log_file, raw_entry=line,
                action='ALLOW' if allow else 'DENY',
            ))
    return findings


# ---- UFW logs ---------------------------------------------------------------

_RE_UFW = re.compile(
    r'\[UFW (\w+)\]'                              # action (BLOCK/ALLOW/LIMIT)
    r'.*?SRC=(\S+)'                               # source IP
    r'.*?DST=(\S+)'                               # dest IP
    r'(?:.*?PROTO=(\w+))?'                        # protocol (optional)
    r'(?:.*?DPT=(\d+))?'                          # dest port (optional)
)

# UFW syslog line prefixes
_RE_SYSLOG_TS = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
_RE_ISO_TS    = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')


def parse_ufw_log(content: str, log_file: str,
                  reference_year: int = 0) -> List[NetworkFinding]:
    findings: List[NetworkFinding] = []
    for line in content.splitlines():
        m = _RE_UFW.search(line)
        if not m:
            continue
        action, src, dst, proto, dpt = m.groups()

        # Parse timestamp
        ts: Optional[datetime] = None
        iso_m = _RE_ISO_TS.match(line)
        sys_m = _RE_SYSLOG_TS.match(line)
        if iso_m:
            try:
                ts = datetime.fromisoformat(iso_m.group(1))
            except ValueError:
                pass
        elif sys_m:
            ts = _parse_syslog_timestamp(sys_m.group(1), reference_year)

        sev = 'INFO'
        if dpt in ('22', '3389', '5985', '5986'):   # SSH, RDP, WinRM
            sev = 'MEDIUM'
        desc = (
            f"UFW {action}: {src} → {dst}"
            + (f":{dpt}" if dpt else '')
            + (f" ({proto})" if proto else '')
        )
        findings.append(NetworkFinding(
            finding_type='firewall_event', description=desc,
            severity=sev, timestamp=ts,
            source_ip=src, dest_ip=dst, dest_port=dpt or '',
            protocol=proto or '', action=action,
            log_file=log_file, raw_entry=line.strip()[:300],
        ))
    return findings


# ---- ARP cache / live_response ----------------------------------------------

_RE_ARP_LINE = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3})\s+\w+\s+([0-9a-fA-F:]{17})',
)


def parse_arp_cache(content: str, log_file: str) -> List[NetworkFinding]:
    findings: List[NetworkFinding] = []
    for line in content.splitlines():
        m = _RE_ARP_LINE.match(line.strip())
        if not m:
            continue
        ip, mac = m.groups()
        findings.append(NetworkFinding(
            finding_type='arp_entry',
            description=f"ARP: {ip} ↔ {mac}",
            severity='INFO',
            source_ip=ip, log_file=log_file, raw_entry=line.strip(),
        ))
    return findings


# ---- Active connections (netstat / ss output) --------------------------------

_RE_NETSTAT = re.compile(
    r'^(tcp[46]?|udp[46]?)\s+\d+\s+\d+\s+'
    r'(\S+):(\S+)\s+(\S+):(\S+)\s+'
    r'(\w+)',
    re.IGNORECASE,
)
_RE_SS = re.compile(
    r'^(tcp|udp)\s+\w+\s+\d+\s+\d+\s+'
    r'(\[?[\w.:]+\]?):(\S+)\s+'
    r'(\[?[\w.:]+\]?):(\S+)',
    re.IGNORECASE,
)

# Ports commonly associated with C2 / suspicious outbound
_SUSPICIOUS_OUTBOUND_PORTS = {
    '4444', '4445', '5555', '6666', '7777', '8888', '9999',  # common C2 defaults
    '31337', '1337', '65535',                                  # 'hacker' ports
    '3128', '8080', '8443',                                    # proxy defaults
}


def parse_connections(content: str, log_file: str) -> List[NetworkFinding]:
    findings: List[NetworkFinding] = []
    for line in content.splitlines():
        # Try netstat format first
        m = _RE_NETSTAT.match(line.strip()) or _RE_SS.match(line.strip())
        if not m:
            continue
        groups = m.groups()
        proto   = groups[0].lower().rstrip('46')
        lhost   = groups[1]
        lport   = str(groups[2])
        rhost   = groups[3]
        rport   = str(groups[4])
        state   = groups[5] if len(groups) > 5 else ''

        # Skip pure loopback or wildcard listeners
        if rhost in ('0.0.0.0', '::', '127.0.0.1', '::1', '*', ''):
            continue

        sev = 'INFO'
        reason = ''
        if rport in _SUSPICIOUS_OUTBOUND_PORTS:
            sev = 'MEDIUM'
            reason = f"connection to suspicious port {rport}"
        is_external = not any(
            rhost.startswith(p) for p in _PRIVATE_PREFIXES
        )
        if is_external:
            sev = 'MEDIUM' if sev == 'INFO' else sev
            reason = reason or 'external connection'

        desc = (
            f"Connection: {lhost}:{lport} → {rhost}:{rport}"
            + (f" [{state}]" if state else '')
            + (f" – {reason}" if reason else '')
        )
        findings.append(NetworkFinding(
            finding_type='active_connection', description=desc,
            severity=sev, source_ip=lhost, dest_ip=rhost,
            dest_port=rport, protocol=proto,
            log_file=log_file, raw_entry=line.strip()[:300],
        ))
    return findings


# ---- Apache / Nginx Combined Log Format -------------------------------------

# Standard Combined Log Format
# 1.2.3.4 - user [15/Jan/2024:10:23:45 +0000] "GET /path HTTP/1.1" 200 1234 "ref" "UA"
_RE_ACCESS_LOG = re.compile(
    r'^(\S+)'                    # client IP
    r'\s+\S+\s+\S+'              # ident, authuser
    r'\s+\[([^\]]+)\]'          # [timestamp]
    r'\s+"(\S+)'                 # "METHOD
    r'\s+(\S+)'                  # URI
    r'\s+\S+"\s+'                # proto"
    r'(\d{3})\s+'                # status
    r'(\d+|-)'                   # bytes
    r'(?:\s+"([^"]*)"'           # referrer (optional)
    r'\s+"([^"]*)")?'            # user-agent (optional)
)


def _score_web_request(
    method: str, uri: str, status: int,
    response_bytes: int, ua: str,
) -> Tuple[bool, str]:
    """Return (is_suspicious, reason) for a web access log entry."""
    reasons = []
    uri_lower = uri.lower()
    ua_lower  = ua.lower()

    # Check URI for webshell filenames
    basename = uri_lower.split('?')[0].split('/')[-1]
    if basename in _WEBSHELL_NAMES:
        reasons.append(f"web-shell filename '{basename}'")

    # URI pattern checks
    for pattern, label in _SUSPICIOUS_URI_PATTERNS:
        if pattern.search(uri):
            reasons.append(label)
            break

    # Suspicious user-agents
    for frag in _SUSPICIOUS_UA_FRAGMENTS:
        if frag in ua_lower:
            reasons.append(f"suspicious UA fragment '{frag}'")
            break

    # POST returning 200 with short response → possible command execution
    if method == 'POST' and status == 200 and 0 < response_bytes < 200:
        reasons.append("POST 200 with tiny response (possible code execution)")

    return bool(reasons), '; '.join(reasons)


def parse_web_access_log(content: str, log_file: str,
                          max_lines: int = 0,
                          unmatched: UnmatchedWriter = None) -> List[WebAccessEvent]:
    """Parse Apache or Nginx Combined Log Format access log.

    Args:
        max_lines: Maximum lines to parse.  0 means unlimited (default).
    """
    events: List[WebAccessEvent] = []
    line_count = 0
    for line in content.splitlines():
        if max_lines > 0 and line_count >= max_lines:
            break
        line_count += 1
        m = _RE_ACCESS_LOG.match(line.strip())
        if not m:
            if unmatched:
                unmatched.add(log_file, line_count, line.strip())
            continue
        (client_ip, ts_s, method, uri,
         status_s, bytes_s, referrer, ua) = m.groups()

        ts = _parse_clf_timestamp(ts_s) if ts_s else None
        status  = int(status_s)
        resp_b  = int(bytes_s) if bytes_s and bytes_s != '-' else 0
        referrer = referrer or ''
        ua       = ua or ''

        sus, reason = _score_web_request(method, uri, status, resp_b, ua)

        # Only store suspicious entries and a sample of all (first 10k)
        if sus or len(events) < 10_000:
            events.append(WebAccessEvent(
                timestamp=ts, client_ip=client_ip,
                method=method, uri=uri,
                status_code=status, response_bytes=resp_b,
                referrer=referrer, user_agent=ua,
                log_file=log_file,
                is_suspicious=sus, suspicion_reason=reason,
            ))
    return events


# ============================================================================
# Main Analyzer
# ============================================================================

class NetworkAnalyzer:
    """
    Discovers and analyzes network-related artifacts from a UAC source.

    Usage::

        analyzer = NetworkAnalyzer(source_path)
        analyzer.analyze()
        analyzer.export_findings_csv('/out/hostname_network.csv')
        analyzer.export_web_access_csv('/out/hostname_web_access.csv')
        analyzer.close()
    """

    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path)
        self.handler = UACHandler(self.source_path)
        self.findings:    List[NetworkFinding] = []
        self.web_events:  List[WebAccessEvent] = []
        self.unmatched = UnmatchedWriter()

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def analyze(self, verbose: bool = True) -> None:
        """Run all network artifact checks."""
        ref_year = self._reference_year()

        checks = [
            ('Hosts file',         self._check_hosts,
             ['etc/hosts', '*etc/hosts']),
            ('resolv.conf',        self._check_resolv,
             ['etc/resolv.conf', '*etc/resolv.conf']),
            ('hosts.allow/deny',   self._check_tcp_wrappers,
             ['etc/hosts.allow', '*etc/hosts.allow',
              'etc/hosts.deny',  '*etc/hosts.deny']),
            ('UFW logs',           lambda pf: self._check_ufw(pf, ref_year),
             ['var/log/ufw.log', '*ufw.log', '*ufw.log.gz', '*ufw.log.1',
              '*ufw.log.1.gz']),
            ('ARP cache',          self._check_arp,
             ['*arp.txt', '*arp-cache.txt', '*arp_cache.txt',
              '*live_response*arp*', 'live_response/network/arp.txt',
              'live_response/network/arp-cache.txt']),
            ('Active connections', self._check_connections,
             ['*netstat.txt', '*ss.txt', '*connections.txt',
              'live_response/network/netstat.txt',
              'live_response/network/ss.txt']),
            ('Apache access logs', self._check_web,
             ['var/log/apache2/access.log',
              '*apache2/access.log',  '*apache2/access.log.gz',
              '*httpd/access_log',    '*httpd/access_log.gz',
              '*apache*access*',      '*httpd*access*']),
            ('Nginx access logs',  self._check_web,
             ['var/log/nginx/access.log',
              '*nginx/access.log',    '*nginx/access.log.gz',
              '*nginx*access*']),
        ]

        for label, handler_fn, patterns in checks:
            pairs = self.handler.find_files_by_suffix(patterns)
            if verbose and pairs:
                logger.info("[%s] %d file(s)", label, len(pairs))
            handler_fn(pairs)

        if verbose:
            logger.info("Network findings:  %d", len(self.findings))
            logger.info("Web access events: %d", len(self.web_events))

    # ------------------------------------------------------------------
    # Per-artifact handlers
    # ------------------------------------------------------------------

    def _check_hosts(self, pairs: List[Tuple[str, str]]) -> None:
        for path, content in pairs:
            self.findings.extend(parse_hosts_file(content, path))

    def _check_resolv(self, pairs: List[Tuple[str, str]]) -> None:
        for path, content in pairs:
            self.findings.extend(parse_resolv_conf(content, path))

    def _check_tcp_wrappers(self, pairs: List[Tuple[str, str]]) -> None:
        for path, content in pairs:
            allow = 'allow' in path.lower()
            self.findings.extend(parse_tcp_wrappers(content, path, allow))

    def _check_ufw(self, pairs: List[Tuple[str, str]],
                   ref_year: int) -> None:
        for path, content in pairs:
            self.findings.extend(parse_ufw_log(content, path, ref_year))

    def _check_arp(self, pairs: List[Tuple[str, str]]) -> None:
        for path, content in pairs:
            self.findings.extend(parse_arp_cache(content, path))

    def _check_connections(self, pairs: List[Tuple[str, str]]) -> None:
        for path, content in pairs:
            self.findings.extend(parse_connections(content, path))

    def _check_web(self, pairs: List[Tuple[str, str]]) -> None:
        for path, content in pairs:
            self.web_events.extend(parse_web_access_log(content, path,
                                                         unmatched=self.unmatched))

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_findings_csv(self, output_path: str) -> str:
        """Export network findings to CSV."""
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (sev_order.get(f.severity, 5),
                           f.timestamp or datetime.max),
        )
        fieldnames = [
            'Timestamp_UTC', 'Finding_Type', 'Severity', 'Description',
            'Source_IP', 'Dest_IP', 'Dest_Port', 'Protocol',
            'Action', 'Log_File', 'Raw_Entry',
        ]
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(e.to_dict() for e in sorted_findings)
        return output_path

    def export_web_access_csv(self, output_path: str,
                              max_rows: int = 0) -> str:
        """
        Export web access events to CSV.

        All events are included by default.  Set *max_rows* > 0 to limit
        output (suspicious entries are always prioritised).
        """
        if max_rows > 0:
            suspicious = [e for e in self.web_events if e.is_suspicious]
            normal_cap = max(0, max_rows - len(suspicious))
            normal = [e for e in self.web_events
                      if not e.is_suspicious][:normal_cap]
            rows = sorted(suspicious + normal,
                          key=lambda e: e.timestamp or datetime.max)
        else:
            rows = sorted(self.web_events,
                          key=lambda e: e.timestamp or datetime.max)
        fieldnames = [
            'Timestamp_UTC', 'Client_IP', 'Method', 'URI',
            'Status_Code', 'Response_Bytes', 'Referrer', 'User_Agent',
            'Log_File', 'Suspicious', 'Suspicion_Reason',
        ]
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(e.to_dict() for e in rows)
        return output_path

    def export_unmatched_csv(self, output_path: str) -> Optional[str]:
        """Export lines that didn't match the access-log regex."""
        return self.unmatched.export_csv(output_path)

    def close(self):
        self.handler.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _reference_year(self) -> int:
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
        description='Linux Network Artifact Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

Parses /etc/hosts, /etc/resolv.conf, UFW/firewalld logs, ARP cache,
active connection tables, Apache and Nginx access logs from a UAC
tarball or extracted directory.

Examples:
  python linux_network_analyzer.py -s uac-hostname.tar.gz
  python linux_network_analyzer.py -s ./extracted_uac/ -o ./results/
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
        logger.error("Source not found: %s", source)
        sys.exit(1)

    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    analyzer = NetworkAnalyzer(source)
    try:
        analyzer.analyze(verbose=not args.quiet)

        if analyzer.findings:
            out = os.path.join(output_dir, 'network_findings.csv')
            analyzer.export_findings_csv(out)
            if not args.quiet:
                logger.info("Network findings: %s", out)

        if analyzer.web_events:
            out = os.path.join(output_dir, 'web_access.csv')
            analyzer.export_web_access_csv(out)
            if not args.quiet:
                logger.info("Web access: %s", out)

        out = os.path.join(output_dir, 'network_unmatched.csv')
        if analyzer.export_unmatched_csv(out):
            if not args.quiet:
                logger.info("Unmatched web-log lines: %s", out)

        if not analyzer.findings and not analyzer.web_events:
            if not args.quiet:
                logger.info("No network artifacts found.")
    finally:
        analyzer.close()


if __name__ == '__main__':
    setup_logging()
    main()
