#!/usr/bin/env python3
"""
Linux Unified Security Analyzer - Orchestrator Script

Runs all Linux forensic analysis tools in parallel and outputs
results to a unified analysis folder named [hostname]_analysis.

Included Analyzers:
- linux_login_timeline.py    - Login/authentication timeline
- linux_journal_analyzer.py  - Systemd journal analysis
- linux_persistence_hunter.py - Persistence mechanism detection
- linux_security_analyzer.py  - Binary/environment security analysis
- linux_memory_analyzer.py   - Memory forensics (optional, requires memory dump)

Author: Security Tools
Version: 1.1.0
License: MIT

Requirements: Python 3.6+ (standard library only)
             Volatility 3 (optional, for memory analysis)
"""

import argparse
import csv
import os
import re
import sys
import tarfile
import tempfile
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.1.0"


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
# Hostname Extraction
# ============================================================================

def extract_hostname_from_tarball(tarball_path: str) -> str:
    """Extract hostname from UAC tarball name or contents."""
    hostname = "unknown"
    
    # Try to get hostname from tarball filename
    # UAC format: uac-hostname-timestamp.tar.gz (hostname comes AFTER uac-)
    basename = os.path.basename(tarball_path)
    for ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar'):
        if basename.lower().endswith(ext):
            basename = basename[:-len(ext)]
            break
    
    # UAC naming pattern: uac-hostname-timestamp or uac_hostname_timestamp
    # Hostname is the part AFTER "uac-" or "uac_"
    lower_basename = basename.lower()
    if lower_basename.startswith('uac-') or lower_basename.startswith('uac_'):
        # Remove the "uac-" or "uac_" prefix
        after_uac = basename[4:]  # Skip "uac-" or "uac_"
        # Hostname is typically the next segment before the timestamp
        # Format: hostname-YYYYMMDD or hostname_YYYYMMDD
        parts = re.split(r'[-_]', after_uac)
        if parts:
            # Find the hostname (non-timestamp parts at the beginning)
            hostname_parts = []
            for part in parts:
                # Stop if we hit a timestamp-like segment (all digits, 6+ chars)
                if re.match(r'^\d{6,}$', part):
                    break
                hostname_parts.append(part)
            if hostname_parts:
                hostname = '-'.join(hostname_parts)
    
    # Fallback: check for old format (hostname-uac-timestamp)
    if hostname == "unknown":
        for sep in ['-uac', '_uac', '-UAC', '_UAC']:
            if sep in basename:
                hostname = basename.split(sep)[0]
                break
    
    if hostname == "unknown":
        # Try first segment before common separators
        for sep in ['-', '_', '.']:
            if sep in basename:
                hostname = basename.split(sep)[0]
                break
        if hostname == "unknown":
            hostname = basename
    
    # Try to read hostname from tarball contents
    try:
        if tarball_path.endswith('.gz') or tarball_path.endswith('.tgz'):
            tar = tarfile.open(tarball_path, 'r:gz')
        elif tarball_path.endswith('.bz2'):
            tar = tarfile.open(tarball_path, 'r:bz2')
        elif tarball_path.endswith('.xz'):
            tar = tarfile.open(tarball_path, 'r:xz')
        else:
            tar = tarfile.open(tarball_path, 'r')
        
        # Look for etc/hostname file
        for member in tar.getmembers()[:500]:
            if member.name.endswith('etc/hostname') and member.isfile():
                f = tar.extractfile(member)
                if f:
                    content = f.read().decode('utf-8', errors='replace').strip()
                    if content and len(content) < 64:
                        hostname = content
                        break
        tar.close()
    except Exception:
        pass
    
    # Sanitize hostname for filesystem
    hostname = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', hostname)
    return hostname


def extract_hostname_from_directory(dir_path: str) -> str:
    """Extract hostname from extracted UAC directory."""
    hostname = "unknown"
    
    # Try to read etc/hostname
    hostname_file = os.path.join(dir_path, 'etc', 'hostname')
    if os.path.exists(hostname_file):
        try:
            with open(hostname_file, 'r') as f:
                content = f.read().strip()
                if content and len(content) < 64:
                    hostname = content
        except Exception:
            pass
    
    # Also check nested UAC structure
    if hostname == "unknown":
        for root, dirs, files in os.walk(dir_path):
            if 'hostname' in files:
                try:
                    with open(os.path.join(root, 'hostname'), 'r') as f:
                        content = f.read().strip()
                        if content and len(content) < 64:
                            hostname = content
                            break
                except Exception:
                    pass
            # Limit search depth
            if root.count(os.sep) - dir_path.count(os.sep) > 3:
                break
    
    # Fallback to directory name
    if hostname == "unknown":
        hostname = os.path.basename(dir_path.rstrip('/\\'))
    
    # Sanitize hostname for filesystem
    hostname = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', hostname)
    return hostname


# ============================================================================
# Analyzer Wrappers
# ============================================================================

def run_login_timeline(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the login timeline analyzer."""
    result = {
        "name": "Login Timeline",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "error": None
    }
    
    try:
        # Import the module
        import linux_login_timeline as llt
        
        # Create timeline object
        timeline = llt.LinuxLoginTimeline(source_path)
        
        # Collect events (verbose=False for parallel execution)
        if timeline.is_tarball:
            timeline._collect_from_tarball(verbose=False)
        else:
            timeline._collect_from_directory(verbose=False)
        
        if timeline.events:
            # Export to CSV
            output_file = os.path.join(output_dir, f"{hostname}_login_timeline.csv")
            timeline.export_csv(output_file)
            result["output_files"].append(output_file)
            result["event_count"] = len(timeline.events)
            result["success"] = True
        else:
            result["error"] = "No events found"
            result["success"] = True  # Not a failure, just no data
        
        # Close tarball handler if used
        if timeline.tarball_handler:
            timeline.tarball_handler.close()
            
    except Exception as e:
        result["error"] = str(e)
    
    return result


def run_journal_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the journal analyzer."""
    result = {
        "name": "Journal Analyzer",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "error": None
    }
    
    try:
        # Import the module
        import linux_journal_analyzer as lja
        
        # Create handler and parser
        handler = lja.UACHandler(source_path)
        
        # Get reference date for year inference
        reference_date = None
        if os.path.isfile(source_path):
            try:
                mtime = os.path.getmtime(source_path)
                reference_date = datetime.fromtimestamp(mtime)
            except (OSError, ValueError):
                pass
        
        if reference_date is None:
            reference_date = datetime.now()
        
        parser = lja.JournalParser(handler, reference_date=reference_date)
        entries = parser.parse_all()
        
        if entries:
            # Export all entries
            all_path = os.path.join(output_dir, f"{hostname}_journal.csv")
            lja.export_csv(entries, all_path)
            result["output_files"].append(all_path)
            
            # Export security events
            sec_path = os.path.join(output_dir, f"{hostname}_journal_security.csv")
            lja.export_security_report(entries, sec_path)
            if os.path.exists(sec_path):
                result["output_files"].append(sec_path)
            
            result["event_count"] = len(entries)
            result["success"] = True
        else:
            result["error"] = "No entries found"
            result["success"] = True
        
        handler.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def run_persistence_hunter(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the persistence hunter."""
    result = {
        "name": "Persistence Hunter",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None
    }
    
    try:
        # Import the module
        import linux_persistence_hunter as lph
        
        # Run the hunter
        hunter = lph.PersistenceHunter(source_path)
        hunter.hunt(verbose=False)
        
        if hunter.findings:
            output_file = os.path.join(output_dir, f"{hostname}_persistence.csv")
            hunter.export_csv(output_file)
            result["output_files"].append(output_file)
            result["finding_count"] = len(hunter.findings)
        
        result["success"] = True
        hunter.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def run_security_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the security analyzer."""
    result = {
        "name": "Security Analyzer",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None
    }
    
    try:
        # Import the module
        import linux_security_analyzer as lsa
        
        # Run the analyzer - it will use its own hostname from the handler
        analyzer = lsa.LinuxSecurityAnalyzer(source_path, output_dir)
        analyzer.analyze(verbose=False)
        
        # Count findings
        result["finding_count"] = len(analyzer.findings)
        
        if analyzer.findings:
            # Export findings - the analyzer uses its own hostname
            exported_files = analyzer.export_csv()
            
            # Rename files to use our consistent hostname prefix format
            for category, old_path in exported_files.items():
                if old_path and os.path.exists(old_path):
                    new_name = f"{hostname}_security_{category}.csv"
                    new_path = os.path.join(output_dir, new_name)
                    if old_path != new_path:
                        try:
                            shutil.move(old_path, new_path)
                        except Exception:
                            new_path = old_path  # Keep original if rename fails
                    result["output_files"].append(new_path)
        
        result["success"] = True
        analyzer.close()
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def run_memory_analyzer(memory_path: str, output_dir: str, hostname: str,
                        symbol_dirs: List[str] = None, quick: bool = False) -> Dict:
    """Run the memory analyzer (Volatility 3 wrapper)."""
    result = {
        "name": "Memory Analyzer",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None
    }
    
    try:
        # Import the module
        import linux_memory_analyzer as lma
        
        # Check if Volatility is installed
        installed, msg = lma.check_volatility_installed()
        if not installed:
            result["error"] = f"Volatility 3 not installed. Run: python linux_memory_analyzer.py --setup"
            return result
        
        # Create memory-specific output subdirectory
        memory_output_dir = os.path.join(output_dir, "memory_analysis")
        os.makedirs(memory_output_dir, exist_ok=True)
        
        # Create analyzer
        analyzer = lma.LinuxMemoryAnalyzer(
            image_path=memory_path,
            output_dir=memory_output_dir,
            symbol_dirs=symbol_dirs,
            offline=True  # Don't try to download symbols
        )
        
        # Validate
        valid, msg = analyzer.validate()
        if not valid:
            result["error"] = msg
            return result
        
        # Run analysis
        if quick:
            # Quick triage mode
            lma.quick_triage(memory_path, symbol_dirs=symbol_dirs, verbose=False)
        else:
            analyzer.analyze(include_optional=False, verbose=False, skip_symbol_check=True)
        
        # Count output files
        if os.path.exists(memory_output_dir):
            for filename in os.listdir(memory_output_dir):
                if filename.endswith('.csv'):
                    filepath = os.path.join(memory_output_dir, filename)
                    result["output_files"].append(filepath)
                    # Count rows in CSV
                    try:
                        with open(filepath, 'r') as f:
                            lines = sum(1 for _ in f) - 1  # Subtract header
                            result["finding_count"] += max(0, lines)
                    except:
                        pass
        
        result["success"] = True
        
    except ImportError:
        result["error"] = "linux_memory_analyzer.py not found"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def run_package_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the package manager log analyzer."""
    result: Dict = {
        "name": "Package Analyzer",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "error": None,
    }
    try:
        import linux_package_analyzer as lpa
        analyzer = lpa.PackageAnalyzer(source_path)
        analyzer.analyze(verbose=False)
        if analyzer.events:
            out = os.path.join(output_dir, f"{hostname}_packages.csv")
            analyzer.export_csv(out)
            result["output_files"].append(out)
            result["event_count"] = len(analyzer.events)
        result["success"] = True
        analyzer.close()
    except ImportError:
        result["error"] = "linux_package_analyzer.py not found"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def run_network_analyzer(source_path: str, output_dir: str, hostname: str) -> Dict:
    """Run the network artifact analyzer."""
    result: Dict = {
        "name": "Network Analyzer",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None,
    }
    try:
        import linux_network_analyzer as lna
        analyzer = lna.NetworkAnalyzer(source_path)
        analyzer.analyze(verbose=False)
        if analyzer.findings:
            out = os.path.join(output_dir, f"{hostname}_network.csv")
            analyzer.export_findings_csv(out)
            result["output_files"].append(out)
            result["finding_count"] += len(analyzer.findings)
        if analyzer.web_events:
            out = os.path.join(output_dir, f"{hostname}_web_access.csv")
            analyzer.export_web_access_csv(out)
            result["output_files"].append(out)
            result["finding_count"] += len(analyzer.web_events)
        result["success"] = True
        analyzer.close()
    except ImportError:
        result["error"] = "linux_network_analyzer.py not found"
    except Exception as exc:
        result["error"] = str(exc)
    return result


# ============================================================================
# Post-Processing: IOC Matching
# ============================================================================

_RE_IPV4   = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_RE_MD5    = re.compile(r'^[0-9a-fA-F]{32}$')
_RE_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')
_RE_DOMAIN = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')


def _classify_ioc(raw: str) -> Tuple[str, str]:
    """Return (ioc_type, normalised_value) for a raw IOC string."""
    raw = raw.strip()
    if ':' in raw:
        prefix, val = raw.split(':', 1)
        prefix = prefix.lower()
        if prefix in ('ip', 'domain', 'md5', 'sha256', 'sha1', 'path', 'hash'):
            return prefix if prefix != 'hash' else 'md5', val.strip()
    if _RE_IPV4.match(raw):
        return 'ip', raw
    if _RE_SHA256.match(raw):
        return 'sha256', raw.lower()
    if _RE_MD5.match(raw):
        return 'md5', raw.lower()
    if raw.startswith('/') or raw.startswith('\\'):
        return 'path', raw
    if _RE_DOMAIN.match(raw):
        return 'domain', raw.lower()
    return 'unknown', raw


def load_ioc_file(ioc_path: str) -> List[Tuple[str, str]]:
    """
    Load IOC indicators from a plain-text file.
    Returns list of (ioc_type, value) tuples.
    Lines starting with '#' are comments; blank lines are ignored.
    """
    iocs: List[Tuple[str, str]] = []
    try:
        with open(ioc_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                ioc_type, value = _classify_ioc(line)
                if ioc_type != 'unknown' and value:
                    iocs.append((ioc_type, value))
    except Exception:
        pass
    return iocs


def run_ioc_matcher(output_dir: str, hostname: str,
                    ioc_path: str) -> Dict:
    """
    Cross-reference IOC indicators against all generated CSVs.

    Searches:
      - _login_timeline.csv  : source_ip  → IP match
      - _network.csv         : Source_IP, Dest_IP, Description → IP / domain
      - _persistence.csv     : MD5, SHA256, Filepath, Indicator → hash / path
      - _security_*.csv      : MD5, SHA256, Filepath → hash / path
      - _packages.csv        : Package → keyword match
      - _mac_timeline.csv    : Filename, MD5 → path / hash
    """
    result: Dict = {
        "name": "IOC Matcher",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None,
    }
    try:
        iocs = load_ioc_file(ioc_path)
        if not iocs:
            result["error"] = "No valid IOCs loaded from file"
            result["success"] = True
            return result

        ip_iocs     = {v for t, v in iocs if t == 'ip'}
        domain_iocs = {v for t, v in iocs if t == 'domain'}
        md5_iocs    = {v for t, v in iocs if t == 'md5'}
        sha256_iocs = {v for t, v in iocs if t == 'sha256'}
        path_iocs   = [v for t, v in iocs if t == 'path']

        hits: List[Dict] = []

        # Columns to search per CSV type
        search_map = {
            f"{hostname}_login_timeline.csv": {
                'ip': ['source_ip'],
            },
            f"{hostname}_network.csv": {
                'ip':     ['Source_IP', 'Dest_IP'],
                'domain': ['Description', 'Raw_Entry'],
            },
            f"{hostname}_web_access.csv": {
                'ip':     ['Client_IP'],
                'domain': ['URI', 'Referrer'],
            },
            f"{hostname}_persistence.csv": {
                'md5':    ['MD5'],
                'sha256': ['SHA256'],
                'path':   ['Filepath', 'Indicator'],
                'domain': ['Indicator', 'Raw_Content'],
            },
            f"{hostname}_mac_timeline.csv": {
                'md5':  ['MD5'],
                'path': ['Filename'],
            },
        }
        # Security CSVs: glob pattern
        for fname in os.listdir(output_dir):
            if re.match(rf'^{re.escape(hostname)}_security_.*\.csv$', fname):
                search_map[fname] = {
                    'md5':    ['MD5'],
                    'sha256': ['SHA256'],
                    'path':   ['Filepath'],
                }
            if re.match(rf'^{re.escape(hostname)}_packages\.csv$', fname):
                search_map[fname] = {
                    'domain': ['Package', 'Raw_Entry'],
                }

        for csv_name, col_map in search_map.items():
            csv_path = os.path.join(output_dir, csv_name)
            if not os.path.isfile(csv_path):
                continue
            try:
                with open(csv_path, newline='', encoding='utf-8',
                          errors='replace') as f:
                    reader = csv.DictReader(f)
                    for row_num, row in enumerate(reader, 2):
                        for ioc_type, columns in col_map.items():
                            for col in columns:
                                if col not in row:
                                    continue
                                cell = (row[col] or '').strip()
                                if not cell:
                                    continue

                                matched_val = ''
                                if ioc_type == 'ip' and ip_iocs:
                                    if cell in ip_iocs:
                                        matched_val = cell
                                    else:
                                        for ip in ip_iocs:
                                            if ip in cell:
                                                matched_val = ip
                                                break
                                elif ioc_type == 'domain' and domain_iocs:
                                    cell_lower = cell.lower()
                                    for d in domain_iocs:
                                        if d in cell_lower:
                                            matched_val = d
                                            break
                                elif ioc_type == 'md5' and md5_iocs:
                                    if cell.lower() in md5_iocs:
                                        matched_val = cell.lower()
                                elif ioc_type == 'sha256' and sha256_iocs:
                                    if cell.lower() in sha256_iocs:
                                        matched_val = cell.lower()
                                elif ioc_type == 'path' and path_iocs:
                                    for p in path_iocs:
                                        if p in cell:
                                            matched_val = p
                                            break

                                if matched_val:
                                    hits.append({
                                        'IOC_Value':      matched_val,
                                        'IOC_Type':       ioc_type.upper(),
                                        'Source_CSV':     csv_name,
                                        'CSV_Row':        row_num,
                                        'Matched_Column': col,
                                        'Matched_Value':  cell[:200],
                                        'Context':        str(row)[:300],
                                    })
            except Exception:
                continue

        if hits:
            out = os.path.join(output_dir, f"{hostname}_ioc_hits.csv")
            fieldnames = [
                'IOC_Value', 'IOC_Type', 'Source_CSV',
                'CSV_Row', 'Matched_Column', 'Matched_Value', 'Context',
            ]
            with open(out, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(hits)
            result["output_files"].append(out)
            result["finding_count"] = len(hits)

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================================
# Post-Processing: Log Gap Detection
# ============================================================================

def run_log_gap_detection(output_dir: str, hostname: str,
                           gap_threshold_hours: float = 6.0) -> Dict:
    """
    Identify suspicious time-gaps in the login/auth event timeline.

    Reads the generated login timeline CSV, computes inter-event gaps,
    and flags gaps exceeding *gap_threshold_hours*.  Large gaps during
    an otherwise active period may indicate log-file clearing or deletion.

    Returns a result dict with gap statistics; does NOT write a separate
    file – findings are added to the summary report section instead.
    """
    result: Dict = {
        "name": "Log Gap Detection",
        "success": False,
        "output_files": [],
        "finding_count": 0,
        "error": None,
        "gap_summary": [],        # list of (start, end, hours) for display
    }

    timeline_csv = os.path.join(output_dir, f"{hostname}_login_timeline.csv")
    if not os.path.isfile(timeline_csv):
        result["error"] = "Login timeline CSV not found; gap detection skipped"
        result["success"] = True
        return result

    try:
        timestamps: List[datetime] = []
        with open(timeline_csv, newline='', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ts_val = row.get('Timestamp_UTC') or row.get('Timestamp') or ''
                if not ts_val:
                    continue
                try:
                    ts = datetime.strptime(ts_val.strip(), '%Y-%m-%d %H:%M:%S')
                    timestamps.append(ts)
                except ValueError:
                    pass

        if len(timestamps) < 2:
            result["error"] = "Insufficient events for gap analysis"
            result["success"] = True
            return result

        timestamps.sort()
        gaps: List[Tuple[datetime, datetime, float]] = []

        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds() / 3600.0
            if delta >= gap_threshold_hours:
                gaps.append((timestamps[i - 1], timestamps[i], delta))

        # Sort by largest gap first
        gaps.sort(key=lambda x: -x[2])

        # Write a gaps CSV if any significant gaps found
        if gaps:
            out = os.path.join(output_dir, f"{hostname}_log_gaps.csv")
            fieldnames = [
                'Gap_Start_UTC', 'Gap_End_UTC',
                'Gap_Duration_Hours', 'Severity',
            ]
            with open(out, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for start, end, hours in gaps:
                    sev = 'HIGH' if hours >= 48 else ('MEDIUM' if hours >= 12 else 'LOW')
                    writer.writerow({
                        'Gap_Start_UTC':       start.strftime('%Y-%m-%d %H:%M:%S'),
                        'Gap_End_UTC':         end.strftime('%Y-%m-%d %H:%M:%S'),
                        'Gap_Duration_Hours':  f"{hours:.1f}",
                        'Severity':            sev,
                    })
            result["output_files"].append(out)
            result["finding_count"] = len(gaps)

            # Store top-5 for summary display
            result["gap_summary"] = [
                (s.strftime('%Y-%m-%d %H:%M'),
                 e.strftime('%Y-%m-%d %H:%M'),
                 h)
                for s, e, h in gaps[:5]
            ]

        result["success"] = True

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================================
# Correlation and Summary
# ============================================================================

def create_summary_report(output_dir: str, hostname: str, results: List[Dict],
                         start_time: datetime, end_time: datetime,
                         bodyfile_path: Optional[str] = None) -> str:
    """Create a summary report of all analysis results."""
    summary_path = os.path.join(output_dir, f"{hostname}_analysis_summary.txt")

    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(f"  Linux Unified Security Analysis Summary\n")
        f.write(f"  Hostname: {hostname}\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"Analysis Start:  {start_time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"Analysis End:    {end_time.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        f.write(f"Duration:        {(end_time - start_time).total_seconds():.2f} seconds\n")
        f.write(f"Tool Version:    {__version__}\n")
        if bodyfile_path:
            f.write(f"Bodyfile:        {bodyfile_path}\n")
        else:
            f.write(f"Bodyfile:        not provided (MAC timeline skipped)\n")
        f.write("\n")
        
        f.write("-" * 70 + "\n")
        f.write("  Analyzer Results\n")
        f.write("-" * 70 + "\n\n")
        
        total_events = 0
        total_findings = 0
        all_files = []
        
        for result in results:
            status = "SUCCESS" if result["success"] else "FAILED"
            f.write(f"[{status}] {result['name']}\n")
            
            if result.get("event_count"):
                f.write(f"         Events: {result['event_count']}\n")
                total_events += result["event_count"]
            
            if result.get("finding_count"):
                f.write(f"         Findings: {result['finding_count']}\n")
                total_findings += result["finding_count"]
            
            if result.get("error"):
                f.write(f"         Note: {result['error']}\n")
            
            if result.get("output_files"):
                for output_file in result["output_files"]:
                    f.write(f"         Output: {os.path.basename(output_file)}\n")
                    all_files.append(output_file)
            
            f.write("\n")
        
        f.write("-" * 70 + "\n")
        f.write("  Summary Statistics\n")
        f.write("-" * 70 + "\n\n")
        f.write(f"Total Timeline Events:     {total_events}\n")
        f.write(f"Total Security Findings:   {total_findings}\n")
        f.write(f"Output Files Generated:    {len(all_files)}\n")

        # IOC hits
        ioc_result = next((r for r in results if r.get("name") == "IOC Matcher"), None)
        if ioc_result and ioc_result.get("finding_count"):
            f.write(f"IOC Hits:                  {ioc_result['finding_count']}\n")

        # Log gap summary
        gap_result = next((r for r in results if r.get("name") == "Log Gap Detection"), None)
        if gap_result and gap_result.get("gap_summary"):
            f.write(f"\n")
            f.write("-" * 70 + "\n")
            f.write("  Notable Log Gaps (possible log tampering)\n")
            f.write("-" * 70 + "\n\n")
            for start_s, end_s, hours in gap_result["gap_summary"]:
                sev = "HIGH" if hours >= 48 else ("MEDIUM" if hours >= 12 else "LOW")
                f.write(f"  [{sev:6}] {start_s} → {end_s}  ({hours:.1f} h)\n")
        f.write("\n")

        # ── Artifact Summary ─────────────────────────────────────────────────
        f.write("-" * 70 + "\n")
        f.write("  Artifact Summary\n")
        f.write("-" * 70 + "\n\n")

        _SKIP_VALS = frozenset({'', '0.0.0.0', '::', '::1', 'n/a', '-', 'unknown', 'none'})

        def _skip_ip(ip: str) -> bool:
            v = ip.lower()
            return v in _SKIP_VALS or v.startswith('127.') or v == '::1'

        unique_users: set = set()
        unique_ips: set = set()

        # Login timeline – users and source IPs
        login_csv = os.path.join(output_dir, f"{hostname}_login_timeline.csv")
        if os.path.isfile(login_csv):
            try:
                with open(login_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        u = (_row.get('username') or '').strip()
                        if u and u.lower() not in _SKIP_VALS:
                            unique_users.add(u)
                        ip = (_row.get('source_ip') or '').strip()
                        if ip and not _skip_ip(ip):
                            unique_ips.add(ip)
            except Exception:
                pass

        # Network findings – source and dest IPs
        net_csv = os.path.join(output_dir, f"{hostname}_network.csv")
        if os.path.isfile(net_csv):
            try:
                with open(net_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        for _col in ('Source_IP', 'Dest_IP'):
                            ip = (_row.get(_col) or '').strip()
                            if ip and not _skip_ip(ip):
                                unique_ips.add(ip)
            except Exception:
                pass

        # Web access – client IPs
        web_csv = os.path.join(output_dir, f"{hostname}_web_access.csv")
        if os.path.isfile(web_csv):
            try:
                with open(web_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        ip = (_row.get('Client_IP') or '').strip()
                        if ip and not _skip_ip(ip):
                            unique_ips.add(ip)
            except Exception:
                pass

        def _ip_sort_key(ip: str):
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    return (0, tuple(int(p) for p in parts))
                except ValueError:
                    pass
            return (1, (ip,))

        if unique_users:
            f.write(f"  Unique Users ({len(unique_users)}):\n")
            for _u in sorted(unique_users):
                f.write(f"    {_u}\n")
            f.write("\n")

        if unique_ips:
            f.write(f"  Unique IP Addresses ({len(unique_ips)}):\n")
            for _ip in sorted(unique_ips, key=_ip_sort_key):
                f.write(f"    {_ip}\n")
            f.write("\n")

        # Top persistence findings (CRITICAL / HIGH)
        persist_csv = os.path.join(output_dir, f"{hostname}_persistence.csv")
        top_findings: List[Tuple] = []
        if os.path.isfile(persist_csv):
            try:
                with open(persist_csv, newline='', encoding='utf-8', errors='replace') as _fh:
                    for _row in csv.DictReader(_fh):
                        sev = (_row.get('Severity') or '').upper()
                        if sev in ('CRITICAL', 'HIGH'):
                            top_findings.append((
                                sev,
                                _row.get('Technique', ''),
                                _row.get('Description', ''),
                                _row.get('Filepath', ''),
                            ))
            except Exception:
                pass

        if top_findings:
            _sev_order = {'CRITICAL': 0, 'HIGH': 1}
            top_findings.sort(key=lambda x: _sev_order.get(x[0], 9))
            f.write(f"  Critical/High Persistence Findings ({len(top_findings)}):\n")
            for _sev, _tech, _desc, _fp in top_findings[:20]:
                f.write(f"    [{_sev}] {_tech}: {_desc}\n")
                if _fp:
                    f.write(f"           {_fp}\n")
            if len(top_findings) > 20:
                f.write(f"    ... and {len(top_findings) - 20} more (see persistence CSV)\n")
            f.write("\n")

        if not unique_users and not unique_ips and not top_findings:
            f.write("  No artifact data collected.\n\n")

        f.write("-" * 70 + "\n")
        f.write("  Output Files\n")
        f.write("-" * 70 + "\n\n")

        for filepath in sorted(all_files):
            basename = os.path.basename(filepath)
            try:
                size = os.path.getsize(filepath)
                size_str = f"{size:,} bytes"
            except:
                size_str = "unknown size"
            f.write(f"  {basename} ({size_str})\n")
    
    return summary_path


# ============================================================================
# Tarball Discovery
# ============================================================================

TARBALL_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz')


def find_tarballs_in_directory(dir_path: str) -> List[str]:
    """
    Find all UAC tarballs in a directory (non-recursive, top-level only).
    
    Args:
        dir_path: Directory to search
        
    Returns:
        List of tarball paths found
    """
    tarballs = []
    try:
        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)
            if os.path.isfile(item_path):
                if any(item.lower().endswith(ext) for ext in TARBALL_EXTENSIONS):
                    tarballs.append(item_path)
    except PermissionError:
        pass
    return sorted(tarballs)


def is_extracted_uac_directory(dir_path: str) -> bool:
    """
    Check if a directory appears to be an extracted UAC collection.
    
    Looks for typical UAC structure: var/log, etc/passwd, home/, etc.
    
    Args:
        dir_path: Directory to check
        
    Returns:
        True if this looks like an extracted UAC directory
    """
    # Check for common UAC artifacts
    indicators = [
        os.path.join(dir_path, "var", "log"),
        os.path.join(dir_path, "etc", "passwd"),
        os.path.join(dir_path, "etc", "hostname"),
    ]
    
    # Also check for nested structure (hostname/var/log)
    try:
        for subdir in os.listdir(dir_path):
            subdir_path = os.path.join(dir_path, subdir)
            if os.path.isdir(subdir_path):
                nested_indicators = [
                    os.path.join(subdir_path, "var", "log"),
                    os.path.join(subdir_path, "etc", "passwd"),
                ]
                if any(os.path.exists(p) for p in nested_indicators):
                    return True
    except PermissionError:
        pass
    
    return any(os.path.exists(p) for p in indicators)


# ============================================================================
# Bodyfile Support
# ============================================================================

#: Bodyfile names that UAC or other collection tools typically produce.
_BODYFILE_NAMES = frozenset({
    'body', 'bodyfile',
    'body.gz', 'bodyfile.gz',
    'body.txt', 'bodyfile.txt',
})

#: Human-readable labels for each MAC timestamp type.
_MAC_LABELS = {
    'M': 'Modification',
    'A': 'Access',
    'C': 'Change (metadata)',
    'B': 'Birth (creation)',
}


def find_bodyfile_in_source(source_path: str) -> Tuple[Optional[str], bool]:
    """
    Auto-detect a Sleuth Kit bodyfile within a UAC tarball or directory.

    UAC typically stores a bodyfile at paths such as:
      [hostname]/[date]/body
      [hostname]/[date]/bodyfile
      body  (flat)
      live_response/body

    Args:
        source_path: Path to UAC tarball or extracted directory.

    Returns:
        Tuple of (bodyfile_path, is_temp).
        ``is_temp`` is True when the file was extracted to a temporary
        location and must be deleted after use.
    """
    # ---- Tarball source -------------------------------------------------- #
    if os.path.isfile(source_path):
        try:
            if source_path.lower().endswith('.gz') or source_path.lower().endswith('.tgz'):
                tar = tarfile.open(source_path, 'r:gz')
            elif source_path.lower().endswith('.bz2'):
                tar = tarfile.open(source_path, 'r:bz2')
            elif source_path.lower().endswith('.xz'):
                tar = tarfile.open(source_path, 'r:xz')
            else:
                tar = tarfile.open(source_path, 'r')

            for member in tar.getmembers():
                if not member.isfile():
                    continue
                basename = os.path.basename(member.name).lower()
                if basename in _BODYFILE_NAMES:
                    suffix = '.body.gz' if basename.endswith('.gz') else '.body'
                    tmp = tempfile.NamedTemporaryFile(
                        delete=False, suffix=suffix, prefix='lft_body_'
                    )
                    fobj = tar.extractfile(member)
                    if fobj:
                        tmp.write(fobj.read())
                        tmp.close()
                        tar.close()
                        return tmp.name, True
            tar.close()
        except Exception:
            pass

    # ---- Directory source ------------------------------------------------- #
    elif os.path.isdir(source_path):
        base_depth = source_path.count(os.sep)
        for root, dirs, files in os.walk(source_path):
            if root.count(os.sep) - base_depth > 6:
                dirs.clear()
                continue
            for fname in files:
                if fname.lower() in _BODYFILE_NAMES:
                    return os.path.join(root, fname), False

    return None, False


def prompt_for_bodyfile(quiet: bool = False) -> Optional[str]:
    """
    Interactively prompt the analyst for an existing Sleuth Kit bodyfile.

    Sets up readline tab-completion for file paths on Unix.  On Windows
    (where readline is absent) the prompt still works, just without
    completion.  Returns ``None`` if the analyst presses Enter without
    entering a path, or if running non-interactively.

    Args:
        quiet: When True, skip the prompt entirely and return None.

    Returns:
        Absolute path to the bodyfile, or None.
    """
    if quiet or not sys.stdin.isatty():
        return None

    # Set up path tab-completion where supported
    try:
        import readline
        import glob as _glob

        def _path_completer(text, state):
            expanded = os.path.expanduser(text)
            matches = _glob.glob(expanded + '*')
            results = [m + os.sep if os.path.isdir(m) else m for m in matches]
            try:
                return results[state]
            except IndexError:
                return None

        readline.set_completer(_path_completer)
        readline.set_completer_delims('\t\n ')
        readline.parse_and_bind('tab: complete')
    except ImportError:
        pass  # Windows – proceed without tab completion

    print(
        f"\n{Style.INFO}Bodyfile (Sleuth Kit MAC timeline):{Style.RESET}",
        file=sys.stderr,
    )
    print(
        f"{Style.DIM}  Provide an existing bodyfile to use for filesystem timeline analysis.{Style.RESET}",
        file=sys.stderr,
    )
    print(
        f"{Style.DIM}  Format: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime{Style.RESET}",
        file=sys.stderr,
    )
    print(
        f"{Style.DIM}  Press Enter to auto-detect from the UAC collection (or skip if absent).{Style.RESET}",
        file=sys.stderr,
    )

    try:
        answer = input("  Bodyfile path [Enter to auto-detect]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return None

    if not answer:
        return None

    expanded = os.path.expanduser(answer)
    abs_path = os.path.abspath(expanded)

    if not os.path.isfile(abs_path):
        print(
            f"{Style.WARNING}  Warning: bodyfile not found: {abs_path}. "
            f"Will attempt auto-detection instead.{Style.RESET}",
            file=sys.stderr,
        )
        return None

    return abs_path


def run_bodyfile_analysis(bodyfile_path: str, output_dir: str, hostname: str) -> Dict:
    """
    Parse a Sleuth Kit bodyfile and produce a chronological MAC timeline CSV.

    Bodyfile format (11 pipe-separated fields):
        MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

    One output row is emitted per (file, timestamp_type) pair where the
    timestamp is non-zero and within a plausible range (1970–2100).

    MAC type legend
    ---------------
    M – Modification time (file content last changed)
    A – Access time      (file last read)
    C – Change time      (metadata last changed, e.g. permissions/owner)
    B – Birth/creation   (not available on all filesystems; may be 0)
    """
    result: Dict = {
        "name": "MAC Timeline (Bodyfile)",
        "success": False,
        "output_files": [],
        "event_count": 0,
        "error": None,
    }

    try:
        import gzip as _gzip

        events: List[Dict] = []
        parse_errors = 0
        total_lines = 0

        # Support gzip-compressed bodyfiles
        is_gz = bodyfile_path.lower().endswith('.gz')
        try:
            if is_gz:
                fh = _gzip.open(bodyfile_path, 'rt', encoding='utf-8', errors='replace')
            else:
                fh = open(bodyfile_path, 'r', encoding='utf-8', errors='replace')
        except Exception as exc:
            result["error"] = f"Cannot open bodyfile: {exc}"
            return result

        def _parse_epoch(s: str) -> int:
            """Convert a bodyfile timestamp string to integer epoch seconds."""
            s = s.strip()
            if not s or s in ('0', '-1'):
                return 0
            try:
                return int(float(s))
            except (ValueError, OverflowError):
                return 0

        with fh:
            for raw_line in fh:
                line = raw_line.rstrip('\n\r')
                if not line or line.startswith('#'):
                    continue
                total_lines += 1

                parts = line.split('|')
                if len(parts) < 11:
                    parse_errors += 1
                    continue

                # The name field (position 1) may itself contain '|'.
                # The last 9 fields are always fixed; everything between
                # field 0 (MD5) and those 9 is the name.
                md5_hash  = parts[0]
                crtime_s  = parts[-1]
                ctime_s   = parts[-2]
                mtime_s   = parts[-3]
                atime_s   = parts[-4]
                size      = parts[-5]
                gid       = parts[-6]
                uid       = parts[-7]
                mode      = parts[-8]
                inode     = parts[-9]
                name      = '|'.join(parts[1:-9])

                atime  = _parse_epoch(atime_s)
                mtime  = _parse_epoch(mtime_s)
                ctime  = _parse_epoch(ctime_s)
                crtime = _parse_epoch(crtime_s)

                is_deleted = (
                    '(deleted)' in name
                    or name.startswith('$OrphanFiles')
                )

                # Plausible epoch range: 1970-01-01 through 2100-01-01
                _MAX_EPOCH = 4102444800

                for mac_type, ts in (('M', mtime), ('A', atime),
                                     ('C', ctime),  ('B', crtime)):
                    if ts <= 0 or ts > _MAX_EPOCH:
                        continue
                    try:
                        dt_utc = datetime.utcfromtimestamp(ts)
                    except (OSError, OverflowError, ValueError):
                        continue

                    events.append({
                        'Timestamp_UTC':   dt_utc.strftime('%Y-%m-%d %H:%M:%S'),
                        'Unix_Epoch':      ts,
                        'MAC_Type':        mac_type,
                        'MAC_Description': _MAC_LABELS[mac_type],
                        'Filename':        name,
                        'Inode':           inode,
                        'Mode':            mode,
                        'UID':             uid,
                        'GID':             gid,
                        'Size_Bytes':      size,
                        'MD5':             md5_hash if md5_hash not in ('0', '') else '',
                        'Is_Deleted':      'Yes' if is_deleted else '',
                    })

        if total_lines == 0:
            result["error"] = "Bodyfile appears empty"
            result["success"] = True
            return result

        if not events:
            result["error"] = (
                f"No valid timestamps found "
                f"({parse_errors} malformed lines out of {total_lines})"
            )
            result["success"] = True
            return result

        # Sort chronologically
        events.sort(key=lambda x: x['Unix_Epoch'])

        output_file = os.path.join(output_dir, f"{hostname}_mac_timeline.csv")
        fieldnames = [
            'Timestamp_UTC', 'Unix_Epoch', 'MAC_Type', 'MAC_Description',
            'Filename', 'Inode', 'Mode', 'UID', 'GID',
            'Size_Bytes', 'MD5', 'Is_Deleted',
        ]
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(events)

        result["output_files"].append(output_file)
        result["event_count"] = len(events)
        result["success"] = True

        if parse_errors:
            result["error"] = (
                f"{parse_errors} lines skipped (malformed)"
            )

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ============================================================================
# Main Orchestrator
# ============================================================================

def run_analysis(source_path: str, output_base: str = None, parallel: bool = True,
                verbose: bool = True, memory_path: str = None,
                symbol_dirs: List[str] = None, quick_memory: bool = False,
                bodyfile_path: str = None,
                ioc_path: str = None) -> Tuple[str, List[Dict]]:
    """
    Run all analyzers on the source and output to a unified directory.
    
    Args:
        source_path: Path to UAC tarball, extracted directory, or directory containing tarballs
        output_base: Base directory for output (default: current directory)
        parallel: Whether to run analyzers in parallel
        verbose: Whether to print progress
        memory_path: Optional path to memory dump for memory analysis
        symbol_dirs: Optional list of symbol directories for memory analysis
        quick_memory: Run quick memory triage instead of full analysis
        bodyfile_path: Optional path to an existing Sleuth Kit bodyfile.
            When provided, this file is used directly for MAC timeline
            analysis and auto-detection is skipped.  When None, the
            function will attempt to locate a bodyfile inside the UAC
            source automatically.

    Returns:
        Tuple of (output_directory, results_list)
    """
    Style.enable_windows_ansi()
    start_time = datetime.now()
    
    # Resolve source path
    source_path = os.path.abspath(source_path)
    
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source not found: {source_path}")
    
    # Determine source type
    is_tarball = any(source_path.lower().endswith(ext) for ext in TARBALL_EXTENSIONS)
    
    # If it's a directory, check if it contains tarballs or is an extracted UAC
    if not is_tarball and os.path.isdir(source_path):
        tarballs_found = find_tarballs_in_directory(source_path)
        is_extracted = is_extracted_uac_directory(source_path)
        
        if tarballs_found and not is_extracted:
            # Directory contains tarballs - run batch analysis
            if verbose:
                print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
                print(f"{Style.HEADER}{Style.BOLD}  Linux Unified Security Analyzer v{__version__}{Style.RESET}", file=sys.stderr)
                print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
                print(f"\n{Style.INFO}Found {len(tarballs_found)} tarball(s) in directory:{Style.RESET}", file=sys.stderr)
                for tb in tarballs_found:
                    print(f"  - {os.path.basename(tb)}", file=sys.stderr)
            
            # Process each tarball
            all_results = []
            output_dirs = []
            for tarball in tarballs_found:
                if verbose:
                    print(f"\n{Style.HEADER}{'='*50}{Style.RESET}", file=sys.stderr)
                    print(f"{Style.INFO}Processing:{Style.RESET} {os.path.basename(tarball)}", file=sys.stderr)
                
                out_dir, results = run_analysis(
                    tarball, output_base, parallel, verbose,
                    memory_path, symbol_dirs, quick_memory,
                    bodyfile_path=None,  # auto-detect per tarball in batch mode
                    ioc_path=ioc_path,
                )
                output_dirs.append(out_dir)
                all_results.extend(results)
            
            if verbose:
                print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
                print(f"{Style.SUCCESS}Batch analysis complete!{Style.RESET}", file=sys.stderr)
                print(f"{Style.INFO}Processed {len(tarballs_found)} tarball(s){Style.RESET}", file=sys.stderr)
                for out_dir in output_dirs:
                    print(f"  - {out_dir}", file=sys.stderr)
            
            return output_dirs[0] if len(output_dirs) == 1 else output_base, all_results
        
        elif tarballs_found and is_extracted:
            # Has both tarballs and extracted content - warn user
            if verbose:
                print(f"\n{Style.WARNING}Warning: Directory contains both tarballs and extracted UAC content.{Style.RESET}", file=sys.stderr)
                print(f"{Style.INFO}Analyzing as extracted directory. To analyze tarballs, specify them directly.{Style.RESET}", file=sys.stderr)
    
    # Extract hostname
    if is_tarball:
        hostname = extract_hostname_from_tarball(source_path)
    else:
        hostname = extract_hostname_from_directory(source_path)
    
    if verbose:
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Linux Unified Security Analyzer v{__version__}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"\n{Style.INFO}Source:{Style.RESET} {source_path}", file=sys.stderr)
        print(f"{Style.INFO}Hostname:{Style.RESET} {hostname}", file=sys.stderr)
        print(f"{Style.INFO}Mode:{Style.RESET} {'Tarball' if is_tarball else 'Directory'}", file=sys.stderr)

    # Create output directory: [hostname]_analysis
    output_base = output_base or os.getcwd()
    output_dir = os.path.join(output_base, f"{hostname}_analysis")
    os.makedirs(output_dir, exist_ok=True)

    if verbose:
        print(f"{Style.INFO}Output Directory:{Style.RESET} {output_dir}", file=sys.stderr)

    # ---- Bodyfile resolution --------------------------------------------- #
    # Track whether we extracted the bodyfile to a temp path so we can clean
    # it up after analysis.
    bodyfile_is_temp = False

    if bodyfile_path and os.path.isfile(bodyfile_path):
        # Caller supplied an explicit bodyfile – use it directly.
        if verbose:
            print(
                f"{Style.INFO}Bodyfile:{Style.RESET} {bodyfile_path} (user-supplied)",
                file=sys.stderr,
            )
    else:
        # Try to locate a bodyfile inside the UAC collection.
        detected, bodyfile_is_temp = find_bodyfile_in_source(source_path)
        if detected:
            bodyfile_path = detected
            if verbose:
                print(
                    f"{Style.INFO}Bodyfile:{Style.RESET} auto-detected in UAC collection",
                    file=sys.stderr,
                )
        else:
            bodyfile_path = None
            if verbose:
                print(
                    f"{Style.DIM}Bodyfile: none found – MAC timeline will be skipped{Style.RESET}",
                    file=sys.stderr,
                )

    # Define analyzers to run
    analyzers = [
        ("Login Timeline",   run_login_timeline),
        ("Journal Analyzer", run_journal_analyzer),
        ("Persistence Hunter", run_persistence_hunter),
        ("Security Analyzer",  run_security_analyzer),
        ("Package Analyzer",   run_package_analyzer),
        ("Network Analyzer",   run_network_analyzer),
    ]

    # Prepend bodyfile analyzer when a bodyfile is available.
    if bodyfile_path and os.path.isfile(bodyfile_path):
        _bf_path = bodyfile_path  # capture for closure

        def _run_mac_timeline(src, out_dir, host):
            return run_bodyfile_analysis(_bf_path, out_dir, host)

        analyzers.insert(0, ("MAC Timeline", _run_mac_timeline))
    
    results = []
    
    if parallel:
        if verbose:
            print(f"\n{Style.INFO}Running {len(analyzers)} analyzers in parallel...{Style.RESET}", file=sys.stderr)
        
        with ThreadPoolExecutor(max_workers=len(analyzers)) as executor:
            futures = {}
            for name, func in analyzers:
                future = executor.submit(func, source_path, output_dir, hostname)
                futures[future] = name
            
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if verbose:
                        status = Style.SUCCESS + "✓" if result["success"] else Style.ERROR + "✗"
                        counts = []
                        if result.get("event_count"):
                            counts.append(f"{result['event_count']} events")
                        if result.get("finding_count"):
                            counts.append(f"{result['finding_count']} findings")
                        count_str = f" ({', '.join(counts)})" if counts else ""
                        print(f"  {status} {name}{count_str}{Style.RESET}", file=sys.stderr)
                        
                except Exception as e:
                    results.append({
                        "name": name,
                        "success": False,
                        "output_files": [],
                        "error": str(e)
                    })
                    if verbose:
                        print(f"  {Style.ERROR}✗ {name}: {e}{Style.RESET}", file=sys.stderr)
    else:
        for name, func in analyzers:
            if verbose:
                print(f"\n{Style.INFO}Running {name}...{Style.RESET}", file=sys.stderr)
            
            try:
                result = func(source_path, output_dir, hostname)
                results.append(result)
                
                if verbose and result["success"]:
                    counts = []
                    if result.get("event_count"):
                        counts.append(f"{result['event_count']} events")
                    if result.get("finding_count"):
                        counts.append(f"{result['finding_count']} findings")
                    count_str = f": {', '.join(counts)}" if counts else ""
                    print(f"  {Style.SUCCESS}✓ Complete{count_str}{Style.RESET}", file=sys.stderr)
                    
            except Exception as e:
                results.append({
                    "name": name,
                    "success": False,
                    "output_files": [],
                    "error": str(e)
                })
                if verbose:
                    print(f"  {Style.ERROR}✗ Error: {e}{Style.RESET}", file=sys.stderr)
    
    # Run memory analyzer if memory path provided
    if memory_path and os.path.exists(memory_path):
        if verbose:
            print(f"\n{Style.INFO}Running Memory Analyzer...{Style.RESET}", file=sys.stderr)
            print(f"  {Style.DIM}Image: {memory_path}{Style.RESET}", file=sys.stderr)
            if symbol_dirs:
                print(f"  {Style.DIM}Symbols: {', '.join(symbol_dirs)}{Style.RESET}", file=sys.stderr)
        
        try:
            mem_result = run_memory_analyzer(
                memory_path=memory_path,
                output_dir=output_dir,
                hostname=hostname,
                symbol_dirs=symbol_dirs,
                quick=quick_memory
            )
            results.append(mem_result)
            
            if verbose:
                if mem_result["success"]:
                    count_str = f" ({mem_result['finding_count']} entries)" if mem_result.get('finding_count') else ""
                    print(f"  {Style.SUCCESS}[OK] Memory Analyzer{count_str}{Style.RESET}", file=sys.stderr)
                else:
                    print(f"  {Style.ERROR}[FAILED] Memory Analyzer: {mem_result.get('error', 'Unknown error')}{Style.RESET}", file=sys.stderr)
        except Exception as e:
            results.append({
                "name": "Memory Analyzer",
                "success": False,
                "output_files": [],
                "error": str(e)
            })
            if verbose:
                print(f"  {Style.ERROR}[FAILED] Memory Analyzer: {e}{Style.RESET}", file=sys.stderr)
    
    # ---- Post-processing: log gap detection --------------------------------- #
    if verbose:
        print(f"\n{Style.INFO}Running log gap detection...{Style.RESET}", file=sys.stderr)
    try:
        gap_result = run_log_gap_detection(output_dir, hostname)
        results.append(gap_result)
        if verbose:
            if gap_result["finding_count"]:
                print(
                    f"  {Style.WARNING}⚠ {gap_result['finding_count']} "
                    f"gap(s) ≥ 6 h in auth timeline{Style.RESET}",
                    file=sys.stderr,
                )
            else:
                print(f"  {Style.SUCCESS}✓ No significant log gaps{Style.RESET}",
                      file=sys.stderr)
    except Exception as exc:
        results.append({"name": "Log Gap Detection", "success": False,
                        "output_files": [], "error": str(exc)})

    # ---- Post-processing: IOC matching -------------------------------------- #
    if ioc_path and os.path.isfile(ioc_path):
        if verbose:
            print(f"\n{Style.INFO}Running IOC matching...{Style.RESET}",
                  file=sys.stderr)
            print(f"  {Style.DIM}IOC file: {ioc_path}{Style.RESET}", file=sys.stderr)
        try:
            ioc_result = run_ioc_matcher(output_dir, hostname, ioc_path)
            results.append(ioc_result)
            if verbose:
                if ioc_result["finding_count"]:
                    print(
                        f"  {Style.CRITICAL}!! {ioc_result['finding_count']} "
                        f"IOC hit(s) found{Style.RESET}",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"  {Style.SUCCESS}✓ No IOC matches{Style.RESET}",
                        file=sys.stderr,
                    )
        except Exception as exc:
            results.append({"name": "IOC Matcher", "success": False,
                            "output_files": [], "error": str(exc)})

    end_time = datetime.now()

    # Create summary report
    if verbose:
        print(f"\n{Style.INFO}Creating summary report...{Style.RESET}", file=sys.stderr)
    
    summary_file = create_summary_report(
        output_dir, hostname, results, start_time, end_time,
        bodyfile_path=bodyfile_path if not bodyfile_is_temp else None,
    )
    
    # Print final summary
    if verbose:
        duration = (end_time - start_time).total_seconds()
        
        total_events = sum(r.get("event_count", 0) for r in results)
        total_findings = sum(r.get("finding_count", 0) for r in results)
        successful = sum(1 for r in results if r["success"])
        
        print(f"\n{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}  Analysis Complete{Style.RESET}", file=sys.stderr)
        print(f"{Style.HEADER}{Style.BOLD}{'='*70}{Style.RESET}", file=sys.stderr)
        print(f"\n{Style.INFO}Duration:{Style.RESET} {duration:.2f} seconds", file=sys.stderr)
        print(f"{Style.INFO}Analyzers:{Style.RESET} {successful}/{len(results)} successful", file=sys.stderr)
        print(f"{Style.INFO}Total Events:{Style.RESET} {total_events}", file=sys.stderr)
        print(f"{Style.INFO}Total Findings:{Style.RESET} {total_findings}", file=sys.stderr)
        print(f"\n{Style.SUCCESS}Output Directory:{Style.RESET} {output_dir}", file=sys.stderr)
        
        # List output files
        print(f"\n{Style.INFO}Generated Files:{Style.RESET}", file=sys.stderr)
        for filename in sorted(os.listdir(output_dir)):
            filepath = os.path.join(output_dir, filename)
            try:
                size = os.path.getsize(filepath)
                if size > 1024 * 1024:
                    size_str = f"{size / (1024*1024):.1f} MB"
                elif size > 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size} bytes"
            except:
                size_str = ""
            print(f"  • {filename} ({size_str})", file=sys.stderr)

    # Clean up any temporary bodyfile extracted from the tarball
    if bodyfile_is_temp and bodyfile_path and os.path.isfile(bodyfile_path):
        try:
            os.unlink(bodyfile_path)
        except OSError:
            pass

    return output_dir, results


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Linux Unified Security Analyzer - Run all forensic tools together",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

This script runs all Linux forensic analysis tools in parallel and outputs
results to a unified analysis folder named [hostname]_analysis.

Included Analyzers:
  • MAC Timeline        - Filesystem timeline from Sleuth Kit bodyfile (M/A/C/B times)
  • Login Timeline      - Authentication/login events from logs
  • Journal Analyzer    - Systemd journal entries
  • Persistence Hunter  - MITRE ATT&CK mapped persistence mechanisms
  • Security Analyzer   - Binary/environment security issues
  • Memory Analyzer     - Volatility 3 memory forensics (optional)

Supported Input Types:
  • UAC tarball (.tar.gz, .tar, .tgz, .tar.bz2, .tar.xz)
  • Extracted UAC directory
  • Directory containing multiple tarballs (batch mode)
  • Live system (use -s /)

Bodyfile / MAC Timeline:
  A Sleuth Kit bodyfile (MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime)
  provides a full filesystem MAC timeline.  You can supply one explicitly
  with --bodyfile; otherwise the tool will auto-detect a bodyfile inside the
  UAC collection.  When running interactively (without --quiet), you will be
  prompted to enter a path (Tab-completion is supported on Unix).

Examples:
  # Analyze a UAC tarball (bodyfile auto-detected if present)
  python linux_analyzer.py -s uac-hostname-20250115.tar.gz

  # Supply an existing bodyfile explicitly
  python linux_analyzer.py -s uac-hostname-20250115.tar.gz --bodyfile /evidence/hostname.body

  # Analyze an extracted UAC directory
  python linux_analyzer.py -s ./extracted_uac/

  # Batch analyze all tarballs in a directory
  python linux_analyzer.py -s ./collections/

  # Analyze with memory dump included
  python linux_analyzer.py -s hostname.tar.gz -m memory.lime --symbols /path/to/symbols

  # Analyze to specific output directory
  python linux_analyzer.py -s hostname.tar.gz -o ./analysis_results/

  # Run analyzers sequentially (not parallel)
  python linux_analyzer.py -s hostname.tar.gz --sequential

Memory Analysis:
  To include memory analysis, you need:
  1. A memory dump file (.lime, .raw, etc.)
  2. Matching symbol files for the kernel

  First-time setup: python linux_memory_analyzer.py --setup
  Identify kernel:  python linux_memory_analyzer.py -i memory.lime --banner

Output:
  Creates directory: [hostname]_analysis/

  Files generated:
    [hostname]_mac_timeline.csv         - Filesystem M/A/C/B timeline (if bodyfile present)
    [hostname]_login_timeline.csv       - Login/auth events
    [hostname]_journal.csv              - Journal entries
    [hostname]_journal_security.csv     - Security-relevant journal entries
    [hostname]_persistence.csv          - ALL scheduled tasks + persistence findings
    [hostname]_security_*.csv           - Security analyzer findings
    [hostname]_analysis_summary.txt     - Summary report
    memory_analysis/*.csv               - Memory forensics results (if -m provided)
        """
    )
    
    parser.add_argument(
        '-s', '--source',
        required=True,
        help='Source: UAC tarball (.tar.gz) or extracted directory'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='.',
        help='Output base directory (default: current directory)'
    )
    
    parser.add_argument(
        '--sequential',
        action='store_true',
        help='Run analyzers sequentially instead of in parallel'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output'
    )
    
    # Memory analysis options
    parser.add_argument(
        '-m', '--memory',
        default=None,
        help='Path to memory dump file (.lime, .raw, etc.) for memory analysis'
    )
    
    parser.add_argument(
        '--symbols',
        action='append',
        default=[],
        help='Path to symbol directory for memory analysis (can be specified multiple times)'
    )
    
    parser.add_argument(
        '--quick-memory',
        action='store_true',
        help='Run quick memory triage instead of full analysis'
    )

    # Bodyfile option
    parser.add_argument(
        '--bodyfile',
        default=None,
        metavar='PATH',
        help=(
            'Path to an existing Sleuth Kit bodyfile '
            '(MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime). '
            'Bypasses auto-detection from the UAC collection and skips the '
            'interactive prompt.  Supports .gz compressed bodyfiles.'
        )
    )

    parser.add_argument(
        '--ioc',
        default=None,
        metavar='PATH',
        help=(
            'Path to an IOC file (one indicator per line: IPs, domains, '
            'MD5/SHA256 hashes, file paths). Cross-referenced against all '
            'generated CSVs after analysis completes. Lines starting with '
            '# are treated as comments.'
        )
    )

    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    args = parser.parse_args()

    # Resolve paths
    source_path = os.path.abspath(args.source)
    output_base = os.path.abspath(args.output)

    if not os.path.exists(source_path):
        print(f"{Style.ERROR}Error: Source not found: {source_path}{Style.RESET}", file=sys.stderr)
        sys.exit(1)

    # Resolve memory path if provided
    memory_path = os.path.abspath(args.memory) if args.memory else None
    if memory_path and not os.path.exists(memory_path):
        print(f"{Style.ERROR}Error: Memory image not found: {memory_path}{Style.RESET}", file=sys.stderr)
        sys.exit(1)

    # Resolve bodyfile path
    # Priority: --bodyfile flag > interactive prompt > auto-detection inside run_analysis()
    bodyfile_path: Optional[str] = None
    if args.bodyfile:
        bp = os.path.abspath(os.path.expanduser(args.bodyfile))
        if not os.path.isfile(bp):
            print(
                f"{Style.ERROR}Error: Bodyfile not found: {bp}{Style.RESET}",
                file=sys.stderr,
            )
            sys.exit(1)
        bodyfile_path = bp
    else:
        # Interactively prompt the analyst (skipped when --quiet or non-TTY)
        bodyfile_path = prompt_for_bodyfile(quiet=args.quiet)

    # Resolve IOC path
    ioc_path: Optional[str] = None
    if args.ioc:
        ioc_path = os.path.abspath(os.path.expanduser(args.ioc))
        if not os.path.isfile(ioc_path):
            print(
                f"{Style.ERROR}Error: IOC file not found: {ioc_path}{Style.RESET}",
                file=sys.stderr,
            )
            sys.exit(1)

    try:
        output_dir, results = run_analysis(
            source_path=source_path,
            output_base=output_base,
            parallel=not args.sequential,
            verbose=not args.quiet,
            memory_path=memory_path,
            symbol_dirs=args.symbols if args.symbols else None,
            quick_memory=args.quick_memory,
            bodyfile_path=bodyfile_path,
            ioc_path=ioc_path,
        )
        
        # Exit with error code if any analyzer failed completely
        failures = [r for r in results if not r["success"]]
        if failures:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Analysis interrupted{Style.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

