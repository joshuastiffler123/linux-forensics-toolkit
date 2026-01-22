#!/usr/bin/env python3
"""
Linux Unified Security Analyzer - Orchestrator Script

Runs all Linux forensic analysis tools in parallel and outputs correlated
results to a unified analysis folder named [hostname]_analysis.

Included Analyzers:
- linux_login_timeline.py    - Login/authentication timeline
- linux_journal_analyzer.py  - Systemd journal analysis
- linux_persistence_hunter.py - Persistence mechanism detection
- linux_security_analyzer.py  - Binary/environment security analysis

Author: Security Tools
Version: 1.0.0
License: MIT

Requirements: Python 3.6+ (standard library only)
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

__version__ = "1.0.0"


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
    # UAC format: hostname-uac-timestamp.tar.gz
    basename = os.path.basename(tarball_path)
    for ext in ('.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.tar'):
        if basename.lower().endswith(ext):
            basename = basename[:-len(ext)]
            break
    
    # Common UAC naming patterns
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


# ============================================================================
# Correlation and Summary
# ============================================================================

def create_summary_report(output_dir: str, hostname: str, results: List[Dict], 
                         start_time: datetime, end_time: datetime) -> str:
    """Create a summary report of all analysis results."""
    summary_path = os.path.join(output_dir, f"{hostname}_analysis_summary.txt")
    
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(f"  Linux Unified Security Analysis Summary\n")
        f.write(f"  Hostname: {hostname}\n")
        f.write("=" * 70 + "\n\n")
        
        f.write(f"Analysis Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Analysis End:   {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Duration:       {(end_time - start_time).total_seconds():.2f} seconds\n\n")
        
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
        f.write(f"Output Files Generated:    {len(all_files)}\n\n")
        
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


def create_correlated_timeline(output_dir: str, hostname: str, results: List[Dict]) -> Optional[str]:
    """
    Create a correlated master timeline from all analyzers.
    Merges events from login timeline, journal, and security findings.
    """
    all_events = []
    
    # Read login timeline events
    login_file = os.path.join(output_dir, f"{hostname}_login_timeline.csv")
    if os.path.exists(login_file):
        try:
            with open(login_file, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    all_events.append({
                        "Timestamp": row.get("Timestamp", ""),
                        "Source": "Login Timeline",
                        "Event_Type": row.get("Event_Type", ""),
                        "Username": row.get("Username", ""),
                        "Source_IP": row.get("Source_IP", ""),
                        "Hostname": row.get("Hostname", hostname),
                        "Description": row.get("Description", ""),
                        "Severity": row.get("Severity", "INFO"),
                        "Source_File": row.get("Source_File", ""),
                        "Raw_Data": row.get("Raw_Data", "")[:500]
                    })
        except Exception:
            pass
    
    # Read journal events
    journal_file = os.path.join(output_dir, f"{hostname}_journal.csv")
    if os.path.exists(journal_file):
        try:
            with open(journal_file, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Map priority to severity
                    priority = row.get("Priority", "INFO")
                    severity_map = {
                        "EMERG": "CRITICAL", "ALERT": "CRITICAL", "CRIT": "CRITICAL",
                        "ERR": "HIGH", "WARNING": "MEDIUM", "NOTICE": "LOW", 
                        "INFO": "INFO", "DEBUG": "INFO"
                    }
                    severity = severity_map.get(priority, "INFO")
                    
                    all_events.append({
                        "Timestamp": row.get("Timestamp", ""),
                        "Source": "Journal",
                        "Event_Type": row.get("Category", ""),
                        "Username": row.get("User", ""),
                        "Source_IP": row.get("Source_IP", ""),
                        "Hostname": row.get("Hostname", hostname),
                        "Description": row.get("Message", "")[:300],
                        "Severity": severity,
                        "Source_File": row.get("Source_File", ""),
                        "Raw_Data": ""
                    })
        except Exception:
            pass
    
    # Read persistence findings
    persistence_file = os.path.join(output_dir, f"{hostname}_persistence.csv")
    if os.path.exists(persistence_file):
        try:
            with open(persistence_file, 'r', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    all_events.append({
                        "Timestamp": "",  # Persistence findings don't have timestamps
                        "Source": "Persistence Hunter",
                        "Event_Type": row.get("Technique", ""),
                        "Username": "",
                        "Source_IP": "",
                        "Hostname": hostname,
                        "Description": row.get("Description", ""),
                        "Severity": row.get("Severity", "MEDIUM"),
                        "Source_File": row.get("Filepath", ""),
                        "Raw_Data": row.get("Raw_Content", "")[:500]
                    })
        except Exception:
            pass
    
    # Read security findings
    for suffix in ["all", "binaries", "environment", "persistence"]:
        sec_file = os.path.join(output_dir, f"{hostname}_security_{suffix}.csv")
        if os.path.exists(sec_file):
            try:
                with open(sec_file, 'r', encoding='utf-8', errors='replace') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        all_events.append({
                            "Timestamp": "",
                            "Source": "Security Analyzer",
                            "Event_Type": row.get("Finding_Type", row.get("Technique", "")),
                            "Username": "",
                            "Source_IP": "",
                            "Hostname": hostname,
                            "Description": row.get("Description", ""),
                            "Severity": row.get("Severity", "MEDIUM"),
                            "Source_File": row.get("Filepath", ""),
                            "Raw_Data": row.get("Raw_Content", row.get("Indicator", ""))[:500]
                        })
            except Exception:
                pass
    
    if not all_events:
        return None
    
    # Sort by timestamp (events without timestamps go to the end)
    def sort_key(event):
        ts = event.get("Timestamp", "")
        if ts:
            return (0, ts)
        return (1, "")
    
    all_events.sort(key=sort_key)
    
    # Write correlated timeline
    output_file = os.path.join(output_dir, f"{hostname}_correlated_timeline.csv")
    fieldnames = ["Timestamp", "Source", "Event_Type", "Severity", "Username", 
                  "Source_IP", "Hostname", "Description", "Source_File", "Raw_Data"]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in all_events:
            writer.writerow(event)
    
    return output_file


# ============================================================================
# Main Orchestrator
# ============================================================================

def run_analysis(source_path: str, output_base: str = None, parallel: bool = True,
                verbose: bool = True) -> Tuple[str, List[Dict]]:
    """
    Run all analyzers on the source and output to a unified directory.
    
    Args:
        source_path: Path to UAC tarball or extracted directory
        output_base: Base directory for output (default: current directory)
        parallel: Whether to run analyzers in parallel
        verbose: Whether to print progress
    
    Returns:
        Tuple of (output_directory, results_list)
    """
    Style.enable_windows_ansi()
    start_time = datetime.now()
    
    # Resolve source path
    source_path = os.path.abspath(source_path)
    
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source not found: {source_path}")
    
    # Determine if tarball or directory
    is_tarball = any(source_path.lower().endswith(ext) 
                     for ext in ('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz'))
    
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
    
    # Define analyzers to run
    analyzers = [
        ("Login Timeline", run_login_timeline),
        ("Journal Analyzer", run_journal_analyzer),
        ("Persistence Hunter", run_persistence_hunter),
        ("Security Analyzer", run_security_analyzer),
    ]
    
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
    
    # Create correlated timeline
    if verbose:
        print(f"\n{Style.INFO}Creating correlated timeline...{Style.RESET}", file=sys.stderr)
    
    correlated_file = create_correlated_timeline(output_dir, hostname, results)
    if correlated_file:
        if verbose:
            try:
                with open(correlated_file, 'r') as f:
                    line_count = sum(1 for _ in f) - 1  # Subtract header
                print(f"  {Style.SUCCESS}✓ Created with {line_count} total events{Style.RESET}", file=sys.stderr)
            except:
                print(f"  {Style.SUCCESS}✓ Created{Style.RESET}", file=sys.stderr)
    
    end_time = datetime.now()
    
    # Create summary report
    if verbose:
        print(f"\n{Style.INFO}Creating summary report...{Style.RESET}", file=sys.stderr)
    
    summary_file = create_summary_report(output_dir, hostname, results, start_time, end_time)
    
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
correlated results to a unified analysis folder named [hostname]_analysis.

Included Analyzers:
  • Login Timeline    - Authentication/login events from logs
  • Journal Analyzer  - Systemd journal entries
  • Persistence Hunter - MITRE ATT&CK mapped persistence mechanisms
  • Security Analyzer  - Binary/environment security issues

Examples:
  # Analyze a UAC tarball
  python linux_analyzer.py -s hostname.tar.gz
  
  # Analyze to specific output directory
  python linux_analyzer.py -s hostname.tar.gz -o ./analysis_results/
  
  # Run analyzers sequentially (not parallel)
  python linux_analyzer.py -s hostname.tar.gz --sequential
  
  # Analyze extracted UAC directory
  python linux_analyzer.py -s ./extracted_uac/

Output:
  Creates directory: [hostname]_analysis/
  
  Files generated:
    [hostname]_login_timeline.csv       - Login/auth events
    [hostname]_journal.csv              - Journal entries
    [hostname]_journal_security.csv     - Security-relevant journal entries
    [hostname]_persistence.csv          - Persistence findings
    [hostname]_security_*.csv           - Security analyzer findings
    [hostname]_correlated_timeline.csv  - All events merged & sorted
    [hostname]_analysis_summary.txt     - Summary report
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
    
    try:
        output_dir, results = run_analysis(
            source_path=source_path,
            output_base=output_base,
            parallel=not args.sequential,
            verbose=not args.quiet
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

