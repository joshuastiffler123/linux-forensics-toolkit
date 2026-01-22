"""
IZE & UAC Collection Sorter
===========================
Recursively searches directories and zip files for:
  - .IZE files (Kaseya collections)
  - .TAR files (UAC collections)

Features:
  - Sorts files into folders based on CSV hostname mapping
  - Extracts Client ID from ZIP/TAR filenames (C###-F pattern)
  - Handles duplicates by keeping the larger file
  - Generates detailed log and results CSV
  - Sanitizes folder names (removes invalid characters like ? : * etc.)

Usage:
    python ize_sorter.py <search_path> <csv_file> <output_dir> [--threshold 70]

CSV Format:
    Column A: Hostname keyword - what to search for in filenames
    Column B: Product/Folder name - the destination folder for matched files
    
    Example CSV:
        Hostname,Product
        SERVER-DC01,Kaseya_Backup
        SERVER-DC02,Kaseya_Backup
        SQL-SERVER,Kaseya_Monitoring

Client ID Extraction:
    Filenames containing 'C###-F' pattern will have the Client ID extracted.
    Example: 'SERVER-DC01-C12345-F0001.tar' -> Client ID: 'C12345'
"""

import os
import sys
import csv
import zipfile
import shutil
import argparse
import tempfile
import threading
import itertools
import time
import logging
import re
from datetime import datetime
from pathlib import Path
from difflib import SequenceMatcher
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass, field


# ============================================================================
# CONSOLE STYLING - Colors and formatting
# ============================================================================

class Style:
    """ANSI color codes and styling for terminal output."""
    
    # Check if terminal supports colors
    ENABLED = sys.stdout.isatty() and os.name == 'nt'
    
    # Colors
    RESET = '\033[0m' if ENABLED else ''
    BOLD = '\033[1m' if ENABLED else ''
    DIM = '\033[2m' if ENABLED else ''
    
    # Foreground colors
    BLACK = '\033[30m' if ENABLED else ''
    RED = '\033[91m' if ENABLED else ''
    GREEN = '\033[92m' if ENABLED else ''
    YELLOW = '\033[93m' if ENABLED else ''
    BLUE = '\033[94m' if ENABLED else ''
    MAGENTA = '\033[95m' if ENABLED else ''
    CYAN = '\033[96m' if ENABLED else ''
    WHITE = '\033[97m' if ENABLED else ''
    
    # Background colors
    BG_BLACK = '\033[40m' if ENABLED else ''
    BG_RED = '\033[41m' if ENABLED else ''
    BG_GREEN = '\033[42m' if ENABLED else ''
    BG_YELLOW = '\033[43m' if ENABLED else ''
    BG_BLUE = '\033[44m' if ENABLED else ''
    BG_MAGENTA = '\033[45m' if ENABLED else ''
    BG_CYAN = '\033[46m' if ENABLED else ''
    
    # Semantic colors
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN
    HEADER = MAGENTA
    ACCENT = BLUE
    MUTED = DIM

    @classmethod
    def enable_windows_ansi(cls):
        """Enable ANSI escape sequences on Windows."""
        if os.name == 'nt':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                cls.ENABLED = True
                # Re-initialize colors
                cls.RESET = '\033[0m'
                cls.BOLD = '\033[1m'
                cls.DIM = '\033[2m'
                cls.RED = '\033[91m'
                cls.GREEN = '\033[92m'
                cls.YELLOW = '\033[93m'
                cls.BLUE = '\033[94m'
                cls.MAGENTA = '\033[95m'
                cls.CYAN = '\033[96m'
                cls.WHITE = '\033[97m'
                cls.SUCCESS = cls.GREEN
                cls.ERROR = cls.RED
                cls.WARNING = cls.YELLOW
                cls.INFO = cls.CYAN
                cls.HEADER = cls.MAGENTA
                cls.ACCENT = cls.BLUE
            except (AttributeError, OSError, ValueError):
                # OWASP A05: Specify exception types instead of bare except
                pass


# ============================================================================
# SECURITY UTILITIES (OWASP Compliance)
# ============================================================================

def is_safe_path(base_path: str, target_path: str) -> bool:
    """
    OWASP A03/A08: Validate that target_path is within base_path.
    Prevents path traversal attacks (zip slip).
    
    Args:
        base_path: The allowed base directory
        target_path: The path to validate
        
    Returns:
        True if target_path is safely within base_path
    """
    base = os.path.abspath(base_path)
    target = os.path.abspath(target_path)
    
    try:
        common = os.path.commonpath([base, target])
        return common == base
    except ValueError:
        return False


def safe_zip_extract(zip_file: zipfile.ZipFile, member: zipfile.ZipInfo, dest_dir: str) -> str:
    """
    OWASP A08: Safely extract a zip member, preventing zip slip attacks.
    
    Args:
        zip_file: Open ZipFile object
        member: ZipInfo member to extract
        dest_dir: Destination directory
        
    Returns:
        Path to extracted file
        
    Raises:
        ValueError: If path traversal is detected
    """
    # Get the intended extraction path
    member_path = os.path.join(dest_dir, member.filename)
    abs_dest = os.path.abspath(dest_dir)
    abs_member = os.path.abspath(member_path)
    
    # Validate the path stays within destination
    if not is_safe_path(abs_dest, abs_member):
        raise ValueError(f"Attempted path traversal in zip: {member.filename}")
    
    return zip_file.extract(member, dest_dir)


def print_banner():
    """Print a sexy ASCII art banner."""
    Style.enable_windows_ansi()
    
    banner = f"""
{Style.CYAN}{Style.BOLD}
     ██████╗ ██████╗ ██╗     ██╗     ███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
    ██╔════╝██╔═══██╗██║     ██║     ██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
    ██║     ██║   ██║██║     ██║     █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
    ██║     ██║   ██║██║     ██║     ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
    ╚██████╗╚██████╔╝███████╗███████╗███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
     ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET}{Style.BOLD}
    ███████╗ ██████╗ ██████╗ ████████╗███████╗██████╗ 
    ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔══██╗
    ███████╗██║   ██║██████╔╝   ██║   █████╗  ██████╔╝
    ╚════██║██║   ██║██╔══██╗   ██║   ██╔══╝  ██╔══██╗
    ███████║╚██████╔╝██║  ██║   ██║   ███████╗██║  ██║
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET}
{Style.DIM}    ───────────────────────────────────────────────────────────────────────────
{Style.CYAN}    📦 IZE + UAC/TAR  {Style.WHITE}│{Style.YELLOW}  🔑 Client ID Extract  {Style.WHITE}│{Style.GREEN}  📂 Smart Sort  {Style.WHITE}│{Style.MAGENTA}  📊 CSV Output
{Style.DIM}    ───────────────────────────────────────────────────────────────────────────{Style.RESET}
"""
    print(banner)


def print_section(title: str, icon: str = "►"):
    """Print a styled section header."""
    print(f"\n{Style.ACCENT}{Style.BOLD}{icon} {title}{Style.RESET}")
    print(f"{Style.DIM}{'─' * 70}{Style.RESET}")


def print_config_box(search_path: str, csv_file: str, output_dir: str, threshold: float, dry_run: bool, log_file: str):
    """Print configuration in a nice box."""
    print(f"""
{Style.DIM}╭─────────────────────────────────────────────────────────────────────────╮{Style.RESET}
{Style.DIM}│{Style.RESET} {Style.BOLD}{Style.WHITE}CONFIGURATION{Style.RESET}                                                         {Style.DIM}│{Style.RESET}
{Style.DIM}├─────────────────────────────────────────────────────────────────────────┤{Style.RESET}
{Style.DIM}│{Style.RESET}  {Style.CYAN}Search Path:{Style.RESET}    {search_path:<54} {Style.DIM}│{Style.RESET}
{Style.DIM}│{Style.RESET}  {Style.CYAN}CSV File:{Style.RESET}       {csv_file:<54} {Style.DIM}│{Style.RESET}
{Style.DIM}│{Style.RESET}  {Style.CYAN}Output Dir:{Style.RESET}     {output_dir:<54} {Style.DIM}│{Style.RESET}
{Style.DIM}│{Style.RESET}  {Style.CYAN}Threshold:{Style.RESET}      {threshold}%{'':<51} {Style.DIM}│{Style.RESET}
{Style.DIM}│{Style.RESET}  {Style.CYAN}Dry Run:{Style.RESET}        {str(dry_run):<54} {Style.DIM}│{Style.RESET}
{Style.DIM}│{Style.RESET}  {Style.CYAN}Log File:{Style.RESET}       {os.path.basename(log_file):<54} {Style.DIM}│{Style.RESET}
{Style.DIM}╰─────────────────────────────────────────────────────────────────────────╯{Style.RESET}
""")


def print_success(msg: str):
    """Print a success message."""
    print(f"  {Style.SUCCESS}✓{Style.RESET} {msg}")


def print_error(msg: str):
    """Print an error message."""
    print(f"  {Style.ERROR}✗{Style.RESET} {msg}")


def print_warning(msg: str):
    """Print a warning message."""
    print(f"  {Style.WARNING}⚠{Style.RESET} {msg}")


def print_info(msg: str):
    """Print an info message."""
    print(f"  {Style.INFO}ℹ{Style.RESET} {msg}")


def print_match(filename: str, folder: str, hostname: str, score: float, source_zip: str = None):
    """Print a match result."""
    source = f" {Style.DIM}from {os.path.basename(source_zip)}{Style.RESET}" if source_zip else ""
    print(f"  {Style.SUCCESS}✓{Style.RESET} {Style.WHITE}{filename}{Style.RESET}{source}")
    print(f"    {Style.DIM}└─►{Style.RESET} {Style.ACCENT}{folder}/{Style.RESET} {Style.DIM}│{Style.RESET} matched '{Style.YELLOW}{hostname}{Style.RESET}' {Style.DIM}│{Style.RESET} score: {Style.GREEN}{score:.1f}%{Style.RESET}")


def print_no_match(filename: str, file_size: int, source_zip: str = None):
    """Print a no-match result."""
    source = f" {Style.DIM}from {os.path.basename(source_zip)}{Style.RESET}" if source_zip else ""
    print(f"  {Style.WARNING}○{Style.RESET} {Style.DIM}{filename}{Style.RESET}{source} {Style.DIM}({file_size:,} bytes){Style.RESET}")


def print_duplicate(filename: str, folder: str, old_size: int, new_size: int, kept_larger: bool):
    """Print duplicate handling info."""
    if kept_larger:
        print(f"  {Style.MAGENTA}⟳{Style.RESET} {Style.WHITE}{filename}{Style.RESET} → {Style.ACCENT}{folder}/{Style.RESET}")
        print(f"    {Style.DIM}└─►{Style.RESET} {Style.GREEN}Replaced{Style.RESET}: {old_size:,} → {Style.BOLD}{new_size:,}{Style.RESET} bytes {Style.DIM}(kept larger){Style.RESET}")
    else:
        print(f"  {Style.MAGENTA}⟳{Style.RESET} {Style.DIM}{filename}{Style.RESET} → {Style.ACCENT}{folder}/{Style.RESET}")
        print(f"    {Style.DIM}└─► Skipped: {new_size:,} bytes (existing {old_size:,} is larger){Style.RESET}")


def print_summary_box(total: int, matched: int, duplicates: int, unmatched: int, errors: int, warnings: int):
    """Print final summary in a styled box."""
    match_pct = (matched / total * 100) if total > 0 else 0
    
    # Color code the match percentage
    if match_pct >= 80:
        pct_color = Style.GREEN
    elif match_pct >= 50:
        pct_color = Style.YELLOW
    else:
        pct_color = Style.RED
    
    print(f"""
{Style.BOLD}{Style.WHITE}╔═══════════════════════════════════════════════════════════════════════════╗
║                              SUMMARY                                      ║
╠═══════════════════════════════════════════════════════════════════════════╣{Style.RESET}
{Style.WHITE}║{Style.RESET}                                                                           {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}   {Style.CYAN}Total .IZE files found:{Style.RESET}     {total:<10}                              {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}   {Style.GREEN}Successfully sorted:{Style.RESET}        {matched:<10} {pct_color}({match_pct:.1f}%){Style.RESET}                       {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}   {Style.MAGENTA}Duplicates replaced:{Style.RESET}        {duplicates:<10}                              {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}   {Style.YELLOW}Unmatched:{Style.RESET}                  {unmatched:<10}                              {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}                                                                           {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}   {Style.RED}Errors:{Style.RESET}                     {errors:<10}                              {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}   {Style.YELLOW}Warnings:{Style.RESET}                   {warnings:<10}                              {Style.WHITE}║{Style.RESET}
{Style.WHITE}║{Style.RESET}                                                                           {Style.WHITE}║{Style.RESET}
{Style.BOLD}{Style.WHITE}╚═══════════════════════════════════════════════════════════════════════════╝{Style.RESET}
""")


# ============================================================================
# LOGGING SETUP
# ============================================================================

class LogManager:
    """Manages both file and console logging with detailed categorization tracking."""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.log_file = None
        self.csv_output_file = None
        self.logger = None
        self.start_time = datetime.now()
        self.errors = []
        self.warnings = []
        self.match_details = []
        self.file_records = []  # Track all files for CSV output
        
    def setup(self):
        """Initialize the log file and logger."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(self.output_dir, f"ize_sorter_log_{timestamp}.txt")
        self.csv_output_file = os.path.join(self.output_dir, f"ize_sorter_results_{timestamp}.csv")
        
        # Create logger
        self.logger = logging.getLogger('ize_sorter')
        self.logger.setLevel(logging.DEBUG)
        
        # File handler - captures everything
        fh = logging.FileHandler(self.log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
        self.logger.addHandler(fh)
        
        # Write header
        self.logger.info("=" * 80)
        self.logger.info("IZE FILE SORTER - DETAILED LOG")
        self.logger.info("=" * 80)
        self.logger.info(f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        return self.log_file
    
    def add_file_record(self, filename: str, source_zip: str, file_size: int,
                        status: str, file_type: str = "IZE", client_id: str = None,
                        destination_folder: str = None, 
                        matched_hostname: str = None, match_score: float = None,
                        match_type: str = None, destination_path: str = None,
                        notes: str = None):
        """Add a record for the output CSV tracking each collection file."""
        self.file_records.append({
            'filename': filename,
            'file_type': file_type,
            'client_id': client_id if client_id else '',
            'source_zip': source_zip if source_zip else '(direct file)',
            'source_zip_name': os.path.basename(source_zip) if source_zip else '(direct file)',
            'file_size_bytes': file_size,
            'status': status,
            'destination_folder': destination_folder if destination_folder else '',
            'matched_hostname': matched_hostname if matched_hostname else '',
            'match_score': f"{match_score:.1f}%" if match_score else '',
            'match_type': match_type if match_type else '',
            'destination_path': destination_path if destination_path else '',
            'notes': notes if notes else ''
        })
    
    def write_output_csv(self):
        """Write all file records to the output CSV."""
        if not self.file_records:
            return None
        
        headers = [
            'Filename',
            'File Type',
            'Client ID',
            'Source ZIP',
            'Source ZIP (Full Path)',
            'File Size (bytes)',
            'Status',
            'Destination Folder',
            'Matched Hostname',
            'Match Score',
            'Match Type',
            'Destination Path',
            'Notes'
        ]
        
        try:
            with open(self.csv_output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                
                for record in self.file_records:
                    writer.writerow([
                        record['filename'],
                        record['file_type'],
                        record['client_id'],
                        record['source_zip_name'],
                        record['source_zip'],
                        record['file_size_bytes'],
                        record['status'],
                        record['destination_folder'],
                        record['matched_hostname'],
                        record['match_score'],
                        record['match_type'],
                        record['destination_path'],
                        record['notes']
                    ])
            
            self.logger.info(f"Output CSV written: {self.csv_output_file}")
            self.logger.info(f"Total records: {len(self.file_records)}")
            return self.csv_output_file
            
        except Exception as e:
            self.log_error(f"Failed to write output CSV: {str(e)}", e)
            return None
    
    def log_config(self, search_path: str, csv_file: str, output_dir: str, threshold: float):
        """Log the configuration used."""
        self.logger.info("-" * 80)
        self.logger.info("CONFIGURATION")
        self.logger.info("-" * 80)
        self.logger.info(f"Search Path:     {search_path}")
        self.logger.info(f"CSV File:        {csv_file}")
        self.logger.info(f"Output Dir:      {output_dir}")
        self.logger.info(f"Match Threshold: {threshold}%")
        self.logger.info("-" * 80)
    
    def log_mappings(self, mappings: list):
        """Log all CSV mappings loaded."""
        self.logger.info("")
        self.logger.info("CSV MAPPINGS LOADED")
        self.logger.info("-" * 80)
        for m in mappings:
            self.logger.info(f"  Row {m.row_number}: '{m.folder_name}' <- hostname '{m.search_term}'")
        self.logger.info(f"Total mappings: {len(mappings)}")
        self.logger.info("-" * 80)
    
    def log_discovered_file(self, filename: str, size: int, source: str = None):
        """Log a discovered IZE file."""
        source_info = f" (from ZIP: {source})" if source else " (direct file)"
        self.logger.debug(f"DISCOVERED: {filename} | Size: {size:,} bytes{source_info}")
    
    def log_match_attempt(self, filename: str, file_size: int, mappings_checked: list, 
                          best_match: dict, threshold: float, file_type: str = "IZE",
                          match_name: str = None):
        """Log detailed matching criteria for a file."""
        self.logger.info("")
        self.logger.info(f"{'='*80}")
        self.logger.info(f"CATEGORIZATION ANALYSIS: {filename}")
        self.logger.info(f"{'='*80}")
        self.logger.info(f"File Type: {file_type}")
        self.logger.info(f"File Size: {file_size:,} bytes")
        if match_name and match_name != filename:
            self.logger.info(f"Extracted Hostname for Matching: {match_name}")
        self.logger.info(f"Threshold Required: {threshold}%")
        self.logger.info("")
        self.logger.info("MATCHING CRITERIA EVALUATED:")
        self.logger.info("-" * 60)
        
        # Log each mapping that was checked
        for check in mappings_checked:
            status = "✓ PASS" if check['score'] >= threshold else "✗ FAIL"
            self.logger.info(f"  Hostname: '{check['search_term']}'")
            self.logger.info(f"    Product/Folder: {check['folder_name']}")
            self.logger.info(f"    Match Score:    {check['score']:.1f}%")
            self.logger.info(f"    Match Type:     {check['match_type']}")
            self.logger.info(f"    Status:         {status}")
            self.logger.info("")
        
        # Log the decision
        self.logger.info("-" * 60)
        if best_match:
            self.logger.info(f"DECISION: MATCHED")
            self.logger.info(f"  Selected Folder:  {best_match['folder_name']}")
            self.logger.info(f"  Matched Hostname: {best_match['search_term']}")
            self.logger.info(f"  Final Score:      {best_match['score']:.1f}%")
            self.logger.info(f"  Match Type:       {best_match['match_type']}")
            
            self.match_details.append({
                'file': filename,
                'folder': best_match['folder_name'],
                'hostname': best_match['search_term'],
                'score': best_match['score'],
                'match_type': best_match['match_type']
            })
        else:
            self.logger.info(f"DECISION: NO MATCH FOUND")
            self.logger.info(f"  Reason: No hostname matched above {threshold}% threshold")
        
        self.logger.info(f"{'='*80}")
    
    def log_duplicate(self, filename: str, folder: str, existing_size: int, 
                      new_size: int, action: str):
        """Log duplicate file handling."""
        self.logger.warning(f"DUPLICATE DETECTED: {filename} in {folder}/")
        self.logger.warning(f"  Existing file size: {existing_size:,} bytes")
        self.logger.warning(f"  New file size:      {new_size:,} bytes")
        self.logger.warning(f"  Action taken:       {action}")
    
    def log_error(self, message: str, exception: Exception = None):
        """Log an error."""
        self.errors.append(message)
        if exception:
            self.logger.error(f"ERROR: {message} | Exception: {str(exception)}")
        else:
            self.logger.error(f"ERROR: {message}")
    
    def log_warning(self, message: str):
        """Log a warning."""
        self.warnings.append(message)
        self.logger.warning(f"WARNING: {message}")
    
    def log_zip_processing(self, zip_path: str, status: str, ize_count: int = 0):
        """Log ZIP file processing."""
        if status == "start":
            self.logger.info(f"PROCESSING ZIP: {zip_path}")
        elif status == "success":
            self.logger.info(f"ZIP COMPLETE: {zip_path} | Found {ize_count} .IZE file(s)")
        elif status == "error":
            self.logger.error(f"ZIP FAILED: {zip_path}")
    
    def log_file_copy(self, source: str, destination: str, size: int):
        """Log a file copy operation."""
        self.logger.info(f"FILE COPIED: {os.path.basename(source)}")
        self.logger.info(f"  From: {source}")
        self.logger.info(f"  To:   {destination}")
        self.logger.info(f"  Size: {size:,} bytes")
    
    def finalize(self, stats: dict):
        """Write final summary to log and generate output CSV."""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        # Write the output CSV
        self.write_output_csv()
        
        self.logger.info("")
        self.logger.info("=" * 80)
        self.logger.info("FINAL SUMMARY")
        self.logger.info("=" * 80)
        self.logger.info(f"Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"Duration:  {duration}")
        self.logger.info("")
        self.logger.info("STATISTICS:")
        self.logger.info(f"  Total .IZE files found:    {stats.get('total_found', 0)}")
        self.logger.info(f"  Successfully matched:      {stats.get('matched', 0)}")
        self.logger.info(f"  Duplicates replaced:       {stats.get('duplicates', 0)}")
        self.logger.info(f"  Unmatched files:           {stats.get('unmatched', 0)}")
        self.logger.info(f"  Total errors:              {len(self.errors)}")
        self.logger.info(f"  Total warnings:            {len(self.warnings)}")
        
        self.logger.info("")
        self.logger.info("OUTPUT FILES:")
        self.logger.info(f"  Log file:    {self.log_file}")
        self.logger.info(f"  Results CSV: {self.csv_output_file}")
        
        if self.errors:
            self.logger.info("")
            self.logger.info("ERRORS ENCOUNTERED:")
            for i, err in enumerate(self.errors, 1):
                self.logger.info(f"  {i}. {err}")
        
        if self.warnings:
            self.logger.info("")
            self.logger.info("WARNINGS:")
            for i, warn in enumerate(self.warnings, 1):
                self.logger.info(f"  {i}. {warn}")
        
        if stats.get('unmatched_files'):
            self.logger.info("")
            self.logger.info("UNMATCHED FILES (consider adding to CSV):")
            for f in stats['unmatched_files']:
                self.logger.info(f"  - {f}")
        
        self.logger.info("")
        self.logger.info("=" * 80)
        self.logger.info("END OF LOG")
        self.logger.info("=" * 80)
        
        return self.log_file


# Global log manager (initialized in main)
log_manager: Optional[LogManager] = None
debug_mode: bool = False


# ============================================================================
# SPINNER - Non-blocking visual feedback during processing
# ============================================================================

class Spinner:
    """Non-blocking spinner for user feedback during processing."""
    
    FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    FRAMES_ASCII = ['|', '/', '-', '\\']
    
    def __init__(self, message: str = "Processing", use_unicode: bool = True):
        self.message = message
        self.frames = self.FRAMES if use_unicode else self.FRAMES_ASCII
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
    
    def _spin(self):
        """Spinner animation loop running in background thread."""
        frame_cycle = itertools.cycle(self.frames)
        while not self._stop_event.is_set():
            frame = next(frame_cycle)
            with self._lock:
                sys.stdout.write(f'\r  {frame} {self.message}' + ' ' * 20)
                sys.stdout.flush()
            time.sleep(0.1)
    
    def start(self, message: str = None):
        """Start the spinner with optional new message."""
        if message:
            self.message = message
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    
    def update(self, message: str):
        """Update the spinner message while it's running."""
        with self._lock:
            self.message = message
    
    def stop(self, final_message: str = None):
        """Stop the spinner and optionally print a final message."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        sys.stdout.flush()
        if final_message:
            print(final_message)
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()


class ProgressBar:
    """Static progress bar that updates in place without scrolling."""
    
    def __init__(self, total: int, width: int = 40, prefix: str = "Progress"):
        self.total = total
        self.width = width
        self.prefix = prefix
        self.current = 0
        self.last_line_length = 0
    
    def update(self, current: int = None, status: str = ""):
        """Update the progress bar in place."""
        if current is not None:
            self.current = current
        else:
            self.current += 1
        
        # Calculate percentage and bar
        percent = (self.current / self.total * 100) if self.total > 0 else 0
        filled = int(self.width * self.current / self.total) if self.total > 0 else 0
        bar = '█' * filled + '░' * (self.width - filled)
        
        # Truncate status if too long
        max_status_len = 30
        if len(status) > max_status_len:
            status = status[:max_status_len-3] + "..."
        
        # Build the line
        line = f"\r  {Style.CYAN}{self.prefix}{Style.RESET} [{Style.GREEN}{bar}{Style.RESET}] {percent:5.1f}% ({self.current}/{self.total}) {Style.DIM}{status}{Style.RESET}"
        
        # Clear any leftover characters from previous line
        padding = ' ' * max(0, self.last_line_length - len(line))
        
        sys.stdout.write(line + padding)
        sys.stdout.flush()
        self.last_line_length = len(line)
    
    def finish(self, message: str = None):
        """Complete the progress bar and optionally print a final message."""
        # Clear the line
        sys.stdout.write('\r' + ' ' * (self.last_line_length + 10) + '\r')
        sys.stdout.flush()
        if message:
            print(message)


# ============================================================================
# DATA CLASSES
# ============================================================================

def sanitize_folder_name(name: str) -> str:
    """
    Remove or replace characters that are invalid in Windows folder names.
    Invalid characters: \ / : * ? " < > |
    """
    # Characters not allowed in Windows file/folder names
    invalid_chars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|']
    
    sanitized = name
    for char in invalid_chars:
        sanitized = sanitized.replace(char, '_')
    
    # Remove leading/trailing spaces and dots (Windows doesn't like these)
    sanitized = sanitized.strip(' .')
    
    # If the name is empty after sanitization, use a default
    if not sanitized:
        sanitized = "unnamed_folder"
    
    return sanitized


def extract_client_id(filename: str) -> Optional[str]:
    """
    Extract Client ID from filename (ZIP or TAR).
    
    Supports multiple patterns:
    
    Pattern 1 (TAR files): [computername]-C[clientid]-F####.tar
        'SERVER-DC01-C12345-F0001.tar' -> 'C12345'
        'WORKSTATION-HR-C98765-F0002.tar' -> 'C98765'
    
    Pattern 2 (ZIP files): ...C-###...-F...
        'Archive_C-12345-F_backup.zip' -> 'C-12345'
        'C-ABC123-F_data.zip' -> 'C-ABC123'
    """
    # Pattern 1: TAR style - [computername]-C[clientid]-F####
    # Matches -C followed by alphanumeric client ID, then -F
    tar_pattern = r'-C([A-Za-z0-9]+)-F'
    match = re.search(tar_pattern, filename)
    if match:
        return f"C{match.group(1)}"  # Return as C##### format
    
    # Pattern 2: ZIP style - C-###-F (with dash after C)
    zip_pattern = r'(C-[A-Za-z0-9]+)-F'
    match = re.search(zip_pattern, filename, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Pattern 3: More flexible - C followed by digits/letters before -F
    flexible_pattern = r'(C[A-Za-z0-9]+)-F'
    match = re.search(flexible_pattern, filename, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None


def extract_hostname_from_tar(tar_filename: str) -> Optional[str]:
    """
    Extract the hostname/computername from a TAR filename.
    
    Pattern: [computername]-C[clientid]-F####.tar
    
    Examples:
        'SERVER-DC01-C12345-F0001.tar' -> 'SERVER-DC01'
        'WORKSTATION-HR-C98765-F0002.tar' -> 'WORKSTATION-HR'
        'LAPTOP-USER1-C55555-F0003.tar' -> 'LAPTOP-USER1'
        'DC01-C123-F001.tar' -> 'DC01'
    """
    # Remove extension first
    name = tar_filename
    for ext in ['.tar.gz', '.tgz', '.tar.bz2', '.tar']:
        if name.lower().endswith(ext):
            name = name[:-len(ext)]
            break
    
    # Pattern: Find -C followed by alphanumeric then -F followed by digits at the end
    # We want everything BEFORE this pattern
    pattern = r'^(.+)-C[A-Za-z0-9]+-F[0-9]+$'
    match = re.match(pattern, name, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Fallback: try to find -C###-F pattern and take everything before it
    pattern2 = r'^(.+)-C[A-Za-z0-9]+-F'
    match = re.match(pattern2, name, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return None


@dataclass
class CollectionFile:
    """Represents a found collection file (IZE or TAR/UAC)"""
    name: str
    full_path: str
    file_type: str = "IZE"  # "IZE" or "UAC" (tar)
    file_size: int = 0
    source_zip: Optional[str] = None
    client_id: Optional[str] = None  # Extracted from filename (C###-F pattern)
    hostname: Optional[str] = None  # Extracted hostname for matching (especially for TAR files)

    def __post_init__(self):
        if self.file_size == 0 and os.path.exists(self.full_path):
            self.file_size = os.path.getsize(self.full_path)
        
        # Extract client ID - first try from filename, then from source ZIP
        if not self.client_id:
            self.client_id = extract_client_id(self.name)
        if not self.client_id and self.source_zip:
            self.client_id = extract_client_id(os.path.basename(self.source_zip))
        
        # For TAR/UAC files, extract the hostname from the filename
        if self.file_type == "UAC" and not self.hostname:
            self.hostname = extract_hostname_from_tar(self.name)
    
    def get_match_name(self) -> str:
        """Get the name to use for hostname matching."""
        # For UAC/TAR files, use the extracted hostname if available
        if self.file_type == "UAC" and self.hostname:
            return self.hostname
        # For IZE files, use the filename
        return self.name


# Alias for backward compatibility
IZEFile = CollectionFile


@dataclass
class CSVMapping:
    """Represents a row from the CSV mapping file"""
    folder_name: str
    search_term: str
    row_number: int


@dataclass
class SortedFile:
    """Tracks a file sorted to a destination for duplicate handling"""
    ize_file: IZEFile
    destination: str
    match_score: float


# ============================================================================
# MATCHING LOGIC
# ============================================================================

def get_match_type(filename: str, search_term: str) -> Tuple[float, str]:
    """
    Calculate fuzzy match score and return the type of match found.
    Returns (score, match_type_description).
    """
    filename_lower = filename.lower()
    search_lower = search_term.lower()
    filename_base = filename_lower.replace('.ize', '')
    
    # Exact match (without extension)
    if filename_base == search_lower:
        return 100.0, "EXACT_MATCH (filename equals hostname)"
    
    # Direct substring match
    if search_lower in filename_base:
        match_ratio = len(search_lower) / len(filename_base)
        score = 90.0 + (match_ratio * 10)
        return score, f"SUBSTRING_MATCH ('{search_lower}' found in filename)"
    
    if filename_base in search_lower:
        return 88.0, f"REVERSE_SUBSTRING (filename found in '{search_lower}')"
    
    # Clean separators and check again
    filename_clean = filename_base.replace('_', '').replace('-', '').replace('.', '')
    search_clean = search_lower.replace('_', '').replace('-', '').replace('.', '')
    
    if search_clean in filename_clean:
        return 85.0, f"NORMALIZED_SUBSTRING ('{search_clean}' found after removing separators)"
    
    # Word-based matching
    filename_parts = set(filename_base.replace('_', ' ').replace('-', ' ').replace('.', ' ').split())
    search_parts = set(search_lower.replace('_', ' ').replace('-', ' ').replace('.', ' ').split())
    
    if search_parts and search_parts.issubset(filename_parts):
        return 80.0, f"WORD_MATCH (all words '{search_parts}' found in filename)"
    
    # Check for any common words
    common = filename_parts & search_parts
    if common:
        score = 70.0 + (len(common) / max(len(search_parts), 1)) * 10
        return score, f"PARTIAL_WORD_MATCH (common words: {common})"
    
    # Sequence matching (fuzzy ratio) as fallback
    ratio = SequenceMatcher(None, filename_clean, search_clean).ratio() * 100
    return ratio, f"FUZZY_RATIO (sequence similarity: {ratio:.1f}%)"


def build_mapping_index(mappings: List[CSVMapping]) -> Dict[str, CSVMapping]:
    """
    Build a case-insensitive index for fast exact/substring matching.
    """
    index = {}
    for mapping in mappings:
        # Index by lowercase search term for exact matching
        key = mapping.search_term.lower()
        index[key] = mapping
    return index


def find_best_match_with_details(coll_file: CollectionFile, mappings: List[CSVMapping], 
                                  threshold: float, mapping_index: Dict[str, CSVMapping] = None) -> Tuple[Optional[CSVMapping], float, str, list]:
    """
    Find the best matching CSV mapping for a collection file.
    Returns (match, score, match_type, all_checks) for logging.
    Uses index for fast lookup when available.
    """
    best_match = None
    best_score = 0.0
    best_match_type = ""
    all_checks = []
    
    # Use the appropriate name for matching (extracted hostname for TAR files)
    match_name = coll_file.get_match_name()
    match_name_lower = match_name.lower()
    
    # Fast path: Check for exact match first using index
    if mapping_index:
        if match_name_lower in mapping_index:
            best_match = mapping_index[match_name_lower]
            best_score = 100.0
            best_match_type = "EXACT_MATCH (hostname equals search term)"
            all_checks.append({
                'folder_name': best_match.folder_name,
                'search_term': best_match.search_term,
                'score': 100.0,
                'match_type': best_match_type
            })
            return best_match, best_score, best_match_type, all_checks
        
        # Check if any search term is contained in the match name
        for term, mapping in mapping_index.items():
            if term in match_name_lower:
                score = 90.0 + (len(term) / len(match_name_lower)) * 10
                if score > best_score:
                    best_score = score
                    best_match = mapping
                    best_match_type = f"SUBSTRING_MATCH ('{term}' found in hostname)"
        
        if best_match and best_score >= threshold:
            all_checks.append({
                'folder_name': best_match.folder_name,
                'search_term': best_match.search_term,
                'score': best_score,
                'match_type': best_match_type
            })
            return best_match, best_score, best_match_type, all_checks
    
    # Slow path: Full fuzzy matching (only if fast path didn't find a match)
    for mapping in mappings:
        score, match_type = get_match_type(match_name, mapping.search_term)
        
        check = {
            'folder_name': mapping.folder_name,
            'search_term': mapping.search_term,
            'score': score,
            'match_type': match_type
        }
        all_checks.append(check)
        
        if score > best_score and score >= threshold:
            best_score = score
            best_match = mapping
            best_match_type = match_type
        
        # Early exit if we found an exact match
        if best_score >= 100:
            break
    
    return best_match, best_score, best_match_type, all_checks


# ============================================================================
# FILE DISCOVERY
# ============================================================================

def find_collections_in_zip(zip_path: str, temp_dir: str, spinner: Optional[Spinner] = None) -> List[CollectionFile]:
    """
    Find all .IZE and .TAR (UAC) files inside a zip file (including nested zips).
    Extracts them to temp_dir for later copying.
    """
    global log_manager, debug_mode
    collection_files = []
    zip_name = os.path.basename(zip_path)
    
    # Extract Client ID from the ZIP filename
    client_id = extract_client_id(zip_name)
    
    try:
        log_manager.log_zip_processing(zip_path, "start")
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            all_entries = zf.infolist()
            
            # Find IZE files
            ize_entries = [zi for zi in all_entries if zi.filename.lower().endswith('.ize')]
            
            # Find TAR files (UAC collections) - support multiple tar extensions
            tar_extensions = ('.tar', '.tar.gz', '.tgz', '.tar.bz2')
            tar_entries = [zi for zi in all_entries if any(zi.filename.lower().endswith(ext) for ext in tar_extensions)]
            
            # Find nested ZIPs
            nested_zips = [zi for zi in all_entries if zi.filename.lower().endswith('.zip')]
            
            # Log what we found for debugging
            if log_manager:
                log_manager.logger.debug(f"ZIP contents for {zip_name}: {len(all_entries)} total entries")
                log_manager.logger.debug(f"  IZE files: {len(ize_entries)}")
                log_manager.logger.debug(f"  TAR files: {len(tar_entries)}")
                log_manager.logger.debug(f"  Nested ZIPs: {len(nested_zips)}")
                for entry in all_entries[:100]:  # Log first 100 entries
                    log_manager.logger.debug(f"    - {entry.filename}")
            
            # Debug mode - print to console
            if debug_mode:
                print(f"\n  {Style.DIM}[DEBUG] {zip_name} contents ({len(all_entries)} entries):{Style.RESET}")
                print(f"  {Style.DIM}  IZE: {len(ize_entries)}, TAR: {len(tar_entries)}, Nested ZIP: {len(nested_zips)}{Style.RESET}")
                # Show sample of files
                sample_entries = all_entries[:20]
                for entry in sample_entries:
                    ext = os.path.splitext(entry.filename)[1].lower()
                    if ext in ['.ize', '.tar', '.zip', '.gz', '.tgz']:
                        print(f"  {Style.YELLOW}    → {entry.filename}{Style.RESET}")
                    else:
                        print(f"  {Style.DIM}    - {entry.filename}{Style.RESET}")
                if len(all_entries) > 20:
                    print(f"  {Style.DIM}    ... and {len(all_entries) - 20} more entries{Style.RESET}")
            
            total_entries = len(ize_entries) + len(tar_entries)
            
            # Process IZE files
            for i, zip_info in enumerate(ize_entries):
                if spinner:
                    spinner.update(f"Extracting from {zip_name}: {zip_info.filename} ({i+1}/{total_entries})")
                # OWASP A08: Safe extraction to prevent zip slip
                extracted_path = safe_zip_extract(zf, zip_info, temp_dir)
                coll_file = CollectionFile(
                    name=os.path.basename(zip_info.filename),
                    full_path=extracted_path,
                    file_type="IZE",
                    file_size=zip_info.file_size,
                    source_zip=zip_path,
                    client_id=client_id
                )
                collection_files.append(coll_file)
                log_manager.log_discovered_file(coll_file.name, coll_file.file_size, zip_name)
            
            # Process TAR files (UAC collections)
            for i, zip_info in enumerate(tar_entries):
                if spinner:
                    spinner.update(f"Extracting UAC from {zip_name}: {zip_info.filename} ({len(ize_entries)+i+1}/{total_entries})")
                try:
                    # OWASP A08: Safe extraction to prevent zip slip
                    extracted_path = safe_zip_extract(zf, zip_info, temp_dir)
                    coll_file = CollectionFile(
                        name=os.path.basename(zip_info.filename),
                        full_path=extracted_path,
                        file_type="UAC",
                        file_size=zip_info.file_size,
                        source_zip=zip_path,
                        client_id=client_id
                    )
                    collection_files.append(coll_file)
                    log_manager.log_discovered_file(coll_file.name, coll_file.file_size, zip_name)
                except Exception as e:
                    log_manager.log_error(f"Failed to extract TAR {zip_info.filename} from {zip_name}: {str(e)}", e)
            
            # Process nested ZIPs
            for nested_info in nested_zips:
                if spinner:
                    spinner.update(f"Found nested zip in {zip_name}: {nested_info.filename}")
                # OWASP A08: Safe extraction to prevent zip slip
                nested_zip_path = safe_zip_extract(zf, nested_info, temp_dir)
                collection_files.extend(find_collections_in_zip(nested_zip_path, temp_dir, spinner))
        
        log_manager.log_zip_processing(zip_path, "success", total_entries)
                
    except zipfile.BadZipFile as e:
        msg = f"Could not read zip file (bad/corrupt): {zip_path}"
        log_manager.log_error(msg, e)
        log_manager.log_zip_processing(zip_path, "error")
    except PermissionError as e:
        msg = f"Permission denied: {zip_path}"
        log_manager.log_error(msg, e)
    except Exception as e:
        msg = f"Error processing {zip_path}: {str(e)}"
        log_manager.log_error(msg, e)
    
    return collection_files


# Alias for backward compatibility
find_ize_in_zip = find_collections_in_zip


def find_all_zip_files(search_path: str) -> List[str]:
    """Find all ZIP files recursively in the search path."""
    zip_files = []
    for root, dirs, files in os.walk(search_path):
        for file in files:
            if file.lower().endswith('.zip'):
                zip_files.append(os.path.join(root, file))
    return zip_files


def find_all_collection_files(search_path: str, temp_dir: str) -> List[CollectionFile]:
    """
    Find all .IZE and .TAR (UAC) files in the search path, including inside zip files.
    Shows spinner during processing.
    """
    global log_manager
    collection_files = []
    
    print_section("SCANNING FOR COLLECTIONS", "🔎")
    print_info(f"Search path: {search_path}")
    print_info(f"Looking for: .IZE files and .TAR (UAC) collections\n")
    log_manager.logger.info("")
    log_manager.logger.info("FILE DISCOVERY")
    log_manager.logger.info("-" * 80)
    
    # Find collection files directly in directories
    spinner = Spinner("Scanning directories...")
    spinner.start()
    
    direct_ize_count = 0
    direct_tar_count = 0
    for root, dirs, files in os.walk(search_path):
        for file in files:
            file_lower = file.lower()
            if file_lower.endswith('.ize'):
                full_path = os.path.join(root, file)
                coll_file = CollectionFile(
                    name=file,
                    full_path=full_path,
                    file_type="IZE",
                    source_zip=None
                )
                collection_files.append(coll_file)
                direct_ize_count += 1
                log_manager.log_discovered_file(file, coll_file.file_size)
                spinner.update(f"Scanning... {direct_ize_count} IZE, {direct_tar_count} UAC")
            elif file_lower.endswith('.tar'):
                full_path = os.path.join(root, file)
                coll_file = CollectionFile(
                    name=file,
                    full_path=full_path,
                    file_type="UAC",
                    source_zip=None
                )
                collection_files.append(coll_file)
                direct_tar_count += 1
                log_manager.log_discovered_file(file, coll_file.file_size)
                spinner.update(f"Scanning... {direct_ize_count} IZE, {direct_tar_count} UAC")
    
    spinner.stop()
    print_success(f"Found {Style.BOLD}{direct_ize_count}{Style.RESET} .IZE file(s) in directories")
    print_success(f"Found {Style.BOLD}{direct_tar_count}{Style.RESET} .TAR (UAC) file(s) in directories")
    
    # Find all ZIP files
    spinner = Spinner("Locating ZIP files...")
    spinner.start()
    zip_files = find_all_zip_files(search_path)
    spinner.stop()
    print_success(f"Found {Style.BOLD}{len(zip_files)}{Style.RESET} ZIP file(s) to scan")
    
    # Process each ZIP file
    if zip_files:
        print(f"\n  {Style.CYAN}Extracting collections from {len(zip_files)} ZIP archive(s)...{Style.RESET}\n")
        
        progress = ProgressBar(len(zip_files), width=35, prefix="ZIP Files")
        total_from_zips = 0
        ize_from_zips = 0
        tar_from_zips = 0
        
        for i, zip_path in enumerate(zip_files, 1):
            zip_name = os.path.basename(zip_path)
            progress.update(i, zip_name)
            
            found_in_zip = find_collections_in_zip(zip_path, temp_dir, None)
            total_from_zips += len(found_in_zip)
            ize_from_zips += sum(1 for f in found_in_zip if f.file_type == "IZE")
            tar_from_zips += sum(1 for f in found_in_zip if f.file_type == "UAC")
            collection_files.extend(found_in_zip)
        
        progress.finish()
        print_success(f"Extracted {Style.BOLD}{ize_from_zips}{Style.RESET} .IZE and {Style.BOLD}{tar_from_zips}{Style.RESET} .TAR (UAC) from {len(zip_files)} ZIPs")
    
    # Count totals by type
    total_ize = sum(1 for f in collection_files if f.file_type == "IZE")
    total_tar = sum(1 for f in collection_files if f.file_type == "UAC")
    
    # Count files with Client IDs
    with_client_id = sum(1 for f in collection_files if f.client_id)
    
    print(f"\n  {Style.BOLD}{Style.CYAN}═══ Total: {len(collection_files)} collection file(s) found ═══{Style.RESET}")
    print(f"  {Style.DIM}({total_ize} IZE, {total_tar} UAC/TAR, {with_client_id} with Client ID){Style.RESET}\n")
    
    log_manager.logger.info(f"TOTAL FILES DISCOVERED: {len(collection_files)} ({total_ize} IZE, {total_tar} UAC)")
    log_manager.logger.info(f"FILES WITH CLIENT ID: {with_client_id}")
    log_manager.logger.info("-" * 80)
    
    return collection_files


# Alias for backward compatibility
find_all_ize_files = find_all_collection_files


# ============================================================================
# CSV LOADING
# ============================================================================

def load_csv_mappings(csv_path: str) -> List[CSVMapping]:
    """
    Load the CSV mapping file.
    Column A (index 0): Hostname keyword - what to search for in filenames
    Column B (index 1): Product/Folder name - destination folder for matched files
    """
    global log_manager
    mappings = []
    
    try:
        with open(csv_path, 'r', newline='', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            
            first_row = next(reader, None)
            if first_row is None:
                log_manager.log_error(f"CSV file is empty: {csv_path}")
                return mappings
            
            # Detect header row
            header_indicators = ['folder', 'name', 'search', 'term', 'match', 'directory', 'host', 'hostname', 'product']
            is_header = any(
                indicator in cell.lower() 
                for cell in first_row 
                for indicator in header_indicators
            )
            
            start_row = 1
            if not is_header and len(first_row) >= 2:
                if first_row[0].strip() and first_row[1].strip():
                    # Column A = hostname/search term, Column B = folder/product name
                    mappings.append(CSVMapping(
                        folder_name=first_row[1].strip(),  # Column B is folder
                        search_term=first_row[0].strip(),  # Column A is hostname
                        row_number=1
                    ))
                start_row = 2
            
            for row_num, row in enumerate(reader, start=start_row):
                if len(row) >= 2 and row[0].strip() and row[1].strip():
                    # Column A = hostname/search term, Column B = folder/product name
                    mappings.append(CSVMapping(
                        folder_name=row[1].strip(),  # Column B is folder
                        search_term=row[0].strip(),  # Column A is hostname
                        row_number=row_num
                    ))
                elif len(row) > 0 and (not row[0].strip() or (len(row) > 1 and not row[1].strip())):
                    log_manager.log_warning(f"CSV row {row_num} skipped (empty hostname or folder): {row}")
    
    except FileNotFoundError as e:
        log_manager.log_error(f"CSV file not found: {csv_path}", e)
    except Exception as e:
        log_manager.log_error(f"Error reading CSV file: {csv_path}", e)
    
    print_success(f"Loaded {Style.BOLD}{len(mappings)}{Style.RESET} mapping(s) from CSV")
    
    if log_manager:
        log_manager.log_mappings(mappings)
    
    return mappings


# ============================================================================
# FILE SORTING WITH DUPLICATE HANDLING (FILE SIZE PRIORITY)
# ============================================================================

def sort_ize_files(
    ize_files: List[IZEFile],
    mappings: List[CSVMapping],
    output_dir: str,
    threshold: float
) -> Tuple[int, int, List[str], int]:
    """
    Sort IZE files into folders based on CSV mappings.
    Handles duplicates by keeping the larger file (file size priority).
    Returns (matched_count, unmatched_count, unmatched_files, duplicates_replaced)
    """
    global log_manager
    
    sorted_tracker: Dict[Tuple[str, str], SortedFile] = {}
    
    matched = 0
    unmatched = 0
    unmatched_files = []
    duplicates_replaced = 0
    
    os.makedirs(output_dir, exist_ok=True)
    
    print_section("SORTING FILES", "⚙")
    print_info("Duplicate detection enabled (keeping larger files)")
    print_info(f"Processing {len(ize_files)} files against {len(mappings)} hostname mappings\n")
    
    log_manager.logger.info("")
    log_manager.logger.info("FILE SORTING & CATEGORIZATION")
    log_manager.logger.info("=" * 80)
    
    # Build index for fast matching
    mapping_index = build_mapping_index(mappings)
    
    progress = ProgressBar(len(ize_files), width=35, prefix="Sorting")
    
    for idx, ize in enumerate(ize_files, 1):
        progress.update(idx, ize.get_match_name() if hasattr(ize, 'get_match_name') else ize.name)
        
        # Get match with full details for logging (use index for speed)
        match, score, match_type, all_checks = find_best_match_with_details(ize, mappings, threshold, mapping_index)
        
        # Log the categorization analysis
        best_match_info = None
        if match:
            best_match_info = {
                'folder_name': match.folder_name,
                'search_term': match.search_term,
                'score': score,
                'match_type': match_type
            }
        
        log_manager.log_match_attempt(ize.name, ize.file_size, all_checks, best_match_info, threshold,
                                       file_type=ize.file_type, match_name=ize.get_match_name())
        
        if match:
            # Sanitize folder name to remove invalid Windows characters
            safe_folder_name = sanitize_folder_name(match.folder_name)
            if safe_folder_name != match.folder_name:
                log_manager.log_warning(f"Folder name sanitized: '{match.folder_name}' -> '{safe_folder_name}'")
            target_folder = os.path.join(output_dir, safe_folder_name)
            target_key = (safe_folder_name, ize.name.lower())
            
            # Check for duplicate
            if target_key in sorted_tracker:
                existing = sorted_tracker[target_key]
                
                if ize.file_size > existing.ize_file.file_size:
                    # Replace with larger file
                    log_manager.log_duplicate(ize.name, safe_folder_name, 
                                             existing.ize_file.file_size, ize.file_size,
                                             "REPLACED with larger file")
                    
                    if os.path.exists(existing.destination):
                        os.remove(existing.destination)
                    
                    os.makedirs(target_folder, exist_ok=True)
                    target_path = os.path.join(target_folder, ize.name)
                    shutil.copy2(ize.full_path, target_path)
                    
                    log_manager.log_file_copy(ize.full_path, target_path, ize.file_size)
                    
                    # Add CSV record for the replacement
                    log_manager.add_file_record(
                        filename=ize.name,
                        source_zip=ize.source_zip,
                        file_size=ize.file_size,
                        status='DUPLICATE_REPLACED',
                        file_type=ize.file_type,
                        client_id=ize.client_id,
                        destination_folder=safe_folder_name,
                        matched_hostname=match.search_term,
                        match_score=score,
                        match_type=match_type,
                        destination_path=target_path,
                        notes=f"Replaced smaller file ({existing.ize_file.file_size:,} bytes)"
                    )
                    
                    sorted_tracker[target_key] = SortedFile(
                        ize_file=ize,
                        destination=target_path,
                        match_score=score
                    )
                    duplicates_replaced += 1
                else:
                    log_manager.log_duplicate(ize.name, safe_folder_name,
                                             existing.ize_file.file_size, ize.file_size,
                                             "KEPT existing (larger or equal)")
                    
                    # Add CSV record for skipped duplicate
                    log_manager.add_file_record(
                        filename=ize.name,
                        source_zip=ize.source_zip,
                        file_size=ize.file_size,
                        status='DUPLICATE_SKIPPED',
                        file_type=ize.file_type,
                        client_id=ize.client_id,
                        destination_folder=safe_folder_name,
                        matched_hostname=match.search_term,
                        match_score=score,
                        match_type=match_type,
                        destination_path='',
                        notes=f"Kept existing larger file ({existing.ize_file.file_size:,} bytes)"
                    )
            else:
                # New file - copy it
                os.makedirs(target_folder, exist_ok=True)
                target_path = os.path.join(target_folder, ize.name)
                
                # OWASP A08: Validate output path to prevent directory traversal
                if not is_safe_path(output_dir, target_path):
                    log_manager.log_error(f"Security: Blocked path traversal attempt for {ize.name}")
                    continue
                
                shutil.copy2(ize.full_path, target_path)
                
                log_manager.log_file_copy(ize.full_path, target_path, ize.file_size)
                
                # Add CSV record for successful match
                log_manager.add_file_record(
                    filename=ize.name,
                    source_zip=ize.source_zip,
                    file_size=ize.file_size,
                    status='MATCHED',
                    file_type=ize.file_type,
                    client_id=ize.client_id,
                    destination_folder=safe_folder_name,
                    matched_hostname=match.search_term,
                    match_score=score,
                    match_type=match_type,
                    destination_path=target_path,
                    notes='' if safe_folder_name == match.folder_name else f"Folder name sanitized from '{match.folder_name}'"
                )
                
                sorted_tracker[target_key] = SortedFile(
                    ize_file=ize,
                    destination=target_path,
                    match_score=score
                )
                matched += 1
        else:
            unmatched += 1
            unmatched_files.append(ize.name)
            
            # Add CSV record for unmatched file
            log_manager.add_file_record(
                filename=ize.name,
                source_zip=ize.source_zip,
                file_size=ize.file_size,
                status='UNMATCHED',
                file_type=ize.file_type,
                client_id=ize.client_id,
                destination_folder='',
                matched_hostname='',
                match_score=None,
                match_type='',
                destination_path='',
                notes='No hostname matched above threshold'
            )
    
    progress.finish()
    print_success(f"Processed {Style.BOLD}{len(ize_files)}{Style.RESET} files")
    
    return matched, unmatched, unmatched_files, duplicates_replaced


# ============================================================================
# MAIN
# ============================================================================

def main():
    global log_manager, debug_mode
    
    parser = argparse.ArgumentParser(
        description='Sort .IZE and .TAR (UAC) collection files based on CSV hostname mapping.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
    python ize_sorter.py ./source_files mapping.csv ./sorted_output
    python ize_sorter.py C:\\ZipArchives hosts.csv C:\\Output --threshold 60

CSV Format (Column A = Hostname to match, Column B = Product/Folder):
    Hostname,Product
    SERVER-DC01,Kaseya_Backup
    SERVER-DC02,Kaseya_Backup
    SQL-SERVER,Kaseya_Monitoring

Features:
    - Finds .IZE files and .TAR (UAC) collections
    - Recursively searches directories and inside ZIP files
    - Extracts Client ID from filenames (C###-F pattern)
    - Duplicate handling: keeps larger file by size
    - Sanitizes folder names (removes ? : * etc.)
    - Detailed log file and results CSV
        """
    )
    
    parser.add_argument('search_path', help='Directory to search for collections (recursively, including ZIPs)')
    parser.add_argument('csv_file', help='CSV file with Hostname keyword (col A) and Product/Folder (col B)')
    parser.add_argument('output_dir', help='Output directory where sorted folders will be created')
    parser.add_argument('--threshold', type=float, default=70.0,
                        help='Minimum match score (0-100) to consider a match (default: 70)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Preview matches without copying files')
    parser.add_argument('--debug', action='store_true',
                        help='Show detailed debug info about ZIP contents')
    parser.add_argument('--test-matching', action='store_true',
                        help='Test matching logic - shows extraction and matching details for each file')
    
    args = parser.parse_args()
    
    # Enable Windows ANSI colors
    Style.enable_windows_ansi()
    
    # Set debug mode
    debug_mode = args.debug
    
    # Print banner
    print_banner()
    
    # Validate inputs
    if not os.path.exists(args.search_path):
        print_error(f"Search path does not exist: {args.search_path}")
        sys.exit(1)
    
    if not os.path.exists(args.csv_file):
        print_error(f"CSV file does not exist: {args.csv_file}")
        sys.exit(1)
    
    # Initialize logging
    log_manager = LogManager(args.output_dir)
    log_file = log_manager.setup()
    log_manager.log_config(args.search_path, args.csv_file, args.output_dir, args.threshold)
    
    print_config_box(args.search_path, args.csv_file, args.output_dir, args.threshold, args.dry_run, log_file)
    
    # Load CSV mappings
    mappings = load_csv_mappings(args.csv_file)
    if not mappings:
        print_error("No valid mappings found in CSV file.")
        print_info("Expected format: Product,Hostname")
        log_manager.log_error("No valid mappings found in CSV file")
        sys.exit(1)
    
    # Show loaded mappings
    print_section("CSV MAPPINGS LOADED", "📋")
    print_info("Column A (hostname) → Column B (product/folder)\n")
    for m in mappings[:10]:
        safe_folder = sanitize_folder_name(m.folder_name)
        folder_note = f" {Style.DIM}(sanitized){Style.RESET}" if safe_folder != m.folder_name else ""
        print(f"  '{Style.YELLOW}{m.search_term}{Style.RESET}' {Style.DIM}→{Style.RESET} {Style.ACCENT}{safe_folder}{Style.RESET}{folder_note}")
    if len(mappings) > 10:
        print(f"  {Style.DIM}... and {len(mappings) - 10} more{Style.RESET}")
    
    # Create temp directory for zip extractions
    with tempfile.TemporaryDirectory() as temp_dir:
        # Find all IZE files
        ize_files = find_all_ize_files(args.search_path, temp_dir)
        
        if not ize_files:
            print_warning("No collection files (.IZE or .TAR) found. Nothing to sort.")
            log_manager.log_warning("No collection files found in search path")
            log_manager.finalize({'total_found': 0, 'matched': 0, 'unmatched': 0, 
                                 'duplicates': 0, 'unmatched_files': []})
            sys.exit(0)
        
        # List found files
        print_section("FILES DISCOVERED", "📁")
        for ize in ize_files[:15]:
            source = f" {Style.DIM}from {os.path.basename(ize.source_zip)}{Style.RESET}" if ize.source_zip else ""
            type_badge = f"{Style.CYAN}[{ize.file_type}]{Style.RESET}" if ize.file_type else ""
            client_badge = f" {Style.YELLOW}({ize.client_id}){Style.RESET}" if ize.client_id else ""
            print(f"  {Style.WHITE}•{Style.RESET} {type_badge} {ize.name}{client_badge} {Style.DIM}({ize.file_size:,} bytes){Style.RESET}{source}")
        if len(ize_files) > 15:
            print(f"  {Style.DIM}... and {len(ize_files) - 15} more files{Style.RESET}")
        
        if args.test_matching:
            # Test matching mode - show detailed extraction and matching for each file
            print_section("MATCHING TEST MODE", "🧪")
            print_info("Testing extraction and matching logic\n")
            
            mapping_index = build_mapping_index(mappings)
            matched_count = 0
            unmatched_count = 0
            
            for ize in ize_files:
                print(f"\n{Style.BOLD}{'─'*70}{Style.RESET}")
                print(f"{Style.CYAN}File:{Style.RESET} {ize.name}")
                print(f"{Style.CYAN}Type:{Style.RESET} {ize.file_type}")
                print(f"{Style.CYAN}Source ZIP:{Style.RESET} {os.path.basename(ize.source_zip) if ize.source_zip else '(direct)'}")
                
                # Show extraction results
                match_name = ize.get_match_name()
                print(f"{Style.YELLOW}Extracted Hostname:{Style.RESET} {match_name}")
                print(f"{Style.YELLOW}Client ID:{Style.RESET} {ize.client_id or '(none)'}")
                
                # Show matching attempt
                match, score, match_type, all_checks = find_best_match_with_details(ize, mappings, args.threshold, mapping_index)
                
                if match:
                    print(f"{Style.GREEN}✓ MATCH FOUND:{Style.RESET}")
                    print(f"  Matched against: '{Style.BOLD}{match.search_term}{Style.RESET}' (Column A - hostname)")
                    print(f"  Goes to folder:  '{Style.BOLD}{sanitize_folder_name(match.folder_name)}{Style.RESET}' (Column B - product)")
                    print(f"  Score: {score:.1f}% | Type: {match_type}")
                    matched_count += 1
                else:
                    print(f"{Style.RED}✗ NO MATCH{Style.RESET}")
                    print(f"  Hostname '{match_name}' did not match any keyword in Column A")
                    print(f"  Threshold: {args.threshold}%")
                    # Show top 3 closest matches
                    if all_checks:
                        sorted_checks = sorted(all_checks, key=lambda x: x['score'], reverse=True)[:3]
                        print(f"  {Style.DIM}Closest matches:{Style.RESET}")
                        for check in sorted_checks:
                            print(f"    {Style.DIM}- '{check['search_term']}' → {check['score']:.1f}%{Style.RESET}")
                    unmatched_count += 1
            
            print(f"\n{Style.BOLD}{'─'*70}{Style.RESET}")
            print(f"\n{Style.BOLD}TEST SUMMARY:{Style.RESET}")
            print(f"  Total files: {len(ize_files)}")
            print(f"  {Style.GREEN}Matched: {matched_count}{Style.RESET}")
            print(f"  {Style.RED}Unmatched: {unmatched_count}{Style.RESET}")
            print()
            sys.exit(0)
        
        if args.dry_run:
            print_section("DRY RUN - Preview Only", "🔍")
            print_info("No files will be copied\n")
            mapping_index = build_mapping_index(mappings)
            for ize in ize_files:
                match, score, match_type, _ = find_best_match_with_details(ize, mappings, args.threshold, mapping_index)
                if match:
                    print_match(ize.name, match.folder_name, match.search_term, score, ize.source_zip)
                else:
                    print_no_match(ize.name, ize.file_size, ize.source_zip)
            print()
            log_manager.finalize({'total_found': len(ize_files), 'matched': 0, 'unmatched': 0,
                                 'duplicates': 0, 'unmatched_files': [], 'dry_run': True})
        else:
            # Sort the files
            matched, unmatched, unmatched_files, duplicates_replaced = sort_ize_files(
                ize_files, mappings, args.output_dir, args.threshold
            )
            
            # Finalize log
            stats = {
                'total_found': len(ize_files),
                'matched': matched,
                'unmatched': unmatched,
                'duplicates': duplicates_replaced,
                'unmatched_files': unmatched_files
            }
            log_manager.finalize(stats)
            
            # Summary
            print_summary_box(len(ize_files), matched, duplicates_replaced, unmatched,
                            len(log_manager.errors), len(log_manager.warnings))
            
            # Show warnings if any
            if log_manager.warnings:
                print_section("WARNINGS", "⚠")
                for i, warning in enumerate(log_manager.warnings[:30], 1):
                    print(f"  {Style.YELLOW}{i}.{Style.RESET} {warning}")
                if len(log_manager.warnings) > 30:
                    print(f"  {Style.DIM}... and {len(log_manager.warnings) - 30} more (see log file){Style.RESET}")
            
            # Show errors if any
            if log_manager.errors:
                print_section("ERRORS", "✗")
                for i, error in enumerate(log_manager.errors[:20], 1):
                    print(f"  {Style.RED}{i}.{Style.RESET} {error}")
                if len(log_manager.errors) > 20:
                    print(f"  {Style.DIM}... and {len(log_manager.errors) - 20} more (see log file){Style.RESET}")
            
            if unmatched_files:
                print_section("UNMATCHED FILES", "○")
                print_info("Consider adding these hostnames to your CSV:\n")
                for f in unmatched_files[:20]:
                    print(f"  {Style.DIM}•{Style.RESET} {f}")
                if len(unmatched_files) > 20:
                    print(f"  {Style.DIM}... and {len(unmatched_files) - 20} more{Style.RESET}")
                print(f"\n  {Style.YELLOW}TIP:{Style.RESET} Lower --threshold (currently {args.threshold}%) or add hostnames to CSV")
            
            print(f"""
{Style.GREEN}{Style.BOLD}✓ COMPLETE{Style.RESET}

  {Style.CYAN}Sorted files:{Style.RESET}  {args.output_dir}
  {Style.CYAN}Log file:{Style.RESET}      {log_file}
  {Style.CYAN}Results CSV:{Style.RESET}   {log_manager.csv_output_file}
""")


if __name__ == '__main__':
    main()
