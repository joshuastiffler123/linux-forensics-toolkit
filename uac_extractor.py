"""
UAC Collection Extractor
========================
Recursively searches through .zip files (including nested ZIPs) in a directory,
finds UAC collection files (tar files), extracts them to a new folder, maps 
them to source zips in a CSV, and removes the source ZIP files after extraction.

Features:
  - Handles nested ZIPs (ZIP inside ZIP inside ZIP, etc.)
  - Supports multiple tar extensions (.tar, .tar.gz, .tgz, .tar.bz2)
  - Tracks the full path chain of nested archives
  - Cleans up source ZIPs after successful extraction

Usage:
    python uac_extractor.py <search_directory> <output_directory>
    python uac_extractor.py C:\ZipArchives C:\ExtractedUAC
    
Options:
    --dry-run       Show what would be done without actually extracting or deleting
    --keep-zips     Don't delete source ZIP files after extraction
    --verbose       Show detailed contents of each ZIP file
"""

import os
import sys
import csv
import zipfile
import shutil
import argparse
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass, field


# ============================================================================
# CONSOLE STYLING
# ============================================================================

class Style:
    """ANSI color codes for terminal output."""
    
    ENABLED = sys.stdout.isatty() and os.name == 'nt'
    
    RESET = '\033[0m' if ENABLED else ''
    BOLD = '\033[1m' if ENABLED else ''
    DIM = '\033[2m' if ENABLED else ''
    
    RED = '\033[91m' if ENABLED else ''
    GREEN = '\033[92m' if ENABLED else ''
    YELLOW = '\033[93m' if ENABLED else ''
    BLUE = '\033[94m' if ENABLED else ''
    MAGENTA = '\033[95m' if ENABLED else ''
    CYAN = '\033[96m' if ENABLED else ''
    
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN
    HEADER = MAGENTA

    @classmethod
    def enable_windows_ansi(cls):
        """Enable ANSI escape sequences on Windows."""
        if os.name == 'nt':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                cls.ENABLED = True
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


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ExtractionResult:
    """Represents a single UAC file extraction."""
    uac_filename: str
    source_zip: str           # The top-level ZIP file name
    source_zip_path: str      # Full path to top-level ZIP
    nested_path: str          # Path through nested ZIPs
    extracted_to: str
    timestamp: str
    size_bytes: int
    success: bool
    error_message: str = ""


@dataclass
class ExtractionStats:
    """Statistics for the extraction process."""
    zips_scanned: int = 0
    nested_zips_scanned: int = 0
    uac_files_found: int = 0
    uac_files_extracted: int = 0
    zips_deleted: int = 0
    errors: int = 0
    total_bytes_extracted: int = 0


# Supported TAR extensions (UAC collection files)
TAR_EXTENSIONS = ('.tar', '.tar.gz', '.tgz', '.tar.bz2')


# ============================================================================
# MAIN EXTRACTOR CLASS
# ============================================================================

class UACExtractor:
    """Extracts UAC collection files from ZIP archives, including nested ZIPs."""
    
    def __init__(
        self,
        search_dir: str,
        output_dir: str,
        dry_run: bool = False,
        keep_zips: bool = False,
        verbose: bool = False
    ):
        self.search_dir = Path(search_dir)
        self.output_dir = Path(output_dir)
        self.dry_run = dry_run
        self.keep_zips = keep_zips
        self.verbose = verbose
        
        self.results: List[ExtractionResult] = []
        self.stats = ExtractionStats()
        self.zips_to_delete: List[Path] = []
        
    def print_header(self):
        """Print styled header."""
        Style.enable_windows_ansi()
        print()
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
        print(f"{Style.HEADER}{Style.BOLD}  UAC Collection Extractor{Style.RESET}")
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
        print()
        print(f"{Style.INFO}Search Directory:{Style.RESET} {self.search_dir}")
        print(f"{Style.INFO}Output Directory:{Style.RESET} {self.output_dir}")
        print(f"{Style.INFO}TAR Extensions:{Style.RESET} {', '.join(TAR_EXTENSIONS)}")
        print(f"{Style.INFO}Dry Run:{Style.RESET} {self.dry_run}")
        print(f"{Style.INFO}Keep ZIPs:{Style.RESET} {self.keep_zips}")
        print(f"{Style.INFO}Verbose:{Style.RESET} {self.verbose}")
        print()
        
    def is_tar_file(self, filename: str) -> bool:
        """Check if a filename is a TAR/UAC collection file."""
        lower_name = filename.lower()
        return any(lower_name.endswith(ext) for ext in TAR_EXTENSIONS)
    
    def is_zip_file(self, filename: str) -> bool:
        """Check if a filename is a ZIP file."""
        return filename.lower().endswith('.zip')
    
    def find_zip_files(self) -> List[Path]:
        """Recursively find all ZIP files in search directory."""
        zip_files = []
        
        print(f"{Style.INFO}Scanning for ZIP files...{Style.RESET}")
        
        for root, dirs, files in os.walk(self.search_dir):
            for file in files:
                if file.lower().endswith('.zip'):
                    zip_files.append(Path(root) / file)
                    
        print(f"{Style.SUCCESS}Found {len(zip_files)} top-level ZIP file(s){Style.RESET}")
        return zip_files
    
    def find_uac_in_zip(
        self, 
        zip_path: str, 
        temp_dir: str,
        top_level_zip: Path,
        zip_chain: List[str],
        depth: int = 0
    ) -> List[ExtractionResult]:
        """
        Find all TAR (UAC) files inside a zip file (including nested zips).
        Extracts nested zips to temp_dir for processing.
        
        This mirrors the approach used in ize_sorter.py which works.
        """
        results = []
        indent = "  " * (depth + 1)
        zip_name = os.path.basename(zip_path)
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Get all entries using infolist (same as ize_sorter.py)
                all_entries = zf.infolist()
                
                # Find TAR files (UAC collections)
                tar_entries = [zi for zi in all_entries 
                              if self.is_tar_file(zi.filename) and not zi.is_dir()]
                
                # Find nested ZIPs
                nested_zips = [zi for zi in all_entries 
                              if self.is_zip_file(zi.filename) and not zi.is_dir()]
                
                # Verbose output - show contents
                if self.verbose:
                    print(f"{indent}{Style.CYAN}Contents of {zip_name} ({len(all_entries)} entries):{Style.RESET}")
                    for entry in all_entries[:30]:
                        marker = ""
                        if self.is_tar_file(entry.filename):
                            marker = f" {Style.GREEN}<-- TAR/UAC{Style.RESET}"
                        elif self.is_zip_file(entry.filename):
                            marker = f" {Style.BLUE}<-- NESTED ZIP{Style.RESET}"
                        print(f"{indent}  {entry.filename}{marker}")
                    if len(all_entries) > 30:
                        print(f"{indent}  ... and {len(all_entries) - 30} more")
                
                # Report what we found
                if tar_entries:
                    print(f"{indent}{Style.SUCCESS}Found {len(tar_entries)} UAC/TAR file(s){Style.RESET}")
                elif self.verbose:
                    print(f"{indent}{Style.DIM}No TAR files at this level{Style.RESET}")
                    
                if nested_zips:
                    print(f"{indent}{Style.BLUE}Found {len(nested_zips)} nested ZIP(s){Style.RESET}")
                elif self.verbose:
                    print(f"{indent}{Style.DIM}No nested ZIPs{Style.RESET}")
                
                self.stats.uac_files_found += len(tar_entries)
                
                # Process TAR files
                for zip_info in tar_entries:
                    tar_filename = os.path.basename(zip_info.filename)
                    full_chain = zip_chain + [tar_filename]
                    nested_path = " -> ".join(full_chain)
                    
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Determine output path
                    output_path = self.output_dir / tar_filename
                    counter = 1
                    original_stem = output_path.stem
                    # Handle .tar.gz etc by getting full suffix
                    if tar_filename.lower().endswith('.tar.gz'):
                        original_suffix = '.tar.gz'
                        original_stem = tar_filename[:-7]
                    elif tar_filename.lower().endswith('.tar.bz2'):
                        original_suffix = '.tar.bz2'
                        original_stem = tar_filename[:-8]
                    else:
                        original_suffix = output_path.suffix
                    
                    while output_path.exists():
                        output_path = self.output_dir / f"{original_stem}_{counter}{original_suffix}"
                        counter += 1
                    
                    if self.dry_run:
                        print(f"{indent}  {Style.YELLOW}[DRY RUN]{Style.RESET} Would extract: {tar_filename}")
                        results.append(ExtractionResult(
                            uac_filename=tar_filename,
                            source_zip=top_level_zip.name,
                            source_zip_path=str(top_level_zip),
                            nested_path=nested_path,
                            extracted_to=str(output_path),
                            timestamp=timestamp,
                            size_bytes=zip_info.file_size,
                            success=True
                        ))
                        self.stats.uac_files_extracted += 1
                        if top_level_zip not in self.zips_to_delete:
                            self.zips_to_delete.append(top_level_zip)
                    else:
                        try:
                            # Create output directory
                            self.output_dir.mkdir(parents=True, exist_ok=True)
                            
                            # OWASP A08: Safe extraction to prevent zip slip
                            temp_extracted = safe_zip_extract(zf, zip_info, temp_dir)
                            shutil.move(temp_extracted, output_path)
                            
                            print(f"{indent}  {Style.SUCCESS}✓ Extracted:{Style.RESET} {tar_filename} ({self._format_size(zip_info.file_size)})")
                            
                            results.append(ExtractionResult(
                                uac_filename=tar_filename,
                                source_zip=top_level_zip.name,
                                source_zip_path=str(top_level_zip),
                                nested_path=nested_path,
                                extracted_to=str(output_path),
                                timestamp=timestamp,
                                size_bytes=zip_info.file_size,
                                success=True
                            ))
                            self.stats.uac_files_extracted += 1
                            self.stats.total_bytes_extracted += zip_info.file_size
                            
                            if top_level_zip not in self.zips_to_delete:
                                self.zips_to_delete.append(top_level_zip)
                                
                        except Exception as e:
                            print(f"{indent}  {Style.ERROR}✗ Failed:{Style.RESET} {tar_filename} - {str(e)}")
                            results.append(ExtractionResult(
                                uac_filename=tar_filename,
                                source_zip=top_level_zip.name,
                                source_zip_path=str(top_level_zip),
                                nested_path=nested_path,
                                extracted_to="",
                                timestamp=timestamp,
                                size_bytes=zip_info.file_size,
                                success=False,
                                error_message=str(e)
                            ))
                            self.stats.errors += 1
                
                # Process nested ZIPs - extract to disk first, then recurse
                for nested_info in nested_zips:
                    nested_filename = os.path.basename(nested_info.filename)
                    print(f"{indent}{Style.BLUE}Entering nested ZIP:{Style.RESET} {nested_filename}")
                    self.stats.nested_zips_scanned += 1
                    
                    try:
                        # OWASP A08: Safe extraction of nested ZIP
                        nested_zip_path = safe_zip_extract(zf, nested_info, temp_dir)
                        
                        # Recursively process the nested ZIP
                        nested_results = self.find_uac_in_zip(
                            nested_zip_path,
                            temp_dir,
                            top_level_zip,
                            zip_chain + [nested_filename],
                            depth + 1
                        )
                        results.extend(nested_results)
                        
                    except zipfile.BadZipFile:
                        print(f"{indent}  {Style.ERROR}ERROR: Invalid nested ZIP{Style.RESET}")
                        self.stats.errors += 1
                    except Exception as e:
                        print(f"{indent}  {Style.ERROR}ERROR: {str(e)}{Style.RESET}")
                        self.stats.errors += 1
                        
        except zipfile.BadZipFile:
            print(f"{indent}{Style.ERROR}ERROR: Invalid or corrupted ZIP: {zip_name}{Style.RESET}")
            self.stats.errors += 1
        except Exception as e:
            print(f"{indent}{Style.ERROR}ERROR processing {zip_name}: {str(e)}{Style.RESET}")
            self.stats.errors += 1
            
        return results
    
    def process_zip_file(self, zip_path: Path) -> List[ExtractionResult]:
        """Process a single top-level ZIP file."""
        self.stats.zips_scanned += 1
        
        print(f"\n{Style.BLUE}Processing:{Style.RESET} {zip_path}")
        
        # Create a temp directory for this ZIP's processing
        with tempfile.TemporaryDirectory() as temp_dir:
            results = self.find_uac_in_zip(
                str(zip_path),
                temp_dir,
                zip_path,
                [zip_path.name],
                depth=0
            )
            
            if not results:
                print(f"  {Style.DIM}No UAC/TAR files found{Style.RESET}")
                
        return results
    
    def cleanup_zips(self):
        """Delete ZIP files that had successful extractions."""
        if self.keep_zips:
            print(f"\n{Style.INFO}Keeping source ZIP files (--keep-zips specified){Style.RESET}")
            return
            
        if not self.zips_to_delete:
            return
            
        print(f"\n{Style.WARNING}Cleaning up source ZIP files...{Style.RESET}")
        
        for zip_path in self.zips_to_delete:
            if self.dry_run:
                print(f"  {Style.YELLOW}[DRY RUN]{Style.RESET} Would delete: {zip_path.name}")
                self.stats.zips_deleted += 1
            else:
                try:
                    zip_path.unlink()
                    print(f"  {Style.SUCCESS}✓ Deleted:{Style.RESET} {zip_path.name}")
                    self.stats.zips_deleted += 1
                except Exception as e:
                    print(f"  {Style.ERROR}✗ Failed to delete:{Style.RESET} {zip_path.name} - {str(e)}")
                    self.stats.errors += 1
    
    def write_mapping_csv(self):
        """Write the mapping CSV file."""
        if not self.results:
            print(f"\n{Style.WARNING}No results to write to CSV{Style.RESET}")
            return
            
        csv_path = self.output_dir / f"uac_mapping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        if self.dry_run:
            print(f"\n{Style.YELLOW}[DRY RUN]{Style.RESET} Would write mapping to: {csv_path}")
            return
            
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'UAC_Filename',
                    'Source_ZIP',
                    'Source_ZIP_Path',
                    'Nested_Path',
                    'Extracted_To',
                    'Timestamp',
                    'Size_Bytes',
                    'Success',
                    'Error_Message'
                ])
                
                for result in self.results:
                    writer.writerow([
                        result.uac_filename,
                        result.source_zip,
                        result.source_zip_path,
                        result.nested_path,
                        result.extracted_to,
                        result.timestamp,
                        result.size_bytes,
                        result.success,
                        result.error_message
                    ])
                    
            print(f"\n{Style.SUCCESS}Mapping CSV written to:{Style.RESET} {csv_path}")
            
        except Exception as e:
            print(f"\n{Style.ERROR}Failed to write CSV:{Style.RESET} {str(e)}")
            self.stats.errors += 1
    
    def print_summary(self):
        """Print extraction summary."""
        print()
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
        print(f"{Style.HEADER}{Style.BOLD}  Extraction Summary{Style.RESET}")
        print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
        print()
        print(f"  Top-level ZIPs scanned: {self.stats.zips_scanned}")
        print(f"  Nested ZIPs scanned:    {self.stats.nested_zips_scanned}")
        print(f"  UAC files found:        {self.stats.uac_files_found}")
        print(f"  UAC files extracted:    {Style.SUCCESS}{self.stats.uac_files_extracted}{Style.RESET}")
        print(f"  Total data extracted:   {self._format_size(self.stats.total_bytes_extracted)}")
        print(f"  ZIP files deleted:      {self.stats.zips_deleted}")
        if self.stats.errors > 0:
            print(f"  Errors:                 {Style.ERROR}{self.stats.errors}{Style.RESET}")
        print()
        
        if self.dry_run:
            print(f"{Style.YELLOW}{Style.BOLD}This was a dry run - no files were actually modified{Style.RESET}")
            print()
    
    def _format_size(self, size_bytes: int) -> str:
        """Format bytes as human-readable size."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
    
    def run(self):
        """Execute the extraction process."""
        self.print_header()
        
        # Validate search directory
        if not self.search_dir.exists():
            print(f"{Style.ERROR}ERROR: Search directory does not exist:{Style.RESET} {self.search_dir}")
            return False
            
        if not self.search_dir.is_dir():
            print(f"{Style.ERROR}ERROR: Search path is not a directory:{Style.RESET} {self.search_dir}")
            return False
        
        # Find all ZIP files
        zip_files = self.find_zip_files()
        
        if not zip_files:
            print(f"\n{Style.WARNING}No ZIP files found in search directory{Style.RESET}")
            return True
        
        # Process each ZIP file
        for zip_path in zip_files:
            results = self.process_zip_file(zip_path)
            self.results.extend(results)
        
        # Write mapping CSV
        self.write_mapping_csv()
        
        # Cleanup ZIPs
        self.cleanup_zips()
        
        # Print summary
        self.print_summary()
        
        return self.stats.errors == 0


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Extract UAC collection files (TAR) from ZIP archives (supports nested ZIPs)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported TAR extensions: .tar, .tar.gz, .tgz, .tar.bz2

Examples:
  python uac_extractor.py C:\\ZipArchives C:\\ExtractedUAC
  python uac_extractor.py ./zips ./output --dry-run
  python uac_extractor.py ./zips ./output --keep-zips
  python uac_extractor.py ./zips ./output --verbose
        """
    )
    
    parser.add_argument(
        'search_directory',
        help='Directory to recursively search for ZIP files'
    )
    
    parser.add_argument(
        'output_directory',
        help='Directory to extract UAC files to'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without actually extracting or deleting'
    )
    
    parser.add_argument(
        '--keep-zips',
        action='store_true',
        help="Don't delete source ZIP files after extraction"
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed contents of each ZIP file for debugging'
    )
    
    args = parser.parse_args()
    
    extractor = UACExtractor(
        search_dir=args.search_directory,
        output_dir=args.output_directory,
        dry_run=args.dry_run,
        keep_zips=args.keep_zips,
        verbose=args.verbose
    )
    
    success = extractor.run()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
