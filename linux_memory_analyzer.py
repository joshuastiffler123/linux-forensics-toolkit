#!/usr/bin/env python3
"""
Linux Memory Analyzer - Volatility 3 Wrapper for Memory Forensics

This script automates Volatility 3 analysis of Linux memory dumps (AVML, LiME, etc.)
and outputs results in CSV format for easy analysis.

Analysis Categories:
1. Kernel Identification - banners, linux.info
2. Process Analysis - pslist, psscan, pstree, psaux
3. Network Analysis - netstat, sockstat, unix sockets
4. Kernel Module Integrity - lsmod, check_modules, hidden_modules
5. Memory Injection Detection - malfind, proc.Maps
6. Privilege Review - check_creds
7. Environment Inspection - envars
8. User Activity - who, bash history

Requirements:
- Python 3.6+
- Volatility 3 installed and accessible as 'vol' or 'vol.py' in PATH
- Linux memory image (AVML .lime, LiME, raw, etc.)

Author: Security Tools
Version: 1.0.0
License: MIT
"""

import argparse
import csv
import os
import shutil
import subprocess
import sys
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
    
    ERROR = RED
    SUCCESS = GREEN
    WARNING = YELLOW
    INFO = CYAN
    HEADER = MAGENTA
    
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
# Volatility Plugin Definitions
# ============================================================================

# Define all plugins to run, grouped by category
VOLATILITY_PLUGINS = {
    "Kernel Identification": [
        ("banners", "banners.csv", "Identifies kernel version from memory"),
        ("linux.info", "linux_info.csv", "System information from kernel"),
    ],
    "Process Analysis": [
        ("linux.pslist", "pslist.csv", "List running processes"),
        ("linux.psscan", "psscan.csv", "Scan for process structures"),
        ("linux.pstree", "pstree.csv", "Process tree hierarchy"),
        ("linux.psaux", "psaux.csv", "Process list with arguments (ps aux style)"),
    ],
    "Network Analysis": [
        ("linux.netstat", "netstat.csv", "Network connections"),
        ("linux.sockstat", "sockstat.csv", "Socket statistics"),
        ("linux.unix", "unix_sockets.csv", "Unix domain sockets"),
    ],
    "Kernel Module Integrity": [
        ("linux.lsmod", "lsmod.csv", "List loaded kernel modules"),
        ("linux.check_modules", "check_modules.csv", "Check for module hiding"),
        ("linux.hidden_modules", "hidden_modules.csv", "Detect hidden kernel modules"),
    ],
    "Memory Injection Detection": [
        ("linux.malfind", "malfind.csv", "Find injected/suspicious memory regions"),
        ("linux.proc.Maps", "proc_maps.csv", "Process memory mappings"),
    ],
    "Privilege Review": [
        ("linux.check_creds", "check_creds.csv", "Check for credential anomalies"),
    ],
    "Environment Inspection": [
        ("linux.envars", "envars.csv", "Process environment variables"),
    ],
    "User Activity": [
        ("linux.who", "who.csv", "Logged in users from utmp"),
        ("linux.bash", "bash_history.csv", "Bash command history from memory"),
    ],
}

# Additional plugins that can be optionally enabled
OPTIONAL_PLUGINS = {
    "File Analysis": [
        ("linux.lsof", "lsof.csv", "List open files"),
        ("linux.find_file", "find_file.csv", "Find file in memory"),
    ],
    "Rootkit Detection": [
        ("linux.check_syscall", "check_syscall.csv", "Check syscall table for hooks"),
        ("linux.check_idt", "check_idt.csv", "Check IDT for hooks"),
        ("linux.tty_check", "tty_check.csv", "Check TTY for hooks"),
    ],
    "Advanced Analysis": [
        ("linux.kmsg", "kmsg.csv", "Kernel message buffer"),
        ("linux.mountinfo", "mountinfo.csv", "Mount information"),
        ("linux.library_list", "library_list.csv", "Loaded libraries per process"),
    ],
}


# ============================================================================
# Volatility Runner
# ============================================================================

class VolatilityRunner:
    """Handles running Volatility 3 plugins."""
    
    def __init__(self, image_path: str, output_dir: str, vol_path: str = None):
        """
        Initialize the Volatility runner.
        
        Args:
            image_path: Path to the memory image file
            output_dir: Directory for output files
            vol_path: Optional path to volatility executable
        """
        self.image_path = os.path.abspath(image_path)
        self.output_dir = os.path.abspath(output_dir)
        self.vol_path = vol_path or self._find_volatility()
        self.results = {}
        self.errors = {}
    
    def _find_volatility(self) -> str:
        """Find Volatility 3 executable in PATH."""
        # Common names for volatility
        vol_names = ['vol', 'vol.py', 'vol3', 'volatility', 'volatility3', 'python -m volatility3']
        
        for name in vol_names:
            if shutil.which(name):
                return name
        
        # Check if vol.py exists in common locations
        common_paths = [
            '/usr/local/bin/vol.py',
            '/usr/bin/vol.py',
            os.path.expanduser('~/.local/bin/vol.py'),
            os.path.expanduser('~/volatility3/vol.py'),
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def check_volatility(self) -> Tuple[bool, str]:
        """
        Check if Volatility 3 is available.
        
        Returns:
            Tuple of (available, message)
        """
        if not self.vol_path:
            return False, "Volatility 3 not found. Please install it or specify path with --vol-path"
        
        try:
            result = subprocess.run(
                [self.vol_path, '--help'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0 or 'volatility' in result.stdout.lower():
                return True, f"Found Volatility at: {self.vol_path}"
        except subprocess.TimeoutExpired:
            return False, f"Volatility at {self.vol_path} timed out"
        except FileNotFoundError:
            return False, f"Volatility not found at: {self.vol_path}"
        except Exception as e:
            return False, f"Error checking Volatility: {e}"
        
        return False, "Could not verify Volatility installation"
    
    def run_plugin(self, plugin: str, output_file: str, description: str = "",
                   verbose: bool = True) -> Tuple[bool, str]:
        """
        Run a single Volatility plugin.
        
        Args:
            plugin: Plugin name (e.g., 'linux.pslist')
            output_file: Output filename
            description: Plugin description for display
            verbose: Whether to print progress
        
        Returns:
            Tuple of (success, message)
        """
        output_path = os.path.join(self.output_dir, output_file)
        stderr_path = os.path.join(self.output_dir, output_file.replace('.csv', '.stderr'))
        
        if verbose:
            print(f"  {Style.INFO}Running {plugin}...{Style.RESET}", end=" ", flush=True)
        
        try:
            # Build command
            cmd = [
                self.vol_path,
                '-f', self.image_path,
                '-r', 'csv',  # CSV output
                plugin
            ]
            
            # Run volatility
            with open(output_path, 'w') as stdout_file, open(stderr_path, 'w') as stderr_file:
                result = subprocess.run(
                    cmd,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=600  # 10 minute timeout per plugin
                )
            
            # Check results
            if result.returncode == 0:
                # Count lines in output
                with open(output_path, 'r') as f:
                    line_count = sum(1 for _ in f) - 1  # Subtract header
                
                self.results[plugin] = {
                    'success': True,
                    'output_file': output_path,
                    'line_count': max(0, line_count)
                }
                
                if verbose:
                    if line_count > 0:
                        print(f"{Style.SUCCESS}OK ({line_count} rows){Style.RESET}")
                    else:
                        print(f"{Style.WARNING}OK (no data){Style.RESET}")
                
                return True, f"Success: {line_count} rows"
            else:
                # Read stderr for error message
                with open(stderr_path, 'r') as f:
                    error = f.read().strip()[:200]
                
                self.errors[plugin] = error
                
                if verbose:
                    print(f"{Style.ERROR}FAILED{Style.RESET}")
                
                return False, error
                
        except subprocess.TimeoutExpired:
            self.errors[plugin] = "Timeout (>10 minutes)"
            if verbose:
                print(f"{Style.ERROR}TIMEOUT{Style.RESET}")
            return False, "Plugin timed out"
            
        except Exception as e:
            self.errors[plugin] = str(e)
            if verbose:
                print(f"{Style.ERROR}ERROR: {e}{Style.RESET}")
            return False, str(e)
    
    def run_all_plugins(self, categories: Dict = None, verbose: bool = True) -> Dict:
        """
        Run all plugins in specified categories.
        
        Args:
            categories: Dict of category->plugins to run (default: VOLATILITY_PLUGINS)
            verbose: Whether to print progress
        
        Returns:
            Dict of results
        """
        if categories is None:
            categories = VOLATILITY_PLUGINS
        
        total_plugins = sum(len(plugins) for plugins in categories.values())
        completed = 0
        
        for category, plugins in categories.items():
            if verbose:
                print(f"\n{Style.HEADER}{Style.BOLD}[{category}]{Style.RESET}")
            
            for plugin, output_file, description in plugins:
                self.run_plugin(plugin, output_file, description, verbose)
                completed += 1
        
        return self.results


# ============================================================================
# Memory Analyzer
# ============================================================================

class LinuxMemoryAnalyzer:
    """Main analyzer class for Linux memory forensics."""
    
    def __init__(self, image_path: str, output_dir: str = None, vol_path: str = None):
        """
        Initialize the memory analyzer.
        
        Args:
            image_path: Path to memory image
            output_dir: Output directory (default: creates based on image name)
            vol_path: Optional path to Volatility executable
        """
        self.image_path = os.path.abspath(image_path)
        
        # Create output directory based on image name
        if output_dir is None:
            image_name = os.path.splitext(os.path.basename(image_path))[0]
            output_dir = f"{image_name}_memory_analysis"
        
        self.output_dir = os.path.abspath(output_dir)
        self.vol_runner = VolatilityRunner(image_path, self.output_dir, vol_path)
        self.start_time = None
        self.end_time = None
    
    def validate(self) -> Tuple[bool, str]:
        """
        Validate that analysis can proceed.
        
        Returns:
            Tuple of (valid, message)
        """
        # Check image exists
        if not os.path.exists(self.image_path):
            return False, f"Memory image not found: {self.image_path}"
        
        # Check image size (should be substantial for memory dump)
        size = os.path.getsize(self.image_path)
        if size < 1024 * 1024:  # Less than 1MB
            return False, f"Image file seems too small ({size} bytes) - is this a valid memory dump?"
        
        # Check Volatility
        vol_ok, vol_msg = self.vol_runner.check_volatility()
        if not vol_ok:
            return False, vol_msg
        
        return True, "Validation passed"
    
    def analyze(self, include_optional: bool = False, verbose: bool = True) -> Dict:
        """
        Run full memory analysis.
        
        Args:
            include_optional: Whether to include optional plugins
            verbose: Whether to print progress
        
        Returns:
            Dict of results
        """
        self.start_time = datetime.now()
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
            print(f"{Style.HEADER}{Style.BOLD}  Linux Memory Analyzer v{__version__}{Style.RESET}")
            print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
            print(f"\n{Style.INFO}Image:{Style.RESET} {self.image_path}")
            print(f"{Style.INFO}Output:{Style.RESET} {self.output_dir}")
            
            size_mb = os.path.getsize(self.image_path) / (1024 * 1024)
            print(f"{Style.INFO}Image Size:{Style.RESET} {size_mb:.1f} MB")
        
        # Build plugin list
        plugins_to_run = dict(VOLATILITY_PLUGINS)
        if include_optional:
            plugins_to_run.update(OPTIONAL_PLUGINS)
        
        # Run all plugins
        results = self.vol_runner.run_all_plugins(plugins_to_run, verbose)
        
        self.end_time = datetime.now()
        
        # Generate summary
        self._generate_summary(verbose)
        
        return results
    
    def _generate_summary(self, verbose: bool = True):
        """Generate analysis summary report."""
        summary_path = os.path.join(self.output_dir, "analysis_summary.txt")
        
        duration = (self.end_time - self.start_time).total_seconds()
        successful = len(self.vol_runner.results)
        failed = len(self.vol_runner.errors)
        
        with open(summary_path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("Linux Memory Analysis Summary\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Analysis Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration:.1f} seconds\n")
            f.write(f"Output Directory: {self.output_dir}\n\n")
            
            f.write("-" * 40 + "\n")
            f.write("Plugin Results\n")
            f.write("-" * 40 + "\n\n")
            
            f.write(f"Successful: {successful}\n")
            f.write(f"Failed: {failed}\n\n")
            
            if self.vol_runner.results:
                f.write("Successful Plugins:\n")
                for plugin, info in self.vol_runner.results.items():
                    f.write(f"  - {plugin}: {info['line_count']} rows\n")
                f.write("\n")
            
            if self.vol_runner.errors:
                f.write("Failed Plugins:\n")
                for plugin, error in self.vol_runner.errors.items():
                    f.write(f"  - {plugin}: {error[:100]}\n")
                f.write("\n")
            
            f.write("-" * 40 + "\n")
            f.write("Output Files\n")
            f.write("-" * 40 + "\n\n")
            
            for filename in sorted(os.listdir(self.output_dir)):
                if filename.endswith('.csv'):
                    filepath = os.path.join(self.output_dir, filename)
                    size = os.path.getsize(filepath)
                    f.write(f"  {filename} ({size:,} bytes)\n")
        
        if verbose:
            print(f"\n{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
            print(f"{Style.HEADER}{Style.BOLD}  Analysis Complete{Style.RESET}")
            print(f"{Style.HEADER}{Style.BOLD}{'='*60}{Style.RESET}")
            print(f"\n{Style.INFO}Duration:{Style.RESET} {duration:.1f} seconds")
            print(f"{Style.INFO}Successful:{Style.RESET} {successful} plugins")
            if failed > 0:
                print(f"{Style.WARNING}Failed:{Style.RESET} {failed} plugins")
            print(f"\n{Style.SUCCESS}Output Directory:{Style.RESET} {self.output_dir}")
            print(f"{Style.SUCCESS}Summary:{Style.RESET} {summary_path}")


# ============================================================================
# Standalone Functions
# ============================================================================

def quick_triage(image_path: str, vol_path: str = None, verbose: bool = True) -> Dict:
    """
    Run quick triage analysis (essential plugins only).
    
    Args:
        image_path: Path to memory image
        vol_path: Optional Volatility path
        verbose: Print progress
    
    Returns:
        Dict of results
    """
    quick_plugins = {
        "Quick Triage": [
            ("linux.info", "info.csv", "System information"),
            ("linux.pslist", "pslist.csv", "Process list"),
            ("linux.netstat", "netstat.csv", "Network connections"),
            ("linux.bash", "bash.csv", "Bash history"),
            ("linux.malfind", "malfind.csv", "Malicious memory"),
        ]
    }
    
    image_name = os.path.splitext(os.path.basename(image_path))[0]
    output_dir = f"{image_name}_quick_triage"
    os.makedirs(output_dir, exist_ok=True)
    
    runner = VolatilityRunner(image_path, output_dir, vol_path)
    
    ok, msg = runner.check_volatility()
    if not ok:
        print(f"{Style.ERROR}Error: {msg}{Style.RESET}")
        return {}
    
    return runner.run_all_plugins(quick_plugins, verbose)


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    Style.enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="Linux Memory Analyzer - Volatility 3 automation for memory forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Version: {__version__}

This script automates Volatility 3 analysis of Linux memory dumps and outputs
results in CSV format for easy analysis.

Supported image formats:
  - AVML (.lime)
  - LiME (.lime, .mem)
  - Raw memory dumps (.raw, .mem)
  - ELF core dumps

Examples:
  # Full analysis
  python linux_memory_analyzer.py -i memory.lime
  
  # Quick triage (essential plugins only)
  python linux_memory_analyzer.py -i memory.lime --quick
  
  # Include optional plugins
  python linux_memory_analyzer.py -i memory.lime --all
  
  # Specify output directory
  python linux_memory_analyzer.py -i memory.lime -o ./analysis_results/
  
  # Specify Volatility path
  python linux_memory_analyzer.py -i memory.lime --vol-path /opt/volatility3/vol.py

Analysis Categories:
  - Kernel Identification: banners, linux.info
  - Process Analysis: pslist, psscan, pstree, psaux
  - Network Analysis: netstat, sockstat, unix sockets
  - Kernel Module Integrity: lsmod, check_modules, hidden_modules
  - Memory Injection: malfind, proc.Maps
  - Privileges: check_creds
  - Environment: envars
  - User Activity: who, bash history

Requirements:
  - Volatility 3 installed (pip install volatility3)
  - 'vol' or 'vol.py' accessible in PATH
        """
    )
    
    parser.add_argument(
        '-i', '--image',
        required=True,
        help='Path to Linux memory image (AVML, LiME, raw, etc.)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Output directory (default: [image_name]_memory_analysis/)'
    )
    
    parser.add_argument(
        '--vol-path',
        default=None,
        help='Path to Volatility 3 executable (default: auto-detect)'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick triage mode - run only essential plugins'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Include optional plugins (file analysis, rootkit detection, etc.)'
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
    
    verbose = not args.quiet
    
    # Quick triage mode
    if args.quick:
        results = quick_triage(args.image, args.vol_path, verbose)
        sys.exit(0 if results else 1)
    
    # Full analysis
    analyzer = LinuxMemoryAnalyzer(
        image_path=args.image,
        output_dir=args.output,
        vol_path=args.vol_path
    )
    
    # Validate
    valid, msg = analyzer.validate()
    if not valid:
        print(f"{Style.ERROR}Error: {msg}{Style.RESET}", file=sys.stderr)
        sys.exit(1)
    
    # Run analysis
    try:
        results = analyzer.analyze(include_optional=args.all, verbose=verbose)
        sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Analysis interrupted by user{Style.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
