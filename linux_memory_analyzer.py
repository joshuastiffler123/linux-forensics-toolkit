#!/usr/bin/env python3
"""
Linux Memory Analyzer - Volatility 3 Wrapper for Memory Forensics

This script automates Volatility 3 analysis of Linux memory dumps (AVML, LiME, etc.)
and outputs results in CSV format for easy analysis.

Key Features:
- Automatic symbol table downloading from ISF servers
- Kernel banner detection for symbol matching
- Comprehensive plugin coverage across multiple categories
- CSV output for easy analysis

Analysis Categories:
1. Kernel Identification - banners, vmcoreinfo
2. Process Analysis - pslist, psscan, pstree, psaux
3. Network Analysis - sockstat, sockscan
4. Kernel Module Integrity - lsmod, check_modules, hidden_modules
5. Memory Injection Detection - malfind, proc.Maps
6. Privilege Review - check_creds
7. Environment Inspection - envars
8. User Activity - bash history

Requirements:
- Python 3.6+
- Volatility 3 installed (local modified version preferred)
- Linux memory image (AVML .lime, LiME, raw, etc.)

Author: Security Tools
Version: 1.1.0
License: MIT
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.2.0"

# ISF Server URLs for automatic symbol downloading
ISF_SERVERS = [
    "https://isf-server.techanarchy.net",
    "https://volatility3.org/isf",
]

# Schema fix pattern - adds btf and symdb support
SCHEMA_OLD_PATTERN = '"pattern": "^(dwarf|symtab|system-map)$"'
SCHEMA_NEW_PATTERN = '"pattern": "^(btf|symdb|dwarf|symtab|system-map)$"'


# ============================================================================
# Setup and Installation
# ============================================================================

def get_script_dir() -> str:
    """Get the directory containing this script."""
    return os.path.dirname(os.path.abspath(__file__))


def get_volatility_dir() -> str:
    """Get the expected volatility3 installation directory."""
    return os.path.join(get_script_dir(), 'volatility3')


def get_venv_vol_path() -> Optional[str]:
    """Get the path to vol executable in our venv."""
    vol_dir = get_volatility_dir()
    if sys.platform == 'win32':
        vol_path = os.path.join(vol_dir, 'venv', 'Scripts', 'vol.exe')
    else:
        vol_path = os.path.join(vol_dir, 'venv', 'bin', 'vol')
    
    if os.path.exists(vol_path):
        return vol_path
    return None


def check_volatility_installed() -> Tuple[bool, str]:
    """
    Check if Volatility 3 is properly installed.
    
    Returns:
        Tuple of (installed, message)
    """
    vol_path = get_venv_vol_path()
    if vol_path:
        return True, f"Volatility 3 found at: {vol_path}"
    
    # Check system PATH
    for name in ['vol', 'vol.exe', 'vol.py', 'volatility3']:
        if shutil.which(name):
            return True, f"Volatility 3 found in PATH: {shutil.which(name)}"
    
    return False, "Volatility 3 not found"


def setup_volatility(verbose: bool = True) -> Tuple[bool, str]:
    """
    Automatically download and setup Volatility 3 with the schema fix.
    
    Returns:
        Tuple of (success, message)
    """
    script_dir = get_script_dir()
    vol_dir = get_volatility_dir()
    
    if verbose:
        print(f"\n{'='*60}")
        print(f"  Volatility 3 Automatic Setup")
        print(f"{'='*60}\n")
    
    # Step 1: Check for git
    if verbose:
        print("[1/5] Checking prerequisites...", end=" ", flush=True)
    
    git_available = shutil.which('git') is not None
    
    if not git_available:
        if verbose:
            print("FAILED")
            print("\n  Git is not installed. Please install git first:")
            print("  - Windows: https://git-scm.com/download/win")
            print("  - Linux: sudo apt install git")
            print("  - macOS: brew install git")
        return False, "Git not found"
    
    if verbose:
        print("OK")
    
    # Step 2: Clone volatility3
    if verbose:
        print("[2/5] Downloading Volatility 3...", end=" ", flush=True)
    
    if os.path.exists(vol_dir):
        if verbose:
            print("EXISTS (skipping clone)")
    else:
        try:
            result = subprocess.run(
                ['git', 'clone', 'https://github.com/volatilityfoundation/volatility3.git', vol_dir],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=script_dir
            )
            if result.returncode != 0:
                if verbose:
                    print("FAILED")
                    print(f"  Error: {result.stderr[:200]}")
                return False, f"Git clone failed: {result.stderr[:100]}"
            if verbose:
                print("OK")
        except subprocess.TimeoutExpired:
            if verbose:
                print("TIMEOUT")
            return False, "Git clone timed out"
        except Exception as e:
            if verbose:
                print(f"ERROR: {e}")
            return False, str(e)
    
    # Step 3: Create virtual environment
    if verbose:
        print("[3/5] Creating virtual environment...", end=" ", flush=True)
    
    venv_dir = os.path.join(vol_dir, 'venv')
    if os.path.exists(venv_dir):
        if verbose:
            print("EXISTS (skipping)")
    else:
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'venv', 'venv'],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=vol_dir
            )
            if result.returncode != 0:
                if verbose:
                    print("FAILED")
                return False, f"venv creation failed: {result.stderr[:100]}"
            if verbose:
                print("OK")
        except Exception as e:
            if verbose:
                print(f"ERROR: {e}")
            return False, str(e)
    
    # Step 4: Install volatility3 in dev mode
    if verbose:
        print("[4/5] Installing Volatility 3 (this may take a few minutes)...", end=" ", flush=True)
    
    if sys.platform == 'win32':
        pip_path = os.path.join(venv_dir, 'Scripts', 'pip.exe')
    else:
        pip_path = os.path.join(venv_dir, 'bin', 'pip')
    
    try:
        result = subprocess.run(
            [pip_path, 'install', '-e', '.[dev]'],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=vol_dir
        )
        if result.returncode != 0:
            if verbose:
                print("FAILED")
                print(f"  Error: {result.stderr[:300]}")
            return False, f"pip install failed: {result.stderr[:100]}"
        if verbose:
            print("OK")
    except subprocess.TimeoutExpired:
        if verbose:
            print("TIMEOUT")
        return False, "pip install timed out"
    except Exception as e:
        if verbose:
            print(f"ERROR: {e}")
        return False, str(e)
    
    # Step 5: Apply schema fix for btf/symdb support
    if verbose:
        print("[5/5] Applying schema fix for extended symbol support...", end=" ", flush=True)
    
    schema_dir = os.path.join(vol_dir, 'volatility3', 'schemas')
    schema_fixed = False
    
    try:
        for filename in os.listdir(schema_dir):
            if filename.startswith('schema-') and filename.endswith('.json'):
                schema_path = os.path.join(schema_dir, filename)
                with open(schema_path, 'r') as f:
                    content = f.read()
                
                if SCHEMA_OLD_PATTERN in content:
                    content = content.replace(SCHEMA_OLD_PATTERN, SCHEMA_NEW_PATTERN)
                    with open(schema_path, 'w') as f:
                        f.write(content)
                    schema_fixed = True
                elif SCHEMA_NEW_PATTERN in content:
                    schema_fixed = True  # Already fixed
        
        if verbose:
            if schema_fixed:
                print("OK")
            else:
                print("SKIPPED (pattern not found)")
    except Exception as e:
        if verbose:
            print(f"WARNING: {e}")
    
    # Verify installation
    vol_path = get_venv_vol_path()
    if vol_path and os.path.exists(vol_path):
        if verbose:
            print(f"\n{'='*60}")
            print(f"  Setup Complete!")
            print(f"{'='*60}")
            print(f"\nVolatility 3 installed at: {vol_path}")
            print(f"\nYou can now run:")
            print(f"  python {os.path.basename(__file__)} -i <memory_image.lime>")
        return True, vol_path
    else:
        return False, "Installation completed but vol executable not found"


def print_setup_instructions():
    """Print manual setup instructions when auto-setup is not available."""
    print(f"\n{'='*60}")
    print(f"  Volatility 3 Setup Required")
    print(f"{'='*60}")
    print(f"""
Volatility 3 is not installed. You have two options:

OPTION 1: Automatic Setup (Recommended)
  Run this script with --setup flag:
  
    python {os.path.basename(__file__)} --setup
  
  This will automatically:
  - Download Volatility 3 from GitHub
  - Create a Python virtual environment
  - Install all dependencies
  - Apply the schema fix for extended symbol support

OPTION 2: Manual Setup
  1. Clone Volatility 3:
     git clone https://github.com/volatilityfoundation/volatility3.git
  
  2. Create and activate a virtual environment:
     cd volatility3
     python -m venv venv
     
     # Windows:
     .\\venv\\Scripts\\activate
     
     # Linux/Mac:
     source venv/bin/activate
  
  3. Install in development mode:
     pip install -e ".[dev]"
  
  4. (Optional) Apply schema fix for btf/symdb support:
     Edit volatility3/schemas/schema-6.2.0.json
     Find:  "pattern": "^(dwarf|symtab|system-map)$"
     Replace with: "pattern": "^(btf|symdb|dwarf|symtab|system-map)$"

Prerequisites:
  - Python 3.8 or higher
  - Git (for automatic setup)
  - Internet connection
""")


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
# Note: Volatility 3 uses full plugin paths like linux.pslist.PsList
VOLATILITY_PLUGINS = {
    "Kernel Identification": [
        ("banners.Banners", "banners.csv", "Identifies kernel version from memory"),
        ("linux.vmcoreinfo.VMCoreInfo", "vmcoreinfo.csv", "VM core information from kernel"),
    ],
    "Process Analysis": [
        ("linux.pslist.PsList", "pslist.csv", "List running processes"),
        ("linux.psscan.PsScan", "psscan.csv", "Scan for process structures"),
        ("linux.pstree.PsTree", "pstree.csv", "Process tree hierarchy"),
        ("linux.psaux.PsAux", "psaux.csv", "Process list with arguments (ps aux style)"),
    ],
    "Network Analysis": [
        ("linux.sockstat.Sockstat", "sockstat.csv", "Socket statistics"),
        ("linux.sockscan.Sockscan", "sockscan.csv", "Scan for socket structures"),
    ],
    "Kernel Module Integrity": [
        ("linux.lsmod.Lsmod", "lsmod.csv", "List loaded kernel modules"),
        ("linux.malware.check_modules.Check_modules", "check_modules.csv", "Check for module hiding"),
        ("linux.malware.hidden_modules.Hidden_modules", "hidden_modules.csv", "Detect hidden kernel modules"),
    ],
    "Memory Injection Detection": [
        ("linux.malware.malfind.Malfind", "malfind.csv", "Find injected/suspicious memory regions"),
        ("linux.proc.Maps", "proc_maps.csv", "Process memory mappings"),
    ],
    "Privilege Review": [
        ("linux.malware.check_creds.Check_creds", "check_creds.csv", "Check for credential anomalies"),
    ],
    "Environment Inspection": [
        ("linux.envars.Envars", "envars.csv", "Process environment variables"),
    ],
    "User Activity": [
        ("linux.bash.Bash", "bash_history.csv", "Bash command history from memory"),
    ],
}

# Additional plugins that can be optionally enabled
OPTIONAL_PLUGINS = {
    "File Analysis": [
        ("linux.lsof.Lsof", "lsof.csv", "List open files"),
        ("linux.pagecache.Files", "pagecache_files.csv", "List files from page cache"),
    ],
    "Rootkit Detection": [
        ("linux.malware.check_syscall.Check_syscall", "check_syscall.csv", "Check syscall table for hooks"),
        ("linux.malware.check_idt.Check_idt", "check_idt.csv", "Check IDT for hooks"),
        ("linux.malware.tty_check.Tty_Check", "tty_check.csv", "Check TTY for hooks"),
        ("linux.malware.netfilter.Netfilter", "netfilter.csv", "Check netfilter hooks"),
    ],
    "Advanced Analysis": [
        ("linux.kmsg.Kmsg", "kmsg.csv", "Kernel message buffer"),
        ("linux.mountinfo.MountInfo", "mountinfo.csv", "Mount information"),
        ("linux.library_list.LibraryList", "library_list.csv", "Loaded libraries per process"),
        ("linux.elfs.Elfs", "elfs.csv", "Memory mapped ELF files"),
        ("linux.capabilities.Capabilities", "capabilities.csv", "Process capabilities"),
    ],
}


# ============================================================================
# Volatility Runner
# ============================================================================

class VolatilityRunner:
    """Handles running Volatility 3 plugins with automatic symbol management."""
    
    def __init__(self, image_path: str, output_dir: str, vol_path: str = None,
                 symbol_dirs: List[str] = None, isf_url: str = None, offline: bool = False):
        """
        Initialize the Volatility runner.
        
        Args:
            image_path: Path to the memory image file
            output_dir: Directory for output files
            vol_path: Optional path to volatility executable
            symbol_dirs: Optional list of symbol directories
            isf_url: Optional ISF server URL for symbol downloads
            offline: Run in offline mode (don't try to download symbols)
        """
        self.image_path = os.path.abspath(image_path)
        self.output_dir = os.path.abspath(output_dir)
        self.vol_path = vol_path or self._find_volatility()
        self.symbol_dirs = symbol_dirs or []
        self.isf_url = isf_url
        self.offline = offline
        self.results = {}
        self.errors = {}
        self.kernel_banner = None
        self.symbols_found = False
    
    def _find_volatility(self) -> str:
        """Find Volatility 3 executable, preferring the local modified installation."""
        # First, check for our local modified volatility3 installation
        # This version has the schema fix for btf/symdb symbol formats
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_vol_paths = [
            # Windows paths - local venv with schema fix
            os.path.join(script_dir, 'volatility3', 'venv', 'Scripts', 'vol.exe'),
            os.path.join(script_dir, 'volatility3', 'venv', 'Scripts', 'vol'),
            # Linux/Mac paths - local venv with schema fix
            os.path.join(script_dir, 'volatility3', 'venv', 'bin', 'vol'),
            os.path.join(script_dir, 'volatility3', 'venv', 'bin', 'vol.py'),
        ]
        
        for path in local_vol_paths:
            if os.path.exists(path):
                return path
        
        # Common names for volatility in PATH
        vol_names = ['vol', 'vol.exe', 'vol.py', 'vol3', 'volatility', 'volatility3']
        
        for name in vol_names:
            found = shutil.which(name)
            if found:
                return found
        
        # Check if vol.py exists in common locations
        common_paths = [
            '/usr/local/bin/vol.py',
            '/usr/bin/vol.py',
            os.path.expanduser('~/.local/bin/vol.py'),
            os.path.expanduser('~/volatility3/vol.py'),
            # Windows common paths
            os.path.expanduser('~\\volatility3\\vol.py'),
            'C:\\volatility3\\vol.py',
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
    
    def _build_base_cmd(self, offline: bool = False) -> List[str]:
        """Build base command with common options for ISF/symbol support."""
        cmd = [self.vol_path, '-f', self.image_path]
        
        # Add symbol directories if specified
        for sym_dir in self.symbol_dirs:
            if os.path.isdir(sym_dir):
                cmd.extend(['-s', sym_dir])
        
        # Handle offline mode vs ISF server
        if offline or self.offline:
            cmd.append('--offline')
        elif self.isf_url:
            cmd.extend(['-u', self.isf_url])
        # Don't add default ISF URLs - let Volatility use its defaults
        # This avoids connection timeouts when servers are unreachable
        
        return cmd
    
    def detect_kernel_banner(self, verbose: bool = True) -> Optional[str]:
        """
        Detect kernel banner from memory image.
        This works without symbol tables and helps identify needed symbols.
        
        Returns:
            Kernel banner string if found, None otherwise
        """
        if verbose:
            print(f"\n{Style.INFO}Detecting kernel banner...{Style.RESET}", end=" ", flush=True)
        
        try:
            # Use offline mode for banner detection - it doesn't need symbols
            cmd = self._build_base_cmd(offline=True) + ['-r', 'csv', 'banners.Banners']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # Parse CSV output to get banner
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:  # Has header + data
                    # Banner is typically in the second column
                    for line in lines[1:]:
                        if 'Linux version' in line:
                            # Extract the banner text
                            match = re.search(r'Linux version [^\n"]+', line)
                            if match:
                                self.kernel_banner = match.group(0)
                                if verbose:
                                    print(f"{Style.SUCCESS}Found{Style.RESET}")
                                    print(f"  {Style.DIM}{self.kernel_banner[:80]}...{Style.RESET}")
                                return self.kernel_banner
            
            if verbose:
                print(f"{Style.WARNING}Not found{Style.RESET}")
            return None
            
        except subprocess.TimeoutExpired:
            if verbose:
                print(f"{Style.WARNING}Timeout{Style.RESET}")
            return None
        except Exception as e:
            if verbose:
                print(f"{Style.WARNING}Error: {e}{Style.RESET}")
            return None
    
    def check_symbols(self, verbose: bool = True) -> Tuple[bool, str]:
        """
        Check if symbols are available for this image by running a simple plugin.
        
        Returns:
            Tuple of (symbols_available, message)
        """
        if verbose:
            print(f"{Style.INFO}Checking symbol table availability...{Style.RESET}", end=" ", flush=True)
        
        try:
            # Try linux.vmcoreinfo which needs symbols
            cmd = self._build_base_cmd() + ['linux.vmcoreinfo.VMCoreInfo']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            stderr = result.stderr.lower()
            
            # Check for symbol-related errors
            if 'symbol_table_name' in stderr or 'unsatisfied requirement' in stderr:
                self.symbols_found = False
                if verbose:
                    print(f"{Style.ERROR}NOT FOUND{Style.RESET}")
                return False, "Symbol tables not found for this kernel"
            
            if result.returncode == 0:
                self.symbols_found = True
                if verbose:
                    print(f"{Style.SUCCESS}Available{Style.RESET}")
                return True, "Symbols available"
            
            # Other error
            self.symbols_found = False
            if verbose:
                print(f"{Style.WARNING}Unknown{Style.RESET}")
            return False, result.stderr[:200]
            
        except subprocess.TimeoutExpired:
            if verbose:
                print(f"{Style.WARNING}Timeout{Style.RESET}")
            return False, "Timeout checking symbols"
        except Exception as e:
            if verbose:
                print(f"{Style.WARNING}Error{Style.RESET}")
            return False, str(e)
    
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
            # Build command with ISF/symbol support
            cmd = self._build_base_cmd() + ['-r', 'csv', plugin]
            
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
    """Main analyzer class for Linux memory forensics with automatic symbol handling."""
    
    def __init__(self, image_path: str, output_dir: str = None, vol_path: str = None,
                 symbol_dirs: List[str] = None, isf_url: str = None, offline: bool = False):
        """
        Initialize the memory analyzer.
        
        Args:
            image_path: Path to memory image
            output_dir: Output directory (default: creates based on image name)
            vol_path: Optional path to Volatility executable
            symbol_dirs: Optional list of directories containing symbol files
            isf_url: Optional ISF server URL for automatic symbol downloading
            offline: Run in offline mode (skip ISF server connections)
        """
        self.image_path = os.path.abspath(image_path)
        
        # Create output directory based on image name
        if output_dir is None:
            image_name = os.path.splitext(os.path.basename(image_path))[0]
            output_dir = f"{image_name}_memory_analysis"
        
        self.output_dir = os.path.abspath(output_dir)
        self.vol_runner = VolatilityRunner(
            image_path, self.output_dir, vol_path,
            symbol_dirs=symbol_dirs, isf_url=isf_url, offline=offline
        )
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
    
    def analyze(self, include_optional: bool = False, verbose: bool = True, 
                skip_symbol_check: bool = False) -> Dict:
        """
        Run full memory analysis.
        
        Args:
            include_optional: Whether to include optional plugins
            verbose: Whether to print progress
            skip_symbol_check: Skip initial symbol availability check
        
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
        
        # Step 1: Detect kernel banner (works without symbols)
        banner = self.vol_runner.detect_kernel_banner(verbose)
        
        # Step 2: Check if symbols are available (unless skipped)
        if not skip_symbol_check:
            symbols_ok, symbols_msg = self.vol_runner.check_symbols(verbose)
            
            if not symbols_ok and verbose:
                self._print_symbol_guidance(banner)
        
        # Build plugin list
        plugins_to_run = dict(VOLATILITY_PLUGINS)
        if include_optional:
            plugins_to_run.update(OPTIONAL_PLUGINS)
        
        # Run all plugins
        if verbose:
            print(f"\n{Style.INFO}Running plugins (Volatility will attempt to download symbols automatically)...{Style.RESET}")
        
        results = self.vol_runner.run_all_plugins(plugins_to_run, verbose)
        
        self.end_time = datetime.now()
        
        # Generate summary
        self._generate_summary(verbose)
        
        return results
    
    def _print_symbol_guidance(self, banner: Optional[str] = None):
        """Print guidance for obtaining symbol tables."""
        print(f"\n{Style.WARNING}{'='*60}{Style.RESET}")
        print(f"{Style.WARNING}  Symbol Tables Not Found{Style.RESET}")
        print(f"{Style.WARNING}{'='*60}{Style.RESET}")
        
        if banner:
            print(f"\n{Style.INFO}Detected Kernel:{Style.RESET}")
            print(f"  {banner[:100]}")
        
        print(f"\n{Style.INFO}Volatility 3 will attempt to download symbols automatically.{Style.RESET}")
        print(f"{Style.INFO}If plugins fail, you may need to generate symbols manually:{Style.RESET}")
        
        print(f"\n{Style.BOLD}Option 1: Download pre-built symbols{Style.RESET}")
        print(f"  - Check: https://isf-server.techanarchy.net/")
        print(f"  - Place .json files in: volatility3/volatility3/symbols/linux/")
        
        print(f"\n{Style.BOLD}Option 2: Generate symbols with dwarf2json{Style.RESET}")
        print(f"  # On a system with matching kernel + debug symbols:")
        print(f"  sudo apt install linux-image-$(uname -r)-dbgsym")
        print(f"  dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > symbols.json")
        
        print(f"\n{Style.BOLD}Option 3: Use --isf-url to specify ISF server{Style.RESET}")
        print(f"  python linux_memory_analyzer.py -i image.lime --isf-url https://your-isf-server.com")
        
        print(f"\n{Style.WARNING}{'='*60}{Style.RESET}")
        print(f"{Style.INFO}Continuing with analysis (some plugins may fail)...{Style.RESET}")
    
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

def quick_triage(image_path: str, vol_path: str = None, verbose: bool = True,
                 symbol_dirs: List[str] = None, isf_url: str = None) -> Dict:
    """
    Run quick triage analysis (essential plugins only).
    
    Args:
        image_path: Path to memory image
        vol_path: Optional Volatility path
        verbose: Print progress
        symbol_dirs: Optional list of symbol directories
        isf_url: Optional ISF server URL
    
    Returns:
        Dict of results
    """
    quick_plugins = {
        "Quick Triage": [
            ("banners.Banners", "banners.csv", "Kernel identification"),
            ("linux.pslist.PsList", "pslist.csv", "Process list"),
            ("linux.sockstat.Sockstat", "sockstat.csv", "Network sockets"),
            ("linux.bash.Bash", "bash.csv", "Bash history"),
            ("linux.malware.malfind.Malfind", "malfind.csv", "Malicious memory"),
        ]
    }
    
    image_name = os.path.splitext(os.path.basename(image_path))[0]
    output_dir = f"{image_name}_quick_triage"
    os.makedirs(output_dir, exist_ok=True)
    
    runner = VolatilityRunner(image_path, output_dir, vol_path,
                              symbol_dirs=symbol_dirs, isf_url=isf_url)
    
    ok, msg = runner.check_volatility()
    if not ok:
        print(f"{Style.ERROR}Error: {msg}{Style.RESET}")
        return {}
    
    # First detect kernel banner
    if verbose:
        print(f"\n{Style.HEADER}{Style.BOLD}Quick Triage Analysis{Style.RESET}")
    runner.detect_kernel_banner(verbose)
    
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
FIRST TIME SETUP:
  If Volatility 3 is not installed, run:
    python {os.path.basename(__file__)} --setup
  
  This automatically downloads and configures Volatility 3.

Version: {__version__}

This script automates Volatility 3 analysis of Linux memory dumps and outputs
results in CSV format for easy analysis. It automatically attempts to download
symbol tables from ISF servers.

Supported image formats:
  - AVML (.lime)
  - LiME (.lime, .mem)
  - Raw memory dumps (.raw, .mem)
  - ELF core dumps

Examples:
  # Full analysis (automatic symbol downloading)
  python linux_memory_analyzer.py -i memory.lime
  
  # Quick triage (essential plugins only)
  python linux_memory_analyzer.py -i memory.lime --quick
  
  # Include optional plugins
  python linux_memory_analyzer.py -i memory.lime --all
  
  # Specify output directory
  python linux_memory_analyzer.py -i memory.lime -o ./analysis_results/
  
  # Specify symbol directory
  python linux_memory_analyzer.py -i memory.lime -s /path/to/symbols/
  
  # Use specific ISF server for symbol downloads
  python linux_memory_analyzer.py -i memory.lime --isf-url https://isf-server.example.com

Analysis Categories:
  - Kernel Identification: banners, vmcoreinfo
  - Process Analysis: pslist, psscan, pstree, psaux
  - Network Analysis: sockstat, sockscan
  - Kernel Module Integrity: lsmod, check_modules, hidden_modules
  - Memory Injection: malfind, proc.Maps
  - Privileges: check_creds
  - Environment: envars
  - User Activity: bash history

Symbol Tables:
  The script automatically attempts to download symbols from ISF servers.
  If symbols are not available, you can:
  1. Download pre-built symbols from https://isf-server.techanarchy.net/
  2. Generate symbols using dwarf2json from debug kernel packages
  3. Specify a custom ISF server with --isf-url
        """
    )
    
    parser.add_argument(
        '-i', '--image',
        required=False,  # Not required if --setup is used
        help='Path to Linux memory image (AVML, LiME, raw, etc.)'
    )
    
    parser.add_argument(
        '--setup',
        action='store_true',
        help='Download and install Volatility 3 automatically (run this first)'
    )
    
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check if Volatility 3 is installed and working'
    )
    
    parser.add_argument(
        '--banner',
        action='store_true',
        help='Only detect and display the kernel banner (useful for identifying needed symbols)'
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
        '-s', '--symbols',
        action='append',
        default=[],
        help='Path to symbol directory (can be specified multiple times)'
    )
    
    parser.add_argument(
        '--isf-url',
        default=None,
        help='ISF server URL for automatic symbol downloading'
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
        '--skip-symbol-check',
        action='store_true',
        help='Skip initial symbol availability check'
    )
    
    parser.add_argument(
        '--offline',
        action='store_true',
        help='Run in offline mode (do not attempt to download symbols from ISF servers)'
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
    
    # Handle --setup flag
    if args.setup:
        success, msg = setup_volatility(verbose=True)
        sys.exit(0 if success else 1)
    
    # Handle --check flag
    if args.check:
        installed, msg = check_volatility_installed()
        if installed:
            print(f"{Style.SUCCESS}[OK] {msg}{Style.RESET}")
            # Try to get version
            vol_path = get_venv_vol_path() or shutil.which('vol') or shutil.which('vol.exe')
            if vol_path:
                try:
                    result = subprocess.run([vol_path, '--help'], capture_output=True, text=True, timeout=30)
                    if 'Framework' in result.stdout:
                        match = re.search(r'Framework (\d+\.\d+\.\d+)', result.stdout)
                        if match:
                            print(f"  Version: {match.group(1)}")
                except:
                    pass
            sys.exit(0)
        else:
            print(f"{Style.ERROR}[MISSING] {msg}{Style.RESET}")
            print_setup_instructions()
            sys.exit(1)
    
    # Check if image is provided for analysis
    if not args.image:
        # Check if volatility is installed
        installed, msg = check_volatility_installed()
        if not installed:
            print_setup_instructions()
            sys.exit(1)
        else:
            parser.print_help()
            print(f"\n{Style.ERROR}Error: -i/--image is required for analysis{Style.RESET}")
            sys.exit(1)
    
    # Handle --banner flag (quick kernel identification)
    if args.banner:
        vol_path = args.vol_path or get_venv_vol_path() or shutil.which('vol') or shutil.which('vol.exe')
        if not vol_path:
            print(f"{Style.ERROR}Error: Volatility 3 not found{Style.RESET}")
            sys.exit(1)
        
        print(f"\n{Style.HEADER}Detecting kernel banner from: {args.image}{Style.RESET}\n")
        
        try:
            cmd = [vol_path, '-f', args.image, '--offline', '-r', 'pretty', 'banners.Banners']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.stdout.strip():
                print(result.stdout)
                
                # Extract and highlight the kernel version
                match = re.search(r'Linux version (\S+)', result.stdout)
                if match:
                    print(f"\n{Style.SUCCESS}Kernel Version: {match.group(1)}{Style.RESET}")
                    print(f"\n{Style.INFO}To analyze this image, you need a symbol file for this kernel.{Style.RESET}")
                    print(f"{Style.INFO}Generate it on a system with the same kernel using:{Style.RESET}")
                    print(f"\n  # Install debug symbols")
                    print(f"  sudo apt install linux-image-{match.group(1)}-dbgsym")
                    print(f"\n  # Generate symbol file")
                    print(f"  dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-{match.group(1)} > symbols.json")
                    print(f"\n  # Then run analysis with:")
                    print(f"  python {os.path.basename(__file__)} -i {args.image} -s /path/to/symbols/")
            else:
                print(f"{Style.WARNING}No kernel banner found in image{Style.RESET}")
                if result.stderr:
                    print(f"{Style.DIM}{result.stderr[:500]}{Style.RESET}")
        except subprocess.TimeoutExpired:
            print(f"{Style.ERROR}Timeout detecting banner{Style.RESET}")
        except Exception as e:
            print(f"{Style.ERROR}Error: {e}{Style.RESET}")
        
        sys.exit(0)
    
    # Check if volatility is installed before proceeding
    installed, msg = check_volatility_installed()
    if not installed:
        print(f"{Style.ERROR}Error: {msg}{Style.RESET}")
        print_setup_instructions()
        sys.exit(1)
    
    # Quick triage mode
    if args.quick:
        results = quick_triage(args.image, args.vol_path, verbose)
        sys.exit(0 if results else 1)
    
    # Full analysis
    analyzer = LinuxMemoryAnalyzer(
        image_path=args.image,
        output_dir=args.output,
        vol_path=args.vol_path,
        symbol_dirs=args.symbols if args.symbols else None,
        isf_url=args.isf_url,
        offline=args.offline
    )
    
    # Validate
    valid, msg = analyzer.validate()
    if not valid:
        print(f"{Style.ERROR}Error: {msg}{Style.RESET}", file=sys.stderr)
        sys.exit(1)
    
    # Run analysis
    try:
        results = analyzer.analyze(
            include_optional=args.all, 
            verbose=verbose,
            skip_symbol_check=args.skip_symbol_check
        )
        sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Style.WARNING}Analysis interrupted by user{Style.RESET}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"{Style.ERROR}Error: {e}{Style.RESET}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
