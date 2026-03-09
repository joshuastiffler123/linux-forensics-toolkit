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

__version__ = "2.0.0"

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


# Ensure sibling modules are importable (direct execution & editable installs)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lft_style import Style


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

# Plugins that work WITHOUT kernel symbol tables
NO_SYMBOL_PLUGINS = {
    "Kernel Identification (no symbols required)": [
        ("banners.Banners", "banners.csv", "Identifies kernel version from memory"),
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

    def _extract_kernel_version(self) -> Optional[str]:
        """
        Extract the kernel version string from the detected banner.

        Example banner: "Linux version 5.15.0-91-generic (buildd@...) ..."
        Returns: "5.15.0-91-generic"
        """
        if not self.kernel_banner:
            return None
        match = re.search(r'Linux version (\S+)', self.kernel_banner)
        return match.group(1) if match else None

    def _test_symbols_with_cmd(self, base_cmd: List[str]) -> Tuple[bool, str]:
        """
        Test if symbols are available by running linux.pslist.PsList.

        This plugin requires full symbol tables and fails fast with a clear
        error when they are missing, making it a reliable probe.

        Returns:
            Tuple of (available, message)
        """
        try:
            cmd = base_cmd + ['linux.pslist.PsList']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )

            stderr_lower = result.stderr.lower()

            # Check for symbol-related errors
            if any(marker in stderr_lower for marker in [
                'symbol_table_name',
                'unsatisfied requirement',
                'unable to validate',
                'no suitable symbol table',
            ]):
                return False, "Symbol tables not found"

            if result.returncode == 0:
                return True, "Symbols available"

            # Non-symbol error — symbols may exist but plugin had another issue
            if 'symbol' not in stderr_lower and 'isf' not in stderr_lower:
                return True, "Plugin ran (non-symbol error)"

            return False, result.stderr[:200]

        except subprocess.TimeoutExpired:
            return False, "Timeout testing symbols"
        except Exception as e:
            return False, str(e)

    def resolve_symbols(self, verbose: bool = True) -> Tuple[bool, str]:
        """
        Attempt to resolve symbol tables using multiple strategies.

        Strategy order:
        1. Try with current settings (local symbol dirs + Volatility defaults)
        2. Try each known ISF server explicitly with -u flag
        3. Give up with actionable guidance

        Returns:
            Tuple of (symbols_resolved, message)
        """
        if verbose:
            print(f"\n{Style.INFO}Resolving symbol tables...{Style.RESET}")

        # Strategy 1: Try with current settings (local dirs + Volatility built-in ISF)
        if verbose:
            print(f"  {Style.DIM}Trying local symbols + Volatility defaults...{Style.RESET}",
                  end=" ", flush=True)

        resolved, msg = self._test_symbols_with_cmd(self._build_base_cmd())
        if resolved:
            if verbose:
                print(f"{Style.SUCCESS}OK{Style.RESET}")
            self.symbols_found = True
            return True, "Symbols resolved with default configuration"

        if verbose:
            print(f"{Style.WARNING}not found{Style.RESET}")

        # Strategy 2: Try each ISF server explicitly
        if not self.offline:
            for isf_url in ISF_SERVERS:
                if verbose:
                    print(f"  {Style.DIM}Trying ISF server: {isf_url}...{Style.RESET}",
                          end=" ", flush=True)

                cmd = [self.vol_path, '-f', self.image_path]
                for sym_dir in self.symbol_dirs:
                    if os.path.isdir(sym_dir):
                        cmd.extend(['-s', sym_dir])
                cmd.extend(['-u', isf_url])

                resolved, msg = self._test_symbols_with_cmd(cmd)
                if resolved:
                    if verbose:
                        print(f"{Style.SUCCESS}OK{Style.RESET}")
                    # Store working ISF URL for subsequent plugin runs
                    self.isf_url = isf_url
                    self.symbols_found = True
                    return True, f"Symbols resolved via ISF server: {isf_url}"

                if verbose:
                    print(f"{Style.WARNING}not found{Style.RESET}")

        # All strategies exhausted
        self.symbols_found = False
        return False, "Symbol tables could not be resolved"

    # Backward-compatible alias
    def check_symbols(self, verbose: bool = True) -> Tuple[bool, str]:
        """Check symbol availability. Delegates to resolve_symbols()."""
        return self.resolve_symbols(verbose)
    
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

        # Step 2: Resolve symbols using multiple strategies (unless skipped)
        symbols_ok = False
        if not skip_symbol_check:
            symbols_ok, symbols_msg = self.vol_runner.resolve_symbols(verbose)

            if not symbols_ok:
                self._print_symbol_guidance(banner)
        else:
            # When skipped, optimistically assume symbols might work
            symbols_ok = True

        # Step 3: Choose plugin set based on symbol availability
        if symbols_ok:
            plugins_to_run = dict(VOLATILITY_PLUGINS)
            if include_optional:
                plugins_to_run.update(OPTIONAL_PLUGINS)

            total = sum(len(p) for p in plugins_to_run.values())
            if verbose:
                print(f"\n{Style.INFO}Running {total} plugins...{Style.RESET}")
        else:
            # Symbols unavailable — only run plugins that don't need them
            plugins_to_run = dict(NO_SYMBOL_PLUGINS)

            full_count = sum(len(p) for p in VOLATILITY_PLUGINS.values())
            no_sym_count = sum(len(p) for p in NO_SYMBOL_PLUGINS.values())
            skipped = full_count - no_sym_count
            if verbose:
                print(f"\n{Style.WARNING}Skipping {skipped} symbol-dependent plugins.{Style.RESET}")
                print(f"{Style.INFO}Running {no_sym_count} plugin(s) that work without symbols...{Style.RESET}")

        # Run selected plugins
        results = self.vol_runner.run_all_plugins(plugins_to_run, verbose)

        self.end_time = datetime.now()

        # Generate summary
        self._generate_summary(verbose, symbols_available=symbols_ok)

        return results
    
    def _print_symbol_guidance(self, banner: Optional[str] = None):
        """Print actionable guidance for obtaining symbol tables."""
        kernel_version = self.vol_runner._extract_kernel_version()

        print(f"\n{Style.WARNING}{'='*60}{Style.RESET}")
        print(f"{Style.WARNING}  Symbol Tables Not Found{Style.RESET}")
        print(f"{Style.WARNING}{'='*60}{Style.RESET}")

        if kernel_version:
            print(f"\n{Style.INFO}Detected Kernel:{Style.RESET} {kernel_version}")
        elif banner:
            print(f"\n{Style.INFO}Detected Banner:{Style.RESET}")
            print(f"  {banner[:100]}")

        print(f"\n{Style.INFO}Volatility needs kernel-specific symbol tables to analyze")
        print(f"memory structures. All automatic download sources were tried.{Style.RESET}")

        # Option 1: ISF web search
        print(f"\n{Style.BOLD}Option 1: Search ISF server manually{Style.RESET}")
        print(f"  Browse: https://isf-server.techanarchy.net/")
        if kernel_version:
            print(f"  Search for: {kernel_version}")
        print(f"  Download the .json.xz file and place it in:")
        print(f"  volatility3/volatility3/symbols/linux/")

        # Option 2: Generate symbols
        print(f"\n{Style.BOLD}Option 2: Generate symbols from a matching system{Style.RESET}")
        if kernel_version:
            print(f"  On a system running kernel {kernel_version}:")
            print(f"    sudo apt install linux-image-{kernel_version}-dbgsym  # Ubuntu/Debian")
            print(f"    dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-{kernel_version} > symbols.json")
        else:
            print(f"  On a system with the same kernel version:")
            print(f"    sudo apt install linux-image-$(uname -r)-dbgsym")
            print(f"    dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > symbols.json")

        # Option 3: Re-run with symbols
        print(f"\n{Style.BOLD}Option 3: Re-run with local symbol file{Style.RESET}")
        print(f"  python linux_memory_analyzer.py -i <image> -s /path/to/symbols/")

        print(f"\n{Style.WARNING}{'='*60}{Style.RESET}")
    
    def _generate_summary(self, verbose: bool = True, symbols_available: bool = True):
        """Generate analysis summary report with error categorization."""
        summary_path = os.path.join(self.output_dir, "analysis_summary.txt")

        duration = (self.end_time - self.start_time).total_seconds()
        successful = len(self.vol_runner.results)
        failed = len(self.vol_runner.errors)
        kernel_version = self.vol_runner._extract_kernel_version()

        # Categorize errors
        symbol_errors = {}
        plugin_errors = {}
        for plugin, error in self.vol_runner.errors.items():
            error_lower = error.lower()
            if any(marker in error_lower for marker in [
                'symbol_table_name', 'unsatisfied requirement',
                'unable to validate', 'no suitable symbol table',
            ]):
                symbol_errors[plugin] = error
            else:
                plugin_errors[plugin] = error

        with open(summary_path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("Linux Memory Analysis Summary\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"Image: {self.image_path}\n")
            f.write(f"Analysis Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration:.1f} seconds\n")
            f.write(f"Output Directory: {self.output_dir}\n")
            if kernel_version:
                f.write(f"Kernel Version: {kernel_version}\n")
            f.write(f"Symbols Available: {'Yes' if symbols_available else 'No'}\n\n")

            f.write("-" * 40 + "\n")
            f.write("Plugin Results\n")
            f.write("-" * 40 + "\n\n")

            f.write(f"Successful: {successful}\n")
            f.write(f"Failed: {failed}\n")
            if symbol_errors:
                f.write(f"  - Symbol-related: {len(symbol_errors)}\n")
            if plugin_errors:
                f.write(f"  - Plugin-specific: {len(plugin_errors)}\n")

            if not symbols_available:
                skipped = sum(len(p) for p in VOLATILITY_PLUGINS.values()) - \
                          sum(len(p) for p in NO_SYMBOL_PLUGINS.values())
                f.write(f"Skipped (no symbols): {skipped} plugins\n")
            f.write("\n")

            if self.vol_runner.results:
                f.write("Successful Plugins:\n")
                for plugin, info in self.vol_runner.results.items():
                    f.write(f"  + {plugin}: {info['line_count']} rows\n")
                f.write("\n")

            if symbol_errors:
                f.write("Symbol-Related Failures (fix symbols to resolve all):\n")
                for plugin in symbol_errors:
                    f.write(f"  - {plugin}\n")
                if kernel_version:
                    f.write(f"\n  Root cause: No symbol table for kernel {kernel_version}\n")
                    f.write(f"  Fix: Download or generate symbols for this kernel version\n")
                f.write("\n")

            if plugin_errors:
                f.write("Plugin-Specific Failures:\n")
                for plugin, error in plugin_errors.items():
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
            if kernel_version:
                print(f"{Style.INFO}Kernel:{Style.RESET} {kernel_version}")
            print(f"{Style.INFO}Successful:{Style.RESET} {successful} plugins")

            if not symbols_available:
                skipped = sum(len(p) for p in VOLATILITY_PLUGINS.values()) - \
                          sum(len(p) for p in NO_SYMBOL_PLUGINS.values())
                print(f"{Style.WARNING}Skipped:{Style.RESET} {skipped} plugins (no symbol tables)")

            if symbol_errors:
                print(f"{Style.ERROR}Symbol failures:{Style.RESET} {len(symbol_errors)} plugins (same root cause)")
            if plugin_errors:
                print(f"{Style.WARNING}Plugin failures:{Style.RESET} {len(plugin_errors)} plugins")
                for plugin, error in plugin_errors.items():
                    print(f"  {Style.DIM}- {plugin}: {error[:80]}{Style.RESET}")

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

    quick_no_symbol_plugins = {
        "Quick Triage (no symbols)": [
            ("banners.Banners", "banners.csv", "Kernel identification"),
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

    if verbose:
        print(f"\n{Style.HEADER}{Style.BOLD}Quick Triage Analysis{Style.RESET}")
    runner.detect_kernel_banner(verbose)

    # Resolve symbols before running plugins
    symbols_ok, _ = runner.resolve_symbols(verbose)

    if symbols_ok:
        return runner.run_all_plugins(quick_plugins, verbose)
    else:
        if verbose:
            kernel_version = runner._extract_kernel_version()
            print(f"\n{Style.WARNING}Symbols not available. Running banner-only triage.{Style.RESET}")
            if kernel_version:
                print(f"{Style.INFO}Kernel: {kernel_version}{Style.RESET}")
        return runner.run_all_plugins(quick_no_symbol_plugins, verbose)


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
