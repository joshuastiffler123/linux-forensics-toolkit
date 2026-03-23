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
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

__version__ = "2.1.0"

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
        logger.info("=" * 60)
        logger.info("  Volatility 3 Automatic Setup")
        logger.info("=" * 60)
    
    # Step 1: Check for git
    if verbose:
        logger.info("[1/5] Checking prerequisites...")

    git_available = shutil.which('git') is not None

    if not git_available:
        logger.error("FAILED")
        logger.error("Git is not installed. Please install git first:")
        logger.error("  - Windows: https://git-scm.com/download/win")
        logger.error("  - Linux: sudo apt install git")
        logger.error("  - macOS: brew install git")
        return False, "Git not found"

    if verbose:
        logger.info("OK")
    
    # Step 2: Clone volatility3
    if verbose:
        logger.info("[2/5] Downloading Volatility 3...")

    if os.path.exists(vol_dir):
        if verbose:
            logger.info("EXISTS (skipping clone)")
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
                logger.error("FAILED")
                logger.error("  Error: %s", result.stderr[:200])
                return False, f"Git clone failed: {result.stderr[:100]}"
            if verbose:
                logger.info("OK")
        except subprocess.TimeoutExpired:
            logger.error("TIMEOUT")
            return False, "Git clone timed out"
        except Exception as e:
            logger.error("ERROR: %s", e)
            return False, str(e)
    
    # Step 3: Create virtual environment
    if verbose:
        logger.info("[3/5] Creating virtual environment...")

    venv_dir = os.path.join(vol_dir, 'venv')
    if os.path.exists(venv_dir):
        if verbose:
            logger.info("EXISTS (skipping)")
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
                logger.error("FAILED")
                return False, f"venv creation failed: {result.stderr[:100]}"
            if verbose:
                logger.info("OK")
        except Exception as e:
            logger.error("ERROR: %s", e)
            return False, str(e)
    
    # Step 4: Install volatility3 in dev mode
    if verbose:
        logger.info("[4/5] Installing Volatility 3 (this may take a few minutes)...")

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
            logger.error("FAILED")
            logger.error("  Error: %s", result.stderr[:300])
            return False, f"pip install failed: {result.stderr[:100]}"
        if verbose:
            logger.info("OK")
    except subprocess.TimeoutExpired:
        logger.error("TIMEOUT")
        return False, "pip install timed out"
    except Exception as e:
        logger.error("ERROR: %s", e)
        return False, str(e)
    
    # Step 5: Apply schema fix for btf/symdb support
    if verbose:
        logger.info("[5/5] Applying schema fix for extended symbol support...")

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
                logger.info("OK")
            else:
                logger.info("SKIPPED (pattern not found)")
    except Exception as e:
        logger.warning("WARNING: %s", e)

    # Verify installation
    vol_path = get_venv_vol_path()
    if vol_path and os.path.exists(vol_path):
        if verbose:
            logger.info("=" * 60)
            logger.info("  Setup Complete!")
            logger.info("=" * 60)
            logger.info("Volatility 3 installed at: %s", vol_path)
            logger.info("You can now run:")
            logger.info("  python %s -i <memory_image.lime>", os.path.basename(__file__))
        return True, vol_path
    else:
        return False, "Installation completed but vol executable not found"


def print_setup_instructions():
    """Print manual setup instructions when auto-setup is not available."""
    logger.info("=" * 60)
    logger.info("  Volatility 3 Setup Required")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Volatility 3 is not installed. You have two options:")
    logger.info("")
    logger.info("OPTION 1: Automatic Setup (Recommended)")
    logger.info("  Run this script with --setup flag:")
    logger.info("")
    logger.info("    python %s --setup", os.path.basename(__file__))
    logger.info("")
    logger.info("  This will automatically:")
    logger.info("  - Download Volatility 3 from GitHub")
    logger.info("  - Create a Python virtual environment")
    logger.info("  - Install all dependencies")
    logger.info("  - Apply the schema fix for extended symbol support")
    logger.info("")
    logger.info("OPTION 2: Manual Setup")
    logger.info("  1. Clone Volatility 3:")
    logger.info("     git clone https://github.com/volatilityfoundation/volatility3.git")
    logger.info("")
    logger.info("  2. Create and activate a virtual environment:")
    logger.info("     cd volatility3")
    logger.info("     python -m venv venv")
    logger.info("")
    logger.info("     # Windows:")
    logger.info("     .\\venv\\Scripts\\activate")
    logger.info("")
    logger.info("     # Linux/Mac:")
    logger.info("     source venv/bin/activate")
    logger.info("")
    logger.info("  3. Install in development mode:")
    logger.info('     pip install -e ".[dev]"')
    logger.info("")
    logger.info("  4. (Optional) Apply schema fix for btf/symdb support:")
    logger.info("     Edit volatility3/schemas/schema-6.2.0.json")
    logger.info('     Find:  "pattern": "^(dwarf|symtab|system-map)$"')
    logger.info('     Replace with: "pattern": "^(btf|symdb|dwarf|symtab|system-map)$"')
    logger.info("")
    logger.info("Prerequisites:")
    logger.info("  - Python 3.8 or higher")
    logger.info("  - Git (for automatic setup)")
    logger.info("  - Internet connection")


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
            logger.info("Detecting kernel banner...")

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
                                    logger.log(25, "Found")
                                    logger.debug("  %s...", self.kernel_banner[:80])
                                return self.kernel_banner

            logger.warning("Not found")
            return None

        except subprocess.TimeoutExpired:
            logger.warning("Timeout")
            return None
        except Exception as e:
            logger.warning("Error: %s", e)
            return None
    
    def check_symbols(self, verbose: bool = True) -> Tuple[bool, str]:
        """
        Check if symbols are available for this image by running a simple plugin.
        
        Returns:
            Tuple of (symbols_available, message)
        """
        if verbose:
            logger.info("Checking symbol table availability...")

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
                logger.error("NOT FOUND")
                return False, "Symbol tables not found for this kernel"

            if result.returncode == 0:
                self.symbols_found = True
                if verbose:
                    logger.log(25, "Available")
                return True, "Symbols available"

            # Other error
            self.symbols_found = False
            logger.warning("Unknown")
            return False, result.stderr[:200]

        except subprocess.TimeoutExpired:
            logger.warning("Timeout")
            return False, "Timeout checking symbols"
        except Exception as e:
            logger.warning("Error")
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
            logger.info("  Running %s...", plugin)

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
                        logger.log(25, "OK (%d rows)", line_count)
                    else:
                        logger.warning("OK (no data)")

                return True, f"Success: {line_count} rows"
            else:
                # Read stderr for error message
                with open(stderr_path, 'r') as f:
                    error = f.read().strip()[:200]

                self.errors[plugin] = error

                logger.error("FAILED")

                return False, error

        except subprocess.TimeoutExpired:
            self.errors[plugin] = "Timeout (>10 minutes)"
            logger.error("TIMEOUT")
            return False, "Plugin timed out"

        except Exception as e:
            self.errors[plugin] = str(e)
            logger.error("ERROR: %s", e)
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
                logger.info("[%s]", category)
            
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
            logger.info("=" * 60)
            logger.info("  Linux Memory Analyzer v%s", __version__)
            logger.info("=" * 60)
            logger.info("Image: %s", self.image_path)
            logger.info("Output: %s", self.output_dir)

            size_mb = os.path.getsize(self.image_path) / (1024 * 1024)
            logger.info("Image Size: %.1f MB", size_mb)
        
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
            logger.info("Running plugins (Volatility will attempt to download symbols automatically)...")
        
        results = self.vol_runner.run_all_plugins(plugins_to_run, verbose)
        
        self.end_time = datetime.now()
        
        # Generate summary
        self._generate_summary(verbose)
        
        return results
    
    def _print_symbol_guidance(self, banner: Optional[str] = None):
        """Print guidance for obtaining symbol tables."""
        logger.warning("=" * 60)
        logger.warning("  Symbol Tables Not Found")
        logger.warning("=" * 60)

        if banner:
            logger.info("Detected Kernel:")
            logger.info("  %s", banner[:100])

        logger.info("Volatility 3 will attempt to download symbols automatically.")
        logger.info("If plugins fail, you may need to generate symbols manually:")

        logger.info("Option 1: Download pre-built symbols")
        logger.info("  - Check: https://isf-server.techanarchy.net/")
        logger.info("  - Place .json files in: volatility3/volatility3/symbols/linux/")

        logger.info("Option 2: Generate symbols with dwarf2json")
        logger.info("  # On a system with matching kernel + debug symbols:")
        logger.info("  sudo apt install linux-image-$(uname -r)-dbgsym")
        logger.info("  dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > symbols.json")

        logger.info("Option 3: Use --isf-url to specify ISF server")
        logger.info("  python linux_memory_analyzer.py -i image.lime --isf-url https://your-isf-server.com")

        logger.warning("=" * 60)
        logger.info("Continuing with analysis (some plugins may fail)...")
    
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
            logger.info("=" * 60)
            logger.info("  Analysis Complete")
            logger.info("=" * 60)
            logger.info("Duration: %.1f seconds", duration)
            logger.info("Successful: %d plugins", successful)
            if failed > 0:
                logger.warning("Failed: %d plugins", failed)
            logger.log(25, "Output Directory: %s", self.output_dir)
            logger.log(25, "Summary: %s", summary_path)


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
        logger.error("Error: %s", msg)
        return {}

    # First detect kernel banner
    if verbose:
        logger.info("Quick Triage Analysis")
    runner.detect_kernel_banner(verbose)
    
    return runner.run_all_plugins(quick_plugins, verbose)


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    from lft.core.logging import setup_logging
    setup_logging()
    
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
            logger.log(25, "[OK] %s", msg)
            # Try to get version
            vol_path = get_venv_vol_path() or shutil.which('vol') or shutil.which('vol.exe')
            if vol_path:
                try:
                    result = subprocess.run([vol_path, '--help'], capture_output=True, text=True, timeout=30)
                    if 'Framework' in result.stdout:
                        match = re.search(r'Framework (\d+\.\d+\.\d+)', result.stdout)
                        if match:
                            logger.info("  Version: %s", match.group(1))
                except Exception:
                    logger.debug("Could not retrieve Volatility version string")
                    pass
            sys.exit(0)
        else:
            logger.error("[MISSING] %s", msg)
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
            logger.error("Error: -i/--image is required for analysis")
            sys.exit(1)
    
    # Handle --banner flag (quick kernel identification)
    if args.banner:
        vol_path = args.vol_path or get_venv_vol_path() or shutil.which('vol') or shutil.which('vol.exe')
        if not vol_path:
            logger.error("Error: Volatility 3 not found")
            sys.exit(1)

        logger.info("Detecting kernel banner from: %s", args.image)

        try:
            cmd = [vol_path, '-f', args.image, '--offline', '-r', 'pretty', 'banners.Banners']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.stdout.strip():
                logger.info("%s", result.stdout)

                # Extract and highlight the kernel version
                match = re.search(r'Linux version (\S+)', result.stdout)
                if match:
                    logger.log(25, "Kernel Version: %s", match.group(1))
                    logger.info("To analyze this image, you need a symbol file for this kernel.")
                    logger.info("Generate it on a system with the same kernel using:")
                    logger.info("  # Install debug symbols")
                    logger.info("  sudo apt install linux-image-%s-dbgsym", match.group(1))
                    logger.info("  # Generate symbol file")
                    logger.info("  dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-%s > symbols.json", match.group(1))
                    logger.info("  # Then run analysis with:")
                    logger.info("  python %s -i %s -s /path/to/symbols/", os.path.basename(__file__), args.image)
            else:
                logger.warning("No kernel banner found in image")
                if result.stderr:
                    logger.debug("%s", result.stderr[:500])
        except subprocess.TimeoutExpired:
            logger.error("Timeout detecting banner")
        except Exception as e:
            logger.error("Error: %s", e)

        sys.exit(0)
    
    # Check if volatility is installed before proceeding
    installed, msg = check_volatility_installed()
    if not installed:
        logger.error("Error: %s", msg)
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
        logger.error("Error: %s", msg)
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
        logger.warning("Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error("Error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
