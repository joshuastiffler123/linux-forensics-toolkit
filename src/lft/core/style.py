"""
Shared ANSI console styling for the Linux Forensics Toolkit.

Provides color constants that automatically disable when output is
piped to a file or non-TTY destination.
"""

import os
import sys

__version__ = "2.1.0"


class Style:
    """ANSI escape codes for console styling.

    Colors are automatically disabled when stdout is not a TTY
    (e.g., when piping to a file), preventing ANSI noise in logs.
    """

    ENABLED = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

    RESET   = '\033[0m'  if ENABLED else ''
    BOLD    = '\033[1m'  if ENABLED else ''
    DIM     = '\033[2m'  if ENABLED else ''

    RED     = '\033[31m' if ENABLED else ''
    GREEN   = '\033[32m' if ENABLED else ''
    YELLOW  = '\033[33m' if ENABLED else ''
    BLUE    = '\033[34m' if ENABLED else ''
    MAGENTA = '\033[35m' if ENABLED else ''
    CYAN    = '\033[36m' if ENABLED else ''
    WHITE   = '\033[37m' if ENABLED else ''

    # Semantic aliases
    ERROR    = RED
    SUCCESS  = GREEN
    WARNING  = YELLOW
    INFO     = CYAN
    HEADER   = MAGENTA
    CRITICAL = f'{RED}{BOLD}' if ENABLED else ''

    @classmethod
    def enable_windows_ansi(cls):
        """Enable ANSI escape sequences on Windows terminals."""
        if os.name == 'nt':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                cls.ENABLED = True
            except (AttributeError, OSError, ValueError):
                pass
