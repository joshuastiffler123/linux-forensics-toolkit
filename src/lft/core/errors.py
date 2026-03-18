"""
Custom exception hierarchy and exit codes for the Linux Forensics Toolkit.

Provides structured error types so callers (CLI, GUI, tests) can
distinguish between different failure modes without parsing messages.

Exception hierarchy::

    LFTError
    ├── SourceNotFoundError   — UAC tarball or directory not found
    ├── SourceCorruptError    — tarball unreadable, truncated, or corrupt
    ├── ParseError            — log, journal, or binary artifact parse failure
    ├── AnalyzerError         — an analyzer failed during execution
    └── ConfigError           — invalid or unreadable configuration

Exit codes (for standalone CLI entry points)::

    EXIT_OK              = 0
    EXIT_ERROR           = 1   (generic / unhandled)
    EXIT_SOURCE_NOT_FOUND = 2
    EXIT_CONFIG_ERROR    = 3
    EXIT_SIGINT          = 130 (Ctrl-C / SIGINT)
"""

__version__ = "2.0.0"


# ============================================================================
# Exception hierarchy
# ============================================================================

class LFTError(Exception):
    """Base exception for all Linux Forensics Toolkit errors.

    Catch this to handle any toolkit-specific error in one place
    (e.g. a GUI's top-level error panel).
    """


class SourceNotFoundError(LFTError):
    """The UAC tarball or extracted directory does not exist."""


class SourceCorruptError(LFTError):
    """The tarball is unreadable, truncated, or uses an unsupported format."""


class ParseError(LFTError):
    """A log file, journal entry, or binary artifact could not be parsed."""


class AnalyzerError(LFTError):
    """An analyzer module failed during execution."""


class ConfigError(LFTError):
    """The configuration file is missing, unreadable, or contains invalid values."""


# ============================================================================
# Exit codes
# ============================================================================

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_SOURCE_NOT_FOUND = 2
EXIT_CONFIG_ERROR = 3
EXIT_SIGINT = 130
