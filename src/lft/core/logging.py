"""
Shared logging configuration for the Linux Forensics Toolkit.

Provides a custom formatter that applies ANSI colors based on log level,
a custom SUCCESS level, and a single setup_logging() entry point.

Usage in modules::

    import logging
    logger = logging.getLogger(__name__)
    logger.info("Processing %s", path)
    logger.success("Done — wrote %d rows", count)

Usage in the orchestrator (linux_analyzer.py)::

    from lft_logging import setup_logging
    setup_logging(quiet=args.quiet)
"""

import logging
import sys

from lft.core.style import Style

__version__ = "2.0.0"

# ---------------------------------------------------------------------------
# Custom SUCCESS level (between INFO=20 and WARNING=30)
# ---------------------------------------------------------------------------
SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")


def _success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS):
        self._log(SUCCESS, message, args, **kwargs)


logging.Logger.success = _success

# ---------------------------------------------------------------------------
# Styled console formatter
# ---------------------------------------------------------------------------

_LEVEL_STYLES = {
    logging.DEBUG:    Style.DIM,
    logging.INFO:     Style.INFO,
    SUCCESS:          Style.SUCCESS,
    logging.WARNING:  Style.WARNING,
    logging.ERROR:    Style.ERROR,
    logging.CRITICAL: Style.CRITICAL,
}


class StyledFormatter(logging.Formatter):
    """Formatter that applies ANSI colors when connected to a TTY."""

    def format(self, record):
        msg = record.getMessage()
        if Style.ENABLED:
            color = _LEVEL_STYLES.get(record.levelno, Style.RESET)
            return f"{color}{msg}{Style.RESET}"
        return msg

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup_logging(*, quiet=False, level=None):
    """Configure logging for the entire toolkit.

    Call once from the orchestrator's ``main()``.  Individual modules
    only need ``logger = logging.getLogger(__name__)``.

    Parameters
    ----------
    quiet : bool
        If True, suppress everything below WARNING (matches ``-q`` flag).
    level : int | None
        Explicit level override.  Takes precedence over *quiet*.
    """
    if level is not None:
        effective_level = level
    elif quiet:
        effective_level = logging.WARNING
    else:
        effective_level = logging.DEBUG

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(StyledFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(effective_level)
