"""
Centralized configuration for the Linux Forensics Toolkit.

Provides a ToolkitConfig dataclass that holds every tunable setting,
plus helpers to load/save JSON config files and merge CLI overrides.

Precedence chain::

    defaults (hardcoded) -> config file -> CLI args

No external dependencies (stdlib only, Python 3.8+).

Usage in the orchestrator::

    from lft_config import default_config, load_config, save_config, merge_cli_args

    cfg = default_config()
    if args.config:
        cfg = load_config(args.config)
    cfg = merge_cli_args(cfg, args)

Usage from a future GUI::

    cfg = load_config("my_settings.json")
    cfg.analyzers_enabled["memory"] = False
    save_config(cfg, "my_settings.json")
"""

import argparse
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from lft.core.errors import ConfigError

__version__ = "2.0.0"

logger = logging.getLogger(__name__)

# ============================================================================
# Analyzer name constants (used as dict keys throughout)
# ============================================================================

ANALYZER_NAMES = [
    "login_timeline",
    "journal",
    "persistence",
    "security",
    "filesystem_timeline",
    "string_analyzer",
    "misc_artifacts",
    "ioc_scanner",
    "memory",
    "packages",
    "network",
]

# ============================================================================
# Default ISF servers (currently hardcoded in linux_memory_analyzer.py)
# ============================================================================

DEFAULT_ISF_SERVERS = [
    "https://isf-server.techanarchy.net",
    "https://volatility3.org/isf",
]


# ============================================================================
# ToolkitConfig dataclass
# ============================================================================

def _default_analyzers_enabled() -> Dict[str, bool]:
    """All analyzers enabled by default."""
    return {name: True for name in ANALYZER_NAMES}


def _default_isf_servers() -> List[str]:
    return list(DEFAULT_ISF_SERVERS)


@dataclass
class ToolkitConfig:
    """Central configuration for the entire toolkit.

    Every field has a default that matches the current hardcoded behavior,
    so running without a config file is identical to today.
    """

    # -- Global settings --
    quiet: bool = False
    parallel: bool = True
    output_base: str = "."

    # -- Analyzer enable/disable --
    analyzers_enabled: Dict[str, bool] = field(
        default_factory=_default_analyzers_enabled,
    )

    # -- Per-analyzer thresholds --
    gap_threshold_hours: float = 6.0
    gap_severity_high_hours: float = 48.0
    gap_severity_medium_hours: float = 12.0
    max_message_length: int = 50000
    ioc_max_file_size: int = 200 * 1024 * 1024  # 200 MB

    # -- Caps (0 = unlimited) --
    web_log_max_lines: int = 0
    web_log_csv_max_rows: int = 0
    journal_max_entries: int = 0
    fs_timeline_min_date: str = ""             # "" = no filter

    # -- Raw extraction --
    export_raw: bool = True

    # -- ISF symbol servers (memory analyzer) --
    isf_servers: List[str] = field(default_factory=_default_isf_servers)

    # -- Optional path overrides --
    ioc_file: Optional[str] = None
    memory_image: Optional[str] = None
    symbol_dirs: List[str] = field(default_factory=list)
    bodyfile: Optional[str] = None
    vol_path: Optional[str] = None


# ============================================================================
# Public API
# ============================================================================

def default_config() -> ToolkitConfig:
    """Return a config with all defaults (matches current hardcoded behavior)."""
    return ToolkitConfig()


def load_config(path: str) -> ToolkitConfig:
    """Load a JSON config file and merge with defaults.

    Unknown keys are silently ignored so older config files work with
    newer toolkit versions.  Missing keys keep their defaults.

    Parameters
    ----------
    path : str
        Filesystem path to a ``.json`` config file.

    Returns
    -------
    ToolkitConfig
        Config with file values merged over defaults.
    """
    cfg = default_config()

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError) as e:
        raise ConfigError(f"Could not load config {path}: {e}") from e

    if not isinstance(raw, dict):
        logger.warning("Config file %s is not a JSON object — using defaults", path)
        return cfg

    # Simple scalar / list fields
    _SCALAR_FIELDS = {
        "quiet": bool,
        "parallel": bool,
        "output_base": str,
        "gap_threshold_hours": (int, float),
        "gap_severity_high_hours": (int, float),
        "gap_severity_medium_hours": (int, float),
        "max_message_length": int,
        "ioc_max_file_size": int,
        "web_log_max_lines": int,
        "web_log_csv_max_rows": int,
        "journal_max_entries": int,
        "fs_timeline_min_date": str,
        "export_raw": bool,
        "ioc_file": (str, type(None)),
        "memory_image": (str, type(None)),
        "bodyfile": (str, type(None)),
        "vol_path": (str, type(None)),
    }

    for key, expected in _SCALAR_FIELDS.items():
        if key in raw:
            val = raw[key]
            if isinstance(val, expected):
                setattr(cfg, key, val)
            else:
                logger.warning(
                    "Config key '%s' has unexpected type %s — skipping",
                    key, type(val).__name__,
                )

    # List fields
    for key in ("isf_servers", "symbol_dirs"):
        if key in raw and isinstance(raw[key], list):
            setattr(cfg, key, raw[key])

    # analyzers_enabled — merge per-key so partial overrides work
    if "analyzers_enabled" in raw and isinstance(raw["analyzers_enabled"], dict):
        for name, enabled in raw["analyzers_enabled"].items():
            if name in cfg.analyzers_enabled and isinstance(enabled, bool):
                cfg.analyzers_enabled[name] = enabled
            elif name not in cfg.analyzers_enabled:
                logger.warning("Unknown analyzer '%s' in config — skipping", name)

    logger.info("Loaded config from %s", path)
    return cfg


def save_config(config: ToolkitConfig, path: str) -> None:
    """Write config to a JSON file.

    Produces a nicely indented file suitable for human editing.
    A ``_comment`` key is prepended for documentation.

    Parameters
    ----------
    config : ToolkitConfig
        The configuration to persist.
    path : str
        Destination file path.
    """
    data = asdict(config)
    # Prepend a documentation comment (JSON doesn't support comments natively)
    ordered = {"_comment": "Linux Forensics Toolkit configuration — edit values below"}
    ordered.update(data)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(ordered, fh, indent=4)
        fh.write("\n")

    logger.info("Saved config to %s", path)


def merge_cli_args(config: ToolkitConfig, args: argparse.Namespace) -> ToolkitConfig:
    """Override config values with explicitly-provided CLI arguments.

    Only arguments that were actually supplied on the command line
    (i.e. not ``None`` and not the argparse default sentinel) take
    effect — so ``lfa -s tarball`` with no other flags leaves the
    config untouched.

    Parameters
    ----------
    config : ToolkitConfig
        Base config (from file or defaults).
    args : argparse.Namespace
        Parsed CLI arguments.

    Returns
    -------
    ToolkitConfig
        The same config object, mutated in place for convenience.
    """
    # --quiet / -q
    if getattr(args, "quiet", False):
        config.quiet = True

    # --sequential (inverts parallel)
    if getattr(args, "sequential", False):
        config.parallel = False

    # --output / -o
    val = getattr(args, "output", None)
    if val is not None:
        config.output_base = val

    # --ioc / -i
    val = getattr(args, "ioc", None)
    if val is not None:
        config.ioc_file = val

    # --memory / -m
    val = getattr(args, "memory", None)
    if val is not None:
        config.memory_image = val

    # --symbols / -s (repeatable)
    val = getattr(args, "symbols", None)
    if val:
        config.symbol_dirs = val

    # --bodyfile
    val = getattr(args, "bodyfile", None)
    if val is not None:
        config.bodyfile = val

    return config
