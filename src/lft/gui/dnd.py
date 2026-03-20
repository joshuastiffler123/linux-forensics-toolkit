"""
Optional drag-and-drop support.

If ``tkinterdnd2`` is installed the module enables file drops on the
source entry.  Otherwise it silently degrades — no hard dependency.
"""

from __future__ import annotations

import re
import tkinter as tk

_HAS_DND = False

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore[import-untyped]

    _HAS_DND = True
except ImportError:
    TkinterDnD = None  # type: ignore[assignment,misc]


def dnd_available() -> bool:
    """Return True if drag-and-drop is supported."""
    return _HAS_DND


def get_base_class():
    """Return the appropriate Tk base class (DnD-aware if available)."""
    if _HAS_DND and TkinterDnD is not None:
        return TkinterDnD.Tk
    return tk.Tk


def setup_dnd(widget: tk.Widget, callback) -> bool:
    """Register *widget* as a file drop target.

    *callback* receives the dropped file path as a string.
    Returns True if DnD was set up successfully.
    """
    if not _HAS_DND:
        return False
    try:
        widget.drop_target_register(DND_FILES)
        widget.dnd_bind("<<Drop>>", callback)
        return True
    except Exception:
        return False


def extract_drop_path(event_data: str) -> str:
    """Normalise the path string from a drop event.

    On some platforms paths with spaces are wrapped in braces:
    ``{/path/to/my file.tar.gz}`` → ``/path/to/my file.tar.gz``
    """
    path = event_data.strip()
    # Remove surrounding braces (Tk on macOS / Windows)
    if path.startswith("{") and path.endswith("}"):
        path = path[1:-1]
    # If multiple files were dropped, take only the first
    # (tkdnd separates with spaces outside braces)
    if " " in path and not path.startswith("/"):
        parts = re.split(r"\s+", path)
        path = parts[0]
    return path
