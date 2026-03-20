"""
Status bar widget for the bottom of the main window.

Shows current status, elapsed timer during analysis, and version.
"""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk

from lft.gui.theme import BG_SECONDARY, BORDER, FG_PRIMARY, FG_SECONDARY, ACCENT


class StatusBar(ttk.Frame):
    """Horizontal status bar with status text, elapsed timer, and version."""

    def __init__(self, parent: tk.Widget, version: str = ""):
        super().__init__(parent, style="StatusBar.TFrame")

        # Custom style with slightly different background
        style = ttk.Style()
        style.configure(
            "StatusBar.TFrame",
            background=BG_SECONDARY,
            relief="flat",
        )
        style.configure(
            "StatusBar.TLabel",
            background=BG_SECONDARY,
            foreground=FG_PRIMARY,
            padding=(6, 3),
        )
        style.configure(
            "StatusBarDim.TLabel",
            background=BG_SECONDARY,
            foreground=FG_SECONDARY,
            padding=(6, 3),
        )
        style.configure(
            "StatusBarAccent.TLabel",
            background=BG_SECONDARY,
            foreground=ACCENT,
            padding=(6, 3),
        )

        # Top border
        sep = ttk.Separator(self, orient=tk.HORIZONTAL)
        sep.pack(fill=tk.X, side=tk.TOP)

        # Content frame
        content = ttk.Frame(self, style="StatusBar.TFrame")
        content.pack(fill=tk.X, padx=4, pady=1)

        # Left: status text
        self._status_label = ttk.Label(
            content, text="Ready", style="StatusBar.TLabel"
        )
        self._status_label.pack(side=tk.LEFT)

        # Right: version
        self._version_label = ttk.Label(
            content,
            text=f"v{version}" if version else "",
            style="StatusBarDim.TLabel",
        )
        self._version_label.pack(side=tk.RIGHT)

        # Center: elapsed timer
        self._elapsed_label = ttk.Label(
            content, text="", style="StatusBarAccent.TLabel"
        )
        self._elapsed_label.pack(side=tk.RIGHT, padx=(0, 12))

        # Timer state
        self._start_time: float | None = None
        self._timer_id: str | None = None

    def set_status(self, text: str) -> None:
        """Update the status text on the left."""
        self._status_label.config(text=text)

    def start_timer(self) -> None:
        """Begin the elapsed-time counter."""
        self._start_time = time.monotonic()
        self._elapsed_label.config(text="Elapsed: 0:00:00")
        self._tick()

    def stop_timer(self) -> None:
        """Freeze the elapsed display."""
        if self._timer_id is not None:
            self.after_cancel(self._timer_id)
            self._timer_id = None

    def _tick(self) -> None:
        """Update elapsed time every second."""
        if self._start_time is None:
            return
        elapsed = int(time.monotonic() - self._start_time)
        h, remainder = divmod(elapsed, 3600)
        m, s = divmod(remainder, 60)
        self._elapsed_label.config(text=f"Elapsed: {h}:{m:02d}:{s:02d}")
        self._timer_id = self.after(1000, self._tick)

    def reset(self) -> None:
        """Reset to initial state."""
        self.stop_timer()
        self._start_time = None
        self._elapsed_label.config(text="")
        self.set_status("Ready")
