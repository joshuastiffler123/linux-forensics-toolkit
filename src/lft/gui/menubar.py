"""
Menu bar for the LFT GUI.

Builds a dark-themed ``tk.Menu`` and binds keyboard accelerators.
"""

from __future__ import annotations

import platform
import sys
import tkinter as tk
from typing import TYPE_CHECKING

from lft.gui.theme import MENU_BG, MENU_FG, MENU_ACTIVE_BG, MENU_ACTIVE_FG

if TYPE_CHECKING:
    from lft.gui.app import ForensicToolkitGUI


# Modifier key: Cmd on macOS, Ctrl elsewhere
_MOD = "Command" if platform.system() == "Darwin" else "Control"
_MOD_DISPLAY = "\u2318" if platform.system() == "Darwin" else "Ctrl+"


def _menu_kwargs() -> dict:
    """Common styling kwargs for all menu widgets."""
    return dict(
        bg=MENU_BG,
        fg=MENU_FG,
        activebackground=MENU_ACTIVE_BG,
        activeforeground=MENU_ACTIVE_FG,
        borderwidth=0,
        relief="flat",
    )


def build_menubar(app: ForensicToolkitGUI) -> tk.Menu:
    """Create and attach the application menu bar.

    Returns the root Menu widget.  The Export sub-menu is stored on
    ``app._export_menu`` so the app can enable/disable its entries.
    """
    menubar = tk.Menu(app, **_menu_kwargs())

    # ── File ─────────────────────────────────────────────────────
    file_menu = tk.Menu(menubar, tearoff=False, **_menu_kwargs())
    file_menu.add_command(
        label="Load Config...",
        accelerator=f"{_MOD_DISPLAY}O",
        command=app._load_config,
    )
    file_menu.add_command(
        label="Save Config...",
        accelerator=f"{_MOD_DISPLAY}S",
        command=app._save_config,
    )
    file_menu.add_separator()
    file_menu.add_command(
        label="Exit",
        accelerator=f"{_MOD_DISPLAY}Q",
        command=app.destroy,
    )
    menubar.add_cascade(label="File", menu=file_menu)

    # ── Analysis ─────────────────────────────────────────────────
    analysis_menu = tk.Menu(menubar, tearoff=False, **_menu_kwargs())
    analysis_menu.add_command(
        label="Run",
        accelerator=f"{_MOD_DISPLAY}R",
        command=app._on_run,
    )
    analysis_menu.add_command(
        label="Cancel",
        accelerator="Escape",
        command=app._on_cancel,
    )
    analysis_menu.add_separator()
    analysis_menu.add_command(
        label="Select All Analyzers",
        command=lambda: app._set_all_analyzers(True),
    )
    analysis_menu.add_command(
        label="Deselect All Analyzers",
        command=lambda: app._set_all_analyzers(False),
    )
    menubar.add_cascade(label="Analysis", menu=analysis_menu)

    # ── View ─────────────────────────────────────────────────────
    view_menu = tk.Menu(menubar, tearoff=False, **_menu_kwargs())
    view_menu.add_command(
        label="Clear Log",
        command=app._clear_log,
    )
    view_menu.add_command(
        label="Toggle Word Wrap",
        command=app._toggle_word_wrap,
    )
    menubar.add_cascade(label="View", menu=view_menu)

    # ── Export ───────────────────────────────────────────────────
    export_menu = tk.Menu(menubar, tearoff=False, **_menu_kwargs())
    export_menu.add_command(
        label="HTML Report...",
        command=app._export_html,
        state=tk.DISABLED,
    )
    export_menu.add_command(
        label="CSV Summary...",
        command=app._export_csv,
        state=tk.DISABLED,
    )
    menubar.add_cascade(label="Export", menu=export_menu)

    # Store ref so app can toggle state
    app._export_menu = export_menu

    # ── Help ─────────────────────────────────────────────────────
    help_menu = tk.Menu(menubar, tearoff=False, **_menu_kwargs())
    help_menu.add_command(
        label="About",
        command=app._show_about,
    )
    help_menu.add_command(
        label="Keyboard Shortcuts",
        command=app._show_shortcuts,
    )
    menubar.add_cascade(label="Help", menu=help_menu)

    # Attach to window
    app.config(menu=menubar)

    # ── Keyboard bindings ────────────────────────────────────────
    app.bind_all(f"<{_MOD}-o>", lambda e: app._load_config())
    app.bind_all(f"<{_MOD}-s>", lambda e: app._save_config())
    app.bind_all(f"<{_MOD}-q>", lambda e: app.destroy())
    app.bind_all(f"<{_MOD}-r>", lambda e: app._on_run())
    app.bind_all("<Escape>", lambda e: app._on_cancel())

    return menubar
