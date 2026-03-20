"""
Dracula-inspired dark theme for the LFT GUI.

Uses the 'clam' ttk base theme — the only cross-platform theme that
reliably respects background/foreground overrides on macOS, Linux, and
Windows.  The default 'aqua' theme on macOS silently ignores most color
settings.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

BG_PRIMARY = "#1a1a2e"  # deepest background (root, panels)
BG_SECONDARY = "#16213e"  # frames, label-frames
BG_TERTIARY = "#0f3460"  # active/selected items
FG_PRIMARY = "#e0e0e0"  # main text
FG_SECONDARY = "#a0a0b0"  # dimmed / placeholder text
ACCENT = "#bd93f9"  # purple (buttons, headers, progress)
ACCENT_HOVER = "#caa4fb"  # lighter purple on hover
SUCCESS = "#50fa7b"
ERROR = "#ff5555"
WARNING = "#f1fa8c"
INFO = "#8be9fd"
BORDER = "#2a2a4e"
ENTRY_BG = "#22224a"
SELECT_BG = "#3a3a5e"
TROUGH = "#12122a"

# Menu colors (tk.Menu uses classic Tk, not ttk)
MENU_BG = BG_SECONDARY
MENU_FG = FG_PRIMARY
MENU_ACTIVE_BG = BG_TERTIARY
MENU_ACTIVE_FG = FG_PRIMARY


# ---------------------------------------------------------------------------
# Theme application
# ---------------------------------------------------------------------------

def apply_dark_theme(root: tk.Tk) -> ttk.Style:
    """Apply the Dracula-inspired dark theme to all ttk widgets.

    Must be called before building any widgets.  Returns the Style
    object for later use (e.g. adding custom tags).
    """
    style = ttk.Style(root)
    style.theme_use("clam")

    # ── Root window ──────────────────────────────────────────────
    root.configure(bg=BG_PRIMARY)
    root.option_add("*TCombobox*Listbox.background", ENTRY_BG)
    root.option_add("*TCombobox*Listbox.foreground", FG_PRIMARY)
    root.option_add("*TCombobox*Listbox.selectBackground", SELECT_BG)

    # ── TFrame ───────────────────────────────────────────────────
    style.configure("TFrame", background=BG_PRIMARY)

    # ── TLabelframe ──────────────────────────────────────────────
    style.configure(
        "TLabelframe",
        background=BG_PRIMARY,
        bordercolor=BORDER,
        relief="groove",
    )
    style.configure(
        "TLabelframe.Label",
        background=BG_PRIMARY,
        foreground=ACCENT,
        font=("TkDefaultFont", 0, "bold"),
    )

    # ── TLabel ───────────────────────────────────────────────────
    style.configure("TLabel", background=BG_PRIMARY, foreground=FG_PRIMARY)

    # ── TButton ──────────────────────────────────────────────────
    style.configure(
        "TButton",
        background=BG_TERTIARY,
        foreground=FG_PRIMARY,
        bordercolor=BORDER,
        focuscolor=ACCENT,
        padding=(8, 4),
    )
    style.map(
        "TButton",
        background=[("active", ACCENT), ("disabled", BG_SECONDARY)],
        foreground=[("disabled", FG_SECONDARY)],
    )

    # Accent button variant (for Run)
    style.configure(
        "Accent.TButton",
        background=ACCENT,
        foreground="#1a1a2e",
        font=("TkDefaultFont", 0, "bold"),
    )
    style.map(
        "Accent.TButton",
        background=[("active", ACCENT_HOVER), ("disabled", BG_SECONDARY)],
        foreground=[("disabled", FG_SECONDARY)],
    )

    # ── TCheckbutton ─────────────────────────────────────────────
    style.configure(
        "TCheckbutton",
        background=BG_PRIMARY,
        foreground=FG_PRIMARY,
        indicatorcolor=ENTRY_BG,
        focuscolor=BG_PRIMARY,
    )
    style.map(
        "TCheckbutton",
        indicatorcolor=[("selected", ACCENT)],
        background=[("active", BG_PRIMARY)],
    )

    # ── TEntry ───────────────────────────────────────────────────
    style.configure(
        "TEntry",
        fieldbackground=ENTRY_BG,
        foreground=FG_PRIMARY,
        bordercolor=BORDER,
        insertcolor=FG_PRIMARY,
    )
    style.map(
        "TEntry",
        fieldbackground=[("focus", "#2a2a5a")],
        bordercolor=[("focus", ACCENT)],
    )

    # ── TProgressbar ─────────────────────────────────────────────
    style.configure(
        "TProgressbar",
        troughcolor=TROUGH,
        background=ACCENT,
        bordercolor=BORDER,
        lightcolor=ACCENT,
        darkcolor=ACCENT,
    )

    # ── TPanedwindow ─────────────────────────────────────────────
    style.configure(
        "TPanedwindow",
        background=BG_PRIMARY,
    )

    # ── TSeparator ───────────────────────────────────────────────
    style.configure("TSeparator", background=BORDER)

    # ── TScrollbar ───────────────────────────────────────────────
    style.configure(
        "TScrollbar",
        background=BG_SECONDARY,
        troughcolor=BG_PRIMARY,
        bordercolor=BG_PRIMARY,
        arrowcolor=FG_SECONDARY,
    )
    style.map(
        "TScrollbar",
        background=[("active", BG_TERTIARY)],
    )

    # ── Treeview ─────────────────────────────────────────────────
    style.configure(
        "Treeview",
        background=BG_PRIMARY,
        foreground=FG_PRIMARY,
        fieldbackground=BG_PRIMARY,
        bordercolor=BORDER,
        rowheight=24,
    )
    style.configure(
        "Treeview.Heading",
        background=BG_SECONDARY,
        foreground=ACCENT,
        bordercolor=BORDER,
        font=("TkDefaultFont", 0, "bold"),
    )
    style.map(
        "Treeview",
        background=[("selected", SELECT_BG)],
        foreground=[("selected", FG_PRIMARY)],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", BG_TERTIARY)],
    )

    # Row tags for colored results
    # (These are applied via Treeview.tag_configure at widget level,
    #  but we define style-level defaults here for consistency.)

    # ── TNotebook (future use) ───────────────────────────────────
    style.configure(
        "TNotebook",
        background=BG_PRIMARY,
        bordercolor=BORDER,
    )
    style.configure(
        "TNotebook.Tab",
        background=BG_SECONDARY,
        foreground=FG_PRIMARY,
        padding=(10, 4),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", BG_PRIMARY), ("active", BG_TERTIARY)],
        foreground=[("selected", ACCENT)],
    )

    return style
