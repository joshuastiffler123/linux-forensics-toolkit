"""
Main application window for the Linux Forensics Toolkit GUI.

Provides a KAPE-like point-and-click interface for configuring and
launching UAC triage analysis.  Runs analysis in a background thread
so the UI stays responsive.

Launch:
    lfa-gui              # installed entry point
    lfa --gui            # via CLI flag
    python -m lft.gui    # module invocation
"""

from __future__ import annotations

import logging
import os
import platform
import queue
import subprocess
import sys
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Optional

from lft.gui.dnd import dnd_available, extract_drop_path, get_base_class, setup_dnd
from lft.gui.menubar import build_menubar
from lft.gui.report import export_csv_summary, generate_html_report
from lft.gui.results_view import ResultsTreeview
from lft.gui.statusbar import StatusBar
from lft.gui.theme import (
    ACCENT,
    BG_PRIMARY,
    BG_SECONDARY,
    BORDER,
    ENTRY_BG,
    ERROR,
    FG_PRIMARY,
    FG_SECONDARY,
    INFO,
    SELECT_BG,
    SUCCESS,
    WARNING,
    apply_dark_theme,
)
from lft.gui.worker import AnalysisWorker, QueueLogHandler, get_config_module

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_TITLE = "Linux Forensics Toolkit"
WINDOW_MIN_W, WINDOW_MIN_H = 900, 750

# Performance tuning
_MAX_LOG_LINES = 5_000  # Trim log after this many lines to prevent slowdown
_MAX_MSGS_PER_TICK = 50  # Max queue messages to process per poll cycle
_POLL_INTERVAL_MS = 80   # Queue poll interval (ms)

# Analyzer display names keyed by config key
ANALYZER_LABELS = {
    "login_timeline": "Login Timeline",
    "journal": "Journal Analyzer",
    "persistence": "Persistence Hunter",
    "security": "Security Analyzer",
    "packages": "Package Analyzer",
    "network": "Network Analyzer",
    "filesystem_timeline": "Filesystem Timeline",
    "string_analyzer": "String Analyzer",
    "misc_artifacts": "Misc Artifacts",
    "ioc_scanner": "IOC Scanner",
    "memory": "Memory Analyzer",
}


# ---------------------------------------------------------------------------
# Main GUI
# ---------------------------------------------------------------------------

_BaseClass = get_base_class()


class ForensicToolkitGUI(_BaseClass):  # type: ignore[misc]
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(WINDOW_MIN_W, WINDOW_MIN_H)
        self.geometry(f"{WINDOW_MIN_W}x{WINDOW_MIN_H}")

        # Apply dark theme before building widgets
        self._style = apply_dark_theme(self)

        # Message queue for worker -> GUI communication
        self._queue: queue.Queue = queue.Queue()
        self._worker: Optional[AnalysisWorker] = None
        self._output_dir: Optional[str] = None
        self._results: List[Dict] = []

        # Tkinter variables
        self._source_var = tk.StringVar()
        self._output_var = tk.StringVar(value=os.getcwd())
        self._ioc_var = tk.StringVar()
        self._memory_var = tk.StringVar()
        self._bodyfile_var = tk.StringVar()
        self._parallel_var = tk.BooleanVar(value=True)
        self._quiet_var = tk.BooleanVar(value=False)
        self._analyzer_vars: Dict[str, tk.BooleanVar] = {}

        # Export menu reference (set by build_menubar)
        self._export_menu: Optional[tk.Menu] = None

        self._build_ui()

        # Menu bar (after _build_ui so all widgets exist)
        build_menubar(self)

        self._poll_queue()

    # ── UI Construction ──────────────────────────────────────────

    def _build_ui(self):
        """Create all widgets."""
        # Use a PanedWindow for top (config) and bottom (output)
        main = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=(8, 0))

        # Top frame: inputs + analyzers side by side
        top = ttk.Frame(main)
        main.add(top, weight=1)

        self._build_inputs(top)
        self._build_analyzers(top)
        self._build_options(top)

        # Run / Cancel buttons
        btn_frame = ttk.Frame(main)
        main.add(btn_frame, weight=0)

        self._run_btn = ttk.Button(
            btn_frame,
            text="\u25b6  Run Analysis",
            command=self._on_run,
            style="Accent.TButton",
        )
        self._run_btn.pack(side=tk.LEFT, pady=6, ipady=4, ipadx=20, padx=(0, 8))

        self._cancel_btn = ttk.Button(
            btn_frame,
            text="\u25a0  Cancel",
            command=self._on_cancel,
            state=tk.DISABLED,
        )
        self._cancel_btn.pack(side=tk.LEFT, pady=6, ipady=4, ipadx=12)

        # Bottom frame: progress + log + results
        bottom = ttk.Frame(main)
        main.add(bottom, weight=2)

        self._build_progress(bottom)

        # Results treeview
        self._results_tree = ResultsTreeview(bottom)
        self._results_tree.pack(fill=tk.BOTH, expand=False, pady=(4, 0))

        # Open output folder button
        results_bar = ttk.Frame(bottom)
        results_bar.pack(fill=tk.X, pady=(4, 0))

        self._results_label = ttk.Label(results_bar, text="")
        self._results_label.pack(side=tk.LEFT)

        self._open_btn = ttk.Button(
            results_bar,
            text="Open Output Folder",
            command=self._open_output_folder,
            state=tk.DISABLED,
        )
        self._open_btn.pack(side=tk.RIGHT)

        # Status bar
        self._statusbar = StatusBar(self, version=self._get_version())
        self._statusbar.pack(fill=tk.X, side=tk.BOTTOM)

    def _build_inputs(self, parent: ttk.Frame):
        """Source, output, IOC, memory, bodyfile path selectors."""
        frame = ttk.LabelFrame(parent, text="Paths", padding=8)
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=(0, 4))
        parent.columnconfigure(0, weight=1)

        # Source row gets TWO browse buttons (tarball vs directory)
        ttk.Label(frame, text="Source:").grid(row=0, column=0, sticky="w", pady=2)
        source_entry = ttk.Entry(frame, textvariable=self._source_var, width=50)
        source_entry.grid(row=0, column=1, sticky="ew", padx=4, pady=2)

        # Set up drag-and-drop on the source entry
        if dnd_available():
            setup_dnd(source_entry, self._on_source_drop)

        source_btns = ttk.Frame(frame)
        source_btns.grid(row=0, column=2, pady=2)
        ttk.Button(
            source_btns,
            text="Tarball\u2026",
            width=8,
            command=self._browse_source_tarball,
        ).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(
            source_btns,
            text="Folder\u2026",
            width=8,
            command=self._browse_source_dir,
        ).pack(side=tk.LEFT)

        # DnD hint
        if dnd_available():
            ttk.Label(
                frame,
                text="(or drag & drop)",
                foreground=FG_SECONDARY,
                font=("TkDefaultFont", 9),
            ).grid(row=0, column=3, padx=(4, 0), pady=2)

        # Remaining paths each get a single Browse button
        other_paths = [
            ("Output directory:", self._output_var, self._browse_dir_output),
            ("IOC file (optional):", self._ioc_var, self._browse_ioc),
            ("Memory image (opt):", self._memory_var, self._browse_memory),
            ("Bodyfile (optional):", self._bodyfile_var, self._browse_bodyfile),
        ]

        for row, (label, var, cmd) in enumerate(other_paths, start=1):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=2)
            entry = ttk.Entry(frame, textvariable=var, width=50)
            entry.grid(row=row, column=1, sticky="ew", padx=4, pady=2)
            ttk.Button(frame, text="Browse\u2026", width=9, command=cmd).grid(
                row=row, column=2, pady=2
            )
            frame.columnconfigure(1, weight=1)

    def _build_analyzers(self, parent: ttk.Frame):
        """Analyzer enable/disable checkboxes."""
        frame = ttk.LabelFrame(parent, text="Analyzers", padding=8)
        frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=(0, 4))
        parent.columnconfigure(1, weight=0)

        # Select all / deselect all
        btn_row = ttk.Frame(frame)
        btn_row.pack(anchor="w", pady=(0, 4))
        ttk.Button(
            btn_row,
            text="All",
            width=5,
            command=lambda: self._set_all_analyzers(True),
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(
            btn_row,
            text="None",
            width=5,
            command=lambda: self._set_all_analyzers(False),
        ).pack(side=tk.LEFT)

        for key, label in ANALYZER_LABELS.items():
            var = tk.BooleanVar(value=True)
            self._analyzer_vars[key] = var
            cb = ttk.Checkbutton(frame, text=label, variable=var)
            cb.pack(anchor="w", pady=1)

    def _build_options(self, parent: ttk.Frame):
        """Parallel, quiet, config load/save."""
        frame = ttk.LabelFrame(parent, text="Options", padding=8)
        frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))

        ttk.Checkbutton(
            frame, text="Parallel execution", variable=self._parallel_var
        ).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Checkbutton(
            frame, text="Quiet mode", variable=self._quiet_var
        ).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Separator(frame, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill="y", padx=8
        )

        ttk.Button(frame, text="Load Config\u2026", command=self._load_config).pack(
            side=tk.LEFT, padx=4
        )

        ttk.Button(frame, text="Save Config\u2026", command=self._save_config).pack(
            side=tk.LEFT, padx=4
        )

    def _build_progress(self, parent: ttk.Frame):
        """Progress bar, log panel."""
        # Progress bar
        prog_frame = ttk.Frame(parent)
        prog_frame.pack(fill=tk.X, pady=(0, 4))

        self._progress_label = ttk.Label(prog_frame, text="Ready")
        self._progress_label.pack(side=tk.LEFT)

        self._progress_bar = ttk.Progressbar(
            prog_frame, mode="determinate", length=300
        )
        self._progress_bar.pack(
            side=tk.RIGHT, fill=tk.X, expand=True, padx=(8, 0)
        )

        # Log panel (scrolled text)
        log_frame = ttk.LabelFrame(parent, text="Output", padding=4)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self._log_text = tk.Text(
            log_frame,
            wrap=tk.NONE,  # NONE is much faster than WORD on Windows
            state=tk.DISABLED,
            font=("Courier", 11),
            bg=BG_PRIMARY,
            fg=FG_PRIMARY,
            insertbackground=FG_PRIMARY,
            selectbackground=SELECT_BG,
            relief=tk.FLAT,
            borderwidth=0,
            padx=8,
            pady=8,
        )
        vsb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL,
                            command=self._log_text.yview)
        hsb = ttk.Scrollbar(log_frame, orient=tk.HORIZONTAL,
                            command=self._log_text.xview)
        self._log_text.configure(yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure text tags for colored output
        self._log_text.tag_configure("success", foreground=SUCCESS)
        self._log_text.tag_configure("error", foreground=ERROR)
        self._log_text.tag_configure("warning", foreground=WARNING)
        self._log_text.tag_configure("info", foreground=INFO)
        self._log_text.tag_configure(
            "header", foreground=ACCENT, font=("Courier", 11, "bold")
        )

    # ── Drag-and-Drop ────────────────────────────────────────────

    def _on_source_drop(self, event) -> None:
        """Handle file drop on the source entry."""
        path = extract_drop_path(event.data)
        if path:
            self._source_var.set(path)

    # ── Browse Dialogs ───────────────────────────────────────────
    #
    # macOS Cocoa + tkinter bug: the Tk_GetOpenFileObjCmd bridge passes
    # file-type extensions to NSSavePanel.setAllowedFileTypes, but
    # certain patterns (compound extensions, bare wildcards, "*.*")
    # produce nil UTIs that crash with NSInvalidArgumentException.
    # The only reliable fix: skip filetypes entirely on macOS.

    _IS_MACOS = platform.system() == "Darwin"

    def _browse_source_tarball(self):
        """Browse for a UAC tarball."""
        if self._IS_MACOS:
            path = filedialog.askopenfilename(title="Select UAC tarball")
        else:
            path = filedialog.askopenfilename(
                title="Select UAC tarball",
                filetypes=[
                    ("Tarballs", "*.tar.gz *.tgz *.tar.bz2 *.tar.xz *.tar"),
                    ("All files", "*"),
                ],
            )
        if path:
            self._source_var.set(path)

    def _browse_source_dir(self):
        """Browse for an extracted UAC directory."""
        path = filedialog.askdirectory(title="Select UAC directory")
        if path:
            self._source_var.set(path)

    def _browse_dir_output(self):
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            self._output_var.set(path)

    def _browse_ioc(self):
        if self._IS_MACOS:
            path = filedialog.askopenfilename(title="Select IOC file")
        else:
            path = filedialog.askopenfilename(
                title="Select IOC file",
                filetypes=[("Text/CSV", "*.txt *.csv *.ioc"), ("All files", "*")],
            )
        if path:
            self._ioc_var.set(path)

    def _browse_memory(self):
        if self._IS_MACOS:
            path = filedialog.askopenfilename(title="Select memory image")
        else:
            path = filedialog.askopenfilename(
                title="Select memory image",
                filetypes=[
                    ("Memory dumps", "*.raw *.lime *.vmem *.mem *.dmp"),
                    ("All files", "*"),
                ],
            )
        if path:
            self._memory_var.set(path)

    def _browse_bodyfile(self):
        if self._IS_MACOS:
            path = filedialog.askopenfilename(title="Select bodyfile")
        else:
            path = filedialog.askopenfilename(
                title="Select bodyfile",
                filetypes=[
                    ("Bodyfiles", "*.body *.bodyfile *.txt"),
                    ("All files", "*"),
                ],
            )
        if path:
            self._bodyfile_var.set(path)

    # ── Analyzer Helpers ─────────────────────────────────────────

    def _set_all_analyzers(self, state: bool):
        for var in self._analyzer_vars.values():
            var.set(state)

    # ── Config Load / Save ───────────────────────────────────────

    def _load_config(self):
        config_mod = get_config_module()
        if self._IS_MACOS:
            path = filedialog.askopenfilename(title="Load config file")
        else:
            path = filedialog.askopenfilename(
                title="Load config file",
                filetypes=[("JSON", "*.json"), ("All files", "*")],
            )
        if not path:
            return
        try:
            cfg = config_mod.load_config(path)
            self._apply_config(cfg)
            self._log("Loaded config: " + path, tag="info")
        except Exception as exc:
            messagebox.showerror("Config Error", str(exc))

    def _save_config(self):
        config_mod = get_config_module()
        if self._IS_MACOS:
            path = filedialog.asksaveasfilename(
                title="Save config file",
                defaultextension=".json",
            )
        else:
            path = filedialog.asksaveasfilename(
                title="Save config file",
                defaultextension=".json",
                filetypes=[("JSON", "*.json")],
            )
        if not path:
            return
        try:
            cfg = self._build_config()
            config_mod.save_config(cfg, path)
            self._log("Saved config: " + path, tag="info")
        except Exception as exc:
            messagebox.showerror("Config Error", str(exc))

    def _apply_config(self, cfg):
        """Populate GUI fields from a ToolkitConfig."""
        self._parallel_var.set(cfg.parallel)
        self._quiet_var.set(cfg.quiet)
        if cfg.output_base and cfg.output_base != ".":
            self._output_var.set(cfg.output_base)
        if cfg.ioc_file:
            self._ioc_var.set(cfg.ioc_file)
        if cfg.memory_image:
            self._memory_var.set(cfg.memory_image)
        if cfg.bodyfile:
            self._bodyfile_var.set(cfg.bodyfile)
        for key, var in self._analyzer_vars.items():
            var.set(cfg.analyzers_enabled.get(key, True))

    def _build_config(self):
        """Build a ToolkitConfig from current GUI state."""
        config_mod = get_config_module()
        cfg = config_mod.default_config()
        cfg.parallel = self._parallel_var.get()
        cfg.quiet = self._quiet_var.get()
        cfg.output_base = self._output_var.get() or "."
        cfg.ioc_file = self._ioc_var.get() or None
        cfg.memory_image = self._memory_var.get() or None
        cfg.bodyfile = self._bodyfile_var.get() or None
        for key, var in self._analyzer_vars.items():
            cfg.analyzers_enabled[key] = var.get()
        return cfg

    # ── Menu-bar actions ─────────────────────────────────────────

    def _toggle_word_wrap(self):
        """Toggle log panel word wrap."""
        current = self._log_text.cget("wrap")
        new_wrap = tk.NONE if current == tk.WORD else tk.WORD
        self._log_text.config(wrap=new_wrap)

    def _export_html(self):
        """Export an HTML analysis report."""
        if not self._results:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = generate_html_report(
            self._output_dir, self._results, self._get_version(), parent=self
        )
        if path:
            self._log(f"HTML report saved: {path}", tag="info")

    def _export_csv(self):
        """Export a CSV summary of results."""
        if not self._results:
            messagebox.showinfo("Export", "No results to export.")
            return
        path = export_csv_summary(
            self._output_dir, self._results, parent=self
        )
        if path:
            self._log(f"CSV summary saved: {path}", tag="info")

    def _show_about(self):
        """Show About dialog."""
        version = self._get_version()
        messagebox.showinfo(
            "About",
            f"{APP_TITLE}\n\n"
            f"Version: {version}\n"
            f"Python: {sys.version.split()[0]}\n"
            f"Tk: {tk.TkVersion}\n\n"
            f"UAC collection analyzer with KAPE-like GUI.\n"
            f"Pure stdlib — no external dependencies.",
        )

    def _show_shortcuts(self):
        """Show keyboard shortcuts dialog."""
        mod = "\u2318" if platform.system() == "Darwin" else "Ctrl"
        messagebox.showinfo(
            "Keyboard Shortcuts",
            f"{mod}+O    Load Config\n"
            f"{mod}+S    Save Config\n"
            f"{mod}+R    Run Analysis\n"
            f"Escape     Cancel Analysis\n"
            f"{mod}+Q    Exit\n",
        )

    # ── Run Analysis ─────────────────────────────────────────────

    def _on_run(self):
        """Validate inputs and launch background worker."""
        source = self._source_var.get().strip()
        if not source:
            messagebox.showwarning("Missing Input", "Please select a source path.")
            return
        if not os.path.exists(source):
            messagebox.showerror("Not Found", f"Source not found:\n{source}")
            return

        # Build config from GUI state
        cfg = self._build_config()

        # Check at least one analyzer is enabled
        if not any(self._analyzer_vars[k].get() for k in self._analyzer_vars):
            messagebox.showwarning(
                "No Analyzers", "Please enable at least one analyzer."
            )
            return

        # Reset UI
        self._clear_log()
        self._results = []
        self._results_tree.clear()
        self._progress_bar["value"] = 0
        self._progress_label.config(text="Starting...")
        self._results_label.config(text="")
        self._open_btn.config(state=tk.DISABLED)
        self._run_btn.config(state=tk.DISABLED)
        self._cancel_btn.config(state=tk.NORMAL)
        self._output_dir = None

        # Disable export menu
        if self._export_menu:
            self._export_menu.entryconfigure(0, state=tk.DISABLED)
            self._export_menu.entryconfigure(1, state=tk.DISABLED)

        # Status bar
        self._statusbar.set_status("Starting analysis...")
        self._statusbar.start_timer()

        # Install queue-based log handler
        handler = QueueLogHandler(self._queue)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.DEBUG)

        self._log_handler = handler  # store ref so we can remove later

        # Header
        self._log("=" * 60, tag="header")
        self._log(f"  {APP_TITLE} v{self._get_version()}", tag="header")
        self._log(
            f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", tag="header"
        )
        self._log("=" * 60, tag="header")
        self._log(f"Source: {source}", tag="info")
        self._log("")

        # Launch worker
        self._worker = AnalysisWorker(
            msg_queue=self._queue,
            source_path=source,
            config=cfg,
            output_base=self._output_var.get().strip() or None,
            memory_path=self._memory_var.get().strip() or None,
            ioc_path=self._ioc_var.get().strip() or None,
            bodyfile_path=self._bodyfile_var.get().strip() or None,
        )
        self._worker.start()

    def _on_cancel(self):
        """Signal the worker to stop after the current analyzer."""
        if self._worker and self._worker.is_alive():
            self._worker.cancel()
            self._cancel_btn.config(state=tk.DISABLED)
            self._progress_label.config(
                text="Cancelling\u2026 (waiting for current analyzer)"
            )
            self._statusbar.set_status("Cancelling...")
            self._log(
                "\n\u26a0  Cancel requested — waiting for current analyzer to finish\u2026",
                tag="warning",
            )

    def _get_version(self) -> str:
        try:
            from lft import __version__

            return __version__
        except Exception:
            return "?"

    # ── Queue Polling ────────────────────────────────────────────

    def _poll_queue(self):
        """Process messages from the worker thread.

        Performance strategy:
        - Cap messages per tick to keep the UI responsive.
        - Batch all log lines into a single Text widget update
          (one state toggle + one see() call instead of per-line).
        """
        log_batch: list = []  # [(text, tag), ...]
        processed = 0

        try:
            while processed < _MAX_MSGS_PER_TICK:
                msg = self._queue.get_nowait()
                processed += 1
                kind = msg[0]

                if kind == "log":
                    text = msg[1]
                    # Color-code based on content
                    tag = None
                    if "\u2713" in text or "SUCCESS" in text.upper():
                        tag = "success"
                    elif (
                        "\u2717" in text
                        or "ERROR" in text.upper()
                        or "FAIL" in text.upper()
                    ):
                        tag = "error"
                    elif "WARNING" in text.upper():
                        tag = "warning"
                    log_batch.append((text, tag))

                elif kind == "progress":
                    _name, result, current, total = (
                        msg[1],
                        msg[2],
                        msg[3],
                        msg[4],
                    )
                    pct = (current / total * 100) if total else 0
                    self._progress_bar["value"] = pct
                    self._progress_label.config(
                        text=f"{current}/{total} analyzers complete"
                    )
                    self._statusbar.set_status(f"Running {_name}...")

                    # Guard against None results from analyzer errors
                    if not isinstance(result, dict):
                        log_batch.append(
                            (f"  \u2717 {_name}: returned no result", "error")
                        )
                        continue
                    # Log the result line
                    if result.get("success"):
                        parts = []
                        if result.get("event_count"):
                            parts.append(f"{result['event_count']} events")
                        if result.get("finding_count"):
                            parts.append(f"{result['finding_count']} findings")
                        extra = f" ({', '.join(parts)})" if parts else ""
                        log_batch.append(
                            (f"  \u2713 {_name}{extra}", "success")
                        )
                    else:
                        err = result.get("error", "unknown error")
                        log_batch.append(
                            (f"  \u2717 {_name}: {err}", "error")
                        )

                elif kind == "done":
                    output_dir, results = msg[1], msg[2]
                    # Flush pending log lines before the completion handler
                    if log_batch:
                        self._log_batch(log_batch)
                        log_batch = []
                    self._on_analysis_complete(output_dir, results)

                elif kind == "cancelled":
                    output_dir, results = msg[1], msg[2]
                    if log_batch:
                        self._log_batch(log_batch)
                        log_batch = []
                    self._on_analysis_cancelled(output_dir, results)

                elif kind == "error":
                    error_msg = msg[1]
                    log_batch.append(
                        (f"\nAnalysis failed: {error_msg}", "error")
                    )
                    if log_batch:
                        self._log_batch(log_batch)
                        log_batch = []
                    self._run_btn.config(state=tk.NORMAL)
                    self._cancel_btn.config(state=tk.DISABLED)
                    self._progress_label.config(text="Failed")
                    self._statusbar.set_status("Failed")
                    self._statusbar.stop_timer()
                    self._cleanup_log_handler()

        except queue.Empty:
            pass

        # Flush any remaining batched log lines in one shot
        if log_batch:
            self._log_batch(log_batch)

        self.after(_POLL_INTERVAL_MS, self._poll_queue)

    # ── Analysis Complete ────────────────────────────────────────

    def _on_analysis_complete(self, output_dir: str, results: List[Dict]):
        """Handle successful analysis completion."""
        self._output_dir = output_dir
        self._results = results
        self._progress_bar["value"] = 100
        self._progress_label.config(text="Complete")
        self._run_btn.config(state=tk.NORMAL)
        self._cancel_btn.config(state=tk.DISABLED)
        self._statusbar.set_status("Complete")
        self._statusbar.stop_timer()

        # Enable export menu
        if self._export_menu:
            self._export_menu.entryconfigure(0, state=tk.NORMAL)
            self._export_menu.entryconfigure(1, state=tk.NORMAL)

        # Populate results treeview
        self._results_tree.populate(results)

        # Summary — filter out any None results from failed analyzers
        results = [r for r in results if isinstance(r, dict)]
        success = sum(1 for r in results if r.get("success"))
        failed = len(results) - success
        total_events = sum(r.get("event_count", 0) or 0 for r in results)
        total_findings = sum(r.get("finding_count", 0) or 0 for r in results)
        total_files = sum(len(r.get("output_files", [])) for r in results)

        self._log("")
        self._log("=" * 60, tag="header")
        self._log("  Analysis Complete", tag="header")
        self._log("=" * 60, tag="header")
        self._log(f"  Analyzers: {success} passed, {failed} failed", tag="info")
        self._log(f"  Events:    {total_events:,}", tag="info")
        self._log(f"  Findings:  {total_findings:,}", tag="info")
        self._log(f"  CSV files: {total_files}", tag="info")
        self._log(f"  Output:    {output_dir}", tag="info")

        self._results_label.config(
            text=f"{total_files} CSV files in {os.path.basename(output_dir)}"
        )
        self._open_btn.config(state=tk.NORMAL)
        self._cleanup_log_handler()

    def _on_analysis_cancelled(
        self, output_dir: Optional[str], results: List[Dict]
    ):
        """Handle cancelled analysis — show partial results."""
        self._results = results
        self._progress_label.config(text="Cancelled")
        self._run_btn.config(state=tk.NORMAL)
        self._cancel_btn.config(state=tk.DISABLED)
        self._statusbar.set_status("Cancelled")
        self._statusbar.stop_timer()

        # Populate results treeview with partial results
        self._results_tree.populate(results)

        # Enable export if we have any results
        if results and self._export_menu:
            self._export_menu.entryconfigure(0, state=tk.NORMAL)
            self._export_menu.entryconfigure(1, state=tk.NORMAL)

        completed = [r for r in results if isinstance(r, dict) and r.get("success")]
        total_files = sum(
            len(r.get("output_files", []))
            for r in results
            if isinstance(r, dict)
        )

        self._log("")
        self._log("=" * 60, tag="warning")
        self._log("  Analysis Cancelled", tag="warning")
        self._log("=" * 60, tag="warning")
        self._log(
            f"  Analyzers completed before cancel: {len(completed)}/{len(results)}",
            tag="info",
        )
        if total_files:
            self._log(f"  Partial CSV files: {total_files}", tag="info")
        if output_dir:
            self._log(f"  Partial output:    {output_dir}", tag="info")
            self._output_dir = output_dir
            self._open_btn.config(state=tk.NORMAL)
            self._results_label.config(
                text=f"Cancelled — {total_files} partial CSV files"
            )
        else:
            self._results_label.config(text="Cancelled")

        self._cleanup_log_handler()

    def _cleanup_log_handler(self):
        """Remove the queue log handler."""
        if hasattr(self, "_log_handler"):
            logging.getLogger().removeHandler(self._log_handler)
            del self._log_handler

    # ── Log Panel Helpers ────────────────────────────────────────

    def _log(self, text: str, tag: str | None = None):
        """Append a single line to the log panel.

        For bulk inserts prefer ``_log_batch()`` which avoids repeated
        state toggles and redraws.
        """
        self._log_batch([(text, tag)])

    def _log_batch(self, lines: list):
        """Append multiple lines in a single Text widget update.

        This is *much* faster than per-line _log() calls because we only
        toggle state once, insert all lines, trim once, scroll once.
        """
        if not lines:
            return

        text_w = self._log_text
        text_w.config(state=tk.NORMAL)

        for text, tag in lines:
            if tag:
                text_w.insert(tk.END, text + "\n", tag)
            else:
                text_w.insert(tk.END, text + "\n")

        # Trim old lines to keep the widget responsive
        line_count = int(text_w.index("end-1c").split(".")[0])
        if line_count > _MAX_LOG_LINES:
            overshoot = line_count - _MAX_LOG_LINES
            text_w.delete("1.0", f"{overshoot}.0")

        text_w.config(state=tk.DISABLED)
        text_w.see(tk.END)

    def _clear_log(self):
        """Clear the log panel."""
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.config(state=tk.DISABLED)

    # ── Open Output Folder ───────────────────────────────────────

    def _open_output_folder(self):
        """Open the output directory in the system file manager."""
        if not self._output_dir or not os.path.isdir(self._output_dir):
            return
        system = platform.system()
        try:
            if system == "Darwin":
                subprocess.Popen(["open", self._output_dir])
            elif system == "Linux":
                subprocess.Popen(["xdg-open", self._output_dir])
            elif system == "Windows":
                os.startfile(self._output_dir)  # type: ignore[attr-defined]
        except Exception:
            messagebox.showinfo("Output", f"Output at:\n{self._output_dir}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Launch the GUI."""
    app = ForensicToolkitGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
