"""
Tkinter-based GUI for the Linux Forensics Toolkit.

Provides a KAPE-like point-and-click interface for configuring and
launching UAC triage analysis.  Runs analysis in a background thread
so the UI stays responsive.

No external dependencies — stdlib only (tkinter ships with Python).

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
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Lazy imports — keeps startup fast; the heavy modules load when Run is clicked
# ---------------------------------------------------------------------------

_cli_module = None
_config_module = None


def _ensure_imports():
    """Import heavy toolkit modules on first use."""
    global _cli_module, _config_module
    if _cli_module is None:
        from lft import cli as _cm
        from lft.core import config as _cfgm
        _cli_module = _cm
        _config_module = _cfgm


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_TITLE = "Linux Forensics Toolkit"
WINDOW_MIN_W, WINDOW_MIN_H = 860, 700

# Analyzer display names keyed by config key
ANALYZER_LABELS = {
    "login_timeline":       "Login Timeline",
    "journal":              "Journal Analyzer",
    "persistence":          "Persistence Hunter",
    "security":             "Security Analyzer",
    "packages":             "Package Analyzer",
    "network":              "Network Analyzer",
    "filesystem_timeline":  "Filesystem Timeline",
    "string_analyzer":      "String Analyzer",
    "misc_artifacts":       "Misc Artifacts",
    "ioc_scanner":          "IOC Scanner",
    "memory":               "Memory Analyzer",
}


# ---------------------------------------------------------------------------
# Logging handler that forwards records to a queue (thread-safe)
# ---------------------------------------------------------------------------

class QueueLogHandler(logging.Handler):
    """Sends log records to a queue for the GUI thread to display."""

    def __init__(self, log_queue: queue.Queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.log_queue.put(("log", msg))
        except Exception:
            self.handleError(record)


# ---------------------------------------------------------------------------
# Background analysis worker
# ---------------------------------------------------------------------------

class AnalysisWorker(threading.Thread):
    """Runs ``run_analysis()`` in a background thread."""

    daemon = True

    def __init__(
        self,
        msg_queue: queue.Queue,
        source_path: str,
        config: Any,
        output_base: str | None = None,
        memory_path: str | None = None,
        ioc_path: str | None = None,
        bodyfile_path: str | None = None,
    ):
        super().__init__(name="lft-analysis-worker")
        self.q = msg_queue
        self.source_path = source_path
        self.config = config
        self.output_base = output_base
        self.memory_path = memory_path
        self.ioc_path = ioc_path
        self.bodyfile_path = bodyfile_path
        self.cancel_event = threading.Event()

    def cancel(self):
        """Signal the worker to stop after the current analyzer finishes."""
        self.cancel_event.set()

    def run(self):
        _ensure_imports()
        try:
            def _progress(name: str, result: Dict, current: int, total: int):
                self.q.put(("progress", name, result, current, total))

            output_dir, results = _cli_module.run_analysis(
                source_path=self.source_path,
                output_base=self.output_base,
                parallel=self.config.parallel,
                verbose=True,
                memory_path=self.memory_path,
                ioc_path=self.ioc_path,
                bodyfile_path=self.bodyfile_path,
                config=self.config,
                progress_callback=_progress,
                cancel_event=self.cancel_event,
            )
            if self.cancel_event.is_set():
                self.q.put(("cancelled", output_dir, results))
            else:
                self.q.put(("done", output_dir, results))
        except Exception as exc:
            if self.cancel_event.is_set():
                self.q.put(("cancelled", None, []))
            else:
                self.q.put(("error", str(exc)))


# ---------------------------------------------------------------------------
# Main GUI
# ---------------------------------------------------------------------------

class ForensicToolkitGUI(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(WINDOW_MIN_W, WINDOW_MIN_H)
        self.geometry(f"{WINDOW_MIN_W}x{WINDOW_MIN_H}")

        # Message queue for worker → GUI communication
        self._queue: queue.Queue = queue.Queue()
        self._worker: Optional[AnalysisWorker] = None
        self._output_dir: Optional[str] = None

        # Tkinter variables
        self._source_var = tk.StringVar()
        self._output_var = tk.StringVar(value=os.getcwd())
        self._ioc_var = tk.StringVar()
        self._memory_var = tk.StringVar()
        self._bodyfile_var = tk.StringVar()
        self._parallel_var = tk.BooleanVar(value=True)
        self._quiet_var = tk.BooleanVar(value=False)
        self._analyzer_vars: Dict[str, tk.BooleanVar] = {}

        self._build_ui()
        self._poll_queue()

    # ── UI Construction ──────────────────────────────────────────────

    def _build_ui(self):
        """Create all widgets."""
        # Use a PanedWindow for top (config) and bottom (output)
        main = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Top frame: inputs + analyzers side by side
        top = ttk.Frame(main)
        main.add(top, weight=1)

        self._build_inputs(top)
        self._build_analyzers(top)
        self._build_options(top)

        # Run button
        btn_frame = ttk.Frame(main)
        main.add(btn_frame, weight=0)

        self._run_btn = ttk.Button(
            btn_frame, text="\u25b6  Run Analysis", command=self._on_run
        )
        self._run_btn.pack(side=tk.LEFT, pady=6, ipady=4, ipadx=20, padx=(0, 8))

        self._cancel_btn = ttk.Button(
            btn_frame, text="\u25a0  Cancel", command=self._on_cancel,
            state=tk.DISABLED
        )
        self._cancel_btn.pack(side=tk.LEFT, pady=6, ipady=4, ipadx=12)

        # Bottom frame: progress + results
        bottom = ttk.Frame(main)
        main.add(bottom, weight=2)

        self._build_progress(bottom)

    def _build_inputs(self, parent: ttk.Frame):
        """Source, output, IOC, memory, bodyfile path selectors."""
        frame = ttk.LabelFrame(parent, text="Paths", padding=8)
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=(0, 4))
        parent.columnconfigure(0, weight=1)

        # Source row gets TWO browse buttons (tarball vs directory)
        ttk.Label(frame, text="Source:").grid(
            row=0, column=0, sticky="w", pady=2
        )
        source_entry = ttk.Entry(frame, textvariable=self._source_var, width=50)
        source_entry.grid(row=0, column=1, sticky="ew", padx=4, pady=2)

        source_btns = ttk.Frame(frame)
        source_btns.grid(row=0, column=2, pady=2)
        ttk.Button(source_btns, text="Tarball\u2026", width=8,
                   command=self._browse_source_tarball).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(source_btns, text="Folder\u2026", width=8,
                   command=self._browse_source_dir).pack(side=tk.LEFT)

        # Remaining paths each get a single Browse button
        other_paths = [
            ("Output directory:",     self._output_var, self._browse_dir_output),
            ("IOC file (optional):",  self._ioc_var,    self._browse_ioc),
            ("Memory image (opt):",   self._memory_var, self._browse_memory),
            ("Bodyfile (optional):",  self._bodyfile_var, self._browse_bodyfile),
        ]

        for row, (label, var, cmd) in enumerate(other_paths, start=1):
            ttk.Label(frame, text=label).grid(
                row=row, column=0, sticky="w", pady=2
            )
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
        ttk.Button(btn_row, text="All", width=5,
                   command=lambda: self._set_all_analyzers(True)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="None", width=5,
                   command=lambda: self._set_all_analyzers(False)).pack(side=tk.LEFT)

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

        ttk.Button(
            frame, text="Load Config\u2026", command=self._load_config
        ).pack(side=tk.LEFT, padx=4)

        ttk.Button(
            frame, text="Save Config\u2026", command=self._save_config
        ).pack(side=tk.LEFT, padx=4)

    def _build_progress(self, parent: ttk.Frame):
        """Progress bar, log panel, results."""
        # Progress bar
        prog_frame = ttk.Frame(parent)
        prog_frame.pack(fill=tk.X, pady=(0, 4))

        self._progress_label = ttk.Label(prog_frame, text="Ready")
        self._progress_label.pack(side=tk.LEFT)

        self._progress_bar = ttk.Progressbar(
            prog_frame, mode="determinate", length=300
        )
        self._progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(8, 0))

        # Log panel (scrolled text)
        log_frame = ttk.LabelFrame(parent, text="Output", padding=4)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self._log_text = tk.Text(
            log_frame, wrap=tk.WORD, state=tk.DISABLED,
            font=("Courier", 11), bg="#1a1a2e", fg="#e0e0e0",
            insertbackground="#e0e0e0", selectbackground="#3a3a5e",
            relief=tk.FLAT, borderwidth=0, padx=8, pady=8,
        )
        scrollbar = ttk.Scrollbar(log_frame, command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure text tags for colored output
        self._log_text.tag_configure("success", foreground="#50fa7b")
        self._log_text.tag_configure("error", foreground="#ff5555")
        self._log_text.tag_configure("warning", foreground="#f1fa8c")
        self._log_text.tag_configure("info", foreground="#8be9fd")
        self._log_text.tag_configure("header", foreground="#bd93f9", font=("Courier", 11, "bold"))

        # Results bar
        results_frame = ttk.Frame(parent)
        results_frame.pack(fill=tk.X, pady=(4, 0))

        self._results_label = ttk.Label(results_frame, text="")
        self._results_label.pack(side=tk.LEFT)

        self._open_btn = ttk.Button(
            results_frame, text="Open Output Folder",
            command=self._open_output_folder, state=tk.DISABLED
        )
        self._open_btn.pack(side=tk.RIGHT)

    # ── Browse Dialogs ───────────────────────────────────────────────
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
                filetypes=[("Memory dumps", "*.raw *.lime *.vmem *.mem *.dmp"), ("All files", "*")],
            )
        if path:
            self._memory_var.set(path)

    def _browse_bodyfile(self):
        if self._IS_MACOS:
            path = filedialog.askopenfilename(title="Select bodyfile")
        else:
            path = filedialog.askopenfilename(
                title="Select bodyfile",
                filetypes=[("Bodyfiles", "*.body *.bodyfile *.txt"), ("All files", "*")],
            )
        if path:
            self._bodyfile_var.set(path)

    # ── Analyzer Helpers ─────────────────────────────────────────────

    def _set_all_analyzers(self, state: bool):
        for var in self._analyzer_vars.values():
            var.set(state)

    # ── Config Load / Save ───────────────────────────────────────────

    def _load_config(self):
        _ensure_imports()
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
            cfg = _config_module.load_config(path)
            self._apply_config(cfg)
            self._log("Loaded config: " + path, tag="info")
        except Exception as exc:
            messagebox.showerror("Config Error", str(exc))

    def _save_config(self):
        _ensure_imports()
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
            _config_module.save_config(cfg, path)
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
        _ensure_imports()
        cfg = _config_module.default_config()
        cfg.parallel = self._parallel_var.get()
        cfg.quiet = self._quiet_var.get()
        cfg.output_base = self._output_var.get() or "."
        cfg.ioc_file = self._ioc_var.get() or None
        cfg.memory_image = self._memory_var.get() or None
        cfg.bodyfile = self._bodyfile_var.get() or None
        for key, var in self._analyzer_vars.items():
            cfg.analyzers_enabled[key] = var.get()
        return cfg

    # ── Run Analysis ─────────────────────────────────────────────────

    def _on_run(self):
        """Validate inputs and launch background worker."""
        source = self._source_var.get().strip()
        if not source:
            messagebox.showwarning("Missing Input", "Please select a source path.")
            return
        if not os.path.exists(source):
            messagebox.showerror("Not Found", f"Source not found:\n{source}")
            return

        # Ensure imports before building config
        _ensure_imports()

        # Build config from GUI state
        cfg = self._build_config()

        # Check at least one analyzer is enabled
        if not any(self._analyzer_vars[k].get() for k in self._analyzer_vars):
            messagebox.showwarning("No Analyzers", "Please enable at least one analyzer.")
            return

        # Reset UI
        self._clear_log()
        self._progress_bar["value"] = 0
        self._progress_label.config(text="Starting...")
        self._results_label.config(text="")
        self._open_btn.config(state=tk.DISABLED)
        self._run_btn.config(state=tk.DISABLED)
        self._cancel_btn.config(state=tk.NORMAL)
        self._output_dir = None

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
        self._log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", tag="header")
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
            self._progress_label.config(text="Cancelling\u2026 (waiting for current analyzer)")
            self._log("\n\u26a0  Cancel requested — waiting for current analyzer to finish\u2026",
                      tag="warning")

    def _get_version(self) -> str:
        try:
            from lft import __version__
            return __version__
        except Exception:
            return "?"

    # ── Queue Polling ────────────────────────────────────────────────

    def _poll_queue(self):
        """Process messages from the worker thread."""
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]

                if kind == "log":
                    text = msg[1]
                    # Color-code based on content
                    tag = None
                    if "\u2713" in text or "SUCCESS" in text.upper():
                        tag = "success"
                    elif "\u2717" in text or "ERROR" in text.upper() or "FAIL" in text.upper():
                        tag = "error"
                    elif "WARNING" in text.upper():
                        tag = "warning"
                    self._log(text, tag=tag)

                elif kind == "progress":
                    _name, result, current, total = msg[1], msg[2], msg[3], msg[4]
                    pct = (current / total * 100) if total else 0
                    self._progress_bar["value"] = pct
                    self._progress_label.config(
                        text=f"{current}/{total} analyzers complete"
                    )
                    # Guard against None results from analyzer errors
                    if not isinstance(result, dict):
                        self._log(f"  \u2717 {_name}: returned no result", tag="error")
                        continue
                    # Log the result line
                    if result.get("success"):
                        parts = []
                        if result.get("event_count"):
                            parts.append(f"{result['event_count']} events")
                        if result.get("finding_count"):
                            parts.append(f"{result['finding_count']} findings")
                        extra = f" ({', '.join(parts)})" if parts else ""
                        self._log(f"  \u2713 {_name}{extra}", tag="success")
                    else:
                        err = result.get("error", "unknown error")
                        self._log(f"  \u2717 {_name}: {err}", tag="error")

                elif kind == "done":
                    output_dir, results = msg[1], msg[2]
                    self._on_analysis_complete(output_dir, results)

                elif kind == "cancelled":
                    output_dir, results = msg[1], msg[2]
                    self._on_analysis_cancelled(output_dir, results)

                elif kind == "error":
                    error_msg = msg[1]
                    self._log(f"\nAnalysis failed: {error_msg}", tag="error")
                    self._run_btn.config(state=tk.NORMAL)
                    self._cancel_btn.config(state=tk.DISABLED)
                    self._progress_label.config(text="Failed")
                    self._cleanup_log_handler()

        except queue.Empty:
            pass

        self.after(100, self._poll_queue)

    # ── Analysis Complete ────────────────────────────────────────────

    def _on_analysis_complete(self, output_dir: str, results: List[Dict]):
        """Handle successful analysis completion."""
        self._output_dir = output_dir
        self._progress_bar["value"] = 100
        self._progress_label.config(text="Complete")
        self._run_btn.config(state=tk.NORMAL)
        self._cancel_btn.config(state=tk.DISABLED)

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

    def _on_analysis_cancelled(self, output_dir: Optional[str],
                                results: List[Dict]):
        """Handle cancelled analysis — show partial results."""
        self._progress_label.config(text="Cancelled")
        self._run_btn.config(state=tk.NORMAL)
        self._cancel_btn.config(state=tk.DISABLED)

        completed = [r for r in results if r.get("success")]
        total_files = sum(len(r.get("output_files", [])) for r in results)

        self._log("")
        self._log("=" * 60, tag="warning")
        self._log("  Analysis Cancelled", tag="warning")
        self._log("=" * 60, tag="warning")
        self._log(f"  Analyzers completed before cancel: {len(completed)}/{len(results)}",
                  tag="info")
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

    # ── Log Panel Helpers ────────────────────────────────────────────

    def _log(self, text: str, tag: str | None = None):
        """Append a line to the log panel."""
        self._log_text.config(state=tk.NORMAL)
        if tag:
            self._log_text.insert(tk.END, text + "\n", tag)
        else:
            self._log_text.insert(tk.END, text + "\n")
        self._log_text.config(state=tk.DISABLED)
        self._log_text.see(tk.END)

    def _clear_log(self):
        """Clear the log panel."""
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.config(state=tk.DISABLED)

    # ── Open Output Folder ───────────────────────────────────────────

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
                os.startfile(self._output_dir)
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
