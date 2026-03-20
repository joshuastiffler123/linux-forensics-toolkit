"""
Results treeview and per-analyzer drill-down window.

The ``ResultsTreeview`` widget displays analysis results in a sortable
table.  Double-clicking a row opens ``DrillDownWindow`` with CSV preview.
"""

from __future__ import annotations

import csv
import os
import platform
import subprocess
import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Optional

from lft.gui.theme import (
    ACCENT,
    BG_PRIMARY,
    BG_SECONDARY,
    BG_TERTIARY,
    BORDER,
    ENTRY_BG,
    ERROR,
    FG_PRIMARY,
    FG_SECONDARY,
    SELECT_BG,
    SUCCESS,
    WARNING,
)


# ---------------------------------------------------------------------------
# Results Treeview
# ---------------------------------------------------------------------------


class ResultsTreeview(ttk.Frame):
    """Sortable table showing per-analyzer results."""

    _COLUMNS = ("analyzer", "status", "events", "findings", "files")
    _HEADINGS = ("Analyzer", "Status", "Events", "Findings", "Files")
    _WIDTHS = (220, 70, 80, 80, 60)
    _ANCHORS = ("w", "center", "e", "e", "e")

    def __init__(self, parent: tk.Widget):
        super().__init__(parent)

        # Treeview
        self._tree = ttk.Treeview(
            self,
            columns=self._COLUMNS,
            show="headings",
            selectmode="browse",
            height=6,
        )

        for col, heading, width, anchor in zip(
            self._COLUMNS, self._HEADINGS, self._WIDTHS, self._ANCHORS
        ):
            self._tree.heading(
                col,
                text=heading,
                command=lambda c=col: self._sort_by(c),
            )
            self._tree.column(col, width=width, anchor=anchor, minwidth=40)

        # Make analyzer column stretch
        self._tree.column("analyzer", stretch=True)
        for col in self._COLUMNS[1:]:
            self._tree.column(col, stretch=False)

        # Row colour tags
        self._tree.tag_configure("success", foreground=SUCCESS)
        self._tree.tag_configure("error", foreground=ERROR)

        # Scrollbar
        vsb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Double-click binding
        self._tree.bind("<Double-1>", self._on_double_click)

        # Internal storage: iid → full result dict
        self._result_data: Dict[str, Dict] = {}
        self._sort_reverse: Dict[str, bool] = {c: False for c in self._COLUMNS}

    # ── Public API ───────────────────────────────────────────────

    def clear(self) -> None:
        """Remove all rows."""
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._result_data.clear()

    def populate(self, results: List[Dict]) -> None:
        """Insert rows from a list of analyzer result dicts.

        Hides the treeview during bulk insert to avoid per-row redraws
        on Windows.
        """
        self.clear()

        # Hide during batch insert to suppress redraws
        pack_info = self._tree.pack_info() if self._tree.winfo_manager() == "pack" else None
        self._tree.pack_forget()

        for result in results:
            if not isinstance(result, dict):
                continue
            ok = result.get("success", False)
            values = (
                result.get("name", "?"),
                "OK" if ok else "FAIL",
                result.get("event_count", 0) or 0,
                result.get("finding_count", 0) or 0,
                len(result.get("output_files", [])),
            )
            tag = "success" if ok else "error"
            iid = self._tree.insert("", tk.END, values=values, tags=(tag,))
            self._result_data[iid] = result

        # Re-show
        if pack_info:
            self._tree.pack(**{k: v for k, v in pack_info.items()
                              if k != "in"})
        else:
            self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # ── Sorting ──────────────────────────────────────────────────

    def _sort_by(self, col: str) -> None:
        """Sort rows by the given column."""
        reverse = self._sort_reverse[col]
        items = [
            (self._tree.set(iid, col), iid)
            for iid in self._tree.get_children()
        ]

        # Numeric sort for numeric columns
        if col in ("events", "findings", "files"):
            items.sort(key=lambda x: int(x[0] or 0), reverse=reverse)
        else:
            items.sort(key=lambda x: x[0].lower(), reverse=reverse)

        for idx, (_val, iid) in enumerate(items):
            self._tree.move(iid, "", idx)

        self._sort_reverse[col] = not reverse

    # ── Drill-down ───────────────────────────────────────────────

    def _on_double_click(self, event: tk.Event) -> None:
        """Open drill-down window for the selected row."""
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]
        result = self._result_data.get(iid)
        if result:
            DrillDownWindow(self.winfo_toplevel(), result)


# ---------------------------------------------------------------------------
# Drill-Down Window
# ---------------------------------------------------------------------------

_MAX_PREVIEW_ROWS = 100
_MAX_COLUMNS = 10
_MAX_CELL_LEN = 80
_MAX_CSV_SIZE = 1_000_000  # 1 MB


class DrillDownWindow(tk.Toplevel):
    """Per-analyzer detail view with CSV preview."""

    def __init__(self, parent: tk.Widget, result: Dict):
        super().__init__(parent)
        self.result = result
        name = result.get("name", "Analyzer")
        self.title(f"{name} — Details")
        self.geometry("900x600")
        self.configure(bg=BG_PRIMARY)
        self.minsize(600, 400)

        self._build_ui()

    def _build_ui(self) -> None:
        result = self.result
        name = result.get("name", "?")
        ok = result.get("success", False)

        # ── Header ───────────────────────────────────────────────
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=12, pady=(12, 4))

        ttk.Label(
            header,
            text=name,
            font=("TkDefaultFont", 16, "bold"),
            foreground=ACCENT,
        ).pack(side=tk.LEFT)

        status_text = "SUCCESS" if ok else "FAILED"
        status_color = SUCCESS if ok else ERROR
        ttk.Label(
            header,
            text=f"  [{status_text}]",
            foreground=status_color,
            font=("TkDefaultFont", 14, "bold"),
        ).pack(side=tk.LEFT, padx=(8, 0))

        # ── Stats ────────────────────────────────────────────────
        stats = ttk.Frame(self)
        stats.pack(fill=tk.X, padx=12, pady=4)

        events = result.get("event_count", 0) or 0
        findings = result.get("finding_count", 0) or 0
        files = result.get("output_files", [])

        for label_text, value in [
            ("Events:", f"{events:,}"),
            ("Findings:", f"{findings:,}"),
            ("Output files:", str(len(files))),
        ]:
            ttk.Label(stats, text=label_text, foreground=FG_SECONDARY).pack(
                side=tk.LEFT, padx=(0, 4)
            )
            ttk.Label(stats, text=value, foreground=FG_PRIMARY).pack(
                side=tk.LEFT, padx=(0, 16)
            )

        # Error message if failed
        error = result.get("error")
        if error:
            err_frame = ttk.Frame(self)
            err_frame.pack(fill=tk.X, padx=12, pady=4)
            ttk.Label(
                err_frame,
                text=f"Error: {error}",
                foreground=ERROR,
                wraplength=850,
            ).pack(anchor="w")

        # ── File list + preview ──────────────────────────────────
        if files:
            paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
            paned.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 8))

            # Left: file list
            file_frame = ttk.LabelFrame(paned, text="Output Files", padding=4)
            paned.add(file_frame, weight=1)

            self._file_listbox = tk.Listbox(
                file_frame,
                bg=ENTRY_BG,
                fg=FG_PRIMARY,
                selectbackground=SELECT_BG,
                selectforeground=FG_PRIMARY,
                borderwidth=0,
                highlightthickness=0,
                font=("Courier", 11),
            )
            file_sb = ttk.Scrollbar(
                file_frame, command=self._file_listbox.yview
            )
            self._file_listbox.configure(yscrollcommand=file_sb.set)
            self._file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            file_sb.pack(side=tk.RIGHT, fill=tk.Y)

            for f in files:
                self._file_listbox.insert(tk.END, os.path.basename(f))
            self._files = files

            # Bind selection to preview
            self._file_listbox.bind("<<ListboxSelect>>", self._on_file_select)

            # Buttons below file list
            btn_frame = ttk.Frame(self)
            btn_frame.pack(fill=tk.X, padx=12, pady=(0, 4))
            ttk.Button(
                btn_frame,
                text="Open in File Manager",
                command=self._open_selected_file,
            ).pack(side=tk.LEFT, padx=(0, 8))
            ttk.Button(
                btn_frame,
                text="Open Containing Folder",
                command=self._open_containing_folder,
            ).pack(side=tk.LEFT)

            # Right: CSV preview
            preview_frame = ttk.LabelFrame(
                paned, text="CSV Preview", padding=4
            )
            paned.add(preview_frame, weight=3)

            self._preview_tree = ttk.Treeview(
                preview_frame, show="headings", height=15
            )
            preview_vsb = ttk.Scrollbar(
                preview_frame,
                orient=tk.VERTICAL,
                command=self._preview_tree.yview,
            )
            preview_hsb = ttk.Scrollbar(
                preview_frame,
                orient=tk.HORIZONTAL,
                command=self._preview_tree.xview,
            )
            self._preview_tree.configure(
                yscrollcommand=preview_vsb.set,
                xscrollcommand=preview_hsb.set,
            )
            self._preview_tree.pack(
                side=tk.LEFT, fill=tk.BOTH, expand=True
            )
            preview_vsb.pack(side=tk.RIGHT, fill=tk.Y)
            preview_hsb.pack(side=tk.BOTTOM, fill=tk.X)

            # Auto-select first file
            if files:
                self._file_listbox.selection_set(0)
                self._load_csv_preview(files[0])

        # ── Coverage ─────────────────────────────────────────────
        coverage = result.get("coverage")
        if coverage:
            cov_frame = ttk.LabelFrame(self, text="Coverage Probes", padding=4)
            cov_frame.pack(fill=tk.X, padx=12, pady=(4, 8))

            cov_text = tk.Text(
                cov_frame,
                height=4,
                wrap=tk.WORD,
                bg=ENTRY_BG,
                fg=FG_PRIMARY,
                borderwidth=0,
                font=("Courier", 10),
                state=tk.NORMAL,
            )
            for probe in coverage:
                if isinstance(probe, dict):
                    status = probe.get("Status", "?")
                    expected = probe.get("Expected_Path", "?")
                    cov_text.insert(tk.END, f"  [{status}] {expected}\n")
                else:
                    cov_text.insert(tk.END, f"  {probe}\n")
            cov_text.config(state=tk.DISABLED)
            cov_text.pack(fill=tk.X)

    # ── CSV Preview ──────────────────────────────────────────────

    def _on_file_select(self, event: tk.Event) -> None:
        sel = self._file_listbox.curselection()
        if sel:
            idx = sel[0]
            self._load_csv_preview(self._files[idx])

    def _load_csv_preview(self, csv_path: str) -> None:
        """Load and display the first N rows of a CSV file.

        Performance notes:
        - All rows are collected first, then inserted while the treeview
          is hidden (pack_forget / re-pack) to suppress per-row redraws.
        - Column widths are pre-computed from the data rather than being
          adjusted per-row.
        """
        tree = self._preview_tree

        # Clear existing
        tree.delete(*tree.get_children())
        tree["columns"] = ()

        if not os.path.isfile(csv_path):
            return

        # Skip large files
        try:
            size = os.path.getsize(csv_path)
        except OSError:
            return
        if size > _MAX_CSV_SIZE:
            tree["columns"] = ("info",)
            tree.heading("info", text="Info")
            tree.column("info", width=400)
            tree.insert(
                "", tk.END,
                values=(f"File too large for preview ({size:,} bytes)",),
            )
            return

        try:
            with open(csv_path, "r", newline="", errors="replace") as f:
                reader = csv.reader(f)
                headers = next(reader, None)
                if not headers:
                    return

                # Cap columns
                if len(headers) > _MAX_COLUMNS:
                    headers = headers[:_MAX_COLUMNS] + [
                        f"... +{len(headers) - _MAX_COLUMNS} more"
                    ]
                    cap = _MAX_COLUMNS
                else:
                    cap = len(headers)

                # Pre-read all display rows into a list
                display_rows: list = []
                col_count = len(headers)
                truncated = False

                for row in reader:
                    if len(display_rows) >= _MAX_PREVIEW_ROWS:
                        truncated = True
                        break

                    display_row = []
                    for cell in row[:cap]:
                        if len(cell) > _MAX_CELL_LEN:
                            cell = cell[: _MAX_CELL_LEN - 1] + "\u2026"
                        display_row.append(cell)
                    # Pad if row has fewer columns than headers
                    while len(display_row) < col_count:
                        display_row.append("")
                    display_rows.append(display_row)

            # --- Batch insert: hide tree, configure, insert, show ---
            # Hiding prevents Tk from reflowing layout on each insert
            pack_info = tree.pack_info() if tree.winfo_manager() == "pack" else None
            tree.pack_forget()

            col_ids = [f"c{i}" for i in range(col_count)]
            tree["columns"] = col_ids

            for cid, h in zip(col_ids, headers):
                display = h[:_MAX_CELL_LEN] if len(h) > _MAX_CELL_LEN else h
                tree.heading(cid, text=display)
                tree.column(cid, width=max(80, min(200, len(h) * 8)))

            for display_row in display_rows:
                tree.insert("", tk.END, values=display_row)

            if truncated:
                tree.insert(
                    "", tk.END,
                    values=[f"... ({_MAX_PREVIEW_ROWS} rows shown)"]
                    + [""] * (col_count - 1),
                )

            # Re-show
            if pack_info:
                tree.pack(**{k: v for k, v in pack_info.items()
                            if k != "in"})
            else:
                tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        except Exception:
            tree["columns"] = ("error",)
            tree.heading("error", text="Error")
            tree.column("error", width=400)
            tree.insert("", tk.END, values=("Could not read CSV file",))

    # ── File operations ──────────────────────────────────────────

    def _open_selected_file(self) -> None:
        sel = self._file_listbox.curselection()
        if not sel:
            return
        path = self._files[sel[0]]
        self._open_path(path)

    def _open_containing_folder(self) -> None:
        sel = self._file_listbox.curselection()
        if not sel:
            return
        folder = os.path.dirname(self._files[sel[0]])
        self._open_path(folder)

    @staticmethod
    def _open_path(path: str) -> None:
        """Open a file or directory in the system file manager."""
        system = platform.system()
        try:
            if system == "Darwin":
                subprocess.Popen(["open", path])
            elif system == "Linux":
                subprocess.Popen(["xdg-open", path])
            elif system == "Windows":
                os.startfile(path)  # type: ignore[attr-defined]
        except Exception:
            pass
