#!/usr/bin/env python3
"""
linux_forensics_gui.py — Professional dark-themed GUI for Linux Forensics Toolkit

A log-viewer-style desktop application for running and exploring Linux incident
response analysis results.  Requires PyQt6:

    pip install PyQt6

Usage:
    python3 linux_forensics_gui.py
"""

import csv
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QRegularExpression,
    QSize,
    QSortFilterProxyModel,
    Qt,
    QThread,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QAction,
    QBrush,
    QColor,
    QFont,
    QFontDatabase,
    QPalette,
    QTextCharFormat,
    QTextCursor,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableView,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Colour palette (Tokyo Night-inspired, forensics feel)
# ---------------------------------------------------------------------------
C = {
    "bg_base":    "#16161e",
    "bg_surface": "#1a1b26",
    "bg_panel":   "#1f2335",
    "bg_header":  "#1f2335",
    "bg_row_alt": "#1e2030",
    "bg_hover":   "#292e42",
    "bg_select":  "#2d3f77",
    "border":     "#3b4261",
    "text_prim":  "#c0caf5",
    "text_dim":   "#565f89",
    "text_bright":"#ffffff",
    "accent":     "#7aa2f7",
    "accent2":    "#7dcfff",
    "sev_critical":"#f7768e",
    "sev_high":   "#ff9e64",
    "sev_medium": "#e0af68",
    "sev_low":    "#9ece6a",
    "sev_info":   "#7aa2f7",
    "sev_crit_bg":"#2d1520",
    "sev_high_bg":"#2d1f15",
    "sev_med_bg": "#2d2510",
    "sev_low_bg": "#1a2d20",
    "sev_info_bg":"#1a2035",
}

STYLESHEET = f"""
/* ── Base ── */
QMainWindow, QDialog {{
    background-color: {C['bg_base']};
}}
QWidget {{
    background-color: {C['bg_surface']};
    color: {C['text_prim']};
    font-size: 12px;
}}

/* ── Menu bar ── */
QMenuBar {{
    background-color: {C['bg_panel']};
    color: {C['text_prim']};
    border-bottom: 1px solid {C['border']};
    padding: 2px 4px;
}}
QMenuBar::item {{
    padding: 5px 12px;
    border-radius: 4px;
    background: transparent;
}}
QMenuBar::item:selected {{
    background-color: {C['bg_hover']};
}}
QMenu {{
    background-color: {C['bg_panel']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 28px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background-color: {C['bg_select']};
}}
QMenu::separator {{
    height: 1px;
    background: {C['border']};
    margin: 4px 8px;
}}

/* ── Toolbar ── */
QToolBar {{
    background-color: {C['bg_panel']};
    border-bottom: 1px solid {C['border']};
    padding: 4px 6px;
    spacing: 4px;
}}
QToolButton {{
    background-color: transparent;
    color: {C['text_prim']};
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 14px;
    font-size: 12px;
}}
QToolButton:hover {{
    background-color: {C['bg_hover']};
    border-color: {C['border']};
}}
QToolButton:pressed {{
    background-color: {C['bg_select']};
}}

/* ── Sidebar ── */
#sidebar {{
    background-color: {C['bg_panel']};
    border-right: 1px solid {C['border']};
}}

/* ── Group box ── */
QGroupBox {{
    background-color: {C['bg_panel']};
    color: {C['accent']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    margin-top: 14px;
    padding: 10px 8px 8px 8px;
    font-weight: 600;
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: {C['accent']};
    top: -2px;
}}

/* ── Labels ── */
QLabel {{
    color: {C['text_prim']};
    background-color: transparent;
}}
QLabel#app_title {{
    font-size: 17px;
    font-weight: 700;
    color: {C['text_bright']};
}}
QLabel#app_sub {{
    font-size: 11px;
    color: {C['text_dim']};
}}
QLabel#section_header {{
    font-size: 11px;
    font-weight: 600;
    color: {C['text_dim']};
    letter-spacing: 1px;
    text-transform: uppercase;
}}

/* ── Line edit ── */
QLineEdit {{
    background-color: {C['bg_surface']};
    color: {C['text_prim']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {C['bg_select']};
}}
QLineEdit:focus {{
    border-color: {C['accent']};
}}
QLineEdit:disabled {{
    background-color: {C['bg_base']};
    color: {C['text_dim']};
}}

/* ── Buttons ── */
QPushButton {{
    background-color: {C['bg_surface']};
    color: {C['text_prim']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: {C['bg_hover']};
    border-color: {C['accent']};
}}
QPushButton:pressed {{
    background-color: {C['bg_select']};
}}
QPushButton#run_btn {{
    background-color: {C['accent']};
    color: #16161e;
    font-weight: 700;
    font-size: 13px;
    padding: 10px 0;
    border: none;
    border-radius: 8px;
    letter-spacing: 0.5px;
}}
QPushButton#run_btn:hover {{
    background-color: #89b4ff;
}}
QPushButton#run_btn:pressed {{
    background-color: #5d8ef0;
}}
QPushButton#run_btn:disabled {{
    background-color: {C['border']};
    color: {C['text_dim']};
}}
QPushButton#load_btn {{
    background-color: {C['bg_hover']};
    color: {C['accent']};
    border: 1px solid {C['accent']};
    border-radius: 6px;
    padding: 6px 0;
    font-size: 12px;
    font-weight: 600;
}}
QPushButton#load_btn:hover {{
    background-color: {C['bg_select']};
}}
QPushButton#browse_btn {{
    background-color: {C['bg_hover']};
    border: 1px solid {C['border']};
    border-radius: 5px;
    padding: 5px 10px;
    min-width: 32px;
    max-width: 32px;
    font-size: 13px;
}}

/* ── CheckBox ── */
QCheckBox {{
    color: {C['text_prim']};
    spacing: 8px;
    background-color: transparent;
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {C['border']};
    border-radius: 3px;
    background-color: {C['bg_surface']};
}}
QCheckBox::indicator:checked {{
    background-color: {C['accent']};
    border-color: {C['accent']};
}}
QCheckBox::indicator:hover {{
    border-color: {C['accent']};
}}

/* ── SpinBox ── */
QSpinBox {{
    background-color: {C['bg_surface']};
    color: {C['text_prim']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 5px 8px;
}}
QSpinBox:focus {{
    border-color: {C['accent']};
}}
QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {C['bg_hover']};
    border: none;
    border-radius: 3px;
    width: 18px;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
    background-color: {C['bg_select']};
}}

/* ── ComboBox ── */
QComboBox {{
    background-color: {C['bg_surface']};
    color: {C['text_prim']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 5px 10px;
}}
QComboBox:hover {{
    border-color: {C['accent']};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox::down-arrow {{
    width: 10px;
    height: 10px;
}}
QComboBox QAbstractItemView {{
    background-color: {C['bg_panel']};
    color: {C['text_prim']};
    border: 1px solid {C['border']};
    selection-background-color: {C['bg_select']};
    outline: none;
}}

/* ── Tab widget ── */
QTabWidget::pane {{
    background-color: {C['bg_surface']};
    border: none;
    border-top: 1px solid {C['border']};
}}
QTabBar {{
    background-color: {C['bg_panel']};
    border-bottom: 1px solid {C['border']};
}}
QTabBar::tab {{
    background-color: {C['bg_panel']};
    color: {C['text_dim']};
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 16px;
    margin-right: 1px;
    font-size: 12px;
}}
QTabBar::tab:selected {{
    color: {C['text_prim']};
    border-bottom: 2px solid {C['accent']};
    background-color: {C['bg_surface']};
}}
QTabBar::tab:hover:!selected {{
    color: #a9b1d6;
    background-color: {C['bg_hover']};
    border-bottom: 2px solid {C['border']};
}}
QTabBar::close-button {{
    image: none;
    subcontrol-position: right;
}}

/* ── Table view ── */
QTableView {{
    background-color: {C['bg_surface']};
    color: {C['text_prim']};
    gridline-color: #252840;
    border: none;
    selection-background-color: {C['bg_select']};
    alternate-background-color: {C['bg_row_alt']};
    font-size: 12px;
    font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace;
}}
QTableView::item {{
    padding: 3px 8px;
    border: none;
}}
QTableView::item:selected {{
    background-color: {C['bg_select']};
    color: {C['text_bright']};
}}
QHeaderView {{
    background-color: {C['bg_header']};
}}
QHeaderView::section {{
    background-color: {C['bg_header']};
    color: {C['accent']};
    border: none;
    border-right: 1px solid {C['border']};
    border-bottom: 2px solid {C['border']};
    padding: 7px 8px;
    font-weight: 700;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}}
QHeaderView::section:hover {{
    background-color: {C['bg_hover']};
    color: {C['text_bright']};
}}
QHeaderView::section:checked {{
    background-color: {C['bg_select']};
}}

/* ── Scrollbars ── */
QScrollBar:vertical {{
    background-color: {C['bg_base']};
    width: 10px;
    margin: 0;
    border-radius: 5px;
}}
QScrollBar::handle:vertical {{
    background-color: {C['border']};
    border-radius: 5px;
    min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {C['text_dim']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background-color: {C['bg_base']};
    height: 10px;
    margin: 0;
    border-radius: 5px;
}}
QScrollBar::handle:horizontal {{
    background-color: {C['border']};
    border-radius: 5px;
    min-width: 28px;
}}
QScrollBar::handle:horizontal:hover {{
    background-color: {C['text_dim']};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* ── Text edit ── */
QTextEdit {{
    background-color: {C['bg_surface']};
    color: {C['text_prim']};
    border: none;
    selection-background-color: {C['bg_select']};
    font-size: 12px;
}}

/* ── Progress bar ── */
QProgressBar {{
    background-color: {C['bg_surface']};
    border: none;
    border-radius: 3px;
    text-align: center;
    font-size: 10px;
    height: 6px;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {C['accent']};
    border-radius: 3px;
}}

/* ── Status bar ── */
QStatusBar {{
    background-color: {C['bg_panel']};
    color: {C['text_dim']};
    border-top: 1px solid {C['border']};
    font-size: 11px;
    padding: 2px 8px;
}}

/* ── Splitter ── */
QSplitter::handle {{
    background-color: {C['border']};
}}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}
QSplitter::handle:hover {{
    background-color: {C['accent']};
}}

/* ── Scroll area ── */
QScrollArea {{
    background-color: {C['bg_panel']};
    border: none;
}}
QScrollArea > QWidget > QWidget {{
    background-color: {C['bg_panel']};
}}

/* ── Filter bar ── */
#filterbar {{
    background-color: {C['bg_panel']};
    border-bottom: 1px solid {C['border']};
}}

/* ── Frame separators ── */
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    background-color: {C['border']};
    border: none;
    max-height: 1px;
    max-width: 1px;
}}
"""

# ---------------------------------------------------------------------------
# Tab name map  (CSV filename suffix → human-readable label)
# ---------------------------------------------------------------------------
TAB_LABEL_MAP = {
    "_login_timeline.csv":       ("Login Timeline",      "🔑"),
    "_journal.csv":              ("Journal",             "📰"),
    "_journal_security.csv":     ("Security Events",     "🚨"),
    "_persistence.csv":          ("Persistence",         "🔗"),
    "_security_binaries.csv":    ("Suspicious Binaries", "⚠"),
    "_security_suid.csv":        ("SUID / SGID",         "⚠"),
    "_security_environment.csv": ("Env Anomalies",       "⚙"),
    "_packages.csv":             ("Packages",            "📦"),
    "_network.csv":              ("Network",             "🌐"),
    "_web_access.csv":           ("Web Access",          "🕸"),
    "_mac_timeline.csv":         ("MAC Timeline",        "🗂"),
    "_audit_logs.csv":           ("Audit Logs",          "📋"),
    "_syslog_extracted.csv":     ("Syslog",              "📄"),
    "_web_logs.csv":             ("Web Logs",            "🕸"),
    "_archive_files.csv":        ("Archives",            "🗜"),
    "_hidden_directories.csv":   ("Hidden Dirs",         "👁"),
    "_scheduled_tasks.csv":      ("Scheduled Tasks",     "⏰"),
    "_log_gaps.csv":             ("Log Gaps",            "⚡"),
    "_ioc_hits.csv":             ("IOC Hits",            "🎯"),
    "_ioc_matches.csv":          ("IOC Matches",         "🎯"),
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

SEV_FG = {
    "CRITICAL": QColor(C["sev_critical"]),
    "HIGH":     QColor(C["sev_high"]),
    "MEDIUM":   QColor(C["sev_medium"]),
    "LOW":      QColor(C["sev_low"]),
    "INFO":     QColor(C["sev_info"]),
}

SEV_BG = {
    "CRITICAL": QColor(C["sev_crit_bg"]),
    "HIGH":     QColor(C["sev_high_bg"]),
    "MEDIUM":   QColor(C["sev_med_bg"]),
    "LOW":      QColor(C["sev_low_bg"]),
    "INFO":     QColor(C["sev_info_bg"]),
}

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
class ForensicsTableModel(QAbstractTableModel):
    """High-performance read-only model for CSV forensics data."""

    def __init__(self, headers: List[str], rows: List[List[str]], parent=None):
        super().__init__(parent)
        self._headers = headers
        self._rows = rows
        self._severities: List[Optional[str]] = [
            self._row_severity(r) for r in rows
        ]

    # ── severity helper ──────────────────────────────────────────────────────
    @staticmethod
    def _row_severity(row: List[str]) -> Optional[str]:
        best, best_p = None, -1
        for cell in row:
            v = str(cell).strip().upper()
            p = SEVERITY_ORDER.get(v, -1)
            if p > best_p:
                best, best_p = v, p
        return best if best_p >= 0 else None

    # ── QAbstractTableModel interface ────────────────────────────────────────
    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self._headers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        r, c = index.row(), index.column()
        if r >= len(self._rows):
            return None

        row = self._rows[r]
        cell = str(row[c]) if c < len(row) else ""

        if role == Qt.ItemDataRole.DisplayRole:
            return cell

        if role == Qt.ItemDataRole.ForegroundRole:
            # Cells that ARE a severity keyword get the severity colour
            cv = cell.strip().upper()
            if cv in SEV_FG:
                return QBrush(SEV_FG[cv])
            # Otherwise dim non-severity rows slightly based on row severity
            sev = self._severities[r]
            if sev:
                return QBrush(SEV_FG[sev].lighter(150))
            return None

        if role == Qt.ItemDataRole.BackgroundRole:
            sev = self._severities[r]
            if sev:
                return QBrush(SEV_BG[sev])
            return None

        if role == Qt.ItemDataRole.FontRole:
            cv = cell.strip().upper()
            if cv in SEV_FG:
                f = QFont()
                f.setBold(True)
                return f
            return None

        if role == Qt.ItemDataRole.ToolTipRole and len(cell) > 80:
            return cell

        return None

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ):
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal:
                return (
                    self._headers[section]
                    if section < len(self._headers)
                    else ""
                )
            return str(section + 1)
        return None

    # ── public helpers ───────────────────────────────────────────────────────
    @property
    def headers(self) -> List[str]:
        return self._headers

    @property
    def total_rows(self) -> int:
        return len(self._rows)


# ---------------------------------------------------------------------------
# Multi-column filter proxy
# ---------------------------------------------------------------------------
class ForensicsFilterProxy(QSortFilterProxyModel):
    """Proxy that searches across all columns (or a single chosen column)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._col = -1  # -1 → all columns
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_filter(self, text: str, col: int = -1):
        self._text = text.lower()
        self._col = col
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._text:
            return True
        model = self.sourceModel()
        if model is None:
            return True
        cols = (
            range(model.columnCount())
            if self._col == -1
            else [self._col]
        )
        for c in cols:
            idx = model.index(source_row, c, source_parent)
            val = model.data(idx, Qt.ItemDataRole.DisplayRole) or ""
            if self._text in val.lower():
                return True
        return False


# ---------------------------------------------------------------------------
# CSV table widget (filter bar + table)
# ---------------------------------------------------------------------------
class CSVTableWidget(QWidget):
    """Sortable, filterable viewer for a single CSV file."""

    def __init__(self, csv_path: str, parent=None):
        super().__init__(parent)
        self._path = csv_path
        self._model: Optional[ForensicsTableModel] = None
        self._proxy: Optional[ForensicsFilterProxy] = None
        self._build_ui()
        self._load(csv_path)

    # ── UI construction ──────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── filter bar ──────────────────────────────────────────────────────
        fb = QWidget()
        fb.setObjectName("filterbar")
        fl = QHBoxLayout(fb)
        fl.setContentsMargins(10, 7, 10, 7)
        fl.setSpacing(8)

        lbl_search = QLabel("🔍")
        lbl_search.setStyleSheet(
            f"font-size: 14px; background: transparent; color: {C['text_dim']};"
        )
        fl.addWidget(lbl_search)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter rows…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._on_filter)
        fl.addWidget(self._search, 1)

        fl.addWidget(
            QLabel("in", styleSheet=f"color:{C['text_dim']};background:transparent;")
        )

        self._col_combo = QComboBox()
        self._col_combo.setFixedWidth(160)
        self._col_combo.addItem("All Columns", -1)
        self._col_combo.currentIndexChanged.connect(self._on_filter)
        fl.addWidget(self._col_combo)

        fl.addStretch()

        self._count_lbl = QLabel(
            "0 rows",
            styleSheet=f"color:{C['text_dim']};font-size:11px;background:transparent;",
        )
        fl.addWidget(self._count_lbl)

        root.addWidget(fb)

        # ── table ────────────────────────────────────────────────────────────
        self._table = QTableView()
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self._table.setSortingEnabled(True)
        self._table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setDefaultSectionSize(24)
        self._table.verticalHeader().hide()
        self._table.setShowGrid(True)
        self._table.setWordWrap(False)
        root.addWidget(self._table)

    # ── data loading ─────────────────────────────────────────────────────────
    def _load(self, path: str):
        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as fh:
                rows = list(csv.reader(fh))
        except OSError as exc:
            self._show_error(str(exc))
            return

        if not rows:
            self._show_error("CSV file is empty.")
            return

        headers, data = rows[0], rows[1:]
        self._model = ForensicsTableModel(headers, data)
        self._proxy = ForensicsFilterProxy()
        self._proxy.setSourceModel(self._model)
        self._table.setModel(self._proxy)

        # Column selector
        self._col_combo.clear()
        self._col_combo.addItem("All Columns", -1)
        for i, h in enumerate(headers):
            self._col_combo.addItem(h, i)

        # Auto-size timestamp / short columns
        for i in range(min(4, len(headers))):
            self._table.resizeColumnToContents(i)

        self._refresh_count()

    def _show_error(self, msg: str):
        lbl = QLabel(f"⚠  {msg}")
        lbl.setStyleSheet(
            f"color:{C['sev_critical']};padding:24px;background:transparent;"
        )
        self.layout().addWidget(lbl)

    # ── filter ───────────────────────────────────────────────────────────────
    def _on_filter(self):
        if not self._proxy:
            return
        col = self._col_combo.currentData()
        self._proxy.set_filter(self._search.text(), col if col is not None else -1)
        self._refresh_count()

    def _refresh_count(self):
        if not self._proxy or not self._model:
            return
        shown = self._proxy.rowCount()
        total = self._model.total_rows
        if shown == total:
            self._count_lbl.setText(f"{total:,} rows")
        else:
            self._count_lbl.setText(f"{shown:,} / {total:,} rows")

    # ── context menu ─────────────────────────────────────────────────────────
    def _context_menu(self, pos):
        menu = QMenu(self)
        act_cell = menu.addAction("📋  Copy Cell Value")
        act_row = menu.addAction("📋  Copy Row (Tab-separated)")
        menu.addSeparator()
        act_export = menu.addAction("💾  Export Filtered Results…")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))
        idx = self._table.indexAt(pos)

        if action == act_cell and idx.isValid():
            val = self._proxy.data(idx, Qt.ItemDataRole.DisplayRole) or ""
            QApplication.clipboard().setText(str(val))

        elif action == act_row and idx.isValid():
            src_row = self._proxy.mapToSource(
                self._proxy.index(idx.row(), 0)
            ).row()
            cells = []
            for c in range(self._model.columnCount()):
                v = self._model.data(
                    self._model.index(src_row, c), Qt.ItemDataRole.DisplayRole
                )
                cells.append(str(v) if v else "")
            QApplication.clipboard().setText("\t".join(cells))

        elif action == act_export:
            self._export_filtered()

    def _export_filtered(self):
        if not self._proxy or not self._model:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Filtered CSV", "", "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(self._model.headers)
                for r in range(self._proxy.rowCount()):
                    row_data = []
                    for c in range(self._model.columnCount()):
                        src = self._proxy.mapToSource(self._proxy.index(r, c))
                        v = self._model.data(src, Qt.ItemDataRole.DisplayRole)
                        row_data.append(str(v) if v else "")
                    w.writerow(row_data)
            QMessageBox.information(
                self,
                "Export Complete",
                f"Exported {self._proxy.rowCount():,} rows to:\n{path}",
            )
        except OSError as exc:
            QMessageBox.critical(self, "Export Error", str(exc))


# ---------------------------------------------------------------------------
# Summary viewer (rich text with colour-coded sections)
# ---------------------------------------------------------------------------
class SummaryWidget(QWidget):
    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._edit = QTextEdit()
        self._edit.setReadOnly(True)
        mono = QFont("Consolas", 12)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._edit.setFont(mono)
        self._edit.setStyleSheet(
            f"QTextEdit {{ background:{C['bg_surface']}; color:{C['text_prim']}; "
            f"font-family:'Consolas','Courier New',monospace; font-size:12px; }}"
        )
        layout.addWidget(self._edit)

        if text:
            self.set_text(text)

    def set_text(self, text: str):
        # Build coloured HTML
        lines = text.splitlines()
        html_lines = []
        for line in lines:
            escaped = (
                line.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            if any(
                kw in line.upper()
                for kw in ("CRITICAL", "!! ", "!!", "[CRITICAL]")
            ):
                colour = C["sev_critical"]
            elif any(kw in line.upper() for kw in ("HIGH", "[HIGH]")):
                colour = C["sev_high"]
            elif any(kw in line.upper() for kw in ("MEDIUM", "[MEDIUM]", "WARN")):
                colour = C["sev_medium"]
            elif any(kw in line.upper() for kw in ("LOW", "[LOW]", "[OK]", "✓", "✔")):
                colour = C["sev_low"]
            elif line.startswith("=") or line.startswith("-"):
                colour = C["accent"]
            elif line.startswith("  Analysis") or line.startswith("  Hostname"):
                colour = C["accent2"]
            else:
                colour = C["text_prim"]
            html_lines.append(
                f'<span style="color:{colour};">{escaped}</span>'
            )
        self._edit.setHtml(
            f'<pre style="margin:0;padding:12px;line-height:1.5;">'
            + "<br>".join(html_lines)
            + "</pre>"
        )


# ---------------------------------------------------------------------------
# Console widget (live analysis output)
# ---------------------------------------------------------------------------
class ConsoleWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._edit = QTextEdit()
        self._edit.setReadOnly(True)
        mono = QFont("Consolas", 11)
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self._edit.setFont(mono)
        self._edit.setStyleSheet(
            f"QTextEdit {{ background:{C['bg_base']}; color:{C['text_prim']}; "
            f"font-family:'Consolas','Courier New',monospace; font-size:11px; }}"
        )
        layout.addWidget(self._edit)

    def append(self, line: str):
        clean = ANSI_ESCAPE.sub("", line).rstrip()
        if not clean:
            return

        if any(kw in clean for kw in ("CRITICAL", "!!")):
            colour = C["sev_critical"]
        elif "HIGH" in clean:
            colour = C["sev_high"]
        elif any(kw in clean for kw in ("MEDIUM", "WARN", "Warning")):
            colour = C["sev_medium"]
        elif "✓" in clean or "complete" in clean.lower() or "done" in clean.lower():
            colour = C["sev_low"]
        elif "Error" in clean or "error" in clean or "failed" in clean.lower():
            colour = C["sev_critical"]
        else:
            colour = C["text_prim"]

        escaped = (
            clean.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        self._edit.append(
            f'<span style="color:{colour};">{escaped}</span>'
        )
        # Auto-scroll
        sb = self._edit.verticalScrollBar()
        sb.setValue(sb.maximum())

    def clear(self):
        self._edit.clear()


# ---------------------------------------------------------------------------
# Results tab panel
# ---------------------------------------------------------------------------
class ResultsPanel(QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self._on_close_tab)
        self._protected_indices: set = set()  # tabs that cannot be closed
        self._console: Optional[ConsoleWidget] = None

        self._add_welcome_tab()

    # ── welcome ──────────────────────────────────────────────────────────────
    def _add_welcome_tab(self):
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.setSpacing(16)

        icon_lbl = QLabel("🔍")
        icon_lbl.setStyleSheet(
            "font-size: 56px; background: transparent; color: #c0caf5;"
        )
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(icon_lbl)

        title = QLabel("Linux Forensics Toolkit")
        title.setStyleSheet(
            f"font-size:22px; font-weight:700; color:{C['text_bright']}; background:transparent;"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(title)

        hint = QLabel(
            "Select a UAC source on the left and click  ▶  Run Analysis\n"
            "or open an existing  *_analysis/  directory."
        )
        hint.setStyleSheet(
            f"font-size:13px; color:{C['text_dim']}; background:transparent;"
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setWordWrap(True)
        vl.addWidget(hint)

        idx = self.addTab(w, "  Welcome  ")
        self._protect(idx)

    # ── tab management ───────────────────────────────────────────────────────
    def _protect(self, idx: int):
        self._protected_indices.add(idx)
        # Remove close button
        tb = self.tabBar()
        if hasattr(tb, "setTabButton"):
            tb.setTabButton(
                idx,
                tb.ButtonPosition.RightSide,  # type: ignore[attr-defined]
                None,
            )

    def _on_close_tab(self, idx: int):
        if idx not in self._protected_indices:
            self.removeTab(idx)
            # Re-sync protected set
            self._protected_indices = {
                i for i in self._protected_indices if i < self.count()
            }

    # ── public API ───────────────────────────────────────────────────────────
    def add_console_tab(self) -> ConsoleWidget:
        """Create (or reuse) the Console tab and return it."""
        if self._console is None:
            self._console = ConsoleWidget()
            idx = self.addTab(self._console, "  Console  ")
            self._protect(idx)
        return self._console

    def add_summary_tab(self, text: str):
        # Remove any existing summary tab
        for i in range(self.count()):
            if self.tabText(i).strip() in ("📋  Summary", "Summary"):
                self.removeTab(i)
                break
        w = SummaryWidget(text)
        idx = self.insertTab(1, w, "📋  Summary")
        self._protect(idx)
        self.setCurrentIndex(idx)

    def add_csv_tab(self, csv_path: str, label: str, icon: str = ""):
        # Skip if already open
        full_label = f"{icon}  {label}" if icon else label
        for i in range(self.count()):
            if self.tabText(i).strip() == full_label.strip():
                return
        w = CSVTableWidget(csv_path)
        self.addTab(w, f" {full_label} ")
        self.setCurrentIndex(self.count() - 1)

    def load_directory(self, output_dir: str):
        """Load all CSVs and summary from an analysis output directory."""
        self.clear_results()
        out = Path(output_dir)

        # Summary first
        for txt in sorted(out.glob("*_analysis_summary.txt")):
            try:
                self.add_summary_tab(
                    txt.read_text(encoding="utf-8", errors="replace")
                )
            except OSError:
                pass

        added_names: set = set()

        # Ordered tabs per TAB_LABEL_MAP
        for suffix, (label, icon) in TAB_LABEL_MAP.items():
            for csv_file in sorted(out.glob(f"*{suffix}")):
                self.add_csv_tab(str(csv_file), label, icon)
                added_names.add(csv_file.name)

        # Any remaining CSVs not in the map
        for csv_file in sorted(out.glob("*.csv")):
            if csv_file.name not in added_names:
                label = csv_file.stem.replace("_", " ").title()
                self.add_csv_tab(str(csv_file), label, "📄")

    def clear_results(self):
        while self.count() > 0:
            self.removeTab(0)
        self._console = None
        self._protected_indices.clear()
        self._add_welcome_tab()


# ---------------------------------------------------------------------------
# Background analysis worker
# ---------------------------------------------------------------------------
class AnalysisWorker(QThread):
    progress = pyqtSignal(str, int)       # (message, 0–100)
    csv_ready = pyqtSignal(str, str, str)  # (path, label, icon)
    summary_ready = pyqtSignal(str)
    log_line = pyqtSignal(str)
    finished = pyqtSignal(str, bool, str)  # (output_dir, success, error)

    def __init__(self, source: str, options: dict, parent=None):
        super().__init__(parent)
        self._source = source
        self._options = options
        self._toolkit_dir = Path(__file__).parent
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    # ── run ──────────────────────────────────────────────────────────────────
    def run(self):
        cmd = self._build_cmd()
        if not cmd:
            self.finished.emit(
                "", False, "Could not locate linux_analyzer.py or the 'lfa' command."
            )
            return

        self.progress.emit("Starting analysis…", 2)
        self.log_line.emit(f"$ {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(
                cmd,
                shell=False,          # explicit: cmd is a list, no shell interpretation
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=str(self._toolkit_dir),
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            self.finished.emit("", False, f"Failed to start analysis: {exc}")
            return

        completed_steps = 0
        total_steps = max(
            sum(1 for k, v in self._options.items() if k.startswith("run_") and v),
            10,
        )

        for raw_line in proc.stdout:  # type: ignore[union-attr]
            if self._cancelled:
                proc.terminate()
                self.finished.emit("", False, "Cancelled by user.")
                return

            line = ANSI_ESCAPE.sub("", raw_line).rstrip()
            if line:
                self.log_line.emit(line)

            lo = line.lower()
            if "✓" in line or "complete" in lo or "finished" in lo:
                completed_steps += 1
                pct = min(90, int(completed_steps / total_steps * 88) + 2)
                self.progress.emit(line.replace("✓", "").strip() or "Step done", pct)
            elif "running" in lo or "analyzing" in lo or "parsing" in lo:
                pct = min(
                    88, int(completed_steps / total_steps * 88) + 2 + 2
                )
                self.progress.emit(line.strip(), pct)

        proc.wait()

        if proc.returncode not in (0, None) and not self._cancelled:
            self.finished.emit(
                "", False, f"Analysis exited with code {proc.returncode}."
            )
            return

        output_dir = self._locate_output_dir()
        if output_dir:
            self.progress.emit("Loading results…", 92)
            self._emit_results(output_dir)
            self.progress.emit("Analysis complete", 100)
            self.finished.emit(output_dir, True, "")
        else:
            self.finished.emit("", False, "Output directory not found.")

    # ── helpers ──────────────────────────────────────────────────────────────
    def _build_cmd(self) -> Optional[List[str]]:
        analyzer = self._toolkit_dir / "linux_analyzer.py"
        if analyzer.exists():
            cmd: List[str] = [sys.executable, str(analyzer)]
        else:
            lfa_path = shutil.which("lfa")
            if lfa_path:
                cmd = [lfa_path]
            else:
                return None

        opts = self._options
        cmd += ["-s", self._source]

        if opts.get("ioc_file"):
            cmd += ["--ioc", opts["ioc_file"]]
        if opts.get("gap_hours", 6) != 6:
            cmd += ["--gap", str(opts["gap_hours"])]
        if opts.get("memory_image"):
            cmd += ["-m", opts["memory_image"]]
        if opts.get("verbose"):
            cmd += ["-v"]

        return cmd

    def _locate_output_dir(self) -> Optional[str]:
        src = Path(self._source)
        stem = src.stem
        # Strip compression extensions from stem (e.g. .tar from .tar.gz)
        while "." in stem:
            stem = Path(stem).stem
            break

        for base in (src.parent, Path.cwd(), self._toolkit_dir):
            cand = base / f"{stem}_analysis"
            if cand.is_dir():
                return str(cand)

        # Broader scan
        for p in src.parent.iterdir():
            if p.is_dir() and p.name.endswith("_analysis"):
                return str(p)

        return None

    def _emit_results(self, output_dir: str):
        out = Path(output_dir)

        for txt in sorted(out.glob("*_analysis_summary.txt")):
            try:
                self.summary_ready.emit(
                    txt.read_text(encoding="utf-8", errors="replace")
                )
            except OSError:
                pass

        added: set = set()
        for suffix, (label, icon) in TAB_LABEL_MAP.items():
            for csv_file in sorted(out.glob(f"*{suffix}")):
                self.csv_ready.emit(str(csv_file), label, icon)
                added.add(csv_file.name)

        for csv_file in sorted(out.glob("*.csv")):
            if csv_file.name not in added:
                label = csv_file.stem.replace("_", " ").title()
                self.csv_ready.emit(str(csv_file), label, "📄")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
class AnalysisSidebar(QWidget):
    run_requested = pyqtSignal(dict)
    open_results_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(270)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Scrollable inner content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            f"QScrollArea {{ background:{C['bg_panel']}; border:none; }}"
        )

        inner = QWidget()
        inner.setStyleSheet(f"background:{C['bg_panel']};")
        vl = QVBoxLayout(inner)
        vl.setContentsMargins(14, 14, 14, 14)
        vl.setSpacing(12)

        # ── App header ────────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        icon_lbl = QLabel("🔍")
        icon_lbl.setStyleSheet("font-size:28px;background:transparent;")
        hdr.addWidget(icon_lbl)

        name_vl = QVBoxLayout()
        name_vl.setSpacing(0)
        t1 = QLabel("Linux Forensics")
        t1.setObjectName("app_title")
        t2 = QLabel("Analysis Toolkit")
        t2.setObjectName("app_sub")
        name_vl.addWidget(t1)
        name_vl.addWidget(t2)
        hdr.addLayout(name_vl)
        hdr.addStretch()
        vl.addLayout(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        vl.addWidget(sep)

        # ── Source input ──────────────────────────────────────────────────────
        src_grp = QGroupBox("Source")
        sg = QVBoxLayout(src_grp)
        sg.setSpacing(6)

        sg.addWidget(
            QLabel("UAC tarball or directory:", styleSheet=f"color:{C['text_dim']};font-size:11px;")
        )
        src_row = QHBoxLayout()
        self._src_edit = QLineEdit()
        self._src_edit.setPlaceholderText("/path/to/uac_output.tar.gz")
        src_row.addWidget(self._src_edit)
        src_btn = QPushButton("…")
        src_btn.setObjectName("browse_btn")
        src_btn.clicked.connect(self._browse_source)
        src_row.addWidget(src_btn)
        sg.addLayout(src_row)

        sg.addWidget(
            QLabel("IOC file (optional):", styleSheet=f"color:{C['text_dim']};font-size:11px;")
        )
        ioc_row = QHBoxLayout()
        self._ioc_edit = QLineEdit()
        self._ioc_edit.setPlaceholderText("iocs.txt")
        ioc_row.addWidget(self._ioc_edit)
        ioc_btn = QPushButton("…")
        ioc_btn.setObjectName("browse_btn")
        ioc_btn.clicked.connect(self._browse_ioc)
        ioc_row.addWidget(ioc_btn)
        sg.addLayout(ioc_row)

        sg.addWidget(
            QLabel("Memory image (optional):", styleSheet=f"color:{C['text_dim']};font-size:11px;")
        )
        mem_row = QHBoxLayout()
        self._mem_edit = QLineEdit()
        self._mem_edit.setPlaceholderText("memory.raw")
        mem_row.addWidget(self._mem_edit)
        mem_btn = QPushButton("…")
        mem_btn.setObjectName("browse_btn")
        mem_btn.clicked.connect(self._browse_memory)
        mem_row.addWidget(mem_btn)
        sg.addLayout(mem_row)

        vl.addWidget(src_grp)

        # ── Open existing results ─────────────────────────────────────────────
        res_grp = QGroupBox("Open Existing Results")
        rg = QVBoxLayout(res_grp)
        rg.setSpacing(6)
        rg.addWidget(
            QLabel("Analysis directory:", styleSheet=f"color:{C['text_dim']};font-size:11px;")
        )
        res_row = QHBoxLayout()
        self._res_edit = QLineEdit()
        self._res_edit.setPlaceholderText("*_analysis/")
        res_row.addWidget(self._res_edit)
        res_btn = QPushButton("…")
        res_btn.setObjectName("browse_btn")
        res_btn.clicked.connect(self._browse_results)
        res_row.addWidget(res_btn)
        rg.addLayout(res_row)

        load_btn = QPushButton("Load Results")
        load_btn.setObjectName("load_btn")
        load_btn.clicked.connect(self._on_load)
        rg.addWidget(load_btn)
        vl.addWidget(res_grp)

        # ── Options ───────────────────────────────────────────────────────────
        opt_grp = QGroupBox("Options")
        og = QVBoxLayout(opt_grp)
        og.setSpacing(6)

        gap_row = QHBoxLayout()
        gap_row.addWidget(
            QLabel("Min log gap (hours):", styleSheet="background:transparent;")
        )
        self._gap_spin = QSpinBox()
        self._gap_spin.setRange(1, 168)
        self._gap_spin.setValue(6)
        self._gap_spin.setFixedWidth(64)
        gap_row.addWidget(self._gap_spin)
        gap_row.addStretch()
        og.addLayout(gap_row)

        self._verbose_cb = QCheckBox("Verbose output")
        og.addWidget(self._verbose_cb)

        vl.addWidget(opt_grp)
        vl.addStretch()

        scroll.setWidget(inner)
        root.addWidget(scroll, 1)

        # ── Run button + progress (outside scroll, always visible) ────────────
        bottom = QWidget()
        bottom.setStyleSheet(
            f"background:{C['bg_panel']};border-top:1px solid {C['border']};"
        )
        bl = QVBoxLayout(bottom)
        bl.setContentsMargins(14, 10, 14, 10)
        bl.setSpacing(6)

        self._run_btn = QPushButton("▶  Run Analysis")
        self._run_btn.setObjectName("run_btn")
        self._run_btn.clicked.connect(self._on_run)
        bl.addWidget(self._run_btn)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(5)
        bl.addWidget(self._progress_bar)

        self._status_lbl = QLabel(
            "Ready",
            styleSheet=f"color:{C['text_dim']};font-size:11px;background:transparent;",
        )
        self._status_lbl.setWordWrap(True)
        bl.addWidget(self._status_lbl)

        root.addWidget(bottom)

    # ── browse helpers ────────────────────────────────────────────────────────
    def _browse_source(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select UAC Tarball",
            "",
            "Archives (*.tar.gz *.tar.bz2 *.tar.xz *.tgz *.zip);;All Files (*)",
        )
        if not path:
            path = QFileDialog.getExistingDirectory(self, "Select UAC Directory")
        if path:
            self._src_edit.setText(path)

    def _browse_ioc(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select IOC File", "", "Text/CSV (*.txt *.csv);;All Files (*)"
        )
        if path:
            self._ioc_edit.setText(path)

    def _browse_memory(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Image",
            "",
            "Images (*.raw *.img *.mem *.dmp *.vmem);;All Files (*)",
        )
        if path:
            self._mem_edit.setText(path)

    def _browse_results(self):
        path = QFileDialog.getExistingDirectory(self, "Select Analysis Directory")
        if path:
            self._res_edit.setText(path)

    # ── actions ───────────────────────────────────────────────────────────────
    def _on_load(self):
        path = self._res_edit.text().strip()
        if path and Path(path).is_dir():
            self.open_results_requested.emit(path)
        else:
            QMessageBox.warning(
                self,
                "Directory Not Found",
                "Please select a valid analysis output directory.",
            )

    def _on_run(self):
        src = self._src_edit.text().strip()
        if not src:
            QMessageBox.warning(
                self, "No Source", "Please provide a UAC tarball or directory."
            )
            return
        if not Path(src).exists():
            QMessageBox.warning(self, "Not Found", f"Path does not exist:\n{src}")
            return

        opts = {
            "source": src,
            "ioc_file": self._ioc_edit.text().strip() or None,
            "memory_image": self._mem_edit.text().strip() or None,
            "gap_hours": self._gap_spin.value(),
            "verbose": self._verbose_cb.isChecked(),
        }
        self.run_requested.emit(opts)

    # ── state ─────────────────────────────────────────────────────────────────
    def set_running(self, running: bool):
        self._run_btn.setEnabled(not running)
        self._run_btn.setText(
            "⏳  Running…" if running else "▶  Run Analysis"
        )

    def update_progress(self, msg: str, pct: int):
        self._progress_bar.setValue(pct)
        truncated = msg if len(msg) <= 48 else msg[:45] + "…"
        self._status_lbl.setText(truncated)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux Forensics Toolkit")
        self.setMinimumSize(1100, 720)
        self.resize(1440, 900)

        self._worker: Optional[AnalysisWorker] = None
        self._console: Optional[ConsoleWidget] = None

        self._build_ui()
        self._build_menu()
        self._build_statusbar()

    # ── layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        hl = QHBoxLayout(central)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.setSpacing(0)

        self._sidebar = AnalysisSidebar()
        self._sidebar.run_requested.connect(self._on_run)
        self._sidebar.open_results_requested.connect(self._on_open_results)
        hl.addWidget(self._sidebar)

        self._results = ResultsPanel()
        hl.addWidget(self._results, 1)

    # ── menu bar ──────────────────────────────────────────────────────────────
    def _build_menu(self):
        mb = self.menuBar()

        # File
        fm = mb.addMenu("&File")

        act_open = QAction("&Open Analysis Results…", self)
        act_open.setShortcut("Ctrl+O")
        act_open.triggered.connect(self._menu_open)
        fm.addAction(act_open)

        fm.addSeparator()

        act_quit = QAction("&Exit", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(self.close)
        fm.addAction(act_quit)

        # View
        vm = mb.addMenu("&View")

        act_clear = QAction("&Clear Results", self)
        act_clear.setShortcut("Ctrl+W")
        act_clear.triggered.connect(self._results.clear_results)
        vm.addAction(act_clear)

        act_console = QAction("Show &Console Tab", self)
        act_console.triggered.connect(self._show_console)
        vm.addAction(act_console)

        # Help
        hm = mb.addMenu("&Help")
        act_about = QAction("&About", self)
        act_about.triggered.connect(self._about)
        hm.addAction(act_about)

    # ── status bar ────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_lbl = QLabel("Ready")
        self._status_lbl.setStyleSheet(
            f"color:{C['text_dim']};background:transparent;"
        )
        sb.addWidget(self._status_lbl, 1)

        self._sb_progress = QProgressBar()
        self._sb_progress.setRange(0, 100)
        self._sb_progress.setTextVisible(False)
        self._sb_progress.setFixedWidth(180)
        self._sb_progress.setFixedHeight(10)
        self._sb_progress.setValue(0)
        sb.addPermanentWidget(self._sb_progress)

    # ── slots ─────────────────────────────────────────────────────────────────
    def _on_run(self, opts: dict):
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Analysis Running",
                "An analysis is already running.\nCancel it and start a new one?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._worker.cancel()
                self._worker.wait(3000)
            else:
                return

        self._results.clear_results()
        self._console = self._results.add_console_tab()
        self._console.clear()
        self._sidebar.set_running(True)
        self._sb_progress.setValue(0)
        self._status_lbl.setText(f"Analyzing:  {opts['source']}")

        self._worker = AnalysisWorker(opts["source"], opts)
        self._worker.progress.connect(self._on_progress)
        self._worker.csv_ready.connect(self._on_csv_ready)
        self._worker.summary_ready.connect(self._results.add_summary_tab)
        self._worker.log_line.connect(self._on_log_line)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    def _on_open_results(self, path: str):
        self._results.load_directory(path)
        self._status_lbl.setText(f"Loaded:  {path}")

    def _menu_open(self):
        path = QFileDialog.getExistingDirectory(self, "Open Analysis Directory")
        if path:
            self._on_open_results(path)

    def _show_console(self):
        self._results.add_console_tab()

    def _on_progress(self, msg: str, pct: int):
        self._sidebar.update_progress(msg, pct)
        self._sb_progress.setValue(pct)

    def _on_csv_ready(self, csv_path: str, label: str, icon: str):
        self._results.add_csv_tab(csv_path, label, icon)

    def _on_log_line(self, line: str):
        if self._console:
            self._console.append(line)
        if line.strip():
            self._status_lbl.setText(line[:100])

    def _on_finished(self, output_dir: str, success: bool, error: str):
        self._sidebar.set_running(False)
        self._sb_progress.setValue(100 if success else 0)

        if success:
            self._sidebar.update_progress("Analysis complete", 100)
            self._status_lbl.setText(f"Complete →  {output_dir}")
        else:
            self._sidebar.update_progress("Analysis failed", 0)
            self._status_lbl.setText(f"Error:  {error}")
            if error:
                QMessageBox.critical(self, "Analysis Failed", error)

    # ── about ─────────────────────────────────────────────────────────────────
    def _about(self):
        QMessageBox.about(
            self,
            "About Linux Forensics Toolkit",
            "<h3>Linux Forensics Toolkit — GUI</h3>"
            "<p>Professional incident response platform for Linux systems.</p>"
            "<p>Analyses UAC collections and detects persistence mechanisms, "
            "suspicious activity, and forensic artefacts across 40+ MITRE ATT&amp;CK "
            "techniques.</p>"
            "<hr>"
            "<p>GUI powered by <b>PyQt6</b><br>"
            "CLI entry point: <code>linux_analyzer.py</code></p>",
        )

    # ── close guard ───────────────────────────────────────────────────────────
    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Confirm Exit",
                "An analysis is still running.\nAre you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            self._worker.cancel()
            self._worker.wait(3000)
        event.accept()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Linux Forensics Toolkit")
    app.setOrganizationName("LinuxForensics")
    app.setStyleSheet(STYLESHEET)

    # Use a clean font if available
    for fam in ("Segoe UI", "Ubuntu", "Helvetica Neue", "Arial"):
        if fam in QFontDatabase.families():
            app.setFont(QFont(fam, 12))
            break

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
