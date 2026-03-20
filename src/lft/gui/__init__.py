"""
Linux Forensics Toolkit — Tkinter GUI package.

Re-exports the public API so that existing imports like
``from lft.gui import main`` and ``lft.gui:main`` continue to work.
"""

from lft.gui.app import ForensicToolkitGUI, main

__all__ = ["ForensicToolkitGUI", "main"]
