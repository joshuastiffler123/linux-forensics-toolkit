# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for the Linux Forensics Toolkit GUI.

Build:
    pip install pyinstaller
    pyinstaller lft.spec

Output:
    dist/lft-gui          (single-file executable)
"""

import sys
from pathlib import Path

block_cipher = None

# Project root
ROOT = Path(SPECPATH)
SRC = ROOT / "src"

a = Analysis(
    [str(SRC / "lft" / "gui.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Ensure all analyzer modules are bundled even though they're
        # imported lazily inside wrapper functions in cli.py
        "lft",
        "lft.cli",
        "lft.core",
        "lft.core.config",
        "lft.core.errors",
        "lft.core.logging",
        "lft.core.style",
        "lft.core.uac",
        "lft.analyzers",
        "lft.analyzers.journal",
        "lft.analyzers.login_timeline",
        "lft.analyzers.persistence",
        "lft.analyzers.security",
        "lft.analyzers.memory",
        "lft.analyzers.packages",
        "lft.analyzers.network",
        "lft.analyzers.filesystem",
        "lft.analyzers.ioc",
        "lft.analyzers.misc",
        "lft.analyzers.strings",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Volatility 3 is optional — exclude to keep the bundle small.
        # Users who need memory analysis should run from source with
        # `pip install -e ".[memory]"` instead.
        "volatility3",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="lft-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # GUI app — no console window
    disable_windowed_traceback=False,
    argv_emulation=True,      # macOS: accept file drops
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
