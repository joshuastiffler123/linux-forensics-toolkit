#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Linux Forensics Toolkit — GUI launcher
#
# Usage:
#   ./run_gui.sh          # just open the GUI
#   bash run_gui.sh       # alternative
#
# On macOS you can also double-click  run_gui.command  in Finder.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Python discovery ──────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3 python3.12 python3.11 python3.10 python3.9 python; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python 3 not found on PATH." >&2
    exit 1
fi

PYVER=$("$PYTHON" -c "import sys; print(sys.version_info[:2])")
echo "Using $PYTHON  ($PYVER)"

# ── PyQt6 check / auto-install ────────────────────────────────────────────────
if ! "$PYTHON" -c "import PyQt6" 2>/dev/null; then
    echo ""
    echo "PyQt6 is not installed.  Installing now…"
    echo "(Run  pip install PyQt6  manually to skip this step in future)"
    echo ""
    "$PYTHON" -m pip install --quiet "PyQt6>=6.4.0"
fi

# ── Launch ────────────────────────────────────────────────────────────────────
echo "Starting Linux Forensics Toolkit GUI…"
exec "$PYTHON" "$SCRIPT_DIR/linux_forensics_gui.py" "$@"
