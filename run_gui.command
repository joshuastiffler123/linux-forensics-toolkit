#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Linux Forensics Toolkit — macOS double-click launcher
#
# Save this file, then in Finder:
#   • Right-click → Open  (first time, to allow running)
#   • Double-click from then on
#
# The .command extension tells macOS Terminal to execute this as a script.
# ─────────────────────────────────────────────────────────────────────────────

# Change to the directory this script lives in
cd "$(dirname "$0")"

# Delegate to the main launcher
bash run_gui.sh
