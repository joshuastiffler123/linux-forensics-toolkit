#!/usr/bin/env bash
# install.sh — Linux Forensics Toolkit quick-install
#
# Usage:
#   chmod +x install.sh && ./install.sh
#
# What it does:
#   1. Verifies Python 3.8+
#   2. Does an editable install (`pip install -e .`) so the `lfa` command
#      points to THIS directory — run `git pull` to get updates with no
#      reinstall required.
#   3. Optionally installs Volatility 3 for memory forensics.
#
# Editable vs. regular install:
#   Editable (-e) is recommended for analysts who clone the repo — changes
#   from `git pull` are picked up automatically.
#   For a standalone install to a venv, omit -e: `pip install .`

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[-]${RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# 1. Python version check
# ---------------------------------------------------------------------------
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>/dev/null)
        major=${ver%%.*}; minor=${ver##*.}
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            PYTHON="$cmd"
            info "Found $cmd $ver"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python 3.8+ is required but was not found."
    error "Install it from https://www.python.org/downloads/ and try again."
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. pip availability
# ---------------------------------------------------------------------------
PIP=""
for cmd in pip3 pip; do
    if "$PYTHON" -m pip --version &>/dev/null 2>&1; then
        PIP="$PYTHON -m pip"
        break
    fi
done

if [ -z "$PIP" ]; then
    error "pip not found. Install pip and try again."
    error "  $PYTHON -m ensurepip --upgrade"
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Editable install
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Installing linux-forensics-toolkit (editable) from $SCRIPT_DIR"
$PIP install -e "$SCRIPT_DIR" --quiet

# ---------------------------------------------------------------------------
# 4. Verify the `lfa` entry point
# ---------------------------------------------------------------------------
if command -v lfa &>/dev/null; then
    info "lfa command is available: $(command -v lfa)"
else
    warn "'lfa' not found on PATH after install."
    warn "You may need to add your Python scripts directory to PATH, or run:"
    warn "  $PYTHON -m lft"
fi

# ---------------------------------------------------------------------------
# 5. Optional: memory forensics
# ---------------------------------------------------------------------------
echo ""
read -r -p "$(echo -e "${YELLOW}[?]${RESET} Install Volatility 3 for memory forensics? [y/N] ")" answer
if [[ "${answer,,}" == "y" ]]; then
    info "Installing Volatility 3..."
    $PIP install volatility3 --quiet
    info "Volatility 3 installed. Run 'lfa --memory <dump>' to use it."
else
    info "Skipping Volatility 3. Install later with: pip install volatility3"
fi

# ---------------------------------------------------------------------------
# 6. Done
# ---------------------------------------------------------------------------
echo ""
info "Installation complete!"
echo ""
echo "  Quick start:"
echo "    lfa -s <uac_tarball_or_directory>"
echo ""
echo "  Launch the GUI:"
echo "    lfa-gui"
echo ""
echo "  With bodyfile:"
echo "    lfa -s collection.tar.gz --bodyfile system.body"
echo ""
echo "  With IOC matching:"
echo "    lfa -s collection.tar.gz --ioc iocs.txt"
echo ""
echo "  With memory dump:"
echo "    lfa -s collection.tar.gz -m memory.lime --symbols ./symbols/"
echo ""
echo "  Full option list:"
echo "    lfa --help"
