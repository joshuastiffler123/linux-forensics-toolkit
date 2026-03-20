# CLAUDE.md — Development Guide

## Project Overview

Linux Forensics Toolkit (LFT) — Python 3.8+ incident-response triage tool for
Linux UAC collections. **Zero mandatory dependencies** for disk forensics (pure
stdlib). Memory forensics optionally uses Volatility 3.

## Quick Start (dev)

```bash
git clone https://github.com/joshuastiffler123/linux-forensics-toolkit.git
cd linux-forensics-toolkit
pip install -e .        # editable install — registers `lfa` and `lfa-gui`
lfa --help              # CLI
lfa-gui                 # tkinter GUI
python -m lft           # alternative GUI launch (no install needed)
```

## Repository Layout

```
src/lft/                  # installable package (PEP 517 / pyproject.toml)
  cli.py                  # CLI entry point  (lfa)
  gui/                    # tkinter GUI      (lfa-gui / python -m lft)
    app.py                #   main window
    worker.py             #   background analysis thread
    results_view.py       #   treeview for results
    theme.py              #   dark-mode styling
    report.py             #   report generation
    menubar.py            #   menu bar
    statusbar.py          #   status bar
    dnd.py                #   drag-and-drop (optional tkinterdnd2)
  core/                   # shared utilities
    uac.py                #   UAC tarball/directory handler + coverage tracking
    style.py              #   ANSI console styling (auto-TTY detection)
    config.py             #   runtime configuration
    errors.py             #   custom exceptions
    logging.py            #   logging setup
  analyzers/              # forensic analyzer modules
    filesystem.py         #   MAC timeline from Sleuth Kit bodyfile
    ioc.py                #   IOC cross-reference matching
    journal.py            #   systemd journal binary logs
    login_timeline.py     #   auth.log, wtmp, btmp, lastlog, SSH
    memory.py             #   Volatility 3 wrapper (optional)
    misc.py               #   archives, hidden dirs, scheduled tasks
    network.py            #   network config, web access logs
    packages.py           #   dpkg/apt/yum/dnf/pacman logs
    persistence.py        #   cron, systemd, SSH keys, SUID — MITRE tagged
    security.py           #   suspicious binaries, rootkit traces
    strings.py            #   log carving from compressed files
tests/                    # pytest test suite
```

## Build System

- **pyproject.toml** is the single source of truth for metadata, deps, and entry points.
- `requirements.txt` is intentionally absent — `pyproject.toml` handles everything.
- Build: `pip install -e .` (dev) or `pip install .` (user).
- Optional memory forensics: `pip install -e ".[memory]"`

## Code Conventions

- **Python 3.8 minimum** — no walrus operator `:=`, no `match/case`, no `typing.TypeAlias`.
- **No external dependencies** for disk forensics. If you need something, use stdlib.
- **Type hints** encouraged but not enforced (no mypy gate yet).
- **Docstrings** on all public functions/classes (Google style preferred).
- **Imports** — stdlib first, then `lft.*` internal imports. No third-party imports
  in core analyzers.
- **Error handling** — use `lft.core.errors` custom exceptions. Never bare `except:`.
- **CSV output** — all analyzers produce CSV. Column names use `PascalCase`.

## GUI Conventions

- GUI is tkinter-only (stdlib). Optional `tkinterdnd2` for drag-and-drop.
- All long-running work goes through `gui/worker.py` (background thread).
- Theme constants live in `gui/theme.py` — don't hardcode colors elsewhere.
- GUI must remain functional without any optional dependencies.

## Testing

```bash
pytest                    # run all tests
pytest tests/ -v          # verbose
pytest -k "test_login"    # run specific tests
```

## Adding a New Analyzer

1. Create `src/lft/analyzers/your_analyzer.py`.
2. Import from `lft.core.uac` for UAC access and `lft.core.style` for console output.
3. Follow the existing pattern: accept a UAC path, return results as a list of dicts.
4. Register it in the CLI orchestrator (`cli.py`).
5. Add CSV column names in `PascalCase`.
6. Add tests in `tests/`.

## Common Commands

```bash
# Run analysis on a UAC tarball
lfa -s server.tar.gz

# Run with IOC matching
lfa -s server.tar.gz --ioc indicators.txt

# Launch GUI
lfa-gui

# Run tests
pytest

# Check package builds cleanly
pip install -e . && lfa --help
```
