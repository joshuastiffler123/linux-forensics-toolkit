"""
Background analysis worker and queue-based log handler.

Moved from the original gui.py to keep the GUI package modular.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Lazy imports — keeps startup fast; heavy modules load when Run is clicked
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


def get_cli_module():
    """Return the cli module, importing lazily if needed."""
    _ensure_imports()
    return _cli_module


def get_config_module():
    """Return the config module, importing lazily if needed."""
    _ensure_imports()
    return _config_module


# ---------------------------------------------------------------------------
# Queue-based log handler (thread-safe)
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
