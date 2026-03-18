"""Tests for lft_logging — setup_logging, StyledFormatter, SUCCESS level."""

import logging

import pytest

from lft.core.logging import setup_logging, StyledFormatter, SUCCESS


# ---- Custom SUCCESS level -----------------------------------------------

class TestSuccessLevel:
    """The custom SUCCESS log level is registered and usable."""

    def test_success_level_value(self):
        assert SUCCESS == 25

    def test_success_level_name(self):
        assert logging.getLevelName(SUCCESS) == "SUCCESS"

    def test_logger_has_success_method(self):
        logger = logging.getLogger("test.success")
        assert hasattr(logger, "success")
        assert callable(logger.success)

    def test_success_method_logs(self, caplog):
        logger = logging.getLogger("test.success.logs")
        with caplog.at_level(SUCCESS, logger="test.success.logs"):
            logger.success("it works")
        assert "it works" in caplog.text


# ---- setup_logging() ----------------------------------------------------

class TestSetupLogging:
    """setup_logging configures the root logger."""

    def teardown_method(self):
        # Reset root logger after each test
        root = logging.getLogger()
        root.handlers.clear()
        root.setLevel(logging.WARNING)

    def test_adds_handler(self):
        setup_logging()
        root = logging.getLogger()
        assert len(root.handlers) >= 1

    def test_handler_is_stderr(self):
        import sys
        setup_logging()
        root = logging.getLogger()
        handler = root.handlers[0]
        assert isinstance(handler, logging.StreamHandler)
        assert handler.stream is sys.stderr

    def test_default_level_is_debug(self):
        setup_logging()
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_quiet_sets_warning_level(self):
        setup_logging(quiet=True)
        root = logging.getLogger()
        assert root.level == logging.WARNING

    def test_explicit_level_overrides_quiet(self):
        setup_logging(quiet=True, level=logging.ERROR)
        root = logging.getLogger()
        assert root.level == logging.ERROR

    def test_handler_uses_styled_formatter(self):
        setup_logging()
        root = logging.getLogger()
        handler = root.handlers[0]
        assert isinstance(handler.formatter, StyledFormatter)


# ---- StyledFormatter ----------------------------------------------------

class TestStyledFormatter:
    """StyledFormatter applies or omits ANSI colors."""

    def test_format_returns_string(self):
        formatter = StyledFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello", args=(), exc_info=None,
        )
        result = formatter.format(record)
        assert isinstance(result, str)
        assert "hello" in result

    def test_format_includes_message_args(self):
        formatter = StyledFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="found %d items", args=(42,), exc_info=None,
        )
        result = formatter.format(record)
        assert "42" in result
