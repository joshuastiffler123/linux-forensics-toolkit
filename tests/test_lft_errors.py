"""Tests for lft_errors — exception hierarchy and exit code constants."""

import pytest

from lft.core.errors import (
    LFTError,
    SourceNotFoundError,
    SourceCorruptError,
    ParseError,
    AnalyzerError,
    ConfigError,
    EXIT_OK,
    EXIT_ERROR,
    EXIT_SOURCE_NOT_FOUND,
    EXIT_CONFIG_ERROR,
    EXIT_SIGINT,
)


# ---- Exception hierarchy ------------------------------------------------

class TestExceptionHierarchy:
    """All custom exceptions descend from LFTError and Exception."""

    @pytest.mark.parametrize("exc_cls", [
        SourceNotFoundError,
        SourceCorruptError,
        ParseError,
        AnalyzerError,
        ConfigError,
    ])
    def test_subclass_of_lft_error(self, exc_cls):
        assert issubclass(exc_cls, LFTError)

    @pytest.mark.parametrize("exc_cls", [
        LFTError,
        SourceNotFoundError,
        SourceCorruptError,
        ParseError,
        AnalyzerError,
        ConfigError,
    ])
    def test_subclass_of_exception(self, exc_cls):
        assert issubclass(exc_cls, Exception)

    def test_lft_error_is_base(self):
        assert LFTError.__bases__ == (Exception,)


# ---- Raisable and catchable --------------------------------------------

class TestExceptionUsage:
    """Exceptions can be raised and caught by base class."""

    def test_raise_source_not_found(self):
        with pytest.raises(LFTError, match="not found"):
            raise SourceNotFoundError("not found")

    def test_raise_source_corrupt(self):
        with pytest.raises(LFTError, match="corrupt"):
            raise SourceCorruptError("corrupt tarball")

    def test_raise_parse_error(self):
        with pytest.raises(LFTError):
            raise ParseError("bad timestamp")

    def test_raise_analyzer_error(self):
        with pytest.raises(LFTError):
            raise AnalyzerError("analyzer crashed")

    def test_raise_config_error(self):
        with pytest.raises(LFTError):
            raise ConfigError("invalid JSON")

    def test_exception_message_preserved(self):
        try:
            raise SourceNotFoundError("path/to/missing")
        except LFTError as e:
            assert "path/to/missing" in str(e)


# ---- Exit code constants ------------------------------------------------

class TestExitCodes:
    """Exit code constants have expected values."""

    def test_exit_ok(self):
        assert EXIT_OK == 0

    def test_exit_error(self):
        assert EXIT_ERROR == 1

    def test_exit_source_not_found(self):
        assert EXIT_SOURCE_NOT_FOUND == 2

    def test_exit_config_error(self):
        assert EXIT_CONFIG_ERROR == 3

    def test_exit_sigint(self):
        assert EXIT_SIGINT == 130
