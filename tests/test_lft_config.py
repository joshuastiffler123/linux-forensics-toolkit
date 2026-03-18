"""Tests for lft_config — ToolkitConfig, load/save, merge_cli_args."""

import argparse
import json

import pytest

from lft.core.config import (
    ToolkitConfig,
    ANALYZER_NAMES,
    default_config,
    load_config,
    save_config,
    merge_cli_args,
)
from lft.core.errors import ConfigError


# ---- default_config() ---------------------------------------------------

class TestDefaultConfig:
    """default_config() returns a ToolkitConfig with sane defaults."""

    def test_returns_toolkit_config(self):
        cfg = default_config()
        assert isinstance(cfg, ToolkitConfig)

    def test_quiet_false(self):
        assert default_config().quiet is False

    def test_parallel_true(self):
        assert default_config().parallel is True

    def test_output_base_dot(self):
        assert default_config().output_base == "."

    def test_all_analyzers_enabled(self):
        cfg = default_config()
        for name in ANALYZER_NAMES:
            assert cfg.analyzers_enabled[name] is True

    def test_gap_threshold(self):
        assert default_config().gap_threshold_hours == 6.0

    def test_max_message_length(self):
        assert default_config().max_message_length == 50000

    def test_ioc_max_file_size(self):
        assert default_config().ioc_max_file_size == 200 * 1024 * 1024

    def test_optional_paths_none(self):
        cfg = default_config()
        assert cfg.ioc_file is None
        assert cfg.memory_image is None
        assert cfg.bodyfile is None
        assert cfg.vol_path is None

    def test_symbol_dirs_empty(self):
        assert default_config().symbol_dirs == []


# ---- save_config / load_config roundtrip --------------------------------

class TestSaveLoadRoundtrip:
    """save_config + load_config preserves all fields."""

    def test_roundtrip(self, tmp_path):
        original = default_config()
        original.quiet = True
        original.gap_threshold_hours = 24.0
        original.analyzers_enabled["memory"] = False

        path = str(tmp_path / "roundtrip.json")
        save_config(original, path)
        loaded = load_config(path)

        assert loaded.quiet is True
        assert loaded.gap_threshold_hours == 24.0
        assert loaded.analyzers_enabled["memory"] is False
        assert loaded.analyzers_enabled["journal"] is True  # untouched

    def test_saved_file_is_valid_json(self, tmp_path):
        path = str(tmp_path / "output.json")
        save_config(default_config(), path)
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert "_comment" in data

    def test_saved_file_has_all_fields(self, tmp_path):
        path = str(tmp_path / "output.json")
        save_config(default_config(), path)
        with open(path) as f:
            data = json.load(f)
        assert "quiet" in data
        assert "analyzers_enabled" in data
        assert "gap_threshold_hours" in data
        assert "isf_servers" in data


# ---- load_config edge cases ---------------------------------------------

class TestLoadConfigEdgeCases:
    """load_config handles partial, empty, and malformed files."""

    def test_empty_object_uses_defaults(self, empty_config_file):
        cfg = load_config(str(empty_config_file))
        assert cfg.quiet is False
        assert cfg.parallel is True
        assert len(cfg.analyzers_enabled) == len(ANALYZER_NAMES)

    def test_partial_config_merges(self, sample_config_file):
        cfg = load_config(str(sample_config_file))
        assert cfg.quiet is True
        assert cfg.parallel is False
        assert cfg.gap_threshold_hours == 12.0
        assert cfg.analyzers_enabled["memory"] is False
        # Unset analyzers keep default True
        assert cfg.analyzers_enabled["journal"] is True

    def test_invalid_json_raises_config_error(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("NOT JSON {{{")
        with pytest.raises(ConfigError):
            load_config(str(bad))

    def test_nonexistent_file_raises_config_error(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(str(tmp_path / "missing.json"))

    def test_non_dict_json_returns_defaults(self, tmp_path):
        arr = tmp_path / "array.json"
        arr.write_text("[1, 2, 3]")
        cfg = load_config(str(arr))
        # Should return defaults, not crash
        assert cfg.quiet is False

    def test_type_mismatch_skipped(self, tmp_path):
        bad_types = tmp_path / "bad_types.json"
        bad_types.write_text(json.dumps({"gap_threshold_hours": "not_a_number"}))
        cfg = load_config(str(bad_types))
        # Should keep default, not crash
        assert cfg.gap_threshold_hours == 6.0

    def test_unknown_analyzer_ignored(self, tmp_path):
        unknown = tmp_path / "unknown.json"
        unknown.write_text(json.dumps({
            "analyzers_enabled": {"nonexistent_analyzer": True}
        }))
        cfg = load_config(str(unknown))
        assert "nonexistent_analyzer" not in cfg.analyzers_enabled


# ---- merge_cli_args() ---------------------------------------------------

class TestMergeCliArgs:
    """CLI args override config values."""

    def _make_namespace(self, **kwargs):
        """Helper: build an argparse.Namespace with sensible defaults."""
        defaults = dict(
            quiet=False, sequential=False, output=None,
            ioc=None, memory=None, symbols=[], bodyfile=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_quiet_override(self):
        cfg = default_config()
        cfg = merge_cli_args(cfg, self._make_namespace(quiet=True))
        assert cfg.quiet is True

    def test_sequential_sets_parallel_false(self):
        cfg = default_config()
        cfg = merge_cli_args(cfg, self._make_namespace(sequential=True))
        assert cfg.parallel is False

    def test_output_override(self):
        cfg = default_config()
        cfg = merge_cli_args(cfg, self._make_namespace(output="/tmp/out"))
        assert cfg.output_base == "/tmp/out"

    def test_ioc_override(self):
        cfg = default_config()
        cfg = merge_cli_args(cfg, self._make_namespace(ioc="/tmp/iocs.txt"))
        assert cfg.ioc_file == "/tmp/iocs.txt"

    def test_memory_override(self):
        cfg = default_config()
        cfg = merge_cli_args(cfg, self._make_namespace(memory="/tmp/mem.lime"))
        assert cfg.memory_image == "/tmp/mem.lime"

    def test_symbols_override(self):
        cfg = default_config()
        cfg = merge_cli_args(cfg, self._make_namespace(symbols=["/sym1", "/sym2"]))
        assert cfg.symbol_dirs == ["/sym1", "/sym2"]

    def test_bodyfile_override(self):
        cfg = default_config()
        cfg = merge_cli_args(cfg, self._make_namespace(bodyfile="/tmp/body.txt"))
        assert cfg.bodyfile == "/tmp/body.txt"

    def test_none_args_leave_config_unchanged(self):
        cfg = default_config()
        cfg.ioc_file = "/original.txt"
        cfg = merge_cli_args(cfg, self._make_namespace())
        assert cfg.ioc_file == "/original.txt"
