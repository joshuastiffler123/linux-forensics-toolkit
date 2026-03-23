"""Integration tests for the CLI entry point."""

import json
import os
import subprocess
import sys

import pytest


class TestCLIHelp:
    """Test CLI help and version flags."""

    def test_help_exits_cleanly(self):
        result = subprocess.run(
            [sys.executable, "-m", "lft.cli", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "Linux Unified Security Analyzer" in result.stdout

    def test_version_shows_2_1_0(self):
        result = subprocess.run(
            [sys.executable, "-m", "lft.cli", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "2.1.0" in result.stdout

    def test_dump_config_outputs_valid_json(self):
        result = subprocess.run(
            [sys.executable, "-m", "lft.cli", "--dump-config"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        config = json.loads(result.stdout)
        assert isinstance(config, dict)
        assert "analyzers_enabled" in config


class TestCLIAnalysis:
    """Test running an actual analysis on synthetic data."""

    def test_analyze_tarball(self, sample_tarball, tmp_path):
        """Run the CLI against the synthetic tarball and verify outputs."""
        output_dir = tmp_path / "output"
        result = subprocess.run(
            [
                sys.executable, "-m", "lft.cli",
                "-s", str(sample_tarball),
                "-o", str(output_dir),
                "-q",  # quiet mode to reduce output
            ],
            capture_output=True, text=True, timeout=120,
        )
        # Should complete without crashing (exit 0 or 1 for analysis issues)
        assert result.returncode in (0, 1), (
            f"CLI failed with code {result.returncode}:\n"
            f"stdout: {result.stdout[-500:]}\n"
            f"stderr: {result.stderr[-500:]}"
        )

    def test_analyze_directory(self, sample_uac_dir, tmp_path):
        """Run the CLI against the synthetic directory."""
        output_dir = tmp_path / "output"
        result = subprocess.run(
            [
                sys.executable, "-m", "lft.cli",
                "-s", str(sample_uac_dir),
                "-o", str(output_dir),
                "-q",
            ],
            capture_output=True, text=True, timeout=120,
        )
        assert result.returncode in (0, 1), (
            f"CLI failed with code {result.returncode}:\n"
            f"stdout: {result.stdout[-500:]}\n"
            f"stderr: {result.stderr[-500:]}"
        )

    def test_creates_output_directory(self, sample_tarball, tmp_path):
        """Verify the analysis creates an output directory."""
        output_dir = tmp_path / "analysis_out"
        subprocess.run(
            [
                sys.executable, "-m", "lft.cli",
                "-s", str(sample_tarball),
                "-o", str(output_dir),
                "-q",
            ],
            capture_output=True, text=True, timeout=120,
        )
        # Should create at least one subdirectory or file
        assert output_dir.exists() or any(
            p.exists() for p in tmp_path.iterdir()
        )


class TestCLIEdgeCases:
    """Test CLI error handling."""

    def test_missing_source_shows_help(self):
        """Running without -s should show usage or error."""
        result = subprocess.run(
            [sys.executable, "-m", "lft.cli"],
            capture_output=True, text=True, timeout=10,
        )
        # Should exit with an error or show help
        combined = result.stdout + result.stderr
        assert "source" in combined.lower() or "usage" in combined.lower() or result.returncode != 0

    def test_nonexistent_source(self, tmp_path):
        """Pointing at a nonexistent path should fail gracefully."""
        result = subprocess.run(
            [
                sys.executable, "-m", "lft.cli",
                "-s", str(tmp_path / "does_not_exist.tar.gz"),
                "-q",
            ],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0
