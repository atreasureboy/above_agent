"""Tests for CLI argument parsing (src.main entry point)."""

import pytest
from src.main import main


class TestCLIScanArguments:
    """Verify scan argument parsing accepts valid values."""

    def test_scan_backend_capstone(self):
        """--backend capstone should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--backend", "capstone"])

    def test_scan_backend_ghidra(self):
        """--backend ghidra should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--backend", "ghidra"])

    def test_scan_no_funnel(self):
        """--no-funnel should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--no-funnel"])

    def test_scan_format_not_in_scan_cmd(self):
        """scan subcommand in main.py doesn't have --format (use report subcommand instead)."""
        # Verify argparse rejects it
        with pytest.raises(SystemExit):
            main(["scan", "nonexistent_dir", "--format", "json"])

    def test_report_format_json(self):
        """report subcommand with --format json should work on missing file."""
        rc = main(["report", "nonexistent_report.json", "--format", "json"])
        assert rc == 1

    def test_report_format_sarif(self):
        """report subcommand with --format sarif should work on missing file."""
        rc = main(["report", "nonexistent_report.json", "--format", "sarif"])
        assert rc == 1

    def test_report_format_html(self):
        """report subcommand with --format html should work on missing file."""
        rc = main(["report", "nonexistent_report.json", "--format", "html"])
        assert rc == 1

    def test_report_format_markdown(self):
        """report subcommand with --format markdown should work on missing file."""
        rc = main(["report", "nonexistent_report.json", "--format", "markdown"])
        assert rc == 1

    def test_scan_workers(self):
        """--workers should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--workers", "2"])

    def test_scan_no_cache(self):
        """--no-cache should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--no-cache"])


class TestCLIReportArguments:
    def test_report_missing_file(self):
        """report subcommand with non-existent file should return 1."""
        rc = main(["report", "nonexistent_report.json"])
        assert rc == 1


class TestCLIListAnalyzers:
    def test_list_analyzers_runs(self):
        """list-analyzers should print registered analyzers."""
        rc = main(["list-analyzers"])
        assert rc == 0


class TestCLIPipelineArguments:
    def test_pipeline_target_not_found(self):
        """pipeline with nonexistent target should return 1."""
        rc = main(["pipeline", "nonexistent_dir"])
        assert rc == 1

    def test_pipeline_no_ovoida(self):
        """--no-ovoida should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--no-ovoida"])
        assert rc == 1


class TestCLIInitConfig:
    def test_init_config_runs(self):
        """init-config should create a default config."""
        rc = main(["init-config"])
        assert rc == 0


class TestCLIScanArgumentsExtended:
    """Extended scan argument parsing tests."""

    def test_scan_threshold(self):
        """--threshold should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--threshold", "7.5"])

    def test_scan_output(self):
        """--output should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--output", "out.json"])

    def test_scan_usermode(self):
        """--usermode should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--usermode"])

    def test_scan_score_engine_exploitability(self):
        """--score-engine exploitability should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--score-engine", "exploitability"])

    def test_scan_timeout(self):
        """--timeout should be accepted."""
        with pytest.raises(ValueError, match="No valid samples found"):
            main(["scan", "nonexistent_dir", "--timeout", "60"])


class TestCLIPipelineArgumentsExtended:
    """Extended pipeline argument parsing tests."""

    def test_pipeline_threshold(self):
        """--threshold should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--threshold", "3.0"])
        assert rc == 1

    def test_pipeline_max_deep(self):
        """--max-deep should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--max-deep", "0"])
        assert rc == 1

    def test_pipeline_backend(self):
        """--backend should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--backend", "ghidra"])
        assert rc == 1

    def test_pipeline_timeout(self):
        """--timeout should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--timeout", "60"])
        assert rc == 1

    def test_pipeline_workers(self):
        """--workers should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--workers", "4"])
        assert rc == 1

    def test_pipeline_no_funnel(self):
        """--no-funnel should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--no-funnel"])
        assert rc == 1

    def test_pipeline_no_cache(self):
        """--no-cache should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--no-cache"])
        assert rc == 1

    def test_pipeline_usermode(self):
        """--usermode should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--usermode"])
        assert rc == 1

    def test_pipeline_format_multiple(self):
        """--format with multiple values should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--format", "json", "html", "sarif"])
        assert rc == 1

    def test_pipeline_workspace(self):
        """--workspace should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--workspace", "/tmp/ws"])
        assert rc == 1

    def test_pipeline_deep_analysis(self):
        """--deep-analysis should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--deep-analysis"])
        assert rc == 1

    def test_pipeline_deep_threshold(self):
        """--deep-threshold should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--deep-threshold", "7.0"])
        assert rc == 1

    def test_pipeline_score_engine_exploitability(self):
        """--score-engine exploitability should be accepted."""
        rc = main(["pipeline", "nonexistent_dir", "--score-engine", "exploitability"])
        assert rc == 1

    def test_pipeline_ovoida_api(self):
        """OVOIDA API args should be accepted."""
        rc = main([
            "pipeline", "nonexistent_dir",
            "--ov-url", "https://api.example.com/v1",
            "--ov-key", "sk-xxx",
            "--ov-model", "gpt-4",
            "--ov-max-iter", "50",
        ])
        assert rc == 1


class TestCLIDeepArguments:
    """Test deep subcommand argument parsing."""

    def test_deep_target_not_found(self):
        """deep with nonexistent target should return 1."""
        rc = main(["deep", "nonexistent.sys"])
        assert rc == 1

    def test_deep_timeout(self):
        """--timeout should be accepted for existing target."""
        # Use nonexistent file, will fail at existence check
        rc = main(["deep", "nonexistent.sys", "--timeout", "600"])
        assert rc == 1

    def test_deep_output(self):
        """--output should be accepted."""
        rc = main(["deep", "nonexistent.sys", "--output", "out.json"])
        assert rc == 1


class TestCLIValidateArguments:
    """Test validate subcommand argument parsing."""

    def test_validate_target_not_found(self):
        """validate with nonexistent target should return 1."""
        rc = main(["validate", "nonexistent.sys"])
        assert rc == 1

    def test_validate_sandbox(self):
        """--sandbox should be accepted."""
        rc = main(["validate", "nonexistent.sys", "--sandbox"])
        assert rc == 1

    def test_validate_debugger(self):
        """--debugger should be accepted."""
        rc = main(["validate", "nonexistent.sys", "--debugger"])
        assert rc == 1

    def test_validate_poc(self):
        """--poc should be accepted."""
        rc = main(["validate", "nonexistent.sys", "--poc", "poc.py"])
        assert rc == 1

    def test_validate_timeout(self):
        """--timeout should be accepted."""
        rc = main(["validate", "nonexistent.sys", "--timeout", "120"])
        assert rc == 1


class TestCLICorrelateArguments:
    """Test correlate subcommand argument parsing."""

    def test_correlate_dir_not_found(self):
        """correlate with nonexistent directory should return 1."""
        rc = main(["correlate", "--drivers", "nonexistent_dir"])
        assert rc == 1

    def test_correlate_with_output(self):
        """--output and --json should be accepted."""
        rc = main([
            "correlate", "--drivers", "nonexistent_dir",
            "--output", "graph.dot",
            "--json", "corr.json",
        ])
        assert rc == 1


class TestCLICheckEnv:
    """Test check-env subcommand."""

    def test_check_env_runs(self):
        """check-env should run without crashing."""
        rc = main(["check-env"])
        # May return 0 or 1 depending on environment readiness
        assert rc in (0, 1)


class TestCLIInvalidCommand:
    """Test invalid CLI commands."""

    def test_no_command(self):
        """No subcommand should exit with SystemExit."""
        with pytest.raises(SystemExit):
            main([])

    def test_unknown_command(self):
        """Unknown subcommand should exit with SystemExit."""
        with pytest.raises(SystemExit):
            main(["foobar"])
