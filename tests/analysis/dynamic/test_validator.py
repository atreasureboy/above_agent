"""Tests for enhanced validator.py -- all mocked."""

import pytest
from pathlib import Path

from src.analysis.dynamic.validator import (
    DynamicValidator,
    ValidationConfig,
    DynamicResult,
)
from src.models import (
    Architecture, Confidence, DisassemblyResult, Finding, FindingCategory,
    Sample, Severity,
)


def _make_sample(name: str, risk_score: float = 5.0) -> Sample:
    return Sample(
        path=Path(name),
        name=name,
        company="TestCorp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=1024,
        is_driver=True,
        risk_score=risk_score,
    )


class TestValidationConfig:
    def test_defaults(self):
        cfg = ValidationConfig()
        assert cfg.sandbox_enabled is False
        assert cfg.debugger_enabled is False
        assert cfg.timeout_per_test == 30

    def test_custom(self):
        cfg = ValidationConfig(
            sandbox_enabled=True,
            timeout_per_test=60,
            qemu_path="C:\\qemu.exe",
        )
        assert cfg.sandbox_enabled is True
        assert cfg.timeout_per_test == 60


class TestDynamicResult:
    def test_defaults(self):
        r = DynamicResult()
        assert r.sample_name == ""
        assert r.crash_detected is False
        assert r.error == ""


class TestDynamicValidator:
    def setup_method(self):
        self.validator = DynamicValidator()

    def test_validate_sample_no_sandbox(self):
        """Without sandbox/debugger, should return early with no error."""
        sample = _make_sample("test.sys")
        result = self.validator.validate_sample(sample)
        assert result.sample_name == "test.sys"
        assert result.error == ""

    def test_validate_sample_sandbox_unavailable(self):
        """Sandbox enabled but not available should fail gracefully."""
        cfg = ValidationConfig(
            sandbox_enabled=True,
            qemu_path="",  # No QEMU path
        )
        validator = DynamicValidator(cfg)
        sample = _make_sample("test.sys")
        result = validator.validate_sample(sample)
        assert "Sandbox not available" in result.error

    def test_validate_sample_debugger_unavailable(self):
        """Debugger enabled but not available should fail gracefully."""
        cfg = ValidationConfig(
            debugger_enabled=True,
            windbg_path="",  # No WinDbg path
        )
        validator = DynamicValidator(cfg)
        sample = _make_sample("test.sys")
        result = validator.validate_sample(sample)
        assert "Debugger not available" in result.error

    def test_validate_findings_legacy(self):
        """Legacy validate_findings should return results."""
        findings = [
            Finding(
                category=FindingCategory.ARBITRARY_MEMORY_MAP,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Test finding",
            ),
        ]
        results = self.validator.validate_findings(findings)
        assert len(results) == 1
        assert len(results[0].findings_validated) == 1

    def test_to_dict_serialization(self):
        """DynamicResult should serialize correctly."""
        result = DynamicResult(
            sample_name="test.sys",
            crash_detected=True,
            poc_executed=True,
            system_changes={"new_devices": ["DeviceX"]},
            elapsed=5.5,
        )
        d = self.validator.to_dict(result)
        assert d["sample_name"] == "test.sys"
        assert d["crash_detected"] is True
        assert d["system_changes"]["new_devices"] == ["DeviceX"]
        assert d["elapsed"] == 5.5

    def test_to_json_serialization(self):
        result = DynamicResult(
            sample_name="test.sys",
            crash_detected=False,
        )
        json_str = self.validator.to_json(result)
        assert "test.sys" in json_str
        assert "crash_detected" in json_str
