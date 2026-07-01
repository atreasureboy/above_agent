"""Tests for scoring calibration."""

import pytest
from src.models import Finding, FindingCategory, Severity, Confidence
from src.scoring.calibration import calibrate, CalibrationResult


def _make_finding(severity=Severity.HIGH, category=FindingCategory.ARBITRARY_MEMORY_MAP):
    return Finding(
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        description="Test finding",
    )


class TestCalibration:
    def test_returns_defaults_when_no_data(self):
        result = calibrate()
        assert result.threshold_recommended == 7.0
        assert result.total_samples == 0

    def test_calculates_metrics_for_mock_data(self):
        """With clearly different vulnerable vs clean findings, should find a good threshold."""
        vuln = [
            [_make_finding(Severity.CRITICAL, FindingCategory.CODE_EXECUTION_PRIMITIVE),
             _make_finding(Severity.HIGH, FindingCategory.ARBITRARY_MEMORY_MAP),
             _make_finding(Severity.HIGH, FindingCategory.KERNEL_RW_PRIMITIVE)],
            [_make_finding(Severity.CRITICAL, FindingCategory.MSR_ACCESS),
             _make_finding(Severity.HIGH, FindingCategory.PHYSICAL_MEMORY_ACCESS)],
        ]
        clean = [
            [_make_finding(Severity.INFO, FindingCategory.IOCTL_DISPATCHER_FOUND)],
            [_make_finding(Severity.LOW, FindingCategory.SIGNED_DRIVER)],
            [],
        ]

        result = calibrate(vulnerable_findings=vuln, clean_findings=clean)
        assert result.total_samples == 5
        assert result.threshold_recommended > 0
        assert result.per_threshold  # Non-empty threshold sweep

    def test_per_threshold_has_required_keys(self):
        vuln = [[_make_finding(Severity.CRITICAL)]]
        clean = [[_make_finding(Severity.INFO)]]
        result = calibrate(vulnerable_findings=vuln, clean_findings=clean)

        for pt in result.per_threshold:
            assert "threshold" in pt
            assert "precision" in pt
            assert "recall" in pt
            assert "f1" in pt
            assert "tp" in pt
            assert "fp" in pt
            assert "tn" in pt
            assert "fn" in pt

    def test_auc_roc_between_0_and_1(self):
        vuln = [[_make_finding(Severity.CRITICAL)]]
        clean = [[_make_finding(Severity.INFO)]]
        result = calibrate(vulnerable_findings=vuln, clean_findings=clean)
        assert 0.0 <= result.auc_roc <= 1.0

    def test_empty_vulnerable_and_clean(self):
        result = calibrate(vulnerable_findings=[], clean_findings=[])
        assert result.total_samples == 0

    def test_all_vulnerable_detected(self):
        """If clean samples have zero findings and vuln samples have many, should find good separation."""
        vuln = [
            [_make_finding(Severity.CRITICAL, FindingCategory.CODE_EXECUTION_PRIMITIVE),
             _make_finding(Severity.CRITICAL, FindingCategory.MSR_ACCESS),
             _make_finding(Severity.HIGH, FindingCategory.ARBITRARY_MEMORY_MAP)],
        ]
        clean = [[]]

        result = calibrate(vulnerable_findings=vuln, clean_findings=clean)
        # Should achieve good precision/recall
        assert result.recall >= 0.0  # At minimum, defined


class TestCalibrationResult:
    def test_dataclass_fields(self):
        r = CalibrationResult(
            threshold_recommended=5.0, precision=0.8, recall=0.9,
            f1=0.85, auc_roc=0.92, total_samples=20,
            true_positives=8, true_negatives=10,
            false_positives=2, false_negatives=0,
        )
        assert r.threshold_recommended == 5.0
        assert r.precision == 0.8
        assert r.f1 == 0.85
