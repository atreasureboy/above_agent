"""Tests for false positive baseline filter (fp_baseline.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.fp_baseline import (
    BENIGN_API_CONTEXTS,
    BaselineFilter,
    BaselineProfile,
    MIN_VALIDATION_APIS,
    SAFE_DRIVER_SIGNATURES,
    SUFFICIENT_VALIDATION_PATTERNS,
    build_default_baseline,
    load_baseline,
)
from src.models import (
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Sample,
    Severity,
    SignatureStatus,
)


def _make_ir(apis: set[str] | None = None) -> DisassemblyResult:
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
    if apis:
        ir.function_apis[0x1000] = list(apis)
    return ir


def _sample(
    name: str = "test.sys",
    company: str = "Test Company",
    sig_status: SignatureStatus = SignatureStatus.UNSIGNED,
    sha256: str = "abc123",
) -> Sample:
    return Sample(
        path=Path(name), name=name, company=company,
        version="1.0", arch="x64", sha256=sha256, size=1024,
        is_driver=True, signature_status=sig_status,
    )


def _finding(
    category: FindingCategory = FindingCategory.ARBITRARY_MEMORY_MAP,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    api_name: str = "",
    context: dict | None = None,
) -> Finding:
    return Finding(
        category=category,
        severity=severity,
        confidence=confidence,
        description="Test finding",
        api_name=api_name,
        context=context or {},
        evidence=[Evidence(type="import", location="IAT", snippet=api_name, rule_id="TEST")],
    )


class TestBaselineConstants:
    """Test baseline constant definitions."""

    def test_benign_api_contexts_defined(self):
        assert "MmMapIoSpace" in BENIGN_API_CONTEXTS
        assert "ExAllocatePoolWithTag" in BENIGN_API_CONTEXTS
        assert "RtlCopyMemory" in BENIGN_API_CONTEXTS

    def test_sufficient_validation_patterns(self):
        assert "probe_and_privilege" in SUFFICIENT_VALIDATION_PATTERNS
        assert "locked_pages" in SUFFICIENT_VALIDATION_PATTERNS
        assert "mode_and_size" in SUFFICIENT_VALIDATION_PATTERNS

    def test_safe_driver_signatures(self):
        assert "microsoft corporation" in SAFE_DRIVER_SIGNATURES
        assert "microsoft" in SAFE_DRIVER_SIGNATURES

    def test_min_validation_apis(self):
        assert MIN_VALIDATION_APIS == 2


class TestBaselineProfile:
    """Test BaselineProfile dataclass."""

    def test_create_profile(self):
        profile = BaselineProfile(
            name="test_driver",
            company="Test Corp",
            known_safe_apis={"MmMapIoSpace"},
            validation_patterns={"probe_and_privilege"},
            driver_category="storage",
        )
        assert profile.name == "test_driver"
        assert "MmMapIoSpace" in profile.known_safe_apis

    def test_to_dict_and_from_dict(self):
        profile = BaselineProfile(
            name="test_driver",
            sha256="abc123",
            company="Test Corp",
            known_safe_apis={"MmMapIoSpace", "RtlCopyMemory"},
            validation_patterns={"locked_pages"},
            driver_category="display",
        )
        d = profile.to_dict()
        restored = BaselineProfile.from_dict(d)
        assert restored.name == profile.name
        assert restored.sha256 == profile.sha256
        assert restored.known_safe_apis == profile.known_safe_apis
        assert restored.validation_patterns == profile.validation_patterns
        assert restored.driver_category == profile.driver_category

    def test_empty_profile(self):
        profile = BaselineProfile(name="minimal")
        assert profile.sha256 == ""
        assert profile.company == ""
        assert len(profile.known_safe_apis) == 0


class TestBaselineFilter:
    """Test BaselineFilter operations."""

    def test_empty_filter_returns_all_findings(self):
        bf = BaselineFilter()
        ir = _make_ir()
        sample = _sample()
        findings = [_finding()]
        filtered = bf.filter_findings(findings, sample, ir)
        assert len(filtered) == 1

    def test_downgrade_for_known_safe_sha(self):
        """Finding should be downgraded when driver SHA matches baseline."""
        profile = BaselineProfile(name="test.sys", sha256="abc123", company="Microsoft")
        bf = BaselineFilter([profile])
        ir = _make_ir()
        sample = _sample(sha256="abc123")
        findings = [_finding(severity=Severity.HIGH, confidence=Confidence.HIGH)]
        filtered = bf.filter_findings(findings, sample, ir)
        assert len(filtered) == 1
        assert filtered[0].severity == Severity.MEDIUM  # Downgraded by one level
        assert "[BASELINE]" in filtered[0].description

    def test_downgrade_for_known_safe_name(self):
        """Finding should be downgraded when driver name matches baseline."""
        profile = BaselineProfile(name="test.sys", company="Microsoft")
        bf = BaselineFilter([profile])
        ir = _make_ir()
        sample = _sample(name="test.sys")
        findings = [_finding(severity=Severity.CRITICAL)]
        filtered = bf.filter_findings(findings, sample, ir)
        assert filtered[0].severity == Severity.HIGH

    def test_no_downgrade_for_unknown_driver(self):
        """Finding should not be downgraded for unknown driver."""
        profile = BaselineProfile(name="safe.sys", sha256="safe123", company="Microsoft")
        bf = BaselineFilter([profile])
        ir = _make_ir()
        sample = _sample(name="evil.sys", sha256="evil123")
        findings = [_finding(severity=Severity.HIGH)]
        filtered = bf.filter_findings(findings, sample, ir)
        assert filtered[0].severity == Severity.HIGH

    def test_attack_chain_not_adjusted(self):
        """ATTACK_CHAIN findings should not be downgraded."""
        profile = BaselineProfile(name="test.sys", sha256="abc123", company="Microsoft")
        bf = BaselineFilter([profile])
        ir = _make_ir()
        sample = _sample(sha256="abc123")
        findings = [_finding(category=FindingCategory.ATTACK_CHAIN, severity=Severity.CRITICAL)]
        filtered = bf.filter_findings(findings, sample, ir)
        assert filtered[0].severity == Severity.CRITICAL  # Not downgraded
        assert "[BASELINE]" not in filtered[0].description

    def test_taint_confirmed_not_adjusted(self):
        """Taint-confirmed findings should not be downgraded."""
        profile = BaselineProfile(name="test.sys", sha256="abc123", company="Microsoft")
        bf = BaselineFilter([profile])
        ir = _make_ir()
        sample = _sample(sha256="abc123")
        findings = [_finding(context={"taint_confirmed": True}, severity=Severity.HIGH)]
        filtered = bf.filter_findings(findings, sample, ir)
        assert filtered[0].severity == Severity.HIGH  # Not downgraded

    def test_downgrade_already_low_stays_low(self):
        """INFO/LOW findings should not be further downgraded for safe drivers."""
        profile = BaselineProfile(name="test.sys", sha256="abc123", company="Microsoft")
        bf = BaselineFilter([profile])
        ir = _make_ir()
        sample = _sample(sha256="abc123")
        findings = [_finding(severity=Severity.LOW)]
        filtered = bf.filter_findings(findings, sample, ir)
        assert filtered[0].severity == Severity.LOW

    def test_multiple_findings_preserved(self):
        """Multiple findings should all be processed independently."""
        bf = BaselineFilter()
        ir = _make_ir()
        sample = _sample()
        findings = [
            _finding(severity=Severity.CRITICAL),
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.MEDIUM),
        ]
        filtered = bf.filter_findings(findings, sample, ir)
        assert len(filtered) == 3


class TestValidationBasedDowngrade:
    """Test downgrade based on validation API presence."""

    def test_driver_with_sufficient_validation(self):
        """Driver with multiple validation patterns should get some downgrades."""
        bf = BaselineFilter()
        ir = _make_ir(apis={
            "ProbeForRead", "SeSinglePrivilegeCheck",
            "MmProbeAndLockPages", "MmProbeAndLockProcessPages",
            "ExGetPreviousMode",
        })
        sample = _sample()
        findings = [_finding(
            category=FindingCategory.MISSING_PRIVILEGE_CHECK,
            severity=Severity.HIGH,
        )]
        filtered = bf.filter_findings(findings, sample, ir)
        # With sufficient validation, MISSING_PRIVILEGE_CHECK should be downgraded
        assert filtered[0].severity == Severity.MEDIUM

    def test_driver_without_validation(self):
        """Driver without validation APIs should not get validation-based downgrades."""
        bf = BaselineFilter()
        ir = _make_ir(apis={"IoCreateDevice"})
        sample = _sample()
        findings = [_finding(
            category=FindingCategory.MISSING_PRIVILEGE_CHECK,
            severity=Severity.HIGH,
        )]
        filtered = bf.filter_findings(findings, sample, ir)
        assert filtered[0].severity == Severity.HIGH  # No downgrade


class TestBenignApiContextDowngrade:
    """Test standalone pool allocation finding downgrade."""

    def test_pool_allocation_downgraded(self):
        """Standalone pool allocation findings should be downgraded to LOW."""
        bf = BaselineFilter()
        ir = _make_ir(apis={"ExAllocatePoolWithTag"})
        sample = _sample()
        findings = [_finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            api_name="ExAllocatePoolWithTag",
        )]
        filtered = bf.filter_findings(findings, sample, ir)
        assert filtered[0].severity == Severity.LOW
        assert "[COMMON-API]" in filtered[0].description


class TestBaselineSerialization:
    """Test BaselineFilter JSON serialization."""

    def test_to_json_and_from_json(self):
        bf = BaselineFilter()
        bf.add_profile(BaselineProfile(
            name="test_driver",
            sha256="abc123",
            company="Test Corp",
            known_safe_apis={"MmMapIoSpace"},
            driver_category="storage",
        ))
        json_str = bf.to_json()
        restored = BaselineFilter.from_json(json_str)
        assert len(restored.profiles) == 1
        assert restored.profiles[0].name == "test_driver"
        assert restored.profiles[0].sha256 == "abc123"

    def test_empty_filter_serialization(self):
        bf = BaselineFilter()
        json_str = bf.to_json()
        assert json_str == "[]"
        restored = BaselineFilter.from_json(json_str)
        assert len(restored.profiles) == 0

    def test_add_profile_updates_indexes(self):
        bf = BaselineFilter()
        profile = BaselineProfile(name="test.sys", sha256="abc123")
        bf.add_profile(profile)
        assert "test.sys" in bf._index_by_name
        assert "abc123" in bf._index_by_sha


class TestBuildDefaultBaseline:
    """Test build_default_baseline function."""

    def test_build_default_has_profiles(self):
        bf = build_default_baseline()
        assert len(bf.profiles) >= 3  # microsoft_generic, storport, dxgkrnl

    def test_default_profiles_have_required_fields(self):
        bf = build_default_baseline()
        for p in bf.profiles:
            assert p.name != ""
            assert p.company != ""
            assert len(p.known_safe_apis) > 0
            assert p.driver_category != ""


class TestLoadBaseline:
    """Test load_baseline function."""

    def test_load_nonexistent_returns_empty(self):
        bf = load_baseline(Path("/nonexistent/path/baseline.json"))
        assert isinstance(bf, BaselineFilter)
        assert len(bf.profiles) == 0


class TestDowngradeHelpers:
    """Test severity/confidence downgrade helper functions."""

    def test_downgrade_critical_to_high(self):
        assert BaselineFilter._downgrade_severity(Severity.CRITICAL) == Severity.HIGH

    def test_downgrade_high_to_medium(self):
        assert BaselineFilter._downgrade_severity(Severity.HIGH) == Severity.MEDIUM

    def test_downgrade_medium_to_low(self):
        assert BaselineFilter._downgrade_severity(Severity.MEDIUM) == Severity.LOW

    def test_downgrade_low_to_info(self):
        assert BaselineFilter._downgrade_severity(Severity.LOW) == Severity.INFO

    def test_downgrade_info_stays_info(self):
        assert BaselineFilter._downgrade_severity(Severity.INFO) == Severity.INFO

    def test_downgrade_confidence_certain_to_high(self):
        assert BaselineFilter._downgrade_confidence(Confidence.CERTAIN) == Confidence.HIGH

    def test_downgrade_confidence_high_to_medium(self):
        assert BaselineFilter._downgrade_confidence(Confidence.HIGH) == Confidence.MEDIUM

    def test_downgrade_confidence_medium_to_low(self):
        assert BaselineFilter._downgrade_confidence(Confidence.MEDIUM) == Confidence.LOW
