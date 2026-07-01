"""Tests for Registry Callback detection (Phase 7)."""

from __future__ import annotations

from pathlib import Path

from src.analysis.core.registry_callback_detector import (
    RegistryCallbackDetector,
    REGISTRY_CALLBACK_APIS,
    REGISTRY_OPERATIONS,
    REGISTRY_PATH_PATTERNS,
    detect_registry_callback_apis,
    detect_registry_paths,
)
from src.models import (
    Architecture,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Sample,
    Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, api_names: list[str] | None = None) -> None:
    func = Function(name=f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    if api_names:
        ir.function_apis[addr] = api_names


class TestRegistryCallbackConstants:
    """Test registry callback detection constant definitions."""

    def test_callback_apis_defined(self):
        assert "CmRegisterCallback" in REGISTRY_CALLBACK_APIS
        assert "CmRegisterCallbackEx" in REGISTRY_CALLBACK_APIS
        assert "CmUnRegisterCallback" in REGISTRY_CALLBACK_APIS

    def test_registry_operations_defined(self):
        assert "ZwCreateKey" in REGISTRY_OPERATIONS
        assert "ZwSetValueKey" in REGISTRY_OPERATIONS
        assert "ZwDeleteKey" in REGISTRY_OPERATIONS
        assert "ZwEnumerateKey" in REGISTRY_OPERATIONS

    def test_registry_path_patterns_defined(self):
        assert "360Safe" in REGISTRY_PATH_PATTERNS
        assert "Qihoo" in REGISTRY_PATH_PATTERNS
        assert "Services\\" in REGISTRY_PATH_PATTERNS


class TestRegistryCallbackApiDetection:
    """Test registry callback API detection."""

    def test_ex_with_write_ops_critical(self):
        """CmRegisterCallbackEx + write operations should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CmRegisterCallbackEx"])
        _add_function(ir, 0x2000, ["ZwSetValueKey", "ZwDeleteKey"])
        findings = detect_registry_callback_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_callback_and_ops_high(self):
        """Callback registration + registry ops should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CmRegisterCallback"])
        _add_function(ir, 0x2000, ["ZwCreateKey"])
        findings = detect_registry_callback_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_callback_only_high(self):
        """Callback registration without registry ops should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CmRegisterCallback"])
        findings = detect_registry_callback_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ops_only_medium(self):
        """Registry ops without callback should be MEDIUM."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ZwCreateKey", "ZwDeleteKey"])
        findings = detect_registry_callback_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_registry_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_registry_callback_apis(ir)
        assert findings == []

    def test_multiple_callback_functions(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CmRegisterCallback"])
        _add_function(ir, 0x2000, ["CmUnRegisterCallback"])
        findings = detect_registry_callback_apis(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["callback_functions"]) == 2


class TestRegistryPathDetection:
    """Test registry path string detection."""

    def test_360_registry_path_critical(self):
        """360-specific registry path should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("\\Registry\\Machine\\SOFTWARE\\360Safe")
        findings = detect_registry_paths(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_qihoo_registry_path_critical(self):
        ir = _make_ir()
        ir.strings.append("Qihoo Software Registry")
        findings = detect_registry_paths(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_services_path_medium(self):
        """Services registry path without 360 should be MEDIUM."""
        ir = _make_ir()
        ir.strings.append("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\MyDriver")
        findings = detect_registry_paths(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_registry_paths(self):
        ir = _make_ir()
        findings = detect_registry_paths(ir)
        assert findings == []


class TestRegistryCallbackDetectorIntegration:
    """Test RegistryCallbackDetector end-to-end."""

    def test_analyzer_name(self):
        detector = RegistryCallbackDetector()
        assert detector.name == "RegistryCallbackDetector"

    def test_analyzer_description(self):
        detector = RegistryCallbackDetector()
        desc = detector.description
        assert "registry" in desc.lower()
        assert "callback" in desc.lower()

    def test_analyze_empty_ir(self):
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = RegistryCallbackDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_callback_and_path(self):
        """Callback API + registry path should produce findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CmRegisterCallbackEx"])
        ir.strings.append("\\Registry\\Machine\\SOFTWARE\\360Safe")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = RegistryCallbackDetector()
        findings = detector.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.REGISTRY_CALLBACK in categories

    def test_analyze_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CmRegisterCallback"])

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = RegistryCallbackDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
