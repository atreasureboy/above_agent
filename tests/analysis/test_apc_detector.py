"""Tests for Kernel APC / Thread Injection detection (Phase 6b)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.apc_detector import (
    ApcInjectionDetector,
    APC_APIS,
    THREAD_HIJACK_APIS,
    KAPC_OFFSETS,
    detect_apc_apis,
    detect_thread_hijack,
    detect_kapc_structure,
)
from src.models import (
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Severity,
    Sample,
    Architecture,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, api_names: list[str] | None = None) -> None:
    func = Function(name=f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    if api_names:
        ir.function_apis[addr] = api_names


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


class TestApcConstants:
    """Test APC detection constant definitions."""

    def test_apc_apis_defined(self):
        assert "KeInitializeApc" in APC_APIS
        assert "KeInsertQueueApc" in APC_APIS
        assert "KeForceInsertQueueApc" in APC_APIS

    def test_thread_hijack_apis_defined(self):
        assert "ZwSuspendThread" in THREAD_HIJACK_APIS
        assert "ZwGetContextThread" in THREAD_HIJACK_APIS
        assert "ZwSetContextThread" in THREAD_HIJACK_APIS

    def test_kapc_offsets_defined(self):
        assert 0x20 in KAPC_OFFSETS  # KernelRoutine
        assert 0x28 in KAPC_OFFSETS  # RundownRoutine
        assert 0x30 in KAPC_OFFSETS  # NormalRoutine


class TestApcApiDetection:
    """Test kernel APC API detection."""

    def test_force_insert_critical(self):
        """KeForceInsertQueueApc should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["KeForceInsertQueueApc"])
        findings = detect_apc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_full_chain_critical(self):
        """Initialize + Insert should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["KeInitializeApc", "KeInsertQueueApc"])
        findings = detect_apc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_multiple_functions_high(self):
        """2+ APC functions without full chain should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["KeInitializeApc"])
        _add_function(ir, 0x2000, ["KeFlushQueuedApcs"])
        findings = detect_apc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_single_api_medium(self):
        """Single APC API should be MEDIUM."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["KeInitializeApc"])
        findings = detect_apc_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_apc_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_apc_apis(ir)
        assert findings == []


class TestThreadHijackDetection:
    """Test thread hijack API detection."""

    def test_full_hijack_critical(self):
        """Suspend+Resume+Context should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "ZwSuspendThread",
            "ZwResumeThread",
            "ZwGetContextThread",
            "ZwSetContextThread",
        ])
        findings = detect_thread_hijack(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_context_only_high(self):
        """Context read/write without suspend should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "ZwGetContextThread",
            "ZwSetContextThread",
        ])
        findings = detect_thread_hijack(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_suspend_resume_medium(self):
        """Suspend+Resume without context should be MEDIUM."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "ZwSuspendThread",
            "ZwResumeThread",
        ])
        findings = detect_thread_hijack(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_single_api_low(self):
        """Single suspend-only API should be LOW."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ZwSuspendThread"])
        findings = detect_thread_hijack(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_no_hijack_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_thread_hijack(ir)
        assert findings == []


class TestKapcStructureDetection:
    """Test KAPC structure initialization pattern detection."""

    def test_kapc_initialization_detected(self):
        """Function writing KAPC offsets should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rcx+0x20], rdx"),   # KernelRoutine
            ("mov", "qword ptr [rcx+0x28], r8"),    # RundownRoutine
            ("mov", "qword ptr [rcx+0x30], r9"),    # NormalRoutine
            ("mov", "qword ptr [rcx+0x38], r10"),   # NormalContext
        ])
        findings = detect_kapc_structure(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.APC_INJECTION
        assert findings[0].severity == Severity.HIGH

    def test_few_offsets_not_flagged(self):
        """Fewer than 3 KAPC offsets should not trigger."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rcx+0x20], rdx"),
        ])
        findings = detect_kapc_structure(ir)
        assert findings == []

    def test_no_functions(self):
        ir = _make_ir()
        findings = detect_kapc_structure(ir)
        assert findings == []


class TestApcInjectionDetectorIntegration:
    """Test ApcInjectionDetector end-to-end."""

    def test_analyzer_name(self):
        detector = ApcInjectionDetector()
        assert detector.name == "ApcInjectionDetector"

    def test_analyzer_description(self):
        detector = ApcInjectionDetector()
        desc = detector.description
        assert "APC" in desc or "apc" in desc.lower()
        assert "hijack" in desc.lower()

    def test_analyze_empty_ir(self):
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = ApcInjectionDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_apc_and_hijack(self):
        """APC APIs + thread hijack should produce findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["KeInitializeApc", "KeInsertQueueApc"])
        _add_function(ir, 0x2000, ["ZwSuspendThread", "ZwSetContextThread"])

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = ApcInjectionDetector()
        findings = detector.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.APC_INJECTION in categories

    def test_analyze_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["KeForceInsertQueueApc"])

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = ApcInjectionDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
