"""Tests for Object Callback protection detection (Phase 8)."""

from __future__ import annotations

from pathlib import Path

from src.analysis.core.object_callback_detector import (
    ObjectCallbackDetector,
    OBJECT_CALLBACK_APIS,
    OBJECT_TYPES,
    ACCESS_RIGHTS,
    OB_CALLBACK_OFFSETS,
    detect_object_callback_apis,
    detect_object_types,
    detect_ob_callback_structure,
)
from src.models import (
    Architecture,
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
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


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


class TestObjectCallbackConstants:
    """Test object callback detection constant definitions."""

    def test_callback_apis_defined(self):
        assert "ObRegisterCallbacks" in OBJECT_CALLBACK_APIS
        assert "ObUnRegisterCallbacks" in OBJECT_CALLBACK_APIS

    def test_object_types_defined(self):
        assert "PsProcessType" in OBJECT_TYPES
        assert "PsThreadType" in OBJECT_TYPES
        assert "ExDesktopObjectType" in OBJECT_TYPES

    def test_access_rights_defined(self):
        assert 0x0001 in ACCESS_RIGHTS  # PROCESS_TERMINATE
        assert 0x0008 in ACCESS_RIGHTS  # PROCESS_VM_READ
        assert 0x0010 in ACCESS_RIGHTS  # PROCESS_VM_WRITE
        assert 0x2000 in ACCESS_RIGHTS  # THREAD_SUSPEND_RESUME

    def test_ob_callback_offsets_defined(self):
        assert 0x00 in OB_CALLBACK_OFFSETS  # ObjectType
        assert 0x08 in OB_CALLBACK_OFFSETS  # Operations flags
        assert 0x10 in OB_CALLBACK_OFFSETS  # PreOperation
        assert 0x18 in OB_CALLBACK_OFFSETS  # PostOperation


class TestObjectCallbackApiDetection:
    """Test ObRegisterCallbacks API detection."""

    def test_ob_register_callbacks_high(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ObRegisterCallbacks"])
        findings = detect_object_callback_apis(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.OBJECT_CALLBACK
        assert findings[0].severity == Severity.HIGH

    def test_multiple_callback_functions(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ObRegisterCallbacks"])
        _add_function(ir, 0x2000, ["ObUnRegisterCallbacks"])
        findings = detect_object_callback_apis(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["callback_functions"]) == 2

    def test_no_callback_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_object_callback_apis(ir)
        assert findings == []


class TestObjectTypeDetection:
    """Test object type string reference detection."""

    def test_process_type_critical(self):
        """PsProcessType reference should be HIGH."""
        ir = _make_ir()
        ir.strings.append("PsProcessType")
        findings = detect_object_types(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_thread_type_critical(self):
        """PsThreadType reference should be HIGH."""
        ir = _make_ir()
        ir.strings.append("PsThreadType")
        findings = detect_object_types(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_process_and_thread_critical(self):
        """Both process and thread type should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("PsProcessType")
        ir.strings.append("PsThreadType")
        findings = detect_object_types(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_other_type_medium(self):
        """Non-process/thread type should be MEDIUM."""
        ir = _make_ir()
        ir.strings.append("ExDesktopObjectType")
        findings = detect_object_types(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_object_types(self):
        ir = _make_ir()
        findings = detect_object_types(ir)
        assert findings == []


class TestObCallbackStructureDetection:
    """Test OB_OPERATION_REGISTRATION structure initialization detection."""

    def test_callback_structure_detected(self):
        """Function writing OB_CALLBACK offsets should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rcx+0x0], rdx"),   # ObjectType
            ("mov", "qword ptr [rcx+0x10], r8"),   # PreOperation
            ("mov", "qword ptr [rcx+0x18], r9"),   # PostOperation
        ])
        findings = detect_ob_callback_structure(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.OBJECT_CALLBACK

    def test_pre_op_and_type_critical(self):
        """PreOperation + ObjectType should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rax+0x0], rdx"),   # ObjectType
            ("mov", "qword ptr [rax+0x10], r8"),   # PreOperation
        ])
        findings = detect_ob_callback_structure(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_single_offset_not_flagged(self):
        """Single offset alone should not trigger (need >= 2 for confidence)."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rax+0x10], r8"),   # PreOperation only
        ])
        findings = detect_ob_callback_structure(ir)
        assert findings == []

    def test_few_offsets_not_flagged(self):
        """Single non-callback offset should not trigger."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rax+0x8], rbx"),
        ])
        findings = detect_ob_callback_structure(ir)
        assert findings == []

    def test_no_functions(self):
        ir = _make_ir()
        findings = detect_ob_callback_structure(ir)
        assert findings == []


class TestObjectCallbackDetectorIntegration:
    """Test ObjectCallbackDetector end-to-end."""

    def test_analyzer_name(self):
        detector = ObjectCallbackDetector()
        assert detector.name == "ObjectCallbackDetector"

    def test_analyzer_description(self):
        detector = ObjectCallbackDetector()
        desc = detector.description
        assert "ObRegisterCallbacks" in desc or "object" in desc.lower()
        assert "callback" in desc.lower()

    def test_analyze_empty_ir(self):
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = ObjectCallbackDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_callback_and_type(self):
        """ObRegisterCallbacks API + object type strings should produce findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ObRegisterCallbacks"])
        ir.strings.append("PsProcessType")
        ir.strings.append("PsThreadType")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = ObjectCallbackDetector()
        findings = detector.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.OBJECT_CALLBACK in categories

    def test_analyze_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ObRegisterCallbacks"])

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = ObjectCallbackDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
