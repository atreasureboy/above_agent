"""Tests for DKOM / hidden process detection (Phase 4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.dkom_detector import (
    DkomDetector,
    APL_OFFSETS,
    PROCESS_LIST_STRINGS,
    THREAD_LIST_STRINGS,
    CID_TABLE_STRINGS,
    TOKEN_STRINGS,
    TOKEN_APIS,
    detect_process_unlink,
    detect_thread_unlink,
    detect_cid_table,
    detect_token_manipulation,
)
from src.models import (
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    BasicBlock,
    CFG,
    Confidence,
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


class TestDkomConstants:
    """Test DKOM detection constant definitions."""

    def test_apl_offsets_defined(self):
        assert 0x2E8 in APL_OFFSETS
        assert 0x2F0 in APL_OFFSETS
        assert 0x448 in APL_OFFSETS

    def test_process_list_strings_defined(self):
        assert "PsActiveProcessHead" in PROCESS_LIST_STRINGS
        assert "ActiveProcessLinks" in PROCESS_LIST_STRINGS
        assert "_EPROCESS" in PROCESS_LIST_STRINGS

    def test_thread_list_strings_defined(self):
        assert "ThreadListEntry" in THREAD_LIST_STRINGS
        assert "_ETHREAD" in THREAD_LIST_STRINGS

    def test_cid_table_strings_defined(self):
        assert "PspCidTable" in CID_TABLE_STRINGS
        assert "HandleTable" in CID_TABLE_STRINGS

    def test_token_strings_defined(self):
        assert "Token" in TOKEN_STRINGS
        assert "ImpersonationToken" in TOKEN_STRINGS
        assert "PrimaryToken" in TOKEN_STRINGS

    def test_token_apis_defined(self):
        assert "PsReferencePrimaryToken" in TOKEN_APIS
        assert "PsRevertToSelf" in TOKEN_APIS
        assert "SePrivilegeCheck" in TOKEN_APIS


class TestProcessUnlinkDetection:
    """Test EPROCESS.ActiveProcessLinks unlink detection."""

    def test_ps_active_process_head_string(self):
        """PsActiveProcessHead string should trigger detection."""
        ir = _make_ir()
        ir.strings.append("PsActiveProcessHead")
        findings = detect_process_unlink(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.DKOM_PROCESS_UNLINK

    def test_active_process_links_string(self):
        """ActiveProcessLinks string should trigger detection."""
        ir = _make_ir()
        ir.strings.append("ActiveProcessLinks")
        findings = detect_process_unlink(ir)
        assert len(findings) == 1

    def test_apl_offset_instruction_access(self):
        """APL offset access in instructions should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, qword ptr [rbx+0x2e8]"),
            ("mov", "rcx, qword ptr [rbx+0x2f0]"),
            ("mov", "qword ptr [rax+8], rcx"),
        ])
        findings = detect_process_unlink(ir)
        assert len(findings) == 1
        assert len(findings[0].context["apl_functions"]) == 1

    def test_combined_string_and_instruction_critical(self):
        """APL offsets + process list strings should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("PsActiveProcessHead")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, qword ptr [rbx+0x2e8]"),
        ])
        findings = detect_process_unlink(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_string_only_medium(self):
        """String-only detection should be MEDIUM."""
        ir = _make_ir()
        ir.strings.append("ActiveProcessLinks")
        findings = detect_process_unlink(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_process_indicators(self):
        ir = _make_ir()
        findings = detect_process_unlink(ir)
        assert findings == []


class TestThreadUnlinkDetection:
    """Test ETHREAD.ThreadListEntry unlink detection."""

    def test_thread_list_entry_string(self):
        """ThreadListEntry string should trigger detection."""
        ir = _make_ir()
        ir.strings.append("ThreadListEntry")
        findings = detect_thread_unlink(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.DKOM_THREAD_UNLINK

    def test_ethread_string(self):
        """ETHREAD string should trigger detection."""
        ir = _make_ir()
        ir.strings.append("_ETHREAD")
        findings = detect_thread_unlink(ir)
        assert len(findings) == 1

    def test_no_thread_indicators(self):
        ir = _make_ir()
        findings = detect_thread_unlink(ir)
        assert findings == []


class TestCIDTableDetection:
    """Test PspCidTable manipulation detection."""

    def test_psp_cid_table_string(self):
        """PspCidTable string should trigger CRITICAL detection."""
        ir = _make_ir()
        ir.strings.append("PspCidTable")
        findings = detect_cid_table(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].context["has_psp_cid_table"] is True

    def test_handle_table_string(self):
        """HandleTable string should trigger HIGH detection."""
        ir = _make_ir()
        ir.strings.append("HandleTable")
        findings = detect_cid_table(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_no_cid_indicator(self):
        ir = _make_ir()
        findings = detect_cid_table(ir)
        assert findings == []


class TestTokenManipulationDetection:
    """Test token manipulation detection."""

    def test_token_string_detected(self):
        """Token string should trigger detection."""
        ir = _make_ir()
        ir.strings.append("PrimaryToken")
        findings = detect_token_manipulation(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.DKOM_TOKEN

    def test_impersonation_string_detected(self):
        """ImpersonationToken should trigger CRITICAL detection."""
        ir = _make_ir()
        ir.strings.append("ImpersonationToken")
        findings = detect_token_manipulation(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_token_api_detected(self):
        """Token APIs in function_apis should trigger CRITICAL detection."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["PsReferencePrimaryToken"])
        findings = detect_token_manipulation(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert len(findings[0].context["token_functions"]) == 1

    def test_multiple_token_apis(self):
        """Multiple token APIs should all be detected."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "PsReferencePrimaryToken",
            "PsRevertToSelf",
            "SePrivilegeCheck",
        ])
        findings = detect_token_manipulation(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["token_functions"]) == 1
        assert len(ctx["token_functions"][0]["apis"]) == 3

    def test_no_token_indicator(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_token_manipulation(ir)
        assert findings == []


class TestDkomDetectorIntegration:
    """Test DkomDetector end-to-end."""

    def test_analyzer_name(self):
        detector = DkomDetector()
        assert detector.name == "DkomDetector"

    def test_analyzer_description(self):
        detector = DkomDetector()
        desc = detector.description
        assert "DKOM" in desc or "dkom" in desc.lower()
        assert "unlink" in desc.lower()

    def test_analyze_empty_ir(self):
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = DkomDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_all_dkom_types(self):
        """Should detect process unlink, thread unlink, CID table, and token."""
        ir = _make_ir()
        # Process unlink
        ir.strings.append("PsActiveProcessHead")
        # Thread unlink
        ir.strings.append("ThreadListEntry")
        # CID table
        ir.strings.append("PspCidTable")
        # Token
        _add_function(ir, 0x1000, ["PsReferencePrimaryToken"])

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = DkomDetector()
        findings = detector.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.DKOM_PROCESS_UNLINK in categories
        assert FindingCategory.DKOM_THREAD_UNLINK in categories
        assert FindingCategory.DKOM_CID_TABLE in categories
        assert FindingCategory.DKOM_TOKEN in categories

    def test_analyze_findings_have_evidence(self):
        ir = _make_ir()
        ir.strings.append("PsActiveProcessHead")
        ir.strings.append("PspCidTable")
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = DkomDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
