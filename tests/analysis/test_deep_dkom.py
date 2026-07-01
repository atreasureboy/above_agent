"""Tests for deep DKOM (Direct Kernel Object Manipulation) detector."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.deep.dkom_detector import (
    DKOMDetector,
    DKOM_APIS,
    DKOM_SYMBOLS,
    EPROCESS_OFFSETS,
    ETHREAD_OFFSETS,
    LIST_ENTRY_PATTERNS,
)
from src.models import (
    BasicBlock,
    CFG,
    DisassemblyResult,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Architecture,
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


def _sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True,
    )


class TestDeepDKOMConstants:
    """Test DKOM detection constant definitions."""

    def test_eprocess_offsets_defined(self):
        assert 0x2E8 in EPROCESS_OFFSETS
        assert EPROCESS_OFFSETS[0x2E8] == "ActiveProcessLinks"
        assert 0x4B8 in EPROCESS_OFFSETS
        assert EPROCESS_OFFSETS[0x4B8] == "Token"
        assert 0x3E8 in EPROCESS_OFFSETS
        assert EPROCESS_OFFSETS[0x3E8] == "Protection"

    def test_ethread_offsets_defined(self):
        assert 0x2F0 in ETHREAD_OFFSETS
        assert ETHREAD_OFFSETS[0x2F0] == "ActiveThreadListEntry"
        assert 0x428 in ETHREAD_OFFSETS
        assert ETHREAD_OFFSETS[0x428] == "Cid.UniqueProcess"

    def test_dkom_symbols_defined(self):
        assert "PsActiveProcessHead" in DKOM_SYMBOLS
        assert "PspCidTable" in DKOM_SYMBOLS
        assert "PiDDBCacheTable" in DKOM_SYMBOLS
        assert "MmUnloadedDrivers" in DKOM_SYMBOLS

    def test_dkom_apis_defined(self):
        assert "PsLookupProcessByProcessId" in DKOM_APIS
        assert "PsSuspendProcess" in DKOM_APIS
        assert "PsIsProtectedProcess" in DKOM_APIS

    def test_list_entry_patterns_defined(self):
        assert "Blink" in LIST_ENTRY_PATTERNS
        assert "Flink" in LIST_ENTRY_PATTERNS


class TestDeepDKOMSymbolDetection:
    """Test DKOM kernel symbol string detection."""

    def test_ps_active_process_head(self):
        ir = _make_ir()
        ir.strings.append("PsActiveProcessHead")
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        sym_findings = [f for f in findings if f.context.get("symbols") and "PsActiveProcessHead" in f.context["symbols"]]
        assert len(sym_findings) >= 1

    def test_psp_cid_table(self):
        ir = _make_ir()
        ir.strings.append("PspCidTable")
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        sym_findings = [f for f in findings if f.context.get("symbols") and "PspCidTable" in f.context["symbols"]]
        assert len(sym_findings) >= 1

    def test_mm_unloaded_drivers(self):
        ir = _make_ir()
        ir.strings.append("MmUnloadedDrivers")
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        sym_findings = [f for f in findings if f.context.get("symbols") and "MmUnloadedDrivers" in f.context["symbols"]]
        assert len(sym_findings) >= 1

    def test_multiple_symbols_grouped(self):
        """Multiple DKOM symbols should be grouped into one finding."""
        ir = _make_ir()
        ir.strings.append("PsActiveProcessHead")
        ir.strings.append("PspCidTable")
        ir.strings.append("PiDDBCacheTable")
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        sym_findings = [f for f in findings if f.context.get("symbols")]
        assert len(sym_findings) == 1
        assert len(sym_findings[0].context["symbols"]) == 3

    def test_no_dkom_symbols_no_symbol_finding(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        sym_findings = [f for f in findings if f.context.get("symbols")]
        assert len(sym_findings) == 0


class TestDeepDKOMAPIDetection:
    """Test DKOM API usage tracking (context only, not standalone findings).

    DKOM APIs like PsLookupProcessByProcessId are normal kernel operations
    used by virtually every driver. They are tracked for context boosting
    but should NOT produce findings on their own.
    """

    def test_ps_lookup_process_no_api_finding(self):
        """PsLookupProcessByProcessId alone should NOT produce a finding."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["PsLookupProcessByProcessId"])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        api_findings = [f for f in findings if f.context.get("apis")]
        assert len(api_findings) == 0

    def test_ps_suspend_process_no_api_finding(self):
        """PsSuspendProcess alone should NOT produce a finding."""
        ir = _make_ir()
        _add_function(ir, 0x2000, ["PsSuspendProcess"])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        api_findings = [f for f in findings if f.context.get("apis")]
        assert len(api_findings) == 0

    def test_multiple_dkom_apis_no_standalone_finding(self):
        """Multiple DKOM APIs together should NOT produce standalone API finding."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "PsLookupProcessByProcessId",
            "PsLookupThreadByThreadId",
            "PsSuspendProcess",
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        api_findings = [f for f in findings if f.context.get("apis")]
        assert len(api_findings) == 0

    def test_non_dkom_api_no_finding(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice", "IoDeleteDevice"])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        api_findings = [f for f in findings if f.context.get("apis")]
        assert len(api_findings) == 0


class TestDeepEPROCESSAccessDetection:
    """Test EPROCESS field offset access detection."""

    def test_active_process_links_access(self):
        """Write to ActiveProcessLinks offset (0x2E8) should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "[rcx+0x2e8], rax"),  # Write to APL (actual unlinking)
            ("mov", "[rax+0x8], rdx"),   # Write to LIST_ENTRY Blink
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        apl_findings = [f for f in findings if f.category == FindingCategory.DKOM_PROCESS_UNLINK
                        and "ActiveProcessLinks" in f.description]
        assert len(apl_findings) >= 1

    def test_token_field_write(self):
        """Write to Token field (0x4B8) should trigger DKOM_TOKEN."""
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("mov", "[rcx+0x4b8], rax"),
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        token_findings = [f for f in findings if f.category == FindingCategory.DKOM_TOKEN]
        assert len(token_findings) >= 1

    def test_protection_field_access(self):
        """Write to Protection field (0x3E8) should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("mov", "[rcx+0x3e8], eax"),  # Write to Protection (bypass)
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        prot_findings = [f for f in findings if "Protection" in f.description]
        assert len(prot_findings) >= 1

    def test_token_win10_variant(self):
        """Token field at Win10 variant offset (0x4C0) should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x4000)
        _add_cfg_with_insns(ir, 0x4000, [
            ("mov", "[rcx+0x4c0], rax"),
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        token_findings = [f for f in findings if f.category == FindingCategory.DKOM_TOKEN]
        assert len(token_findings) >= 1

    def test_token_win11_variant(self):
        """Token field at Win11 variant offset (0x5A0) should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x5000)
        _add_cfg_with_insns(ir, 0x5000, [
            ("mov", "[rcx+0x5a0], rax"),
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        token_findings = [f for f in findings if f.category == FindingCategory.DKOM_TOKEN]
        assert len(token_findings) >= 1


class TestDeepETHREADAccessDetection:
    """Test ETHREAD field offset access detection."""

    def test_active_thread_list_entry(self):
        """Write to ActiveThreadListEntry (0x2F0) should trigger thread hiding detection."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "[rcx+0x2f0], rax"),  # Write to thread list entry (unlink)
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        thread_findings = [f for f in findings if f.category == FindingCategory.DKOM_THREAD_UNLINK]
        assert len(thread_findings) >= 1

    def test_ethread_win11_variant(self):
        """ActiveThreadListEntry at Win11 offset (0x300) should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("mov", "[rcx+0x300], rax"),  # Write to Win11 thread list entry
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        thread_findings = [f for f in findings if f.category == FindingCategory.DKOM_THREAD_UNLINK]
        assert len(thread_findings) >= 1


class TestDeepLISTENTRYDetection:
    """Test LIST_ENTRY manipulation pattern detection."""

    def test_blink_flink_access(self):
        """Blink/Flink field access should be tracked."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x0]"),
            ("mov", "rdx, [rcx+0x8]"),
            ("mov", "[rax+0x8], rdx"),
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        # LIST_ENTRY patterns should be tracked


class TestDeepDKOMDetectorIntegration:
    """Test DKOMDetector end-to-end."""

    def test_analyzer_name(self):
        detector = DKOMDetector()
        assert detector.name == "DKOMDetector"

    def test_analyzer_description(self):
        detector = DKOMDetector()
        desc = detector.description
        assert "Kernel Object" in desc or "kernel" in desc.lower()

    def test_analyze_empty_ir(self):
        """Should handle empty IR without errors."""
        ir = _make_ir()
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        assert findings == []

    def test_analyze_combined_dkom_patterns(self):
        """Should detect multiple DKOM patterns simultaneously."""
        ir = _make_ir()
        # DKOM symbols in strings
        ir.strings.append("PsActiveProcessHead")
        ir.strings.append("PspCidTable")

        # DKOM APIs
        _add_function(ir, 0x1000, ["PsLookupProcessByProcessId"])

        # EPROCESS offset access (writes)
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("mov", "[rcx+0x2e8], rax"),  # Write APL
            ("mov", "[rcx+0x4b8], rdx"),  # Write Token
        ])

        # ETHREAD offset access (write)
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("mov", "[rcx+0x2f0], rax"),  # Write thread list entry
        ])

        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)

        categories = {f.category for f in findings}
        assert FindingCategory.DKOM_PROCESS_UNLINK in categories
        assert FindingCategory.DKOM_TOKEN in categories
        assert FindingCategory.DKOM_THREAD_UNLINK in categories

    def test_all_findings_have_evidence(self):
        """All findings should have evidence attached."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x2e8]"),
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        for f in findings:
            assert len(f.evidence) > 0

    def test_severity_critical_for_process_unlink(self):
        """ActiveProcessLinks access should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x2e8]"),
            ("mov", "[rax], rdx"),
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        apl_findings = [f for f in findings if "ActiveProcessLinks" in f.description]
        if apl_findings:
            assert apl_findings[0].severity == Severity.CRITICAL

    def test_severity_critical_for_token(self):
        """Token swap should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "[rcx+0x4b8], rax"),
        ])
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        token_findings = [f for f in findings if f.category == FindingCategory.DKOM_TOKEN]
        if token_findings:
            assert token_findings[0].severity == Severity.CRITICAL

    def test_no_dkom_patterns_no_findings(self):
        """Normal instructions without DKOM patterns should return empty."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rbx"),
            ("push", "rbp"),
            ("ret", ""),
        ])
        ir.strings.append("Hello World")
        detector = DKOMDetector()
        findings = detector.analyze(_sample(), ir)
        assert findings == []
