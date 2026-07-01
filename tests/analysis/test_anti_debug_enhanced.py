"""Tests for Phase 12: Comprehensive anti-debug detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.models import (
    APICallInfo,
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
from src.analysis.core.semantic_analyzer import (
    SEMANTIC_RULES,
    SemanticAnalyzer,
    _check_kd_disable,
    _check_nt_set_info_thread,
    _check_nt_close,
    _check_nt_query_info_process,
    _check_nt_create_debug_object,
    _check_ob_register_callbacks,
    _check_system_debug_control,
    _check_psp_cid_table,
)
from src.analysis.core.anti_debug_detector import (
    ANTI_DEBUG_HIDE_APIS,
    ANTI_DEBUG_DETECT_APIS,
    ANTI_DEBUG_MANIPULATE_APIS,
    ANTI_DEBUG_BLOCK_APIS,
    ANTI_DEBUG_TRAP_APIS,
    ANTI_DEBUG_STRINGS,
    detect_anti_debug_apis,
    detect_anti_debug_strings,
    correlate_anti_debug,
    run_anti_debug_analysis,
    _check_api_category,
)


def _make_sample() -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="TestDriver",
        company="TestCo",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=0x10000,
    )


def _make_ir_with_api(func_addr: int, api_name: str) -> DisassemblyResult:
    """Create IR with a function that calls the given API."""
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
    func = Function(name=f"sub_{func_addr:X}", address=func_addr, size=0x200)
    ir.functions[func_addr] = func
    ir.function_apis[func_addr] = [api_name]
    ir.function_api_details[func_addr] = [
        APICallInfo(name=api_name, call_address=func_addr + 0x50),
    ]
    ir.ioctl_handlers[0x22A004] = func_addr
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    block = BasicBlock(
        address=func_addr,
        end_address=func_addr + 0x200,
        instructions=[
            Instruction(
                address=func_addr + 0x50,
                mnemonic="call",
                operands=api_name,
                api_target=api_name,
            ),
        ],
        successors=[],
    )
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg
    return ir


# ---------------------------------------------------------------------------
# Semantic rule check function tests
# ---------------------------------------------------------------------------

class TestAntiDebugSemanticRules:
    """Test new anti-debug semantic rule check functions."""

    def test_kd_disable_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="KdDisableDebugger", api_target="KdDisableDebugger")
        assert _check_kd_disable(None, 0, insn)

    def test_kd_refresh_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="KdRefreshDebuggerHidden", api_target="KdRefreshDebuggerHidden")
        assert _check_kd_disable(None, 0, insn)

    def test_kd_disable_no_api_target(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="", api_target=None)
        assert not _check_kd_disable(None, 0, insn)

    def test_nt_set_info_thread_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="NtSetInformationThread", api_target="NtSetInformationThread")
        assert _check_nt_set_info_thread(None, 0, insn)

    def test_zw_set_info_thread_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="ZwSetInformationThread", api_target="ZwSetInformationThread")
        assert _check_nt_set_info_thread(None, 0, insn)

    def test_nt_close_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="NtClose", api_target="NtClose")
        assert _check_nt_close(None, 0, insn)

    def test_zw_close_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="ZwClose", api_target="ZwClose")
        assert _check_nt_close(None, 0, insn)

    def test_nt_close_no_api_target(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="", api_target=None)
        assert not _check_nt_close(None, 0, insn)

    def test_nt_query_info_process_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="NtQueryInformationProcess", api_target="NtQueryInformationProcess")
        assert _check_nt_query_info_process(None, 0, insn)

    def test_nt_create_debug_object_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="NtCreateDebugObject", api_target="NtCreateDebugObject")
        assert _check_nt_create_debug_object(None, 0, insn)

    def test_ob_register_callbacks_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="ObRegisterCallbacks", api_target="ObRegisterCallbacks")
        assert _check_ob_register_callbacks(None, 0, insn)

    def test_ob_unregister_callbacks_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="ObUnRegisterCallbacks", api_target="ObUnRegisterCallbacks")
        assert _check_ob_register_callbacks(None, 0, insn)

    def test_system_debug_control_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="ZwSystemDebugControl", api_target="ZwSystemDebugControl")
        assert _check_system_debug_control(None, 0, insn)

    def test_psp_cid_table_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="PspCidTable", api_target="PspCidTable")
        assert _check_psp_cid_table(None, 0, insn)

    def test_non_api_not_detected(self):
        insn = Instruction(address=0x100, mnemonic="call", operands="DbgPrint", api_target="DbgPrint")
        assert not _check_nt_set_info_thread(None, 0, insn)
        assert not _check_nt_close(None, 0, insn)
        assert not _check_nt_query_info_process(None, 0, insn)
        assert not _check_nt_create_debug_object(None, 0, insn)
        assert not _check_ob_register_callbacks(None, 0, insn)
        assert not _check_system_debug_control(None, 0, insn)
        assert not _check_psp_cid_table(None, 0, insn)


# ---------------------------------------------------------------------------
# Anti-debug API detection tests
# ---------------------------------------------------------------------------

class TestAntiDebugAPIDetection:
    """Test API-based anti-debug detection."""

    def test_thread_hide_from_debugger(self):
        """NtSetInformationThread should be detected as anti-debug."""
        ir = _make_ir_with_api(0x1000, "NtSetInformationThread")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) >= 1
        assert "ThreadHideFromDebugger" in findings[0].description

    def test_process_debug_port_query(self):
        """NtQueryInformationProcess should be detected."""
        ir = _make_ir_with_api(0x2000, "NtQueryInformationProcess")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) >= 1
        assert "ProcessDebugPort" in findings[0].description

    def test_debug_object_creation(self):
        """NtCreateDebugObject should be detected."""
        ir = _make_ir_with_api(0x3000, "NtCreateDebugObject")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) >= 1
        assert "NtCreateDebugObject" in findings[0].description

    def test_ob_callbacks_detected(self):
        """ObRegisterCallbacks should be detected as debugger blocking."""
        ir = _make_ir_with_api(0x4000, "ObRegisterCallbacks")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) >= 1
        assert "ObRegisterCallbacks" in findings[0].description

    def test_nt_close_trap(self):
        """NtClose should be detected as anti-debug trap."""
        ir = _make_ir_with_api(0x5000, "NtClose")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) >= 1
        assert "NtClose" in findings[0].description

    def test_kd_disable_detected(self):
        """KdDisableDebugger should be detected."""
        ir = _make_ir_with_api(0x6000, "KdDisableDebugger")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) >= 1
        assert "KdDisableDebugger" in findings[0].description

    def test_system_debug_control(self):
        """ZwSystemDebugControl should be detected."""
        ir = _make_ir_with_api(0x7000, "ZwSystemDebugControl")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) >= 1
        assert "ZwSystemDebugControl" in findings[0].description

    def test_multiple_apis_grouped(self):
        """Multiple anti-debug APIs should be grouped by category."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func1 = Function(name="sub_1000", address=0x1000, size=0x100)
        func2 = Function(name="sub_2000", address=0x2000, size=0x100)
        ir.functions[0x1000] = func1
        ir.functions[0x2000] = func2
        ir.function_apis[0x1000] = ["NtSetInformationThread", "NtClose"]
        ir.function_apis[0x2000] = ["ObRegisterCallbacks"]
        ir.ioctl_handlers[0x22A004] = 0x1000

        findings = detect_anti_debug_apis(ir)
        # Should produce at least one finding
        assert len(findings) >= 1

    def test_clean_driver_no_api_findings(self):
        """Driver with only safe APIs should produce no anti-debug findings."""
        ir = _make_ir_with_api(0x8000, "DbgPrint")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) == 0

    def test_empty_ir_no_crash(self):
        """Empty IR should not crash anti-debug detection."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        findings = detect_anti_debug_apis(ir)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Anti-debug string detection tests
# ---------------------------------------------------------------------------

class TestAntiDebugStringDetection:
    """Test string-level anti-debug detection."""

    def _make_ir_with_strings(self, strings: list[str]) -> DisassemblyResult:
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = strings
        return ir

    def test_kd_debugger_enabled_string(self):
        """KdDebuggerEnabled string should be detected."""
        ir = self._make_ir_with_strings(["KdDebuggerEnabled"])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) >= 1
        assert "KdDebuggerEnabled" in findings[0].description

    def test_nt_global_flag_string(self):
        """NtGlobalFlag string should be detected."""
        ir = self._make_ir_with_strings(["NtGlobalFlag"])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) >= 1
        assert "NtGlobalFlag" in findings[0].description

    def test_softice_device_string(self):
        """\\.\ntice string should be detected."""
        ir = self._make_ir_with_strings([r"\\.\ntice"])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) >= 1
        assert "SoftICE" in findings[0].description

    def test_vmware_string(self):
        """VMware string should be detected."""
        ir = self._make_ir_with_strings(["VMware"])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) >= 1

    def test_virtualbox_string(self):
        """VirtualBox string should be detected."""
        ir = self._make_ir_with_strings(["VirtualBox"])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) >= 1

    def test_heap_flags_string(self):
        """HeapFlags string should be detected."""
        ir = self._make_ir_with_strings(["HeapFlags"])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) >= 1

    def test_multiple_strings_higher_severity(self):
        """3+ anti-debug strings should produce HIGH severity."""
        ir = self._make_ir_with_strings([
            "KdDebuggerEnabled",
            "NtGlobalFlag",
            "HeapFlags",
        ])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH

    def test_clean_driver_no_string_findings(self):
        """Driver with no anti-debug strings should produce no findings."""
        ir = self._make_ir_with_strings([
            "Copyright 2024 Test Corp",
            "Driver version 1.0.0",
        ])
        findings = detect_anti_debug_strings(ir)
        assert len(findings) == 0

    def test_empty_strings_no_crash(self):
        """Empty strings list should not crash."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        ir.strings = []
        findings = detect_anti_debug_strings(ir)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Anti-debug correlation tests
# ---------------------------------------------------------------------------

class TestAntiDebugCorrelation:
    """Test anti-debug signal correlation."""

    def test_single_signal_no_chain(self):
        """Single signal should not produce chain."""
        api = [Finding(
            category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="NtSetInformationThread",
        )]
        chains = correlate_anti_debug(api, [], [])
        assert len(chains) == 0

    def test_two_signals_low_confidence(self):
        """2 signals should produce LOW confidence chain."""
        api = [Finding(
            category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="NtSetInformationThread",
            context={"techniques": ["ThreadHideFromDebugger"]},
        )]
        str_findings = [Finding(
            category=FindingCategory.DANGEROUS_STRING,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="NtGlobalFlag",
            context={"techniques": ["NtGlobalFlag"]},
        )]
        chains = correlate_anti_debug(api, str_findings, [])
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.LOW

    def test_three_signals_medium_confidence(self):
        """3+ signals should produce MEDIUM confidence chain."""
        api = [
            Finding(
                category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="NtSetInformationThread",
                context={"techniques": ["Hide from debugger"]},
            ),
            Finding(
                category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="ObRegisterCallbacks",
                context={"techniques": ["Block debugger"]},
            ),
        ]
        str_findings = [Finding(
            category=FindingCategory.DANGEROUS_STRING,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="NtGlobalFlag",
            context={"techniques": ["NtGlobalFlag"]},
        )]
        chains = correlate_anti_debug(api, str_findings, [])
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.MEDIUM

    def test_five_plus_signals_high_confidence(self):
        """5+ signals should produce HIGH confidence chain."""
        api = [
            Finding(category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG, severity=Severity.HIGH, confidence=Confidence.MEDIUM, description="API 1", context={"techniques": ["Hide from debugger"]}),
            Finding(category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG, severity=Severity.HIGH, confidence=Confidence.MEDIUM, description="API 2", context={"techniques": ["Block debugger"]}),
            Finding(category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG, severity=Severity.HIGH, confidence=Confidence.MEDIUM, description="API 3", context={"techniques": ["Detect debugger"]}),
        ]
        str_findings = [
            Finding(category=FindingCategory.DANGEROUS_STRING, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, description="Str 1", context={"techniques": ["KdDebuggerEnabled"]}),
            Finding(category=FindingCategory.DANGEROUS_STRING, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, description="Str 2", context={"techniques": ["NtGlobalFlag"]}),
        ]
        chains = correlate_anti_debug(api, str_findings, [])
        assert len(chains) == 1
        assert chains[0].severity == Severity.CRITICAL
        assert chains[0].confidence == Confidence.HIGH

    def test_hide_block_detect_triggers_high(self):
        """Hide + block + detect should trigger HIGH even with 3 signals."""
        api = [
            Finding(category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG, severity=Severity.HIGH, confidence=Confidence.MEDIUM, description="Hide", context={"techniques": ["Hide from debugger"]}),
            Finding(category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG, severity=Severity.HIGH, confidence=Confidence.MEDIUM, description="Block", context={"techniques": ["Block debugger"]}),
            Finding(category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG, severity=Severity.HIGH, confidence=Confidence.MEDIUM, description="Detect", context={"techniques": ["Detect debugger"]}),
        ]
        chains = correlate_anti_debug(api, [], [])
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.HIGH
        assert chains[0].severity == Severity.CRITICAL

    def test_chain_has_context_fields(self):
        """Chain finding should have correlation context."""
        api = [
            Finding(category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG, severity=Severity.HIGH, confidence=Confidence.MEDIUM, description="API", context={"techniques": ["Hide from debugger"]}),
        ]
        str_findings = [
            Finding(category=FindingCategory.DANGEROUS_STRING, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, description="Str", context={"techniques": ["KdDebuggerEnabled"]}),
        ]
        chains = correlate_anti_debug(api, str_findings, [])
        assert len(chains) == 1
        ctx = chains[0].context
        assert "chain_type" in ctx
        assert ctx["chain_type"] == "anti_debug_correlated"
        assert "signal_count" in ctx
        assert ctx["signal_count"] == 2


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------

class TestAntiDebugIntegration:
    """Test full anti-debug analysis pipeline."""

    def test_run_anti_debug_with_api_and_strings(self):
        """Analysis with both API and string signals should correlate."""
        ir = _make_ir_with_api(0x1000, "NtSetInformationThread")
        ir.strings = ["NtGlobalFlag", "KdDebuggerEnabled"]
        sample = _make_sample()

        findings = run_anti_debug_analysis(sample, ir)
        # Should have API finding + string finding + (maybe) chain
        assert len(findings) >= 2
        assert any("ThreadHideFromDebugger" in f.description for f in findings)
        assert any("NtGlobalFlag" in f.description for f in findings)

    def test_run_anti_debug_clean_driver(self):
        """Clean driver should produce no anti-debug findings."""
        ir = _make_ir_with_api(0x1000, "DbgPrint")
        ir.strings = ["Copyright 2024"]
        sample = _make_sample()

        findings = run_anti_debug_analysis(sample, ir)
        assert len(findings) == 0

    def test_api_categories_are_defined(self):
        """All anti-debug API categories should have entries."""
        assert len(ANTI_DEBUG_HIDE_APIS) >= 1
        assert len(ANTI_DEBUG_DETECT_APIS) >= 1
        assert len(ANTI_DEBUG_MANIPULATE_APIS) >= 1
        assert len(ANTI_DEBUG_BLOCK_APIS) >= 1
        assert len(ANTI_DEBUG_TRAP_APIS) >= 1
        assert len(ANTI_DEBUG_STRINGS) >= 5

    def test_check_api_category_returns_hits(self):
        """_check_api_category should return matching hits."""
        ir = _make_ir_with_api(0x1000, "NtClose")
        hits = _check_api_category(ir, ANTI_DEBUG_TRAP_APIS)
        assert len(hits) >= 1
        assert hits[0]["api_name"] == "NtClose"

    def test_check_api_category_no_false_positives(self):
        """_check_api_category should not match safe APIs."""
        ir = _make_ir_with_api(0x1000, "IoCreateDevice")
        hits = _check_api_category(ir, ANTI_DEBUG_TRAP_APIS)
        assert len(hits) == 0


# ---------------------------------------------------------------------------
# Semantic analyzer integration with new anti-debug rules
# ---------------------------------------------------------------------------

class TestSemanticAnalyzerAntiDebugRules:
    """Test that new anti-debug rules are integrated into SemanticAnalyzer."""

    def test_new_rules_in_semetic_rules_list(self):
        """New anti-debug rules should be in SEMANTIC_RULES."""
        rule_ids = {r.rule_id for r in SEMANTIC_RULES}
        assert "SEM_KD_DISABLE" in rule_ids
        assert "SEM_NT_SET_INFO_THREAD" in rule_ids
        assert "SEM_NT_CLOSE" in rule_ids
        assert "SEM_NT_QUERY_INFO_PROCESS" in rule_ids
        assert "SEM_NT_DEBUG_OBJECT" in rule_ids
        assert "SEM_OB_CALLBACKS" in rule_ids
        assert "SEM_SYS_DEBUG_CONTROL" in rule_ids
        assert "SEM_PSP_CID_TABLE" in rule_ids

    def test_nt_set_info_thread_finding(self):
        """NtSetInformationThread API should produce ANTI_DEBUG_SYSTEM_FLAG finding."""
        ir = _make_ir_with_api(0x1000, "NtSetInformationThread")
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert any(
            f.category == FindingCategory.ANTI_DEBUG_SYSTEM_FLAG
            for f in findings
        )

    def test_ob_callbacks_finding(self):
        """ObRegisterCallbacks should produce ANTI_DEBUG_EXCEPTION finding."""
        ir = _make_ir_with_api(0x2000, "ObRegisterCallbacks")
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert any(
            f.category == FindingCategory.ANTI_DEBUG_EXCEPTION
            for f in findings
        )

    def test_psp_cid_table_finding(self):
        """PspCidTable should produce ANTI_DEBUG_SYSTEM_FLAG finding."""
        ir = _make_ir_with_api(0x3000, "PspCidTable")
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert any(
            f.category == FindingCategory.ANTI_DEBUG_SYSTEM_FLAG
            for f in findings
        )

    def test_nt_close_finding(self):
        """NtClose should produce ANTI_DEBUG_TRAP finding."""
        ir = _make_ir_with_api(0x4000, "NtClose")
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert any(
            f.category == FindingCategory.ANTI_DEBUG_TRAP
            for f in findings
        )

    def test_debug_object_finding(self):
        """NtCreateDebugObject should produce ANTI_DEBUG_SYSTEM_FLAG finding."""
        ir = _make_ir_with_api(0x5000, "NtCreateDebugObject")
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert any(
            f.category == FindingCategory.ANTI_DEBUG_SYSTEM_FLAG
            for f in findings
        )

    def test_system_debug_control_finding(self):
        """ZwSystemDebugControl should produce ANTI_DEBUG_SYSTEM_FLAG finding."""
        ir = _make_ir_with_api(0x6000, "ZwSystemDebugControl")
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert any(
            f.category == FindingCategory.ANTI_DEBUG_SYSTEM_FLAG
            for f in findings
        )
