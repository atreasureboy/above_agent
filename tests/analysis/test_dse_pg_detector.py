"""Tests for DSE bypass / PatchGuard trigger detector (dse_pg_detector.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.deep.dse_pg_detector import (
    DSEPgAnalyzer,
    DSE_STRINGS,
    DSE_APIS,
    PATCHGUARD_STRINGS,
    PATCHGUARD_APIS,
    ETW_STRINGS,
    ETW_APIS,
    KPP_CALLBACK_STRINGS,
    KPP_CALLBACK_APIS,
    PATCHGUARD_BUGCHECK_CODES,
    detect_dse_bypass,
    detect_patchguard_trigger,
    detect_etw_bypass,
    detect_kpp_callback_disable,
)
from src.models import (
    BasicBlock,
    CFG,
    Confidence,
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


# ===================================================================
# Constants tests
# ===================================================================

class TestDSEPgConstants:
    """Test constant definitions."""

    def test_dse_strings_defined(self):
        assert "g_CiOptions" in DSE_STRINGS
        assert "CiInitialize" in DSE_STRINGS
        assert "SepInitializeCodeIntegrity" in DSE_STRINGS

    def test_dse_apis_defined(self):
        assert "ZwSetSystemInformation" in DSE_APIS
        assert "ZwLoadDriver" in DSE_APIS

    def test_patchguard_strings_defined(self):
        assert "KeBugCheckEx" in PATCHGUARD_STRINGS
        assert "KiSystemCall64" in PATCHGUARD_STRINGS
        assert "KdPitchDebugger" in PATCHGUARD_STRINGS

    def test_patchguard_apis_defined(self):
        assert "KeBugCheckEx" in PATCHGUARD_APIS
        assert "RtlCaptureContext" in PATCHGUARD_APIS

    def test_patchguard_bugcheck_codes(self):
        assert 0x00000109 in PATCHGUARD_BUGCHECK_CODES  # CRITICAL_STRUCTURE_CORRUPTION
        assert 0x00000132 in PATCHGUARD_BUGCHECK_CODES  # SECURE_KERNEL_ERROR

    def test_etw_strings_defined(self):
        assert "EtwThreatIntProvRegHandle" in ETW_STRINGS
        assert "Etwp" in ETW_STRINGS

    def test_etw_apis_defined(self):
        assert "EtwUnregister" in ETW_APIS or "EtwpUnregisterProvider" in ETW_APIS
        assert "NtTraceControl" in ETW_APIS

    def test_kpp_callback_strings_defined(self):
        assert "PsSetCreateProcessNotifyRoutine" in KPP_CALLBACK_STRINGS
        assert "CmRegisterCallbackEx" in KPP_CALLBACK_STRINGS
        assert "ObRegisterCallbacks" in KPP_CALLBACK_STRINGS

    def test_kpp_callback_apis_defined(self):
        assert "PsSetCreateProcessNotifyRoutine" in KPP_CALLBACK_APIS
        assert "CmUnRegisterCallback" in KPP_CALLBACK_APIS
        assert "ObUnRegisterCallbacks" in KPP_CALLBACK_APIS


# ===================================================================
# DSE Bypass detection tests
# ===================================================================

class TestDSEBypassDetection:
    """Test DSE bypass detection."""

    def test_g_cioptions_string_detected(self):
        ir = _make_ir()
        ir.strings.append("g_CiOptions")
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.DSE_BYPASS
        assert findings[0].context.get("has_g_cioptions") is True

    def test_ci_initialize_detected(self):
        ir = _make_ir()
        ir.strings.append("CiInitialize")
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1

    def test_testsigning_detected(self):
        ir = _make_ir()
        ir.strings.append("TESTSIGNING")
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1
        assert findings[0].context.get("has_testsigning") is True

    def test_dse_api_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ZwSetSystemInformation"])
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1
        assert len(findings[0].context.get("dse_api_functions", [])) >= 1

    def test_multiple_dse_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ZwSetSystemInformation", "ZwLoadDriver", "ZwUnloadDriver"])
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1
        assert len(findings[0].context["dse_api_functions"][0]["apis"]) == 3

    def test_dse_string_plus_instruction_critical(self):
        """String + instruction pattern should be CRITICAL severity."""
        ir = _make_ir()
        ir.strings.append("g_CiOptions")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("lea", "rax, [rip+0x1234]"),
            ("mov", "dword ptr [rip+0x1234], 0x6"),
        ])
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].confidence == Confidence.HIGH

    def test_dse_string_only_high(self):
        """String-only detection should be HIGH severity."""
        ir = _make_ir()
        ir.strings.append("g_CiOptions")
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH

    def test_no_dse_patterns_no_finding(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        findings = detect_dse_bypass(ir)
        assert findings == []

    def test_hvci_bypass_detected(self):
        ir = _make_ir()
        ir.strings.append("HviIsAnyHypervisorPresent")
        findings = detect_dse_bypass(ir)
        assert len(findings) >= 1


# ===================================================================
# PatchGuard Trigger detection tests
# ===================================================================

class TestPatchGuardTriggerDetection:
    """Test PatchGuard trigger detection."""

    def test_kebugcheckex_detected(self):
        ir = _make_ir()
        ir.strings.append("KeBugCheckEx")
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.PATCHGUARD_TRIGGER

    def test_ki_system_call_64_detected(self):
        ir = _make_ir()
        ir.strings.append("KiSystemCall64")
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1

    def test_kd_pitch_debugger_detected(self):
        ir = _make_ir()
        ir.strings.append("KdPitchDebugger")
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1

    def test_explicit_patchguard_reference_critical(self):
        """Explicit PatchGuard string should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("PatchGuard")
        ir.strings.append("KeBugCheckEx")
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1
        assert findings[0].context.get("has_explicit_patchguard_ref") is True

    def test_critical_structure_corruption_critical(self):
        """BugCheck 0x109 (CRITICAL_STRUCTURE_CORRUPTION) should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("KeBugCheckEx")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("push", "0x109"),
        ])
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1
        assert findings[0].context.get("has_critical_structure_corruption") is True

    def test_bugcheck_api_function(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["KeBugCheckEx", "RtlCaptureContext"])
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1
        assert len(findings[0].context.get("patchguard_api_functions", [])) >= 1

    def test_kd_debugger_enabled(self):
        ir = _make_ir()
        ir.strings.append("KdDebuggerEnabled")
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1

    def test_no_patchguard_patterns_no_finding(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        findings = detect_patchguard_trigger(ir)
        assert findings == []

    def test_bugcheck_codes_in_context(self):
        ir = _make_ir()
        ir.strings.append("KeBugCheckEx")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("push", "0x109"),
            ("push", "0x132"),
        ])
        findings = detect_patchguard_trigger(ir)
        assert len(findings) >= 1
        codes = findings[0].context.get("bugcheck_codes", [])
        assert len(codes) >= 2


# ===================================================================
# ETW Bypass detection tests
# ===================================================================

class TestETWBypassDetection:
    """Test ETW bypass detection."""

    def test_etw_threat_intel_detected(self):
        ir = _make_ir()
        ir.strings.append("EtwThreatIntProvRegHandle")
        findings = detect_etw_bypass(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.ETW_BYPASS
        assert findings[0].context.get("has_threat_intel_bypass") is True

    def test_etw_prefix_detected(self):
        ir = _make_ir()
        ir.strings.append("EtwpDisableKernelLogger")
        findings = detect_etw_bypass(ir)
        assert len(findings) >= 1

    def test_etw_api_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtTraceControl"])
        findings = detect_etw_bypass(ir)
        assert len(findings) >= 1

    def test_etw_disable_pattern_critical(self):
        """ETW disable pattern + threat intel should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("EtwThreatIntProvRegHandle")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("call", "EtwpUnregisterProvider"),
        ])
        findings = detect_etw_bypass(ir)
        assert len(findings) >= 1
        # Should have high or critical severity
        assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    def test_etw_unregister_api(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["EtwUnregister"])
        findings = detect_etw_bypass(ir)
        assert len(findings) >= 1

    def test_no_etw_patterns_no_finding(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        findings = detect_etw_bypass(ir)
        assert findings == []

    def test_etw_stop_trace_detected(self):
        ir = _make_ir()
        ir.strings.append("EtwDisable")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("call", "EtwpStopTrace"),
        ])
        findings = detect_etw_bypass(ir)
        assert len(findings) >= 1
        assert findings[0].context.get("has_explicit_disable") is True


# ===================================================================
# KPP Callback Disable detection tests
# ===================================================================

class TestKPPCallbackDisableDetection:
    """Test KPP callback disable detection."""

    def test_ps_set_create_process_notify(self):
        ir = _make_ir()
        ir.strings.append("PsSetCreateProcessNotifyRoutine")
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.KPP_CALLBACK_DISABLE

    def test_cm_register_callback_ex(self):
        ir = _make_ir()
        ir.strings.append("CmRegisterCallbackEx")
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1

    def test_ob_register_callbacks(self):
        ir = _make_ir()
        ir.strings.append("ObRegisterCallbacks")
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1

    def test_callback_removal_critical(self):
        """Explicit callback removal APIs should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["CmUnRegisterCallback"])
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].context.get("removes_registry_callback") is True

    def test_ps_remove_thread_notify_critical(self):
        ir = _make_ir()
        _add_function(ir, 0x2000, ["PsRemoveCreateThreadNotifyRoutine"])
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ps_remove_load_image_notify(self):
        ir = _make_ir()
        _add_function(ir, 0x3000, ["PsRemoveLoadImageNotifyRoutine"])
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ob_unregister_callbacks(self):
        ir = _make_ir()
        _add_function(ir, 0x4000, ["ObUnRegisterCallbacks"])
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_callback_registration_high(self):
        """Callback registration without removal should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["PsSetCreateProcessNotifyRoutine"])
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH

    def test_no_callback_patterns_no_finding(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        findings = detect_kpp_callback_disable(ir)
        assert findings == []

    def test_process_notify_removal_flagged(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["PsSetCreateProcessNotifyRoutineEx"])
        findings = detect_kpp_callback_disable(ir)
        assert len(findings) >= 1
        assert findings[0].context.get("removes_process_notify") is False  # Set, not remove


# ===================================================================
# DSEPgAnalyzer integration tests
# ===================================================================

class TestDSEPgAnalyzerIntegration:
    """Test DSEPgAnalyzer end-to-end."""

    def test_analyzer_name(self):
        analyzer = DSEPgAnalyzer()
        assert analyzer.name == "DSEPgAnalyzer"

    def test_analyzer_description(self):
        analyzer = DSEPgAnalyzer()
        desc = analyzer.description
        assert "DSE" in desc
        assert "PatchGuard" in desc

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        analyzer = DSEPgAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert findings == []

    def test_combined_dse_and_patchguard(self):
        """Should detect both DSE and PatchGuard patterns."""
        ir = _make_ir()
        ir.strings.append("g_CiOptions")
        ir.strings.append("KeBugCheckEx")
        sample = _sample()
        analyzer = DSEPgAnalyzer()
        findings = analyzer.analyze(sample, ir)
        categories = {f.category for f in findings}
        assert FindingCategory.DSE_BYPASS in categories
        assert FindingCategory.PATCHGUARD_TRIGGER in categories

    def test_all_four_categories_detected(self):
        """All four detection types should fire independently."""
        ir = _make_ir()
        # DSE
        ir.strings.append("g_CiOptions")
        # PatchGuard
        ir.strings.append("KiSystemCall64")
        # ETW
        ir.strings.append("EtwThreatIntProvRegHandle")
        # KPP
        _add_function(ir, 0x1000, ["CmUnRegisterCallback"])
        sample = _sample()
        analyzer = DSEPgAnalyzer()
        findings = analyzer.analyze(sample, ir)
        categories = {f.category for f in findings}
        assert FindingCategory.DSE_BYPASS in categories
        assert FindingCategory.PATCHGUARD_TRIGGER in categories
        assert FindingCategory.ETW_BYPASS in categories
        assert FindingCategory.KPP_CALLBACK_DISABLE in categories

    def test_all_findings_have_evidence(self):
        """All findings should have evidence attached."""
        ir = _make_ir()
        ir.strings.append("g_CiOptions")
        ir.strings.append("KeBugCheckEx")
        _add_function(ir, 0x1000, ["CmUnRegisterCallback"])
        sample = _sample()
        analyzer = DSEPgAnalyzer()
        findings = analyzer.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0

    def test_safe_driver_no_findings(self):
        """Normal driver patterns should not trigger DSE/PG findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice", "IoDeleteDevice"])
        ir.strings.append("\\Device\\MyDriver")
        sample = _sample()
        analyzer = DSEPgAnalyzer()
        findings = analyzer.analyze(sample, ir)
        # None of the DSE/PG/ETW/KPP categories should appear
        dangerous_categories = {
            FindingCategory.DSE_BYPASS,
            FindingCategory.PATCHGUARD_TRIGGER,
            FindingCategory.ETW_BYPASS,
            FindingCategory.KPP_CALLBACK_DISABLE,
        }
        assert not (set(f.category for f in findings) & dangerous_categories)
