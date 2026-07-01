"""Tests for callback_resolver.py."""

from __future__ import annotations

from pathlib import Path

from src.analysis.deep.callback_resolver import (
    CallbackResolver,
    CallbackSecurityClass,
    AccessMaskModifier,
    CALLBACK_APIS,
    DOWNGRADE_APIS,
    NTSTATUS,
    OB_CALLBACK_STRUCT_OFFSETS,
)
from src.models import (
    BasicBlock, CFG, Confidence, DisassemblyResult, FindingCategory,
    Function, Instruction, Sample, Architecture, Severity,
)


def _make_ir() -> DisassemblyResult:
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
    ir.callback_registrations = []
    return ir


def _add_function(ir: DisassemblyResult, addr: int, name: str = None, calls: list[int] = None) -> Function:
    func = Function(name=name or f"sub_{addr:X}", address=addr, size=0x200)
    if calls:
        func.calls = calls
    ir.functions[addr] = func
    return func


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


class TestCallbackConstants:
    """Test constant definitions."""

    def test_callback_api_groups_defined(self):
        assert "object_callback" in CALLBACK_APIS
        assert "process_notify" in CALLBACK_APIS
        assert "thread_notify" in CALLBACK_APIS
        assert "image_notify" in CALLBACK_APIS
        assert "registry_callback" in CALLBACK_APIS
        assert "fs_callback" in CALLBACK_APIS
        assert "minifilter" in CALLBACK_APIS
        assert "shutdown_notify" in CALLBACK_APIS

    def test_ob_register_callbacks_api(self):
        assert "ObRegisterCallbacks" in CALLBACK_APIS["object_callback"]

    def test_ps_create_process_notify(self):
        assert "PsSetCreateProcessNotifyRoutine" in CALLBACK_APIS["process_notify"]

    def test_cm_register_callback(self):
        assert "CmRegisterCallbackEx" in CALLBACK_APIS["registry_callback"]

    def test_downgrade_apis_defined(self):
        assert "ObDereferenceObject" in DOWNGRADE_APIS
        assert "PsGetCurrentProcessId" in DOWNGRADE_APIS

    def test_ntstatus_codes(self):
        assert NTSTATUS["STATUS_SUCCESS"] == 0x00000000
        assert NTSTATUS["STATUS_ACCESS_DENIED"] == 0xC0000022

    def test_ob_callback_struct_offsets(self):
        assert 0x00 in OB_CALLBACK_STRUCT_OFFSETS
        assert 0x08 in OB_CALLBACK_STRUCT_OFFSETS
        assert 0x10 in OB_CALLBACK_STRUCT_OFFSETS
        assert 0x18 in OB_CALLBACK_STRUCT_OFFSETS

    def test_access_mask_values(self):
        assert AccessMaskModifier.PROCESS_TERMINATE.value == 0x0001
        assert AccessMaskModifier.PROCESS_VM_READ.value == 0x0010
        assert AccessMaskModifier.PROCESS_QUERY_INFORMATION.value == 0x0400

    def test_callback_security_class(self):
        assert CallbackSecurityClass.PROTECTIVE.value == "protective"
        assert CallbackSecurityClass.MONITORING.value == "monitoring"
        assert CallbackSecurityClass.MANIPULATING.value == "manipulating"
        assert CallbackSecurityClass.PASSIVE.value == "passive"


class TestCallbackResolverBasics:
    """Test basic analyzer functionality."""

    def test_analyzer_name(self):
        resolver = CallbackResolver()
        assert resolver.name == "CallbackResolver"

    def test_analyzer_description(self):
        resolver = CallbackResolver()
        assert "callback" in resolver.description.lower()

    def test_is_correlator(self):
        resolver = CallbackResolver()
        assert resolver.is_correlator is True

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        assert findings == []


class TestObRegisterCallbacksDetection:
    """Test ObRegisterCallbacks detection."""

    def test_ob_register_callbacks_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, "RegisterCallbacks")
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        ob_findings = [f for f in findings if f.category == FindingCategory.CALLBACK_RESOLVED
                      and "ObRegisterCallbacks" in f.description]
        assert len(ob_findings) >= 1
        assert ob_findings[0].context["api"] == "ObRegisterCallbacks"

    def test_ob_callback_with_process_type(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, "RegisterCallbacks")
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        ir.strings.append("PsProcessType")
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        ob_findings = [f for f in findings if f.category == FindingCategory.CALLBACK_RESOLVED]
        if ob_findings:
            assert ob_findings[0].context.get("protection_type") == "process protection"

    def test_ob_callback_with_thread_type(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, "RegisterCallbacks")
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        ir.strings.append("PsThreadType")
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        ob_findings = [f for f in findings if f.category == FindingCategory.CALLBACK_RESOLVED]
        if ob_findings:
            assert ob_findings[0].context.get("protection_type") == "thread protection"

    def test_ob_callback_registers_callback_registration(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, "RegisterCallbacks")
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        sample = _sample()
        resolver = CallbackResolver()
        resolver.analyze(sample, ir)
        assert len(ir.callback_registrations) >= 1
        assert ir.callback_registrations[0]["api"] == "ObRegisterCallbacks"


class TestProcessNotifyDetection:
    """Test process creation notify callbacks."""

    def test_ps_set_create_process_notify(self):
        ir = _make_ir()
        _add_function(ir, 0x2000, "RegisterProcessNotify")
        ir.function_apis[0x2000] = ["PsSetCreateProcessNotifyRoutine"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        process_findings = [f for f in findings if
                          "process_notify" in f.description.lower() or
                          "PsSetCreateProcessNotifyRoutine" in f.description or
                          f.category == FindingCategory.CALLBACK_RESOLVED]
        assert len(process_findings) >= 1

    def test_ps_set_create_process_notify_ex(self):
        ir = _make_ir()
        _add_function(ir, 0x3000, "RegisterProcessNotifyEx")
        ir.function_apis[0x3000] = ["PsSetCreateProcessNotifyRoutineEx"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        assert len(findings) >= 1


class TestThreadNotifyDetection:
    """Test thread creation notify callbacks."""

    def test_ps_set_create_thread_notify(self):
        ir = _make_ir()
        _add_function(ir, 0x4000, "RegisterThreadNotify")
        ir.function_apis[0x4000] = ["PsSetCreateThreadNotifyRoutine"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        thread_findings = [f for f in findings if
                         "thread_notify" in f.description.lower() or
                         "PsSetCreateThreadNotifyRoutine" in f.description or
                         f.category == FindingCategory.CALLBACK_RESOLVED]
        assert len(thread_findings) >= 1


class TestImageNotifyDetection:
    """Test image load notify callbacks."""

    def test_ps_set_load_image_notify(self):
        ir = _make_ir()
        _add_function(ir, 0x5000, "RegisterImageNotify")
        ir.function_apis[0x5000] = ["PsSetLoadImageNotifyRoutine"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        assert len(findings) >= 1


class TestRegistryCallbackDetection:
    """Test registry callback detection."""

    def test_cm_register_callback_ex(self):
        ir = _make_ir()
        _add_function(ir, 0x6000, "RegisterRegistryCallback")
        ir.function_apis[0x6000] = ["CmRegisterCallbackEx"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        reg_findings = [f for f in findings if
                       "registry_callback" in f.description.lower() or
                       "CmRegisterCallbackEx" in f.description or
                       f.category == FindingCategory.CALLBACK_RESOLVED]
        assert len(reg_findings) >= 1


class TestFSCallbackDetection:
    """Test file system callback detection."""

    def test_io_register_fs_registration_change(self):
        ir = _make_ir()
        _add_function(ir, 0x7000, "RegisterFSCallback")
        ir.function_apis[0x7000] = ["IoRegisterFsRegistrationChange"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        fs_findings = [f for f in findings if
                      "fs_callback" in f.description.lower() or
                      "IoRegisterFsRegistrationChange" in f.description or
                      f.category == FindingCategory.CALLBACK_RESOLVED]
        assert len(fs_findings) >= 1


class TestMultipleCallbacks:
    """Test detection of multiple callback types."""

    def test_multiple_callbacks_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, "RegisterOb")
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        _add_function(ir, 0x2000, "RegisterProcessNotify")
        ir.function_apis[0x2000] = ["PsSetCreateProcessNotifyRoutine"]
        _add_function(ir, 0x3000, "RegisterImageNotify")
        ir.function_apis[0x3000] = ["PsSetLoadImageNotifyRoutine"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        cb_findings = [f for f in findings if f.category == FindingCategory.CALLBACK_RESOLVED]
        assert len(cb_findings) >= 3


class TestFindingsStructure:
    """Test finding structure and content."""

    def test_all_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, "RegisterCallbacks")
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0

    def test_ob_finding_has_context(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, "RegisterCallbacks")
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        sample = _sample()
        resolver = CallbackResolver()
        findings = resolver.analyze(sample, ir)
        ob_findings = [f for f in findings if f.category == FindingCategory.CALLBACK_RESOLVED
                      and f.context.get("api") == "ObRegisterCallbacks"]
        if ob_findings:
            ctx = ob_findings[0].context
            assert "registration_func" in ctx
            assert "protection_type" in ctx
            assert "callback_behavior" in ctx


class TestFindFuncsWithAPIs:
    """Test _find_funcs_with_apis helper."""

    def test_find_in_function_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]
        resolver = CallbackResolver()
        found = resolver._find_funcs_with_apis(ir, {"ObRegisterCallbacks"})
        assert 0x1000 in found

    def test_find_multiple_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        ir.function_apis[0x1000] = ["ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutine"]
        resolver = CallbackResolver()
        found = resolver._find_funcs_with_apis(ir, {"ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutine"})
        assert 0x1000 in found

    def test_no_match_returns_empty(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        ir.function_apis[0x1000] = ["IoCreateDevice"]
        resolver = CallbackResolver()
        found = resolver._find_funcs_with_apis(ir, {"ObRegisterCallbacks"})
        assert len(found) == 0

    def test_find_in_dynamic_imports(self):
        ir = _make_ir()
        ir.dynamic_imports[0x1000] = {"api_name": "ObRegisterCallbacks", "func_addr": 0x2000}
        resolver = CallbackResolver()
        found = resolver._find_funcs_with_apis(ir, {"ObRegisterCallbacks"})
        assert 0x2000 in found
