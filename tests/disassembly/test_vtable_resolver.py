"""Tests for Phase 8: Indirect call / vtable resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.models import (
    Architecture,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Function,
    Instruction,
    Sample,
)
from src.disassembly.vtable_resolver import (
    VTableInfo,
    ResolvedTarget,
    CallbackRegistration,
    resolve_indirect_call,
    identify_vtables,
    populate_indirect_calls,
    IO_COMPLETION_CALLBACK_OFFSETS,
    WDF_QUEUE_CALLBACK_OFFSETS,
    CALLBACK_REGISTER_APIS,
)


def _make_ir_with_functions(func_addrs: list[int]) -> DisassemblyResult:
    """Create an IR with functions at given addresses."""
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
    for addr in func_addrs:
        ir.functions[addr] = Function(name=f"sub_{addr:X}", address=addr, size=0x100)
    return ir


# ---------------------------------------------------------------------------
# Constant Definitions Tests
# ---------------------------------------------------------------------------

class TestCallbackConstants:
    """Test callback struct offset constants."""

    def test_io_completion_offsets(self):
        assert 0x28 in IO_COMPLETION_CALLBACK_OFFSETS

    def test_wdf_queue_offsets(self):
        assert 0x18 in WDF_QUEUE_CALLBACK_OFFSETS
        assert 0x20 in WDF_QUEUE_CALLBACK_OFFSETS
        assert 0x28 in WDF_QUEUE_CALLBACK_OFFSETS

    def test_callback_register_apis(self):
        assert "IoSetCompletionRoutine" in CALLBACK_REGISTER_APIS
        assert "WdfIoQueueCreate" in CALLBACK_REGISTER_APIS


# ---------------------------------------------------------------------------
# Indirect Call Resolution Tests
# ---------------------------------------------------------------------------

class TestResolveIndirectCall:
    """Test indirect call target resolution."""

    def test_constant_target_resolved(self):
        """call rax where rax was loaded from a constant should resolve."""
        ir = _make_ir_with_functions([0x4000, 0x5000])

        all_insns = {
            0x100: Instruction(address=0x100, mnemonic="mov", operands="rax, 0x4000", size=7),
            0x110: Instruction(address=0x110, mnemonic="call", operands="rax", size=2),
        }
        target = resolve_indirect_call(all_insns[0x110], all_insns, ir)

        assert target is not None
        assert target.target_addr == 0x4000
        assert target.resolution_method == "constant"
        assert target.confidence >= 0.9

    def test_rip_relative_resolved(self):
        """call qword ptr [rip+offset] should resolve if target is a function."""
        ir = _make_ir_with_functions([0x3000])

        # call [rip+0x5A] at 0x2FA0 → target = 0x2FA0 + 6 + 0x5A = 0x3000
        all_insns = {
            0x2FA0: Instruction(
                address=0x2FA0, mnemonic="call",
                operands="qword ptr [rip + 0x5A]", size=6,
            ),
        }
        target = resolve_indirect_call(all_insns[0x2FA0], all_insns, ir)

        assert target is not None
        assert target.target_addr == 0x3000
        assert target.resolution_method == "constant"

    def test_non_call_returns_none(self):
        """Non-call instruction should return None."""
        ir = _make_ir_with_functions([0x1000])
        insn = Instruction(address=0x100, mnemonic="mov", operands="rax, rcx")
        assert resolve_indirect_call(insn, {}, ir) is None

    def test_unknown_register_returns_none(self):
        """call rax with no prior mov to rax should return None."""
        ir = _make_ir_with_functions([0x1000])
        all_insns = {
            0x100: Instruction(address=0x100, mnemonic="call", operands="rax", size=2),
        }
        target = resolve_indirect_call(all_insns[0x100], all_insns, ir)
        assert target is None


# ---------------------------------------------------------------------------
# VTable Identification Tests
# ---------------------------------------------------------------------------

class TestVTableIdentification:
    """Test vtable identification from PE sections."""

    def test_vtable_dataclass_exists(self):
        vt = VTableInfo(address=0x4000, entries=[0x1000, 0x2000, 0x3000])
        assert len(vt.entries) == 3
        assert vt.address == 0x4000

    def test_populate_indirect_calls_initializes_fields(self):
        """populate_indirect_calls should initialize new IR fields."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.functions[0x1000] = Function(name="sub_1000", address=0x1000, size=0x100)

        populate_indirect_calls(ir, {}, pe_path=None)

        assert hasattr(ir, 'resolved_indirect_calls')
        assert hasattr(ir, 'vtables')
        assert hasattr(ir, 'callback_registrations')


# ---------------------------------------------------------------------------
# Callback Registration Tests
# ---------------------------------------------------------------------------

class TestCallbackRegistration:
    """Test callback registration detection."""

    def test_callback_registration_detected(self):
        """Function calling IoSetCompletionRoutine should register callback."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_2000", address=0x2000, size=0x200)
        ir.functions[0x2000] = func
        ir.function_apis[0x2000] = ["IoSetCompletionRoutine"]

        populate_indirect_calls(ir, {}, pe_path=None)

        assert len(ir.callback_registrations) >= 1
        assert ir.callback_registrations[0]["registered_by"] == "IoSetCompletionRoutine"

    def test_no_callback_api_no_registration(self):
        """Function without callback API should not register."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_3000", address=0x3000, size=0x100)
        ir.functions[0x3000] = func
        ir.function_apis[0x3000] = ["MmMapIoSpaceEx"]

        populate_indirect_calls(ir, {}, pe_path=None)

        assert len(ir.callback_registrations) == 0
