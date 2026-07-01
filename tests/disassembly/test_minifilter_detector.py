"""Tests for MiniFilter callback detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.disassembly.minifilter_detector import (
    MINIFILTER_CALLBACK_OFFSETS,
    MINIFILTER_REGISTER_APIS,
    detect_minifilter,
)
from src.models import BasicBlock, CFG, DisassemblyResult, Function, Instruction


def _make_ir() -> DisassemblyResult:
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
    # Default: not a minifilter
    return ir


def _add_api_to_ir(ir: DisassemblyResult, func_addr: int, api_name: str) -> None:
    func = Function(name=f"sub_{func_addr:X}", address=func_addr, size=0x100)
    ir.functions[func_addr] = func
    ir.function_apis[func_addr] = [api_name]


def _add_callback_struct(ir: DisassemblyResult, callback_addr: int, offset: int) -> None:
    """Add a function with a mov [reg+offset], imm instruction at a callback offset."""
    cfg = CFG(function_address=callback_addr, entry_block=callback_addr)
    block = BasicBlock(
        address=callback_addr,
        end_address=callback_addr + 0x50,
        instructions=[
            Instruction(
                address=callback_addr + 0x10,
                mnemonic="mov",
                operands=f"qword ptr [rbx + 0x{offset:X}], sub_{callback_addr:X}",
            ),
        ],
        successors=[],
    )
    cfg.blocks[callback_addr] = block
    ir.cfgs[callback_addr] = ir.simple_cfgs[callback_addr] = cfg


class TestMinifilterConstants:
    """Test minifilter detection constants."""

    def test_devicecontrol_offset_defined(self):
        assert 0x78 in MINIFILTER_CALLBACK_OFFSETS
        assert MINIFILTER_CALLBACK_OFFSETS[0x78] == "DeviceControl"

    def test_filesystemcontrol_offset_defined(self):
        assert 0x70 in MINIFILTER_CALLBACK_OFFSETS
        assert MINIFILTER_CALLBACK_OFFSETS[0x70] == "FileSystemControl"

    def test_register_apis_defined(self):
        assert "FltRegisterFilter" in MINIFILTER_REGISTER_APIS
        assert "FltStartFiltering" in MINIFILTER_REGISTER_APIS
        assert "FltUnregisterFilter" in MINIFILTER_REGISTER_APIS


class TestMinifilterDetection:
    """Test MiniFilter driver detection logic."""

    def test_non_minifilter_unchanged(self):
        """Driver without FltRegisterFilter should remain is_minifilter=False."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "IoCreateDevice")
        detect_minifilter(ir)
        assert ir.is_minifilter is False
        assert len(ir.minifilter_handlers) == 0

    def test_minifilter_detected_via_function_apis(self):
        """Driver with FltRegisterFilter in function_apis should be detected."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        detect_minifilter(ir)
        assert ir.is_minifilter is True

    def test_minifilter_detected_via_flstartfiltering(self):
        """Driver with FltStartFiltering should also be detected."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x2000, "FltStartFiltering")
        detect_minifilter(ir)
        assert ir.is_minifilter is True

    def test_empty_ir_no_crash(self):
        """Empty IR should not crash detect_minifilter."""
        ir = _make_ir()
        detect_minifilter(ir)  # Should complete without error
        assert ir.is_minifilter is False

    def test_minifilter_without_callbacks(self):
        """Minifilter without callback struct setup should have no handlers."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        detect_minifilter(ir)
        assert ir.is_minifilter is True
        assert len(ir.minifilter_handlers) == 0


class TestMinifilterCallbackExtraction:
    """Test callback function pointer extraction from PFLT_REGISTRATION struct."""

    def test_devicecontrol_callback_detected(self):
        """mov [rbx+0x78], funcptr should register DeviceControl callback."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        _add_callback_struct(ir, 0x2000, 0x78)
        detect_minifilter(ir)
        assert 0x78 in ir.minifilter_handlers

    def test_filesystemcontrol_callback_detected(self):
        """mov [rbx+0x70], funcptr should register FileSystemControl callback."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        _add_callback_struct(ir, 0x2000, 0x70)
        detect_minifilter(ir)
        assert 0x70 in ir.minifilter_handlers

    def test_multiple_callbacks_detected(self):
        """Multiple callback offsets should all be detected."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        _add_callback_struct(ir, 0x2000, 0x78)  # DeviceControl
        _add_callback_struct(ir, 0x3000, 0x20)  # Read
        detect_minifilter(ir)
        assert 0x78 in ir.minifilter_handlers
        assert 0x20 in ir.minifilter_handlers

    def test_callback_target_added_to_functions(self):
        """Callback target addresses should be in ir.functions."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        _add_callback_struct(ir, 0x2000, 0x78)
        detect_minifilter(ir)
        # The callback target address from the instruction should exist
        assert len(ir.functions) >= 2

    def test_non_callback_offset_ignored(self):
        """mov [rbx+0x999] at non-callback offset should not be matched."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        block = BasicBlock(
            address=0x2000,
            end_address=0x2050,
            instructions=[
                Instruction(
                    address=0x2010,
                    mnemonic="mov",
                    operands="qword ptr [rbx + 0x999], sub_2000",
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x2000] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        detect_minifilter(ir)
        assert 0x999 not in ir.minifilter_handlers

    def test_non_mov_instruction_ignored(self):
        """lea [rbx+0x78], imm should not be matched (only mov)."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        block = BasicBlock(
            address=0x2000,
            end_address=0x2050,
            instructions=[
                Instruction(
                    address=0x2010,
                    mnemonic="lea",
                    operands="rax, qword ptr [rbx + 0x78]",
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x2000] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        detect_minifilter(ir)
        assert 0x78 not in ir.minifilter_handlers

    def test_non_ptr_memory_access_ignored(self):
        """mov without ptr keyword should not be matched."""
        ir = _make_ir()
        _add_api_to_ir(ir, 0x1000, "FltRegisterFilter")
        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        block = BasicBlock(
            address=0x2000,
            end_address=0x2050,
            instructions=[
                Instruction(
                    address=0x2010,
                    mnemonic="mov",
                    operands="rax, [rbx + 0x78]",  # No 'ptr' keyword
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x2000] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        detect_minifilter(ir)
        assert 0x78 not in ir.minifilter_handlers
