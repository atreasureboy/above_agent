"""Tests for CFG visualizer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.models import BasicBlock, CFG, DisassemblyResult, Function, Instruction
from src.report.cfg_visualizer import (
    export_cfg_to_dot,
    export_all_cfgs_to_dot,
    export_chain_dot,
    _block_has_validation,
    _block_has_dangerous_call,
)


def _make_mock_ir_with_cfg() -> DisassemblyResult:
    """Create a mock IR with a simple CFG."""
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
    handler_addr = 0x1000

    handler = Function(name="sub_1000", address=handler_addr, size=0x200)
    handler.calls = [0x2000]
    ir.functions[handler_addr] = handler

    # Entry block with cmp (validation)
    entry = BasicBlock(
        address=handler_addr,
        end_address=handler_addr + 0x50,
        instructions=[
            Instruction(address=0x1010, mnemonic="cmp", operands="rcx, 0x1000", size=4),
            Instruction(address=0x1020, mnemonic="jbe", operands="0x1050", size=6),
        ],
        successors=[handler_addr + 0x50],
    )

    # Block with dangerous API call
    sink_block = BasicBlock(
        address=handler_addr + 0x50,
        end_address=handler_addr + 0x100,
        instructions=[
            Instruction(
                address=0x1060,
                mnemonic="call",
                operands="qword ptr [rip+0x1000]",
                api_target="MmMapIoSpaceEx",
                size=6,
            ),
        ],
        successors=[],
    )

    cfg = CFG(function_address=handler_addr, entry_block=handler_addr)
    cfg.blocks[entry.address] = entry
    cfg.blocks[sink_block.address] = sink_block

    ir.cfgs[handler_addr] = ir.simple_cfgs[handler_addr] = cfg
    ir.ioctl_handlers[0x22A004] = handler_addr

    return ir


class TestCfgToDot:
    """Test single function CFG export."""

    def test_export_basic_cfg(self, tmp_path):
        """Basic CFG export produces valid DOT."""
        ir = _make_mock_ir_with_cfg()
        out = tmp_path / "handler.dot"
        export_cfg_to_dot(ir, 0x1000, out)

        content = out.read_text()
        assert "digraph" in content
        assert "0x1000" in content  # entry block
        assert "0x1050" in content  # sink block
        assert "cmp" in content
        assert "MmMapIoSpaceEx" in content

    def test_export_no_cfg_available(self, tmp_path):
        """Missing CFG produces placeholder DOT."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        out = tmp_path / "nocfg.dot"
        export_cfg_to_dot(ir, 0x9999, out)

        content = out.read_text()
        assert "digraph" in content
        assert "No CFG available" in content

    def test_validation_block_colored(self, tmp_path):
        """Blocks with cmp are colored green."""
        ir = _make_mock_ir_with_cfg()
        out = tmp_path / "validation.dot"
        export_cfg_to_dot(ir, 0x1000, out)

        content = out.read_text()
        assert "#90EE90" in content  # validation color

    def test_dangerous_api_block_colored(self, tmp_path):
        """Blocks with dangerous API calls are colored red."""
        ir = _make_mock_ir_with_cfg()
        out = tmp_path / "dangerous.dot"
        export_cfg_to_dot(ir, 0x1000, out)

        content = out.read_text()
        assert "#FF6B6B" in content  # dangerous API color

    def test_edges_present(self, tmp_path):
        """CFG edges are present in DOT output."""
        ir = _make_mock_ir_with_cfg()
        out = tmp_path / "edges.dot"
        export_cfg_to_dot(ir, 0x1000, out)

        content = out.read_text()
        assert "->" in content
        assert "0x1000" in content
        assert "0x1050" in content


class TestExportAllCfgs:
    """Test batch CFG export."""

    def test_export_handlers_only(self, tmp_path):
        """Exports only handler CFGs when handler_only=True."""
        ir = _make_mock_ir_with_cfg()
        paths = export_all_cfgs_to_dot(ir, tmp_path, handler_only=True)
        assert len(paths) >= 1
        assert all(p.suffix == ".dot" for p in paths)


class TestExportChainDot:
    """Test exploit chain call graph export."""

    def test_basic_chain_export(self, tmp_path):
        """Chain export produces valid DOT."""
        chains = [
            {
                "name": "TestDriver",
                "severity": "CRITICAL",
                "function": "0x140001000",
                "dangerous_apis": ["MmMapIoSpaceEx"],
                "validation": "none",
                "user_controllable": True,
            },
        ]
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        out = tmp_path / "chains.dot"
        export_chain_dot(chains, ir, out)

        content = out.read_text()
        assert "digraph" in content
        assert "ExploitChains" in content
        assert "TestDriver" in content
        assert "CRITICAL" in content

    def test_multiple_chains(self, tmp_path):
        """Multiple chains are all represented."""
        chains = [
            {
                "name": "Chain1",
                "severity": "CRITICAL",
                "function": "0x1000",
                "dangerous_apis": ["MmMapIoSpaceEx"],
                "validation": "none",
                "user_controllable": True,
            },
            {
                "name": "Chain2",
                "severity": "HIGH",
                "function": "0x2000",
                "dangerous_apis": ["KeWriteMsr"],
                "validation": "partial",
                "user_controllable": False,
            },
        ]
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        out = tmp_path / "chains.dot"
        export_chain_dot(chains, ir, out)

        content = out.read_text()
        assert "Chain1" in content
        assert "Chain2" in content


class TestBlockAnalysis:
    """Test block classification helpers."""

    def test_block_has_validation_cmp(self):
        """Block with cmp is detected as validation."""
        block = BasicBlock(
            address=0x1000,
            end_address=0x1050,
            instructions=[
                Instruction(address=0x1010, mnemonic="cmp", operands="rcx, 0x1000", size=4),
            ],
        )
        assert _block_has_validation(block) is True

    def test_block_has_validation_api(self):
        """Block with validation API is detected."""
        block = BasicBlock(
            address=0x1000,
            end_address=0x1050,
            instructions=[
                Instruction(
                    address=0x1010, mnemonic="call", operands="ProbeForRead",
                    api_target="ProbeForRead", size=6,
                ),
            ],
        )
        assert _block_has_validation(block) is True

    def test_block_has_dangerous_call(self):
        """Block with dangerous API call is detected."""
        block = BasicBlock(
            address=0x1000,
            end_address=0x1050,
            instructions=[
                Instruction(
                    address=0x1010, mnemonic="call", operands="MmMapIoSpaceEx",
                    api_target="MmMapIoSpaceEx", size=6,
                ),
            ],
        )
        assert _block_has_dangerous_call(block) is True
