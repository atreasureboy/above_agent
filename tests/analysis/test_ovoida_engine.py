"""Tests for OvoidaEngine exploit chain building."""

from __future__ import annotations

from pathlib import Path

from src.models import Architecture, DisassemblyResult, Function, Sample
from src.analysis.deep.ovoida_engine import OvoidaEngine


def _make_sample() -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="TestDrv",
        company="Test",
        version="1.0",
        arch=Architecture.X64,
        sha256="abc123",
        size=1000,
        driver_type="WDM",
    )


class TestBuildExploitChains:
    """Test OvoidaEngine._build_exploit_chains."""

    def test_chain_with_taint_confirmed(self):
        """Confirmed taint should produce CRITICAL chain with detailed steps."""
        engine = OvoidaEngine()
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        # Create function with MmMapIoSpaceEx
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        ir.functions[0x1000] = func

        functions_detail = [{
            "address": "0x1000",
            "name": "sub_1000",
            "size": 0x100,
            "api_calls": ["MmMapIoSpaceEx"],
            "api_details": [],
            "has_validation": False,
            "has_privilege_check": False,
            "has_size_check": False,
            "taint_reaches_api": True,
            "taint_sources": ["SystemBuffer@0x60"],
            "taint_sinks": ["MmMapIoSpaceEx(rcx)"],
            "cfg_blocks": 5,
            "instruction_count": 50,
            "calls": [],
            "called_by": [],
        }]

        chains = engine._build_exploit_chains(functions_detail, sample, ir)
        assert len(chains) == 1

        chain = chains[0]
        assert chain["severity"] == "CRITICAL"
        assert chain["user_controllable"] is True
        assert "MmMapIoSpaceEx" in chain["dangerous_apis"]
        assert chain["transfer_method"] == "METHOD_BUFFERED"  # default
        assert "buffer_size" in chain
        assert len(chain["poc_steps"]) >= 5  # Detailed steps

    def test_chain_without_taint(self):
        """No taint should produce HIGH (not CRITICAL) chain."""
        engine = OvoidaEngine()
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        func = Function(name="sub_2000", address=0x2000, size=0x100)
        ir.functions[0x2000] = func

        functions_detail = [{
            "address": "0x2000",
            "name": "sub_2000",
            "size": 0x100,
            "api_calls": ["ZwLoadDriver"],
            "api_details": [],
            "has_validation": False,
            "has_privilege_check": False,
            "has_size_check": False,
            "taint_reaches_api": False,
            "taint_sources": [],
            "taint_sinks": [],
            "cfg_blocks": 3,
            "instruction_count": 30,
            "calls": [],
            "called_by": [],
        }]

        chains = engine._build_exploit_chains(functions_detail, sample, ir)
        assert len(chains) == 1

        chain = chains[0]
        assert chain["severity"] == "HIGH"
        assert chain["user_controllable"] is False

    def test_chain_skips_full_validation(self):
        """Functions with full validation should be skipped."""
        engine = OvoidaEngine()
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        functions_detail = [{
            "address": "0x3000",
            "name": "sub_3000",
            "size": 0x100,
            "api_calls": ["MmMapIoSpaceEx"],
            "api_details": [],
            "has_validation": True,
            "has_privilege_check": True,
            "has_size_check": True,
            "taint_reaches_api": True,
            "taint_sources": [],
            "taint_sinks": [],
            "cfg_blocks": 5,
            "instruction_count": 50,
            "calls": [],
            "called_by": [],
        }]

        chains = engine._build_exploit_chains(functions_detail, sample, ir)
        assert len(chains) == 0

    def test_chain_skips_non_dangerous_api(self):
        """Functions with non-dangerous APIs should not produce chains."""
        engine = OvoidaEngine()
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        functions_detail = [{
            "address": "0x4000",
            "name": "sub_4000",
            "size": 0x100,
            "api_calls": ["DbgPrint"],  # Not in EXPLOIT_CHAIN_APIS
            "api_details": [],
            "has_validation": False,
            "has_privilege_check": False,
            "has_size_check": False,
            "taint_reaches_api": False,
            "taint_sources": [],
            "taint_sinks": [],
            "cfg_blocks": 2,
            "instruction_count": 10,
            "calls": [],
            "called_by": [],
        }]

        chains = engine._build_exploit_chains(functions_detail, sample, ir)
        assert len(chains) == 0

    def test_chain_sorted_by_severity(self):
        """Chains should be sorted with CRITICAL first."""
        engine = OvoidaEngine()
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        func1 = Function(name="sub_1000", address=0x1000, size=0x100)
        func2 = Function(name="sub_2000", address=0x2000, size=0x100)
        ir.functions[0x1000] = func1
        ir.functions[0x2000] = func2

        functions_detail = [
            {
                "address": "0x2000",
                "name": "sub_2000",
                "api_calls": ["ZwLoadDriver"],
                "api_details": [],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": False,  # HIGH
                "taint_sources": [],
                "taint_sinks": [],
                "cfg_blocks": 3,
                "instruction_count": 30,
                "calls": [],
                "called_by": [],
            },
            {
                "address": "0x1000",
                "name": "sub_1000",
                "api_calls": ["MmMapIoSpaceEx"],
                "api_details": [],
                "has_validation": False,
                "has_privilege_check": False,
                "has_size_check": False,
                "taint_reaches_api": True,  # CRITICAL
                "taint_sources": ["SystemBuffer@0x60"],
                "taint_sinks": ["MmMapIoSpaceEx(rcx)"],
                "cfg_blocks": 5,
                "instruction_count": 50,
                "calls": [],
                "called_by": [],
            },
        ]

        chains = engine._build_exploit_chains(functions_detail, sample, ir)
        assert len(chains) == 2
        assert chains[0]["severity"] == "CRITICAL"  # First
        assert chains[1]["severity"] == "HIGH"  # Second
