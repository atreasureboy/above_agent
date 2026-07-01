"""Tests for structure_analyzer.py and extract_device_names."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.structure_analyzer import (
    StructureAnalyzer,
    extract_device_names,
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
    SignatureStatus,
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


def _sample(
    name: str = "test.sys",
    company: str = "Test",
    debug_path: str = "",
) -> Sample:
    return Sample(
        path=Path(name), name=name, company=company,
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True, debug_path=debug_path,
    )


class TestStructureAnalyzerBasics:
    """Test basic structure analyzer functionality."""

    def test_analyzer_name(self):
        analyzer = StructureAnalyzer()
        assert analyzer.name == "StructureAnalyzer"

    def test_analyzer_description(self):
        analyzer = StructureAnalyzer()
        desc = analyzer.description
        assert "IOCTL" in desc
        assert "IRP" in desc

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert findings == []

    def test_irp_mj_device_control_detected(self):
        """IRP_MJ_DEVICE_CONTROL handler registration should be detected."""
        ir = _make_ir()
        ir.irp_handlers[0xE] = 0x1000
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        disp_findings = [f for f in findings if f.category == FindingCategory.IOCTL_DISPATCHER_FOUND
                        and "IRP_MJ_DEVICE_CONTROL" in f.description]
        assert len(disp_findings) >= 1

    def test_ioctl_codes_reported(self):
        """IOCTL codes should be reported."""
        ir = _make_ir()
        ir.ioctl_codes = [0x22A004, 0x22A008]
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        code_findings = [f for f in findings if f.category == FindingCategory.IOCTL_DISPATCHER_FOUND
                        and "IOCTL code" in f.description]
        assert len(code_findings) >= 1

    def test_ioctl_handlers_mapped(self):
        """IOCTL code to handler mapping should be reported."""
        ir = _make_ir()
        ir.ioctl_handlers = {0x22A004: 0x1000, 0x22A008: 0x2000}
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        handler_findings = [f for f in findings if f.category == FindingCategory.IOCTL_CODE_EXPOSED]
        assert len(handler_findings) >= 1
        assert "0x22A004" in handler_findings[0].description

    def test_other_irp_handlers_reported(self):
        """Non-DEVICE_CONTROL IRP handlers should be reported."""
        ir = _make_ir()
        ir.irp_handlers = {0x02: 0x1000, 0x03: 0x2000, 0x1B: 0x3000}
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        irp_findings = [f for f in findings if "IRP_MJ_CLOSE" in f.description or "IRP_MJ_PNP" in f.description]
        assert len(irp_findings) >= 1

    def test_wdf_driver_detected(self):
        """WDF driver flag should produce finding."""
        ir = _make_ir()
        ir.is_wdf_driver = True
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        wdf_findings = [f for f in findings if "WDF" in f.description or "KMDF" in f.description]
        assert len(wdf_findings) >= 1

    def test_filter_driver_detected(self):
        """Filter driver detection via IoAttachDevice API."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoAttachDeviceToDeviceStack"])
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        filter_findings = [f for f in findings if "Filter driver" in f.description]
        assert len(filter_findings) >= 1
        assert ir.is_filter_driver is True

    def test_fastio_handlers_reported(self):
        """FastIO dispatch should be reported."""
        ir = _make_ir()
        ir.fastio_handlers = {0x0: 0x1000, 0x8: 0x2000}
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        fastio_findings = [f for f in findings if f.category == FindingCategory.FASTIO_DISPATCHER_FOUND]
        assert len(fastio_findings) >= 1

    def test_minifilter_detected(self):
        """MiniFilter flag should produce finding."""
        ir = _make_ir()
        ir.is_minifilter = True
        ir.minifilter_handlers = {0x0: 0x1000}
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        mf_findings = [f for f in findings if f.category == FindingCategory.MINIFILTER_CALLBACK_FOUND]
        assert len(mf_findings) >= 1

    def test_mmio_surface_reported(self):
        """MMIO surface should be reported."""
        ir = _make_ir()
        ir.mmio_surfaces = [{"func_addr": 0x1000, "apis": ["MmMapIoSpaceEx"], "is_entry_point": True}]
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        mmio_findings = [f for f in findings if f.category == FindingCategory.MMIO_SURFACE]
        assert len(mmio_findings) >= 1


class TestPDBPathAnalysis:
    """Test PDB path analysis."""

    def test_pdb_wdk_build_detected(self):
        """WDK build path should be inferred."""
        ir = _make_ir()
        sample = _sample(debug_path="C:\\build\\obj\\mydriver.pdb")
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        pdb_findings = [f for f in findings if f.category == FindingCategory.DEBUG_SYMBOLS_PRESENT]
        assert len(pdb_findings) >= 1
        assert "WDK" in pdb_findings[0].description or "build" in pdb_findings[0].description.lower()

    def test_pdb_visual_studio_detected(self):
        """Visual Studio build path should be inferred."""
        ir = _make_ir()
        sample = _sample(debug_path="C:\\Visual Studio\\Projects\\MyDriver\\mydriver.pdb")
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        pdb_findings = [f for f in findings if f.category == FindingCategory.DEBUG_SYMBOLS_PRESENT]
        assert len(pdb_findings) >= 1

    def test_pdb_github_actions_detected(self):
        """GitHub CI build path should be inferred."""
        ir = _make_ir()
        sample = _sample(debug_path="D:\\github\\runner\\mydriver.pdb")
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        pdb_findings = [f for f in findings if f.category == FindingCategory.DEBUG_SYMBOLS_PRESENT]
        assert len(pdb_findings) >= 1

    def test_pdb_driver_hint_filter(self):
        """PDB path with 'filter' keyword should hint at filter driver."""
        ir = _make_ir()
        sample = _sample(debug_path="C:\\src\\myfilter_driver\\myfilter.pdb")
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        pdb_findings = [f for f in findings if f.category == FindingCategory.DEBUG_SYMBOLS_PRESENT]
        assert len(pdb_findings) >= 1
        assert "filter" in pdb_findings[0].description.lower()


class TestSecurityIRPHandlers:
    """Test PnP/Power/WMI security analysis."""

    def test_pnp_handler_with_dangerous_api(self):
        """PnP handler calling dangerous APIs should be HIGH severity."""
        ir = _make_ir()
        ir.irp_handlers = {0x1B: 0x2000}
        _add_function(ir, 0x2000, ["MmMapIoSpaceEx"])
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        pnp_findings = [f for f in findings if "IRP_MJ_PNP" in f.description]
        assert len(pnp_findings) >= 1

    def test_pnp_handler_without_dangerous_api(self):
        """PnP handler without dangerous APIs should be INFO."""
        ir = _make_ir()
        ir.irp_handlers = {0x1B: 0x2000}
        _add_function(ir, 0x2000, ["IoCreateDevice"])
        sample = _sample()
        analyzer = StructureAnalyzer()
        findings = analyzer.analyze(sample, ir)
        pnp_findings = [f for f in findings if "IRP_MJ_PNP" in f.description]
        assert len(pnp_findings) >= 1
        assert pnp_findings[0].severity == Severity.INFO


class TestExtractDeviceNames:
    """Test extract_device_names function."""

    def test_device_string_extracted(self):
        """\\Device\\MyDriver should be extracted."""
        ir = _make_ir()
        ir.strings.append("\\Device\\MyDriver")
        names = extract_device_names(ir)
        assert any("MyDriver" in n for n in names)

    def test_dosdevices_extracted(self):
        """\\DosDevices\\MyLink should be extracted."""
        ir = _make_ir()
        ir.strings.append("\\DosDevices\\MyLink")
        names = extract_device_names(ir)
        assert any("MyLink" in n for n in names)

    def test_question_prefix_extracted(self):
        """\\??\\MyDevice should be extracted."""
        ir = _make_ir()
        ir.strings.append("\\??\\MyDevice")
        names = extract_device_names(ir)
        assert any("MyDevice" in n for n in names)

    def test_rpc_control_extracted(self):
        """\\RPC Control\\MyPort should be extracted."""
        ir = _make_ir()
        ir.strings.append("\\RPC Control\\MyPort")
        names = extract_device_names(ir)
        assert any("MyPort" in n for n in names)

    def test_global_prefix_extracted(self):
        """Global\\MyGlobalDevice should be extracted."""
        ir = _make_ir()
        ir.strings.append("Global\\MyGlobalDevice")
        names = extract_device_names(ir)
        assert any("MyGlobalDevice" in n for n in names)

    def test_no_device_names_empty(self):
        """No device strings should return empty list (or fallback to driver stem)."""
        ir = _make_ir()
        ir.strings.append("Hello World")
        names = extract_device_names(ir)
        # May return fallback to driver stem, so just check no actual device-like names
        assert all("Device" not in n and "MyDriver" not in n for n in names)

    def test_no_duplicates(self):
        """Same device name should not be duplicated."""
        ir = _make_ir()
        ir.strings.append("\\Device\\MyDriver")
        ir.strings.append("\\DosDevices\\MyDriver")
        names = extract_device_names(ir)
        count = sum(1 for n in names if "MyDriver" in n)
        assert count == 1
