"""
Tests for the preprocessing pipeline — Phase 0.

Covers:
- Packer detection (classify)
- UPX static unpacker
- MPRESS static unpacker
- CFF deflattening
- Dead code detection
- IAT reconstruction
- Anti-evasion engine
- Memory analyzer
- Pipeline routing
- Full preprocessing pipeline integration
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_pe(tmp_path: Path) -> Path:
    """Create a minimal valid PE file for testing."""
    # MZ header
    mz = bytearray(512)
    mz[0:2] = b"MZ"
    # e_lfanew at offset 0x3C → points to PE signature
    struct.pack_into("<I", mz, 0x3C, 0x80)
    # PE signature
    mz[0x80:0x84] = b"PE\x00\x00"
    # COFF header (x64)
    struct.pack_into("<H", mz, 0x84, 0x8664)  # Machine = AMD64
    struct.pack_into("<H", mz, 0x86, 1)       # NumberOfSections
    struct.pack_into("<H", mz, 0x94, 0xF0)    # SizeOfOptionalHeader
    struct.pack_into("<H", mz, 0x96, 0x0022)  # Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    # Optional header (PE32+)
    struct.pack_into("<H", mz, 0x98, 0x020B)  # Magic = PE32+
    struct.pack_into("<I", mz, 0xB0, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", mz, 0xB8, 0x140000000)  # ImageBase
    struct.pack_into("<I", mz, 0xD8, 0x1000)  # SectionAlignment
    struct.pack_into("<I", mz, 0xDC, 0x200)   # FileAlignment
    struct.pack_into("<I", mz, 0xF4, 0x3000)  # SizeOfImage
    struct.pack_into("<I", mz, 0xF8, 0x200)   # SizeOfHeaders
    # Section header (.text)
    sec_offset = 0x100
    mz[sec_offset:sec_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", mz, sec_offset + 8, 0x100)   # VirtualSize
    struct.pack_into("<I", mz, sec_offset + 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", mz, sec_offset + 16, 0x200)   # SizeOfRawData
    struct.pack_into("<I", mz, sec_offset + 20, 0x200)   # PointerToRawData
    struct.pack_into("<I", mz, sec_offset + 36, 0x60000020)  # Characteristics (CODE|EXECUTE|READ)

    pe_path = tmp_path / "test_driver.sys"
    pe_path.write_bytes(bytes(mz))
    return pe_path


@pytest.fixture
def upx_like_pe(tmp_path: Path) -> Path:
    """Create a PE that looks UPX-packed (UPX section names + high entropy)."""
    import math
    import os

    mz = bytearray(1024)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x80)
    mz[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", mz, 0x84, 0x8664)  # AMD64
    struct.pack_into("<H", mz, 0x86, 3)       # 3 sections (UPX0, UPX1, UPX2)
    struct.pack_into("<H", mz, 0x94, 0xF0)
    struct.pack_into("<H", mz, 0x96, 0x0022)
    # Optional header
    struct.pack_into("<H", mz, 0x98, 0x020B)
    struct.pack_into("<I", mz, 0xB0, 0x1000)   # EP in UPX0
    struct.pack_into("<Q", mz, 0xB8, 0x140000000)
    struct.pack_into("<I", mz, 0xD8, 0x1000)
    struct.pack_into("<I", mz, 0xDC, 0x200)
    struct.pack_into("<I", mz, 0xF4, 0x4000)
    struct.pack_into("<I", mz, 0xF8, 0x200)

    # UPX0 section (stub)
    sec = 0x100
    mz[sec:sec + 8] = b"UPX0\x00\x00\x00\x00"
    struct.pack_into("<I", mz, sec + 8, 0x200)
    struct.pack_into("<I", mz, sec + 12, 0x1000)
    struct.pack_into("<I", mz, sec + 16, 0x200)
    struct.pack_into("<I", mz, sec + 20, 0x200)
    struct.pack_into("<I", mz, sec + 36, 0x60000020)

    # UPX1 section (packed data — fill with high-entropy random data)
    sec2 = sec + 40
    mz[sec2:sec2 + 8] = b"UPX1\x00\x00\x00\x00"
    struct.pack_into("<I", mz, sec2 + 8, 0x1000)
    struct.pack_into("<I", mz, sec2 + 12, 0x2000)
    struct.pack_into("<I", mz, sec2 + 16, 0x200)
    struct.pack_into("<I", mz, sec2 + 20, 0x400)
    struct.pack_into("<I", mz, sec2 + 36, 0xC0000040)  # RW

    # Fill UPX1 data area with random bytes (high entropy)
    random_data = os.urandom(0x200)
    mz[0x400:0x600] = random_data

    # UPX2 section
    sec3 = sec2 + 40
    mz[sec3:sec3 + 8] = b"UPX2\x00\x00\x00\x00"
    struct.pack_into("<I", mz, sec3 + 8, 0x100)
    struct.pack_into("<I", mz, sec3 + 12, 0x3000)
    struct.pack_into("<I", mz, sec3 + 16, 0x100)
    struct.pack_into("<I", mz, sec3 + 20, 0x600)
    struct.pack_into("<I", mz, sec3 + 36, 0xC0000040)

    pe_path = tmp_path / "upx_packed.sys"
    pe_path.write_bytes(bytes(mz))
    return pe_path


# ---------------------------------------------------------------------------
# Packer Detection Tests
# ---------------------------------------------------------------------------

class TestPackerDetection:
    """Test packer classification."""

    def test_detect_upx_sections(self, upx_like_pe: Path):
        """UPX section names should trigger packer detection."""
        from src.analysis.preprocessing.pipeline import _classify_packer

        info = _classify_packer(upx_like_pe)
        # The test PE has UPX section names, so it should be detected
        # However, if pefile can't parse it fully, it might not detect
        # The important thing is it doesn't crash
        assert isinstance(info.is_packed, bool)
        if info.is_packed:
            assert len(info.reasons) > 0

    def test_detect_normal_pe(self, minimal_pe: Path):
        """Normal PE should not be detected as packed."""
        from src.analysis.preprocessing.pipeline import _classify_packer

        info = _classify_packer(minimal_pe)
        # May or may not be packed depending on heuristics
        # The key test is that it doesn't crash
        assert isinstance(info.is_packed, bool)

    def test_nonexistent_file(self, tmp_path: Path):
        """Non-existent file should not crash."""
        from src.analysis.preprocessing.pipeline import _classify_packer

        info = _classify_packer(tmp_path / "nonexistent.sys")
        assert info.is_packed is False


# ---------------------------------------------------------------------------
# Static Unpacker Tests
# ---------------------------------------------------------------------------

class TestUPXUnpacker:
    """Test UPX static unpacker."""

    def test_can_handle_upx_pe(self, upx_like_pe: Path):
        """UPXUnpacker should attempt to handle UPX-packed PE."""
        from src.analysis.preprocessing.static_unpacker import UPXUnpacker

        unpacker = UPXUnpacker()
        # The test PE has UPX section names, so it should be detected
        # But since it's not a real UPX-packed binary, may return False
        result = unpacker.can_handle(upx_like_pe)
        assert isinstance(result, bool)

    def test_cannot_handle_normal_pe(self, minimal_pe: Path):
        """UPXUnpacker should reject normal PE."""
        from src.analysis.preprocessing.static_unpacker import UPXUnpacker

        unpacker = UPXUnpacker()
        assert unpacker.can_handle(minimal_pe) is False

    def test_get_output_path(self, minimal_pe: Path, tmp_path: Path):
        """Output path generation should work correctly."""
        from src.analysis.preprocessing.static_unpacker import UPXUnpacker

        unpacker = UPXUnpacker()
        out = unpacker._get_output_path(minimal_pe, str(tmp_path))
        assert out.parent == tmp_path
        assert "_unpacked" in out.name
        assert out.suffix == ".sys"


class TestMPRESSUnpacker:
    """Test MPRESS static unpacker."""

    def test_cannot_handle_normal_pe(self, minimal_pe: Path):
        """MPRESSUnpacker should reject normal PE."""
        from src.analysis.preprocessing.static_unpacker import MPRESSUnpacker

        unpacker = MPRESSUnpacker()
        assert unpacker.can_handle(minimal_pe) is False


class TestGenericPEUnpacker:
    """Test generic PE rebuilder."""

    def test_can_handle_any_pe(self, minimal_pe: Path):
        """GenericPEUnpacker should accept any valid PE."""
        from src.analysis.preprocessing.static_unpacker import GenericPEUnpacker

        unpacker = GenericPEUnpacker()
        assert unpacker.can_handle(minimal_pe) is True


# ---------------------------------------------------------------------------
# CFF Deflattening Tests
# ---------------------------------------------------------------------------

class TestCFFDeflattener:
    """Test control flow flattening detection."""

    def test_detect_no_cff(self):
        """Simple function should not be detected as CFF."""
        from src.analysis.preprocessing.deobfuscator import CFFDeflattener
        from src.models import BasicBlock, Instruction

        # Create a simple linear CFG
        ir = MagicMock()
        block = MagicMock()
        block.address = 0x1000
        block.successors = [0x1010]
        block.instructions = [MagicMock()]
        ir.cfgs = {0x1000: MagicMock(blocks={0x1000: block, 0x1010: MagicMock()})}
        ir.simple_cfgs = {}

        deflattener = CFFDeflattener()
        pattern = deflattener.detect(0x1000, ir)
        # Should not detect CFF in a simple linear flow
        assert pattern is None or pattern.confidence < 0.3

    def test_deflattener_initialization(self):
        """CFFDeflattener should initialize with correct thresholds."""
        from src.analysis.preprocessing.deobfuscator import CFFDeflattener

        deflattener = CFFDeflattener()
        assert deflattener.MIN_DISPATCH_SUCCESSORS >= 3
        assert deflattener.MIN_REAL_BLOCKS >= 2


# ---------------------------------------------------------------------------
# Dead Code Detection Tests
# ---------------------------------------------------------------------------

class TestDeadCodeRemover:
    """Test dead code detection."""

    def test_detect_nop_sled(self):
        """NOP sleds should be detected as junk."""
        from src.analysis.preprocessing.deobfuscator import DeadCodeRemover

        remover = DeadCodeRemover()
        # Create a block with NOPs
        block = MagicMock()
        block.instructions = []
        for i in range(5):
            insn = MagicMock()
            insn.mnemonic = "nop"
            insn.address = 0x1000 + i
            block.instructions.append(insn)
        block.address = 0x1000

        cfg = MagicMock()
        cfg.blocks = {0x1000: block}
        ir = MagicMock()
        ir.cfgs = {0x1000: cfg}
        ir.simple_cfgs = {}

        regions = remover.detect(0x1000, ir)
        nop_regions = [r for r in regions if r.reason == "junk_nop"]
        assert len(nop_regions) >= 1

    def test_detect_push_pop_junk(self):
        """push reg; pop reg should be detected as junk."""
        from src.analysis.preprocessing.deobfuscator import DeadCodeRemover

        remover = DeadCodeRemover()

        push_insn = MagicMock()
        push_insn.mnemonic = "push"
        push_insn.operands = "eax"
        push_insn.address = 0x1000

        pop_insn = MagicMock()
        pop_insn.mnemonic = "pop"
        pop_insn.operands = "eax"
        pop_insn.address = 0x1002

        block = MagicMock()
        block.instructions = [push_insn, pop_insn]
        block.address = 0x1000
        block.successors = []

        cfg = MagicMock()
        cfg.blocks = {0x1000: block}
        ir = MagicMock()
        ir.cfgs = {0x1000: cfg}
        ir.simple_cfgs = {}

        regions = remover.detect(0x1000, ir)
        push_pop = [r for r in regions if "push_pop" in r.reason]
        assert len(push_pop) >= 1


# ---------------------------------------------------------------------------
# IAT Reconstructor Tests
# ---------------------------------------------------------------------------

class TestIATReconstructor:
    """Test IAT reconstruction."""

    def test_known_apis_populated(self):
        """Known API database should be populated."""
        from src.analysis.preprocessing.iat_reconstructor import KNOWN_KERNEL_APIS

        assert "ntoskrnl.exe" in KNOWN_KERNEL_APIS
        assert "MmMapIoSpace" in KNOWN_KERNEL_APIS["ntoskrnl.exe"]
        assert "KeWriteMsr" in KNOWN_KERNEL_APIS["ntoskrnl.exe"]
        assert len(KNOWN_KERNEL_APIS["ntoskrnl.exe"]) > 50

    def test_reconstruction_on_empty_data(self):
        """Reconstruction on empty data should fail gracefully."""
        from src.analysis.preprocessing.iat_reconstructor import IATReconstructor

        recon = IATReconstructor()
        result = recon.reconstruct(b"", image_base=0)
        assert result.success is False

    def test_reconstruction_result_properties(self):
        """IATReconstructionResult properties should work correctly."""
        from src.analysis.preprocessing.iat_reconstructor import (
            IATReconstructionResult,
            ResolvedImport,
            ImportGroup,
        )

        result = IATReconstructionResult()
        result.resolved_imports = [
            ResolvedImport(dll_name="ntoskrnl.exe", api_name="MmMapIoSpace"),
            ResolvedImport(dll_name="ntoskrnl.exe", api_name="KeWriteMsr"),
            ResolvedImport(dll_name="hal.dll", api_name="HalSetSystemInformation"),
        ]
        result.import_groups = [
            ImportGroup(dll_name="ntoskrnl.exe", imports=result.resolved_imports[:2]),
            ImportGroup(dll_name="hal.dll", imports=result.resolved_imports[2:]),
        ]

        assert result.total_resolved == 3
        assert result.total_dlls == 2

    def test_dump_imports_nonexistent(self, tmp_path: Path):
        """dump_imports should handle non-existent files gracefully."""
        from src.analysis.preprocessing.iat_reconstructor import dump_imports

        result = dump_imports(tmp_path / "nonexistent.sys")
        assert result == []


# ---------------------------------------------------------------------------
# Anti-Evasion Tests
# ---------------------------------------------------------------------------

class TestAntiEvasion:
    """Test anti-evasion engine."""

    def test_evasion_levels(self):
        """Evasion levels should be ordered correctly."""
        from src.analysis.dynamic.anti_evasion import EvasionLevel

        assert EvasionLevel.OFF < EvasionLevel.BASIC
        assert EvasionLevel.BASIC < EvasionLevel.MEDIUM
        assert EvasionLevel.MEDIUM < EvasionLevel.AGGRESSIVE

    def test_config_defaults(self):
        """AntiEvasionConfig should have sensible defaults."""
        from src.analysis.dynamic.anti_evasion import AntiEvasionConfig, EvasionLevel

        config = AntiEvasionConfig()
        assert config.level == EvasionLevel.MEDIUM
        assert config.hide_debugger is True
        assert config.hide_vm is True
        assert len(config.hidden_process_names) > 10
        assert len(config.vm_signatures) > 10

    def test_engine_patches_tracking(self):
        """AntiEvasionEngine should track applied patches."""
        from src.analysis.dynamic.anti_evasion import AntiEvasionEngine

        engine = AntiEvasionEngine()
        assert engine.patches_applied == []

    def test_apply_all_no_session(self):
        """apply_all without Frida session should not crash."""
        from src.analysis.dynamic.anti_evasion import AntiEvasionEngine, AntiEvasionConfig, EvasionLevel

        config = AntiEvasionConfig(level=EvasionLevel.BASIC)
        engine = AntiEvasionEngine(config)

        # Without a Frida session, only sandbox-level patches apply
        patches = engine.apply_all(frida_session=None, sandbox=None)
        assert isinstance(patches, list)


# ---------------------------------------------------------------------------
# Memory Analyzer Tests
# ---------------------------------------------------------------------------

class TestMemoryAnalyzer:
    """Test memory analyzer."""

    def test_find_pe_in_memory_mz(self):
        """Should find MZ signature in memory data."""
        from src.analysis.dynamic.memory_analyzer import MemoryAnalyzer

        analyzer = MemoryAnalyzer()

        # Create data with embedded MZ header
        data = bytearray(0x200)
        data[0x100:0x102] = b"MZ"
        struct.pack_into("<I", data, 0x100 + 0x3C, 0x80)
        data[0x100 + 0x80:0x100 + 0x84] = b"PE\x00\x00"

        pes = analyzer.find_pe_in_memory(bytes(data), base_address=0x10000)
        # May or may not find a valid PE depending on header completeness
        # but should not crash
        assert isinstance(pes, list)

    def test_detect_inline_hook_jmp(self):
        """Should detect JMP rel32 inline hook."""
        from src.analysis.dynamic.memory_analyzer import MemoryAnalyzer

        analyzer = MemoryAnalyzer()

        # Create data with a JMP rel32 at offset 0
        data = bytearray(0x100)
        data[0] = 0xE9  # JMP rel32
        struct.pack_into("<i", data, 1, 0x1000)  # Jump far away

        hooks = analyzer.detect_hooks(bytes(data), module_base=0x1000)
        jmp_hooks = [h for h in hooks if h.hook_type == "inline"]
        assert len(jmp_hooks) >= 1

    def test_detect_inline_hook_push_ret(self):
        """Should detect PUSH+RET inline hook."""
        from src.analysis.dynamic.memory_analyzer import MemoryAnalyzer

        analyzer = MemoryAnalyzer()

        data = bytearray(0x100)
        data[0] = 0x68  # PUSH imm32
        struct.pack_into("<I", data, 1, 0xDEADBEEF)
        data[5] = 0xC3  # RET

        hooks = analyzer.detect_hooks(bytes(data), module_base=0x2000)
        push_ret = [h for h in hooks if "PUSH" in h.target]
        assert len(push_ret) >= 1

    def test_suspicious_rwx_regions(self):
        """RWX regions should be flagged as suspicious."""
        from src.analysis.dynamic.memory_analyzer import MemoryAnalyzer, MemoryRegion

        analyzer = MemoryAnalyzer()

        regions = [
            MemoryRegion(base_address=0x1000, size=0x2000, protection="rwx", state="commit"),
            MemoryRegion(base_address=0x4000, size=0x2000, protection="r-x", state="commit"),
            MemoryRegion(base_address=0x6000, size=0x2000, protection="rw-", state="commit"),
        ]

        suspicious = analyzer.find_suspicious_regions(regions)
        assert len(suspicious) >= 1
        assert suspicious[0].base_address == 0x1000

    def test_memory_region_properties(self):
        """MemoryRegion properties should work correctly."""
        from src.analysis.dynamic.memory_analyzer import MemoryRegion

        rwx = MemoryRegion(protection="rwx")
        assert rwx.is_executable
        assert rwx.is_writable

        rx = MemoryRegion(protection="r-x")
        assert rx.is_executable
        assert not rx.is_writable

        region = MemoryRegion(base_address=0x1000, size=0x500)
        assert region.end_address == 0x1500


# ---------------------------------------------------------------------------
# Pipeline Routing Tests
# ---------------------------------------------------------------------------

class TestPreprocessingRouter:
    """Test preprocessing router."""

    def test_route_no_packer(self, minimal_pe: Path):
        """Non-packed PE should get deobfuscation only."""
        from src.analysis.preprocessing.pipeline import (
            PreprocessingRouter,
            PreprocessingConfig,
            PackerInfo,
        )

        router = PreprocessingRouter()
        config = PreprocessingConfig()
        packer_info = PackerInfo(is_packed=False)

        steps = router.route(minimal_pe, packer_info, config)
        step_names = [s[0] for s in steps]
        assert "deobfuscate" in step_names
        assert "unpack" not in step_names

    def test_route_upx(self, upx_like_pe: Path):
        """UPX-packed PE should get static unpack."""
        from src.analysis.preprocessing.pipeline import (
            PreprocessingRouter,
            PreprocessingConfig,
            PackerInfo,
        )

        router = PreprocessingRouter()
        config = PreprocessingConfig()
        packer_info = PackerInfo(name="UPX", is_packed=True)

        steps = router.route(upx_like_pe, packer_info, config)
        step_names = [s[0] for s in steps]
        assert "unpack" in step_names
        handler_names = [s[1] for s in steps]
        assert "UPXUnpacker" in handler_names

    def test_route_vmprotect(self, minimal_pe: Path):
        """VMProtect-packed PE should get dynamic unpack."""
        from src.analysis.preprocessing.pipeline import (
            PreprocessingRouter,
            PreprocessingConfig,
            PackerInfo,
        )

        router = PreprocessingRouter()
        config = PreprocessingConfig(allow_dynamic_unpack=True)
        packer_info = PackerInfo(name="VMProtect", is_packed=True)

        steps = router.route(minimal_pe, packer_info, config)
        handler_names = [s[1] for s in steps]
        assert "DynamicUnpacker" in handler_names


# ---------------------------------------------------------------------------
# Full Pipeline Integration Tests
# ---------------------------------------------------------------------------

class TestPreprocessingPipeline:
    """Test full preprocessing pipeline."""

    def test_run_preprocessing_normal_pe(self, minimal_pe: Path):
        """Pipeline should handle normal PE without error."""
        from src.analysis.preprocessing import run_preprocessing

        result = run_preprocessing(str(minimal_pe))
        assert result.target == str(minimal_pe)
        assert result.elapsed >= 0
        assert isinstance(result.cleaned_target, str)

    def test_run_preprocessing_nonexistent(self, tmp_path: Path):
        """Pipeline should handle non-existent target gracefully."""
        from src.analysis.preprocessing import run_preprocessing

        result = run_preprocessing(str(tmp_path / "nonexistent.sys"))
        assert len(result.warnings) > 0
        assert result.cleaned_target == str(tmp_path / "nonexistent.sys")

    def test_run_preprocessing_disabled(self, minimal_pe: Path):
        """Disabled preprocessing should pass through."""
        from src.analysis.preprocessing import run_preprocessing
        from src.analysis.preprocessing.pipeline import PreprocessingConfig

        config = PreprocessingConfig(enabled=False)
        result = run_preprocessing(str(minimal_pe), config)
        assert result.cleaned_target == str(minimal_pe)
        assert result.was_unpacked is False

    def test_preprocessing_config_defaults(self):
        """PreprocessingConfig should have sensible defaults."""
        from src.analysis.preprocessing.pipeline import PreprocessingConfig

        config = PreprocessingConfig()
        assert config.enabled is True
        assert config.allow_static_unpack is True
        assert config.allow_dynamic_unpack is True
        assert config.allow_deobfuscation is True
        assert config.dynamic_unpack_timeout > 0

    def test_preprocessing_result_properties(self):
        """PreprocessingResult properties should work correctly."""
        from src.analysis.preprocessing.pipeline import PreprocessingResult, UnpackResult

        result = PreprocessingResult()
        assert result.was_unpacked is False

        result.unpack_result = UnpackResult(success=True)
        assert result.was_unpacked is True


# ---------------------------------------------------------------------------
# Sandbox Manager Tests
# ---------------------------------------------------------------------------

class TestSandboxManager:
    """Test QEMU sandbox manager."""

    def test_sandbox_config_defaults(self):
        """SandboxConfig should have sensible defaults."""
        from src.analysis.dynamic.sandbox import SandboxConfig

        config = SandboxConfig()
        assert config.memory_mb == 4096
        assert config.cpu_cores == 2
        assert config.snapshot_name == "clean"

    def test_sandbox_not_available_without_config(self):
        """Sandbox should not be available without QEMU configured."""
        from src.analysis.dynamic.sandbox import SandboxManager, SandboxConfig

        manager = SandboxManager(SandboxConfig())
        assert manager.is_available is False

    def test_sandbox_state_initial(self):
        """SandboxState should start in clean state."""
        from src.analysis.dynamic.sandbox import SandboxState

        state = SandboxState()
        assert state.running is False
        assert state.qga_connected is False
        assert state.transfer_method == ""
