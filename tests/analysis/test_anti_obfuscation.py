"""Tests for Phase 11: Anti-Debug, Anti-Obfuscation, and Anti-Reversing detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    Architecture,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Severity,
    Confidence,
)
from src.analysis.core.semantic_analyzer import SemanticAnalyzer
from src.analysis.core.anti_obfuscation import (
    AntiObfuscationAnalyzer,
    detect_flattening,
    detect_dead_code,
    detect_packer,
    detect_api_hashing,
    detect_string_encryption,
    _shannon_entropy,
)


def _make_sample() -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="test.sys",
        company="Test Corp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="abc123",
        size=8192,
    )


def _make_ir_with_instructions(func_addr: int, instructions: list) -> DisassemblyResult:
    """Create a DisassemblyResult with a single function containing given instructions."""
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
    func = Function(name=f"sub_{func_addr:X}", address=func_addr, size=0x200)
    ir.functions[func_addr] = func
    ir.ioctl_handlers[0x22A004] = func_addr

    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    block = BasicBlock(
        address=func_addr,
        end_address=func_addr + 0x200,
        instructions=instructions,
        successors=[],
    )
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg
    return ir


def _make_mock_instruction(address: int, mnemonic: str, operands: str = "", api_target=None) -> MagicMock:
    """Create a mock Instruction."""
    insn = MagicMock()
    insn.address = address
    insn.mnemonic = mnemonic
    insn.operands = operands
    insn.api_target = api_target
    return insn


# ---------------------------------------------------------------------------
# Anti-Debug Instruction Tests (SemanticAnalyzer)
# ---------------------------------------------------------------------------

class TestAntiDebugSemanticRules:
    """Test anti-debug instruction detection via SemanticAnalyzer."""

    def setup_method(self):
        self.analyzer = SemanticAnalyzer()
        self.sample = _make_sample()

    def test_detects_rdtsc_timing_check(self):
        """RDTSC instruction should be flagged as anti-debug timing."""
        ir = _make_ir_with_instructions(0x1000, [
            _make_mock_instruction(0x1010, "rdtsc", ""),
            _make_mock_instruction(0x1020, "sub", "eax, edx"),
        ])
        findings = self.analyzer.analyze(self.sample, ir)
        rdtsc_findings = [f for f in findings if "RDTSC" in f.description or "rdtsc" in f.description]
        assert len(rdtsc_findings) >= 1

    def test_detects_cpuid_hypervisor_check(self):
        """CPUID instruction should be flagged as potential hypervisor detection."""
        ir = _make_ir_with_instructions(0x2000, [
            _make_mock_instruction(0x2010, "cpuid", ""),
        ])
        findings = self.analyzer.analyze(self.sample, ir)
        cpuid_findings = [f for f in findings if "CPUID" in f.description or "cpuid" in f.description]
        assert len(cpuid_findings) >= 1

    def test_detects_int3_trap(self):
        """INT 3 should be flagged as potential anti-debug trap."""
        ir = _make_ir_with_instructions(0x3000, [
            _make_mock_instruction(0x3010, "int", "3"),
        ])
        findings = self.analyzer.analyze(self.sample, ir)
        int3_findings = [f for f in findings if "INT 3" in f.description or "int" in f.description.lower()]
        assert len(int3_findings) >= 1

    def test_detects_sidt_hypervisor(self):
        """SIDT should be flagged as Red Pill hypervisor detection."""
        ir = _make_ir_with_instructions(0x4000, [
            _make_mock_instruction(0x4010, "sidt", "[rsp]"),
        ])
        findings = self.analyzer.analyze(self.sample, ir)
        sidt_findings = [f for f in findings if "SIDT" in f.description or "sidt" in f.description.lower()]
        assert len(sidt_findings) >= 1

    def test_detects_sgdt_hypervisor(self):
        """SGDT should be flagged as Red Pill hypervisor detection."""
        ir = _make_ir_with_instructions(0x5000, [
            _make_mock_instruction(0x5010, "sgdt", "[rsp]"),
        ])
        findings = self.analyzer.analyze(self.sample, ir)
        sgdt_findings = [f for f in findings if "SGDT" in f.description or "sgdt" in f.description.lower()]
        assert len(sgdt_findings) >= 1

    def test_detects_str_anti_vm(self):
        """STR should be flagged as anti-VM detection."""
        ir = _make_ir_with_instructions(0x6000, [
            _make_mock_instruction(0x6010, "str", "rax"),
        ])
        findings = self.analyzer.analyze(self.sample, ir)
        str_findings = [f for f in findings if "STR" in f.description and "hypervisor" in f.description.lower()]
        assert len(str_findings) >= 1

    def test_detects_seh_setup(self):
        """FS:[0] write should be flagged as SEH anti-debug setup."""
        ir = _make_ir_with_instructions(0x7000, [
            _make_mock_instruction(0x7010, "mov", "dword ptr fs:[0], eax"),
        ])
        findings = self.analyzer.analyze(self.sample, ir)
        seh_findings = [f for f in findings if "SEH" in f.description or "fs:[0]" in f.description.lower()]
        assert len(seh_findings) >= 1


# ---------------------------------------------------------------------------
# Control Flow Flattening Tests
# ---------------------------------------------------------------------------

class TestControlFlowFlattening:
    """Test CFG-based control flow flattening detection."""

    def test_detects_flat_cfg(self):
        """Function with many small blocks should be flagged as flat."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_1000", address=0x1000, size=0x400)
        ir.functions[0x1000] = func
        ir.ioctl_handlers[0x22A004] = 0x1000

        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        # Create 40 blocks with 2 instructions each (flat CFG)
        for i in range(40):
            addr = 0x1000 + i * 0x10
            block = BasicBlock(
                address=addr,
                end_address=addr + 0x10,
                instructions=[
                    _make_mock_instruction(addr, "mov", "rax, rbx"),
                    _make_mock_instruction(addr + 8, "jmp", f"0x{addr + 0x20:X}"),
                ],
                successors=[addr + 0x20] if i < 39 else [],
            )
            cfg.blocks[addr] = block

        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

        suspicious = detect_flattening(ir)
        assert len(suspicious) >= 1
        assert suspicious[0][0] == 0x1000

    def test_detects_dispatch_blocks(self):
        """Multiple blocks with many successors should trigger dispatch detection."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_2000", address=0x2000, size=0x800)
        ir.functions[0x2000] = func
        ir.ioctl_handlers[0x22A004] = 0x2000

        cfg = CFG(function_address=0x2000, entry_block=0x2000)

        # Dispatch block with 8 successors
        dispatch_block = BasicBlock(
            address=0x2000,
            end_address=0x2020,
            instructions=[
                _make_mock_instruction(0x2000, "jmp", "qword ptr [rax+rcx*8]"),
            ],
            successors=[0x2100 + i * 0x100 for i in range(8)],
        )
        cfg.blocks[0x2000] = dispatch_block

        # Many target blocks
        for i in range(30):
            addr = 0x2100 + i * 0x100
            block = BasicBlock(
                address=addr,
                end_address=addr + 0x50,
                instructions=[
                    _make_mock_instruction(addr, "nop", ""),
                ],
                successors=[],
            )
            cfg.blocks[addr] = block

        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        suspicious = detect_flattening(ir)
        assert len(suspicious) >= 1

    def test_no_false_positive_small_function(self):
        """Small functions should not be flagged."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_3000", address=0x3000, size=0x50)
        ir.functions[0x3000] = func

        cfg = CFG(function_address=0x3000, entry_block=0x3000)
        block = BasicBlock(
            address=0x3000,
            end_address=0x3050,
            instructions=[
                _make_mock_instruction(0x3000, "mov", "rax, rbx"),
                _make_mock_instruction(0x3010, "ret", ""),
            ],
            successors=[],
        )
        cfg.blocks[0x3000] = block
        ir.cfgs[0x3000] = ir.simple_cfgs[0x3000] = cfg

        suspicious = detect_flattening(ir)
        assert len(suspicious) == 0


# ---------------------------------------------------------------------------
# Dead Code / Junk Injection Tests
# ---------------------------------------------------------------------------

class TestDeadCodeDetection:
    """Test junk instruction detection."""

    def test_detects_junk_code(self):
        """Function with high junk instruction density should be flagged."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_4000", address=0x4000, size=0x400)
        ir.functions[0x4000] = func
        ir.ioctl_handlers[0x22A004] = 0x4000

        cfg = CFG(function_address=0x4000, entry_block=0x4000)

        # Junk: push/pop pairs
        instructions = []
        addr = 0x4000
        for i in range(15):
            instructions.append(_make_mock_instruction(addr, "push", "rax"))
            addr += 2
            instructions.append(_make_mock_instruction(addr, "pop", "rax"))
            addr += 2

        # Junk: consecutive NOPs
        for i in range(10):
            instructions.append(_make_mock_instruction(addr, "nop", ""))
            addr += 1

        # Some real instructions
        for i in range(10):
            instructions.append(_make_mock_instruction(addr, "mov", "rax, rbx"))
            addr += 4

        block = BasicBlock(
            address=0x4000,
            end_address=addr,
            instructions=instructions,
            successors=[],
        )
        cfg.blocks[0x4000] = block
        ir.cfgs[0x4000] = ir.simple_cfgs[0x4000] = cfg

        suspicious = detect_dead_code(ir)
        assert len(suspicious) >= 1

    def test_no_false_positive_clean_function(self):
        """Clean functions should not trigger junk detection."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_5000", address=0x5000, size=0x100)
        ir.functions[0x5000] = func

        cfg = CFG(function_address=0x5000, entry_block=0x5000)
        block = BasicBlock(
            address=0x5000,
            end_address=0x5100,
            instructions=[
                _make_mock_instruction(0x5000, "push", "rbp"),
                _make_mock_instruction(0x5010, "mov", "rbp, rsp"),
                _make_mock_instruction(0x5020, "mov", "rax, rcx"),
                _make_mock_instruction(0x5030, "call", "0x6000"),
                _make_mock_instruction(0x5040, "pop", "rbp"),
                _make_mock_instruction(0x5050, "ret", ""),
            ],
            successors=[],
        )
        cfg.blocks[0x5000] = block
        ir.cfgs[0x5000] = ir.simple_cfgs[0x5000] = cfg

        suspicious = detect_dead_code(ir)
        assert len(suspicious) == 0


# ---------------------------------------------------------------------------
# PE Packer Detection Tests
# ---------------------------------------------------------------------------

class TestPackerDetection:
    """Test PE packer detection."""

    def test_upx_detection(self):
        """UPX packer should be detected via section names."""
        mock_pe = MagicMock()
        s1 = MagicMock()
        s1.Name = b"UPX0    "
        s1.VirtualAddress = 0x1000
        s1.Misc_VirtualSize = 0x1000
        s1.get_data.return_value = b"\xCC" * 0x100  # Low entropy data

        s2 = MagicMock()
        s2.Name = b"UPX1    "
        s2.VirtualAddress = 0x2000
        s2.Misc_VirtualSize = 0x2000
        s2.get_data.return_value = b"\xAA\xBB" * 0x50  # Some data

        mock_pe.sections = [s1, s2]
        mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1500
        mock_pe.DIRECTORY_ENTRY_IMPORT = [MagicMock()]

        with patch("pefile.PE", return_value=mock_pe):
            result = detect_packer(Path("test.sys"))
            assert result["packer_name"] == "UPX"
            assert result["overall_suspicious"] is True

    def test_high_entropy_detection(self):
        """Sections with very high entropy should be flagged."""
        mock_pe = MagicMock()
        s1 = MagicMock()
        s1.Name = b".text   "
        s1.VirtualAddress = 0x1000
        s1.Misc_VirtualSize = 0x1000
        # Generate high-entropy data (uniformly distributed bytes)
        s1.get_data.return_value = bytes(range(256)) * 10

        mock_pe.sections = [s1]
        mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe.DIRECTORY_ENTRY_IMPORT = [MagicMock()]

        with patch("pefile.PE", return_value=mock_pe):
            result = detect_packer(Path("test.sys"))
            assert ".text" in result["high_entropy_sections"]
            assert result["overall_suspicious"] is True

    def test_empty_iat_detection(self):
        """Empty import table should be flagged."""
        mock_pe = MagicMock()
        s1 = MagicMock()
        s1.Name = b".text   "
        s1.VirtualAddress = 0x1000
        s1.Misc_VirtualSize = 0x1000
        s1.get_data.return_value = b"\x90" * 0x100

        mock_pe.sections = [s1]
        mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe.DIRECTORY_ENTRY_IMPORT = []  # Empty!

        with patch("pefile.PE", return_value=mock_pe):
            result = detect_packer(Path("test.sys"))
            assert result["has_empty_iat"] is True
            assert result["overall_suspicious"] is True

    def test_clean_driver_no_detection(self):
        """Normal driver should not trigger packer detection."""
        mock_pe = MagicMock()
        s1 = MagicMock()
        s1.Name = b".text   "
        s1.VirtualAddress = 0x1000
        s1.Misc_VirtualSize = 0x1000
        s1.get_data.return_value = b"\x90" * 0x100  # NOPs, low entropy

        s2 = MagicMock()
        s2.Name = b".rdata  "
        s2.VirtualAddress = 0x2000
        s2.Misc_VirtualSize = 0x1000
        s2.get_data.return_value = b"Hello World\x00" * 10

        mock_pe.sections = [s1, s2]
        mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe.DIRECTORY_ENTRY_IMPORT = [MagicMock()]

        with patch("pefile.PE", return_value=mock_pe):
            result = detect_packer(Path("test.sys"))
            assert result["overall_suspicious"] is False
            assert result["packer_name"] is None


# ---------------------------------------------------------------------------
# API Hashing Detection Tests
# ---------------------------------------------------------------------------

class TestAPIHashingDetection:
    """Test API hashing pattern detection."""

    def test_detects_hashing_pattern(self):
        """Function with ROL/ROR + XOR chains should be flagged."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_6000", address=0x6000, size=0x300)
        ir.functions[0x6000] = func
        ir.ioctl_handlers[0x22A004] = 0x6000

        cfg = CFG(function_address=0x6000, entry_block=0x6000)

        instructions = [
            # Hash computation loop pattern
            _make_mock_instruction(0x6000, "mov", "eax, dword ptr [rcx]"),
            _make_mock_instruction(0x6010, "ror", "eax, 0xd"),
            _make_mock_instruction(0x6020, "xor", "eax, 0x12345678"),
            _make_mock_instruction(0x6030, "rol", "eax, 0x7"),
            _make_mock_instruction(0x6040, "xor", "eax, 0xDEADBEEF"),
            _make_mock_instruction(0x6050, "shr", "eax, 3"),
            _make_mock_instruction(0x6060, "xor", "eax, 0xCAFEBABE"),
            _make_mock_instruction(0x6070, "rol", "eax, 0xb"),
            _make_mock_instruction(0x6080, "xor", "eax, 0x01020304"),
            _make_mock_instruction(0x6090, "shr", "eax, 5"),
            _make_mock_instruction(0x60A0, "xor", "eax, 0xFEDCBA98"),
            _make_mock_instruction(0x60B0, "ret", ""),
        ]

        block = BasicBlock(
            address=0x6000,
            end_address=0x60C0,
            instructions=instructions,
            successors=[],
        )
        cfg.blocks[0x6000] = block
        ir.cfgs[0x6000] = ir.simple_cfgs[0x6000] = cfg

        suspicious = detect_api_hashing(ir)
        assert len(suspicious) >= 1

    def test_no_false_positive_normal_function(self):
        """Normal functions should not be flagged as API hashing."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_7000", address=0x7000, size=0x100)
        ir.functions[0x7000] = func

        cfg = CFG(function_address=0x7000, entry_block=0x7000)
        block = BasicBlock(
            address=0x7000,
            end_address=0x7100,
            instructions=[
                _make_mock_instruction(0x7000, "push", "rbp"),
                _make_mock_instruction(0x7010, "mov", "rbp, rsp"),
                _make_mock_instruction(0x7020, "mov", "eax, [rcx]"),
                _make_mock_instruction(0x7030, "add", "eax, 1"),
                _make_mock_instruction(0x7040, "pop", "rbp"),
                _make_mock_instruction(0x7050, "ret", ""),
            ],
            successors=[],
        )
        cfg.blocks[0x7000] = block
        ir.cfgs[0x7000] = ir.simple_cfgs[0x7000] = cfg

        suspicious = detect_api_hashing(ir)
        assert len(suspicious) == 0


# ---------------------------------------------------------------------------
# Shannon Entropy Tests
# ---------------------------------------------------------------------------

class TestEntropyCalculation:
    """Test Shannon entropy calculation."""

    def test_zero_entropy(self):
        """All same bytes should have zero entropy."""
        data = b"\x00" * 100
        assert _shannon_entropy(data) == 0.0

    def test_low_entropy(self):
        """Repeating pattern should have low entropy."""
        data = b"\x00\xFF" * 50
        assert _shannon_entropy(data) == 1.0

    def test_high_entropy(self):
        """Uniformly distributed bytes should have high entropy (~8.0)."""
        data = bytes(range(256)) * 10
        entropy = _shannon_entropy(data)
        assert entropy > 7.5


# ---------------------------------------------------------------------------
# Full AntiObfuscationAnalyzer Tests
# ---------------------------------------------------------------------------

class TestAntiObfuscationAnalyzer:
    """Test the full AntiObfuscationAnalyzer integration."""

    def setup_method(self):
        self.analyzer = AntiObfuscationAnalyzer()
        self.sample = _make_sample()

    def test_analyzer_detects_flattening(self):
        """Analyzer should produce finding for CFG flattening."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_8000", address=0x8000, size=0x400)
        ir.functions[0x8000] = func
        ir.ioctl_handlers[0x22A004] = 0x8000

        cfg = CFG(function_address=0x8000, entry_block=0x8000)
        for i in range(40):
            addr = 0x8000 + i * 0x10
            block = BasicBlock(
                address=addr,
                end_address=addr + 0x10,
                instructions=[
                    _make_mock_instruction(addr, "mov", "rax, rbx"),
                ],
                successors=[addr + 0x10] if i < 39 else [],
            )
            cfg.blocks[addr] = block
        ir.cfgs[0x8000] = ir.simple_cfgs[0x8000] = cfg

        # Sample path doesn't exist, so packer detection is skipped
        self.sample.path = Path(__file__)  # Use existing file

        findings = self.analyzer.analyze(self.sample, ir)
        flattening_findings = [
            f for f in findings if f.category == FindingCategory.CONTROL_FLOW_FLATTENING
        ]
        assert len(flattening_findings) >= 1

    def test_analyzer_no_findings_on_clean_driver(self):
        """Clean driver should not produce anti-obfuscation findings."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="DriverEntry", address=0x9000, size=0x100)
        ir.functions[0x9000] = func

        cfg = CFG(function_address=0x9000, entry_block=0x9000)
        block = BasicBlock(
            address=0x9000,
            end_address=0x9100,
            instructions=[
                _make_mock_instruction(0x9000, "push", "rbp"),
                _make_mock_instruction(0x9010, "mov", "rbp, rsp"),
                _make_mock_instruction(0x9020, "ret", ""),
            ],
            successors=[],
        )
        cfg.blocks[0x9000] = block
        ir.cfgs[0x9000] = ir.simple_cfgs[0x9000] = cfg

        self.sample.path = Path(__file__)
        findings = self.analyzer.analyze(self.sample, ir)

        # Should have no anti-obfuscation findings
        obf_findings = [
            f for f in findings
            if f.category in (
                FindingCategory.CONTROL_FLOW_FLATTENING,
                FindingCategory.DEAD_CODE_INJECTION,
                FindingCategory.PACKED_BINARY,
                FindingCategory.API_HASHING,
            )
        ]
        assert len(obf_findings) == 0


# ---------------------------------------------------------------------------
# String Encryption Detection Tests
# ---------------------------------------------------------------------------

class TestStringEncryption:
    """Test string encryption / decryption pattern detection."""

    def test_xor_decrypt_loop(self):
        """XOR decrypt loop should be detected."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_7000", address=0x7000, size=0x100)
        ir.functions[0x7000] = func

        cfg = CFG(function_address=0x7000, entry_block=0x7000)
        block = BasicBlock(
            address=0x7000,
            end_address=0x7100,
            instructions=[
                _make_mock_instruction(0x7000, "mov", "rax, rcx"),
                _make_mock_instruction(0x7010, "mov", "al, byte ptr [rax]"),  # byte array read
                _make_mock_instruction(0x7020, "xor", "al, 0x42"),           # XOR with key
                _make_mock_instruction(0x7030, "mov", "byte ptr [rdx], al"),  # byte array write
                _make_mock_instruction(0x7040, "mov", "al, byte ptr [rax+1]"),
                _make_mock_instruction(0x7050, "xor", "al, 0x42"),
                _make_mock_instruction(0x7060, "mov", "byte ptr [rdx+1], al"),
                _make_mock_instruction(0x7070, "add", "rax, 2"),
                _make_mock_instruction(0x7080, "cmp", "rax, rcx"),
                _make_mock_instruction(0x7090, "jne", "0x7010"),
                _make_mock_instruction(0x70a0, "ret", ""),
            ],
            successors=[],
        )
        cfg.blocks[0x7000] = block
        ir.cfgs[0x7000] = ir.simple_cfgs[0x7000] = cfg

        suspicious = detect_string_encryption(ir)
        assert len(suspicious) >= 1
        assert suspicious[0][1]["xor_decrypt"] >= 2
        assert suspicious[0][1]["byte_array_access"] >= 2

    def test_stack_string_construction(self):
        """Stack-based string construction should be detected."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_8000", address=0x8000, size=0x100)
        ir.functions[0x8000] = func

        cfg = CFG(function_address=0x8000, entry_block=0x8000)
        block = BasicBlock(
            address=0x8000,
            end_address=0x8100,
            instructions=[
                _make_mock_instruction(0x8000, "push", "rbp"),
                _make_mock_instruction(0x8010, "mov", "rbp, rsp"),
                _make_mock_instruction(0x8015, "sub", "rsp, 0x20"),
                _make_mock_instruction(0x8020, "mov", "byte ptr [rsp+0x10], 0x41"),  # 'A'
                _make_mock_instruction(0x8030, "mov", "byte ptr [rsp+0x11], 0x42"),  # 'B'
                _make_mock_instruction(0x8040, "mov", "byte ptr [rsp+0x12], 0x43"),  # 'C'
                _make_mock_instruction(0x8050, "mov", "byte ptr [rsp+0x13], 0x44"),  # 'D'
                _make_mock_instruction(0x8060, "mov", "byte ptr [rsp+0x14], 0x00"),  # null
                _make_mock_instruction(0x8070, "lea", "rax, [rsp+0x10]"),
                _make_mock_instruction(0x8080, "mov", "rcx, rax"),
                _make_mock_instruction(0x8085, "pop", "rbp"),
                _make_mock_instruction(0x8090, "ret", ""),
            ],
            successors=[],
        )
        cfg.blocks[0x8000] = block
        ir.cfgs[0x8000] = ir.simple_cfgs[0x8000] = cfg

        suspicious = detect_string_encryption(ir)
        assert len(suspicious) >= 1
        assert suspicious[0][1]["stack_str_build"] >= 4

    def test_no_false_positive_clean_function(self):
        """Clean functions should not trigger string encryption detection."""
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_9000", address=0x9000, size=0x100)
        ir.functions[0x9000] = func

        cfg = CFG(function_address=0x9000, entry_block=0x9000)
        block = BasicBlock(
            address=0x9000,
            end_address=0x9100,
            instructions=[
                _make_mock_instruction(0x9000, "push", "rbp"),
                _make_mock_instruction(0x9010, "mov", "rbp, rsp"),
                _make_mock_instruction(0x9020, "mov", "rax, rcx"),
                _make_mock_instruction(0x9030, "xor", "edx, edx"),  # XOR reg, reg (not imm)
                _make_mock_instruction(0x9040, "call", "0xa000"),
                _make_mock_instruction(0x9050, "pop", "rbp"),
                _make_mock_instruction(0x9060, "ret", ""),
            ],
            successors=[],
        )
        cfg.blocks[0x9000] = block
        ir.cfgs[0x9000] = ir.simple_cfgs[0x9000] = cfg

        suspicious = detect_string_encryption(ir)
        assert len(suspicious) == 0
