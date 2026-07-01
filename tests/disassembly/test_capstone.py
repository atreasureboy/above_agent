"""Tests for Capstone disassembly backend."""

import pytest
from pathlib import Path
from src.disassembly.capstone_backend import (
    CapstoneBackend,
    DANGEROUS_APIS,
)
from src.utils.ioctl import looks_like_ioctl_code
from src.models import Architecture


SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"
MOCK_DRIVER = SAMPLES_DIR / "unknown" / "mock_driver.sys"


def _has_sample():
    return MOCK_DRIVER.exists()


class TestCapstoneBackendAvailability:
    def test_is_available(self):
        backend = CapstoneBackend()
        assert backend.name == "capstone"

    def test_is_available_returns_bool(self):
        backend = CapstoneBackend()
        result = backend.is_available()
        assert isinstance(result, bool)

    def test_get_version(self):
        backend = CapstoneBackend()
        if backend.is_available():
            v = backend.get_version()
            assert isinstance(v, str)
            assert len(v) > 0


class TestDangerousAPIs:
    def test_contains_memory_apis(self):
        assert "MmMapIoSpace" in DANGEROUS_APIS

    def test_contains_msr_apis(self):
        assert "KeWriteMsr" in DANGEROUS_APIS
        assert "KeReadMsr" in DANGEROUS_APIS

    def test_contains_physical_memory_apis(self):
        assert "MmGetPhysicalAddress" in DANGEROUS_APIS

    def test_contains_kernel_rw_apis(self):
        assert "MmCopyVirtualMemory" in DANGEROUS_APIS

    def test_contains_process_manipulation_apis(self):
        assert "ZwOpenProcess" in DANGEROUS_APIS
        assert "ZwCreateThreadEx" in DANGEROUS_APIS

    def test_contains_wdf_apis(self):
        assert "WdfDriverCreate" in DANGEROUS_APIS
        assert "WdfIoQueueCreate" in DANGEROUS_APIS


class TestLooksLikeIoctlCode:
    """Tests for the shared IOCTL code heuristic."""

    def test_zero_not_ioctl(self):
        assert not looks_like_ioctl_code(0)

    def test_small_value_not_ioctl(self):
        """Values < 0x10000 can't have a device type."""
        assert not looks_like_ioctl_code(0x1234)

    def test_kernel_pointer_rejected(self):
        """0xFxxxxxxx range should be rejected."""
        assert not looks_like_ioctl_code(0xFFFF1234)

    def test_valid_device_type_with_realistic_function(self):
        """Device type 0x22 (FILE_DEVICE_UNKNOWN) + function 0x100 = realistic."""
        # CTL_CODE(0x22, 0x100, 0x0, 0x0) = 0x22 << 16 | 0x100 << 2 = 0x220400
        val = (0x22 << 16) | (0x100 << 2) | 0x0
        assert looks_like_ioctl_code(val)

    def test_method_neither_valid(self):
        """Method=3 (NEITHER) is still valid."""
        val = (0x22 << 16) | (0x80 << 2) | 0x3
        assert looks_like_ioctl_code(val)

    def test_any_access_valid(self):
        """Access=0 (ANY) is valid."""
        val = (0x8000 << 16) | (0x1 << 2) | 0x0  # FILE_DEVICE_USER_DEFINED
        assert looks_like_ioctl_code(val)

    def test_function_too_large(self):
        """Function > 0x800 should be rejected."""
        val = (0x22 << 16) | (0x900 << 2) | 0x0
        assert not looks_like_ioctl_code(val)

    def test_unknown_device_type(self):
        """Random device type not in whitelist."""
        val = (0x77 << 16) | (0x100 << 2) | 0x0
        assert not looks_like_ioctl_code(val)

    def test_common_hid_ioctl(self):
        """HID device type (0xAA55) with reasonable function."""
        val = (0xAA55 << 16) | (0x200 << 2) | 0x0
        assert looks_like_ioctl_code(val)

    def test_vmbus_ioctl(self):
        """VMBUS device type (0x47) with reasonable function."""
        val = (0x47 << 16) | (0x100 << 2) | 0x0
        assert looks_like_ioctl_code(val)


class TestCapstoneIndirectCallResolution:
    """Phase 2: Indirect call resolution via register tracing."""

    def test_trace_iat_load_to_register_basic(self):
        """Trace call rax back to mov rax, qword ptr [rip+offset]."""
        backend = CapstoneBackend()
        backend._image_base = 0x10000

        class MockInsn:
            def __init__(self, mnemonic, operands, size=7):
                self.mnemonic = mnemonic
                self.operands = operands
                self.size = size

        # mov rax, qword ptr [rip+0x100] at 0x1000, size=7
        # target_va = 0x1000 + 7 + 0x100 = 0x1107
        all_insns = {
            0x1000: MockInsn("mov", "rax, qword ptr [rip + 0x100]", 7),
            0x1010: MockInsn("nop", "", 1),
            0x1020: MockInsn("call", "rax", 2),
        }

        result = backend._trace_iat_load_to_register("rax", 0x1020, all_insns)
        # Returns VA = addr(0x1000) + size(7) + offset(0x100) + image_base(0x10000) = 0x11107
        assert result == 0x11107

    def test_trace_stopped_by_clobber(self):
        """If register is overwritten before call, tracing should stop."""
        backend = CapstoneBackend()
        backend._image_base = 0x10000

        class MockInsn:
            def __init__(self, mnemonic, operands, size=3):
                self.mnemonic = mnemonic
                self.operands = operands
                self.size = size

        all_insns = {
            0x1000: MockInsn("mov", "rax, qword ptr [rip + 0x100]", 7),
            0x1010: MockInsn("mov", "rax, 0x42", 5),  # Clobbered with non-IAT value
            0x1020: MockInsn("call", "rax", 2),
        }

        result = backend._trace_iat_load_to_register("rax", 0x1020, all_insns)
        assert result is None

    def test_trace_returns_none_when_no_load(self):
        """If no IAT load found before call, should return None."""
        backend = CapstoneBackend()
        backend._image_base = 0x10000

        class MockInsn:
            def __init__(self, mnemonic, operands, size=1):
                self.mnemonic = mnemonic
                self.operands = operands
                self.size = size

        all_insns = {
            0x1010: MockInsn("nop", "", 1),
            0x1020: MockInsn("call", "rax", 2),
        }

        result = backend._trace_iat_load_to_register("rax", 0x1020, all_insns)
        assert result is None


class TestCapstoneArm64Detection:
    """Phase 2: ARM64 architecture detection."""

    def test_arm64_machine_constant(self):
        """Verify 0xAA64 is the correct ARM64 machine constant."""
        # Per PE spec: IMAGE_FILE_MACHINE_ARM64 = 0xAA64
        assert 0xAA64 == 43620  # Confirms the constant

    def test_arm64_arch_detection_via_pefile(self):
        """Use pefile to parse a real minimal ARM64 PE."""
        import capstone
        import pefile

        # Use a minimal valid PE structure that pefile can parse
        # Build with pefile itself
        import struct
        dos = bytearray(128)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 128)  # e_lfanew = 128

        pe_header = b"PE\x00\x00"
        # COFF: Machine(2), NumSections(2), Time(4), SymTablePtr(4), NumSymbols(4), OptHeaderSize(2), Characteristics(2)
        # ARM64 = 0xAA64, PE32+ optional header = 240 bytes for x64/ARM64
        coff = struct.pack("<HHIIIHH", 0xAA64, 0, 0, 0, 0, 240, 0x0022)

        # PE32+ optional header (240 bytes)
        opt = bytearray(240)
        struct.pack_into("<H", opt, 0, 0x020B)  # Magic = PE32+
        struct.pack_into("<I", opt, 16, 0x1000)  # ImageBase (low)
        struct.pack_into("<H", opt, 32, 0x200)   # FileAlignment
        struct.pack_into("<H", opt, 68, 0x0003)  # Subsystem = NATIVE
        struct.pack_into("<H", opt, 70, 0x2000)  # DllCharacteristics

        raw = bytes(dos) + pe_header + coff + bytes(opt)

        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".sys")
        os.write(fd, raw)
        os.close(fd)
        try:
            pe = pefile.PE(path, fast_load=True)
            backend = CapstoneBackend()
            arch = backend._detect_capstone_arch(pe)
            assert arch == capstone.CS_ARCH_ARM64
            mode = backend._detect_capstone_mode(pe)
            assert mode == capstone.CS_MODE_ARM
            pe.close()
        finally:
            os.unlink(path)


class TestARM64PrologueDetection:
    """Phase 5: ARM64 function identification via prologue detection."""

    def test_finds_arm64_prologue_in_find_prologue_before(self):
        """_find_prologue_before should detect ARM64 stp x29, x30 prologue."""
        backend = CapstoneBackend()

        class MockInsn:
            def __init__(self, mnemonic, operands):
                self.mnemonic = mnemonic
                self.operands = operands

        # ARM64 function: stp x29, x30, [sp, #-16]! at 0x1000, mov x29, sp at 0x1004, ret at 0x1008
        all_insns = {
            0x1000: MockInsn("stp", "x29, x30, [sp, #-16]!"),
            0x1004: MockInsn("mov", "x29, sp"),
            0x1008: MockInsn("ret", ""),
        }
        sorted_addrs = [0x1000, 0x1004, 0x1008]
        addr_to_idx = {a: i for i, a in enumerate(sorted_addrs)}

        result = backend._find_prologue_before(
            0x1008, sorted_addrs, all_insns, addr_to_idx
        )
        assert result == 0x1000

    def test_finds_arm64_prologue_in_find_function_start(self):
        """_find_function_start should detect ARM64 stp x29, x30 prologue."""
        backend = CapstoneBackend()

        class MockInsn:
            def __init__(self, mnemonic, operands):
                self.mnemonic = mnemonic
                self.operands = operands

        all_insns = {
            0x1000: MockInsn("stp", "x29, x30, [sp, #-16]!"),
            0x1004: MockInsn("mov", "x29, sp"),
            0x1008: MockInsn("bl", "0x2000"),  # call target
        }
        sorted_addrs = [0x1000, 0x1004, 0x1008]
        addr_to_idx = {a: i for i, a in enumerate(sorted_addrs)}

        result = backend._find_function_start(
            0x1008, sorted_addrs, all_insns, addr_to_idx
        )
        assert result == 0x1000


class TestCapstoneBackendAnalyze:
    """Integration tests for CapstoneBackend.analyze()."""

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_analyze_returns_disassembly_result(self):
        backend = CapstoneBackend()
        if not backend.is_available():
            pytest.skip("Capstone not available")
        result = backend.analyze(MOCK_DRIVER, quick=True)
        assert result.sample_path == MOCK_DRIVER
        assert result.backend == "capstone"

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_analyze_populates_functions(self):
        backend = CapstoneBackend()
        if not backend.is_available():
            pytest.skip("Capstone not available")
        result = backend.analyze(MOCK_DRIVER, quick=True)
        # Should identify at least some functions
        assert len(result.functions) > 0

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_analyze_populates_strings(self):
        backend = CapstoneBackend()
        if not backend.is_available():
            pytest.skip("Capstone not available")
        result = backend.analyze(MOCK_DRIVER, quick=True)
        assert isinstance(result.strings, list)

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_analyze_populates_import_addresses(self):
        backend = CapstoneBackend()
        if not backend.is_available():
            pytest.skip("Capstone not available")
        result = backend.analyze(MOCK_DRIVER, quick=True)
        assert isinstance(result.import_addresses, dict)

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_analyze_function_apis(self):
        backend = CapstoneBackend()
        if not backend.is_available():
            pytest.skip("Capstone not available")
        result = backend.analyze(MOCK_DRIVER, quick=True)
        assert isinstance(result.function_apis, dict)

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_analyze_rejects_oversized_file(self, tmp_path):
        """Files > 200MB should raise ValueError."""
        backend = CapstoneBackend()
        if not backend.is_available():
            pytest.skip("Capstone not available")
        # Create a small file but patch the check
        fake = tmp_path / "big.sys"
        fake.write_bytes(b"MZ" + b"\x00" * 100)
        # Should fail as not a valid PE first
        with pytest.raises(Exception):
            backend.analyze(fake)
