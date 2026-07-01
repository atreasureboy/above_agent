"""Tests for api_resolver: dynamic import resolution, string tracing, behavioral inference."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.disassembly.api_resolver import (
    _op_str,
    _trace_string_argument,
    _trace_register_source,
    _find_indirect_call_after,
    _find_pushed_string_near,
    _count_stdcall_params,
    _match_api_by_params,
    _infer_api_from_behavior,
    _extract_unicode_string,
    _extract_api_names_from_data_sections,
    _looks_like_kernel_api,
    scan_for_dynamic_imports,
    _find_function_containing,
    _try_decrypt_api_strings,
)
from src.models import APICallInfo, DisassemblyResult, Function, Instruction


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_insn(address: int, mnemonic: str, operands: str, size: int = 4) -> Instruction:
    return Instruction(
        address=address, mnemonic=mnemonic, operands=operands, size=size,
    )


def _make_ir(functions=None, function_apis=None, import_addresses=None,
             dynamic_imports=None) -> DisassemblyResult:
    ir = DisassemblyResult(
        sample_path=Path("dummy.sys"),
        backend="capstone",
    )
    if functions:
        ir.functions = functions
    if function_apis:
        ir.function_apis = function_apis
    if import_addresses:
        ir.import_addresses = import_addresses
    if dynamic_imports is not None:
        ir.dynamic_imports = dynamic_imports
    return ir


# ------------------------------------------------------------------
# Test _op_str
# ------------------------------------------------------------------

class TestOpStr:
    def test_instruction_object(self):
        insn = _make_insn(0x100, "mov", "eax, ebx")
        assert _op_str(insn) == "eax, ebx"

    def test_capstone_like_object(self):
        class FakeCapstoneInsn:
            op_str = "rcx, [rip+0x1234]"
        assert _op_str(FakeCapstoneInsn()) == "rcx, [rip+0x1234]"

    def test_missing_both(self):
        class NoOpStr:
            pass
        assert _op_str(NoOpStr()) == ""


# ------------------------------------------------------------------
# Test _looks_like_kernel_api
# ------------------------------------------------------------------

class TestLooksLikeKernelApi:
    @pytest.mark.parametrize("name", [
        "MmMapIoSpaceEx", "KeReadMsr", "ZwTerminateProcess",
        "NtMapViewOfSection", "ExAllocatePoolWithTag",
        "PsSetLoadImageNotifyRoutine", "IoCreateDevice",
        "SeSinglePrivilegeCheck", "ObReferenceObjectByHandle",
        "RtlInitUnicodeString", "HalTranslateBusAddress",
    ])
    def test_valid_api(self, name):
        assert _looks_like_kernel_api(name) is True

    @pytest.mark.parametrize("name", [
        "memset", "memcpy", "strcpy", "printf",
        "sub_1000", "FUN_1234", "random_string",
        "", "a", "MmGetSystemRoutineAddress",  # This one IS a kernel API but not in the patterns we check for dynamic resolution
    ])
    def test_not_dynamic_api(self, name):
        # Some of these ARE kernel APIs but the pattern check is for
        # *dynamically resolved* ones; MmGetSystemRoutineAddress itself
        # is the resolver, not the resolved.
        result = _looks_like_kernel_api(name)
        if name == "MmGetSystemRoutineAddress":
            assert result is True  # It matches the Mm pattern
        else:
            assert result is False


# ------------------------------------------------------------------
# Test _trace_string_argument — x64 patterns
# ------------------------------------------------------------------

class TestTraceStringArgumentX64:
    def test_lea_rcx_rip_relative(self):
        insns = {
            0x100: _make_insn(0x100, "lea", "rcx, [rip+0x500]", 7),
            0x110: _make_insn(0x110, "call", "qword ptr [rip+0x100]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        result = _trace_string_argument(0x110, insns[0x110], insns, sorted_addrs)
        # target = 0x100 + 7 + 0x500 = 0x607
        assert result == 0x607

    def test_mov_rcx_immediate(self):
        insns = {
            0x200: _make_insn(0x200, "mov", "rcx, 0x140001000", 10),
            0x210: _make_insn(0x210, "call", "qword ptr [rip+0x100]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        result = _trace_string_argument(0x210, insns[0x210], insns, sorted_addrs)
        assert result == 0x140001000

    def test_rcx_overwritten_stops(self):
        insns = {
            0x300: _make_insn(0x300, "mov", "rcx, 0x12345678", 10),
            0x310: _make_insn(0x310, "mov", "rcx, rdx", 3),
            0x320: _make_insn(0x320, "call", "qword ptr [rip+0x100]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        result = _trace_string_argument(0x320, insns[0x320], insns, sorted_addrs)
        # rcx overwritten at 0x310 with rdx, not a valid string source
        assert result is None

    def test_too_far_back(self):
        insns = {
            0x100: _make_insn(0x100, "mov", "rcx, 0xDEADBEEF", 10),
            0x400: _make_insn(0x400, "call", "qword ptr [rip+0x100]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        result = _trace_string_argument(0x400, insns[0x400], insns, sorted_addrs)
        # 0x400 - 0x100 = 0x300 > 0x200
        assert result is None


# ------------------------------------------------------------------
# Test _trace_string_argument — x86 patterns
# ------------------------------------------------------------------

class TestTraceStringArgumentX86:
    def test_push_immediate(self):
        insns = {
            0x100: _make_insn(0x100, "push", "0x14A32", 5),
            0x110: _make_insn(0x110, "call", "dword ptr [0x2fee8]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        result = _trace_string_argument(0x110, insns[0x110], insns, sorted_addrs)
        assert result == 0x14A32

    def test_no_push_near_call(self):
        insns = {
            0x100: _make_insn(0x100, "mov", "eax, 0x1234", 5),
            0x110: _make_insn(0x110, "call", "dword ptr [0x2fee8]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        result = _trace_string_argument(0x110, insns[0x110], insns, sorted_addrs)
        assert result is None


# ------------------------------------------------------------------
# Test _find_indirect_call_after
# ------------------------------------------------------------------

class TestFindIndirectCallAfter:
    def test_call_rax(self):
        insns = {
            0x100: _make_insn(0x100, "call", "dword ptr [rip+0x100]", 6),
            0x110: _make_insn(0x110, "test", "eax, eax", 2),
            0x120: _make_insn(0x120, "call", "rax", 2),
        }
        sorted_addrs = sorted(insns.keys())
        result = _find_indirect_call_after(0x100, insns, sorted_addrs)
        assert result == 0x120

    def test_call_eax(self):
        insns = {
            0x200: _make_insn(0x200, "call", "dword ptr [0x2fee8]", 6),
            0x210: _make_insn(0x210, "test", "eax, eax", 2),
            0x220: _make_insn(0x220, "call", "eax", 2),
        }
        sorted_addrs = sorted(insns.keys())
        result = _find_indirect_call_after(0x200, insns, sorted_addrs)
        assert result == 0x220

    def test_mov_then_call(self):
        insns = {
            0x300: _make_insn(0x300, "call", "dword ptr [0x2fee8]", 6),
            0x310: _make_insn(0x310, "mov", "rcx, rax", 3),
            0x320: _make_insn(0x320, "call", "rcx", 2),
        }
        sorted_addrs = sorted(insns.keys())
        result = _find_indirect_call_after(0x300, insns, sorted_addrs)
        assert result == 0x320

    def test_rax_clobbered(self):
        insns = {
            0x400: _make_insn(0x400, "call", "dword ptr [0x2fee8]", 6),
            0x410: _make_insn(0x410, "mov", "eax, ebx", 3),
            0x420: _make_insn(0x420, "call", "eax", 2),
        }
        sorted_addrs = sorted(insns.keys())
        result = _find_indirect_call_after(0x400, insns, sorted_addrs)
        # eax clobbered by mov eax, ebx before any call rax
        assert result is None

    def test_too_far(self):
        insns = {
            0x100: _make_insn(0x100, "call", "dword ptr [0x2fee8]", 6),
            0x500: _make_insn(0x500, "call", "rax", 2),
        }
        sorted_addrs = sorted(insns.keys())
        result = _find_indirect_call_after(0x100, insns, sorted_addrs)
        assert result is None


# ------------------------------------------------------------------
# Test _count_stdcall_params
# ------------------------------------------------------------------

class TestCountStdcallParams:
    def test_two_params(self):
        insns = {
            0x100: _make_insn(0x100, "push", "eax", 1),
            0x110: _make_insn(0x110, "push", "ebx", 1),
            0x120: _make_insn(0x120, "call", "eax", 2),
        }
        sorted_addrs = sorted(insns.keys())
        result = _count_stdcall_params(0x120, insns, sorted_addrs)
        assert result == 2

    def test_stops_at_another_call(self):
        insns = {
            0x100: _make_insn(0x100, "push", "eax", 1),
            0x110: _make_insn(0x110, "push", "ebx", 1),
            0x115: _make_insn(0x115, "call", "some_func", 5),
            0x120: _make_insn(0x120, "push", "ecx", 1),
            0x130: _make_insn(0x130, "call", "eax", 2),
        }
        sorted_addrs = sorted(insns.keys())
        result = _count_stdcall_params(0x130, insns, sorted_addrs)
        # Stops at call some_func, so only counts push ecx
        assert result == 1

    def test_zero_params(self):
        insns = {
            0x100: _make_insn(0x100, "xor", "eax, eax", 2),
            0x110: _make_insn(0x110, "ret", "", 1),
        }
        sorted_addrs = sorted(insns.keys())
        result = _count_stdcall_params(0x110, insns, sorted_addrs)
        assert result == 0


# ------------------------------------------------------------------
# Test _match_api_by_params
# ------------------------------------------------------------------

class TestMatchApiByParams:
    def test_2_params(self):
        data_map = {0x1000: "ObGetObjectType", 0x2000: "RtlInitUnicodeString"}
        result = _match_api_by_params(2, data_map)
        assert "RtlInitUnicodeString" in result

    def test_no_match(self):
        data_map = {0x1000: "SomeUnknownApi"}
        result = _match_api_by_params(2, data_map)
        assert result == []

    def test_unknown_param_count(self):
        data_map = {0x1000: "SomeApi"}
        result = _match_api_by_params(10, data_map)
        assert result == []


# ------------------------------------------------------------------
# Test _find_pushed_string_near
# ------------------------------------------------------------------

class TestFindPushedStringNear:
    def test_match_by_near_rva(self):
        insns = {
            0x100: _make_insn(0x100, "push", "0x1500", 5),
            0x110: _make_insn(0x110, "call", "dword ptr [0x2fee8]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        data_map = {0x1000: "MmMapIoSpace"}
        # push 0x1500, image_base=0, pushed_rva=0x1500, near 0x1000 (within 0x20)? No
        result = _find_pushed_string_near(0x110, insns, sorted_addrs, data_map, 0x0)
        assert result is None

        # Try with pushed value near data_map key
        insns2 = {
            0x100: _make_insn(0x100, "push", "0x1010", 5),
            0x110: _make_insn(0x110, "call", "dword ptr [0x2fee8]", 6),
        }
        sorted_addrs2 = sorted(insns2.keys())
        result = _find_pushed_string_near(0x110, insns2, sorted_addrs2, data_map, 0x0)
        assert result == "MmMapIoSpace"

    def test_no_push_no_match(self):
        insns = {
            0x100: _make_insn(0x100, "mov", "eax, 0x1234", 5),
            0x110: _make_insn(0x110, "call", "dword ptr [0x2fee8]", 6),
        }
        sorted_addrs = sorted(insns.keys())
        data_map = {0x1000: "MmMapIoSpace"}
        result = _find_pushed_string_near(0x110, insns, sorted_addrs, data_map, 0x0)
        assert result is None


# ------------------------------------------------------------------
# Test _infer_api_from_behavior
# ------------------------------------------------------------------

class TestInferApiFromBehavior:
    def test_single_missing_api(self):
        functions = {
            0x1000: Function(name="sub_1000", address=0x1000, size=0x100),
        }
        function_apis = {0x1000: ["MmGetSystemRoutineAddress"]}
        data_map = {0x2000: "ObGetObjectType"}

        insns = {0x1050: _make_insn(0x1050, "call", "dword ptr [0x2fee8]", 6)}
        sorted_addrs = sorted(insns.keys())

        ir = _make_ir(
            functions=functions,
            function_apis=function_apis,
            import_addresses={"0x2fee8": "ntoskrnl.MmGetSystemRoutineAddress"},
        )
        result = _infer_api_from_behavior(
            0x1050, insns, sorted_addrs, ir, data_map, 0x0,
        )
        # Only one missing API from data_map not in function_apis
        assert result == "ObGetObjectType"

    def test_multiple_missing_uses_param_count(self):
        functions = {
            0x1000: Function(name="sub_1000", address=0x1000, size=0x200),
        }
        function_apis = {0x1000: ["MmGetSystemRoutineAddress"]}
        data_map = {
            0x2000: "ObGetObjectType",
            0x2100: "RtlInitUnicodeString",
        }

        insns = {
            0x1050: _make_insn(0x1050, "call", "dword ptr [0x2fee8]", 6),
            0x1060: _make_insn(0x1060, "mov", "dword ptr [0x34c9c], eax", 6),
            0x1070: _make_insn(0x1070, "push", "eax", 1),
            0x1080: _make_insn(0x1080, "push", "ebx", 1),
            0x1090: _make_insn(0x1090, "call", "dword ptr [0x34c9c]", 6),
        }
        sorted_addrs = sorted(insns.keys())

        ir = _make_ir(
            functions=functions,
            function_apis=function_apis,
            import_addresses={"0x2fee8": "ntoskrnl.MmGetSystemRoutineAddress"},
        )
        result = _infer_api_from_behavior(
            0x1050, insns, sorted_addrs, ir, data_map, 0x0,
        )
        # 2 params pushed, should try to match
        assert result is not None


# ------------------------------------------------------------------
# Test _extract_unicode_string — noise filtering
# ------------------------------------------------------------------

class TestExtractUnicodeStringNoise:
    def test_garbage_returns_none(self):
        # Simulate extracting "NP ,.PR\"$" — not a valid API name
        api_name = "NP ,.PR\"$"
        string_bytes = api_name.encode("utf-16le") + b"\x00\x00"
        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = string_bytes

        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER.ImageBase = 0x140000000
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            string_va = 0x140001000
            result = _extract_unicode_string(string_va, {}, 0x140000000, pe_path)
            assert result is None

    def test_valid_api_name(self):
        api_name = "MmMapIoSpaceEx"
        string_bytes = api_name.encode("utf-16le") + b"\x00\x00"
        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = string_bytes

        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER.ImageBase = 0x140000000
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            string_va = 0x140001000
            result = _extract_unicode_string(string_va, {}, 0x140000000, pe_path)
            assert result == api_name

    def test_api_with_digits(self):
        api_name = "MmMapIoSpaceEx2"
        string_bytes = api_name.encode("utf-16le") + b"\x00\x00"
        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = string_bytes

        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER.ImageBase = 0x140000000
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            string_va = 0x140001000
            result = _extract_unicode_string(string_va, {}, 0x140000000, pe_path)
            assert result == api_name

    def test_lowercase_rejected(self):
        api_name = "mmmapiospace"
        string_bytes = api_name.encode("utf-16le") + b"\x00\x00"
        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = string_bytes

        mock_pe = MagicMock()
        mock_pe.OPTIONAL_HEADER.ImageBase = 0x140000000
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            string_va = 0x140001000
            result = _extract_unicode_string(string_va, {}, 0x140000000, pe_path)
            assert result is None


# ------------------------------------------------------------------
# Test scan_for_dynamic_imports — end-to-end
# ------------------------------------------------------------------

class TestScanForDynamicImports:
    def test_no_mmgetsystem_import(self):
        ir = _make_ir(import_addresses={"0x100": "ntoskrnl.SomeOtherApi"})
        insns = {}
        scan_for_dynamic_imports(ir, insns, 0x140000000, Path("nonexistent.sys"))
        assert ir.dynamic_imports == {}

    def test_no_mmgetsystem_call(self):
        ir = _make_ir(
            import_addresses={"0x100": "ntoskrnl.MmGetSystemRoutineAddress"},
        )
        insns = {0x1000: _make_insn(0x1000, "call", "0x2000", 5)}
        # No api_target set
        scan_for_dynamic_imports(ir, insns, 0x140000000, Path("nonexistent.sys"))
        assert ir.dynamic_imports == {}


# ------------------------------------------------------------------
# Test _try_decrypt_api_strings — XOR decryption
# ------------------------------------------------------------------

class TestTryDecryptApiStrings:
    def test_single_byte_xor_decrypts_api_name(self):
        """XOR key 0x55 on 'MmMapIoSpace' should be detected."""
        api_name = b"MmMapIoSpace"
        key = 0x55
        encrypted = bytes(b ^ key for b in api_name) + b"\x00"

        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = encrypted

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            result = _try_decrypt_api_strings(pe_path, _make_ir(), {})
            # Should find the decrypted API name
            assert any("MmMapIoSpace" in v for v in result.values())

    def test_single_byte_xor_multiple_apis(self):
        """Multiple XOR-encrypted API names in same section."""
        key = 0xAA
        apis = [b"KeReadMsr", b"IoCreateDevice"]
        encrypted = b""
        for api in apis:
            encrypted += bytes(b ^ key for b in api) + b"\x00"

        mock_section = MagicMock()
        mock_section.Name = b".data\x00\x00\x00\x00"
        mock_section.VirtualAddress = 0x2000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = encrypted

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            result = _try_decrypt_api_strings(pe_path, _make_ir(), {})
            assert len(result) >= 2
            names = set(result.values())
            assert "KeReadMsr" in names
            assert "IoCreateDevice" in names

    def test_existing_map_not_overwritten(self):
        """Already-decrypted entries should not be overwritten."""
        api_name = b"ZwTerminateProcess"
        key = 0x33
        encrypted = bytes(b ^ key for b in api_name) + b"\x00"

        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = encrypted

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        existing = {0x1000: "ZwTerminateProcess"}  # Already known
        with patch("pefile.PE", return_value=mock_pe):
            result = _try_decrypt_api_strings(pe_path, _make_ir(), existing)
            # Should not re-decrypt since it's in existing_map
            assert 0x1000 not in result

    def test_no_decryption_for_non_api_strings(self):
        """Non-API strings should not appear in results."""
        # XOR "HelloWorld" — not a kernel API name
        key = 0x77
        text = b"HelloWorld"
        encrypted = bytes(b ^ key for b in text) + b"\x00"

        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = encrypted

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            result = _try_decrypt_api_strings(pe_path, _make_ir(), {})
            assert result == {}

    def test_pe_path_not_exists_returns_empty(self):
        """Non-existent PE path should return empty dict."""
        result = _try_decrypt_api_strings(
            Path("nonexistent_file.sys"), _make_ir(), {}
        )
        assert result == {}

    def test_two_byte_xor_known_prefix(self):
        """2-byte XOR with known prefix attack for 'MmMapIoSpaceEx'."""
        api_name = b"MmMapIoSpaceEx"
        key = bytes([0x42, 0x7F])
        encrypted = bytes(api_name[i] ^ key[i % 2] for i in range(len(api_name))) + b"\x00"

        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x3000
        mock_section.Misc_VirtualSize = 0x1000
        mock_section.get_data.return_value = encrypted

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        pe_path = Path(__file__)
        with patch("pefile.PE", return_value=mock_pe):
            result = _try_decrypt_api_strings(pe_path, _make_ir(), {})
            assert any("MmMapIoSpaceEx" in v for v in result.values())
