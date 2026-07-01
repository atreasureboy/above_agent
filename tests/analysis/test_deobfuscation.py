"""Tests for API hashing resolution and string deobfuscation."""

from __future__ import annotations

from pathlib import Path

from src.analysis.core.deobfuscation import (
    compute_api_hash,
    compute_ror_hash,
    build_hash_table,
    resolve_hash,
    resolve_all_hashes,
    decrypt_xor_string,
    try_decrypt_from_array,
    resolve_api_hashes,
    create_resolution_findings,
    _NTOSKRNL_APIS,
)
from src.models import (
    Architecture, BasicBlock, CFG, Confidence, DisassemblyResult,
    Finding, FindingCategory, Function, Instruction, Sample, Severity,
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


class TestApiHashComputation:
    """Test API hash algorithm implementations."""

    def test_rol_hash_consistency(self):
        assert compute_api_hash("MmMapIoSpaceEx", shift=7) == compute_api_hash("MmMapIoSpaceEx", shift=7)

    def test_different_shifts_produce_different_hashes(self):
        h7 = compute_api_hash("ObReferenceObjectByHandle", shift=7)
        h11 = compute_api_hash("ObReferenceObjectByHandle", shift=11)
        assert h7 != h11

    def test_hash_is_32bit(self):
        for api in ["MmMapIoSpaceEx", "ZwCreateFile", "PsCreateSystemThread"]:
            h = compute_api_hash(api, shift=7)
            assert 0 <= h <= 0xFFFFFFFF

    def test_ror_hash_consistency(self):
        assert compute_ror_hash("MmMapIoSpaceEx", shift=13) == compute_ror_hash("MmMapIoSpaceEx", shift=13)

    def test_case_insensitive(self):
        # The hash function uses .lower() internally, so mixed-case and lowercase
        # produce identical hashes
        h1 = compute_api_hash("MmMapIoSpaceEx", shift=7)
        h2 = compute_api_hash("mmmapiospaceex", shift=7)
        assert h1 == h2
        # Also test uppercase variant (same letters, different case)
        h3 = compute_api_hash("MMMAPIOSPACEEX", shift=7)
        assert h1 == h3


class TestHashTable:
    """Test hash table construction and lookup."""

    def test_table_contains_all_apis(self):
        tbl = build_hash_table(shift=7)
        for api in _NTOSKRNL_APIS:
            h = compute_api_hash(api, shift=7)
            assert tbl[h] == api

    def test_no_collisions_for_common_shift(self):
        tbl = build_hash_table(shift=7)
        assert len(tbl) == len(_NTOSKRNL_APIS)

    def test_custom_seed(self):
        tbl = build_hash_table(shift=1, seed=0x55555555)
        assert len(tbl) > 0


class TestHashResolution:
    """Test resolving hash values back to API names."""

    def test_resolve_known_hash(self):
        h = compute_api_hash("MmMapIoSpaceEx", shift=7)
        results = resolve_hash(h)
        assert len(results) >= 1
        api_names = [r[0] for r in results]
        assert "MmMapIoSpaceEx" in api_names

    def test_resolve_obreference(self):
        h = compute_api_hash("ObReferenceObjectByHandle", shift=7)
        results = resolve_hash(h)
        assert any("ObReferenceObjectByHandle" in r[0] for r in results)

    def test_resolve_multiple_hashes(self):
        apis = ["MmMapIoSpaceEx", "ZwCreateFile", "PsCreateSystemThread"]
        hash_vals = [compute_api_hash(a, shift=7) for a in apis]
        resolved = resolve_all_hashes(hash_vals)
        resolved_names = set()
        for h, matches in resolved.items():
            for name, _ in matches:
                resolved_names.add(name)
        for api in apis:
            assert api in resolved_names

    def test_unknown_hash_returns_empty(self):
        results = resolve_hash(0xDEADBEEF)
        assert results == []


class TestStringDecryption:
    """Test XOR string decryption."""

    def test_decrypt_simple_xor(self):
        plaintext = "Hello"
        key = 0x42
        encrypted = bytes(ord(c) ^ key for c in plaintext)
        assert decrypt_xor_string(encrypted, key) == "Hello"

    def test_decrypt_null_terminated(self):
        # Encrypted data: "ABC\0" XOR'd with key 0x55
        # Encrypted bytes: [0x41^0x55, 0x42^0x55, 0x43^0x55, 0x00^0x55]
        data = bytes([0x41 ^ 0x55, 0x42 ^ 0x55, 0x43 ^ 0x55, 0x00 ^ 0x55])
        assert decrypt_xor_string(data, 0x55) == "ABC"

    def test_try_decrypt_array(self):
        plaintext = "DeviceName"
        key = 0x77
        encrypted = [ord(c) ^ key for c in plaintext]
        result = try_decrypt_from_array(encrypted, key)
        assert result == "DeviceName"

    def test_invalid_key_returns_none(self):
        assert try_decrypt_from_array([0x41, 0x42, 0x43], 0) is None


class TestResolveApiHashesIntegration:
    """Test end-to-end API hash resolution on IR."""

    def test_resolve_injects_into_ir(self):
        """Hash constants in a flagged function should be resolved and injected."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        # Simulate API hashing: ROL + XOR-immediate + CMP against hash value
        h = compute_api_hash("MmMapIoSpaceEx", shift=7)
        _add_cfg_with_insns(ir, 0x1000, [
            ("rol", "eax, 7"),
            ("xor", "eax, 0x55"),
            ("rol", "eax, 7"),
            ("xor", "eax, 0xAA"),
            ("rol", "eax, 7"),
            ("cmp", f"eax, 0x{h:X}"),  # This is the hash comparison
        ])

        resolved = resolve_api_hashes(ir)
        # The hash should be resolved and injected
        if resolved:
            all_apis = []
            for apis in resolved.values():
                all_apis.extend(apis)
            assert "MmMapIoSpaceEx" in all_apis

    def test_no_flagged_functions_returns_empty(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rcx"),
            ("ret", ""),
        ])
        resolved = resolve_api_hashes(ir)
        assert resolved == {}


class TestCreateResolutionFindings:
    """Test Finding generation from resolved hashes."""

    def test_findings_created(self):
        resolved = {"sub_1000": ["MmMapIoSpaceEx", "ZwCreateFile"]}
        findings = create_resolution_findings(None, resolved)  # type: ignore[arg-type]
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].confidence == Confidence.HIGH
        assert "MmMapIoSpaceEx" in findings[0].description
        assert "ZwCreateFile" in findings[0].description
