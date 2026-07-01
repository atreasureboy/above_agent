"""Tests for api_hash_bruteforce.py."""

import pytest

from src.analysis.core.api_hash_bruteforce import (
    hash_crc32, hash_djb2, hash_fnv1a, hash_elf, hash_jenkins,
    hash_ror13, hash_ror7, hash_murmur3_finalize,
    hash_fnv1a_64, hash_crc64,
    _crc32_custom,
    resolve_extended_hash, resolve_64bit_hash,
    build_extended_hash_tables, build_64bit_hash_tables,
    _ALL_APIS, ALGO_REGISTRY, ALGO_REGISTRY_64,
)
from src.models import DisassemblyResult, FindingCategory, Instruction


class TestHashAlgorithms:
    def test_crc32_produces_32bit(self):
        h = hash_crc32("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_djb2_produces_32bit(self):
        h = hash_djb2("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_djb2_deterministic(self):
        h1 = hash_djb2("ZwCreateFile")
        h2 = hash_djb2("ZwCreateFile")
        assert h1 == h2

    def test_fnv1a_produces_32bit(self):
        h = hash_fnv1a("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_elf_produces_32bit(self):
        h = hash_elf("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_jenkins_produces_32bit(self):
        h = hash_jenkins("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_different_apis_different_hashes(self):
        h1 = hash_djb2("ZwCreateFile")
        h2 = hash_djb2("ZwClose")
        assert h1 != h2

    def test_case_insensitive(self):
        h1 = hash_djb2("ZwCreateFile")
        h2 = hash_djb2("zwcreatefile")
        assert h1 == h2


class TestExtendedHashTables:
    def test_build_tables_returns_results(self):
        tables = build_extended_hash_tables(["ZwCreateFile", "ZwClose"])
        assert len(tables) > 0

    def test_resolve_known_hash(self):
        # Compute a known djb2 hash and verify resolution
        target = "ZwCreateFile"
        h = hash_djb2(target)
        results = resolve_extended_hash(h)
        # Should find at least one match
        api_names = [r[0] for r in results]
        assert target in api_names


class TestResolveExtendedHash:
    def test_no_match_for_random_value(self):
        results = resolve_extended_hash(0xDEADBEEF)
        # Very unlikely to match any API
        assert len(results) == 0

    def test_match_for_crc32_hash(self):
        target = "ZwClose"
        h = _crc32_custom(target)
        results = resolve_extended_hash(h)
        api_names = [r[0] for r in results]
        assert target in api_names

    def test_returns_algo_info(self):
        target = "IoCreateDevice"
        h = hash_fnv1a(target)
        results = resolve_extended_hash(h)
        if results:
            # Each result should have (api_name, algo_name, config)
            for api_name, algo_name, cfg in results:
                assert isinstance(algo_name, str)
                assert isinstance(cfg, dict)


# ------------------------------------------------------------------
# Wave 2: New hash algorithms
# ------------------------------------------------------------------

class TestROR13:
    def test_produces_32bit(self):
        h = hash_ror13("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_deterministic(self):
        h1 = hash_ror13("ZwCreateFile")
        h2 = hash_ror13("ZwCreateFile")
        assert h1 == h2

    def test_case_insensitive(self):
        h1 = hash_ror13("ZwCreateFile")
        h2 = hash_ror13("zwcreatefile")
        assert h1 == h2

    def test_different_apis(self):
        h1 = hash_ror13("ZwCreateFile")
        h2 = hash_ror13("ZwClose")
        assert h1 != h2

    def test_seed_variants(self):
        h0 = hash_ror13("ZwCreateFile", seed=0)
        h1 = hash_ror13("ZwCreateFile", seed=0xDEADBEEF)
        assert h0 != h1


class TestROR7:
    def test_produces_32bit(self):
        h = hash_ror7("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_deterministic(self):
        h1 = hash_ror7("ZwCreateFile")
        h2 = hash_ror7("ZwCreateFile")
        assert h1 == h2

    def test_case_insensitive(self):
        h1 = hash_ror7("ZwCreateFile")
        h2 = hash_ror7("zwcreatefile")
        assert h1 == h2

    def test_different_apis(self):
        h1 = hash_ror7("ZwCreateFile")
        h2 = hash_ror7("ZwClose")
        assert h1 != h2


class TestMurmurHash3:
    def test_produces_32bit(self):
        h = hash_murmur3_finalize("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFF

    def test_deterministic(self):
        h1 = hash_murmur3_finalize("ZwCreateFile")
        h2 = hash_murmur3_finalize("ZwCreateFile")
        assert h1 == h2

    def test_seed_variants(self):
        h0 = hash_murmur3_finalize("ZwCreateFile", seed=0)
        h1 = hash_murmur3_finalize("ZwCreateFile", seed=0x9747B28C)
        assert h0 != h1

    def test_different_apis(self):
        h1 = hash_murmur3_finalize("ZwCreateFile")
        h2 = hash_murmur3_finalize("ZwClose")
        assert h1 != h2

    def test_known_empty_string(self):
        """Empty string should produce consistent hash."""
        h1 = hash_murmur3_finalize("", seed=0)
        h2 = hash_murmur3_finalize("", seed=0)
        assert h1 == h2


class TestFNV1a64:
    def test_produces_64bit(self):
        h = hash_fnv1a_64("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_deterministic(self):
        h1 = hash_fnv1a_64("ZwCreateFile")
        h2 = hash_fnv1a_64("ZwCreateFile")
        assert h1 == h2

    def test_case_insensitive(self):
        h1 = hash_fnv1a_64("ZwCreateFile")
        h2 = hash_fnv1a_64("zwcreatefile")
        assert h1 == h2

    def test_different_apis(self):
        h1 = hash_fnv1a_64("ZwCreateFile")
        h2 = hash_fnv1a_64("ZwClose")
        assert h1 != h2

    def test_default_seed(self):
        """Should use FNV-1a 64-bit offset basis."""
        h = hash_fnv1a_64("ZwCreateFile", seed=0xF5E447683B0DC113)
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF


class TestCRC64:
    def test_produces_64bit(self):
        h = hash_crc64("ZwCreateFile")
        assert 0 <= h <= 0xFFFFFFFFFFFFFFFF

    def test_deterministic(self):
        h1 = hash_crc64("ZwCreateFile")
        h2 = hash_crc64("ZwCreateFile")
        assert h1 == h2

    def test_case_insensitive(self):
        h1 = hash_crc64("ZwCreateFile")
        h2 = hash_crc64("zwcreatefile")
        assert h1 == h2

    def test_different_apis(self):
        h1 = hash_crc64("ZwCreateFile")
        h2 = hash_crc64("ZwClose")
        assert h1 != h2

    def test_empty_string(self):
        """Empty string CRC64 should be ~0 XOR'd = 0."""
        h = hash_crc64("")
        assert h == 0  # Initial crc=0xFFFFFFFFFFFFFFFF, then ^ = 0


# ------------------------------------------------------------------
# Wave 2: Expanded API list
# ------------------------------------------------------------------

class TestExpandedAPIs:
    def test_api_count_150_plus(self):
        """Should have 150+ APIs."""
        assert len(_ALL_APIS) >= 150

    def test_vmx_apis_present(self):
        """VMX/EPT APIs should be in the list."""
        vmx_apis = {"__vmx_on", "__vmx_vmread", "__invept"}
        assert vmx_apis.issubset(set(_ALL_APIS))

    def test_debug_apis_present(self):
        """Debug APIs should be in the list."""
        debug_apis = {"NtQueryDebugObject", "NtSetInformationThread"}
        assert debug_apis.issubset(set(_ALL_APIS))

    def test_filter_manager_apis(self):
        """Filter Manager APIs should be in the list."""
        flt_apis = {"FltCreateFile", "FltReadFile", "FltWriteFile"}
        assert flt_apis.issubset(set(_ALL_APIS))

    def test_security_apis(self):
        """Security APIs should be in the list."""
        sec_apis = {"SeAccessCheck", "SePrivilegeCheck"}
        assert sec_apis.issubset(set(_ALL_APIS))

    def test_all_apis_hashable(self):
        """All APIs should be hashable with all algorithms."""
        for api in _ALL_APIS:
            for algo_name, hash_func, variants in ALGO_REGISTRY:
                for variant in variants:
                    h = hash_func(api, **variant)
                    assert isinstance(h, int) and 0 <= h <= 0xFFFFFFFF

    def test_64bit_algos_registered(self):
        """64-bit algorithms should be in registry."""
        assert len(ALGO_REGISTRY_64) >= 2

    def test_ror13_in_registry(self):
        """ROR13 should be in ALGO_REGISTRY."""
        algo_names = [a[0] for a in ALGO_REGISTRY]
        assert "ror13" in algo_names


# ------------------------------------------------------------------
# Wave 2: 64-bit hash resolution
# ------------------------------------------------------------------

class Test64BitResolution:
    def test_build_64bit_tables(self):
        """Should build 64-bit hash tables."""
        tables = build_64bit_hash_tables(["ZwCreateFile", "ZwClose"])
        assert len(tables) >= 2

    def test_resolve_known_64bit_hash(self):
        """Should resolve a known FNV-1a 64-bit hash."""
        target = "ZwCreateFile"
        h = hash_fnv1a_64(target)
        results = resolve_64bit_hash(h)
        api_names = [r[0] for r in results]
        assert target in api_names

    def test_resolve_crc64_hash(self):
        """Should resolve a CRC64 hash."""
        target = "ZwClose"
        h = hash_crc64(target)
        results = resolve_64bit_hash(h)
        api_names = [r[0] for r in results]
        assert target in api_names

    def test_no_match_for_random_64bit(self):
        """Random 64-bit value should not match."""
        results = resolve_64bit_hash(0xDEADBEEFCAFEBABE)
        assert len(results) == 0

    def test_64bit_resolution_direct(self):
        """resolve_64bit_hash should work directly."""
        target = "ZwCreateFile"
        h = hash_fnv1a_64(target)
        results = resolve_64bit_hash(h)
        assert len(results) >= 1
        assert results[0][0] == target  # api_name
        assert results[0][1] == "fnv1a_64"  # algo_name
