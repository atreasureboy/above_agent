"""
DriverScope — API Hashing Resolution + String Decryption.

After AntiObfuscationAnalyzer *detects* that API hashing or string encryption
exists, this module attempts to *resolve* the actual values:

1. **API Hash Resolver**: Extracts the hashed API name constants from
   the hash-resolution function, then brute-force matches against the full
   Windows kernel API list to recover the real names.

2. **String Decryptor**: Simulates XOR-decryption loops found in capstone
   instructions to recover plaintext strings from encrypted byte arrays.

These resolved values are injected back into the DisassemblyResult so that
all downstream detectors (dangerous primitives, attack chains, etc.)
can reason about the *actual* behavior instead of "sub_XXXX calls unknown".
"""

from __future__ import annotations

import ctypes
import struct
from collections import defaultdict

from src.models import DisassemblyResult, Finding, FindingCategory, Severity, Confidence, Evidence

# ---------------------------------------------------------------------------
# Known Windows kernel API list — the universe against which hashes are matched
# ---------------------------------------------------------------------------

_NTOSKRNL_APIS = [
    # Memory management
    "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
    "MmUnlockPages", "MmProbeAndLockPages", "MmCopyVirtualMemory",
    "MmGetSystemRoutineAddress", "ExAllocatePoolWithTag", "ExAllocatePool",
    "ExFreePoolWithTag", "ExFreePool",
    # Process / thread
    "PsCreateSystemThread", "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine", "PsLookupProcessByProcessId",
    "PsLookupThreadByThreadId", "PsTerminateSystemThread",
    "PsGetCurrentProcessId", "PsGetCurrentThreadId",
    "PsGetProcessImageFileName",
    # Object manager
    "ObReferenceObjectByHandle", "ObReferenceObjectByName",
    "ObDereferenceObject", "ObOpenObjectByPointer",
    "ObRegisterCallbacks", "ObUnRegisterCallbacks",
    "ObCreateObject", "ObAssignSecurity",
    # I/O manager
    "IoCreateDevice", "IoCreateSymbolicLink", "IoDeleteDevice",
    "IoDeleteSymbolicLink", "IoQueueWorkItem", "IoAllocateMdl",
    "IoFreeMdl", "IoCompleteRequest", "IoGetCurrentProcess",
    "IoCreateFile", "IoDeviceObjectFromFileObject",
    "IoGetDeviceObjectPointer", "IoGetRelatedDeviceObject",
    "IoRegisterDeviceInterface", "IoSetDeviceInterfaceState",
    # Zw/Nt system calls
    "ZwCreateFile", "ZwOpenFile", "ZwClose", "ZwReadFile", "ZwWriteFile",
    "ZwDeviceIoControlFile", "ZwLoadDriver", "ZwUnloadDriver",
    "ZwCreateKey", "ZwOpenKey", "ZwDeleteKey", "ZwSetValueKey",
    "ZwQueryValueKey", "ZwEnumerateKey", "ZwEnumerateValueKey",
    "ZwQuerySystemInformation", "ZwQueryInformationProcess",
    "ZwQueryInformationThread", "ZwSetInformationThread",
    "ZwSuspendThread", "ZwResumeThread", "ZwGetContextThread",
    "ZwSetContextThread", "ZwProtectVirtualMemory",
    "ZwCreateThread", "ZwTerminateProcess",
    "ZwMapViewOfSection", "ZwUnmapViewOfSection",
    "ZwAllocateVirtualMemory", "ZwFreeVirtualMemory",
    "ZwQueryVirtualMemory", "ZwQuerySection",
    "ZwCreateSection", "ZwOpenSection",
    "ZwDuplicateObject", "ZwQueryObject",
    "ZwCreateMutant", "ZwOpenMutant",
    "ZwCreateEvent", "ZwOpenEvent",
    "ZwWaitForSingleObject", "ZwDelayExecution",
    "ZwCreateNamedPipeFile", "ZwCreateMailslotFile",
    "ZwFsControlFile", "ZwSetInformationFile",
    "ZwQueryInformationFile",
    # ALPC
    "ZwAlpcCreatePort", "ZwAlpcConnectPort",
    "ZwAlpcSendWaitReceivePort", "ZwAlpcAcceptConnectPort",
    "NtAlpcConnectPort", "NtAlpcSendWaitReceivePort",
    # APC
    "KeInitializeApc", "KeInsertQueueApc", "KeForceInsertQueueApc",
    "KeStackAttachProcess", "KeUnstackDetachProcess",
    "KeAttachProcess", "KeDetachProcess",
    "KeSynchronizeExecution", "KeWaitForSingleObject",
    # Registry callbacks
    "CmRegisterCallbackEx", "CmUnRegisterCallback",
    # Executive
    "ExGetPreviousMode", "ExAcquireResourceExclusiveLite",
    "ExReleaseResourceLite", "ExInitializeResourceLite",
    "ExDeleteResourceLite", "ExAcquireFastMutex",
    "ExReleaseFastMutex", "ExSystemTimeToLocalTime",
    "ExInterlockedInsertTailList", "ExInterlockedRemoveHeadList",
    "InitializeListHead", "InsertHeadList", "InsertTailList",
    "RemoveEntryList",
    # String / RTL
    "RtlInitUnicodeString", "RtlInitAnsiString",
    "RtlUnicodeStringToAnsiString", "RtlCompareUnicodeString",
    "RtlCopyUnicodeString", "RtlAppendUnicodeToString",
    "RtlGetVersion", "RtlWriteRegistryValue",
    "RtlQueryRegistryValues",
    # Security
    "SeCreateClientSecurity", "SeImpersonateClientEx",
    "SeQueryInformationToken", "SeAccessCheck",
    # Misc
    "HalGetBusAddress", "HalTranslateBusAddress",
    "IoGetDmaAdapter", "KeQueryActiveProcessorCount",
    "KeQueryTimeIncrement", "KeDelayExecutionThread",
    # Named pipe
    "NtCreateNamedPipeFile",
    # WDF (for KMDF drivers)
    "WdfDriverCreate", "WdfDeviceCreate",
    "WdfIoQueueCreate", "WdfIoQueueStart",
    "WdfRequestComplete", "WdfRequestRetrieveInputBuffer",
    "WdfRequestRetrieveOutputBuffer",
    # Mini-filter
    "FltRegisterFilter", "FltStartFiltering",
    "FltUnregisterFilter", "FltCreateCommunicationPort",
    "FltCloseCommunicationPort",
]

# Common user32/gdi32/apis that kernel might reference indirectly
_USER_APIS = [
    "NtCreateNamedPipeFile", "NtAlpcConnectPort",
]


# ---------------------------------------------------------------------------
# 1. API Hash Resolver
# ---------------------------------------------------------------------------

# 360 commonly uses the ROL-32 + XOR hashing algorithm:
#   hash = 0
#   for each char in api_name:
#       hash = ROL(hash, N) ^ ord(char.lower())
#
# The shift amount N varies: 7, 11, 13, 17 are most common in 360.
# Some variants use XOR with a seed constant after the loop.

def _rol32(value: int, shift: int, bits: int = 32) -> int:
    """32-bit rotate left."""
    shift &= (bits - 1)
    return ((value << shift) | (value >> (bits - shift))) & 0xFFFFFFFF


def _ror32(value: int, shift: int, bits: int = 32) -> int:
    """32-bit rotate right."""
    shift &= (bits - 1)
    return ((value >> shift) | (value << (bits - shift))) & 0xFFFFFFFF


def compute_api_hash(api_name: str, shift: int = 7, seed: int = 0) -> int:
    """Compute the standard ROL-based API hash used by 360-style protectors."""
    h = seed
    for c in api_name.lower():
        h = _rol32(h, shift) ^ ord(c)
    return h


def compute_ror_hash(api_name: str, shift: int = 13, seed: int = 0) -> int:
    """Alternative ROR-based hash sometimes used by commercial drivers."""
    h = seed
    for c in api_name.lower():
        h = _ror32(h, shift) ^ ord(c)
    return h


def build_hash_table(shift: int = 7, seed: int = 0, apis: list[str] | None = None) -> dict[int, str]:
    """Build a hash → API name lookup table for a given algorithm variant."""
    table: dict[int, str] = {}
    target_apis = apis or _NTOSKRNL_APIS
    for api in target_apis:
        h = compute_api_hash(api, shift=shift, seed=seed)
        table[h] = api
    return table


# Pre-compute tables for the most common 360 variants
_COMMON_VARIANTS = [
    {"shift": 7, "seed": 0, "algo": "rol"},
    {"shift": 11, "seed": 0, "algo": "rol"},
    {"shift": 13, "seed": 0, "algo": "rol"},
    {"shift": 17, "seed": 0, "algo": "rol"},
    {"shift": 1, "seed": 0x55555555, "algo": "rol"},
    {"shift": 1, "seed": 0, "algo": "rol"},
    {"shift": 13, "seed": 0, "algo": "ror"},
]

HASH_TABLES: list[tuple[dict[int, str], dict]] = []
for cfg in _COMMON_VARIANTS:
    if cfg["algo"] == "rol":
        tbl = build_hash_table(cfg["shift"], cfg["seed"])
    else:
        tbl = {}
        for api in _NTOSKRNL_APIS:
            tbl[compute_ror_hash(api, cfg["shift"], cfg["seed"])] = api
    HASH_TABLES.append((tbl, cfg))


def resolve_hash(hash_value: int) -> list[tuple[str, dict]]:
    """Resolve a single hash value to possible API names.

    Returns list of (api_name, config) for all matches across all variants.
    """
    results: list[tuple[str, dict]] = []
    for tbl, cfg in HASH_TABLES:
        if hash_value in tbl:
            results.append((tbl[hash_value], cfg))
    return results


def resolve_all_hashes(known_hashes: list[int]) -> dict[int, list[tuple[str, dict]]]:
    """Resolve multiple hash values at once."""
    resolved: dict[int, list[tuple[str, dict]]] = {}
    for h in known_hashes:
        matches = resolve_hash(h)
        if matches:
            resolved[h] = matches
    return resolved


# ---------------------------------------------------------------------------
# 2. Extract hashed constants from IR (detect immediate values in hash loops)
# ---------------------------------------------------------------------------

def extract_hash_candidates(ir: DisassemblyResult) -> list[tuple[int, int]]:
    """Extract potential API hash constants from detected hash-resolution functions.

    Strategy: In the AntiObfuscationAnalyzer output, functions flagged as
    API-hashing typically contain a pattern:
      - ROL/ROR + XOR-immediate loop
      - The loop compares accumulated hash against immediate constant(s)
      - Those immediate constants ARE the pre-computed API hashes

    We extract all immediate values from functions flagged for API hashing,
    then match them against our hash tables.
    """
    from src.analysis.core.anti_obfuscation import detect_api_hashing

    flagged_funcs = detect_api_hashing(ir)
    if not flagged_funcs:
        return []

    candidates: list[tuple[int, int]] = []  # (func_addr, hash_value)

    for func_addr, metrics in flagged_funcs:
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                mnem = insn.mnemonic.lower()

                # CMP instruction with immediate — this is the hash comparison
                if mnem == "cmp":
                    import re as _re
                    m = _re.search(r"0x([0-9a-f]+)", ops)
                    if m:
                        val = int(m.group(1), 16)
                        # Filter trivially wrong values
                        if val > 0xFFFF:  # Real API hashes are 32-bit
                            candidates.append((func_addr, val))

                # Also catch MOV with large immediate (loading hash constants)
                if mnem == "mov":
                    import re as _re
                    m = _re.search(r",\s*0x([0-9a-f]{8})", ops)
                    if m:
                        val = int(m.group(1), 16)
                        if val > 0xFFFF and val < 0xFFFFFFFF:
                            candidates.append((func_addr, val))

    return candidates


# ---------------------------------------------------------------------------
# 3. String Decryptor — simulate XOR-decryption loops
# ---------------------------------------------------------------------------

def decrypt_xor_string(data: bytes, key_byte: int) -> str:
    """Decrypt a single-byte XOR-encrypted string."""
    result = bytearray()
    for b in data:
        dec = b ^ key_byte
        if dec == 0:
            break
        result.append(dec)
    try:
        return result.decode("utf-8", errors="replace")
    except Exception:
        return result.decode("ascii", errors="replace")


def try_decrypt_from_array(data_bytes: list[int], key: int) -> str | None:
    """Try to decrypt a byte array with a single-byte XOR key.

    Returns plaintext if result looks like a valid ASCII/UTF-8 string.
    """
    if not data_bytes or key == 0:
        return None
    result = bytearray()
    for b in data_bytes:
        dec = b ^ key
        if dec == 0:
            break
        result.append(dec)
    # Heuristic: result should be mostly printable ASCII
    printable = sum(1 for c in result if 32 <= c < 127)
    if len(result) >= 3 and printable / max(len(result), 1) > 0.7:
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# 4. Integration: resolve and inject back into IR
# ---------------------------------------------------------------------------

def resolve_api_hashes(ir: DisassemblyResult) -> dict[str, list[str]]:
    """Main entry point: resolve all hashed API names and inject into IR.

    Returns dict mapping func_addr_str → [resolved_api_names].
    Also mutates ir.function_apis and ir.function_api_details.
    """
    candidates = extract_hash_candidates(ir)
    if not candidates:
        return {}

    # Deduplicate hash values
    unique_hashes = list(set(h for _, h in candidates))
    resolved = resolve_all_hashes(unique_hashes)

    results: dict[str, list[str]] = defaultdict(list)

    for func_addr, hash_val in candidates:
        if hash_val in resolved:
            for api_name, cfg in resolved[hash_val]:
                func_key = f"sub_{func_addr:X}"
                if api_name not in results[func_key]:
                    results[func_key].append(api_name)
                # Inject into IR for downstream detectors
                if func_addr not in ir.function_apis:
                    ir.function_apis[func_addr] = []
                if api_name not in ir.function_apis[func_addr]:
                    ir.function_apis[func_addr].append(api_name)

    return dict(results)


def create_resolution_findings(
    ir: DisassemblyResult,
    resolved: dict[str, list[str]],
) -> list[Finding]:
    """Create Finding objects for resolved API hashes."""
    findings: list[Finding] = []

    for func_name, apis in resolved.items():
        findings.append(
            Finding(
                category=FindingCategory.API_HASHING,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=(
                    f"{func_name}: Resolved hashed API calls → {', '.join(apis)}"
                ),
                context={"resolved_apis": apis},
                evidence=[
                    Evidence(
                        type="api_hash_resolution",
                        location=func_name,
                        snippet=f"Resolved: {', '.join(apis)}",
                        rule_id="API_HASH_RESOLVED",
                    )
                ],
            )
        )

    return findings
