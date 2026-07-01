"""
DriverScope — Extended API Hash Bruteforce Engine.

Complements deobfuscation.py by adding support for additional hashing
algorithms commonly found in commercial protectors (360, VMProtect, Themida):

- CRC32 (standard and custom polynomial)
- DJB2 (Bernstein's hash)
- FNV-1a (Fowler-Noll-Vo)
- ELF hash (System V ABI)
- Jenkins one-at-a-time

Each algorithm is used with various seeds/variants. The engine builds
pre-computed lookup tables and resolves hash constants extracted from
the disassembly IR.
"""

from __future__ import annotations

from collections import defaultdict

from src.models import DisassemblyResult, Finding, FindingCategory, Severity, Confidence, Evidence


# ------------------------------------------------------------------
# Expanded API list (150+)
# ------------------------------------------------------------------

_ALL_APIS = [
    # Memory management
    "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
    "MmUnlockPages", "MmProbeAndLockPages", "MmCopyVirtualMemory",
    "MmGetSystemRoutineAddress", "ExAllocatePoolWithTag", "ExAllocatePool",
    "ExFreePoolWithTag", "ExFreePool",
    "MmAllocateContiguousMemory", "MmAllocateContiguousMemorySpecifyCache",
    "MmAllocateNonCachedMemory", "MmFreeContiguousMemory",
    "MmMapVirtualMemory", "MmUnmapVirtualMemory",
    # Process / thread
    "PsCreateSystemThread", "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine", "PsLookupProcessByProcessId",
    "PsLookupThreadByThreadId", "PsTerminateSystemThread",
    "PsGetCurrentProcessId", "PsGetCurrentThreadId",
    "PsGetProcessImageFileName",
    "PsSuspendProcess", "PsResumeProcess",
    "PsSetCreateThreadNotifyRoutineEx",
    "NtTerminateProcess", "NtOpenProcess", "NtOpenThread",
    # Object manager
    "ObReferenceObjectByHandle", "ObReferenceObjectByName",
    "ObDereferenceObject", "ObOpenObjectByPointer",
    "ObRegisterCallbacks", "ObUnRegisterCallbacks",
    # I/O manager
    "IoCreateDevice", "IoCreateSymbolicLink", "IoDeleteDevice",
    "IoDeleteSymbolicLink", "IoQueueWorkItem", "IoAllocateMdl",
    "IoFreeMdl", "IoCompleteRequest", "IoGetCurrentProcess",
    "ZwCreateFile", "ZwOpenFile", "ZwClose", "ZwReadFile", "ZwWriteFile",
    "ZwDeviceIoControlFile", "ZwLoadDriver", "ZwUnloadDriver",
    "ZwQuerySystemInformation", "ZwQueryInformationProcess",
    "ZwQueryInformationThread", "ZwSetInformationThread",
    "ZwMapViewOfSection", "ZwUnmapViewOfSection",
    "ZwAllocateVirtualMemory", "ZwFreeVirtualMemory",
    "ZwCreateSection", "ZwOpenSection",
    "ZwDuplicateObject", "ZwQueryObject",
    "ZwCreateEvent", "ZwOpenEvent",
    "ZwWaitForSingleObject", "ZwDelayExecution",
    # ALPC
    "ZwAlpcCreatePort", "ZwAlpcConnectPort",
    "ZwAlpcSendWaitReceivePort", "NtAlpcConnectPort",
    # APC
    "KeInitializeApc", "KeInsertQueueApc", "KeForceInsertQueueApc",
    "KeStackAttachProcess", "KeUnstackDetachProcess",
    # Registry
    "CmRegisterCallbackEx", "CmUnRegisterCallback",
    # Executive
    "ExGetPreviousMode", "ExAcquireResourceExclusiveLite",
    "ExReleaseResourceLite",
    # String / RTL
    "RtlInitUnicodeString", "RtlInitAnsiString",
    "RtlGetVersion",
    # Security
    "SeCreateClientSecurity", "SeImpersonateClientEx",
    "SeAssignSecurity", "SeAccessCheck", "SePrivilegeCheck",
    "SeTokenIsAdmin",
    # Named pipe
    "NtCreateNamedPipeFile",
    # WDF
    "WdfDriverCreate", "WdfDeviceCreate",
    "WdfIoQueueCreate", "WdfRequestComplete",
    # Debug / Anti-Debug
    "NtQueryDebugObject", "NtCreateDebugObject",
    "NtDebugActiveProcess", "NtSetDebugFilterState",
    "NtSetInformationThread",
    # VMX / EPT Virtualization
    "__vmx_on", "__vmx_vmclear", "__vmx_vmlaunch",
    "__vmx_vmresume", "__vmx_off", "__vmx_vmread", "__vmx_vmwrite",
    "__invept", "__invvpid",
    # Filter Manager
    "FltCreateFile", "FltQueryInformationFile", "FltSetInformationFile",
    "FltReadFile", "FltWriteFile", "FltRegisterFilter",
    "FltStartFiltering", "FltSetCallback",
    # Power / Cache
    "PoRegisterPowerSettingCallback", "PoSetPowerState",
    "KeFlushEntireTb",
    # HAL / Interrupt
    "HalGetInterruptVector", "HalSetBusData", "HalGetBusData",
    # Process/Thread Extended
    "PsGetProcessPeb", "PsGetThreadTeb",
    "PsGetCurrentProcess", "PsGetCurrentThread",
    "PsSetImageNotifyRoutine", "PsRemoveLoadImageNotifyRoutine",
    "PsIsProtectedProcess",
    # Memory Extended
    "MmIsAddressValid", "MmIsNonPagedSystemAddressValid",
    "MmGetVirtualForPhysical", "MmGetPhysicalAddress",
    "MmSecureVirtualMemory", "MmUnsecureVirtualMemory",
    # I/O Extended
    "IoAttachDevice", "IoDetachDevice",
    "IoGetDeviceObjectPointer", "IoDeleteSymbolicLink",
    "IoBuildDeviceIoControlRequest", "IoCallDriver",
    "IoSkipCurrentIrpStackLocation", "IoCopyCurrentIrpStackLocationToNext",
    # Zw/Nt Extended
    "ZwQueryVirtualMemory", "ZwProtectVirtualMemory",
    "ZwQueryDirectoryFile", "ZwSetInformationFile",
    "ZwQuerySecurityObject", "ZwSetSecurityObject",
    "ZwCreateThread", "ZwCreateProcess",
    "ZwQueryDirectoryObject", "ZwOpenDirectoryObject",
    # Ke Extended
    "KeWaitForSingleObject", "KeReleaseMutex",
    "KeInitializeEvent", "KeSetEvent",
    "KeInitializeSpinLock", "KeAcquireSpinLock",
    "KeReleaseSpinLock", "KeDelayExecutionThread",
    "KeQueryPerformanceCounter", "KeQuerySystemTime",
    # Ex Extended
    "ExInterlockedInsertTailList", "ExInterlockedRemoveHeadList",
    "ExInitializeResourceLite", "ExDeleteResourceLite",
    # Rtl Extended
    "RtlUnicodeStringToAnsiString", "RtlAnsiStringToUnicodeString",
    "RtlCompareUnicodeString", "RtlEqualUnicodeString",
    "RtlHashUnicodeString", "RtlUpcaseUnicodeString",
    # RTL Memory Operations (common in drivers)
    "RtlCopyMemory", "RtlMoveMemory", "RtlZeroMemory",
    "RtlFillMemory", "RtlCompareMemory",
    # RTL String Operations
    "RtlStringCbCopyW", "RtlStringCbPrintfW",
    "RtlUnicodeStringCopy", "RtlAnsiStringToUnicodeSize",
    # RTL Integer / Arithmetic
    "RtlLargeIntegerDivide", "RtlMultiply", "RtlAdd",
    # Zw/Nt Registry
    "ZwQueryValueKey", "ZwSetValueKey", "ZwDeleteValueKey",
    "ZwEnumerateValueKey", "ZwCreateKey", "ZwDeleteKey",
    "ZwEnumerateKey", "ZwFlushKey",
    # Zw/Nt Sync / IPC
    "ZwCreateMutant", "ZwOpenMutant",
    "ZwCreateSemaphore", "ZwOpenSemaphore",
    "ZwSetEvent", "ZwResetEvent",
    "ZwPulseEvent", "ZwClearEvent",
    # Zw/Nt Memory Extended
    "ZwLockVirtualMemory", "ZwUnlockVirtualMemory",
    "ZwQuerySection", "ZwExtendSection",
    # Zw/Nt Process Extended
    "ZwTerminateProcess", "ZwSuspendProcess", "ZwResumeProcess",
    "ZwQueryInformationJobObject",
    # Mm Virtual Memory Extended
    "MmProtectVirtualMemory", "MmUnlockVirtualMemory",
    "MmLockVirtualMemory", "MmAllocateMappingAddress",
    "MmFreeMappingAddress", "MmGetPhysicalMemoryRangesEx2",
    # Io Target / Device Interface
    "IoRegisterDeviceInterface", "IoSetDeviceInterfaceState",
    "IoGetDeviceInterfaces", "IoOpenDeviceInterfaceRegistryKey",
    "IoConnectInterrupt", "IoConnectInterruptEx",
    "IoDisconnectInterrupt", "IoAllocateIrp", "IoFreeIrp",
    "IoReuseIrp", "IoSetCompletionRoutineEx",
    # Ps Notify / Callback Extended
    "PsSetLoadImageNotifyRoutine", "PsSetLoadImageNotifyRoutineEx",
    "PsRemoveCreateThreadNotifyRoutine",
    "PsSetCreateProcessNotifyRoutineEx",
    "PsGetProcessSessionId", "PsGetProcessWow64Process",
    # Ob Extended
    "ObGetObjectType", "ObQueryNameString",
    "ObInsertObject", "ObMakeTemporaryObject",
    # FsRtl (File System Runtime)
    "FsRtlIsNameInExpression", "FsRtlIsDbcsInExpression",
    "FsRtlInitializeOplock", "FsRtlOplockFsctrl",
    "FsRtlCompleteRequestIrp",
    # WDF Extended
    "WdfIoTargetCreate", "WdfIoTargetOpen",
    "WdfIoTargetSendIoctlSynchronously",
    "WdfWorkItemCreate", "WdfWorkItemEnqueue",
    "WdfMemoryCreate", "WdfMemoryCreatePreallocated",
    "WdfSpinLockCreate", "WdfWaitLockCreate",
    # HAL Extended
    "HalGetPhysicalAddress", "HalTranslateBusAddress",
    "HalAllocateCommonBuffer", "HalFreeCommonBuffer",
]


def hash_crc32(name: str) -> int:
    """Standard CRC32 hash (using Python's builtin for reference)."""
    import zlib
    return zlib.crc32(name.lower().encode("ascii")) & 0xFFFFFFFF


def _crc32_custom(name: str, poly: int = 0xEDB88320) -> int:
    """Custom CRC32 with configurable polynomial."""
    crc = 0xFFFFFFFF
    for c in name.lower().encode("ascii"):
        crc ^= c
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def hash_djb2(name: str, seed: int = 5381) -> int:
    """DJB2 hash: h = ((h << 5) + h) + c."""
    h = seed
    for c in name.lower():
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def hash_fnv1a(name: str, seed: int = 0x811C9DC5) -> int:
    """FNV-1a 32-bit hash."""
    h = seed
    for c in name.lower():
        h ^= ord(c)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def hash_elf(name: str) -> int:
    """ELF hash (System V ABI)."""
    h = 0
    for c in name.lower():
        h = ((h << 4) + ord(c)) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g
    return h


def hash_jenkins(name: str) -> int:
    """Jenkins one-at-a-time hash."""
    h = 0
    for c in name.lower():
        h += ord(c)
        h &= 0xFFFFFFFF
        h += (h << 10)
        h &= 0xFFFFFFFF
        h ^= (h >> 6)
        h &= 0xFFFFFFFF
    h += (h << 3)
    h &= 0xFFFFFFFF
    h ^= (h >> 11)
    h &= 0xFFFFFFFF
    h += (h << 15)
    h &= 0xFFFFFFFF
    return h


# ------------------------------------------------------------------
# New hash algorithms (Wave 2)
# ------------------------------------------------------------------

def hash_ror13(name: str, seed: int = 0) -> int:
    """ROR13 hash: h = ((h >> 13) | (h << 19)) + c.

    Used by 360 protectors and many shellcode loaders.
    """
    h = seed
    for c in name.lower():
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def hash_ror7(name: str, seed: int = 0) -> int:
    """ROR7 hash: h = ((h >> 7) | (h << 25)) + c.

    Common variant in shellcode.
    """
    h = seed
    for c in name.lower():
        h = ((h >> 7) | (h << 25)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def _murmur3_mix(h: int) -> int:
    """MurmurHash3 finalizer mixing."""
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h


def hash_murmur3_finalize(name: str, seed: int = 0) -> int:
    """Simplified MurmurHash3 finalizer variant.

    Applies only the mixing step to the length-xored seed.
    """
    h = seed ^ len(name)
    return _murmur3_mix(h)


def hash_fnv1a_64(name: str, seed: int = 0xF5E447683B0DC113) -> int:
    """FNV-1a 64-bit hash."""
    h = seed
    prime = 0x00000100000001B3
    for c in name.lower():
        h ^= ord(c)
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
    return h


def hash_crc64(name: str, poly: int = 0xC96C5795D7870F42) -> int:
    """CRC64-ECMA (ECMA-182) hash."""
    crc = 0xFFFFFFFFFFFFFFFF
    for c in name.lower().encode("ascii"):
        crc ^= c
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFFFFFFFFFF


# Algorithm registry: (name, hash_function, variants)
# Each variant is a dict of kwargs (seed, poly, etc.)
ALGO_REGISTRY = [
    ("crc32_custom", _crc32_custom, [{"poly": 0xEDB88320}, {"poly": 0x04C11DB7}]),
    ("djb2", hash_djb2, [{"seed": 5381}, {"seed": 0}]),
    ("fnv1a", hash_fnv1a, [{"seed": 0x811C9DC5}, {"seed": 0}]),
    ("elf", hash_elf, [{}]),
    ("jenkins", hash_jenkins, [{}]),
    # Wave 2 additions
    ("ror13", hash_ror13, [{"seed": 0}, {"seed": 0xDEADBEEF}]),
    ("ror7", hash_ror7, [{"seed": 0}, {"seed": 0x12345678}]),
    ("murmur3", hash_murmur3_finalize, [{"seed": 0}, {"seed": 0x9747B28C}]),
]

# 64-bit algorithm registry
ALGO_REGISTRY_64 = [
    ("fnv1a_64", hash_fnv1a_64, [{"seed": 0xF5E447683B0DC113}]),
    ("crc64", hash_crc64, [{"poly": 0xC96C5795D7870F42}]),
]


def build_extended_hash_tables(apis: list[str] | None = None) -> list[tuple[dict[int, str], str, dict]]:
    """Build lookup tables for all extended hash algorithms.

    Returns list of (hash_table, algo_name, config) tuples.
    """
    tables = []
    target_apis = apis or _ALL_APIS
    for algo_name, hash_func, variants in ALGO_REGISTRY:
        for variant in variants:
            table: dict[int, str] = {}
            for api in target_apis:
                h = hash_func(api, **variant)
                table[h] = api
            tables.append((table, algo_name, variant))
    return tables


# Pre-compute all tables
EXTENDED_HASH_TABLES = build_extended_hash_tables()


def build_64bit_hash_tables(apis: list[str] | None = None) -> list[tuple[dict[int, str], str, dict]]:
    """Build lookup tables for 64-bit hash algorithms.

    Returns list of (hash_table, algo_name, config) tuples.
    """
    tables = []
    target_apis = apis or _ALL_APIS
    for algo_name, hash_func, variants in ALGO_REGISTRY_64:
        for variant in variants:
            table: dict[int, str] = {}
            for api in target_apis:
                h = hash_func(api, **variant)
                table[h] = api
            tables.append((table, algo_name, variant))
    return tables


# Pre-compute 64-bit tables
HASH_TABLES_64 = build_64bit_hash_tables()


def resolve_extended_hash(hash_value: int) -> list[tuple[str, str, dict]]:
    """Resolve a hash value using extended algorithms.

    Returns list of (api_name, algo_name, config) for all matches.
    """
    results = []
    for tbl, algo_name, cfg in EXTENDED_HASH_TABLES:
        if hash_value in tbl:
            results.append((tbl[hash_value], algo_name, cfg))
    return results


def resolve_64bit_hash(hash_value: int) -> list[tuple[str, str, dict]]:
    """Resolve a 64-bit hash value.

    Returns list of (api_name, algo_name, config) for all matches.
    """
    results = []
    for tbl, algo_name, cfg in HASH_TABLES_64:
        if hash_value in tbl:
            results.append((tbl[hash_value], algo_name, cfg))
    return results


def extract_extended_candidates(ir: DisassemblyResult) -> list[tuple[int, int]]:
    """Extract potential hash constants from the IR.

    Same strategy as deobfuscation.extract_hash_candidates but
    also scans functions not flagged by anti-obfuscation (broader net).
    """
    candidates: list[tuple[int, int]] = []

    for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                mnem = insn.mnemonic.lower()

                if mnem in ("cmp", "test"):
                    import re as _re
                    for m in _re.finditer(r"0x([0-9a-f]+)", ops):
                        val = int(m.group(1), 16)
                        if 0x10000 < val < 0xFFFFFFFF:
                            candidates.append((func_addr, val))

                if mnem == "mov":
                    import re as _re
                    m = _re.search(r",\s*0x([0-9a-f]{8})", ops)
                    if m:
                        val = int(m.group(1), 16)
                        if 0x10000 < val < 0xFFFFFFFF:
                            candidates.append((func_addr, val))

    return candidates


def resolve_extended_api_hashes(
    ir: DisassemblyResult,
) -> dict[str, list[tuple[str, str, dict]]]:
    """Main entry point: resolve hashed APIs using extended algorithms.

    Returns dict mapping func_addr_str → [(api_name, algo_name, config)].
    Mutates ir.function_apis and ir.dynamic_imports.
    """
    candidates = extract_extended_candidates(ir)
    if not candidates:
        return {}

    unique_hashes = list(set(h for _, h in candidates))

    results: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)

    for func_addr, hash_val in candidates:
        # Try 32-bit hashes
        matches = resolve_extended_hash(hash_val)
        if not matches:
            # Try 64-bit hashes (large immediate values)
            matches = resolve_64bit_hash(hash_val)
        if matches:
            func_key = f"sub_{func_addr:X}"
            for api_name, algo_name, cfg in matches:
                entry = (api_name, algo_name, cfg)
                if entry not in results[func_key]:
                    results[func_key].append(entry)
                # Inject into IR
                if func_addr not in ir.function_apis:
                    ir.function_apis[func_addr] = []
                if api_name not in ir.function_apis[func_addr]:
                    ir.function_apis[func_addr].append(api_name)

    return dict(results)


def create_extended_findings(
    ir: DisassemblyResult,
    resolved: dict[str, list[tuple[str, str, dict]]],
) -> list[Finding]:
    """Create Finding objects for extended API hash resolution."""
    findings: list[Finding] = []

    for func_name, entries in resolved.items():
        api_names = list(set(e[0] for e in entries))
        algos = list(set(f"{e[1]}" for e in entries))
        findings.append(
            Finding(
                category=FindingCategory.API_HASH_RESOLVED_EXTENDED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description=(
                    f"{func_name}: Extended hash resolution → {', '.join(api_names)}"
                    f" (algorithms: {', '.join(algos)})"
                ),
                context={
                    "resolved_apis": api_names,
                    "algorithms": algos,
                },
                evidence=[
                    Evidence(
                        type="extended_api_hash_resolution",
                        location=func_name,
                        snippet=f"Resolved: {', '.join(api_names)}",
                        rule_id="API_HASH_EXT",
                    )
                ],
            )
        )

    return findings
