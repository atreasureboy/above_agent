"""
DriverScope — Centralized configuration defaults.

This module extracts magic constants from analysis code into a single
source of truth.  All stages, analyzers, and scoring reference these
values rather than hardcoding them.

Usage:
    from src.config.defaults import DANGEROUS_API_WEIGHTS
    from src.config.defaults import SYSTEM_DRIVER_WHITELIST
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Funnel L2: Import scoring weights
# ---------------------------------------------------------------------------

DANGEROUS_API_WEIGHTS: dict[str, int] = {
    # Memory mapping (high weight)
    "MmMapIoSpace": 15,
    "MmMapIoSpaceEx": 15,
    "MmMapLockedPagesSpecifyCache": 20,
    "MmMapLockedPages": 20,
    "ZwMapViewOfSection": 12,
    "NtMapViewOfSection": 12,
    # Memory mapping extensions
    "MmMapViewInSystemSpace": 16,
    "MmMapViewInSessionSpace": 14,
    "MmGetVirtualForPhysical": 18,
    "MmIsAddressValid": 6,
    "MmMapVideoDisplay": 12,
    "MmUnmapVideoDisplay": 6,
    "ZwAllocateVirtualMemory": 10,
    "ZwFreeVirtualMemory": 4,
    "NtAllocateVirtualMemory": 10,
    "NtFreeVirtualMemory": 4,
    "MmGetPhysicalAddressEx": 10,
    # MSR access (critical)
    "KeReadMsr": 8,
    "KeWriteMsr": 20,
    "__readmsr": 20,
    "__writemsr": 20,
    # Physical memory
    "MmGetPhysicalAddress": 8,
    "MmGetPhysicalMemoryRanges": 6,
    "MmGetPhysicalMemoryRangesEx": 6,
    "MmGetPhysicalMemoryRangesEx2": 6,
    "MmAllocateContiguousMemory": 10,
    "MmAllocateContiguousMemorySpecifyCache": 12,
    "MmAllocateContiguousMemorySpecifyCacheNode": 12,
    # Kernel R/W
    "MmCopyVirtualMemory": 15,
    "ZwWriteVirtualMemory": 15,
    "NtWriteVirtualMemory": 15,
    "MmCopyMemory": 14,
    "ZwReadVirtualMemory": 15,
    "NtReadVirtualMemory": 15,
    # Code execution (critical)
    "ZwCreateThreadEx": 20,
    # Process manipulation
    "ZwOpenProcess": 6,
    "ZwQueueApcThread": 12,
    "ZwSetInformationProcess": 18,
    # Process/thread extensions
    "PsCreateSystemThread": 16,
    "PsTerminateSystemThread": 6,
    "ZwOpenThread": 8,
    "ZwTerminateThread": 12,
    "ZwSuspendThread": 10,
    "ZwResumeThread": 10,
    "KeStackAttachProcess": 14,
    "KeUnstackDetachProcess": 8,
    "PsLookupProcessByProcessId": 10,
    "PsLookupThreadByThreadId": 10,
    # DPC / Work Queue (indirect code execution)
    "IoQueueWorkItem": 10,
    "IoAllocateWorkItem": 8,
    "IoFreeWorkItem": 2,
    "KeInitializeDpc": 8,
    "KeSetTimer": 6,
    "KeSetTimerEx": 6,
    # DMA primitives (physical memory abuse)
    "WdfDmaEnablerCreate": 10,
    "WdfDmaTransactionCreate": 10,
    "MmAllocateAdapterChannel": 8,
    "IoGetDmaAdapter": 6,
    # DMA extensions
    "IoAllocateAdapterChannel": 8,
    "IoMapTransfer": 10,
    "WdfCommonBufferCreate": 12,
    "WdfDmaTransactionInitialize": 10,
    "HalGetPhysicalAddress": 8,
    # Pool manipulation (user-controlled size → overflow)
    "ExAllocatePoolWithTag": 6,
    "ExAllocatePool": 6,
    "ExAllocatePool2": 6,
    "ExAllocatePool3": 6,
    "ExFreePool": 3,
    "ExFreePoolWithTag": 3,
    # Interrupt hooking
    "IoConnectInterrupt": 14,
    "IoConnectInterruptEx": 14,
    "IoDisconnectInterrupt": 4,
    "HalSetSystemInformation": 16,
    # Handle / object manipulation
    "ObReferenceObjectByHandle": 10,
    "ObOpenObjectByPointer": 8,
    "ZwDuplicateObject": 10,
    # Security bypass
    "PsSetLoadImageNotifyRoutine": 12,
    "PsSetCreateProcessNotifyRoutine": 12,
    "PsSetCreateThreadNotifyRoutine": 12,
    "PsRemoveLoadImageNotifyRoutine": 4,
    "ObRegisterCallbacks": 12,
    "ObUnRegisterCallbacks": 4,
    "PsWrapApcWow64Thread": 6,
    # Security token / privilege extensions
    "SeImpersonateClientEx": 14,
    "SeCreateClientSecurity": 12,
    "PsImpersonateClient": 12,
    "SeQuerySecurityDescriptorInfo": 10,
    "ZwSetInformationToken": 10,
    "SeAssignSecurity": 10,
    # Registry manipulation
    "ZwCreateKey": 6,
    "NtCreateKey": 6,
    "ZwSetValueKey": 8,
    "NtSetValueKey": 8,
    "ZwDeleteKey": 6,
    "ZwEnumerateKey": 4,
    "CmRegisterCallback": 10,
    "RtlWriteRegistryValue": 6,
    # File system / filter
    "IoCreateFileSpecifyDeviceObjectHint": 10,
    "ZwCreateFile": 6,
    "NtCreateFile": 6,
    "ZwReadFile": 6,
    "ZwWriteFile": 8,
    "IoCallDriver": 8,
    "IoBuildDeviceIoControlRequest": 8,
    "IoGetDeviceObjectPointer": 6,
    # WDF专属
    "WdfIoTargetSendIoctlSynchronously": 10,
    "WdfRequestRetrieveParameters": 6,
    "WdfIoQueueReadyNotify": 8,
    "WdfObjectGetTypedContext": 8,
    "WdfMemoryCreate": 8,
    "WdfWorkItemEnqueue": 8,
    # 未覆盖的 ntoskrnl 导出
    "ExRegisterCallback": 10,
    "KeRegisterNmiCallback": 14,
    "IoRegisterShutdownNotification": 8,
    "MmLockPagableCodeSection": 6,
    "ZwLoadDriver": 16,
    "NtLoadDriver": 16,
    "ZwUnloadDriver": 10,
    "NtUnloadDriver": 10,
    # Other interesting APIs
    "ZwDeviceIoControlFile": 3,
    "IoCreateDevice": 2,
    "IoCreateDeviceSecure": 2,
    "IoCreateSymbolicLink": 2,
    "RtlCopyMemory": 1,
    # Privilege checks
    "SeSinglePrivilegeCheck": 5,
    "ExGetPreviousMode": 4,
    "ProbeForRead": 4,
    "ProbeForWrite": 4,
    "MmProbeAndLockPages": 4,
    "MmProbeAndLockProcessPages": 4,
    # Kernel APC / Thread injection (360 self-protection)
    "KeInitializeApc": 14,
    "KeInsertQueueApc": 16,
    "KeForceInsertQueueApc": 18,
    "ZwSuspendThread": 10,
    "ZwGetContextThread": 14,
    "ZwSetContextThread": 14,
    # Registry callback (360 registry protection)
    "CmRegisterCallback": 12,
    "CmRegisterCallbackEx": 12,
    # Named pipe communication
    "NtCreateNamedPipeFile": 12,
    "ZwCreateNamedPipeFile": 12,
    "NtFsControlFile": 10,
    "ZwFsControlFile": 10,
}

# Set of all dangerous API names (derived from weights dict,
# used by disassembly backend for IAT resolution).
DANGEROUS_API_SET: set[str] = set(DANGEROUS_API_WEIGHTS.keys())

# Default threshold for import score stage — samples below this are filtered
IMPORT_SCORE_DEFAULT_THRESHOLD = 15

# Strings that suggest user-mode device accessibility
USER_MODE_ACCESS_STRINGS: list[str] = [
    r"\\Device\\",
    r"\\DosDevices\\",
    r"\\GLOBAL??",
    r"DeviceIoControl",
]

# ---------------------------------------------------------------------------
# Funnel L1: Whitelist
# ---------------------------------------------------------------------------

SYSTEM_DRIVER_WHITELIST: set[str] = {
    # Core kernel
    "ntoskrnl.exe", "hal.dll", "hal*.dll", "kd*.dll",
    "acpi.sys", "pci.sys", "pcw.sys", "fileinfo.sys",
    "ksecdd.sys", "ksecpkcs.sys", "cng.sys", "bcrypt.sys",
    "fvevol.sys", "volmgr.sys", "volsnap.sys",
    # Storage
    "storport.sys", "disk.sys", "partmgr.sys", "volume.sys",
    "ntfs.sys", "fastfat.sys", "exfat.sys", "udfs.sys",
    "cdfs.sys", "fs_rec.sys", "msfs.sys", "npfs.sys",
    # Network
    "ndis.sys", "tcpip.sys", "netio.sys", "netbt.sys", "afd.sys",
    "vwififlt.sys", "mrxsmb*.sys", "rdbss.sys", "smbdirect.sys",
    "tcpipk.sys", "fwpkclnt.sys", "wfplwfs.sys",
    # Graphics / Display
    "dxgkrnl.sys", "dxgmms*.sys", "dxgthk.sys", "watchdog.sys",
    "framebuf.sys", "rdpdd*.sys",
    # Audio
    "portcls.sys", "portcls*.sys", "stream.sys", "wdmaud.sys",
    "ksthunk.sys",
    # USB
    "usbhub.sys", "usbhub3.sys", "usbccgp.sys", "usbehci.sys",
    "usbuhci.sys", "usbohci.sys", "usbccgp.sys",
    # Input / HID
    "kbdhid.sys", "mouhid.sys", "hidclass.sys", "hidparse.sys",
    "kbdclass.sys", "mouclass.sys",
    # WDF framework
    "wdf01000.sys", "wdfldr.sys",
    # Virtual / emulated
    "vmbus.sys", "vmstor.sys", "vmbkmcl.sys",
    "intelpep.sys", "amdi2c.sys",
    # Power / thermal
    "thermtht.sys", "battdrvr.sys", "cmbatt.sys",
    # Display miniport
    "basicdisplay.sys", "basicrender.sys",
    # Misc MS drivers
    "mssmbios.sys", "msisadrv.sys", "intelide.sys", "viaide.sys",
    "1394ohci.sys", "ehstor*.sys", "flpydisk.sys",
    "raspti.sys", "rasl2tp.sys", "raspppoe.sys",
    "wanarp.sys", "ndproxy.sys",
}

# Whitelisted directory patterns (regex)
WHITELIST_DIR_PATTERNS: list[str] = [
    r"\\Windows\\System32\\DriverStore",
    r"\\Windows\\winsxs",
]

# Microsoft company name keywords
MICROSOFT_CN_KEYWORDS: list[str] = [
    "microsoft windows",
    "microsoft corporation",
    "microsoft",
]

# Max driver size to consider (KB)
WHITELIST_MAX_SIZE_KB = 200

# ---------------------------------------------------------------------------
# Scoring: Category weights
# ---------------------------------------------------------------------------

CATEGORY_WEIGHTS: dict[str, float] = {
    # Core BYOVD indicators
    "attack_chain": 2.0,
    "unvalidated_user_input": 1.5,
    "arbitrary_memory_map": 1.5,
    "msr_access": 1.3,
    "kernel_rw_primitive": 1.3,
    "physical_memory_access": 1.2,
    "code_execution_primitive": 1.8,
    "process_manipulation": 1.1,
    # Extended primitives
    "dpc_work_queue": 1.3,
    "dma_primitive": 1.4,
    "pool_manipulation": 1.0,
    "interrupt_hooking": 1.8,
    "handle_manipulation": 1.2,
    "callback_registration": 1.4,
    # Validation gaps
    "missing_size_check": 0.3,
    "missing_privilege_check": 0.5,
    "partial_validation": 0.8,
    # Structural findings
    "ioctl_code_exposed": 0.3,
    "ioctl_dispatcher": 0.1,
    # Intel / info
    "known_vulnerable_hash": 2.5,
    "signed_driver": 0.1,
    "dangerous_string": 0.3,
    "debug_symbols": 0.1,
    # Phase 10: Privileged instruction primitives
    "debug_register_write": 1.6,
    "gdt_idt_modification": 1.8,
    "tlb_invalidation": 0.8,
    "processor_state_manipulation": 1.0,
    # Phase 11: Anti-debug and anti-reversing indicators
    "anti_debug_timing": 1.4,
    "anti_debug_hypervisor": 1.2,
    "anti_debug_trap": 1.0,
    "anti_debug_nmi": 0.8,
    "anti_debug_exception": 0.6,
    "anti_debug_system_flag": 1.5,
    "control_flow_flattening": 1.6,
    "dead_code_injection": 1.0,
    "packed_binary": 1.8,
    "string_encryption": 1.4,
    "api_hashing": 1.6,
    # Phase 13: Kernel hook detection
    "inline_hook": 2.0,
    "ssdt_hook": 2.2,
    "idt_hook": 1.8,
    "code_self_check": 1.0,
    # Phase 2: VMX / EPT virtualization
    "vmx_instruction": 2.2,
    "ept_manipulation": 2.5,
    "hypervisor_setup": 2.5,
    # Phase 3: VMProtect / Themida virtualization
    "vm_protect": 2.0,
    "vm_entry": 2.5,
    "vm_handler_dispatch": 1.6,
    # Phase 4: DKOM / hidden process
    "dkom_process_unlink": 2.2,
    "dkom_thread_unlink": 2.0,
    "dkom_cid_table": 1.8,
    "dkom_token": 2.5,
    # Phase 5: ALPC/LPC cross-driver communication
    "alpc_communication": 2.0,
    "alpc_port_name": 1.6,
    "alpc_shared_memory": 1.4,
    "alpc_message": 1.2,
    # Phase 5b: Named pipe communication
    "named_pipe": 1.8,
    # Phase 6b: Kernel APC / Thread injection
    "apc_injection": 2.2,
    # Phase 7: Registry callback protection
    "registry_callback": 1.6,
    # Phase 8: Object callback protection
    "object_callback": 2.0,
    # Phase 3: VMProtect / Themida
    "vm_protect": 2.0,
    "vm_entry": 2.5,
    "vm_handler": 1.6,

    # Wave 1: Enhanced string decryption
    "string_decrypted": 1.6,
    "string_encryption": 1.4,

    # Wave 2: Extended API hash resolution
    "api_hash_resolved_extended": 1.8,
    "api_hashing": 1.6,

    # Wave 3: Advanced taint analysis
    "unvalidated_data_flow": 1.2,
    "validated_surface": 0.5,

    # Deep analysis categories
    "call_chain_analyzed": 0.6,
    "callback_resolved": 0.6,
    "filter_callback_analyzed": 0.6,
    "memory_map_analyzed": 0.6,
    "xref_table_usage": 0.8,
    "struct_inferred": 0.6,
    "data_structure_identified": 0.6,
    "stack_string_reconstructed": 0.8,
    "wide_string_found": 0.6,
    "xref_hot_data": 1.0,
    "whitelist_check_detected": 1.0,
    "blacklist_check_detected": 1.0,
    "array_iteration_cmp": 0.8,
    "cpp_object_detected": 0.8,
    "security_mechanism": 0.4,
    "string_rva_resolved": 0.6,
    "dispatch_table_resolved": 0.8,
    "runtime_alloc_table": 0.6,
    "whitelist_table_detected": 1.0,
    "memory_map_positioning": 0.8,

    # Communication protocol
    "comm_protocol_analyzed": 0.4,
    "ioctl_command_inferred": 1.2,
    "alpc_port_exposed": 1.0,
    "named_pipe_exposed": 1.0,
    "alpc_port_name": 1.6,

    # Minifilter
    "minifilter_rules_analyzed": 0.6,
    "minifilter_callback": 1.4,

    # VMX/EPT deep
    "vmx_deep_analyzed": 1.4,
    "eptp_construction": 1.8,
    "vmcs_field_write": 1.4,
    "ept_hook_pattern": 2.0,

    # Enhanced deobfuscation
    "cff_deobfuscated": 1.2,

    # User-mode analysis
    "dangerous_usermode_import": 0.8,
    "com_interface_exposed": 1.0,
    "service_registration": 0.2,
    "embedded_driver": 0.6,
    "usermode_kernel_bridge": 1.6,

    # Multi-driver correlation
    "cross_driver_alpc": 1.4,
    "cross_driver_named_pipe": 1.2,
    "cross_driver_shared_device": 1.0,
    "cross_driver_attack_chain": 2.2,
    "shared_ioctl_protocol": 1.2,

    # Data content
    "data_content_analyzed": 0.4,
    "string_table_identified": 0.6,

    # Dynamic analysis
    "dynamic_crash_confirmed": 1.0,
    "dynamic_ioctl_validated": 0.8,
    "dynamic_hook_detected": 1.6,
    "dynamic_new_device": 0.4,
    "dynamic_registry_write": 0.2,
    "dynamic_file_created": 0.2,
    "dynamic_process_injection": 2.0,
}

# ---------------------------------------------------------------------------
# Pipeline defaults
# ---------------------------------------------------------------------------

# Max files to ingest in a single directory scan
INGEST_MAX_FILES = 2000

# Max file size for disassembly (200MB)
DISASM_MAX_SIZE = 200 * 1024 * 1024

# Default timeout per driver in batch mode (seconds)
DEFAULT_TIMEOUT_PER_DRIVER = 30

# Default limit for funnel L4 survivors
FUNNEL_L4_DEFAULT_MAX = 20

# Minimum samples to trigger funnel (below this, scan directly)
FUNNEL_MIN_SAMPLES = 5

# Analysis cache TTL (7 days)
CACHE_TTL_SECONDS = 7 * 24 * 3600

# ---------------------------------------------------------------------------
# M3: Privileged instruction set (compiler intrinsics / inline assembly)
# ---------------------------------------------------------------------------

# Maps assembly mnemonic → pseudo-API name for instruction-level detection.
# These are raw CPU instructions that act as dangerous kernel primitives
# without going through IAT function calls.
PRIVILEGED_INSTRUCTIONS: dict[str, str] = {
    "wrmsr": "__writemsr",       # Write MSR → arbitrary kernel code execution
    "rdmsr": "__readmsr",        # Read MSR → information disclosure / syscall redirect
    "invlpg": "__invlpg",        # Invalidate TLB → memory manipulation
    "lgdt": "__lgdt",            # Load GDT → descriptor table manipulation
    "lidt": "__lidt",            # Load IDT → interrupt handler hijacking
    "ltr": "__ltr",              # Load TR → TSS manipulation
    "lmsw": "__lmsw",            # Load MSW → processor mode switching
    "clts": "__clts",            # Clear TS flag → FPU/SSE state manipulation
    "mov": None,                 # Special-cased: only cr0/cr3/cr4/dr0-7
}

# Control/debug register subsets detected via "mov" mnemonic
MOV_CR_DR_REGS = {
    "cr0": "__mov_cr0",   # Control register 0 → paging/protected mode
    "cr3": "__mov_cr3",   # Page directory base → arbitrary page table manipulation
    "cr4": "__mov_cr4",   # Control register 4 → SMEP/SMAP bypass potential
    "dr0": "__mov_dr0",   # Debug register → hardware breakpoints
    "dr1": "__mov_dr1",
    "dr2": "__mov_dr2",
    "dr3": "__mov_dr3",
    "dr4": "__mov_dr4",
    "dr5": "__mov_dr5",
    "dr6": "__mov_dr6",
    "dr7": "__mov_dr7",   # Debug control → arbitrary debug state
}

# ---------------------------------------------------------------------------
# M3: ntoskrnl.exe ordinal → API name mapping (common exports)
# ---------------------------------------------------------------------------
# Only covers the most commonly imported-by-ordinal APIs in BYOVD contexts.
# Full table has 2000+ entries — these are the high-value ones.

# ---------------------------------------------------------------------------
# Correlator: Validation & overflow detection constants
# ---------------------------------------------------------------------------

VALIDATION_APIS: set[str] = {
    "SeSinglePrivilegeCheck", "ExGetPreviousMode",
    "ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages",
    "MmProbeAndUnlockPages", "MmProbeAndLockProcessPages",
}

SAFE_ARITHMETIC_APIS: set[str] = {
    "RtlULongAdd", "RtlLongAdd", "RtlULongMult", "RtlLongMult",
    "RtlAddSatUlong", "RtlSubSatUlong",
    "IntSafeMultiply", "IntSafeAdd",
}

# x64 arithmetic mnemonics that can cause integer overflow
X64_ARITHMETIC_MNEMONICS: set[str] = {"add", "sub", "mul", "imul", "adc", "sbb", "inc", "dec"}
# ARM64 arithmetic mnemonics that can cause integer overflow
ARM64_ARITHMETIC_MNEMONICS: set[str] = {
    "adds", "subs", "madd", "msub", "mul", "smull", "umull",
    "smaddl", "umaddl", "sdiv", "udiv",
}

# x64 overflow flag checks (jump on overflow/carry)
X64_OVERFLOW_FLAG_CHECKS: set[str] = {"jo", "jno", "jc", "jnc", "seto", "setc"}
# ARM64 overflow flag checks (branch on overflow set/clear)
ARM64_OVERFLOW_FLAG_CHECKS: set[str] = {"b.vs", "b.vc", "tbz", "tbnz"}

# x64 validation branches (after size comparison, branch to fail path)
X64_VALIDATION_BRANCHES: set[str] = {"jbe", "jna", "jb"}
# ARM64 validation branches
ARM64_VALIDATION_BRANCHES: set[str] = {"b.ls", "b.hi", "b.lo", "b.hs"}

NTOSKRNL_ORDINAL_MAP: dict[str, str] = {
    # Memory management
    "ntoskrnl_358": "MmMapIoSpace",
    "ntoskrnl_359": "MmMapIoSpaceEx",
    "ntoskrnl_343": "MmMapLockedPagesSpecifyCache",
    "ntoskrnl_342": "MmMapLockedPages",
    "ntoskrnl_337": "MmGetPhysicalAddress",
    "ntoskrnl_334": "MmGetPhysicalMemoryRanges",
    "ntoskrnl_335": "MmGetPhysicalMemoryRangesEx",
    "ntoskrnl_336": "MmGetPhysicalMemoryRangesEx2",
    "ntoskrnl_325": "MmCopyVirtualMemory",
    "ntoskrnl_249": "MmProbeAndLockPages",
    "ntoskrnl_250": "MmProbeAndLockProcessPages",
    "ntoskrnl_248": "MmProbeAndUnlockPages",
    "ntoskrnl_227": "MmAllocateContiguousMemory",
    "ntoskrnl_228": "MmAllocateContiguousMemorySpecifyCache",
    "ntoskrnl_229": "MmAllocateContiguousMemorySpecifyCacheNode",
    # MSR / privileged
    "ntoskrnl_202": "KeReadMsr",
    "ntoskrnl_215": "KeWriteMsr",
    "ntoskrnl_216": "KeXSave",
    "ntoskrnl_199": "KeIpiGenericCall",
    # Security
    "ntoskrnl_565": "SeSinglePrivilegeCheck",
    "ntoskrnl_566": "SeQueryInformationToken",
    "ntoskrnl_567": "SeCreateClientSecurity",
    "ntoskrnl_553": "SeExports",
    # Process/thread
    "ntoskrnl_468": "PsGetCurrentProcess",
    "ntoskrnl_469": "PsGetCurrentThreadId",
    "ntoskrnl_470": "PsGetCurrentProcessId",
    "ntoskrnl_483": "PsSetLoadImageNotifyRoutine",
    "ntoskrnl_484": "PsSetCreateProcessNotifyRoutine",
    "ntoskrnl_485": "PsSetCreateThreadNotifyRoutine",
    "ntoskrnl_500": "PsLookupProcessByProcessId",
    "ntoskrnl_501": "PsLookupThreadByThreadId",
    # System information
    "ntoskrnl_608": "ZwQuerySystemInformation",
    "ntoskrnl_609": "ZwSetSystemInformation",
    # Misc
    "ntoskrnl_155": "ExAllocatePoolWithTag",
    "ntoskrnl_154": "ExAllocatePool",
    "ntoskrnl_156": "ExAllocatePool2",
    "ntoskrnl_157": "ExAllocatePool3",
    "ntoskrnl_170": "ExFreePool",
    "ntoskrnl_171": "ExFreePoolWithTag",
    "ntoskrnl_64": "DbgPrint",
    "ntoskrnl_65": "DbgPrintEx",
    # Dynamic resolution helper
    "ntoskrnl_340": "MmGetSystemRoutineAddress",
    # HAL
    "hal_140": "HalTranslateBusAddress",
    "hal_141": "HalSetSystemInformation",
    "hal_20": "HalAllocateAdapterChannel",
    "hal_21": "HalGetAdapter",
}
