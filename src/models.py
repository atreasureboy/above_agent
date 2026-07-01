"""
DriverScope — Core data models.

These are the types that flow through the 4-layer pipeline.
Each layer transforms or enriches these objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Layer 1: Ingestion
# ---------------------------------------------------------------------------

class SignatureStatus(Enum):
    UNSIGNED = "unsigned"
    SIGNED_VALID = "signed_valid"
    SIGNED_INVALID = "signed_invalid"
    SIGNED_EXPIRED = "signed_expired"
    SIGNED_UNTRUSTED = "signed_untrusted"


class Architecture(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


@dataclass
class Sample:
    """Standardized sample object flowing through the pipeline."""
    path: Path
    name: str  # OriginalFilename from PE resources
    company: str  # CompanyName from PE resources
    version: str  # FileVersion
    arch: Architecture
    sha256: str
    size: int

    # PE metadata
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    entry_point: int = 0
    compile_timestamp: int = 0  # PE header TimeDateStamp
    debug_path: str = ""  # PDB path from debug directory

    # Driver-specific
    is_driver: bool = False
    driver_type: str = ""  # "WDM", "WDF/KMDF", "WDF/UMDF", etc.
    subsystem: str = ""  # "NATIVE", "WINDOWS_GUI", etc.

    # Signing
    signature_status: SignatureStatus = SignatureStatus.UNSIGNED
    signer_name: str = ""

    # Enriched by later layers
    disassembly_result: DisassemblyResult | None = None
    analysis_findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0

    # Phase 1A: User-mode analysis fields
    is_usermode: bool = False           # True for .exe/.dll, False for .sys
    binary_type: str = ""               # "exe", "dll", "sys"
    com_interfaces: list[str] = field(default_factory=list)  # Exposed COM interfaces
    service_info: dict = field(default_factory=dict)         # Service registration info
    embedded_files: list[Path] = field(default_factory=list)  # Embedded resources (may contain drivers)

    # Phase 2: Dynamic analysis results
    dynamic_results: list[dict] = field(default_factory=list)

    def is_wdm(self) -> bool:
        return self.driver_type == "WDM"

    def is_wdf(self) -> bool:
        return self.driver_type.startswith("WDF")


# ---------------------------------------------------------------------------
# Layer 2: Disassembly & IR
# ---------------------------------------------------------------------------

@dataclass
class Function:
    """Represents a disassembled function."""
    name: str
    address: int
    size: int
    called_by: list[int] = field(default_factory=list)
    calls: list[int] = field(default_factory=list)
    is_entry: bool = False
    is_ioctl_handler: bool = False
    pseudo_code: str = ""
    # Phase 5: Decompiler and type information
    signature: str = ""  # e.g. "NTSTATUS sub_1000(PDEVICE_OBJECT, PIRP)"
    local_vars: list[dict] = field(default_factory=list)  # [{name, type, stack_offset}]


@dataclass
class BasicBlock:
    """A basic block in a CFG."""
    address: int
    end_address: int
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class APICallInfo:
    """Structured information about an API call instruction."""
    name: str  # "MmMapIoSpaceEx"
    call_address: int  # Address of the call instruction
    params_hint: str = ""  # e.g. "rcx (from IRP+0x60)", "rip+0x1234"
    user_controllable: bool = False  # True if params trace back to user input


@dataclass
class Instruction:
    """A single instruction."""
    address: int
    mnemonic: str
    operands: str
    api_target: str = ""  # If this is a call to a known API (short name)
    api_info: APICallInfo | None = None  # Full API call context
    size: int = 0  # Instruction size in bytes


@dataclass
class CFG:
    """Control Flow Graph for a function."""
    function_address: int
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    entry_block: int = 0


@dataclass
class DisassemblyResult:
    """Complete disassembly output for a sample."""
    sample_path: Path
    backend: str  # "ghidra", "ida", "radare2"
    functions: dict[int, Function] = field(default_factory=dict)
    cfgs: dict[int, CFG] = field(default_factory=dict)  # Full CFGs (non-quick mode)
    simple_cfgs: dict[int, CFG] = field(default_factory=dict)  # Simplified CFGs (quick mode, direct branches only)
    ioctl_codes: list[int] = field(default_factory=list)
    ioctl_dispatcher: int = 0  # Address of the dispatch function
    irp_handlers: dict[int, int] = field(default_factory=dict)  # IRP_MJ_* -> handler addr
    ioctl_handlers: dict[int, int] = field(default_factory=dict)  # IOCTL_code -> handler func addr
    import_addresses: dict[int, str] = field(default_factory=dict)  # addr -> "ntoskrnl.ZwXxx"
    function_apis: dict[int, list[str]] = field(default_factory=dict)  # func_addr -> ["MmMapIoSpace", ...]
    function_api_details: dict[int, list[APICallInfo]] = field(default_factory=dict)  # func_addr -> [APICallInfo, ...]
    strings: list[str] = field(default_factory=list)
    is_wdf_driver: bool = False  # True if WDF imports detected
    is_arm64: bool = False  # True if ARM64 architecture
    is_filter_driver: bool = False  # True if filter driver (IoAttachDevice pattern)
    dynamic_imports: dict[int, list[str]] = field(default_factory=dict)  # func_addr -> [resolved API names]
    deferred_callbacks: dict[int, list[dict]] = field(default_factory=dict)  # callback_addr -> [{queue_api, caller_func, callback_type}]
    wdf_dispatch_functions: dict[int, list[int]] = field(default_factory=dict)  # IOCTL_code -> [handler func addrs] (WDF)
    wdf_context_objects: dict[int, list[str]] = field(default_factory=dict)  # func_addr -> [context type names]
    wdf_io_queue_configs: list[dict] = field(default_factory=list)  # [{queue_type, dispatch_func, ioctl_range}]

    # Phase 1: Additional entry points for zero false-negative detection
    fastio_handlers: dict[int, int] = field(default_factory=dict)  # FastIO offset -> handler addr
    wmi_handlers: dict[int, int] = field(default_factory=dict)  # WMI GUID index -> handler addr
    minifilter_handlers: dict[int, int] = field(default_factory=dict)  # callback offset -> handler addr
    is_minifilter: bool = False
    mmio_surfaces: list[dict] = field(default_factory=list)  # [{func_addr, apis, is_entry_point}]

    # Phase 5: Decompiler and type information
    data_xrefs: dict[int, list[dict]] = field(default_factory=dict)  # func_addr -> [{type, target_addr, source_insn}]
    struct_types: dict[str, dict] = field(default_factory=dict)  # struct name -> {field_name: offset}
    type_info: dict[int, dict] = field(default_factory=dict)  # func_addr -> {signature, param_types, return_type}

    # Deep reverse engineering
    stack_strings: list[dict] = field(default_factory=list)  # [{address, func_addr, string, encoding, insn_addresses}]
    wide_strings: list[dict] = field(default_factory=list)  # [{address, string, section}]
    data_structures: dict[int, dict] = field(default_factory=dict)  # rva -> {type, element_count, element_size, entropy, values, cross_refs}
    data_references: list[dict] = field(default_factory=list)  # [{func_addr, insn_addr, insn_text, rva, access_type}]
    comparison_traces: list[dict] = field(default_factory=list)  # [{insn_addr, insn_text, data_rva, compared_value, is_whitelist, is_blacklist, is_array_iteration}]
    string_locations: list[dict] = field(default_factory=list)  # [{rva, value, section}] — strings with position info
    string_rvas: dict[int, str] = field(default_factory=dict)  # rva -> string value (fast lookup)
    callback_registrations: list[dict] = field(default_factory=list)  # [{api, func_addr, callback_funcs, object_type}]
    filter_callbacks: list[dict] = field(default_factory=list)  # [{type, callback_addr, pre_op, post_op}]


# ---------------------------------------------------------------------------
# Layer 3: Analysis
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    CERTAIN = 1.0   # SHA256 match, verified hash
    HIGH = 0.9
    MEDIUM = 0.7
    LOW = 0.4


class FindingCategory(Enum):
    # Structure findings
    IOCTL_DISPATCHER_FOUND = "ioctl_dispatcher"
    IOCTL_CODE_EXPOSED = "ioctl_code_exposed"

    # Dangerous primitives
    ARBITRARY_MEMORY_MAP = "arbitrary_memory_map"
    MSR_ACCESS = "msr_access"
    PHYSICAL_MEMORY_ACCESS = "physical_memory_access"
    KERNEL_RW_PRIMITIVE = "kernel_rw_primitive"
    CODE_EXECUTION_PRIMITIVE = "code_execution_primitive"
    PROCESS_MANIPULATION = "process_manipulation"
    DPC_WORK_QUEUE = "dpc_work_queue"
    DMA_PRIMITIVE = "dma_primitive"
    POOL_MANIPULATION = "pool_manipulation"
    INTERRUPT_HOOKING = "interrupt_hooking"
    HANDLE_MANIPULATION = "handle_manipulation"
    CALLBACK_REGISTRATION = "callback_registration"

    # Data flow findings
    UNVALIDATED_USER_INPUT = "unvalidated_user_input"
    MISSING_SIZE_CHECK = "missing_size_check"
    MISSING_PRIVILEGE_CHECK = "missing_privilege_check"
    PARTIAL_VALIDATION = "partial_validation"
    UNVALIDATED_DATA_FLOW = "unvalidated_data_flow"

    # Info
    SIGNED_DRIVER = "signed_driver"
    KNOWN_VULNERABLE_HASH = "known_vulnerable_hash"
    DEBUG_SYMBOLS_PRESENT = "debug_symbols"

    # String analysis
    DANGEROUS_STRING = "dangerous_string"

    # Correlated findings
    ATTACK_CHAIN = "attack_chain"

    # Phase 1: Additional entry point categories
    FASTIO_DISPATCHER_FOUND = "fastio_dispatcher"
    WMI_HANDLER_FOUND = "wmi_handler"
    MINIFILTER_CALLBACK_FOUND = "minifilter_callback"
    MMIO_SURFACE = "mmio_surface"

    # Phase 4: Semantic primitive detection (non-API-based)
    CUSTOM_PHYSICAL_MEMORY_MAPPING = "custom_physical_memory_mapping"
    CUSTOM_CODE_EXECUTION = "custom_code_execution"
    DIRECT_MSR_WRITE = "direct_msr_write"
    DIRECT_CR_WRITE = "direct_control_register_write"
    PCI_CONFIG_ACCESS = "pci_config_access"
    DIRECT_PORT_IO = "direct_port_io"

    # Phase 10: Missing privileged instruction detection
    DEBUG_REGISTER_WRITE = "debug_register_write"
    GDT_IDT_MODIFICATION = "gdt_idt_modification"
    TLB_INVALIDATION = "tlb_invalidation"
    PROCESSOR_STATE_MANIPULATION = "processor_state_manipulation"

    # Phase 11: Anti-debug and anti-reversing detection
    ANTI_DEBUG_TIMING = "anti_debug_timing"       # rdtsc timing checks
    ANTI_DEBUG_HYPERVISOR = "anti_debug_hypervisor"  # cpuid/SVM/VMX detection
    ANTI_DEBUG_TRAP = "anti_debug_trap"            # int 3, icebp, etc.
    ANTI_DEBUG_NMI = "anti_debug_nmi"              # NMI callback manipulation
    ANTI_DEBUG_EXCEPTION = "anti_debug_exception"  # SEH-based anti-debug
    ANTI_DEBUG_SYSTEM_FLAG = "anti_debug_system_flag"  # NtGlobalFlag, KdDebuggerEnabled
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    DEAD_CODE_INJECTION = "dead_code_injection"
    PACKED_BINARY = "packed_binary"
    STRING_ENCRYPTION = "string_encryption"
    API_HASHING = "api_hashing"

    # Phase 13: Kernel hook detection
    INLINE_HOOK = "inline_hook"
    SSDT_HOOK = "ssdt_hook"
    IDT_HOOK = "idt_hook"
    CODE_SELF_CHECK = "code_self_check"
    IAT_HOOK = "iat_hook"
    EAT_HOOK = "eat_hook"
    # Phase 2: VMX / EPT virtualization detection
    VMX_INSTRUCTION = "vmx_instruction"
    EPT_MANIPULATION = "ept_manipulation"
    HYPERVISOR_SETUP = "hypervisor_setup"
    # Phase 3: VMProtect / Themida virtualization detection
    VM_PROTECT = "vm_protect"
    VM_ENTRY = "vm_entry"
    VM_HANDLER = "vm_handler"
    # Phase 4: DKOM / hidden process detection
    DKOM_PROCESS_UNLINK = "dkom_process_unlink"
    DKOM_THREAD_UNLINK = "dkom_thread_unlink"
    DKOM_CID_TABLE = "dkom_cid_table"
    DKOM_TOKEN = "dkom_token"
    # Phase 5: ALPC/LPC cross-driver communication
    ALPC_COMMUNICATION = "alpc_communication"
    ALPC_PORT_NAME = "alpc_port_name"
    ALPC_SHARED_MEMORY = "alpc_shared_memory"
    ALPC_MESSAGE = "alpc_message"
    # Phase 5b: Named pipe communication
    NAMED_PIPE = "named_pipe"
    # Phase 6b: Kernel APC / Thread injection
    APC_INJECTION = "apc_injection"
    # Phase 7: Registry callback protection
    REGISTRY_CALLBACK = "registry_callback"
    # Phase 8: Object callback protection
    OBJECT_CALLBACK = "object_callback"

    # Dynamic analysis (Phase 2)
    DYNAMIC_CRASH_CONFIRMED = "dynamic_crash_confirmed"
    DYNAMIC_IOCTL_VALIDATED = "dynamic_ioctl_validated"
    DYNAMIC_HOOK_DETECTED = "dynamic_hook_detected"
    DYNAMIC_NEW_DEVICE = "dynamic_new_device"
    DYNAMIC_REGISTRY_WRITE = "dynamic_registry_write"
    DYNAMIC_FILE_CREATED = "dynamic_file_created"
    DYNAMIC_PROCESS_INJECTION = "dynamic_process_injection"

    # User-mode analysis (Phase 1A)
    DANGEROUS_USERMODE_IMPORT = "dangerous_usermode_import"
    COM_INTERFACE_EXPOSED = "com_interface_exposed"
    SERVICE_REGISTRATION = "service_registration"
    EMBEDDED_DRIVER = "embedded_driver"
    USERMODE_KERNEL_BRIDGE = "usermode_kernel_bridge"

    # Multi-driver correlation (Phase 1C)
    CROSS_DRIVER_ALPC = "cross_driver_alpc"
    CROSS_DRIVER_NAMED_PIPE = "cross_driver_named_pipe"
    CROSS_DRIVER_SHARED_DEVICE = "cross_driver_shared_device"
    CROSS_DRIVER_ATTACK_CHAIN = "cross_driver_attack_chain"
    SHARED_IOCTL_PROTOCOL = "shared_ioctl_protocol"

    # Enhanced deobfuscation (Phase 1B)
    CFF_DEOBFUSCATED = "cff_deobfuscated"
    STRING_DECRYPTED = "string_decrypted"
    API_HASH_RESOLVED_EXTENDED = "api_hash_resolved_extended"

    # Deep reverse engineering
    STACK_STRING_RECONSTRUCTED = "stack_string_reconstructed"
    WIDE_STRING_FOUND = "wide_string_found"
    DATA_STRUCTURE_IDENTIFIED = "data_structure_identified"
    XREF_HOT_DATA = "xref_hot_data"
    WHITELIST_CHECK_DETECTED = "whitelist_check_detected"
    BLACKLIST_CHECK_DETECTED = "blacklist_check_detected"
    ARRAY_ITERATION_CMP = "array_iteration_cmp"
    STRUCT_INFERRED = "struct_inferred"
    CPP_OBJECT_DETECTED = "cpp_object_detected"
    VALIDATED_SURFACE = "validated_surface"
    SECURITY_MECHANISM = "security_mechanism"

    # Data content semantic analysis
    STRING_TABLE_IDENTIFIED = "string_table_identified"
    DATA_CONTENT_ANALYZED = "data_content_analyzed"

    # Deep protection mechanism analysis
    CALL_CHAIN_ANALYZED = "call_chain_analyzed"
    CALLBACK_RESOLVED = "callback_resolved"
    FILTER_CALLBACK_ANALYZED = "filter_callback_analyzed"

    # Phase 14: Dynamic memory table positioning
    MEMORY_MAP_ANALYZED = "memory_map_analyzed"
    RUNTIME_ALLOC_TABLE = "runtime_alloc_table"
    WHITELIST_TABLE_DETECTED = "whitelist_table_detected"
    STRING_RVA_RESOLVED = "string_rva_resolved"
    DISPATCH_TABLE_RESOLVED = "dispatch_table_resolved"
    XREF_TABLE_USAGE = "xref_table_usage"

    # Phase 2b: EPT/VT-x hook detection enhancement
    EPTP_CONSTRUCTION = "eptp_construction"
    VMCS_FIELD_WRITE = "vmcs_field_write"
    EPT_HOOK_PATTERN = "ept_hook_pattern"

    # Phase 15: Communication protocol analysis
    IOCTL_COMMAND_INFERRED = "ioctl_command_inferred"
    ALPC_PORT_EXPOSED = "alpc_port_exposed"
    NAMED_PIPE_EXPOSED = "named_pipe_exposed"

    # Phase 16: Minifilter rule analysis
    MINIFILTER_RULES_ANALYZED = "minifilter_rules_analyzed"

    # Phase 17: Memory map analysis
    MEMORY_MAP_POSITIONING = "memory_map_positioning"

    # Phase 18: VMX/EPT deep analysis
    VMX_DEEP_ANALYZED = "vmx_deep_analyzed"

    # Phase 20: DSE bypass / PatchGuard trigger detection
    DSE_BYPASS = "dse_bypass"
    PATCHGUARD_TRIGGER = "patchguard_trigger"
    ETW_BYPASS = "etw_bypass"
    KPP_CALLBACK_DISABLE = "kpp_callback_disable"


@dataclass
class Evidence:
    """Traceable evidence supporting a finding."""
    type: str        # "import" | "string" | "instruction_pattern" | "cfg_path"
    location: str    # e.g. "IAT@0x12340"
    snippet: str     # Related code or data snippet
    rule_id: str     # Triggered rule ID


@dataclass
class Finding:
    """A single analysis finding."""
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    description: str
    function_address: int = 0
    instruction_address: int = 0
    api_name: str = ""
    ioctl_code: int = 0
    context: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "function_address": hex(self.function_address) if self.function_address else 0,
            "instruction_address": hex(self.instruction_address) if self.instruction_address else 0,
            "api_name": self.api_name,
            "ioctl_code": hex(self.ioctl_code) if self.ioctl_code else 0,
            "context": self.context,
            "evidence": [
                e if isinstance(e, dict) else {"type": e.type, "location": e.location, "snippet": e.snippet, "rule_id": e.rule_id}
                for e in self.evidence
            ],
        }


# ---------------------------------------------------------------------------
# Layer 4: Scoring & Reporting
# ---------------------------------------------------------------------------

def score_level(score: float) -> str:
    """Map numeric risk score to severity level string."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 1.0:
        return "LOW"
    return "NONE"


@dataclass
class RiskScore:
    """Aggregate risk score for a sample."""
    overall: float  # 0.0 - 10.0
    breakdown: dict[str, float] = field(default_factory=dict)

    @property
    def level(self) -> str:
        return score_level(self.overall)


@dataclass
class Report:
    """Complete analysis report for a sample or batch."""
    samples: list[Sample]
    timestamp: str
    tool_version: str
    backend: str
    total_analyzed: int = 0
    total_findings: int = 0
    summary: dict[str, Any] = field(default_factory=dict)

    def top_n(self, n: int = 10) -> list[Sample]:
        """Return top-N samples by risk score."""
        return sorted(
            [s for s in self.samples if s.risk_score > 0],
            key=lambda s: s.risk_score,
            reverse=True,
        )[:n]
