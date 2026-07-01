"""
DriverScope — VMX / EPT Virtualization Detector.

Detects hardware-assisted virtualization and hypervisor techniques in kernel drivers:

1. **VMX Instructions**: VMXON, VMXOFF, VMLAUNCH, VMRESUME, VMREAD, VMWRITE,
   VMCLEAR, VMPTRLD, VMPTRST, INVEPT, INVVPID, VMFUNC.
   These indicate the driver is setting up or managing a Type-2 hypervisor
   (Blue Pill / hardware-assisted rootkit).

2. **EPT / SLAT Manipulation**: EPT pointer construction, INVEPT/INVVPID cache
   flushes, EPTP (EPT Pointer) setup with memory type / walk-length encoding.
   Used for hidden page tables, memory stealth, and hooking.

3. **Hypervisor Setup**: VMXON region initialization (setting the VMX revision ID),
   CR4.VMXE bit enablement, VMCS (Virtual Machine Control Structure) setup
   sequences, and VMX feature detection via CPUID leaf 0x01 / 0x0A.

4. **EPTP Construction**: Detects Extended Page Table Pointer construction patterns
   — memory type encoding (WB=6, UC=0), page-walk length (4 = value 3), and
   EPT_POINTER VMCS field writes.

5. **VMCS Field Analysis**: Tracks vmwrite/vmread targets using known VMCS field
   encodings to infer hypervisor configuration (guest CR3, EPT pointer, host RIP,
   MSR bitmaps, etc.).

6. **EPT Hook Pattern Recognition**: Detects EPT-based hook characteristics —
   page table-like data structures, INVEPT context invalidation types, and
   memory-type manipulation suggesting page-level interception.

These techniques are used by:
- Commercial security products (360, Tencent PC Manager) for kernel protection
- Malware / rootkits (Blue Pill, Darkhalo, BlackLotus) for stealth
- Legitimate hypervisors (Hyper-V, VirtualBox) — but NOT typically in 3rd-party drivers
"""

from __future__ import annotations

from src.models import (
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)
from src.analysis.analyzer import Analyzer


# ---------------------------------------------------------------------------
# 1. VMX Instruction Detection
# ---------------------------------------------------------------------------

# All x86-64 VMX instructions
VMX_INSTRUCTIONS = {
    # VMX lifecycle
    "vmxon": "Enter VMX root operation",
    "vmxoff": "Leave VMX root operation",
    # VMCS management
    "vmclear": "Clear VMCS cache",
    "vmptrld": "Load current VMCS pointer",
    "vmptrst": "Store current VMCS pointer",
    "vmread": "Read field from VMCS",
    "vmwrite": "Write field to VMCS",
    # VM execution
    "vmlaunch": "Launch VM (first entry)",
    "vmresume": "Resume VM (subsequent entries)",
    # Cache maintenance
    "invept": "Invalidate EPT mappings",
    "invvpid": "Invalidate VPID mappings",
    # Nested / extended
    "vmfunc": "Invoke VM function (EPT switching, etc.)",
}

# Instructions that suggest VMX but are not VMX-specific
VMX_HINT_INSTRUCTIONS = {
    "xsetbv": "Set XCR (Extended Control Register) — often paired with VMX setup",
    "xgetbv": "Get XCR — VMX feature probing",
}


def detect_vmx_instructions(ir: DisassemblyResult) -> list[Finding]:
    """Detect VMX instruction usage in the binary.

    Each VMX instruction is a strong indicator of hypervisor-related code.
    Grouped by function for correlated findings.
    """
    findings: list[Finding] = []

    func_vmx: dict[int, list[tuple[str, str, int]]] = {}  # func_addr -> [(insn_name, desc, addr)]

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        for block in cfg.blocks.values():
            for insn in block.instructions:
                mnemonic = insn.mnemonic.lower()
                if mnemonic in VMX_INSTRUCTIONS:
                    func_vmx.setdefault(func_addr, []).append(
                        (mnemonic, VMX_INSTRUCTIONS[mnemonic], insn.address)
                    )

    if not func_vmx:
        return findings

    for func_addr, vmx_list in func_vmx.items():
        insn_names = [name for name, _, _ in vmx_list]
        insn_descs = [desc for _, desc, _ in vmx_list]
        insn_addrs = [addr for _, _, addr in vmx_list]

        # Lifecycle instructions (vmxon/vmxoff) are the strongest signal
        has_lifecycle = any(n in ("vmxon", "vmxoff") for n in insn_names)
        # VMCS operations indicate full hypervisor management
        has_vmcs_ops = any(n in ("vmread", "vmwrite", "vmlaunch", "vmresume") for n in insn_names)
        # EPT cache flush indicates EPT management
        has_ept_flush = any(n in ("invept", "invvpid") for n in insn_names)

        if has_lifecycle:
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        elif has_vmcs_ops:
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        elif has_ept_flush:
            severity = Severity.HIGH
            confidence = Confidence.HIGH
        else:
            severity = Severity.HIGH
            confidence = Confidence.MEDIUM

        findings.append(
            Finding(
                category=FindingCategory.VMX_INSTRUCTION,
                severity=severity,
                confidence=confidence,
                description=(
                    f"Function sub_{func_addr:X}: VMX instructions detected: "
                    f"{', '.join(insn_names)}. "
                    f"This driver manipulates Intel VT-x hardware virtualization."
                ),
                function_address=func_addr,
                instruction_address=insn_addrs[0],
                context={
                    "vmx_instructions": insn_names,
                    "descriptions": insn_descs,
                    "addresses": [hex(a) for a in insn_addrs],
                    "has_vmx_lifecycle": has_lifecycle,
                    "has_vmcs_operations": has_vmcs_ops,
                    "has_ept_flush": has_ept_flush,
                },
                evidence=[
                    Evidence(
                        type="instruction_pattern",
                        location=f"sub_{func_addr:X}",
                        snippet=f"VMX: {', '.join(insn_names[:5])}",
                        rule_id="VMX_INSN",
                    )
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# 2. EPT / SLAT Manipulation Detection
# ---------------------------------------------------------------------------

# EPT-related patterns in instructions or strings
EPT_INDICATORS = {
    # String-level
    "EPTP": "EPT Pointer structure",
    "EptPointer": "EPT pointer variable name",
    "ept_pointer": "EPT pointer variable name",
    "EPT Violation": "EPT violation handler reference",
    "ept_violation": "EPT violation handler reference",
    "INVEPT": "Invalidate EPT cache reference",
    "INVVPID": "Invalidate VPID cache reference",
    "SLAT": "Second Level Address Table reference",
    "Extended Page Table": "Full EPT name reference",
    # Page table related strings
    "PML4": "Page Map Level 4 — EPT page table structure",
    "PDPT": "Page Directory Pointer Table — EPT page table structure",
    "PML4E": "PML4 Entry — EPT page table",
    "PDPE": "PDP Entry — EPT page table",
    "PDE": "Page Directory Entry — EPT page table",
    "PTE": "Page Table Entry — EPT page table",
    # Memory type encoding
    "UC-": "Uncacheable memory type in EPT",
    "WB": "Write-Back memory type (EPT default)",
}


def detect_ept_manipulation(ir: DisassemblyResult) -> list[Finding]:
    """Detect EPT / SLAT manipulation patterns.

    Combines instruction-level detection (INVEPT, INVVPID, mov to cr3/cr4
    with VMXE-related bit patterns) and string-level indicators.
    """
    findings: list[Finding] = []

    # 1. String-level EPT indicators
    ept_strings = []
    for s in ir.strings:
        for pattern, desc in EPT_INDICATORS.items():
            if pattern in s:
                ept_strings.append((s, desc))

    # 2. Instruction-level: VMX instructions that manage EPT
    ept_insns: list[tuple[str, int]] = []  # [(mnemonic, addr)]
    cr3_writes: list[int] = []  # Functions that write CR3 (EPTP / page table switch)
    cr4_vmx_patterns: list[tuple[int, str]] = []  # Functions with CR4 VMXE bit manipulation

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        for block in cfg.blocks.values():
            for insn in block.instructions:
                mnemonic = insn.mnemonic.lower()

                # EPT-specific VMX instructions
                if mnemonic in ("invept", "invvpid", "vmfunc"):
                    ept_insns.append((mnemonic, insn.address))

                # CR3 write — may be switching to EPT page tables
                if mnemonic == "mov" and "cr3" in insn.operands.lower():
                    cr3_writes.append(func_addr)

                # CR4 manipulation — VMXE is bit 13 (0x2000)
                # Pattern: mov cr4, ... with values that include VMXE bit
                if mnemonic == "mov" and "cr4" in insn.operands.lower():
                    ops = insn.operands.lower()
                    # VMXE = bit 13 = 0x2000
                    for val in ("0x2000", "0x20000", "8192"):
                        if val in ops:
                            cr4_vmx_patterns.append((func_addr, ops))
                            break
                    # Also detect: or reg, 0x2000 ; mov cr4, reg
                    if "or" in ops and "0x2000" in ops:
                        cr4_vmx_patterns.append((func_addr, ops))

    if not ept_strings and not ept_insns:
        return findings

    # Deduplicate strings
    seen_strings = set()
    unique_ept_strings = []
    for s, desc in ept_strings:
        if s not in seen_strings:
            seen_strings.add(s)
            unique_ept_strings.append((s, desc))

    # Determine severity
    has_ept_flush_insn = any(m in ("invept", "invvpid") for m, _ in ept_insns)
    has_vmfunc = any(m == "vmfunc" for m, _ in ept_insns)
    has_cr4_vmx = len(cr4_vmx_patterns) > 0

    if has_ept_flush_insn or has_vmfunc:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_cr4_vmx and ept_strings:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    str_snippets = [s for s, _ in unique_ept_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.EPT_MANIPULATION,
            severity=severity,
            confidence=confidence,
            description=(
                f"EPT/SLAT manipulation detected. "
                f"Strings: {', '.join(str_snippets[:5])}. "
                f"EPT instructions: {', '.join(m for m, _ in ept_insns)}. "
                f"This driver may manipulate Extended Page Tables for stealth."
            ),
            context={
                "ept_strings": str_snippets,
                "ept_instructions": [m for m, _ in ept_insns],
                "ept_instruction_addresses": [hex(a) for _, a in ept_insns],
                "cr3_write_functions": list(set(hex(a) for a in cr3_writes)),
                "cr4_vmx_patterns": [
                    {"function": hex(f), "operands": o} for f, o in cr4_vmx_patterns
                ],
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings + instructions",
                    snippet=str_snippets[0] if str_snippets else "EPT instruction pattern",
                    rule_id="EPT_MANIPULATION",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. Hypervisor Setup Detection
# ---------------------------------------------------------------------------

# CPUID leaves related to VMX
VMX_CPUID_LEAVES = {
    "0x1": "VMX flag (ECX bit 5) — basic VMX support",
    "0xa": "VMX capability enumeration",
    "0x40000001": "Hyper-V VMX compatibility",
}

# Strings that suggest hypervisor setup code
HYPERVISOR_SETUP_STRINGS = {
    "VMXON": "VMXON region initialization",
    "VMCS": "VMCS structure reference",
    "vmcs_revision_id": "VMCS revision ID — hypervisor setup",
    "VmcsRevision": "VMCS revision ID — hypervisor setup",
    "launch_state": "VMLAUNCH/VMRESUME state tracking",
    "vmx_enabled": "VMX enablement flag",
    "Hypervisor": "Hypervisor reference",
    "vmm_init": "Virtual Machine Monitor initialization",
    "virtual_machine": "Virtual machine reference",
    "root_mode": "VMX root operation mode",
    "guest_mode": "VMX guest operation mode",
    "host_stack": "VMX host stack pointer",
    "guest_rip": "VMCS guest RIP field",
    "host_rip": "VMCS host RIP field",
}


def detect_hypervisor_setup(ir: DisassemblyResult) -> list[Finding]:
    """Detect hypervisor setup and initialization patterns.

    Looks for:
    1. VMXON region setup (write VMX revision ID to memory)
    2. CPUID checks for VMX support
    3. Strings indicating hypervisor/VMM initialization
    4. CR4.VMXE enablement sequence
    """
    findings: list[Finding] = []

    # 1. String-level hypervisor indicators
    hyp_strings = []
    for s in ir.strings:
        for pattern, desc in HYPERVISOR_SETUP_STRINGS.items():
            if pattern.lower() in s.lower():
                hyp_strings.append((s, desc))

    # 2. CPUID usage with VMX-related leaf values
    cpuid_vmx_leaves: list[tuple[int, str]] = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        for block in cfg.blocks.values():
            for insn in block.instructions:
                if insn.mnemonic.lower() == "cpuid":
                    # Check if preceding instructions set up a VMX-related leaf
                    # This is a heuristic — we look at the string context
                    cpuid_vmx_leaves.append((func_addr, hex(insn.address)))

    # 3. CR4 VMXE enablement (also tracked in EPT, but relevant here)
    cr4_vmx_funcs = set()
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue
        for block in cfg.blocks.values():
            for insn in block.instructions:
                if insn.mnemonic.lower() == "mov" and "cr4" in insn.operands.lower():
                    ops = insn.operands.lower()
                    if "0x2000" in ops:  # VMXE bit
                        cr4_vmx_funcs.add(func_addr)

    if not hyp_strings and not cpuid_vmx_leaves:
        return findings

    # Deduplicate strings
    seen = set()
    unique_strings = []
    for s, desc in hyp_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((s, desc))

    has_vmxon_ref = any("VMXON" in s for s, _ in unique_strings)
    has_vmcs_ref = any("VMCS" in s.upper() for s, _ in unique_strings)
    has_vmm_ref = any("vmm" in s.lower() for s, _ in unique_strings)

    if has_vmxon_ref or has_vmm_ref:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_vmcs_ref and (cpuid_vmx_leaves or cr4_vmx_funcs):
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    str_snippets = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.HYPERVISOR_SETUP,
            severity=severity,
            confidence=confidence,
            description=(
                f"Hypervisor/VMM setup detected: {len(unique_strings)} indicator(s). "
                f"Strings: {', '.join(str_snippets[:5])}. "
                f"CPUID references: {len(cpuid_vmx_leaves)}. "
                f"This driver may initialize a hardware hypervisor."
            ),
            context={
                "hypervisor_strings": str_snippets,
                "cpuid_references": [{"function": hex(f), "address": a} for f, a in cpuid_vmx_leaves],
                "cr4_vmx_enable_functions": [hex(f) for f in cr4_vmx_funcs],
                "has_vmxon_reference": has_vmxon_ref,
                "has_vmcs_reference": has_vmcs_ref,
                "has_vmm_reference": has_vmm_ref,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_snippets[0] if str_snippets else "hypervisor setup indicator",
                    rule_id="HYPERVISOR_SETUP",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 4. EPTP Construction Detection
# ---------------------------------------------------------------------------

# VMCS field encodings (Intel SDM Vol 3C, Appendix B)
VMCS_FIELD_ENCODINGS: dict[int, str] = {
    0x0000201A: "EPT_POINTER",
    0x0000201E: "VPID",
    0x0000681A: "GUEST_CR3",
    0x00006C1A: "HOST_CR3",
    0x0000681C: "GUEST_PDPTE0",
    0x0000681E: "GUEST_PDPTE1",
    0x00006820: "GUEST_PDPTE2",
    0x00006822: "GUEST_PDPTE3",
    0x00002004: "MSR_BITMAPS_ADDRESS",
    0x00002006: "MSR_BITMAPS_ADDRESS_HIGH",
    0x00006C14: "HOST_IA32_EFER",
    0x00006C16: "HOST_IA32_PAT",
    0x00006826: "GUEST_IA32_EFER",
    0x00006828: "GUEST_IA32_PAT",
    0x0000401C: "PIN_BASED_VM_EXEC_CONTROL",
    0x0000401E: "CPU_BASED_VM_EXEC_CONTROL",
    0x00004020: "EXCEPTION_BITMAP",
    0x00006C18: "HOST_CR0",
    0x00006818: "GUEST_CR0",
    0x00006C1C: "HOST_CR4",
    0x00006824: "GUEST_CR4",
    0x00006C0A: "HOST_RSP",
    0x00006C08: "HOST_RIP",
    0x0000681E: "GUEST_RIP",
    0x00006820: "GUEST_RSP",
    0x0000441E: "SECONDARY_VM_EXEC_CONTROL",
}

# EPTP bit field definitions
EPTP_MEMORY_TYPES = {
    0: "Uncacheable (UC)",
    6: "Write-Back (WB)",
}
EPTP_PAGE_WALK_LENGTHS = {
    1: "2-level",
    2: "3-level",
    3: "4-level (standard x64)",
}

# INVEPT type encodings
INVEPT_TYPES: dict[int, str] = {
    1: "Individual context -- single EPTP invalidation",
    2: "Global context -- all EPTPs invalidation",
}


def detect_eptp_construction(ir: DisassemblyResult) -> list[Finding]:
    """Detect EPTP (Extended Page Table Pointer) construction patterns.

    The EPTP is a 64-bit value written to the EPT_POINTER VMCS field (0x201A).
    Its structure:
      - Bits 2:0: Memory type (0=UC, 6=WB)
      - Bits 5:3: Page-walk length minus 1 (3 = 4-level)
      - Bits 6:12: Reserved (must be 0)
      - Bits 63:N: PML4 page table base physical address

    Detection strategy:
    - Look for immediate values matching valid EPTP patterns
    - Look for vmwrite of EPT_POINTER field encoding (0x201A)
    """
    findings: list[Finding] = []
    eptp_constructors: list[dict[str, Any]] = []

    import re

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        eptp_field_write = False
        eptp_immediates: list[int] = []
        vmwrite_targets: list[int] = []

        for block in cfg.blocks.values():
            for insn in block.instructions:
                mnemonic = insn.mnemonic.lower()
                ops = insn.operands.lower()

                # Detect vmwrite with EPT_POINTER field
                if mnemonic == "vmwrite":
                    if "0x201a" in ops:
                        eptp_field_write = True
                        vmwrite_targets.append(0x201A)

                    # Extract immediate values that could be EPTP
                    match = re.search(r"0x([0-9a-fA-F]{4,16})", ops)
                    if match:
                        val = int(match.group(1), 16)
                        vmwrite_targets.append(val)

                # Detect large immediate values that could be EPTP
                if mnemonic == "mov":
                    match = re.search(r"0x([0-9a-fA-F]{4,16})", ops)
                    if match:
                        val = int(match.group(1), 16)
                        mem_type = val & 0x7
                        pwl = (val >> 3) & 0x7
                        if mem_type in (0, 6) and pwl in (1, 2, 3) and val > 0x1000:
                            reserved = (val >> 6) & 0x7F
                            # Real EPTP has a physical page address in bits 63:12,
                            # not a virtual address or MSR-like constant. Require
                            # PML4 base >= 1MB (typical physical RAM range).
                            pml4_base = val & ~0xFFF
                            if reserved == 0 and pml4_base >= 0x100000:
                                eptp_immediates.append(val)

        # Require genuine VMX context: either vmwrite to EPT_POINTER or
        # vmwrite to any VMCS field. Immediate values alone are not enough —
        # many drivers use 0xC0000010-style constants that accidentally match
        # the EPTP format (mem_type=0, pwl=2, reserved=0) but are not EPTP.
        if eptp_field_write or (eptp_immediates and vmwrite_targets):
            eptp_constructors.append({
                "func_addr": func_addr,
                "eptp_immediates": eptp_immediates,
                "vmwrite_targets": vmwrite_targets,
                "eptp_field_write": eptp_field_write,
            })

    if not eptp_constructors:
        return findings

    for ctor in eptp_constructors:
        func_addr = ctor["func_addr"]
        decoded_eptps = []
        for eptp in ctor["eptp_immediates"]:
            mem_type = eptp & 0x7
            pwl = (eptp >> 3) & 0x7
            pml4_base = eptp & ~0x3F
            decoded_eptps.append({
                "eptp_value": eptp,
                "memory_type": EPTP_MEMORY_TYPES.get(mem_type, f"Unknown({mem_type})"),
                "page_walk_length": EPTP_PAGE_WALK_LENGTHS.get(pwl, f"Unknown({pwl})"),
                "pml4_base": pml4_base,
            })

        findings.append(
            Finding(
                category=FindingCategory.EPTP_CONSTRUCTION,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description=(
                    f"Function sub_{func_addr:X}: EPTP construction detected. "
                    f"EPT pointer: {', '.join(f'0x{d['eptp_value']:X}' for d in decoded_eptps)}. "
                    f"Memory type: {', '.join(d['memory_type'] for d in decoded_eptps)}."
                ),
                function_address=func_addr,
                context={
                    "eptp_values": [d["eptp_value"] for d in decoded_eptps],
                    "decoded_eptps": decoded_eptps,
                    "vmwrite_targets": [hex(t) for t in ctor["vmwrite_targets"]],
                    "eptp_field_write": ctor["eptp_field_write"],
                },
                evidence=[
                    Evidence(
                        type="instruction_pattern",
                        location=f"sub_{func_addr:X}",
                        snippet=f"EPTP: {', '.join(f'0x{d['eptp_value']:X}' for d in decoded_eptps[:3])}",
                        rule_id="EPTP_CTOR",
                    )
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# 5. VMCS Field Analysis
# ---------------------------------------------------------------------------

def detect_vmcs_fields(ir: DisassemblyResult) -> list[Finding]:
    """Analyze VMCS field operations to infer hypervisor configuration.

    Detects vmwrite/vmread to known VMCS fields and classifies the
    hypervisor configuration being set up.
    """
    findings: list[Finding] = []
    vmcs_operations: list[dict[str, Any]] = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        vmwrite_fields: list[tuple[str, int]] = []
        vmread_fields: list[tuple[str, int]] = []

        for block in cfg.blocks.values():
            for insn in block.instructions:
                mnemonic = insn.mnemonic.lower()
                ops = insn.operands.lower()

                if mnemonic in ("vmwrite", "vmread"):
                    for field_enc, field_name in VMCS_FIELD_ENCODINGS.items():
                        hex_str = f"0x{field_enc:x}"
                        if hex_str in ops:
                            if mnemonic == "vmwrite":
                                vmwrite_fields.append((field_name, insn.address))
                            else:
                                vmread_fields.append((field_name, insn.address))
                            break

        if vmwrite_fields or vmread_fields:
            vmcs_operations.append({
                "func_addr": func_addr,
                "vmwrite_fields": vmwrite_fields,
                "vmread_fields": vmread_fields,
            })

    if not vmcs_operations:
        return findings

    for op in vmcs_operations:
        func_addr = op["func_addr"]
        written = [f for f, _ in op["vmwrite_fields"]]
        read = [f for f, _ in op["vmread_fields"]]

        critical_fields = {"EPT_POINTER", "GUEST_CR3", "HOST_RIP", "HOST_CR3",
                          "MSR_BITMAPS_ADDRESS"}
        has_critical = any(f in critical_fields for f in written)
        has_ept_config = "EPT_POINTER" in written
        has_guest_state = any(f.startswith("GUEST_") for f in written)
        has_host_state = any(f.startswith("HOST_") for f in written)

        severity = Severity.CRITICAL if has_critical else Severity.HIGH
        confidence = Confidence.HIGH if (has_ept_config or has_guest_state) else Confidence.MEDIUM

        findings.append(
            Finding(
                category=FindingCategory.VMCS_FIELD_WRITE,
                severity=severity,
                confidence=confidence,
                description=(
                    f"Function sub_{func_addr:X}: VMCS field operations. "
                    f"Written: {', '.join(written) if written else 'none'}. "
                    f"Read: {', '.join(read) if read else 'none'}."
                ),
                function_address=func_addr,
                context={
                    "vmwrite_fields": written,
                    "vmread_fields": read,
                    "has_ept_config": has_ept_config,
                    "has_guest_state_config": has_guest_state,
                    "has_host_state_config": has_host_state,
                },
                evidence=[
                    Evidence(
                        type="instruction_pattern",
                        location=f"sub_{func_addr:X}",
                        snippet=f"VMCS write: {', '.join(written[:5])}",
                        rule_id="VMCS_FIELD",
                    )
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# 6. EPT Hook Pattern Recognition
# ---------------------------------------------------------------------------

# EPT entry permission patterns
EPT_ENTRY_READ_ONLY = 0x1
EPT_ENTRY_WRITE_ONLY = 0x2
EPT_ENTRY_EXECUTE_ONLY = 0x4
EPT_ENTRY_READ_WRITE = 0x3
EPT_ENTRY_FULL_ACCESS = 0x7


def detect_ept_hook_patterns(ir: DisassemblyResult) -> list[Finding]:
    """Detect EPT hook pattern characteristics.

    EPT hooks intercept memory accesses via shadow page tables. Detection:
    1. INVEPT with type parameter analysis (individual vs global)
    2. Page-table-like data structures in .data/.rdata sections
    3. Execute-only or read-only EPT entry patterns
    """
    findings: list[Finding] = []

    # 1. Detect INVEPT with type parameter
    invept_types_found: list[tuple[int, str, int]] = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        for block in cfg.blocks.values():
            for insn in block.instructions:
                if insn.mnemonic.lower() == "invept":
                    ops = insn.operands.lower()
                    if "0x1" in ops or ", 1" in ops:
                        invept_types_found.append((1, "Individual context", func_addr))
                    elif "0x2" in ops or ", 2" in ops:
                        invept_types_found.append((2, "Global context", func_addr))
                    else:
                        invept_types_found.append((0, "Unknown type", func_addr))

    # 2. Detect page-table-like data structures
    page_table_structures = []
    for rva, ds in (ir.data_structures or {}).items():
        values = ds.get("values", [])
        if len(values) < 4:
            continue
        pt_like_count = 0
        for val in values:
            if isinstance(val, int) and val != 0:
                if val & 0x1 and (val & ~0xFFF) != 0:
                    pt_like_count += 1
        if pt_like_count >= len(values) * 0.5:
            page_table_structures.append({
                "rva": rva,
                "entry_count": len(values),
                "pt_like_count": pt_like_count,
            })

    # 3. Detect execute-only / read-only EPT entry patterns
    ept_entry_patterns = []
    for rva, ds in (ir.data_structures or {}).items():
        values = ds.get("values", [])
        xo_count = sum(1 for v in values if isinstance(v, int) and (v & 0x7) == EPT_ENTRY_EXECUTE_ONLY)
        ro_count = sum(1 for v in values if isinstance(v, int) and (v & 0x7) == EPT_ENTRY_READ_ONLY)
        if xo_count > 0 or ro_count > 0:
            ept_entry_patterns.append({
                "rva": rva,
                "execute_only_count": xo_count,
                "read_only_count": ro_count,
            })

    # Generate findings
    for inv_type, inv_desc, inv_func in invept_types_found:
        findings.append(
            Finding(
                category=FindingCategory.EPT_HOOK_PATTERN,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=(
                    f"Function sub_{inv_func:X}: INVEPT with {inv_desc} invalidation. "
                    f"Suggests targeted EPT context management."
                ),
                function_address=inv_func,
                context={
                    "invept_type": inv_type,
                    "invept_description": inv_desc,
                    "hook_type": "ept_context_invalidation",
                },
                evidence=[
                    Evidence(
                        type="instruction_pattern",
                        location=f"sub_{inv_func:X}",
                        snippet=f"INVEPT type={inv_type} ({inv_desc})",
                        rule_id="EPT_HOOK_INVEPT",
                    )
                ],
            )
        )

    for pt in page_table_structures:
        findings.append(
            Finding(
                category=FindingCategory.EPT_HOOK_PATTERN,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=(
                    f"Data at RVA 0x{pt['rva']:X}: possible EPT page table. "
                    f"{pt['pt_like_count']}/{pt['entry_count']} entries match PTE format."
                ),
                context={
                    "rva": pt["rva"],
                    "entry_count": pt["entry_count"],
                    "page_table_like_count": pt["pt_like_count"],
                    "hook_type": "ept_page_table_structure",
                },
                evidence=[
                    Evidence(
                        type="instruction_pattern",
                        location=f"data:0x{pt['rva']:X}",
                        snippet=f"{pt['pt_like_count']}/{pt['entry_count']} PTE-like",
                        rule_id="EPT_HOOK_PTABLE",
                    )
                ],
            )
        )

    for ep in ept_entry_patterns:
        if ep["execute_only_count"] > 0:
            findings.append(
                Finding(
                    category=FindingCategory.EPT_HOOK_PATTERN,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Data at RVA 0x{ep['rva']:X}: {ep['execute_only_count']} execute-only "
                        f"EPT entries (X=1,R=0,W=0) suggest code interception hook."
                    ),
                    context={
                        "rva": ep["rva"],
                        "execute_only_count": ep["execute_only_count"],
                        "hook_type": "execute_only_intercept",
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"data:0x{ep['rva']:X}",
                            snippet=f"{ep['execute_only_count']} XO EPT entries",
                            rule_id="EPT_HOOK_XO",
                        )
                    ],
                )
            )
        if ep["read_only_count"] > 0:
            findings.append(
                Finding(
                    category=FindingCategory.EPT_HOOK_PATTERN,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Data at RVA 0x{ep['rva']:X}: {ep['read_only_count']} read-only "
                        f"EPT entries (R=1,W=0,X=0) suggest monitoring hook."
                    ),
                    context={
                        "rva": ep["rva"],
                        "read_only_count": ep["read_only_count"],
                        "hook_type": "read_only_monitor",
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"data:0x{ep['rva']:X}",
                            snippet=f"{ep['read_only_count']} RO EPT entries",
                            rule_id="EPT_HOOK_RO",
                        )
                    ],
                )
            )

    return findings


# ---------------------------------------------------------------------------
# EptVmxDetector — Main plugin
# ---------------------------------------------------------------------------

class EptVmxDetector(Analyzer):
    """Detects hardware-assisted virtualization (VMX/EPT) in kernel drivers."""

    @property
    def name(self) -> str:
        return "EptVmxDetector"

    @property
    def description(self) -> str:
        return (
            "Detects Intel VT-x / VMX instructions, EPT/SLAT manipulation, "
            "and hypervisor setup patterns."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. VMX instruction detection
        vmx_findings = detect_vmx_instructions(ir)
        findings.extend(vmx_findings)

        # 2. EPT / SLAT manipulation detection
        ept_findings = detect_ept_manipulation(ir)
        findings.extend(ept_findings)

        # 3. Hypervisor setup detection
        hyp_findings = detect_hypervisor_setup(ir)
        findings.extend(hyp_findings)

        # 4. EPTP construction detection
        eptp_findings = detect_eptp_construction(ir)
        findings.extend(eptp_findings)

        # 5. VMCS field analysis
        vmcs_findings = detect_vmcs_fields(ir)
        findings.extend(vmcs_findings)

        # 6. EPT hook pattern recognition
        hook_findings = detect_ept_hook_patterns(ir)
        findings.extend(hook_findings)

        return findings
