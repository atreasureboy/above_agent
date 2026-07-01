"""DriverScope — ARM64 Analysis Enhancement.

Extends the existing analysis pipeline with ARM64-specific support:
  - ARM64 dangerous API intrinsics (compiler builtins)
  - ARM64 validation pattern recognition (cmp + b.cond)
  - ARM64 taint source/sink patterns (ldr/str instead of mov [reg+offset])
  - ARM64 calling convention awareness (x0-x7 for first 8 params)

These are integrated into the existing pipeline by extending the
configuration constants in src/config/defaults.py and the taint tracker
in src/analysis/dataflow/input_tracker.py.

Usage:
    # ARM64 detection is automatic — when is_arm64=True on DisassemblyResult,
    # all analyzers use ARM64-specific patterns.
    from src.analysis.core.arm64 import ARM64_TAINT_SOURCES, ARM64_DANGEROUS_SINKS
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# ARM64 compiler intrinsics / builtins
# These are the ARM64 equivalents of x64 privileged instructions and APIs.
# ---------------------------------------------------------------------------

# ARM64 MSR access intrinsics (via compiler builtins or inline asm)
ARM64_MSR_INTRINSICS = {
    "__readmsr",       # Still valid on ARM64 via emulation layer
    "__writemsr",
    "__get_AIDR_EL0",  # ARM ID register
    "__set_SCTLR_EL1", # System control register (privileged)
    "__get_SCTLR_EL1",
    "__set_TTBR0_EL1", # Translation table base (page table manipulation)
    "__get_TTBR0_EL1",
    "__set_TTBR1_EL1",
    "__get_TTBR1_EL1",
    "__set_VBAR_EL1",  # Vector base address (exception vector manipulation)
    "__get_VBAR_EL1",
}

# ARM64 system registers that indicate privileged access patterns
ARM64_SYSTEM_REGS = {
    "SCTLR_EL1": "System Control — cache/MMU configuration",
    "TTBR0_EL1": "Translation Table Base 0 — page table manipulation",
    "TTBR1_EL1": "Translation Table Base 1 — kernel page tables",
    "VBAR_EL1": "Vector Base Address — exception vector hijacking",
    "TPIDR_EL1": "Thread ID — thread-local state manipulation",
    "SPSR_EL1": "Saved Program Status — exception state manipulation",
    "ELR_EL1": "Exception Link — exception return address control",
    "ESR_EL1": "Exception Syndrome — exception cause inspection",
    "MAIR_EL1": "Memory Attribute Indirection — memory type configuration",
    "TCR_EL1": "Translation Control — page table configuration",
}

# ---------------------------------------------------------------------------
# ARM64-specific dangerous sinks
# These APIs have ARM64-specific variants or are commonly used in ARM64 drivers.
# ---------------------------------------------------------------------------

ARM64_DANGEROUS_SINKS = {
    # ARM64 cache maintenance (can be abused for code injection)
    "__clean_dcache",
    "__invalidate_icache",
    "__flush_dcache",
    "__clean_invalidate_dcache",
    # ARM64 memory barrier intrinsics
    "__dsb",       # Data Synchronization Barrier
    "__dmb",       # Data Memory Barrier
    "__isb",       # Instruction Synchronization Barrier
    # ARM64 atomic operations (can be used for race condition exploitation)
    "__ldxr",      # Load Exclusive Register
    "__stxr",      # Store Exclusive Register
    "__ldar",      # Load-Acquire Register
    "__stlr",      # Store-Release Register
    # ARM64 page table manipulation
    "__tlbi_vmalle1is",   # TLB invalidate all, EL1, inner shareable
    "__tlbi_vae1",        # TLB invalidate by VA, EL1
    "__dsb_sy",
    "__isb_sy",
}

# ---------------------------------------------------------------------------
# ARM64 validation patterns
# These are the ARM64 equivalents of x64 validation branch patterns.
# ---------------------------------------------------------------------------

# ARM64 conditional branch mnemonics used for validation
ARM64_VALIDATION_BRANCHES_FULL = {
    "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
    "b.lo", "b.ls", "b.hi", "b.hs",
    "b.mi", "b.pl",
    "b.vs", "b.vc",
    "cbz", "cbnz",       # Compare and Branch on Zero
    "tbz", "tbnz",       # Test Bit and Branch
}

# ARM64 size check patterns
# ARM64 cmp instructions: "cmp w0, #0x1000" or "cmp x0, x1"
ARM64_CMP_PATTERNS = ["cmp", "cmn", "subs", "subs"]

# ---------------------------------------------------------------------------
# ARM64 taint source patterns
# ARM64 uses ldr instead of mov for memory access
# ---------------------------------------------------------------------------

ARM64_TAINT_SOURCE_PATTERNS = {
    # Direct IRP field access via ldr
    "ldr x8, [x0, #0x60]": "SystemBuffer (METHOD_BUFFERED)",
    "ldr x8, [x0, #0x18]": "UserBuffer (METHOD_NEITHER)",
    "ldr x8, [x0, #0x98]": "Parameters",
}

# ---------------------------------------------------------------------------
# ARM64 calling convention registers
# First 8 parameters in x0-x7 (AAPCS64)
# ---------------------------------------------------------------------------

ARM64_PARAM_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
ARM64_RETURN_REG = "x0"

# ---------------------------------------------------------------------------
# ARM64 validation API patterns
# Same as x64, but with ARM64-specific instruction patterns
# ---------------------------------------------------------------------------

ARM64_PROBE_PATTERNS = {
    "ProbeForRead": "ProbeForRead(x0, x1, x2)",     # Buffer, Length, Alignment
    "ProbeForWrite": "ProbeForWrite(x0, x1, x2)",
}

# ---------------------------------------------------------------------------
# ARM64-specific ordinal mappings (for import-by-ordinal on ARM64)
# ---------------------------------------------------------------------------

ARM64_ORDINAL_EXTENSIONS = {
    # Additional ARM64-specific exports
    "ntoskrnl_700": "KeFlushInstructionCache",
    "ntoskrnl_701": "KeInvalidateAllCaches",
    "ntoskrnl_702": "HalGetInterruptVectorEx",
    "ntoskrnl_703": "IoConnectInterruptEx",
}

# ---------------------------------------------------------------------------
# Integration helper
# ---------------------------------------------------------------------------

def get_arm64_enhanced_dangerous_sinks() -> set[str]:
    """Return the full set of dangerous sinks including ARM64-specific ones."""
    from src.analysis.dataflow.input_tracker import DANGEROUS_SINKS
    return DANGEROUS_SINKS | ARM64_DANGEROUS_SINKS


def get_arm64_enhanced_api_set() -> set[str]:
    """Return the full set of dangerous APIs including ARM64 intrinsics."""
    from src.config.defaults import DANGEROUS_API_SET
    return DANGEROUS_API_SET | ARM64_MSR_INTRINSICS | ARM64_DANGEROUS_SINKS
