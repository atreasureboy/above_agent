"""
DriverScope — Unpacking Strategy Database.

Maps known packers/protectors to optimal unpacking strategies.
Each strategy includes step-by-step guides and tool recommendations.

Categories:
1. Simple Packers (UPX, MPRESS, etc.) — static unpacking
2. Runtime Packers (ASPack, PECompact, etc.) — semi-dynamic
3. Commercial Protectors (VMProtect, Themida, etc.) — full dynamic
4. Custom Packers — heuristic-based approach

Usage:
    from src.analysis.preprocessing.unpack_strategies import (
        get_strategy, PACKER_DATABASE, UnpackingStrategy
    )

    strategy = get_strategy("UPX")
    if strategy:
        steps = strategy.get_steps(sample_info)
        for step in steps:
            print(f"  {step.description}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class UnpackMethod(Enum):
    """Unpacking method category."""
    STATIC = "static"            # No execution needed
    SEMI_DYNAMIC = "semi_dynamic"  # Execute in controlled environment
    DYNAMIC = "dynamic"          # Full sandbox + instrumentation
    MANUAL = "manual"            # Requires manual analysis


class Difficulty(Enum):
    """Difficulty level for unpacking."""
    TRIVIAL = "trivial"          # One-click unpack
    EASY = "easy"                # Standard tools sufficient
    MODERATE = "moderate"        # Requires some expertise
    HARD = "hard"                # Commercial protector
    EXPERT = "expert"            # State-of-the-art protection


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class UnpackStep:
    """A single step in an unpacking strategy."""
    step_number: int = 0
    title: str = ""
    description: str = ""
    tool: str = ""               # Tool to use (e.g., "upx", "frida", "x64dbg")
    tool_args: str = ""          # Arguments for the tool
    expected_output: str = ""    # What to expect after this step
    on_failure: str = ""         # What to do if this step fails
    is_critical: bool = True     # If False, can be skipped


@dataclass
class UnpackingStrategy:
    """Complete unpacking strategy for a packer type."""
    packer_name: str = ""
    packer_version: str = ""     # Version range (e.g., "1.0-3.8.4")
    method: UnpackMethod = UnpackMethod.STATIC
    difficulty: Difficulty = Difficulty.EASY
    description: str = ""
    steps: list[UnpackStep] = field(default_factory=list)
    tools_required: list[str] = field(default_factory=list)
    success_rate: float = 0.0    # Estimated success rate (0-1)
    anti_debug: bool = False     # Has anti-debug protections
    anti_vm: bool = False        # Has anti-VM protections
    anti_dump: bool = False      # Has anti-dump protections
    iat_encryption: bool = False # IAT is encrypted
    code_virtualization: bool = False  # Uses code virtualization
    notes: list[str] = field(default_factory=list)

    def get_steps(self, sample_info: dict | None = None) -> list[UnpackStep]:
        """Get unpacking steps, optionally customized for the sample."""
        return list(self.steps)


# ---------------------------------------------------------------------------
# Packer Database
# ═══════════════════════════════════════════════════════════════════════════

PACKER_DATABASE: dict[str, UnpackingStrategy] = {}


def _register_strategy(strategy: UnpackingStrategy) -> None:
    """Register an unpacking strategy."""
    PACKER_DATABASE[strategy.packer_name.upper()] = strategy


# ── UPX ─────────────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="UPX",
    packer_version="0.5-4.0.2",
    method=UnpackMethod.STATIC,
    difficulty=Difficulty.TRIVIAL,
    description="Ultimate Packer for eXecutables — most common packer. "
                "Uses LZMA/NRV2B compression. Easily unpacked with official tool.",
    tools_required=["upx"],
    success_rate=0.99,
    steps=[
        UnpackStep(1, "Verify UPX", "Confirm sample is UPX-packed by checking section names (UPX0/UPX1/UPX2)",
                   tool="file", tool_args="", expected_output="UPX compressed"),
        UnpackStep(2, "Static Unpack", "Run UPX decompression",
                   tool="upx", tool_args="-d -o unpacked.exe packed.exe",
                   expected_output="Decompressed PE file"),
        UnpackStep(3, "Verify", "Check that unpacked file has valid PE structure and imports",
                   tool="python", tool_args="-m src lab unpacked.exe classify",
                   expected_output="No packer detected"),
    ],
    notes=[
        "UPX is open source — unpacking is trivial",
        "Some modified UPX variants may require manual fixup",
        "UPX can pack DLLs and drivers too",
    ],
))

# ── MPRESS ──────────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="MPRESS",
    method=UnpackMethod.STATIC,
    difficulty=Difficulty.EASY,
    description="Mpress Packer — less common than UPX. Uses LZMA compression.",
    tools_required=[],
    success_rate=0.90,
    steps=[
        UnpackStep(1, "Verify MPRESS", "Check for .MPRESS1/.MPRESS2 sections",
                   expected_output="MPRESS-packed binary"),
        UnpackStep(2, "Extract from Overlay", "MPRESS often stores original PE in overlay",
                   tool="python", tool_args="extract_overlay.py",
                   expected_output="Original PE from overlay"),
        UnpackStep(3, "Fallback: Dynamic", "If overlay method fails, use dynamic unpacking",
                   tool="frida", expected_output="Dumped memory at OEP"),
    ],
    notes=[
        "MPRESS is less common but straightforward",
        "Overlay extraction works ~80% of the time",
    ],
))

# ── ASPack ──────────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="ASPACK",
    packer_version="1.0-2.4",
    method=UnpackMethod.SEMI_DYNAMIC,
    difficulty=Difficulty.MODERATE,
    description="ASPack — popular runtime packer. Uses custom compression. "
                "OEP detection via pushad/popad pattern.",
    tools_required=["x64dbg", "Scylla"],
    success_rate=0.85,
    anti_debug=True,
    steps=[
        UnpackStep(1, "Load in Debugger", "Load packed binary in x64dbg/WinDbg",
                   tool="x64dbg", expected_output="Break at system breakpoint"),
        UnpackStep(2, "Set Breakpoint", "Set BP on VirtualAlloc or VirtualProtect",
                   tool="x64dbg", tool_args="bp VirtualAlloc",
                   expected_output="Break on allocation"),
        UnpackStep(3, "Run to OEP", "Step through unpacker stub to find OEP (pushad...popad+jmp pattern)",
                   expected_output="At Original Entry Point"),
        UnpackStep(4, "Dump Memory", "Dump the unpacked image from memory",
                   tool="Scylla", expected_output="Memory dump file"),
        UnpackStep(5, "Fix IAT", "Rebuild Import Address Table",
                   tool="Scylla", tool_args="IAT autosearch + fix",
                   expected_output="Valid IAT"),
        UnpackStep(6, "Fix PE", "Fix section alignment and entry point",
                   tool="python", tool_args="-m pe_repair dump.exe",
                   expected_output="Clean PE file"),
    ],
    notes=[
        "ASPack has basic anti-debug (IsDebuggerPresent check)",
        "OEP is usually after a pushad/popad sequence",
        "Scylla is the best tool for IAT rebuilding",
    ],
))

# ── PECompact ───────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="PECOMPACT",
    method=UnpackMethod.SEMI_DYNAMIC,
    difficulty=Difficulty.MODERATE,
    description="PECompact — runtime packer with compression. "
                "Similar to ASPack but different stub.",
    tools_required=["x64dbg", "Scylla"],
    success_rate=0.80,
    steps=[
        UnpackStep(1, "Load in Debugger", "Load in x64dbg", tool="x64dbg"),
        UnpackStep(2, "Trace to OEP", "Single-step or use ESP trick: record ESP at entry, BP on ESP restore"),
        UnpackStep(3, "Dump", "Dump from memory at OEP", tool="Scylla"),
        UnpackStep(4, "Fix IAT", "Rebuild IAT", tool="Scylla"),
    ],
))

# ── VMProtect ───────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="VMPROTECT",
    packer_version="2.0-3.8.4",
    method=UnpackMethod.DYNAMIC,
    difficulty=Difficulty.HARD,
    description="VMProtect — commercial protector using code virtualization, "
                "mutation, and packing. One of the strongest protections.",
    tools_required=["x64dbg", "frida", "Scylla", "Python"],
    success_rate=0.60,
    anti_debug=True,
    anti_vm=True,
    anti_dump=True,
    iat_encryption=True,
    code_virtualization=True,
    steps=[
        UnpackStep(1, "Anti-Debug Bypass",
                   "Patch IsDebuggerPresent, NtQueryInformationProcess, timing checks, PEB.BeingDebugged",
                   tool="frida", tool_args="--script=antidebug_level3.js",
                   is_critical=True),
        UnpackStep(2, "Anti-VM Bypass", "Scrub SMBIOS, CPUID hypervisor bit, registry keys",
                   tool="frida", tool_args="--script=antivm.js",
                   is_critical=False),
        UnpackStep(3, "Locate .vmp Sections",
                   "Identify VMProtect sections — look for .vmp0, .vmp1 sections (virtualized code + VM handlers)"),
        UnpackStep(4, "Dump Unpacked Code", "VMProtect unpacks to memory — dump the full image",
                   tool="frida", tool_args="--script=memory_dump.js"),
        UnpackStep(5, "Rebuild IAT", "VMProtect encrypts the IAT — use API tracing to resolve imports",
                   tool="python", tool_args="iat_reconstructor.py"),
        UnpackStep(6, "Handle VM Handlers",
                   "VMProtect compiles code into bytecode executed by VM handlers. Full de-virtualization is extremely complex.",
                   is_critical=False,
                   on_failure="Skip — analyze VM handlers separately"),
    ],
    notes=[
        "VMProtect is one of the strongest commercial protectors",
        "Code virtualization makes full unpacking nearly impossible",
        "Focus on dumping the unpacked image and rebuilding IAT",
        "VM handler analysis requires deep understanding of the VM architecture",
        "Anti-debug is sophisticated — use Frida for patches, not manual",
        "Consider using a hardware-assisted approach (PIN, DynamoRIO)",
    ],
))

# ── Themida ─────────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="THEMIDA",
    packer_version="1.0-3.1.2",
    method=UnpackMethod.DYNAMIC,
    difficulty=Difficulty.HARD,
    description="Themida/WinLicense — commercial protector with SecureEngine, "
                "code virtualization, and anti-debug. Similar difficulty to VMProtect.",
    tools_required=["x64dbg", "frida", "Scylla", "OllyDbg plugins"],
    success_rate=0.55,
    anti_debug=True,
    anti_vm=True,
    anti_dump=True,
    iat_encryption=True,
    code_virtualization=True,
    steps=[
        UnpackStep(1, "Anti-Debug", "Comprehensive anti-debug bypass",
                   tool="frida", tool_args="--script=antidebug_level3.js"),
        UnpackStep(2, "Anti-VM", "Hide VM environment",
                   tool="frida", tool_args="--script=antivm.js"),
        UnpackStep(3, "Bypass SecureEngine",
                   "Find and bypass the SecureEngine loader stub — Themida restructures the PE"),
        UnpackStep(4, "Find OEP",
                   "Themida uses complex OEP obfuscation — may need to trace through multiple layers of decryption"),
        UnpackStep(5, "Dump + Fix IAT", "Standard dump procedure",
                   tool="Scylla"),
    ],
    notes=[
        "Themida is comparable to VMProtect in difficulty",
        "SecureEngine adds an extra layer of protection",
        "Some older versions have known bypass techniques",
    ],
))

# ── Obsidium ────────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="OBSIDIUM",
    method=UnpackMethod.DYNAMIC,
    difficulty=Difficulty.MODERATE,
    description="Obsidium — mid-tier commercial protector. "
                "Less complex than VMProtect/Themida but still challenging.",
    tools_required=["x64dbg", "Scylla"],
    success_rate=0.75,
    anti_debug=True,
    anti_vm=False,
    steps=[
        UnpackStep(1, "Anti-Debug", "Basic anti-debug patches"),
        UnpackStep(2, "Find OEP", "Standard tracing"),
        UnpackStep(3, "Dump + IAT", "Standard procedure"),
    ],
))

# ── Enigma Protector ────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="ENIGMA",
    method=UnpackMethod.SEMI_DYNAMIC,
    difficulty=Difficulty.MODERATE,
    description="Enigma Protector — runtime packer with registration system. "
                "Less aggressive anti-debug than VMProtect.",
    tools_required=["x64dbg", "Scylla"],
    success_rate=0.80,
    anti_debug=True,
    steps=[
        UnpackStep(1, "Anti-Debug", "Patch IsDebuggerPresent + timing"),
        UnpackStep(2, "Find OEP", "Standard tracing — OEP is usually clear"),
        UnpackStep(3, "Dump + IAT", "Standard procedure"),
    ],
))

# ── ExeCryptor ──────────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="EXECRYPTOR",
    method=UnpackMethod.DYNAMIC,
    difficulty=Difficulty.HARD,
    description="ExeCryptor — strong commercial protector with "
                "code virtualization and anti-debug.",
    tools_required=["x64dbg", "frida", "Scylla"],
    success_rate=0.50,
    anti_debug=True,
    anti_vm=True,
    iat_encryption=True,
    code_virtualization=True,
    steps=[
        UnpackStep(1, "Anti-Debug", "Comprehensive bypass"),
        UnpackStep(2, "Find OEP", "Complex — multiple layers"),
        UnpackStep(3, "Dump + IAT", "Dynamic IAT resolution needed"),
    ],
))

# ── Unknown/Generic ─────────────────────────────────────────

_register_strategy(UnpackingStrategy(
    packer_name="UNKNOWN",
    method=UnpackMethod.DYNAMIC,
    difficulty=Difficulty.EXPERT,
    description="Unknown packer — use heuristic approach. "
                "Start with entropy analysis and pattern matching to "
                "identify the packer family, then apply appropriate strategy.",
    tools_required=["pestudio", "CFF Explorer", "x64dbg", "frida", "Scylla"],
    success_rate=0.40,
    steps=[
        UnpackStep(1, "Identify Packer", "Use entropy analysis + section names + strings",
                   tool="pestudio", expected_output="Packer family identified"),
        UnpackStep(2, "Research", "Search for packer-specific unpacking guides",
                   is_critical=False),
        UnpackStep(3, "Anti-Debug", "Apply generic anti-debug patches",
                   tool="frida", tool_args="--script=antidebug_level2.js"),
        UnpackStep(4, "Trace Entry",
                   "Find the OEP using standard techniques: ESP trick, LastError, VirtualProtect BP"),
        UnpackStep(5, "Dump", "Dump from memory", tool="Scylla"),
        UnpackStep(6, "Fix IAT", "Rebuild IAT", tool="Scylla"),
        UnpackStep(7, "Fix PE", "Repair PE headers",
                   tool="python", tool_args="-m pe_repair"),
    ],
    notes=[
        "For unknown packers, start by identifying the packer family",
        "Section names, import patterns, and entropy are key indicators",
        "Search the web for packer-specific unpacking tutorials",
    ],
))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_strategy(packer_name: str) -> UnpackingStrategy | None:
    """Get the unpacking strategy for a known packer.

    Args:
        packer_name: Name of the packer (case-insensitive).

    Returns:
        UnpackingStrategy if found, None otherwise.
    """
    return PACKER_DATABASE.get(packer_name.upper())


def get_all_strategies() -> list[UnpackingStrategy]:
    """Get all registered unpacking strategies."""
    return list(PACKER_DATABASE.values())


def get_strategy_for_sample(sample_info: dict) -> UnpackingStrategy:
    """Determine the best strategy for a sample based on its characteristics.

    Args:
        sample_info: Dict with packer info (from _classify_packer).

    Returns:
        Best matching strategy.
    """
    packer_name = sample_info.get("packer_name", "")

    # Direct match
    if packer_name:
        strategy = get_strategy(packer_name)
        if strategy:
            return strategy

    # Heuristic match based on characteristics
    has_empty_iat = sample_info.get("has_empty_iat", False)
    high_entropy = sample_info.get("entropy", 0) > 6.5
    entry_anomaly = sample_info.get("entry_point_anomaly", False)

    if has_empty_iat and high_entropy:
        # Likely a strong packer
        return get_strategy("UNKNOWN") or PACKER_DATABASE.get("UNKNOWN")

    if entry_anomaly and high_entropy:
        # Likely a runtime packer
        return get_strategy("ASPACK") or get_strategy("UNKNOWN")

    # Default to unknown strategy
    return PACKER_DATABASE.get("UNKNOWN")


def list_packer_families() -> dict[str, list[str]]:
    """List packers grouped by family/category."""
    families = {
        "Simple Packers (static unpack)": [],
        "Runtime Packers (dynamic unpack)": [],
        "Commercial Protectors (complex)": [],
        "Unknown": [],
    }

    for name, strategy in PACKER_DATABASE.items():
        if strategy.method == UnpackMethod.STATIC:
            families["Simple Packers (static unpack)"].append(name)
        elif strategy.method == UnpackMethod.SEMI_DYNAMIC:
            families["Runtime Packers (dynamic unpack)"].append(name)
        elif strategy.difficulty in (Difficulty.HARD, Difficulty.EXPERT):
            families["Commercial Protectors (complex)"].append(name)
        else:
            families["Unknown"].append(name)

    return families
