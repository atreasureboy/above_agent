"""
DriverScope — Anti-Obfuscation Analyzer.

Detects common anti-reversing techniques in Windows kernel drivers:
1. Control flow flattening (CFG analysis)
2. Dead code / junk instruction injection
3. PE packer signatures (UPX, MPRESS, etc.)
4. API hashing patterns
5. String encryption indicators

These techniques are used by commercial drivers and rootkits to evade
static analysis and hide malicious behavior.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

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
# Control flow flattening detection via CFG metrics
# ---------------------------------------------------------------------------

def detect_flattening(ir: DisassemblyResult) -> list[tuple[int, dict]]:
    """Detect potential control flow flattening in functions.

    Signs of flattening:
    1. Single dispatch block with many successors (switch dispatcher)
    2. Very high basic block count relative to instruction count
    3. Many indirect branches (computed jumps)
    4. State variable pattern (read-modify-write on a single register)

    Returns list of (func_addr, metrics) for suspicious functions.
    """
    suspicious = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None or len(cfg.blocks) < 10:
            continue

        total_insns = sum(len(b.instructions) for b in cfg.blocks.values())
        block_count = len(cfg.blocks)
        avg_insns_per_block = total_insns / max(block_count, 1)

        # Count indirect branches per block
        indirect_branches = 0
        for block in cfg.blocks.values():
            if block.instructions:
                last = block.instructions[-1]
                if last.mnemonic.lower() in ("jmp", "call") and "[" in last.operands:
                    indirect_branches += 1

        # Dispatch detection: block with many successors (>=5)
        max_successors = 0
        dispatch_blocks = 0
        for block in cfg.blocks.values():
            succ_count = len(block.successors)
            if succ_count > max_successors:
                max_successors = succ_count
            if succ_count >= 5:
                dispatch_blocks += 1

        # Heuristics for flattening
        is_suspicious = False
        reasons = []

        # High block count with low avg instructions per block
        if block_count > 30 and avg_insns_per_block < 4:
            is_suspicious = True
            reasons.append(
                f"High CFG complexity: {block_count} blocks, "
                f"avg {avg_insns_per_block:.1f} insns/block"
            )

        # Multiple dispatch blocks
        if dispatch_blocks >= 2:
            is_suspicious = True
            reasons.append(f"{dispatch_blocks} dispatch blocks detected (>=5 successors each)")

        # Many indirect branches
        if indirect_branches > 5:
            is_suspicious = True
            reasons.append(f"{indirect_branches} indirect branches in function")

        # Very high block-to-instruction ratio
        if total_insns > 100 and block_count > total_insns * 0.3:
            is_suspicious = True
            reasons.append(
                f"Block/instruction ratio {block_count}/{total_insns} "
                f"({block_count / max(total_insns, 1):.2f})"
            )

        if is_suspicious:
            suspicious.append((func_addr, {
                "block_count": block_count,
                "total_instructions": total_insns,
                "avg_insns_per_block": round(avg_insns_per_block, 1),
                "indirect_branches": indirect_branches,
                "dispatch_blocks": dispatch_blocks,
                "max_successors": max_successors,
                "reasons": reasons,
            }))

    return suspicious


# ---------------------------------------------------------------------------
# Dead code / junk instruction detection
# ---------------------------------------------------------------------------

# Patterns of meaningless instruction sequences (junk code)
JUNK_PATTERNS = [
    # Push/pop pairs that cancel out
    (r"push\s+(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11)", "push_pop"),
    (r"pop\s+(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11)", "push_pop"),
    # XOR self (zeroing, but in junk often paired with redundant computation)
    (r"xor\s+\w+,\s*\w+", "xor_self"),
    # NOP sleds
    (r"nop", "nop"),
    # Redundant moves (mov reg, reg)
    (r"mov\s+(\w+),\s*\1", "redundant_mov"),
    # Arithmetic that cancels out (add X, N; sub X, N)
    (r"add\s+\w+,\s*", "add_sub"),
    (r"sub\s+\w+,\s*", "add_sub"),
]


def detect_dead_code(ir: DisassemblyResult) -> list[tuple[int, dict]]:
    """Detect potential dead code / junk instruction injection.

    Signs of junk code:
    1. High density of push/pop pairs with no intervening calls
    2. Redundant mov reg, reg
    3. NOP sequences longer than 4
    4. Add/sub pairs that cancel out

    Returns list of (func_addr, metrics) for suspicious functions.
    """
    suspicious = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        # Count junk patterns per function
        push_pop_count = 0
        xor_self_count = 0
        nop_count = 0
        redundant_mov_count = 0
        add_sub_count = 0
        total_insns = 0

        last_push_reg = None
        consecutive_nops = 0
        max_consecutive_nops = 0

        for block in sorted(cfg.blocks.values(), key=lambda b: b.address):
            for insn in block.instructions:
                total_insns += 1
                ops = f"{insn.mnemonic} {insn.operands}"

                # Track push/pop pairs
                m = re.match(r"push\s+(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11)", ops)
                if m:
                    last_push_reg = m.group(1)
                    push_pop_count += 1
                m = re.match(r"pop\s+(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11)", ops)
                if m:
                    if m.group(1) == last_push_reg:
                        push_pop_count += 1  # Canceling pair
                    last_push_reg = None

                # XOR self
                if re.match(r"xor\s+(\w+),\s*\1", ops):
                    xor_self_count += 1

                # NOP tracking
                if insn.mnemonic.lower() == "nop":
                    consecutive_nops += 1
                    nop_count += 1
                    max_consecutive_nops = max(max_consecutive_nops, consecutive_nops)
                else:
                    consecutive_nops = 0

                # Redundant mov
                if re.match(r"mov\s+(\w+),\s*\1", ops):
                    redundant_mov_count += 1

                # Add/sub pairs
                if re.match(r"(add|sub)\s+\w+,\s*", ops):
                    add_sub_count += 1

        if total_insns < 20:
            continue  # Skip tiny functions

        # Score the junk density
        junk_score = (
            push_pop_count * 2
            + xor_self_count * 3
            + max_consecutive_nops * 2
            + redundant_mov_count * 2
        ) / max(total_insns, 1)

        is_suspicious = False
        reasons = []

        if junk_score > 0.3:
            is_suspicious = True
            reasons.append(f"High junk density: {junk_score:.2f}")

        if max_consecutive_nops >= 8:
            is_suspicious = True
            reasons.append(f"{max_consecutive_nops} consecutive NOPs")

        if push_pop_count > total_insns * 0.2:
            is_suspicious = True
            reasons.append(
                f"Push/pop density: {push_pop_count}/{total_insns} "
                f"({push_pop_count / max(total_insns, 1):.2f})"
            )

        if is_suspicious:
            suspicious.append((func_addr, {
                "total_instructions": total_insns,
                "push_pop_pairs": push_pop_count,
                "xor_self": xor_self_count,
                "max_consecutive_nops": max_consecutive_nops,
                "redundant_movs": redundant_mov_count,
                "junk_score": round(junk_score, 2),
                "reasons": reasons,
            }))

    return suspicious


# ---------------------------------------------------------------------------
# PE Packer detection
# ---------------------------------------------------------------------------

KNOWN_PACKERS = {
    "UPX0": "UPX",
    "UPX1": "UPX",
    "UPX2": "UPX",
    ".upx": "UPX",
    "MPRESS1": "MPRESS",
    "MPRESS2": "MPRESS",
    ".mpress": "MPRESS",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    "PECompact2": "PECompact",
    ".pec2": "PECompact",
    ".sforce": "SForce",
    ".themida": "Themida",
    ".winlicen": "WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    "PROTECT": "PEtite",
    ".petite": "PEtite",
}

# Entropy thresholds
HIGH_ENTROPY_THRESHOLD = 7.0  # Very high entropy suggests encryption/packing


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def detect_packer(pe_path: Path) -> dict:
    """Detect if a PE file is packed or protected.

    Checks:
    1. Section names matching known packer signatures
    2. Per-section entropy analysis
    3. Import table emptiness (packed imports)
    4. Entry point outside sections (OEP obfuscation)

    Returns dict with detection results.
    """
    import pefile

    result = {
        "packer_name": None,
        "high_entropy_sections": [],
        "section_entropy": {},
        "has_empty_iat": False,
        "entry_point_anomaly": False,
        "overall_suspicious": False,
        "reasons": [],
    }

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
    except Exception:
        return result

    # Check section names for packer signatures
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="replace").rstrip("\x00 ")
        if name in KNOWN_PACKERS:
            result["packer_name"] = KNOWN_PACKERS[name]
            result["overall_suspicious"] = True
            result["reasons"].append(f"Section '{name}' matches {KNOWN_PACKERS[name]} packer signature")

    # Entropy analysis per section
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="replace").rstrip("\x00 ")
        try:
            data = section.get_data()
            entropy = _shannon_entropy(data)
            result["section_entropy"][name] = round(entropy, 2)
            if entropy > HIGH_ENTROPY_THRESHOLD:
                result["high_entropy_sections"].append(name)
                result["reasons"].append(
                    f"Section '{name}' has very high entropy ({entropy:.2f})"
                )
                result["overall_suspicious"] = True
        except Exception:
            pass

    # Empty or minimal import table
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT") or not pe.DIRECTORY_ENTRY_IMPORT:
        result["has_empty_iat"] = True
        result["reasons"].append("No import table (likely packed or manually resolved)")
        result["overall_suspicious"] = True

    # Entry point outside known sections
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_in_section = False
    for section in pe.sections:
        if section.VirtualAddress <= ep_rva < section.VirtualAddress + section.Misc_VirtualSize:
            ep_in_section = True
            break
    if not ep_in_section:
        result["entry_point_anomaly"] = True
        result["reasons"].append("Entry point outside any section (OEP hidden)")
        result["overall_suspicious"] = True

    pe.close()
    return result


# ---------------------------------------------------------------------------
# API hashing detection
# ---------------------------------------------------------------------------

def detect_api_hashing(ir: DisassemblyResult) -> list[tuple[int, dict]]:
    """Detect API hashing patterns.

    Signs of API hashing:
    1. Functions that compute hashes on strings (rol+xor patterns)
    2. Calls to GetProcAddress with constant hash values instead of names
    3. ROR/ROL chains on immediate values

    This is a heuristic detection — the hash algorithm varies by packer.
    """
    suspicious = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        ror_rol_count = 0
        xor_immediate_count = 0
        total_insns = 0

        for block in cfg.blocks.values():
            for insn in block.instructions:
                total_insns += 1
                mnemonic = insn.mnemonic.lower()
                ops = insn.operands.lower()

                if mnemonic in ("ror", "rol", "shr", "shl"):
                    ror_rol_count += 1
                if "xor" in mnemonic and re.search(r",\s*0x[0-9a-f]+", ops):
                    xor_immediate_count += 1

        # Hash loop signature: multiple ROL/ROR + XOR with immediates
        hash_score = ror_rol_count + xor_immediate_count

        if hash_score >= 5 and total_insns > 10:
            suspicious.append((func_addr, {
                "total_instructions": total_insns,
                "ror_rol_count": ror_rol_count,
                "xor_immediate_count": xor_immediate_count,
                "hash_score": hash_score,
                "reasons": [
                    f"API hashing pattern: {ror_rol_count} shift + {xor_immediate_count} XOR-immediate"
                ],
            }))

    return suspicious


# ---------------------------------------------------------------------------
# String encryption detection
# ---------------------------------------------------------------------------

def detect_string_encryption(ir: DisassemblyResult) -> list[tuple[int, dict]]:
    """Detect string encryption / runtime decryption patterns.

    Signs of string encryption:
    1. XOR-decryption loop: MOV byte from array, XOR with immediate key,
       MOV byte back — repeated pattern typical of decrypt functions.
    2. Stack-based string construction: Many MOV byte [rsp+offset], imm8
       instructions building a string character-by-character.
    3. Combined weak signals: XOR-immediate + stack byte stores.
    """
    suspicious = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        xor_decrypt_pattern = 0
        stack_str_build = 0
        byte_array_access = 0
        total_insns = 0

        for block in cfg.blocks.values():
            for insn in block.instructions:
                total_insns += 1
                mnemonic = insn.mnemonic.lower()
                ops = insn.operands.lower()

                # XOR-decryption: XOR reg/mem with immediate byte
                if mnemonic == "xor" and re.search(r",\s*0x[0-9a-f]{1,2}$", ops):
                    xor_decrypt_pattern += 1

                # Stack string construction: MOV byte ptr [rsp+..], imm8
                if mnemonic == "mov" and "byte" in ops and (
                    "rsp" in ops or "rbp" in ops
                ) and re.search(r",\s*0x[0-9a-f]{1,2}$", ops):
                    stack_str_build += 1

                # Byte array read/write (decrypt loop body)
                if mnemonic == "mov" and "al" in ops.replace(" ", "") and (
                    "[" in ops and "]" in ops
                ):
                    byte_array_access += 1

        decrypt_score = 0
        reasons = []

        # XOR decrypt loop: need both XOR-immediate and byte array access
        if xor_decrypt_pattern >= 2 and byte_array_access >= 2:
            decrypt_score += xor_decrypt_pattern + byte_array_access
            reasons.append(
                f"XOR decrypt loop: {xor_decrypt_pattern} XOR + {byte_array_access} byte array access"
            )

        # Stack string construction
        if stack_str_build >= 4:
            decrypt_score += stack_str_build
            reasons.append(f"Stack string construction: {stack_str_build} byte stores")

        # Combined weak signal
        if xor_decrypt_pattern >= 1 and stack_str_build >= 2:
            decrypt_score += 3
            reasons.append(
                f"Mixed decrypt + build: {xor_decrypt_pattern} XOR + {stack_str_build} stack stores"
            )

        if decrypt_score >= 5 and total_insns > 10:
            suspicious.append((func_addr, {
                "total_instructions": total_insns,
                "xor_decrypt": xor_decrypt_pattern,
                "stack_str_build": stack_str_build,
                "byte_array_access": byte_array_access,
                "decrypt_score": decrypt_score,
                "reasons": reasons,
            }))

    return suspicious

class AntiObfuscationAnalyzer(Analyzer):
    """Detects anti-reversing and anti-debugging techniques in drivers."""

    @property
    def name(self) -> str:
        return "AntiObfuscationAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Detects anti-reversing techniques: control flow flattening, "
            "dead code injection, PE packer signatures, API hashing, "
            "and string encryption indicators."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. PE Packer detection (if sample path is available)
        if sample.path and sample.path.exists():
            packer_result = detect_packer(sample.path)
            if packer_result["overall_suspicious"]:
                reasons = "; ".join(packer_result["reasons"])
                findings.append(
                    Finding(
                        category=FindingCategory.PACKED_BINARY,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Driver appears to be packed/protected: "
                            f"{packer_result.get('packer_name', 'unknown packer')}. {reasons}"
                        ),
                        context={
                            "packer_name": packer_result.get("packer_name"),
                            "high_entropy_sections": packer_result["high_entropy_sections"],
                            "section_entropy": packer_result["section_entropy"],
                            "empty_iat": packer_result["has_empty_iat"],
                            "entry_point_anomaly": packer_result["entry_point_anomaly"],
                            "reasons": packer_result["reasons"],
                        },
                        evidence=[
                            Evidence(
                                type="pe_analysis",
                                location="PE headers + sections",
                                snippet=reasons[:200],
                                rule_id="PACKER_DETECT",
                            )
                        ],
                    )
                )

        # 2. Control flow flattening detection
        flattening_funcs = detect_flattening(ir)
        for func_addr, metrics in flattening_funcs:
            reasons = "; ".join(metrics["reasons"])
            findings.append(
                Finding(
                    category=FindingCategory.CONTROL_FLOW_FLATTENING,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Function sub_{func_addr:X}: Potential control flow flattening. {reasons}"
                    ),
                    function_address=func_addr,
                    context=metrics,
                    evidence=[
                        Evidence(
                            type="cfg_analysis",
                            location=f"sub_{func_addr:X}",
                            snippet=reasons[:200],
                            rule_id="CFG_FLATTEN",
                        )
                    ],
                )
            )

        # 3. Dead code / junk injection detection
        dead_code_funcs = detect_dead_code(ir)
        for func_addr, metrics in dead_code_funcs:
            reasons = "; ".join(metrics["reasons"])
            findings.append(
                Finding(
                    category=FindingCategory.DEAD_CODE_INJECTION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    description=(
                        f"Function sub_{func_addr:X}: Potential dead code/junk injection. {reasons}"
                    ),
                    function_address=func_addr,
                    context=metrics,
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{func_addr:X}",
                            snippet=reasons[:200],
                            rule_id="JUNK_CODE",
                        )
                    ],
                )
            )

        # 4. API hashing detection
        api_hash_funcs = detect_api_hashing(ir)
        for func_addr, metrics in api_hash_funcs:
            reasons = "; ".join(metrics["reasons"])
            findings.append(
                Finding(
                    category=FindingCategory.API_HASHING,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Function sub_{func_addr:X}: Potential API hashing pattern. {reasons}"
                    ),
                    function_address=func_addr,
                    context=metrics,
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{func_addr:X}",
                            snippet=reasons[:200],
                            rule_id="API_HASH",
                        )
                    ],
                )
            )

        # 5. String encryption detection
        str_enc_funcs = detect_string_encryption(ir)
        for func_addr, metrics in str_enc_funcs:
            reasons = "; ".join(metrics["reasons"])
            findings.append(
                Finding(
                    category=FindingCategory.STRING_ENCRYPTION,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Function sub_{func_addr:X}: Potential string encryption/decryption. {reasons}"
                    ),
                    function_address=func_addr,
                    context=metrics,
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{func_addr:X}",
                            snippet=reasons[:200],
                            rule_id="STR_ENCRYPT",
                        )
                    ],
                )
            )

        return findings
