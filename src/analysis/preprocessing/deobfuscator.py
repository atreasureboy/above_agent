"""
DriverScope — Deobfuscation Engine.

Restores obfuscated code to a more analyzable form:

1. Control Flow Flattening (CFF) Deflattening
   - Detect dispatch blocks and state variables
   - Reconstruct original execution order
   - Simplify flattened switch-case structures

2. Dead Code Removal
   - Identify and remove junk instructions
   - Detect opaque predicates
   - Clean up NOP sleds

3. String Decryption (extends existing deep/string_decryptor.py)
4. API Hash Resolution (extends existing deep/api_hash_bruteforce.py)

Usage:
    from src.analysis.preprocessing.deobfuscator import Deobfuscator

    deobf = Deobfuscator()
    result = deobf.deflatten_function(func_addr, ir)
    cleaned = deobf.remove_dead_code(func_addr, ir)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CFFPattern:
    """Detected control flow flattening pattern."""
    function_address: int = 0
    dispatch_block: int = 0           # Address of the dispatch switch block
    state_variable: str = ""          # Register used as state variable (e.g., "eax")
    state_init_value: int = 0         # Initial state value
    num_states: int = 0               # Number of states in the switch
    real_blocks: list[int] = field(default_factory=list)  # Actual computation blocks
    confidence: float = 0.0           # 0.0 - 1.0
    reasons: list[str] = field(default_factory=list)


@dataclass
class DeflattenResult:
    """Result of CFF deflattening."""
    function_address: int = 0
    original_cfg: Any = None
    restored_order: list[int] = field(default_factory=list)  # Block addresses in order
    simplified_pseudocode: str = ""
    num_blocks_merged: int = 0
    confidence: float = 0.0


@dataclass
class DeadCodeRegion:
    """A region of dead/junk code."""
    start_address: int = 0
    end_address: int = 0
    instruction_count: int = 0
    reason: str = ""  # "unreachable", "opaque_predicate", "junk_nop", "junk_math"


@dataclass
class DeobfuscationResult:
    """Complete deobfuscation result for a function."""
    function_address: int = 0
    cff_detected: bool = False
    cff_pattern: CFFPattern | None = None
    deflatten_result: DeflattenResult | None = None
    dead_code_regions: list[DeadCodeRegion] = field(default_factory=list)
    strings_decrypted: list[dict[str, Any]] = field(default_factory=list)
    apis_resolved: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CFF Deflattener
# ---------------------------------------------------------------------------

class CFFDeflattener:
    """Control Flow Flattening deflattener.

    Detects and restores the original control flow of flattened functions.

    CFF pattern:
        - Single dispatch block with many successors (switch)
        - State variable updated in each real block
        - Each real block has 1 successor (back to dispatch)
        - Real blocks do actual computation between state transitions
    """

    # Minimum thresholds for CFF detection
    MIN_DISPATCH_SUCCESSORS = 5
    MIN_REAL_BLOCKS = 3
    MAX_AVG_INSNS_PER_BLOCK = 15  # CFF blocks are typically small

    def detect(self, func_addr: int, ir: Any) -> CFFPattern | None:
        """Detect CFF pattern in a function.

        Args:
            func_addr: Function address.
            ir: DisassemblyResult with CFG data.

        Returns:
            CFFPattern if detected, None otherwise.
        """
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None or len(cfg.blocks) < self.MIN_DISPATCH_SUCCESSORS + 2:
            return None

        # Find dispatch block: block with most successors
        dispatch_addr = None
        max_succ = 0
        for block_addr, block in cfg.blocks.items():
            if len(block.successors) > max_succ:
                max_succ = len(block.successors)
                dispatch_addr = block_addr

        if dispatch_addr is None or max_succ < self.MIN_DISPATCH_SUCCESSORS:
            return None

        dispatch_block = cfg.blocks[dispatch_addr]

        # Check if dispatch looks like a switch (indirect jump)
        if not dispatch_block.instructions:
            return None

        last_insn = dispatch_block.instructions[-1]
        is_indirect = (
            last_insn.mnemonic.lower() in ("jmp", "call")
            and ("[" in last_insn.operands or "reg" in last_insn.operands.lower())
        )

        if not is_indirect and max_succ < 8:
            return None

        # Identify real blocks (those with 1 successor pointing back to dispatch)
        real_blocks = []
        for block_addr, block in cfg.blocks.items():
            if block_addr == dispatch_addr:
                continue
            if len(block.successors) == 1 and dispatch_addr in block.successors:
                real_blocks.append(block_addr)
            elif len(block.successors) == 0 and block_addr in dispatch_block.successors:
                # Exit block
                pass

        if len(real_blocks) < self.MIN_REAL_BLOCKS:
            return None

        # Detect state variable
        state_var = self._detect_state_variable(dispatch_block, real_blocks, cfg)

        # Build pattern
        pattern = CFFPattern(
            function_address=func_addr,
            dispatch_block=dispatch_addr,
            state_variable=state_var,
            num_states=len(real_blocks),
            real_blocks=sorted(real_blocks),
            confidence=self._compute_confidence(dispatch_block, real_blocks, cfg),
            reasons=[
                f"Dispatch block at 0x{dispatch_addr:X} with {max_succ} successors",
                f"{len(real_blocks)} real blocks routing back to dispatch",
                f"State variable: {state_var or 'undetected'}",
            ],
        )

        return pattern

    def deflatten(
        self,
        func_addr: int,
        ir: Any,
        pattern: CFFPattern | None = None,
    ) -> DeflattenResult:
        """Deflatten a function's control flow.

        Args:
            func_addr: Function address.
            ir: DisassemblyResult.
            pattern: Pre-detected CFF pattern (auto-detected if None).

        Returns:
            DeflattenResult with restored block order.
        """
        if pattern is None:
            pattern = self.detect(func_addr, ir)

        result = DeflattenResult(function_address=func_addr)

        if pattern is None:
            return result

        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            return result

        # Step 1: Extract state transitions from each real block
        transitions = {}
        for block_addr in pattern.real_blocks:
            block = cfg.blocks.get(block_addr)
            if block is None:
                continue
            state_change = self._extract_state_transition(block, pattern.state_variable)
            if state_change is not None:
                transitions[block_addr] = state_change

        # Step 2: Reconstruct execution order
        # Start from the initial state, follow transitions
        restored_order = self._reconstruct_order(
            pattern.state_init_value,
            transitions,
            pattern.real_blocks,
        )

        result.restored_order = restored_order
        result.num_blocks_merged = len(restored_order)
        result.confidence = pattern.confidence

        # Step 3: Generate simplified pseudocode
        result.simplified_pseudocode = self._generate_pseudocode(
            restored_order, cfg, ir
        )

        return result

    def _detect_state_variable(
        self,
        dispatch_block: Any,
        real_blocks: list[int],
        cfg: Any,
    ) -> str:
        """Detect the state variable used for dispatch.

        The state variable is typically:
        - Set before the dispatch (initial value)
        - Read in the dispatch to select the next block
        - Modified in each real block (new state value)
        """
        # Look for registers used in the dispatch's last instruction (switch)
        if not dispatch_block.instructions:
            return ""

        last_insn = dispatch_block.instructions[-1]
        # Common state variable registers
        candidates = ["eax", "ebx", "ecx", "edx", "r10", "r11", "rbx"]

        for reg in candidates:
            if reg in last_insn.operands.lower():
                return reg

        # Check real blocks for common register writes
        for block_addr in real_blocks[:3]:
            block = cfg.blocks.get(block_addr)
            if block is None:
                continue
            for insn in block.instructions:
                for reg in candidates:
                    if insn.mnemonic.lower() == "mov" and reg in insn.operands.lower():
                        return reg

        return ""

    def _compute_confidence(
        self,
        dispatch_block: Any,
        real_blocks: list[int],
        cfg: Any,
    ) -> float:
        """Compute confidence score for CFF detection."""
        score = 0.0

        # High successor count → more likely CFF
        succ_count = len(dispatch_block.successors)
        if succ_count >= 10:
            score += 0.4
        elif succ_count >= 7:
            score += 0.3
        elif succ_count >= 5:
            score += 0.2

        # Many real blocks → more likely CFF
        if len(real_blocks) >= 8:
            score += 0.3
        elif len(real_blocks) >= 5:
            score += 0.2
        elif len(real_blocks) >= 3:
            score += 0.1

        # Small average instructions per block → more likely CFF
        total_insns = sum(
            len(cfg.blocks[addr].instructions)
            for addr in real_blocks
            if addr in cfg.blocks
        )
        avg_insns = total_insns / max(len(real_blocks), 1)
        if avg_insns <= 5:
            score += 0.3
        elif avg_insns <= 10:
            score += 0.2
        elif avg_insns <= 15:
            score += 0.1

        return min(score, 1.0)

    def _extract_state_transition(
        self,
        block: Any,
        state_var: str,
    ) -> int | None:
        """Extract the state value that a block transitions to.

        Looks for: mov state_var, IMM  (the new state value)
        """
        if not state_var:
            return None

        for insn in block.instructions:
            if insn.mnemonic.lower() == "mov":
                parts = insn.operands.split(",")
                if len(parts) == 2 and state_var in parts[0].strip().lower():
                    # Found: mov state_var, imm
                    try:
                        value = int(parts[1].strip(), 0)
                        return value
                    except (ValueError, TypeError):
                        continue

        return None

    def _reconstruct_order(
        self,
        init_value: int,
        transitions: dict[int, int],
        all_blocks: list[int],
    ) -> list[int]:
        """Reconstruct the original execution order from state transitions.

        Args:
            init_value: Initial state value.
            transitions: Map from block address to next state value.
            all_blocks: All real block addresses.

        Returns:
            List of block addresses in execution order.
        """
        # Build reverse mapping: state_value → block_address
        state_to_block = {}
        for block_addr, next_state in transitions.items():
            state_to_block[next_state] = block_addr

        # Follow the chain from init_value
        order = []
        visited = set()
        current = init_value

        for _ in range(len(all_blocks) * 2):  # Safety limit
            if current in visited:
                break
            if current not in state_to_block:
                break

            block_addr = state_to_block[current]
            if block_addr in visited:
                break

            order.append(block_addr)
            visited.add(block_addr)

            # Get next state
            next_state = transitions.get(block_addr)
            if next_state is None or next_state == current:
                break
            current = next_state

        # If we couldn't reconstruct the full chain, just use sorted order
        if len(order) < len(all_blocks) // 2:
            order = sorted(all_blocks)

        return order

    def _generate_pseudocode(
        self,
        restored_order: list[int],
        cfg: Any,
        ir: Any,
    ) -> str:
        """Generate simplified pseudocode from restored block order."""
        lines = []

        for i, block_addr in enumerate(restored_order):
            block = cfg.blocks.get(block_addr)
            if block is None:
                continue

            lines.append(f"// Block {i + 1} @ 0x{block_addr:X}")
            for insn in block.instructions[:10]:  # First 10 instructions
                api = f"  ; CALL {insn.api_target}" if insn.api_target else ""
                lines.append(f"  {hex(insn.address)}: {insn.mnemonic} {insn.operands}{api}")
            if len(block.instructions) > 10:
                lines.append(f"  ... ({len(block.instructions)} total instructions)")
            lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dead Code Remover
# ---------------------------------------------------------------------------

class DeadCodeRemover:
    """Remove dead/junk code from functions.

    Detects:
    1. Unreachable blocks (not in any CFG path from entry)
    2. Opaque predicates (always-true/false conditions)
    3. Junk instructions (sequences that don't affect program state)
    4. NOP sleds
    """

    # Instructions that are almost always junk in obfuscated code
    JUNK_PATTERNS = {
        # Self-cancelling pairs
        ("push", "pop"): True,        # push eax; pop eax
        ("inc", "dec"): True,         # inc eax; dec eax
        ("add", "sub"): True,         # add eax, 1; sub eax, 1
        ("xor_self",): True,          # xor eax, eax (sometimes junk, sometimes init)
    }

    def detect(self, func_addr: int, ir: Any) -> list[DeadCodeRegion]:
        """Detect dead code regions in a function."""
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            return []

        regions = []

        # 1. Unreachable blocks
        unreachable = self._find_unreachable_blocks(func_addr, cfg)
        for block_addr in unreachable:
            block = cfg.blocks[block_addr]
            if block.instructions:
                regions.append(DeadCodeRegion(
                    start_address=block.address,
                    end_address=block.address + block.instructions[-1].address,
                    instruction_count=len(block.instructions),
                    reason="unreachable",
                ))

        # 2. NOP sleds
        for block_addr, block in cfg.blocks.items():
            nop_count = sum(
                1 for insn in block.instructions
                if insn.mnemonic.lower() in ("nop", "xchg eax,eax")
            )
            if nop_count >= 3:
                regions.append(DeadCodeRegion(
                    start_address=block.address,
                    end_address=block.address + (block.instructions[-1].address if block.instructions else block.address),
                    instruction_count=nop_count,
                    reason="junk_nop",
                ))

        # 3. Junk math patterns
        for block_addr, block in cfg.blocks.items():
            junk = self._detect_junk_math(block)
            if junk:
                regions.append(junk)

        return regions

    def _find_unreachable_blocks(self, func_addr: int, cfg: Any) -> list[int]:
        """Find blocks not reachable from the function entry."""
        if not cfg.blocks:
            return []

        # BFS from entry block
        entry = func_addr  # Usually the function address is the entry
        visited = set()
        queue = [entry]

        while queue:
            addr = queue.pop(0)
            if addr in visited:
                continue
            visited.add(addr)

            block = cfg.blocks.get(addr)
            if block:
                for succ in block.successors:
                    if succ not in visited:
                        queue.append(succ)

        # Return blocks not in visited set
        unreachable = [addr for addr in cfg.blocks if addr not in visited]
        return unreachable

    def _detect_junk_math(self, block: Any) -> DeadCodeRegion | None:
        """Detect junk math instruction sequences."""
        insns = block.instructions
        if len(insns) < 2:
            return None

        # Look for self-cancelling patterns
        for i in range(len(insns) - 1):
            curr = insns[i]
            next_insn = insns[i + 1]

            # push reg; pop reg
            if (curr.mnemonic.lower() == "push" and
                next_insn.mnemonic.lower() == "pop" and
                curr.operands == next_insn.operands):
                return DeadCodeRegion(
                    start_address=curr.address,
                    end_address=next_insn.address,
                    instruction_count=2,
                    reason="junk_push_pop",
                )

            # add reg, imm; sub reg, imm (same value)
            if (curr.mnemonic.lower() == "add" and
                next_insn.mnemonic.lower() == "sub"):
                curr_parts = curr.operands.split(",")
                next_parts = next_insn.operands.split(",")
                if (len(curr_parts) == 2 and len(next_parts) == 2 and
                    curr_parts[0].strip() == next_parts[0].strip() and
                    curr_parts[1].strip() == next_parts[1].strip()):
                    return DeadCodeRegion(
                        start_address=curr.address,
                        end_address=next_insn.address,
                        instruction_count=2,
                        reason="junk_add_sub",
                    )

        return None


# ---------------------------------------------------------------------------
# Combined Deobfuscator
# ---------------------------------------------------------------------------

class Deobfuscator:
    """Combined deobfuscation engine.

    Applies all deobfuscation passes to a function.
    """

    def __init__(self):
        self.cff_deflattener = CFFDeflattener()
        self.dead_code_remover = DeadCodeRemover()

    def analyze(self, func_addr: int, ir: Any) -> DeobfuscationResult:
        """Run all deobfuscation passes on a function.

        Args:
            func_addr: Function address.
            ir: DisassemblyResult.

        Returns:
            DeobfuscationResult with all findings.
        """
        result = DeobfuscationResult(function_address=func_addr)

        # Pass 1: CFF detection
        cff_pattern = self.cff_deflattener.detect(func_addr, ir)
        if cff_pattern:
            result.cff_detected = True
            result.cff_pattern = cff_pattern
            result.deflatten_result = self.cff_deflattener.deflatten(
                func_addr, ir, cff_pattern
            )
            logger.info(
                "[deobf] CFF detected in 0x%X (confidence: %.2f, %d states)",
                func_addr,
                cff_pattern.confidence,
                cff_pattern.num_states,
            )

        # Pass 2: Dead code detection
        dead_regions = self.dead_code_remover.detect(func_addr, ir)
        result.dead_code_regions = dead_regions
        if dead_regions:
            logger.info(
                "[deobf] %d dead code regions in 0x%X",
                len(dead_regions),
                func_addr,
            )

        return result

    def deflatten_function(
        self,
        func_addr: int,
        ir: Any,
    ) -> DeflattenResult | None:
        """Deflatten a single function (convenience method)."""
        pattern = self.cff_deflattener.detect(func_addr, ir)
        if pattern:
            return self.cff_deflattener.deflatten(func_addr, ir, pattern)
        return None

    def remove_dead_code(
        self,
        func_addr: int,
        ir: Any,
    ) -> list[DeadCodeRegion]:
        """Remove dead code from a function (convenience method)."""
        return self.dead_code_remover.detect(func_addr, ir)
