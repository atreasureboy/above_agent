"""DriverScope — CFG Visualizer.

Exports Control Flow Graphs to DOT/GraphViz format for visualization.
Supports:
  - Single function CFG export
  - Batch export for all IOCTL handlers
  - Cross-function exploit chain call graph

No external dependencies required — produces plain .dot text files.
Render with: dot -Tpng file.dot -o file.png

Usage:
    from src.report.cfg_visualizer import export_cfg_to_dot
    export_cfg_to_dot(ir, func_addr, Path("handler.dot"))
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.models import BasicBlock, CFG, DisassemblyResult
from src.config.defaults import VALIDATION_APIS


# Validation branch mnemonics (x64) — edges from these blocks go to fail path
VALIDATION_BRANCHES = {"jbe", "jna", "jb", "jle", "jng", "jl"}

# Colors
COLOR_VALIDATION = "#90EE90"       # light green
COLOR_DANGEROUS_API = "#FF6B6B"    # red
COLOR_ENTRY = "#87CEEB"            # sky blue
COLOR_TAIL = "#DDA0DD"             # plum
EDGE_TAINT_COLOR = "#FF8C00"       # dark orange
EDGE_VALIDATION_COLOR = "#228B22"  # forest green
EDGE_FALLTHROUGH = "#888888"       # gray


def _escape_dot(s: str) -> str:
    """Escape special characters for DOT string literals."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _instruction_snippet(block: BasicBlock, max_insns: int = 5) -> str:
    """Generate a short HTML-like label for a block's instructions."""
    lines = []
    for insn in block.instructions[:max_insns]:
        api_marker = ""
        if insn.api_target:
            api_marker = f"  <font color='red'><b>CALL {insn.api_target}</b></font>"
        lines.append(
            f"{hex(insn.address)}: {insn.mnemonic} {insn.operands}{api_marker}"
        )
    if len(block.instructions) > max_insns:
        lines.append(f"  ... ({len(block.instructions) - max_insns} more)")
    return "\\n".join(_escape_dot(l) for l in lines)


def _block_has_validation(block: BasicBlock) -> bool:
    """Check if a block contains validation instructions."""
    for insn in block.instructions:
        if insn.api_target in VALIDATION_APIS:
            return True
        if insn.mnemonic.lower() == "cmp":
            return True
        if insn.mnemonic.lower() == "test":
            return True
    return False


def _block_has_dangerous_call(block: BasicBlock) -> bool:
    """Check if a block calls a dangerous API."""
    for insn in block.instructions:
        if insn.api_target and insn.api_target not in VALIDATION_APIS:
            return True
    return False


def _block_has_taint(block: BasicBlock, taint_addrs: set[int]) -> bool:
    """Check if any instruction in the block is on the taint path."""
    for insn in block.instructions:
        if insn.address in taint_addrs:
            return True
    return False


def _is_branch_block(block: BasicBlock) -> str | None:
    """If the block ends with a conditional branch, return the mnemonic."""
    if not block.instructions:
        return None
    last = block.instructions[-1]
    mn = last.mnemonic.lower()
    if mn.startswith("j") and mn not in ("jmp",):
        return mn
    return None


def export_cfg_to_dot(
    ir: DisassemblyResult,
    func_addr: int,
    output_path: Path,
    taint_result=None,
    max_instructions_per_block: int = 5,
) -> Path:
    """Export a single function's CFG to DOT format.

    Args:
        ir: The DisassemblyResult containing the CFG.
        func_addr: Address of the function to export.
        output_path: Path to write the .dot file.
        taint_result: Optional TaintResult for highlighting taint path.
        max_instructions_per_block: Max instructions to show per node.

    Returns:
        The output path that was written.
    """
    cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
    if not cfg:
        output_path.write_text(
            f'digraph "sub_{func_addr:X}" {{\n'
            f'  label="No CFG available for sub_{func_addr:X}"\n'
            f"}}\n",
            encoding="utf-8",
        )
        return output_path

    func = ir.functions.get(func_addr)
    func_name = func.name if func else f"sub_{func_addr:X}"

    # Collect taint addresses
    taint_addrs: set[int] = set()
    if taint_result:
        for sink in getattr(taint_result, "sinks", []):
            taint_addrs.add(sink.address)
        for source in getattr(taint_result, "sources", []):
            taint_addrs.add(source.address)

    lines = [
        f'digraph "{func_name}" {{',
        f'  rankdir=TB;',
        f'  fontname="Helvetica";',
        f'  node [shape=record, fontname="Courier", fontsize=10];',
        f'  edge [fontname="Courier", fontsize=8];',
        f'  label="{func_name} (0x{func_addr:X})";',
        f'  labelloc=t;',
        "",
    ]

    # Nodes
    for block_addr, block in sorted(cfg.blocks.items()):
        label = _instruction_snippet(block, max_instructions_per_block)

        # Determine fill color
        fill = COLOR_ENTRY if block_addr == cfg.entry_block else "white"
        if _block_has_dangerous_call(block):
            fill = COLOR_DANGEROUS_API
        elif _block_has_validation(block):
            fill = COLOR_VALIDATION
        elif _block_has_taint(block, taint_addrs):
            fill = "#FFD700"  # gold for taint path

        lines.append(
            f'  "0x{block_addr:X}" ['
            f'label="{label}", '
            f'fillcolor="{fill}", '
            f'style=filled];'
        )

    lines.append("")

    # Edges
    for block_addr, block in sorted(cfg.blocks.items()):
        branch_mn = _is_branch_block(block)

        for i, succ_addr in enumerate(block.successors):
            edge_color = EDGE_FALLTHROUGH
            edge_label = ""
            penwidth = "1.0"

            if branch_mn:
                if i == 0:
                    edge_label = branch_mn
                    edge_color = EDGE_VALIDATION_COLOR if _block_has_validation(block) else EDGE_FALLTHROUGH
                else:
                    edge_label = "else"

            # Check if edge passes through taint
            if taint_addrs and (block_addr in taint_addrs or succ_addr in taint_addrs):
                edge_color = EDGE_TAINT_COLOR
                penwidth = "2.0"

            lines.append(
                f'  "0x{block_addr:X}" -> "0x{succ_addr:X}" ['
                f'label="{edge_label}", '
                f'color="{edge_color}", '
                f'penwidth={penwidth}];'
            )

    lines.append("}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


def export_all_cfgs_to_dot(
    ir: DisassemblyResult,
    output_dir: Path,
    handler_only: bool = True,
) -> list[Path]:
    """Batch export CFGs for all functions (or just handlers).

    Args:
        ir: The DisassemblyResult.
        output_dir: Directory to write .dot files.
        handler_only: If True, only export IOCTL handler CFGs.

    Returns:
        List of output paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []

    if handler_only:
        func_addrs = set(ir.ioctl_handlers.values())
        if 0xE in ir.irp_handlers:
            func_addrs.add(ir.irp_handlers[0xE])
        func_addrs.discard(0)
    else:
        func_addrs = ir.functions.keys()

    for func_addr in sorted(func_addrs):
        if func_addr not in ir.functions:
            continue
        out = output_dir / f"sub_{func_addr:X}.dot"
        export_cfg_to_dot(ir, func_addr, out)
        paths.append(out)

    return paths


def export_chain_dot(
    chains: list[dict[str, Any]],
    ir: DisassemblyResult,
    output_path: Path,
) -> Path:
    """Export exploit chains as a cross-function call graph in DOT format.

    Each node is a function, edges represent the exploit flow.
    Functions with dangerous APIs are colored red, validated ones green.

    Args:
        chains: List of exploit chain dicts.
        ir: The DisassemblyResult.
        output_path: Path to write the .dot file.

    Returns:
        The output path that was written.
    """
    lines = [
        'digraph "ExploitChains" {',
        '  rankdir=LR;',
        '  fontname="Helvetica";',
        '  node [shape=box, fontname="Courier", fontsize=12];',
        '  edge [fontname="Courier", fontsize=10, color=red];',
        '  label="BYOVD Exploit Chains";',
        '  labelloc=t;',
        "",
    ]

    for i, chain in enumerate(chains):
        cluster = f"chain_{i}"
        func = chain.get("function", "unknown")
        name = chain.get("name", "unknown")
        severity = chain.get("severity", "HIGH")
        apis = chain.get("dangerous_apis", [])
        validation = chain.get("validation", "none")
        user_ctrl = chain.get("user_controllable", False)

        fill = COLOR_DANGEROUS_API if user_ctrl else "#FFA07A"
        if validation == "partial":
            fill = "#FFD700"  # gold for partial validation

        label = (
            f"{name}\\n"
            f"Function: {func}\\n"
            f"Severity: {severity}\\n"
            f"APIs: {', '.join(apis)}\\n"
            f"Validation: {validation}"
        )

        lines.append(f'  "{cluster}" [')
        lines.append(f'    label="{_escape_dot(label)}",')
        lines.append(f'    fillcolor="{fill}",')
        lines.append(f'    style=filled];')

    lines.append("}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path
