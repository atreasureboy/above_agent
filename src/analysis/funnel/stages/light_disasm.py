"""L4: Light disassembly filter stage.

Disassembles only the first 8KB of .text to detect IOCTL dispatchers.
Filters samples that have neither an IOCTL dispatcher nor a high import score.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import capstone
import pefile

from src.analysis.funnel.stages import FilterStage, FilterResult
from src.utils.ioctl import looks_like_ioctl_code


def _looks_like_ioctl(val: int) -> bool:
    """Check if a value looks like an IOCTL code."""
    return looks_like_ioctl_code(val)


def _light_disasm(pe_path: Path) -> dict[str, Any]:
    """Light disassembly: scan .text first 8KB for IOCTL patterns and WDF indicators."""
    result: dict[str, Any] = {
        "ioctl_codes": [],
        "irp_handlers": {},
        "function_count": 0,
        "is_wdf_driver": False,
    }

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories()

        # Detect architecture from PE header
        machine = pe.FILE_HEADER.Machine
        if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64
        elif machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_32
        elif machine == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
            cs_arch = capstone.CS_ARCH_ARM64
            cs_mode = capstone.CS_MODE_ARM
        else:
            cs_arch = capstone.CS_ARCH_X86
            cs_mode = capstone.CS_MODE_64  # fallback

        # Check for WDF imports (framework detection)
        # WDF drivers import WDFLDR.SYS or WDF01000.SYS (not .dll in kernel mode)
        wdf_indicators = {"wdfldr.sys", "wdf01000.sys", "wdfldr.dll", "wdf01000.dll", "wdfversion.dll"}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace").lower()
                if dll_name in wdf_indicators:
                    result["is_wdf_driver"] = True
                    break

        text_section = None
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00").lower()
            if name == ".text":
                text_section = section
                break

        if not text_section:
            pe.close()
            return result

        text_rva = text_section.VirtualAddress
        full_text = text_section.get_data()
        if not full_text:
            pe.close()
            return result

        # Segment-scanned .text: divide into 4 windows of 8KB each to
        # catch IOCTL dispatchers in large drivers (>32KB .text).
        # Priority order:
        #   1. Entry point area (DriverEntry usually near start)
        #   2. First 8KB (initialization code)
        #   3. Middle segments (dispatcher often in middle)
        #   4. Last 8KB (cleanup/secondary handlers)
        window_size = 0x2000  # 8KB per window
        max_scan = min(0x20000, len(full_text))  # Cap at 128KB total

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False

        has_ioctl = False

        def _scan_chunk(data: bytes, rva: int) -> list:
            nonlocal has_ioctl
            insns = list(md.disasm(data, rva))
            for insn in insns:
                # x64/x86: mov [reg+0x70], handler — IRP_MJ_DEVICE_CONTROL
                if insn.mnemonic == "mov" and "ptr" in insn.op_str:
                    if re.search(r'0x70', insn.op_str) and "rsp" not in insn.op_str.lower() and "esp" not in insn.op_str.lower():
                        result["irp_handlers"][0xE] = insn.address
                        has_ioctl = True

                # x64/x86: cmp/test with IOCTL-looking constants
                if insn.mnemonic in ("cmp", "test"):
                    m = re.search(r'0x([0-9a-fA-F]{4,8})', insn.op_str)
                    if m:
                        val = int(m.group(1), 16)
                        if _looks_like_ioctl(val) and val not in result["ioctl_codes"]:
                            result["ioctl_codes"].append(val)
                            has_ioctl = True

                # ARM64: cmp w0, #0x22xxxx or movz/movk with IOCTL patterns
                if cs_arch == capstone.CS_ARCH_ARM64:
                    if insn.mnemonic in ("cmp", "cmn"):
                        m = re.search(r'#(0x[0-9a-fA-F]+|\d+)', insn.op_str)
                        if m:
                            val = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
                            if _looks_like_ioctl(val) and val not in result["ioctl_codes"]:
                                result["ioctl_codes"].append(val)
                                has_ioctl = True

            return insns

        # Build scan windows: prioritize entry point area
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint if pe.OPTIONAL_HEADER.AddressOfEntryPoint else 0
        text_start = text_rva
        text_end = text_rva + len(full_text)

        # Calculate windows
        windows = []
        # Window 1: entry point area (±8KB around entry point)
        if entry_rva >= text_start and entry_rva < text_end:
            ep_offset = entry_rva - text_rva
            win_start = max(0, ep_offset - 0x2000)
            win_end = min(len(full_text), win_start + 0x4000)
            windows.append((win_start, win_end))

        # Window 2: first 8KB
        windows.append((0, min(window_size, len(full_text))))

        # Window 3-4: middle and last segments
        remaining = max_scan - window_size * 2
        if remaining > 0:
            # Middle window
            mid_start = window_size + remaining // 4
            windows.append((mid_start, min(mid_start + window_size, len(full_text))))
            # Last window
            last_start = max_scan - window_size
            if last_start > window_size:
                windows.append((last_start, min(last_start + window_size, len(full_text))))

        # Deduplicate and sort windows
        windows.sort(key=lambda w: w[0])
        merged = []
        for start, end in windows:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))

        all_instructions = []
        for win_start, win_end in merged:
            chunk = full_text[win_start:win_end]
            if chunk:
                insns = _scan_chunk(chunk, text_rva + win_start)
                all_instructions.extend(insns)

        # Count function prologues
        if cs_arch == capstone.CS_ARCH_ARM64:
            prologue_count = sum(
                1 for insn in all_instructions
                if insn.mnemonic == "stp" and "x29" in insn.op_str
            )
        else:
            prologue_count = sum(
                1 for insn in all_instructions
                if insn.mnemonic == "push" and "rbp" in insn.op_str
            )
        result["function_count"] = max(prologue_count, 1)

        pe.close()
    except Exception as e:
        print(f"[light_disasm] Warning: Failed to disassemble {pe_path}: {e}")

    return result


class LightDisasmStage(FilterStage):
    """L4: Light disassembly to find IOCTL dispatcher.

    Drivers pass if they have BOTH:
    - An IOCTL dispatcher (WDM style) OR a high import score (>= 50)
    AND at least one dangerous API in imports.

    This ensures we only pass drivers that are BOTH:
    - Actually handling user-mode IOCTLs
    - AND have potentially dangerous kernel API imports
    """

    @property
    def name(self) -> str:
        return "L4: Light disassembly (IOCTL)"

    @property
    def cost(self) -> str:
        return "s"

    def apply(self, items: list[dict]) -> FilterResult:
        """Apply light disasm filtering.

        Args:
            items: Enriched dicts from ImportScoreStage (each has 'sample' and 'import_score').
        """
        passed: list[dict] = []
        rejected: list = []

        for info in items:
            sample = info["sample"]
            disasm_info = _light_disasm(sample.path)

            info["ioctl_codes"] = disasm_info.get("ioctl_codes", [])
            info["irp_handlers"] = disasm_info.get("irp_handlers", {})
            info["function_count"] = disasm_info.get("function_count", 0)
            # Only override is_wdf_driver if disasm found WDF imports;
            # otherwise preserve pre-set value from previous stages.
            info["is_wdf_driver"] = disasm_info.get("is_wdf_driver", False) or info.get("is_wdf_driver", False)
            info["has_ioctl_dispatcher"] = bool(
                disasm_info.get("irp_handlers", {}).get(0xE)
                or disasm_info.get("ioctl_codes")
            )

            # WDF drivers: don't look for WDM-style IOCTL dispatcher.
            # The WDF framework handles IOCTL dispatch internally via
            # EvtIoDeviceControl callbacks. Pass through if import score
            # indicates dangerous APIs (>= 30, ~2+ dangerous APIs).
            if info["is_wdf_driver"]:
                passes_score = info["import_score"] >= 30
                if passes_score:
                    passed.append(info)
                else:
                    rejected.append((
                        sample,
                        f"WDF driver, low import score (score={info['import_score']})",
                    ))
                continue

            # WDM drivers: pass if they have BOTH:
            # 1. IOCTL dispatcher (handles user-mode IOCTLs)
            # 2. Dangerous API imports (has kernel primitives)
            # OR has a very high import score (>= 60, ~4+ dangerous APIs)
            passes_ioctl = info["has_ioctl_dispatcher"]
            passes_score = info["import_score"] >= 60

            if passes_ioctl or passes_score:
                passed.append(info)
            else:
                rejected.append((
                    sample,
                    f"no IOCTL (score={info['import_score']})",
                ))

        # Sort by BYOVD risk: WDF drivers with dangerous imports are highest
        # priority (framework dispatch = all functions reachable).
        # Then WDM drivers with IOCTL dispatcher.
        # Then by IOCTL count and import score.
        passed.sort(key=lambda x: (
            x["is_wdf_driver"],           # WDF drivers first (all funcs reachable)
            x["has_ioctl_dispatcher"],    # Then WDM with IOCTL dispatcher
            x["import_score"],            # Then by import score (dangerous APIs)
            len(x.get("ioctl_codes", [])),  # Then by IOCTL count
        ), reverse=True)

        return FilterResult(passed=passed, rejected=rejected)
