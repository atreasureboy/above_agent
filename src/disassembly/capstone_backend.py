"""
DriverScope — Capstone disassembly backend.

Lightweight, pure-Python disassembly for MVP. Identifies functions via
heuristic prologue/ret scanning, maps API calls through the IAT, and
extracts IOCTL dispatcher patterns.
"""

from __future__ import annotations

import logging
import re
import bisect
import time
from pathlib import Path
from typing import Any

import capstone
import pefile

from src.disassembly.backend import DisassemblyBackend
from src.models import (
    APICallInfo,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Function,
    Instruction,
)
from src.config.defaults import DANGEROUS_API_SET


# APIs that are interesting for disassembly IAT resolution but NOT
# classified as dangerous for scoring (e.g. used for indirect call resolution).
_DISASM_ONLY_APIS = {
    "MmGetSystemRoutineAddress",
    "MmUnmapIoSpace", "MmUnmapLockedPages",
    "HalTranslateBusAddress",
    "ZwReadVirtualMemory", "NtReadVirtualMemory",
    "ZwOpenThread", "ZwSuspendProcess", "ZwResumeProcess",
    "ZwTerminateProcess",
    "ZwOpenProcessToken", "PsGetCurrentProcessToken",
    "WdfDriverCreate", "WdfIoQueueCreate", "WdfVersionGetClass",
}

# All APIs tracked for IAT resolution = scoring defaults + disasm-only.
DANGEROUS_APIS = DANGEROUS_API_SET | _DISASM_ONLY_APIS


class CapstoneBackend(DisassemblyBackend):
    """Capstone-based disassembly backend.

    Uses PE section parsing for code boundaries, Capstone for x64/x86
    disassembly, and heuristic function detection via prologue/ret patterns.
    """

    @property
    def name(self) -> str:
        return "capstone"

    def is_available(self) -> bool:
        try:
            import capstone
            return capstone.cs_support(capstone.CS_ARCH_X86)
        except Exception:
            return False

    def get_version(self) -> str:
        import capstone
        return capstone.__version__

    def __init__(self) -> None:
        self._image_base: int = 0
        self._iat_trace_cache: dict[tuple[str, int], int | None] = {}
        self._string_locations: list[dict] = []

    def analyze(
        self,
        sample_path: Path,
        quick: bool = False,
        timeout: int = 30,
    ) -> DisassemblyResult:
        """Run full disassembly on a .sys file.

        Args:
            quick: Skip full CFG building (10-100x faster).
            timeout: Max seconds for disassembly + CFG. If exceeded,
                     skips CFG construction entirely.
        """
        start_time = time.time()
        # Reject excessively large files (>200MB) to prevent OOM
        file_size = sample_path.stat().st_size
        max_size = 200 * 1024 * 1024  # 200MB
        if file_size > max_size:
            raise ValueError(
                f"File too large: {file_size / 1024 / 1024:.0f}MB > 200MB limit"
            )

        raw = sample_path.read_bytes()
        pe = pefile.PE(data=raw, fast_load=True)
        pe.parse_data_directories()

        # Store image base for RVA→VA conversion during call resolution
        self._image_base = pe.OPTIONAL_HEADER.ImageBase
        self._iat_trace_cache.clear()  # Reset memoization cache per-analysis

        arch = self._detect_capstone_arch(pe)
        mode = self._detect_capstone_mode(pe)

        md = capstone.Cs(arch, mode)
        md.detail = True

        result = DisassemblyResult(
            sample_path=sample_path,
            backend=self.name,
        )

        # Step 1: Map IAT entries to API names
        iat_map = self._build_iat_map(pe)
        result.import_addresses = iat_map

        # Step 2: Disassemble executable sections
        all_instructions: dict[int, Instruction] = {}

        for section in pe.sections:
            chars = section.Characteristics
            is_exec = chars & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
            is_code = chars & 0x00000020  # IMAGE_SCN_CNT_CODE

            if is_exec or is_code:
                rva = section.VirtualAddress
                raw_data = section.get_data()
                file_offset = section.PointerToRawData

                # Disassemble linearly — step through instructions, not every byte.
                # This is O(n) instead of O(n²).
                for insn in md.disasm(raw_data, rva):
                    addr = insn.address
                    if addr not in all_instructions:
                        all_instructions[addr] = Instruction(
                            address=addr,
                            mnemonic=insn.mnemonic,
                            operands=insn.op_str,
                            size=insn.size,
                        )
                        # Resolve API calls
                        if insn.mnemonic == "call":
                            self._resolve_call(insn, addr, iat_map, all_instructions)

                # Enrich dangerous API calls with parameter context
                for addr, insn in all_instructions.items():
                    if insn.api_info and insn.api_info.name in DANGEROUS_API_SET:
                        insn.api_info.params_hint = self._extract_api_context(addr, all_instructions)

        # Step 2b: Resolve ordinal imports (can run early, doesn't need functions)
        self._resolve_ordinal_imports(pe, result)

        # Step 3: Identify functions via heuristics
        functions = self._identify_functions(pe, all_instructions)
        result.functions = functions

        # Step 4: Build CFGs — skip in quick mode or on timeout
        elapsed = time.time() - start_time
        if quick:
            # Quick mode: only record entry/ret info, no basic block graph
            self._build_lightweight_cfgs(functions, all_instructions, result)
        elif elapsed < timeout * 0.6:
            # Full mode: only build if we have enough time budget
            self._build_all_cfgs_batched(functions, all_instructions, result, quick=False)
        # else: skip CFG construction (timeout risk)

        # Step 5: Extract strings
        result.strings = self._extract_strings(pe)
        result.string_locations = list(self._string_locations)
        result.string_rvas = {s["rva"]: s["value"] for s in self._string_locations}

        # Step 6: Detect WDM IOCTL dispatch pattern
        self._detect_wdm_patterns(pe, all_instructions, functions, result)

        # Step 6a: Detect MiniFilter callbacks
        from src.disassembly.minifilter_detector import detect_minifilter
        detect_minifilter(result)

        # Step 6b: Inject IRP/IOCTL handler instruction addresses as proper
        # Function objects — the correlator looks for findings by function
        # address, so handler entry points must be in the functions dict.
        self._inject_handlers_as_functions(result, functions, all_instructions)

        # Parse IRP major function constants from code (handled by _detect_wdm_patterns)
        # _parse_irp_constants removed — its regex produced false positives on
        # random 0xE constants (e.g. 0xE0000000). The mov ptr+0x70 pattern in
        # _detect_wdm_patterns is specific to DriverObject+IRP_MJ_DEVICE_CONTROL.

        # Step 7: Map API calls to their containing functions
        result.function_apis = self._build_function_apis(functions, all_instructions)

        # Step 7b: Map API calls with detailed context (call addresses, param hints)
        result.function_api_details = self._build_function_api_details(functions, all_instructions)

        # Step 7c: Resolve dynamic imports (MmGetSystemRoutineAddress) — needs
        # ir.functions populated so _find_function_containing can work.
        self._resolve_dynamic_imports(pe, all_instructions, result, sample_path)

        # Step 8: Scan for inline privileged instructions
        self._scan_privileged_instructions(all_instructions, result)

        pe.close()
        return result

    # ------------------------------------------------------------------
    # Architecture detection
    # ------------------------------------------------------------------

    def _detect_capstone_arch(self, pe: pefile.PE) -> int:
        import capstone
        machine = pe.FILE_HEADER.Machine
        if machine == 0x8664:  # AMD64
            return capstone.CS_ARCH_X86
        elif machine == 0x14C:  # x86
            return capstone.CS_ARCH_X86
        elif machine == 0xAA64:  # ARM64
            return capstone.CS_ARCH_ARM64
        return capstone.CS_ARCH_X86

    def _detect_capstone_mode(self, pe: pefile.PE) -> int:
        import capstone
        machine = pe.FILE_HEADER.Machine
        if machine == 0x8664:
            return capstone.CS_MODE_64
        elif machine == 0x14C:
            return capstone.CS_MODE_32
        elif machine == 0xAA64:
            return capstone.CS_MODE_ARM
        return capstone.CS_MODE_32

    # ------------------------------------------------------------------
    # IAT mapping
    # ------------------------------------------------------------------

    def _build_iat_map(self, pe: pefile.PE) -> dict[int, str]:
        """Build a map of IAT thunk addresses to API names.

        Returns:
            {iat_va: "dll_name.api_name", ...}
            Keys are VAs (thunk.address from pefile, which is VA).
        """
        iat_map: dict[int, str] = {}

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace").lower()
                for thunk in entry.imports:
                    if thunk.name:
                        api_name = thunk.name.decode("utf-8", errors="replace")
                        iat_va = thunk.address  # pefile returns VA
                        iat_map[iat_va] = f"{dll_name}.{api_name}"
        except Exception as e:
            logging.warning("[capstone] Failed to build IAT map: %s", e)

        return iat_map

    # ------------------------------------------------------------------
    # Dynamic import resolution (M1: MmGetSystemRoutineAddress + M3: ordinals)
    # ------------------------------------------------------------------

    def _resolve_dynamic_imports(
        self,
        pe: pefile.PE,
        all_instructions: dict[int, Instruction],
        result: DisassemblyResult,
        sample_path: Path,
    ) -> None:
        """Resolve APIs imported by ordinal and via MmGetSystemRuntimeAddress."""
        # M3: Resolve ordinal imports
        self._resolve_ordinal_imports(pe, result)

        # M1: Resolve dynamic imports via MmGetSystemRuntimeAddress
        try:
            from src.disassembly.api_resolver import scan_for_dynamic_imports
            scan_for_dynamic_imports(
                result, all_instructions, pe.OPTIONAL_HEADER.ImageBase,
                pe_path=sample_path,
            )
        except Exception as e:
            logging.warning("[capstone] Failed to resolve dynamic imports: %s", e)

    def _resolve_ordinal_imports(
        self,
        pe: pefile.PE,
        result: DisassemblyResult,
    ) -> None:
        """Resolve APIs imported by ordinal (not by name).

        Some drivers import ntoskrnl APIs by ordinal to evade static analysis.
        We maintain a mapping of common kernel export ordinals to API names.
        """
        from src.config.defaults import NTOSKRNL_ORDINAL_MAP

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace").lower()
                if "ntoskrnl" not in dll_name and "hal.dll" not in dll_name:
                    continue

                dll_prefix = "ntoskrnl" if "ntoskrnl" in dll_name else "hal"

                for thunk in entry.imports:
                    if thunk.name:
                        continue  # Named import, already handled
                    if not thunk.ordinal:
                        continue

                    ordinal = thunk.ordinal & 0xFFFF  # Mask off hint flag
                    api_name = NTOSKRNL_ORDINAL_MAP.get(
                        f"{dll_prefix}_{ordinal}", ""
                    )
                    if api_name:
                        iat_rva = thunk.address
                        result.import_addresses[iat_rva] = f"{dll_prefix}.{api_name}"
        except Exception as e:
            logging.warning("[capstone] Failed to resolve ordinal imports: %s", e)

    def _scan_privileged_instructions(
        self,
        all_instructions: dict[int, Instruction],
        result: DisassemblyResult,
    ) -> None:
        """Scan for inline privileged instructions that act like dangerous APIs.

        Compilers emit these as raw instructions, not function calls.
        Each detected instruction is recorded as a pseudo-API call so
        the primitive_analyzer can match it.
        """
        from src.config.defaults import PRIVILEGED_INSTRUCTIONS

        for addr, insn in all_instructions.items():
            mnemonic = insn.mnemonic.lower()
            operands = insn.operands.lower()

            for ins_name, pseudo_api in PRIVILEGED_INSTRUCTIONS.items():
                if mnemonic == ins_name:
                    # Filter: mov cr0/cr3/cr4 (not general mov)
                    if ins_name == "mov" and not re.search(r'\bcr[0-9]\b', operands):
                        continue
                    # Filter: mov dr0-dr7 (debug registers)
                    if ins_name == "mov" and not re.search(r'\bdr[0-7]\b', operands):
                        continue

                    # Create a pseudo-API entry
                    fake_rva = addr + 0x100000  # Unique address space
                    result.import_addresses[fake_rva] = f"__insn.{pseudo_api}"

                    # Inject into the containing function's function_apis
                    func_addr = self._find_function_for_address(addr, result.functions)
                    if func_addr:
                        if func_addr not in result.function_apis:
                            result.function_apis[func_addr] = []
                        if pseudo_api not in result.function_apis[func_addr]:
                            result.function_apis[func_addr].append(pseudo_api)
                    break

    # ------------------------------------------------------------------
    # Call resolution
    # ------------------------------------------------------------------

    def _resolve_call(
        self,
        insn,
        addr: int,
        iat_map: dict[int, str],
        all_instructions: dict[int, Instruction],
    ) -> None:
        """Try to resolve a call instruction to a known API."""
        op_str = insn.op_str.strip()

        # Direct call via IAT: call qword ptr [rip+0x...]
        if "ptr" in op_str and "[" in op_str:
            # Try to extract the RIP-relative offset
            match = re.search(r'\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', op_str)
            if match:
                offset = int(match.group(1), 16)
                # Capstone insn.address is section.VirtualAddress (RVA).
                # For x64 RIP-relative: target_VA = (addr + ImageBase) + insn.size + offset
                # where (addr + ImageBase) is the instruction's VA.
                target_va = addr + self._image_base + insn.size + offset
                api_name = iat_map.get(target_va, "")
                if api_name:
                    all_instructions[addr].api_target = api_name
                    all_instructions[addr].api_info = APICallInfo(
                        name=api_name.split(".")[-1],
                        call_address=addr,
                        params_hint=f"rip+0x{offset:X}",
                    )
                    return

            # Also try without rip+: call qword ptr [0x...]
            match = re.search(r'\[\s*0x([0-9a-fA-F]+)\s*\]', op_str)
            if match:
                target_va = int(match.group(1), 16)
                api_name = iat_map.get(target_va, "")
                if api_name:
                    all_instructions[addr].api_target = api_name
                    all_instructions[addr].api_info = APICallInfo(
                        name=api_name.split(".")[-1],
                        call_address=addr,
                        params_hint=f"[0x{target_va:X}]",
                    )

        # Indirect call via register: call rax / call rcx / call x0 / etc.
        # Scan backwards for a recent IAT load into that register.
        elif re.match(r'^(r[a-d]x|r(?:8|9|1[0-5])|x[0-9]|x[12][0-9]|x30)$', op_str, re.IGNORECASE):
            reg = op_str.lower()
            iat_va = self._trace_iat_load_to_register(reg, addr, all_instructions)
            if iat_va and iat_va in iat_map:
                api_name = iat_map[iat_va]
                all_instructions[addr].api_target = api_name
                all_instructions[addr].api_info = APICallInfo(
                    name=api_name.split(".")[-1],
                    call_address=addr,
                    params_hint=f"via {reg} (from IAT)",
                )

        # Indexed indirect call: call [rax + rbx*8] or [rip + idx*8 + base]
        # M2: Try to resolve switch table entries instead of just marking.
        elif "*" in op_str and ("[" in op_str):
            resolved = self._resolve_switch_table_call(
                op_str, addr, iat_map, all_instructions
            )
            if not resolved:
                all_instructions[addr].api_target = "__indirect_switch__"

        # M2: Indirect jump (jmp reg) — same semantics as call reg for dispatch
        elif insn.mnemonic == "jmp" and re.match(r'^(r[a-d]x|r(?:8|9|1[0-5])|x[0-9]|x[12][0-9]|x30)$', op_str, re.IGNORECASE):
            reg = op_str.lower()
            iat_va = self._trace_iat_load_to_register(reg, addr, all_instructions)
            if iat_va and iat_va in iat_map:
                api_name = iat_map[iat_va]
                all_instructions[addr].api_target = api_name
                all_instructions[addr].api_info = APICallInfo(
                    name=api_name.split(".")[-1],
                    call_address=addr,
                    params_hint=f"jmp via {reg} (from IAT)",
                )

        # Direct relative call: call 0x...
        elif op_str.startswith("0x") or op_str.startswith("0X"):
            pass  # Internal function call, no API resolution needed

        # M4: ARM64 BLR (branch with link via register) — indirect call
        elif insn.mnemonic == "blr" and re.match(r'^(x[0-9]|x[12][0-9]|x30)$', op_str, re.IGNORECASE):
            reg = op_str.lower()
            iat_va = self._trace_iat_load_to_register(reg, addr, all_instructions)
            if iat_va and iat_va in iat_map:
                api_name = iat_map[iat_va]
                all_instructions[addr].api_target = api_name
                all_instructions[addr].api_info = APICallInfo(
                    name=api_name.split(".")[-1],
                    call_address=addr,
                    params_hint=f"blr via {reg} (from IAT)",
                )

        # M4: ARM64 ADRP+LDR pattern for IAT access
        # The IAT thunk is accessed via:
        #   adrp xN, page
        #   ldr xN, [xN, #offset]
        #   blr xN
        # We handle this through the existing _trace_iat_load_to_register
        # which now also tracks ARM64 ADRP/LDR patterns.

    def _trace_iat_load_to_register(
        self,
        reg: str,
        call_addr: int,
        all_instructions: dict[int, Instruction],
        max_back: int = 200,
    ) -> int | None:
        """Trace backwards from a `call reg` to find the IAT load into `reg`.

        M2: Increased max_back from 100→200, distance from 0x400→0x800
        to handle deeper indirection chains.

        M8: Memoized on (reg, call_addr) to avoid redundant tracing.

        Looks for patterns like:
            mov rax, qword ptr [rip+0x1234]
            ... (no intervening writes to rax)
            call rax

        Also tracks register-to-register transfers:
            mov rbx, qword ptr [rip+0x1234]
            mov rax, rbx
            call rax

        Returns the absolute VA of the IAT thunk, or None.
        """
        cache_key = (reg, call_addr)
        if cache_key in self._iat_trace_cache:
            return self._iat_trace_cache[cache_key]
        result = self._trace_iat_load_to_register_impl(
            reg, call_addr, all_instructions, max_back,
        )
        self._iat_trace_cache[cache_key] = result
        return result

    def _trace_iat_load_to_register_impl(
        self,
        reg: str,
        call_addr: int,
        all_instructions: dict[int, Instruction],
        max_back: int = 200,
    ) -> int | None:
        sorted_addrs = sorted(all_instructions.keys())
        idx = bisect.bisect_left(sorted_addrs, call_addr)
        if idx <= 0:
            return None

        # Track which registers have been clobbered as we scan backwards
        clobbered: set[str] = set()
        # Track register aliases: reg -> source_reg (e.g., rax -> rbx)
        aliases: dict[str, str] = {}

        for i in range(idx - 1, max(-1, idx - max_back - 1), -1):
            cur_addr = sorted_addrs[i]
            if call_addr - cur_addr > 0x800:
                break  # Too far back, stop tracing

            cur = all_instructions[cur_addr]
            if cur.mnemonic not in ("mov", "lea", "ldr", "adrp", "adr"):
                continue

            cur_str = cur.operands.strip()

            # Check if this instruction writes to our target register
            dest_match = re.match(r'^([a-z0-9]+)\b', cur_str, re.IGNORECASE)
            if not dest_match:
                continue
            dest_reg = dest_match.group(1).lower()

            if dest_reg != reg:
                # Writes to a different register — track clobbering
                clobbered.add(dest_reg)
                # Check if this is a register-to-register move that aliases our target
                src_match = re.search(r'\b([a-z0-9]+)\b', cur_str[len(dest_reg):], re.IGNORECASE)
                if src_match:
                    src_reg = src_match.group(1).lower()
                    if src_reg not in clobbered and src_reg != dest_reg:
                        # If dest_reg was our alias target, track the chain
                        pass
                continue

            # This instruction writes to our target register.
            # Check if it loads from an IAT thunk: mov reg, qword ptr [rip+offset]
            if "ptr" in cur_str and "rip" in cur_str:
                m = re.search(r'\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', cur_str)
                if m:
                    offset = int(m.group(1), 16)
                    insn_size = cur.size if cur.size else 6
                    target_rva = cur_addr + insn_size + offset
                    target_va = target_rva + self._image_base
                    return target_va

            # Check for memory load: mov reg, [rip+offset] (no ptr keyword)
            m = re.search(r'\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', cur_str)
            if m and "ptr" not in cur_str:
                offset = int(m.group(1), 16)
                insn_size = cur.size if cur.size else 6
                target_rva = cur_addr + insn_size + offset
                target_va = target_rva + self._image_base
                return target_va

            # Check for register-to-register transfer: mov rax, rbx
            # Where rbx was loaded from IAT
            src_match = re.search(r'\b([a-z0-9]+)\b', cur_str[len(dest_reg):], re.IGNORECASE)
            if src_match:
                src_reg = src_match.group(1).lower()
                if src_reg not in clobbered and src_reg != reg:
                    # Follow the alias chain
                    aliases[reg] = src_reg
                    # Try to trace through the aliased register
                    result = self._trace_iat_load_to_register(src_reg, cur_addr, all_instructions, max_back=max(30, max_back // 2))
                    if result:
                        return result

            # Register overwritten with something else — stop tracing
            return None

        return None

    def _resolve_switch_table_call(
        self,
        op_str: str,
        addr: int,
        iat_map: dict[int, str],
        all_instructions: dict[int, Instruction],
    ) -> bool:
        """M2: Attempt to resolve indexed indirect calls via switch tables.

        Pattern: call [rax + rbx*8]
        Where rax points to a jump table or IAT pointer array.

        Strategy:
        1. Trace back to find the base register value (pointer to table)
        2. Scan nearby memory-access patterns for IAT-like entries
        3. If a matching IAT entry is found, resolve the API
        """
        # Extract base register from pattern like [rax + rbx*8]
        base_match = re.search(r'\[\s*(r[a-z0-9]+)\s*\+', op_str, re.IGNORECASE)
        if not base_match:
            return False

        base_reg = base_match.group(1).lower()

        # Trace backwards to find what base_reg points to
        sorted_addrs = sorted(all_instructions.keys())
        idx = bisect.bisect_left(sorted_addrs, addr)

        for i in range(idx - 1, max(-1, idx - 50 - 1), -1):
            cur_addr = sorted_addrs[i]
            if addr - cur_addr > 0x200:
                break

            cur = all_instructions[cur_addr]
            cur_str = cur.operands.strip()

            # lea base_reg, [rip+offset] → pointer to table
            if cur.mnemonic == "lea":
                dest_m = re.match(r'^([a-z0-9]+)\b', cur_str, re.IGNORECASE)
                if dest_m and dest_m.group(1).lower() == base_reg:
                    off_m = re.search(r'\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', cur_str)
                    if off_m:
                        offset = int(off_m.group(1), 16)
                        insn_size = cur.size if cur.size else 7
                        table_va = cur_addr + insn_size + offset
                        # Scan the IAT map for nearby entries
                        for va in iat_map:
                            if abs(va - table_va) < 0x1000:
                                # Found IAT entry near the table base
                                all_instructions[addr].api_target = iat_map[va]
                                all_instructions[addr].api_info = APICallInfo(
                                    name=iat_map[va].split(".")[-1],
                                    call_address=addr,
                                    params_hint=f"switch_table@{hex(table_va)}",
                                )
                                return True

            # mov base_reg, rip-relative → pointer to table
            if cur.mnemonic == "mov":
                dest_m = re.match(r'^([a-z0-9]+)\b', cur_str, re.IGNORECASE)
                if dest_m and dest_m.group(1).lower() == base_reg:
                    if "rip" in cur_str and "ptr" in cur_str:
                        off_m = re.search(r'\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', cur_str)
                        if off_m:
                            offset = int(off_m.group(1), 16)
                            insn_size = cur.size if cur.size else 6
                            va = cur_addr + insn_size + offset
                            api_name = iat_map.get(va, "")
                            if api_name:
                                all_instructions[addr].api_target = api_name
                                all_instructions[addr].api_info = APICallInfo(
                                    name=api_name.split(".")[-1],
                                    call_address=addr,
                                    params_hint=f"via {base_reg} from switch table",
                                )
                                return True

        return False

    # ------------------------------------------------------------------
    # Function identification
    # ------------------------------------------------------------------

    def _identify_functions(
        self,
        pe: pefile.PE,
        all_instructions: dict[int, Instruction],
    ) -> dict[int, Function]:
        """Identify functions via prologue/ret heuristics.

        Strategy:
        1. Find ret/retfq instructions as function ends
        2. Scan backwards for function prologue (push rbp; mov rbp, rsp)
        3. Also identify call targets as function entry points
        """
        sorted_addrs = sorted(all_instructions.keys())
        functions: dict[int, Function] = {}

        # Find ret instructions and pair with preceding prologue
        ret_addrs = [
            addr for addr in sorted_addrs
            if all_instructions[addr].mnemonic in ("ret", "retf", "retfq")
        ]

        # Build address→index map once to avoid O(n²) lookups
        addr_to_idx = {addr: i for i, addr in enumerate(sorted_addrs)}

        for ret_addr in ret_addrs:
            # Scan backwards for prologue
            prologue_addr = self._find_prologue_before(ret_addr, sorted_addrs, all_instructions, addr_to_idx)
            if prologue_addr is not None:
                if prologue_addr not in functions:
                    func = Function(
                        name=f"sub_{prologue_addr:X}",
                        address=prologue_addr,
                        size=ret_addr - prologue_addr,
                    )
                    functions[prologue_addr] = func

        # Also mark call targets as function starts
        call_targets = set()
        for addr in sorted_addrs:
            insn = all_instructions[addr]
            if insn.mnemonic == "call":
                target = self._extract_call_target(insn, addr)
                if target and target in all_instructions:
                    call_targets.add(target)

        for target in call_targets:
            if target not in functions:
                # Find approximate function start by scanning backwards
                start = self._find_function_start(target, sorted_addrs, all_instructions, addr_to_idx)
                if start not in functions:
                    func = Function(
                        name=f"sub_{start:X}",
                        address=start,
                        size=0,  # Will be computed later
                    )
                    functions[start] = func

        # Add export table entries as function starts
        self._add_export_functions(pe, all_instructions, functions)

        # Compute function sizes using next function's start address
        self._compute_function_sizes(functions, sorted_addrs)

        # Tighten boundaries: split functions at ret instructions that
        # reveal multiple real functions merged into one due to missing
        # prologue in intermediate code blocks.
        self._tighten_function_boundaries(functions, sorted_addrs, all_instructions)

        # Build call graph (which function calls which)
        for addr in sorted_addrs:
            insn = all_instructions[addr]
            if insn.mnemonic == "call":
                target = self._extract_call_target(insn, addr)
                if target:
                    # Find which function this instruction belongs to
                    owner = self._find_function_for_address(addr, functions)
                    if owner is not None:
                        if target in functions:
                            functions[owner].calls.append(target)
                            if owner not in functions[target].called_by:
                                functions[target].called_by.append(owner)

        # Mark DriverEntry if found
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if entry_point_rva in functions:
            functions[entry_point_rva].is_entry = True
            functions[entry_point_rva].name = "DriverEntry"

        return functions

    def _find_prologue_before(
        self,
        ret_addr: int,
        sorted_addrs: list[int],
        all_instructions: dict[int, Instruction],
        addr_to_idx: dict[int, int] | None = None,
        max_distance: int = 2000,
    ) -> int | None:
        """Scan backwards from ret to find a function prologue."""
        if addr_to_idx:
            idx = addr_to_idx.get(ret_addr, -1)
        else:
            idx = sorted_addrs.index(ret_addr) if ret_addr in sorted_addrs else -1
        if idx < 0:
            return None

        # Look for standard prologue patterns
        for i in range(idx - 1, max(-1, idx - 201), -1):
            addr = sorted_addrs[i]
            if ret_addr - addr > max_distance:
                break

            insn = all_instructions[addr]

            # push rbp; mov rbp, rsp
            if insn.mnemonic == "push" and "rbp" in insn.operands:
                # Check next instruction
                if i + 1 < idx:
                    next_addr = sorted_addrs[i + 1]
                    next_insn = all_instructions[next_addr]
                    if (next_insn.mnemonic == "mov" and "rbp" in next_insn.operands
                            and "rsp" in next_insn.operands):
                        return addr

            # ARM64: stp x29, x30, [sp, #-imm]!; mov x29, sp
            if insn.mnemonic == "stp" and ("x29" in insn.operands or "x30" in insn.operands):
                if "sp" in insn.operands and ("[" in insn.operands or "]" in insn.operands):
                    if i + 1 < idx:
                        next_addr = sorted_addrs[i + 1]
                        next_insn = all_instructions[next_addr]
                        if next_insn.mnemonic == "mov" and "x29" in next_insn.operands and "sp" in next_insn.operands:
                            return addr
                    elif i + 1 == idx:
                        # stp is immediately before ret — single-instruction prologue
                        return addr

            # push rdi; push rsi; push rbx (common driver prologue)
            if insn.mnemonic == "push" and any(
                reg in insn.operands for reg in ("rbx", "rsi", "rdi", "r12", "r13", "r14", "r15")
            ):
                # Check if this looks like a function start (preceded by alignment or another function's ret)
                if i == 0:
                    return addr
                prev_addr = sorted_addrs[i - 1]
                prev_insn = all_instructions[prev_addr]
                if prev_insn.mnemonic in ("ret", "retf", "retfq", "nop", "int3"):
                    return addr

            # sub rsp, 0x... (stack frame allocation — often early in function)
            if insn.mnemonic == "sub" and "rsp" in insn.operands:
                if i == 0:
                    return addr
                prev_addr = sorted_addrs[i - 1]
                prev_insn = all_instructions[prev_addr]
                if prev_insn.mnemonic in ("push", "ret", "retf", "retfq"):
                    return addr

        return None

    def _find_function_start(
        self,
        target_addr: int,
        sorted_addrs: list[int],
        all_instructions: dict[int, Instruction],
        addr_to_idx: dict[int, int] | None = None,
        max_distance: int = 500,
    ) -> int:
        """Find the start of the function containing target_addr."""
        if addr_to_idx:
            idx = addr_to_idx.get(target_addr, -1)
        else:
            idx = sorted_addrs.index(target_addr) if target_addr in sorted_addrs else -1

        # Check if preceded by ret/nop (only when index was resolved)
        if idx > 0:
            prev_addr = sorted_addrs[idx - 1]
            prev_insn = all_instructions[prev_addr]
            if prev_insn.mnemonic in ("ret", "retf", "retfq", "nop", "int3"):
                return target_addr
            if target_addr - prev_addr > max_distance:
                return target_addr

        # Scan backwards for prologue
        for i in range(idx - 1, max(-1, idx - 101), -1):
            addr = sorted_addrs[i]
            if target_addr - addr > max_distance:
                break
            insn = all_instructions[addr]
            if insn.mnemonic == "push" and "rbp" in insn.operands:
                return addr
            # ARM64: stp x29, x30, [sp, #-imm]!
            if insn.mnemonic == "stp" and "x29" in insn.operands and "sp" in insn.operands:
                return addr
            if insn.mnemonic == "push" and any(
                reg in insn.operands for reg in ("rbx", "rsi", "rdi")
            ):
                if i == 0:
                    return addr
                prev_addr = sorted_addrs[i - 1]
                if all_instructions[prev_addr].mnemonic in ("ret", "retf", "retfq", "nop"):
                    return addr

        return target_addr

    def _find_function_for_address(
        self,
        addr: int,
        functions: dict[int, Function],
    ) -> int | None:
        """Find which function owns the given address."""
        sorted_funcs = sorted(functions.keys())
        for i in range(len(sorted_funcs) - 1, -1, -1):
            func_addr = sorted_funcs[i]
            if addr >= func_addr:
                func = functions[func_addr]
                if func.size > 0 and addr < func_addr + func.size:
                    return func_addr
                elif func.size == 0:
                    # Size not computed — check if addr is before next function
                    if i + 1 < len(sorted_funcs):
                        next_addr = sorted_funcs[i + 1]
                        if addr < next_addr:
                            return func_addr
                    else:
                        return func_addr
        return None

    def _extract_api_context(
        self,
        call_addr: int,
        all_instructions: dict[int, Instruction],
        max_back: int = 20,
    ) -> str:
        """Extract parameter context for an API call instruction.

        Scans backwards to find where the first parameter (rcx on x64)
        comes from. Returns a hint string like:
        - "rcx from [rcx+0x60] (IRP SystemBuffer, user-controllable)"
        - "rcx = constant 0x..."
        - "rcx from local variable [rsp+0x...]"
        """
        sorted_addrs = sorted(all_instructions.keys())
        idx = bisect.bisect_left(sorted_addrs, call_addr)
        if idx <= 0:
            return ""

        for i in range(idx - 1, max(-1, idx - max_back - 1), -1):
            cur_addr = sorted_addrs[i]
            if call_addr - cur_addr > 0x100:
                break

            cur = all_instructions[cur_addr]
            cur_str = cur.operands.strip()

            # mov rcx, ... — trace where rcx comes from
            if cur.mnemonic == "mov":
                dest_match = re.match(r'^(rcx)\b', cur_str, re.IGNORECASE)
                if dest_match:
                    # What is rcx being set to?
                    src_part = cur_str[len("rcx"):].strip().lstrip(",").strip()

                    # mov rcx, [rax+0x60] — IRP offset
                    off_match = re.search(r'\[\s*\w+\s*\+\s*(0x[0-9a-fA-F]+)\s*\]', src_part)
                    if off_match:
                        off = int(off_match.group(1), 16)
                        if off == 0x60:
                            return "rcx from [reg+0x60] (IRP SystemBuffer, user-controllable)"
                        elif off == 0x18:
                            return "rcx from [reg+0x18] (IRP UserBuffer, user-controllable)"
                        elif off == 0x98:
                            return "rcx from [reg+0x98] (IRP Parameters)"
                        else:
                            return f"rcx from [reg+0x{off:X}]"

                    # mov rcx, 0x... — constant
                    if src_part.startswith("0x") or src_part.isdigit():
                        return f"rcx = {src_part}"

                    # mov rcx, rax — register transfer, trace further
                    reg_match = re.match(r'^([a-z0-9]+)$', src_part, re.IGNORECASE)
                    if reg_match:
                        src_reg = reg_match.group(1).lower()
                        # Check if source reg is rcx itself (no-op)
                        if src_reg == "rcx":
                            continue
                        # Otherwise trace the source register
                        return f"rcx from {src_reg}"

            # lea rcx, [...] — load effective address
            if cur.mnemonic == "lea":
                dest_match = re.match(r'^(rcx)\b', cur_str, re.IGNORECASE)
                if dest_match:
                    return f"rcx = address of {cur_str.split(',', 1)[-1].strip()}"

        return ""

    def _get_op_str(self, insn) -> str:
        """Get operand string from either a capstone instruction or our Instruction object."""
        if hasattr(insn, "op_str"):
            return insn.op_str.strip()
        return getattr(insn, "operands", "").strip()

    def _add_export_functions(
        self,
        pe: pefile.PE,
        all_instructions: dict[int, Instruction],
        functions: dict[int, Function],
    ) -> None:
        """Add PE export table entries as function start points."""
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.address:
                        rva = exp.address
                        if rva in all_instructions and rva not in functions:
                            func = Function(
                                name=exp.name.decode("utf-8", errors="replace") if exp.name else f"export_{rva:X}",
                                address=rva,
                                size=0,
                            )
                            functions[rva] = func
        except Exception as e:
            logging.warning("[capstone] Failed to add export functions: %s", e)

    def _compute_function_sizes(
        self,
        functions: dict[int, Function],
        sorted_addrs: list[int],
    ) -> None:
        """Compute function sizes based on distance to next function start."""
        sorted_funcs = sorted(functions.keys())
        for i, func_addr in enumerate(sorted_funcs):
            func = functions[func_addr]
            if func.size > 0:
                continue  # Already has a size from ret-based detection

            if i + 1 < len(sorted_funcs):
                next_addr = sorted_funcs[i + 1]
                # Find last instruction before next function
                for addr in reversed(sorted_addrs):
                    if func_addr <= addr < next_addr:
                        func.size = addr - func_addr + 1
                        break
                if func.size == 0:
                    func.size = next_addr - func_addr
            else:
                # Last function — estimate from code boundaries
                for addr in reversed(sorted_addrs):
                    if addr >= func_addr:
                        func.size = max(addr - func_addr + 1, 0x10)
                        break

    def _tighten_function_boundaries(
        self,
        functions: dict[int, Function],
        sorted_addrs: list[int],
        all_instructions: dict[int, Instruction],
    ) -> None:
        """Split functions at ret boundaries that reveal merged functions.

        After initial identification, a large function may actually contain
        multiple real functions if intermediate blocks lack prologue.
        Use bisect to find ret instructions inside each function and create
        new function entries at the instruction following each ret.
        """
        func_addrs = sorted(functions.keys())
        if not func_addrs:
            return

        ret_addrs = sorted([
            addr for addr in sorted_addrs
            if all_instructions[addr].mnemonic in ("ret", "retf", "retfq")
        ])

        new_functions: dict[int, Function] = {}

        for func_addr in func_addrs:
            func = functions[func_addr]
            if func.size <= 0x20:
                continue  # Too small to contain multiple functions

            func_end = func_addr + func.size

            # Use bisect to find rets within this function's range
            lo = bisect.bisect_left(ret_addrs, func_addr)
            hi = bisect.bisect_right(ret_addrs, func_end - 1)

            for ret_idx in range(lo, hi):
                ret_addr = ret_addrs[ret_idx]
                # ret should not be at the very end of the function
                if ret_addr >= func_end - 4:
                    continue
                # ret should not be too close to function start
                if ret_addr - func_addr < 0x10:
                    continue

                # Find the first instruction after this ret
                after_idx = bisect.bisect_right(sorted_addrs, ret_addr)
                if after_idx >= len(sorted_addrs):
                    continue

                after_addr = sorted_addrs[after_idx]
                # Must still be within this function
                if after_addr >= func_end:
                    continue
                # Must not already be a known function
                if after_addr in functions or after_addr in new_functions:
                    continue

                # Gap check: ret and next instruction should be close
                if after_addr - ret_addr > 0x100:
                    continue

                # Found a split point — create new function
                new_functions[after_addr] = Function(
                    name=f"sub_{after_addr:X}",
                    address=after_addr,
                    size=0,
                )

        if new_functions:
            functions.update(new_functions)
            # Recompute sizes now that boundaries are tighter
            self._compute_function_sizes(functions, sorted_addrs)

    def _extract_call_target(self, insn, call_addr: int) -> int | None:
        """Extract the target address of a call instruction.

        Works with both capstone instructions (has op_str, size)
        and custom Instruction objects (has operands, no size).

        M4: Added ARM64 BL / BLR support.
        """
        # Handle both capstone and Instruction objects
        if hasattr(insn, "op_str"):
            op_str = insn.op_str.strip()
            insn_size = getattr(insn, "size", 6)
        else:
            op_str = insn.operands.strip()
            insn_size = 6  # Default for x64 RIP-relative call

        # ARM64: BL (branch with link) — relative call
        if op_str.startswith("0x") or op_str.startswith("0X"):
            try:
                return int(op_str, 16)
            except ValueError:
                pass

        # ARM64: BLR (branch link register) — indirect call via register
        # Similar to x86 call rax, handled separately in _resolve_call
        # but for function identification we need to recognize the target

        # RIP-relative: call qword ptr [rip+0x...]
        match = re.search(r'\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', op_str)
        if match:
            offset = int(match.group(1), 16)
            return call_addr + insn_size + offset

        # Absolute: call qword ptr [0x...]
        match = re.search(r'\[\s*0x([0-9a-fA-F]+)\s*\]', op_str)
        if match:
            return int(match.group(1), 16)

        return None

    # ------------------------------------------------------------------
    # Lightweight CFG for quick mode (entry/ret + direct branches)
    # ------------------------------------------------------------------

    def _build_lightweight_cfgs(
        self,
        functions: dict[int, Function],
        all_instructions: dict[int, Instruction],
        result: DisassemblyResult,
    ) -> None:
        """Build minimal CFGs for quick mode: entry, ret, direct branches.

        Each CFG has a single block (the whole function) with entry_block set.
        Successors are only direct branch targets. No fall-through linking.
        """
        import bisect
        func_addrs = sorted(functions.keys())
        sorted_insn_addrs = sorted(all_instructions.keys())

        # Group instructions by function
        func_instructions: dict[int, list[int]] = {fa: [] for fa in func_addrs}
        for insn_addr in sorted_insn_addrs:
            idx = bisect.bisect_right(func_addrs, insn_addr) - 1
            if idx >= 0:
                func_instructions[func_addrs[idx]].append(insn_addr)

        for func_addr in func_addrs:
            func_insn_addrs = func_instructions[func_addr]
            if not func_insn_addrs:
                continue

            cfg = CFG(function_address=func_addr)
            # Single block for the entire function
            block = BasicBlock(
                address=func_addr,
                end_address=func_insn_addrs[-1],
            )
            block.instructions = [all_instructions[a] for a in func_insn_addrs]
            cfg.blocks[func_addr] = block
            cfg.entry_block = func_addr

            # Record direct branch targets as successors
            branch_targets = set()
            for addr in func_insn_addrs:
                insn = all_instructions[addr]
                if insn.mnemonic in ("jmp", "je", "jne", "jz", "jnz",
                                     "ja", "jae", "jb", "jbe", "jg", "jge",
                                     "jl", "jle", "js", "jns", "jo", "jno",
                                     "jc", "jnc"):
                    target = self._extract_branch_target(insn, addr)
                    if target and target in func_instructions[func_addr]:
                        branch_targets.add(target)

            for target in branch_targets:
                if target not in cfg.blocks:
                    target_block = BasicBlock(
                        address=target,
                        end_address=target,
                    )
                    if target in all_instructions:
                        target_block.instructions.append(all_instructions[target])
                    cfg.blocks[target] = target_block
                block.successors.append(target)
                cfg.blocks[target].predecessors.append(func_addr)

            result.simple_cfgs[func_addr] = cfg

    # ------------------------------------------------------------------
    # CFG construction (batch O(N log F))
    # ------------------------------------------------------------------

    def _build_all_cfgs_batched(
        self,
        functions: dict[int, Function],
        all_instructions: dict[int, Instruction],
        result: DisassemblyResult,
        quick: bool,
    ) -> None:
        """Build CFGs for all functions in a single batch pass.

        Instead of O(F*N) per-function filtering, this pre-sorts all
        instructions once, groups them by function using bisect, then
        builds CFGs from the per-function instruction subsets.
        """
        import bisect
        import time

        func_addrs = sorted(functions.keys())
        if not func_addrs:
            return

        start_time = time.time()
        timeout = 25  # max seconds for all CFG construction

        # Step 1: Group instructions by function in O(N log F)
        func_instructions: dict[int, list[int]] = {fa: [] for fa in func_addrs}
        sorted_insn_addrs = sorted(all_instructions.keys())

        for insn_addr in sorted_insn_addrs:
            # Find the function this instruction belongs to
            idx = bisect.bisect_right(func_addrs, insn_addr) - 1
            if idx < 0:
                continue
            func_instructions[func_addrs[idx]].append(insn_addr)

        # Step 2: Build CFG for each function from its subset
        for i, func_addr in enumerate(func_addrs):
            # Timeout check every 100 functions
            if i % 100 == 0 and time.time() - start_time > timeout:
                break

            func_insn_addrs = func_instructions[func_addr]
            if not func_insn_addrs:
                continue

            cfg = self._build_cfg_from_subset(
                func_addr, func_insn_addrs, all_instructions, quick,
            )
            if quick:
                result.simple_cfgs[func_addr] = cfg
            else:
                result.cfgs[func_addr] = cfg

    def _build_cfg_from_subset(
        self,
        func_addr: int,
        sorted_insn_addrs: list[int],
        all_instructions: dict[int, Instruction],
        quick: bool,
    ) -> CFG:
        """Build a CFG from a pre-filtered set of instruction addresses.

        This is O(M log M) where M = instructions in this function,
        rather than O(N log N) for the full instruction set.
        """
        cfg = CFG(function_address=func_addr)

        # Find block boundaries
        boundaries = {func_addr}
        addr_to_idx = {addr: i for i, addr in enumerate(sorted_insn_addrs)}

        for addr in sorted_insn_addrs:
            insn = all_instructions[addr]
            if self._is_branch(insn):
                target = self._extract_branch_target(insn, addr)
                if target and target in addr_to_idx:
                    boundaries.add(target)
                # Next instruction after branch
                idx = addr_to_idx.get(addr, -1)
                if idx >= 0 and idx + 1 < len(sorted_insn_addrs):
                    boundaries.add(sorted_insn_addrs[idx + 1])

        sorted_boundaries = sorted(b for b in boundaries if b in addr_to_idx)

        # Create basic blocks
        for i, boundary in enumerate(sorted_boundaries):
            block = BasicBlock(address=boundary, end_address=boundary)
            block_end = boundary
            next_boundary = sorted_boundaries[i + 1] if i + 1 < len(sorted_boundaries) else None

            for addr in sorted_insn_addrs:
                if addr < boundary:
                    continue
                if next_boundary is not None and addr >= next_boundary:
                    break
                block.instructions.append(all_instructions[addr])
                block_end = addr

            block.end_address = block_end
            cfg.blocks[boundary] = block

        # Link successors/predecessors
        sorted_keys = sorted(cfg.blocks.keys())
        key_to_idx = {k: i for i, k in enumerate(sorted_keys)}

        for addr, block in cfg.blocks.items():
            last_insn = block.instructions[-1] if block.instructions else None
            if last_insn and self._is_branch(last_insn):
                target = self._extract_branch_target(last_insn, addr)
                if target and target in cfg.blocks:
                    block.successors.append(target)
                    cfg.blocks[target].predecessors.append(addr)

            # Fall-through
            idx = key_to_idx.get(addr, -1)
            if idx >= 0 and idx + 1 < len(sorted_keys):
                next_addr = sorted_keys[idx + 1]
                if next_addr not in block.successors:
                    block.successors.append(next_addr)
                    cfg.blocks[next_addr].predecessors.append(addr)

        if sorted_boundaries:
            cfg.entry_block = sorted_boundaries[0]

        return cfg

    def _is_branch(self, insn: Instruction) -> bool:
        """Check if an instruction is a branch/call/ret."""
        return insn.mnemonic in (
            "jmp", "je", "jne", "jz", "jnz",
            "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
            "js", "jns", "jo", "jno", "jp", "jnp",
            "jc", "jnc", "jcxz", "jecxz", "jrcxz",
            "call", "ret", "retf", "retfq",
            "loop", "loope", "loopne",
        )

    def _extract_branch_target(self, insn: Instruction, addr: int) -> int | None:
        """Extract branch target from an instruction."""
        if hasattr(insn, "op_str"):
            op_str = insn.op_str.strip()
            insn_size = getattr(insn, "size", 2)
        else:
            op_str = insn.operands.strip()
            insn_size = 2

        if op_str.startswith("0x") or op_str.startswith("0X"):
            try:
                return int(op_str, 16)
            except ValueError:
                pass

        # RIP-relative
        match = re.search(r'0x([0-9a-fA-F]+)', op_str)
        if match:
            try:
                val = int(match.group(1), 16)
                # Check if it's a small offset (RIP-relative)
                if val < 0x10000:
                    return addr + insn_size + val
                return val
            except ValueError:
                pass

        return None

    # ------------------------------------------------------------------
    # String extraction
    # ------------------------------------------------------------------

    @staticmethod
    def read_bytes_at_rva(rva: int, size: int, pe) -> bytes | None:
        """Read raw bytes at a given RVA from a PE file.

        Args:
            rva: Relative virtual address to read from.
            size: Number of bytes to read.
            pe: pefile.PE object (must already be loaded).

        Returns:
            Bytes at the given RVA, or None if RVA is not in any section.
            May be shorter than ``size`` if the RVA is near the end of a section.
        """
        for section in pe.sections:
            sec_start = section.VirtualAddress
            sec_end = sec_start + section.Misc_VirtualSize
            if sec_start <= rva < sec_end:
                offset = rva - sec_start
                available = sec_end - rva
                read_size = min(size, available)
                try:
                    raw = section.get_data()
                    return raw[offset:offset + read_size]
                except Exception:
                    return None
        return None

    def _extract_strings(self, pe: pefile.PE) -> list[str]:
        """Extract printable ASCII strings from .rdata and .data sections.

        Populates ``self._string_locations`` as a side effect so the caller
        can attach string location data to the IR afterwards.
        """
        strings: list[str] = []
        self._string_locations = []

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            if name in (".rdata", ".data", ".rodata", "PAGE"):
                try:
                    data = section.get_data()
                    base_rva = section.VirtualAddress
                    # Find ASCII strings (printable chars, length >= 4)
                    pattern = re.compile(rb'[\x20-\x7e]{4,}')
                    for match in pattern.finditer(data):
                        value = match.group().decode("ascii", errors="replace")
                        string_rva = base_rva + match.start()
                        strings.append(value)
                        self._string_locations.append({
                            "rva": string_rva,
                            "value": value,
                            "section": name,
                        })
                except Exception as e:
                    logging.warning("[capstone] Failed to extract strings from section %s: %s", name, e)

        return strings

    # ------------------------------------------------------------------
    # WDM pattern detection
    # ------------------------------------------------------------------

    def _detect_wdm_patterns(
        self,
        pe: pefile.PE,
        all_instructions: dict[int, Instruction],
        functions: dict[int, Function],
        result: DisassemblyResult,
    ) -> None:
        """Detect WDM IOCTL dispatch and IRP handler registration."""
        # Pattern 1: DriverObject->MajorFunction[IRP_MJ_*] = handler
        # This typically looks like:
        #   mov [DriverObject+offset], handler_addr
        #
        # IRP Major Function offset table (offset = index * 8 on x64):
        IRP_OFFSET_TABLE = {
            0x70: 0x0E,  # IRP_MJ_DEVICE_CONTROL (existing — primary)
            0x68: 0x0D,  # IRP_MJ_CREATE (existing)
            0x10: 0x02,  # IRP_MJ_CLOSE (existing)
            0xD8: 0x1B,  # IRP_MJ_PNP — Plug and Play
            0xE0: 0x1C,  # IRP_MJ_POWER — Power management
            0xF0: 0x1E,  # IRP_MJ_SYSTEM_CONTROL — WMI/GUID provider
        }

        for addr, insn in all_instructions.items():
            # Look for mov instructions that set function pointers in MajorFunction array
            # Must be a memory write: mov [reg+0xNN], handler_addr
            # This avoids matching bare constants like "mov eax, 0x70".
            if insn.mnemonic == "mov":
                op_str = self._get_op_str(insn)
                if "ptr" not in op_str:
                    continue
                for offset_hex, irp_major in IRP_OFFSET_TABLE.items():
                    if re.search(rf'\[\s*\w+\s*\+\s*(?:0x{offset_hex:X}|{offset_hex})\s*\]', op_str):
                        result.irp_handlers[irp_major] = addr

        # Pattern 2: IOCTL switch-case — look for comparison with constants
        # that look like IOCTL codes (CTL_CODE macros produce specific values)
        #
        # Strategy: find cmp instructions with IOCTL-like constants, then
        # follow the je/jne branch to find the handler function for that code.
        for addr, insn in all_instructions.items():
            if insn.mnemonic in ("cmp", "test"):
                op_str = self._get_op_str(insn)
                match = re.search(r'0x([0-9a-fA-F]{4,8})', op_str)
                if match:
                    val = int(match.group(1), 16)
                    if self._looks_like_ioctl_code(val):
                        if val not in result.ioctl_codes:
                            result.ioctl_codes.append(val)

                        # Try to follow the conditional branch (je/jne) to find
                        # the handler function for this IOCTL code.
                        handler_addr = self._find_ioctl_handler_for_code(
                            addr, insn, val, all_instructions, functions
                        )
                        if handler_addr:
                            result.ioctl_handlers[val] = handler_addr
                        else:
                            # Fallback: use the dispatcher function
                            func_addr = self._find_function_for_address(addr, functions)
                            if func_addr is not None:
                                if val not in result.ioctl_handlers:
                                    result.ioctl_handlers[val] = func_addr

        # Pattern 3: Check for WdfLdr/Wdf01000 imports → WDF driver
        for api_name in result.import_addresses.values():
            if "wdf" in api_name.lower():
                result.is_wdf_driver = True
                break

        # M4: Detect ARM64 architecture for taint tracking
        machine = pe.FILE_HEADER.Machine
        if machine == 0xAA64:  # ARM64
            result.is_arm64 = True

        # Phase 1: Detect FastIO dispatch
        self._detect_fastio_patterns(pe, all_instructions, functions, result)

    def _detect_fastio_patterns(
        self,
        pe: pefile.PE,
        all_instructions: dict[int, Instruction],
        functions: dict[int, Function],
        result: DisassemblyResult,
    ) -> None:
        """Detect FAST_IO_DISPATCH registration for entry point expansion.

        FastIO is an alternative to IRP dispatch used by filesystem drivers.
        FAST_IO_DISPATCH struct offsets (x64):
          0x00 FastIoCheckIfPossible
          0x08 FastIoRead
          0x10 FastIoWrite
          0x18 FastIoQueryBasicInfo
          0x20 FastIoQueryStandardInfo
          0x28 FastIoDeviceControl (critical — IOCTL equivalent)
          0x30 FastIoInternalDeviceControl
          0x38 FastIoLock
          0x40 FastIoUnlockSingle
          0x48 FastIoUnlockAll
          0x50 FastIoUnlockAllByKey
          0x58 FastIoQueryNetworkOpenInfo
          0x60 FastIoMdlRead / FastIoMdlReadDeviceControl
        """
        fastio_offset_map = {
            0x00: "FastIoCheckIfPossible",
            0x08: "FastIoRead",
            0x10: "FastIoWrite",
            0x28: "FastIoDeviceControl",
            0x30: "FastIoInternalDeviceControl",
            0x38: "FastIoLock",
            0x40: "FastIoUnlockSingle",
            0x48: "FastIoUnlockAll",
            0x50: "FastIoUnlockAllByKey",
        }

        # Pattern 1: mov [reg+offset], handler where offset matches FAST_IO_DISPATCH
        for addr, insn in all_instructions.items():
            if insn.mnemonic == "mov" and "ptr" in self._get_op_str(insn):
                op_str = self._get_op_str(insn)
                for off, name in fastio_offset_map.items():
                    if re.search(rf'\[\s*\w+\s*\+\s*(?:0x{off:X}|{off})\s*\]', op_str):
                        # Make sure this is NOT already matched as an IRP handler
                        if addr not in result.irp_handlers.values():
                            result.fastio_handlers[off] = addr

        # Pattern 2: Import-based confirmation
        fastio_imports = {
            "IoRegisterFileSystem",
            "IoRegisterFsRegistrationChange",
            "IoRegisterFsRegistrationChangeEx",
        }
        has_fastio_import = any(
            api in fastio_imports
            for api in result.import_addresses.values()
        )
        # If no fastio_imports but we found struct patterns, still report
        # (drivers may import by ordinal or dynamically resolve)

    def _inject_handlers_as_functions(
        self,
        result: DisassemblyResult,
        functions: dict[int, Function],
        all_instructions: dict[int, Instruction],
    ) -> None:
        """Resolve IRP/IOCTL handler instruction addresses to function entry points.

        _detect_wdm_patterns stores the *instruction* address (e.g. where
        `mov [reg+0x70], handler` lives).  The correlator indexes findings by
        *function* address, so we need the function entry point.
        """
        handler_addrs: set[int] = set()

        for addr in result.irp_handlers.values():
            handler_addrs.add(addr)
        for addr in result.ioctl_handlers.values():
            handler_addrs.add(addr)

        sorted_addrs = sorted(all_instructions.keys())

        for insn_addr in handler_addrs:
            # Resolve instruction address to owning function
            func_addr = self._find_function_for_address(insn_addr, functions)
            if func_addr is not None:
                # Already registered as part of an existing function — skip
                continue

            # No owning function found — create one from this instruction address
            start = self._find_function_start(
                insn_addr, sorted_addrs, all_instructions, max_distance=500,
            )
            if start not in functions:
                func = Function(
                    name=f"sub_{start:X}",
                    address=start,
                    size=0,
                )
                functions[start] = func

    def _looks_like_ioctl_code(self, val: int) -> bool:
        """Heuristic check if a value looks like an IOCTL code."""
        from src.utils.ioctl import looks_like_ioctl_code
        return looks_like_ioctl_code(val)

    def _find_ioctl_handler_for_code(
        self,
        cmp_addr: int,
        cmp_insn: Instruction,
        ioctl_code: int,
        all_instructions: dict[int, Instruction],
        functions: dict[int, Function],
    ) -> int | None:
        """Follow the conditional branch after a cmp to find the handler function.

        After `cmp eax, IOCTL_CODE`, the next instruction is typically je/jne.
        We follow the branch target (the 'equal' path) to find the first call
        or the function that the branch leads to.

        Returns:
            Handler function address, or None if not determinable.
        """
        sorted_addrs = sorted(all_instructions.keys())
        addr_to_idx = {a: i for i, a in enumerate(sorted_addrs)}
        idx = addr_to_idx.get(cmp_addr, -1)
        if idx < 0:
            return None

        # Look at the next 1-3 instructions after cmp for je/jne/jg/jl
        branch_targets = []
        for i in range(idx + 1, min(idx + 4, len(sorted_addrs))):
            next_addr = sorted_addrs[i]
            if next_addr - cmp_addr > 0x20:  # Too far, not the branch
                break
            next_insn = all_instructions[next_addr]
            if next_insn.mnemonic in ("je", "jne", "jz", "jnz", "ja", "jb", "jg", "jl"):
                target = self._extract_branch_target(next_insn, next_addr)
                if target:
                    branch_targets.append(target)
            break  # Only consider the first branch

        if not branch_targets:
            return None

        # For each branch target, find what function it leads to
        for target in branch_targets:
            # Check if target is a call instruction — follow it
            target_insn = all_instructions.get(target)
            if target_insn and target_insn.mnemonic == "call":
                call_target = self._extract_call_target(target_insn, target)
                if call_target and call_target in functions:
                    return call_target

            # Otherwise find the function containing the target
            func_addr = self._find_function_for_address(target, functions)
            if func_addr and func_addr != self._find_function_for_address(cmp_addr, functions):
                return func_addr

        return None

    # ------------------------------------------------------------------
    # Function API mapping
    # ------------------------------------------------------------------

    def _build_function_apis(
        self,
        functions: dict[int, Function],
        all_instructions: dict[int, Instruction],
    ) -> dict[int, list[str]]:
        """Map each function to the kernel APIs it calls.

        Uses Instruction.api_target (set by _resolve_call) to find
        which APIs each function references through its IAT calls.

        Uses binary search on sorted function start addresses to find
        the containing function in O(log n) instead of O(n).
        """
        func_apis: dict[int, list[str]] = {}
        for func_addr in functions:
            func_apis[func_addr] = []

        # Build sorted list of (start_addr, func_addr, end_addr) for binary search
        sorted_funcs: list[tuple[int, int, int]] = []
        for func_addr, func in functions.items():
            func_end = func_addr + func.size if func.size > 0 else func_addr + 0x100
            sorted_funcs.append((func_addr, func_addr, func_end))
        sorted_funcs.sort(key=lambda x: x[0])
        func_starts = [s[0] for s in sorted_funcs]

        # For each API call instruction, find its containing function via bisect
        for addr, insn in all_instructions.items():
            if not insn.api_target:
                continue
            api_short = insn.api_target.split(".")[-1] if "." in insn.api_target else insn.api_target

            # Binary search: find rightmost function start <= addr
            idx = bisect.bisect_right(func_starts, addr) - 1
            if idx < 0:
                continue
            _, start, end = sorted_funcs[idx]
            if start <= addr < end:
                if api_short not in func_apis[start]:
                    func_apis[start].append(api_short)

        return func_apis

    def _build_function_api_details(
        self,
        functions: dict[int, Function],
        all_instructions: dict[int, Instruction],
    ) -> dict[int, list[APICallInfo]]:
        """Map each function to detailed API call information.

        Like _build_function_apis but returns APICallInfo objects with
        call addresses and parameter hints instead of just API names.
        """
        func_api_details: dict[int, list[APICallInfo]] = {}
        for func_addr in functions:
            func_api_details[func_addr] = []

        sorted_funcs: list[tuple[int, int, int]] = []
        for func_addr, func in functions.items():
            func_end = func_addr + func.size if func.size > 0 else func_addr + 0x100
            sorted_funcs.append((func_addr, func_addr, func_end))
        sorted_funcs.sort(key=lambda x: x[0])
        func_starts = [s[0] for s in sorted_funcs]

        for addr, insn in all_instructions.items():
            if not insn.api_info:
                continue

            idx = bisect.bisect_right(func_starts, addr) - 1
            if idx < 0:
                continue
            _, start, end = sorted_funcs[idx]
            if start <= addr < end:
                func_api_details[start].append(insn.api_info)

        return func_api_details


# ---------------------------------------------------------------------------
# IR serialization helpers — used by analysis cache and deep analysis module
# ---------------------------------------------------------------------------

def _serialize_ir(ir: DisassemblyResult) -> dict[str, Any]:
    """Serialize a DisassemblyResult to a JSON-compatible dict."""
    def _func(f: Function) -> dict:
        return {
            "name": f.name, "address": f.address, "size": f.size,
            "called_by": f.called_by, "calls": f.calls,
            "is_entry": f.is_entry, "is_ioctl_handler": f.is_ioctl_handler,
            "pseudo_code": f.pseudo_code,
        }

    def _insn(i: Instruction) -> dict:
        d = {
            "address": i.address, "mnemonic": i.mnemonic, "operands": i.operands,
            "api_target": i.api_target, "size": i.size,
        }
        if i.api_info:
            d["api_info"] = {
                "name": i.api_info.name, "call_address": i.api_info.call_address,
                "params_hint": i.api_info.params_hint,
                "user_controllable": i.api_info.user_controllable,
            }
        return d

    def _block(b: BasicBlock) -> dict:
        return {
            "address": b.address, "end_address": b.end_address,
            "successors": b.successors, "predecessors": b.predecessors,
            "instructions": [_insn(i) for i in b.instructions],
        }

    def _cfg(c: CFG) -> dict:
        return {
            "function_address": c.function_address,
            "entry_block": c.entry_block,
            "blocks": {str(a): _block(bl) for a, bl in c.blocks.items()},
        }

    return {
        "sample_path": str(ir.sample_path),
        "backend": ir.backend,
        "functions": {str(a): _func(f) for a, f in ir.functions.items()},
        "cfgs": {str(a): _cfg(c) for a, c in ir.cfgs.items()},
        "simple_cfgs": {str(a): _cfg(c) for a, c in ir.simple_cfgs.items()},
        "ioctl_codes": ir.ioctl_codes,
        "ioctl_dispatcher": ir.ioctl_dispatcher,
        "irp_handlers": {str(k): v for k, v in ir.irp_handlers.items()},
        "ioctl_handlers": {str(k): v for k, v in ir.ioctl_handlers.items()},
        "import_addresses": {str(k): v for k, v in ir.import_addresses.items()},
        "function_apis": {str(k): v for k, v in ir.function_apis.items()},
        "function_api_details": {
            str(k): [
                {"name": a.name, "call_address": a.call_address,
                 "params_hint": a.params_hint, "user_controllable": a.user_controllable}
                for a in apis
            ]
            for k, apis in ir.function_api_details.items()
        },
        "strings": ir.strings,
        "is_wdf_driver": ir.is_wdf_driver,
        "is_arm64": ir.is_arm64,
        "is_filter_driver": ir.is_filter_driver,
        "dynamic_imports": {str(k): v for k, v in ir.dynamic_imports.items()},
        "deferred_callbacks": {str(k): v for k, v in ir.deferred_callbacks.items()},
        "wdf_dispatch_functions": {str(k): v for k, v in ir.wdf_dispatch_functions.items()},
        "wdf_context_objects": {str(k): v for k, v in ir.wdf_context_objects.items()},
        "wdf_io_queue_configs": ir.wdf_io_queue_configs,
        "string_locations": ir.string_locations,
        "string_rvas": {str(k): v for k, v in ir.string_rvas.items()},
    }


def _deserialize_ir(raw: dict[str, Any], sample_path: Path, backend: str = "ghidra") -> DisassemblyResult:
    """Deserialize a JSON dict back to a DisassemblyResult."""
    ir = DisassemblyResult(sample_path=sample_path, backend=backend)

    def _func(d: dict) -> Function:
        return Function(
            name=d["name"], address=d["address"], size=d["size"],
            called_by=d["called_by"], calls=d["calls"],
            is_entry=d["is_entry"], is_ioctl_handler=d["is_ioctl_handler"],
            pseudo_code=d["pseudo_code"],
        )

    def _insn(d: dict) -> Instruction:
        api_info = None
        if d.get("api_info"):
            ai = d["api_info"]
            api_info = APICallInfo(
                name=ai["name"], call_address=ai["call_address"],
                params_hint=ai.get("params_hint", ""),
                user_controllable=ai.get("user_controllable", False),
            )
        return Instruction(
            address=d["address"], mnemonic=d["mnemonic"], operands=d["operands"],
            api_target=d.get("api_target", ""), api_info=api_info,
            size=d.get("size", 0),
        )

    def _block(d: dict) -> BasicBlock:
        return BasicBlock(
            address=d["address"], end_address=d["end_address"],
            successors=d["successors"], predecessors=d["predecessors"],
            instructions=[_insn(i) for i in d["instructions"]],
        )

    def _cfg(d: dict) -> CFG:
        c = CFG(function_address=d["function_address"], entry_block=d["entry_block"])
        c.blocks = {int(a): _block(bl) for a, bl in d["blocks"].items()}
        return c

    ir.functions = {int(a): _func(f) for a, f in raw.get("functions", {}).items()}
    ir.cfgs = {int(a): _cfg(c) for a, c in raw.get("cfgs", {}).items()}
    ir.simple_cfgs = {int(a): _cfg(c) for a, c in raw.get("simple_cfgs", {}).items()}
    ir.ioctl_codes = raw.get("ioctl_codes", [])
    ir.ioctl_dispatcher = raw.get("ioctl_dispatcher", 0)
    ir.irp_handlers = {int(k): v for k, v in raw.get("irp_handlers", {}).items()}
    ir.ioctl_handlers = {int(k): v for k, v in raw.get("ioctl_handlers", {}).items()}
    ir.import_addresses = {int(k): v for k, v in raw.get("import_addresses", {}).items()}
    ir.function_apis = {int(k): v for k, v in raw.get("function_apis", {}).items()}
    ir.function_api_details = {
        int(k): [
            APICallInfo(name=a["name"], call_address=a["call_address"],
                        params_hint=a.get("params_hint", ""),
                        user_controllable=a.get("user_controllable", False))
            for a in apis
        ]
        for k, apis in raw.get("function_api_details", {}).items()
    }
    ir.strings = raw.get("strings", [])
    ir.is_wdf_driver = raw.get("is_wdf_driver", False)
    ir.is_arm64 = raw.get("is_arm64", False)
    ir.is_filter_driver = raw.get("is_filter_driver", False)
    ir.dynamic_imports = {int(k): v for k, v in raw.get("dynamic_imports", {}).items()}
    ir.deferred_callbacks = {int(k): v for k, v in raw.get("deferred_callbacks", {}).items()}
    ir.wdf_dispatch_functions = {int(k): v for k, v in raw.get("wdf_dispatch_functions", {}).items()}
    ir.wdf_context_objects = {int(k): v for k, v in raw.get("wdf_context_objects", {}).items()}
    ir.wdf_io_queue_configs = raw.get("wdf_io_queue_configs", [])
    ir.string_locations = raw.get("string_locations", [])
    ir.string_rvas = {int(k): v for k, v in raw.get("string_rvas", {}).items()}

    return ir
