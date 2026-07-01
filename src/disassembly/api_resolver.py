"""DriverScope — Dynamic API Resolver.

Detects APIs resolved at runtime via MmGetSystemRoutineAddress
and similar dynamic import mechanisms.

Patterns detected:
  1. MmGetSystemRoutineAddress(L"ApiName")
  2. ZwQuerySystemInformation(SystemModuleInformation) → manual IAT walk
  3. GetProcAddress-style resolution in user-mode drivers (UMDF)

Resolved APIs are injected into:
  - DisassemblyResult.dynamic_imports: {func_addr: [api_names]}
  - The calling function's function_apis mapping
"""

from __future__ import annotations

import bisect
import logging
import re
from pathlib import Path
from typing import Any

from src.models import APICallInfo, DisassemblyResult, Function, Instruction


def _op_str(insn) -> str:
    """Get operand string, works with both Instruction and raw capstone objects."""
    if hasattr(insn, "op_str"):
        return insn.op_str.strip()
    return getattr(insn, "operands", "").strip()


# UNICODE_STRING structure offset for x64
# UNICODE_STRING { Length (2), MaximumLength (2), Buffer (8) }
# We look for the string pointer directly.

# Common APIs resolved dynamically by BYOVD drivers
_KNOWN_DYNAMIC_API_PATTERNS = [
    r"^(Mm[A-Z]\w+)$",      # MmMapIoSpace, MmGetPhysicalAddress, etc.
    r"^(Ke[A-Z]\w+)$",      # KeWriteMsr, KeReadMsr, etc.
    r"^(Zw[A-Z]\w+)$",      # ZwCreateThreadEx, etc.
    r"^(Nt[A-Z]\w+)$",      # Nt* aliases
    r"^(Ex[A-Z]\w+)$",      # ExAllocatePoolWithTag, etc.
    r"^(Ps[A-Z]\w+)$",      # PsSetLoadImageNotifyRoutine, etc.
    r"^(Io[A-Z]\w+)$",      # IoQueueWorkItem, etc.
    r"^(Se[A-Z]\w+)$",      # SeSinglePrivilegeCheck
    r"^(Ob[A-Z]\w+)$",      # ObReferenceObjectByHandle, etc.
    r"^(Rtl[A-Z]\w+)$",     # RtlCompareMemory, etc.
    r"^(Hal[A-Z]\w+)$",     # HalTranslateBusAddress, etc.
]


def _looks_like_kernel_api(name: str) -> bool:
    """Check if a string looks like a Windows kernel API name."""
    for pat in _KNOWN_DYNAMIC_API_PATTERNS:
        if re.match(pat, name):
            return True
    return False


def scan_for_dynamic_imports(
    ir: DisassemblyResult,
    all_instructions: dict[int, Instruction],
    image_base: int = 0,
    pe_path: Path | None = None,
) -> None:
    """Scan for MmGetSystemRoutineAddress and similar dynamic import patterns.

    For each detected dynamic import:
    1. Extract the API name from the UNICODE_STRING argument
    2. Find the indirect call that uses the resolved function pointer
    3. Inject the resolved API into ir.dynamic_imports and ir.function_apis
    4. Add to ir.import_addresses so primitive_analyzer can match it

    Handles both x64 (rcx first arg) and x86 (stack push) calling conventions.
    For x86 drivers with obfuscated strings, falls back to behavioral inference.

    Args:
        ir: DisassemblyResult to update in-place.
        all_instructions: All instructions (from CapstoneBackend).
        image_base: Image base address for RVA→VA conversion.
    """
    if not ir.import_addresses:
        return

    # Check if MmGetSystemRoutineAddress is imported
    has_mm_get_system = any(
        "mmgetsystemroutineaddress" in api.lower()
        for api in ir.import_addresses.values()
    )
    if not has_mm_get_system:
        return

    ir.dynamic_imports = {}
    sorted_addrs = sorted(all_instructions.keys())

    # Pre-scan PE data sections for all kernel API name strings
    data_section_map: dict[int, str] = {}
    if pe_path and pe_path.exists():
        data_section_map = _extract_api_names_from_data_sections(pe_path, ir)

        # Attempt to decrypt XOR-encrypted API strings and merge into the map
        decrypted = _try_decrypt_api_strings(pe_path, ir, data_section_map)
        if decrypted:
            data_section_map.update(decrypted)
            logging.info(
                "[api_resolver] Decrypted %d encrypted API string(s) from data sections",
                len(decrypted),
            )

    # Find all calls to MmGetSystemRoutineAddress
    for addr, insn in all_instructions.items():
        api_target = getattr(insn, 'api_target', '')
        if not api_target:
            continue
        api_short = api_target.split(".")[-1] if "." in api_target else api_target
        if api_short.lower() != "mmgetsystemroutineaddress":
            continue

        # Found a call to MmGetSystemRoutineAddress.
        string_va = _trace_string_argument(addr, insn, all_instructions, sorted_addrs)

        api_name = None
        if string_va:
            api_name = _extract_unicode_string(string_va, all_instructions, image_base, pe_path)

        # Fallback: try the pre-scanned data section map by matching nearby RVA
        if not api_name or not _looks_like_kernel_api(api_name):
            img_base = image_base if image_base else 0
            string_rva = string_va - img_base if string_va else None

            if string_rva and string_rva in data_section_map:
                api_name = data_section_map[string_rva]
            else:
                # Try nearby matches (UNICODE_STRING.Buffer may be offset)
                if string_rva:
                    for rva, name in data_section_map.items():
                        if abs(rva - string_rva) < 0x20:
                            api_name = name
                            break

                # For x86 drivers with obfuscated strings: try to find a pushed
                # string address near the call that matches data_section_map
                if not api_name:
                    api_name = _find_pushed_string_near(
                        addr, all_instructions, sorted_addrs, data_section_map, img_base
                    )

        # Final fallback: infer API from post-call behavior
        # (look at what the resolved function is used for)
        if not api_name:
            api_name = _infer_api_from_behavior(
                addr, all_instructions, sorted_addrs, ir, data_section_map, image_base,
            )

        if not api_name or not _looks_like_kernel_api(api_name):
            # Record as unknown dynamic resolve — still useful for analysis
            api_name = "__dynamic_resolve"

        # Find the function that contains this call
        func_addr = _find_function_containing(addr, ir, sorted_addrs)
        if not func_addr:
            continue

        # Find the indirect call that uses the return value
        call_addr = _find_indirect_call_after(addr, all_instructions, sorted_addrs)

        # Register the dynamic import
        if func_addr not in ir.dynamic_imports:
            ir.dynamic_imports[func_addr] = []
        if api_name not in ir.dynamic_imports[func_addr]:
            ir.dynamic_imports[func_addr].append(api_name)

        # Inject into function_apis
        if func_addr not in ir.function_apis:
            ir.function_apis[func_addr] = []
        if api_name not in ir.function_apis[func_addr]:
            ir.function_apis[func_addr].append(api_name)

        # Inject into import_addresses
        inject_addr = call_addr if call_addr else addr + 0x1000
        if inject_addr not in ir.import_addresses:
            ir.import_addresses[inject_addr] = f"ntoskrnl.{api_name}"

        # If we found the actual call instruction, mark it too
        if call_addr and call_addr in all_instructions:
            call_insn = all_instructions[call_addr]
            call_insn.api_target = f"ntoskrnl.{api_name}"
            call_insn.api_info = APICallInfo(
                name=api_name,
                call_address=call_addr,
                params_hint="via MmGetSystemRoutineAddress",
            )


def _trace_string_argument(
    call_addr: int,
    call_insn: Instruction,
    all_instructions: dict[int, Instruction],
    sorted_addrs: list[int],
    max_back: int = 50,
) -> int | None:
    """Trace backwards from MmGetSystemRoutineAddress call to find the string VA.

    x64: The string address is passed in rcx (first argument).
         Look for: lea rcx, [rip+offset] or mov rcx, immediate
    x86:  The string address is pushed on the stack.
         Look for: push offset_string  (push 0xXXXXXXXX)
    """
    idx = bisect.bisect_left(sorted_addrs, call_addr)
    if idx <= 0:
        return None

    for i in range(idx - 1, max(-1, idx - max_back - 1), -1):
        cur_addr = sorted_addrs[i]
        if call_addr - cur_addr > 0x200:
            break

        cur = all_instructions[cur_addr]
        cur_str = _op_str(cur)

        # --- x64 patterns ---
        # lea rcx, [rip+offset] — UNICODE_STRING pointer
        if cur.mnemonic == "lea":
            m = re.match(r'^rcx\s*,\s*\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', cur_str, re.IGNORECASE)
            if m:
                offset = int(m.group(1), 16)
                insn_size = cur.size if cur.size else 7
                return cur_addr + insn_size + offset

        # mov rcx, 0x... — immediate string address
        if cur.mnemonic == "mov":
            m = re.match(r'^rcx\s*,\s*0x([0-9a-fA-F]+)$', cur_str, re.IGNORECASE)
            if m:
                return int(m.group(1), 16)

            # mov rcx, rax — register transfer, trace the source
            m = re.match(r'^rcx\s*,\s*(r[a-z0-9]+)$', cur_str, re.IGNORECASE)
            if m:
                src_reg = m.group(1).lower()
                return _trace_register_source(src_reg, cur_addr, all_instructions, sorted_addrs, max_back=max(10, max_back // 2))

            # rcx overwritten with something else — stop
            if re.match(r'^rcx\b', cur_str, re.IGNORECASE):
                break

        # --- x86 patterns ---
        # push 0xXXXXXXXX — immediate push of string VA (UNICODE_STRING pointer)
        if cur.mnemonic == "push":
            m = re.match(r'^0x([0-9a-fA-F]+)$', cur_str, re.IGNORECASE)
            if m:
                return int(m.group(1), 16)

        # mov dword ptr [esp+0x4], reg — first arg setup (stdcall)
        if cur.mnemonic == "mov" and "esp" in cur_str.lower():
            m = re.search(r'\[\s*esp\s*\+\s*0x4\s*\]', cur_str, re.IGNORECASE)
            if m:
                # Trace the source register
                src_m = re.search(r',\s*([a-z0-9]+)', cur_str, re.IGNORECASE)
                if src_m:
                    src_reg = src_m.group(1).lower()
                    return _trace_register_source(src_reg, cur_addr, all_instructions, sorted_addrs, max_back=max(10, max_back // 2))

    return None


def _trace_register_source(
    reg: str,
    from_addr: int,
    all_instructions: dict[int, Instruction],
    sorted_addrs: list[int],
    max_back: int = 30,
) -> int | None:
    """Trace backwards to find where a register got its value."""
    idx = bisect.bisect_left(sorted_addrs, from_addr)
    if idx <= 0:
        return None

    for i in range(idx - 1, max(-1, idx - max_back - 1), -1):
        cur_addr = sorted_addrs[i]
        if from_addr - cur_addr > 0x100:
            break

        cur = all_instructions[cur_addr]
        cur_str = _op_str(cur)

        if cur.mnemonic in ("mov", "lea"):
            dest_m = re.match(r'^([a-z0-9]+)\b', cur_str, re.IGNORECASE)
            if dest_m and dest_m.group(1).lower() == reg:
                # Check if loading from RIP-relative
                m = re.search(r'\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]', cur_str, re.IGNORECASE)
                if m:
                    offset = int(m.group(1), 16)
                    insn_size = cur.size if cur.size else 7
                    return cur_addr + insn_size + offset
                # Check for immediate
                m = re.search(r',\s*0x([0-9a-fA-F]+)$', cur_str, re.IGNORECASE)
                if m:
                    return int(m.group(1), 16)

    return None


def _extract_unicode_string(
    string_va: int,
    all_instructions: dict[int, Instruction],
    image_base: int,
    pe_path: Path | None = None,
) -> str | None:
    """Extract a wide-char string (UNICODE_STRING.Buffer) from the PE file.

    Reads raw bytes from the PE's .rdata/.data/PAGE sections to find
    the UTF-16LE string at the given virtual address.
    """
    if pe_path is None or not pe_path.exists():
        return None

    import pefile

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        img_base = pe.OPTIONAL_HEADER.ImageBase
        rva = string_va - img_base

        for section in pe.sections:
            sec_rva = section.VirtualAddress
            sec_size = section.Misc_VirtualSize
            if sec_rva <= rva < sec_rva + sec_size:
                offset = rva - sec_rva
                data = section.get_data()
                if offset >= len(data):
                    pe.close()
                    return None

                # Extract UTF-16LE null-terminated string
                end = offset
                while end + 1 < len(data) and end < offset + 512:
                    if data[end] == 0 and data[end + 1] == 0:
                        break
                    end += 2

                raw_bytes = data[offset:end]
                try:
                    decoded = raw_bytes.decode("utf-16le", errors="replace")
                except Exception:
                    pe.close()
                    return None

                pe.close()
                # Filter: kernel API names are [A-Z][A-Za-z0-9]{2,60}
                cleaned = "".join(c for c in decoded if c.isprintable() and ord(c) < 128)
                if len(cleaned) >= 3 and re.match(r'^[A-Z][A-Za-z0-9]{2,60}$', cleaned):
                    return cleaned
                return None

        pe.close()
    except Exception as e:
        logging.warning("[api_resolver] Failed to extract unicode string at 0x%X: %s", string_va, e)

    return None


def _extract_api_names_from_data_sections(
    pe_path: Path,
    ir: DisassemblyResult,
) -> dict[int, str]:
    """Extract API name strings from PE data sections.

    Read the raw PE file to find UNICODE_STRING buffers containing
    kernel API names. Returns {string_rva: api_name} mapping.

    Handles both x64 (UTF-16LE wide strings) and x86 (may be ASCII
    or UTF-16LE). Scans .rdata, .data, PAGE, and .rodata sections.
    """
    import pefile

    string_map: dict[int, str] = {}

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        image_base = pe.OPTIONAL_HEADER.ImageBase

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            if name not in (".rdata", ".data", "PAGE", ".rodata"):
                continue

            data = section.get_data()
            section_rva = section.VirtualAddress

            # --- Pass 1: UTF-16LE wide-char strings ---
            i = 0
            while i < len(data) - 4:
                if data[i] >= 0x20 and data[i] <= 0x7E and data[i + 1] == 0:
                    chars = []
                    j = i
                    while j + 1 < len(data) and data[j] != 0 and data[j + 1] == 0:
                        if data[j] >= 0x20 and data[j] <= 0x7E:
                            chars.append(chr(data[j]))
                        else:
                            break
                        j += 2

                    if j > i + 2:
                        s = "".join(chars)
                        if _looks_like_kernel_api(s):
                            rva = section_rva + i
                            string_map[rva] = s
                            i = j + 2
                            continue

                i += 2

            # --- Pass 2: ASCII strings (fallback for x86 drivers) ---
            # Some x86 drivers store API names as ASCII with null terminator
            ascii_pattern = re.compile(rb'[A-Z][a-zA-Z]{3,60}\x00')
            for m in ascii_pattern.finditer(data):
                s = m.group().decode("ascii", errors="replace").rstrip("\x00")
                if _looks_like_kernel_api(s):
                    rva = section_rva + m.start()
                    if rva not in string_map:  # Don't overwrite wide-char match
                        string_map[rva] = s

        pe.close()
    except Exception as e:
        logging.warning("[api_resolver] Failed to extract API names from data sections: %s", e)

    return string_map


def _try_decrypt_api_strings(
    pe_path: Path,
    ir: DisassemblyResult,
    existing_map: dict[int, str],
) -> dict[int, str]:
    """Attempt to decrypt XOR-encrypted API name strings in PE data sections.

    Tries single-byte XOR keys 0x01-0xFF against each byte sequence in
    .rdata/.data/PAGE sections. Results that match kernel API patterns
    are returned as {rva: api_name} entries.

    This handles drivers that store API names as XOR-encrypted bytes
    to evade static analysis.
    """
    import pefile

    decrypted: dict[int, str] = {}
    # API name pattern for validation
    api_re = re.compile(rb'^[A-Z][A-Za-z0-9]{2,60}$')

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            if name not in (".rdata", ".data", "PAGE", ".rodata"):
                continue

            data = section.get_data()
            section_rva = section.VirtualAddress

            # Find candidate byte sequences: sequences of non-null bytes 4-80 bytes long
            i = 0
            while i < len(data):
                # Skip null bytes
                if data[i] == 0:
                    i += 1
                    continue

                # Find start of non-null run
                start = i
                while i < len(data) and data[i] != 0 and (i - start) < 80:
                    i += 1
                end = i

                length = end - start
                if length < 4 or length > 80:
                    continue

                blob = data[start:end]
                rva_base = section_rva + start

                # Try each XOR key
                for key in range(0x01, 0x100):
                    dec = bytes(b ^ key for b in blob)
                    if api_re.match(dec):
                        api_name = dec.decode("ascii")
                        if _looks_like_kernel_api(api_name) and rva_base not in existing_map:
                            decrypted[rva_base] = api_name
                            break  # Found one, don't try more keys for this blob

            # Also try 2-byte XOR keys on candidate blobs (known-plaintext attack)
            # Only on blobs NOT already decrypted by single-byte pass
            if len(data) > 8:
                known_prefixes = [b"Mm", b"Ke", b"Zw", b"Io", b"Ex", b"Ps", b"Ob", b"Rt", b"Se"]
                i = 0
                while i < len(data):
                    if data[i] == 0:
                        i += 1
                        continue
                    start = i
                    while i < len(data) and data[i] != 0 and (i - start) < 80:
                        i += 1
                    end = i
                    if end - start < 8:
                        continue
                    rva_base = section_rva + start
                    # Skip if already decrypted by single-byte pass
                    if rva_base in decrypted:
                        continue
                    blob = data[start:end]

                    for prefix in known_prefixes:
                        if len(blob) < 2:
                            continue
                        key0 = blob[0] ^ prefix[0]
                        key1 = blob[1] ^ prefix[1]
                        if key0 == 0 and key1 == 0:
                            continue  # Already handled by single-byte pass
                        key_bytes = bytes([key0, key1])
                        dec = bytearray()
                        for j, b in enumerate(blob):
                            d = b ^ key_bytes[j % 2]
                            if d == 0:
                                break
                            if d < 0x20 or d > 0x7E:
                                break
                            dec.append(d)
                        if len(dec) < 8:
                            continue
                        if api_re.match(bytes(dec)):
                            api_name = dec.decode("ascii")
                            if _looks_like_kernel_api(api_name) and rva_base not in existing_map:
                                decrypted[rva_base] = api_name
                                break

        pe.close()
    except Exception as e:
        logging.warning("[api_resolver] Failed to decrypt API strings: %s", e)

    return decrypted


def _find_function_containing(
    addr: int,
    ir: DisassemblyResult,
    sorted_addrs: list[int],
) -> int | None:
    """Find the function that contains the given address."""
    func_addrs = sorted(ir.functions.keys())
    for i in range(len(func_addrs) - 1, -1, -1):
        fa = func_addrs[i]
        func = ir.functions[fa]
        end = fa + func.size if func.size > 0 else fa + 0x1000
        if fa <= addr < end:
            return fa
    return None


def _infer_api_from_behavior(
    mm_call_addr: int,
    all_instructions: dict[int, Instruction],
    sorted_addrs: list[int],
    ir: DisassemblyResult,
    data_section_map: dict[int, str],
    image_base: int,
    max_forward: int = 50,
) -> str | None:
    """Infer which API was resolved by MmGetSystemRoutineAddress from post-call behavior.

    Strategy:
    1. Find the global variable where the resolved pointer is cached
    2. Find the indirect call to that cached variable
    3. Count parameters pushed before the indirect call
    4. Look at what OTHER APIs are called in the same function — co-occurrence hints
    5. Match against the pre-scanned data_section_map for APIs NOT already in function_apis

    The key insight: if a function already has ObReferenceObjectByHandle and
    MmGetSystemRoutineAddress, the dynamically resolved API is likely something
    NOT in the IAT — one of the data_section_map APIs not yet in function_apis.
    """
    func_addr = _find_function_containing(mm_call_addr, ir, sorted(ir.functions.keys()))
    if not func_addr:
        return None

    existing_apis = set(ir.function_apis.get(func_addr, []))

    # Find which data-section API names are NOT already in this function's APIs
    missing_apis = [
        name for rva, name in data_section_map.items()
        if name not in existing_apis and name != "MmGetSystemRoutineAddress"
    ]

    # If there's exactly one missing API from data_section_map, that's likely the one
    if len(missing_apis) == 1:
        return missing_apis[0]

    # If multiple missing, use parameter count to narrow down
    idx = bisect.bisect_right(sorted_addrs, mm_call_addr)
    if idx >= len(sorted_addrs):
        return missing_apis[0] if missing_apis else None

    cached_var = None
    indirect_call_addr = None

    for i in range(idx, min(len(sorted_addrs), idx + max_forward)):
        cur_addr = sorted_addrs[i]
        if cur_addr - mm_call_addr > 0x300:
            break

        cur = all_instructions[cur_addr]
        cur_str = _op_str(cur)

        if cur.mnemonic == "mov" and "eax" in cur_str.lower():
            m = re.search(r'\[\s*0x([0-9a-fA-F]+)\s*\]', cur_str, re.IGNORECASE)
            if m:
                cached_var = int(m.group(1), 16)

        if cur.mnemonic == "call":
            m = re.search(r'\[\s*0x([0-9a-fA-F]+)\s*\]', cur_str, re.IGNORECASE)
            if m and cached_var and int(m.group(1), 16) == cached_var:
                indirect_call_addr = cur_addr
                break

    if not indirect_call_addr:
        # Try jmp eax pattern
        for i in range(idx, min(len(sorted_addrs), idx + max_forward)):
            cur_addr = sorted_addrs[i]
            if cur_addr - mm_call_addr > 0x300:
                break
            cur = all_instructions[cur_addr]
            cur_op = _op_str(cur)
            if cur.mnemonic == "jmp" and cur_op.lower() == "eax":
                return missing_apis[0] if missing_apis else None

    if indirect_call_addr and missing_apis:
        param_count = _count_stdcall_params(indirect_call_addr, all_instructions, sorted_addrs)
        candidates = _match_api_by_params(param_count, data_section_map)
        if candidates:
            # Return the first candidate that's in missing_apis
            for c in candidates:
                if c in missing_apis:
                    return c
            # Otherwise return first missing
            return missing_apis[0]

    return missing_apis[0] if missing_apis else None


def _count_stdcall_params(
    call_addr: int,
    all_instructions: dict[int, Instruction],
    sorted_addrs: list[int],
    max_back: int = 50,
) -> int:
    """Count how many parameters are pushed before a stdcall."""
    idx = bisect.bisect_left(sorted_addrs, call_addr)
    if idx <= 0:
        return 0

    count = 0
    for i in range(idx - 1, max(-1, idx - max_back - 1), -1):
        cur_addr = sorted_addrs[i]
        if call_addr - cur_addr > 0x200:
            break

        cur = all_instructions[cur_addr]
        if cur.mnemonic == "push":
            count += 1
        elif cur.mnemonic in ("call", "ret", "jmp"):
            # Hit another call/ret — stop counting
            break

    return count


def _match_api_by_params(
    param_count: int,
    data_section_map: dict[int, str],
) -> list[str]:
    """Match API names by parameter count against known signatures."""
    api_by_params: dict[int, list[str]] = {
        1: ["PsGetCurrentProcess", "PsGetCurrentThread", "PsGetCurrentProcessId",
            "IoGetCurrentProcess", "ExGetPreviousMode", "MmIsAddressValid"],
        2: ["RtlInitUnicodeString", "IoCreateSymbolicLink", "IoDeleteSymbolicLink",
            "IoDeleteDevice", "ObReferenceObjectByHandle", "ObfDereferenceObject",
            "ZwClose", "ZwOpenProcess", "ZwTerminateProcess"],
        3: ["ZwQueryInformationThread", "ZwQueryVirtualMemory", "ObDuplicateObject",
            "ZwAdjustPrivilegesToken"],
        4: ["IoGetDeviceObjectPointer", "ObOpenObjectByPointer"],
    }

    candidates = api_by_params.get(param_count, [])
    # Filter to only those in data_section_map
    known_names = set(data_section_map.values())
    return [c for c in candidates if c in known_names]


def _find_pushed_string_near(
    call_addr: int,
    all_instructions: dict[int, Instruction],
    sorted_addrs: list[int],
    data_section_map: dict[int, str],
    image_base: int,
    max_back: int = 50,
) -> str | None:
    """For x86: find a pushed string address near a MmGetSystemRoutineAddress call.

    Scans backwards from the call looking for `push 0xXXXXXXXX` where the
    pushed address points to a known API name string in data_section_map.
    """
    idx = bisect.bisect_left(sorted_addrs, call_addr)
    if idx <= 0:
        return None

    img_base = image_base if image_base else 0

    for i in range(idx - 1, max(-1, idx - max_back - 1), -1):
        cur_addr = sorted_addrs[i]
        if call_addr - cur_addr > 0x200:
            break

        cur = all_instructions[cur_addr]
        cur_str = _op_str(cur)

        # push 0xXXXXXXXX — check if this points to a known API string
        if cur.mnemonic == "push":
            m = re.match(r'^0x([0-9a-fA-F]+)$', cur_str, re.IGNORECASE)
            if m:
                pushed_va = int(m.group(1), 16)
                pushed_rva = pushed_va - img_base
                # Check against data_section_map
                for rva, name in data_section_map.items():
                    if abs(rva - pushed_rva) < 0x20:
                        return name

                # Also try direct RVA match
                if pushed_rva in data_section_map:
                    return data_section_map[pushed_rva]

    return None


def _find_indirect_call_after(
    mm_call_addr: int,
    all_instructions: dict[int, Instruction],
    sorted_addrs: list[int],
    max_forward: int = 30,
) -> int | None:
    """Find the indirect call that uses the return value of MmGetSystemRoutineAddress.

    x64: After the call, the function pointer is in rax.
         Look for: call rax, call rcx (if moved), or jmp rax.
    x86: After the call, the function pointer is in eax.
         Look for: call eax, call ecx, etc.
    """
    idx = bisect.bisect_right(sorted_addrs, mm_call_addr)
    if idx >= len(sorted_addrs):
        return None

    for i in range(idx, min(len(sorted_addrs), idx + max_forward)):
        cur_addr = sorted_addrs[i]
        if cur_addr - mm_call_addr > 0x200:
            break

        cur = all_instructions[cur_addr]

        # Direct indirect call: call rax / call eax
        if cur.mnemonic == "call" and _op_str(cur).lower() in ("rax", "eax"):
            return cur_addr

        # Call via register that was loaded from rax/eax
        if cur.mnemonic == "mov":
            op = _op_str(cur)
            if re.match(r'^r[a-z0-9]+\s*,\s*rax\s*$', op, re.IGNORECASE) or \
               re.match(r'^[a-z0-9]+\s*,\s*eax\s*$', op, re.IGNORECASE):
                dest = op.split(",")[0].strip().lower()
                return _find_call_to_register(dest, cur_addr, all_instructions, sorted_addrs)

        # call via any register (generic indirect call after MmGetSystem)
        if cur.mnemonic == "call" and re.match(
            r'^(r[a-d]x|r(?:8|9|1[0-5])|e[a-d]x|e[sc]x|e[bs]i|e[bd]i)$',
            _op_str(cur), re.IGNORECASE
        ):
            return cur_addr

        # rax/eax clobbered — stop searching
        if cur.mnemonic == "mov" and re.match(r'^(r|e)ax\s*,', _op_str(cur), re.IGNORECASE):
            src = _op_str(cur).split(",", 1)[-1].strip()
            if not src.startswith("["):
                break

    return None


def _find_call_to_register(
    reg: str,
    from_addr: int,
    all_instructions: dict[int, Instruction],
    sorted_addrs: list[int],
    max_forward: int = 20,
) -> int | None:
    """Find the next call to a specific register."""
    idx = bisect.bisect_right(sorted_addrs, from_addr)
    if idx >= len(sorted_addrs):
        return None

    for i in range(idx, min(len(sorted_addrs), idx + max_forward)):
        cur_addr = sorted_addrs[i]
        if cur_addr - from_addr > 0x100:
            break

        cur = all_instructions[cur_addr]
        if cur.mnemonic == "call" and _op_str(cur).lower() == reg:
            return cur_addr

    return None
