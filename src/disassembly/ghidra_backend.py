"""
DriverScope — Ghidra Headless disassembly backend.

Runs Ghidra's analyzeHeadless CLI tool with a custom Python script that
extracts functions, API calls, CFG, strings, and IOCTL patterns. Produces
a DisassemblyResult compatible with the analysis pipeline.

Requires Ghidra 11.3.x (Jython 2.7 built-in) or Ghidra 12.x (PyGhidra/Jep).
The internal script is written in Jython-compatible Python 2.7 syntax.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from src.disassembly.backend import DisassemblyBackend
from src.models import (
    APICallInfo,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Function,
    Instruction,
)


# Ghidra analysis script — runs inside Ghidra's headless environment.
# Uses the FlatProgram API to extract structured data as JSON.
# The output path is passed via the environment variable DRIVERSCOPE_OUTPUT.
# Compatible with Ghidra 11.3.x Jython (Python 2.7) runtime.
GHIDRA_SCRIPT = r"""
# @name: DriverScopeExtract
# @category: DriverScope

from __future__ import print_function
import json
import os

output_path = os.environ.get("DRIVERSCOPE_OUTPUT")
if not output_path:
    print("ERROR: DRIVERSCOPE_OUTPUT env var not set")
    exit()

result = {
    "functions": [],
    "api_calls": [],
    "strings": [],
    "wide_strings": [],
    "imports": [],
    "exports": [],
    "cfg_blocks": [],
    "calls": [],
    "entry_point": None,
    "architecture": None,
    "image_base": None,
    "data_xrefs": [],
    "data_structures": [],
}

prog = currentProgram
addr_factory = prog.getAddressFactory()
listing = prog.getListing()
fm = prog.getFunctionManager()
ref_mgr = prog.getReferenceManager()
sym_table = prog.getSymbolTable()

# Image base
result["image_base"] = prog.getImageBase().getOffset()

# Architecture - include bitness (x86_64 vs x86)
lang = prog.getLanguage()
proc = str(lang.getProcessor())
addr_size = lang.getAddressFactory().getDefaultAddressSpace().getPointerSize()
if proc == "x86" and addr_size == 8:
    proc = "x86_64"
elif proc == "AARCH64" or proc == "ARM":
    if addr_size == 8:
        proc = "AARCH64"
result["architecture"] = proc

# Entry point - use image base (PE drivers) or first function
entry_point_addr = prog.getImageBase().getOffset()
func_iter = fm.getFunctions(True)
if func_iter.hasNext():
    first_func = func_iter.next()
    entry_point_addr = first_func.getEntryPoint().getOffset()
result["entry_point"] = entry_point_addr

# Imports: extract via multiple methods for maximum coverage
_import_names_seen = set()

# Method 1: Thunk functions (standard PE IAT imports)
for func in fm.getFunctions(True):
    if func.isThunk():
        thunked = func.getThunkedFunction(True)
        ext_addr = thunked.getEntryPoint()
        sym = sym_table.getPrimarySymbol(ext_addr)
        if sym:
            n = sym.getName()
            if n not in _import_names_seen:
                _import_names_seen.add(n)
                result["imports"].append(n)

# Method 2: External namespace symbols (catches non-thunk imports)
try:
    ext_ns = sym_table.getExternalNamespace()
    if ext_ns:
        ext_symbols = ext_ns.getSymbols()
        if ext_symbols:
            for sym in ext_symbols:
                n = sym.getName()
                if n and not n.startswith("UNDEFINED") and n not in _import_names_seen:
                    _import_names_seen.add(n)
                    result["imports"].append(n)
except Exception:
    pass

# Method 3: External address space functions
try:
    ext_space = addr_factory.getExternalAddressSpace()
    if ext_space:
        ext_funcs = fm.getFunctions(ext_space, True)
        if ext_funcs:
            for ef in ext_funcs:
                sym = sym_table.getPrimarySymbol(ef.getEntryPoint())
                if sym:
                    n = sym.getName()
                    if n not in _import_names_seen:
                        _import_names_seen.add(n)
                        result["imports"].append(n)
except Exception:
    pass

# Method 4: Scan for library references (ntoskrnl.exe, hal.dll, etc.)
# Look for external references from instructions
try:
    memory = prog.getMemory()
    for block in memory.getBlocks():
        if block.getName().upper() in ("EXTERNAL", "EXTERNAL RAM"):
            start = block.getStart()
            end = block.getEnd()
            addr = start
            while addr.compareTo(end) <= 0:
                sym = sym_table.getPrimarySymbol(addr)
                if sym:
                    n = sym.getName()
                    if n and n not in _import_names_seen:
                        _import_names_seen.add(n)
                        result["imports"].append(n)
                addr = addr.add(1)
except Exception:
    pass

# Functions
functions = fm.getFunctions(True)
for func in functions:
    entry_addr = func.getEntryPoint()
    body = func.getBody()
    size = body.getNumAddresses() if body else 0

    # --- Phase 5: Extract decompiled pseudocode, signature, local vars ---
    pseudo_code = ""
    signature = ""
    local_vars = []
    try:
        # Ghidra 11.x: use DecompInterface directly via Java reflection
        # The decompiler may not be importable in all headless configurations
        DecompInterface = ghidra.app.decompiler.DecompInterface
        iface = DecompInterface()
        if iface.openProgram(currentProgram):
            import ghidra.util.task
            ghidra_monitor = ghidra.util.task.ConsoleTaskMonitor()
            decomp_res = iface.decompileFunction(func, 60, ghidra_monitor)
            if decomp_res and decomp_res.decompileCompleted():
                c_code = decomp_res.getDecompiledFunction()
                if c_code:
                    pseudo_code = c_code.getC()
                high_func = decomp_res.getHighFunction()
                if high_func:
                    local_sym_map = high_func.getLocalSymbolMap()
                    if local_sym_map:
                        for sym in local_sym_map.getSymbols():
                            if sym:
                                lv_name = sym.getName()
                                lv_type = ""
                                if sym.getDataType():
                                    lv_type = sym.getDataType().getName()
                                if lv_name:
                                    local_vars.append({
                                        "name": lv_name,
                                        "type": lv_type,
                                        "stack_offset": sym.getStorage().getStackOffset() if sym.getStorage() else -1,
                                    })
                    ret_type = ""
                    if high_func.getReturn():
                        dt = high_func.getReturn().getDataType()
                        if dt:
                            ret_type = dt.getName()
                    params = []
                    iter_hf = high_func.getParameters()
                    if iter_hf:
                        for p in iter_hf:
                            p_name = p.getName() if p.getName() else "param_" + str(p.getOrdinal())
                            p_type = p.getDataType().getName() if p.getDataType() else "unknown"
                            params.append(p_type + " " + p_name)
                    signature = ret_type + " " + func.getName() + "(" + ", ".join(params) + ")"
            iface.dispose()
    except:
        pass

    ep_match = (entry_addr.getOffset() == entry_point_addr)
    f_data = {
        "addr": entry_addr.getOffset(),
        "name": func.getName(),
        "size": size,
        "is_entry": ep_match,
        "pseudo_code": pseudo_code,
        "signature": signature,
        "local_vars": local_vars,
    }
    result["functions"].append(f_data)

    # Called by / calls (cross-references via ReferenceManager)
    for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
        if ref.getReferenceType().isCall():
            src = ref.getFromAddress()
            src_func = fm.getFunctionContaining(src)
            if src_func:
                result["calls"].append({
                    "caller": src_func.getEntryPoint().getOffset(),
                    "target": entry_addr.getOffset(),
                })

    # Instructions + API calls via function body iterator
    if body:
        inst_iter = listing.getInstructions(body, True)
        for i in inst_iter:
            addr_off = i.getAddress().getOffset()
            mnemonic = i.getMnemonicString()
            operands_str = ""
            op_count = i.getNumOperands()
            op_parts = []
            for op_idx in range(op_count):
                try:
                    op_obj = i.getOpObjects(op_idx)
                    op_strs = []
                    for obj in op_obj:
                        op_strs.append(str(obj))
                    op_parts.append(" ".join(op_strs))
                except:
                    pass
            operands_str = ", ".join(op_parts) if op_parts else ""

            api_name = None
            for ref in i.getReferencesFrom():
                if ref.getReferenceType().isCall():
                    target = ref.getToAddress()
                    sym = sym_table.getPrimarySymbol(target)
                    if sym:
                        api_name = sym.getName()

            insn_data = {
                "addr": addr_off,
                "mnemonic": mnemonic,
                "operands": operands_str,
            }
            if api_name:
                insn_data["api"] = api_name
                result["api_calls"].append({
                    "func_addr": entry_addr.getOffset(),
                    "api_name": api_name,
                    "call_addr": addr_off,
                })

            # Also build a flat CFG block per function (all instructions together)
            if not result["cfg_blocks"] or result["cfg_blocks"][-1].get("_func_addr") != entry_addr.getOffset():
                result["cfg_blocks"].append({
                    "_func_addr": entry_addr.getOffset(),
                    "block_addr": entry_addr.getOffset(),
                    "successors": [],
                    "instructions": [],
                })
            result["cfg_blocks"][-1]["instructions"].append(insn_data)

# Strings - two-pass approach:
# Pass 1: Use Ghidra-defined data types (most accurate)
# Pass 2: Raw byte scan for ASCII strings (fallback for undefined data)
_seen_strings = set()
memory = prog.getMemory()
count = 0

def _add_string(val):
    # Add a string if not already seen and meets minimum length
    global count
    if count >= 2000:
        return False
    if val and len(val) >= 4 and val not in _seen_strings:
        _seen_strings.add(val)
        result["strings"].append(val)
        count += 1
        return True
    return False

for block in memory.getBlocks():
    if block.isInitialized() and count < 2000:
        addr = block.getStart()
        end = block.getEnd()
        block_name = block.getName()
        while addr.compareTo(end) <= 0 and count < 2000:
            try:
                data = listing.getDataAt(addr)
                if data and data.isDefined():
                    dt_name = data.getDataType().getName()
                    if dt_name in ("string", "terminating_string"):
                        val = data.getDefaultValueRepresentation()
                        _add_string(val)
                        addr = addr.add(data.getLength())
                    elif dt_name in ("unicode", "unicode16", "wchar"):
                        val = data.getDefaultValueRepresentation()
                        if len(val) >= 4:
                            rva = addr.getOffset() - result["image_base"]
                            result["wide_strings"].append({
                                "string": val,
                                "section": block_name,
                                "rva": rva,
                            })
                        addr = addr.add(data.getLength())
                    else:
                        addr = addr.add(data.getLength())
                else:
                    addr = addr.add(1)
            except:
                addr = addr.add(1)

# Pass 2: Raw byte scan for ASCII strings in .rdata/.data sections
_PRINTABLE = set(range(0x20, 0x7F))
for block in memory.getBlocks():
    if not block.isInitialized() or count >= 2000:
        continue
    bname = block.getName().upper()
    if bname not in (".RDATA", ".DATA", ".RODATA"):
        continue
    try:
        buf = bytearray()
        block_size = int(block.getSize())
        for i in range(block_size):
            try:
                b = block.getByte(block.getStart().add(i))
                buf.append(b & 0xFF)
            except:
                buf.append(0)
        # Scan for ASCII sequences
        current = []
        for byte_val in buf:
            if byte_val in _PRINTABLE:
                current.append(chr(byte_val))
            elif byte_val == 0:
                if len(current) >= 4:
                    _add_string("".join(current))
                current = []
            else:
                if len(current) >= 4:
                    _add_string("".join(current))
                current = []
        if len(current) >= 4:
            _add_string("".join(current))
    except:
        pass

# Data structure candidates: look for arrays in .rdata/.data
# Scan for potential DWORD/QWORD arrays (function pointer tables, whitelists)
# Ghidra data types: "pointer", "undefined8", "address", "offset", "undefined *"
# These map to 8-byte (qword) or 4-byte (dword) values.
_QWORD_DTYPES = ("qword", "address", "offset", "pointer", "undefined8", "undefined *")
_DWORD_DTYPES = ("dword", "int4", "int", "undefined4")

for block in memory.getBlocks():
    if block.isInitialized() and block.getName() in (".rdata", ".data"):
        block_start = block.getStart()
        block_end = block.getEnd()
        block_size = block_end.subtract(block_start) + 1
        if block_size > 8 and block_size < 0x100000:
            addr = block_start
            while addr.compareTo(block_end) < 0:
                try:
                    data = listing.getDataAt(addr)
                    if data and data.isDefined():
                        dt_name = data.getDataType().getName()
                        data_size = data.getLength()
                        if dt_name in _QWORD_DTYPES:
                            rva = addr.getOffset() - result["image_base"]
                            values = []
                            scan_addr = addr
                            for _ in range(16):
                                d = listing.getDataAt(scan_addr)
                                if d and d.isDefined() and d.getDataType().getName() in _QWORD_DTYPES:
                                    values.append(d.getDefaultValueRepresentation())
                                    scan_addr = scan_addr.add(d.getLength())
                                else:
                                    break
                            if len(values) >= 3:
                                result["data_structures"].append({
                                    "rva": rva,
                                    "type": "qword_array",
                                    "section": block.getName(),
                                    "element_count": len(values),
                                    "values": values[:4],
                                })
                            addr = scan_addr if len(values) >= 3 else addr.add(data_size)
                        elif dt_name in _DWORD_DTYPES:
                            rva = addr.getOffset() - result["image_base"]
                            values = []
                            scan_addr = addr
                            for _ in range(32):
                                d = listing.getDataAt(scan_addr)
                                if d and d.isDefined() and d.getDataType().getName() in _DWORD_DTYPES:
                                    values.append(d.getDefaultValueRepresentation())
                                    scan_addr = scan_addr.add(d.getLength())
                                else:
                                    break
                            if len(values) >= 4:
                                result["data_structures"].append({
                                    "rva": rva,
                                    "type": "dword_array",
                                    "section": block.getName(),
                                    "element_count": len(values),
                                    "values": values[:4],
                                })
                            addr = scan_addr if len(values) >= 4 else addr.add(data_size)
                        else:
                            addr = addr.add(data_size)
                    else:
                        addr = addr.add(1)
                except:
                    addr = addr.add(1)

# Exports (entry point function)
for func in fm.getFunctions(True):
    if func.getEntryPoint().getOffset() == entry_point_addr:
        result["exports"].append({
            "addr": func.getEntryPoint().getOffset(),
            "name": func.getName(),
        })

# Phase 5: Data cross-references - sample from first 30 functions
sampled = 0
for func in fm.getFunctions(True):
    if sampled >= 30:
        break
    if not func.getBody():
        continue
    body = func.getBody()
    func_xrefs = []
    inst_iter = listing.getInstructions(body, True)
    for i in inst_iter:
        for ref in i.getReferencesFrom():
            ref_type = ref.getReferenceType().getName()
            target = ref.getToAddress()
            if not ref_type.lower().startswith("call") and not ref_type.lower().startswith("flow"):
                target_func = fm.getFunctionAt(target)
                if target_func is None:
                    func_xrefs.append({
                        "func_addr": func.getEntryPoint().getOffset(),
                        "type": ref_type,
                        "target_addr": target.getOffset(),
                        "source_insn": i.getAddress().getOffset(),
                    })
                    sampled += 1
    result["data_xrefs"].extend(func_xrefs)

with open(output_path, "w") as f:
    json.dump(result, f)

print("DriverScope: extracted %d functions, %d API calls, %d strings, %d wide strings, %d imports, %d data structures" % (
    len(result["functions"]), len(result["api_calls"]),
    len(result["strings"]), len(result["wide_strings"]),
    len(result["imports"]), len(result["data_structures"])))
"""


class GhidraBackend(DisassemblyBackend):
    """Ghidra Headless disassembly backend.

    Runs Ghidra's analyzeHeadless with a custom extraction script.
    Falls back to checking for Ghidra installation via environment variable
    or PATH search.
    """

    @property
    def name(self) -> str:
        return "ghidra"

    def is_available(self) -> bool:
        """Check if Ghidra analyzeHeadless is available."""
        if self._find_headless():
            return True
        return False

    def get_version(self) -> str:
        """Return Ghidra version string."""
        headless = self._find_headless()
        if not headless:
            return "unknown"
        try:
            result = subprocess.run(
                [headless, "-version"],
                capture_output=True, text=True, timeout=10,
            )
            # Ghidra prints version to stderr or stdout
            output = result.stderr or result.stdout
            for line in output.splitlines():
                if "Ghidra" in line or "Version" in line:
                    return line.strip()
            return "ghidra"
        except Exception:
            return "ghidra"

    def analyze(self, sample_path: Path) -> DisassemblyResult:
        """Run Ghidra headless analysis on a .sys file.

        This is slow (minutes per file) but produces precise results
        because Ghidra has full symbolic execution for function identification,
        IAT resolution, and CFG construction with instruction-level detail.
        """
        headless = self._find_headless()
        if not headless:
            raise RuntimeError(
                "Ghidra analyzeHeadless not found. "
                "Set GHIDRA_INSTALL_DIR or ensure analyzeHeadless is in PATH."
            )

        with tempfile.TemporaryDirectory(prefix="ghidra_ds_") as tmpdir:
            tmpdir_path = Path(tmpdir)
            output_json = tmpdir_path / "ghidra_output.json"
            script_file = tmpdir_path / "DriverScopeExtract.py"
            project_dir = tmpdir_path / "ghidra_project"

            # Write the extraction script
            script_file.write_text(GHIDRA_SCRIPT, encoding="utf-8")

            # Create project directory
            project_dir.mkdir()

            # Build analyzeHeadless command
            abs_sample = sample_path.resolve()
            cmd = [
                headless,
                str(project_dir),
                f"DriverScope_{abs_sample.stem}",
                "-import", str(abs_sample),
                "-scriptPath", str(tmpdir_path),
                "-postScript", "DriverScopeExtract.py",
                "-deleteProject",
                "-analysisTimeoutPerFile", "300",
            ]

            # Pass output path via environment variable (headless mode)
            env = os.environ.copy()
            env["DRIVERSCOPE_OUTPUT"] = str(output_json)
            env["_JAVA_OPTIONS"] = "-Xmx4g -Xms512m"

            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=600,
                env=env, cwd=str(tmpdir_path),
            )

            if result.returncode != 0:
                stderr_snippet = result.stderr[-1000:] if result.stderr else "unknown error"
                raise RuntimeError(
                    f"Ghidra analyzeHeadless failed (rc={result.returncode}): {stderr_snippet}"
                )

            if not output_json.exists():
                raise RuntimeError(
                    "Ghidra completed but output JSON was not created. "
                    "Check Ghidra logs for script errors."
                )

            raw = json.loads(output_json.read_text(encoding="utf-8"))
            return self._build_disassembly_result(raw, sample_path)

    @staticmethod
    def _extract_imports_pefile(sample_path: Path) -> list[str]:
        """Fallback: extract imports via pefile when Ghidra's thunk detection misses them."""
        imports: list[str] = []
        try:
            import pefile
            pe = pefile.PE(str(sample_path), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='replace').lower()
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='replace')
                            imports.append(f"{dll_name}.{name}")
                        else:
                            imports.append(f"{dll_name}.ordinal_{imp.ordinal}")
            pe.close()
        except Exception:
            pass
        return imports

    def _build_disassembly_result(
        self,
        raw: dict,
        sample_path: Path,
    ) -> DisassemblyResult:
        """Convert Ghidra JSON output to DisassemblyResult.

        The Ghidra backend produces instruction-level CFG blocks with
        full instruction details (mnemonic, operands, API targets),
        which enables precise taint tracking and pattern matching.
        """
        result = DisassemblyResult(
            sample_path=sample_path,
            backend=self.name,
        )

        # Detect architecture
        arch = raw.get("architecture", "x86")
        if "AARCH64" in str(arch) or "ARM" in str(arch):
            result.is_arm64 = True

        # Functions
        for f_data in raw.get("functions", []):
            func = Function(
                name=f_data.get("name", f"sub_{f_data['addr']:X}"),
                address=f_data["addr"],
                size=f_data.get("size", 0),
                is_entry=f_data.get("is_entry", False),
                pseudo_code=f_data.get("pseudo_code", ""),
                signature=f_data.get("signature", ""),
                local_vars=f_data.get("local_vars", []),
            )
            result.functions[func.address] = func

        # Build instruction index: addr → Instruction for all instructions
        all_instructions: dict[int, Instruction] = {}

        # CFG blocks from Ghidra — each has full instruction data
        for block_data in raw.get("cfg_blocks", []):
            # New format: _func_addr directly links block to function
            func_addr = block_data.get("_func_addr") or block_data.get("func_addr")
            block_addr = block_data.get("block_addr", func_addr or 0)
            if func_addr is None:
                # Fallback: search for function by address range
                for f_data in raw.get("functions", []):
                    f_addr = f_data["addr"]
                    func = result.functions.get(f_addr)
                    if func and func.address <= block_addr < func.address + max(func.size, 0x1000):
                        func_addr = f_addr
                        break

            # Build instructions for this block
            instructions = []
            for insn_data in block_data.get("instructions", []):
                insn = Instruction(
                    address=insn_data["addr"],
                    mnemonic=insn_data["mnemonic"],
                    operands=insn_data.get("operands", ""),
                )

                # Set API target if present
                api_name = insn_data.get("api")
                if api_name:
                    short_name = api_name.split(".")[-1] if "." in api_name else api_name
                    insn.api_target = short_name
                    insn.api_info = APICallInfo(name=short_name, call_address=insn_data["addr"])

                all_instructions[insn.address] = insn
                instructions.append(insn)

            # Build BasicBlock
            block = BasicBlock(
                address=block_addr,
                end_address=0,  # Refined after instructions are populated
                instructions=instructions,
                successors=block_data.get("successors", []),
            )
            if instructions:
                # Use actual instruction sizes if available, fall back to address gap
                last = instructions[-1]
                if last.size:
                    block.end_address = last.address + last.size
                elif len(instructions) > 1:
                    # Estimate from address gap between last two instructions
                    block.end_address = last.address + (last.address - instructions[-2].address)
                else:
                    block.end_address = last.address + 4  # Final fallback

            cfg = result.cfgs.setdefault(func_addr or block_addr, CFG(
                function_address=func_addr or block_addr,
            ))
            cfg.blocks[block_addr] = block

        # API calls (for function_apis index)
        for api_call in raw.get("api_calls", []):
            func_addr = api_call["func_addr"]
            api_name = api_call["api_name"]
            call_addr = api_call["call_addr"]

            result.function_apis.setdefault(func_addr, [])
            short_name = api_name.split(".")[-1] if "." in api_name else api_name
            if short_name not in result.function_apis[func_addr]:
                result.function_apis[func_addr].append(short_name)

            result.function_api_details.setdefault(func_addr, [])
            result.function_api_details[func_addr].append(
                APICallInfo(
                    name=short_name,
                    call_address=call_addr,
                    params_hint="",
                )
            )

        # Strings
        result.strings = raw.get("strings", [])

        # Wide strings with RVA info (for MemoryMapAnalyzer, whitelist detection)
        for ws in raw.get("wide_strings", []):
            result.wide_strings.append({
                "string": ws.get("string", ""),
                "section": ws.get("section", ""),
                "rva": ws.get("rva", 0),
            })

        # Data structures (for MemoryMapAnalyzer, dispatch table detection)
        for ds in raw.get("data_structures", []):
            rva = ds.get("rva", 0)
            result.data_structures[rva] = {
                "type": ds.get("type", ""),
                "section": ds.get("section", ""),
                "element_count": ds.get("element_count", 0),
                "values": ds.get("values", []),
            }

        # Imports — merge Ghidra's symbolic imports with pefile fallback
        ghidra_imports = raw.get("imports", [])
        if len(ghidra_imports) < 5:
            # Ghidra's thunk detection missed most imports — fall back to pefile
            pefile_imports = self._extract_imports_pefile(sample_path)
            # Merge: keep Ghidra's first, add pefile's that aren't already present
            seen = set(n.lower() for n in ghidra_imports)
            for imp in pefile_imports:
                if imp.lower() not in seen:
                    seen.add(imp.lower())
                    ghidra_imports.append(imp)

        # Use incrementing IAT slot as unique key
        for i, imp in enumerate(ghidra_imports):
            result.import_addresses[0x1000 + i * 8] = imp

        # Call graph (from cross-references)
        for call in raw.get("calls", []):
            caller = call["caller"]
            target = call["target"]
            caller_func = result.functions.get(caller)
            target_func = result.functions.get(target)
            if caller_func and target_func:
                if target not in caller_func.calls:
                    caller_func.calls.append(target)
                if caller not in target_func.called_by:
                    target_func.called_by.append(caller)

        # Exports not stored in DisassemblyResult; they live on Sample
        # (skipped here)

        # Phase 5: Data cross-references
        for xref in raw.get("data_xrefs", []):
            func_addr = xref.get("func_addr")
            if func_addr is not None:
                result.data_xrefs.setdefault(func_addr, []).append({
                    "type": xref.get("type", ""),
                    "target_addr": xref.get("target_addr", 0),
                    "source_insn": xref.get("source_insn", 0),
                })

        # Image base
        result.image_base = raw.get("image_base", 0x0)

        # Phase 5: Type info from function signatures
        for f_data in raw.get("functions", []):
            if f_data.get("signature"):
                result.type_info[f_data["addr"]] = {
                    "signature": f_data["signature"],
                    "local_vars": f_data.get("local_vars", []),
                }

        # Dynamic import resolution (MmGetSystemRoutineAddress)
        try:
            from src.disassembly.api_resolver import scan_for_dynamic_imports
            all_insn_list = list(all_instructions.values())
            scan_for_dynamic_imports(
                result, all_instructions, result.image_base, sample_path,
            )
        except Exception:
            pass

        return result

    @staticmethod
    def _find_headless() -> str | None:
        """Locate Ghidra's analyzeHeadless binary.

        Search order:
        1. GHIDRA_INSTALL_DIR environment variable
        2. GHIDRA_HEADLESS environment variable (direct path)
        3. PATH search for analyzeHeadless / analyzeHeadless.bat
        4. Common installation directories
        """
        # Direct path override
        direct = os.environ.get("GHIDRA_HEADLESS")
        if direct and Path(direct).exists():
            return direct

        # Via install dir — prefer .bat on Windows, shell script on Unix
        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if install_dir:
            base = Path(install_dir)
            for candidate in [
                base / "support" / "analyzeHeadless.bat",
                base / "support" / "analyzeHeadless",
                base / "analyzeHeadless.bat",
                base / "analyzeHeadless",
            ]:
                if candidate.exists():
                    return str(candidate)

        # PATH search
        headless_exe = shutil.which("analyzeHeadless")
        if headless_exe:
            return headless_exe
        headless_bat = shutil.which("analyzeHeadless.bat")
        if headless_bat:
            return headless_bat

        # Common installation directories
        common_paths = [
            Path(os.environ.get("ProgramFiles", ""), "Ghidra", "support", "analyzeHeadless.bat"),
            Path(os.environ.get("ProgramFiles(x86)", ""), "Ghidra", "support", "analyzeHeadless.bat"),
            Path(os.environ.get("LOCALAPPDATA", ""), "Ghidra", "support", "analyzeHeadless.bat"),
            Path(os.environ.get("HOME", ""), "ghidra", "support", "analyzeHeadless"),
            Path(os.environ.get("HOME", ""), "opt", "ghidra", "support", "analyzeHeadless"),
        ]
        for p in common_paths:
            if p.exists():
                return str(p)

        # Project-local Ghidra (bundled in repo root)
        try:
            import importlib.metadata
            pkg_root = Path(__file__).resolve().parent.parent.parent
            for candidate in [
                pkg_root / "ghidra_11.3.1_PUBLIC" / "support" / "analyzeHeadless.bat",
                pkg_root / "ghidra_12.1_PUBLIC" / "support" / "analyzeHeadless.bat",
                pkg_root / "ghidra" / "support" / "analyzeHeadless.bat",
                pkg_root / "Ghidra" / "support" / "analyzeHeadless.bat",
            ]:
                if candidate.exists():
                    return str(candidate)
        except Exception:
            pass

        return None
