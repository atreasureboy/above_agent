"""MiniFilter callback detection for BYOVD entry point expansion.

MiniFilter drivers register via FltRegisterFilter with a PFLT_REGISTRATION
struct containing callback function pointers. These callbacks (especially
DeviceControl at offset 0x78 and FileSystemControl at 0x70) are equivalent
to IOCTL handlers but completely invisible to the IRP dispatch table scan.

Usage:
    from src.disassembly.minifilter_detector import detect_minifilter
    detect_minifilter(result)
"""

from __future__ import annotations

import re

from src.models import DisassemblyResult, Function, Instruction


# Offsets within PFLT_REGISTRATION struct for callback types
MINIFILTER_CALLBACK_OFFSETS = {
    0x00: "GenerateFileName",
    0x08: "Create",
    0x10: "CreateNamedPipe",
    0x18: "Close",
    0x20: "Read",
    0x28: "Write",
    0x30: "QueryInformation",
    0x38: "SetInformation",
    0x40: "QueryEa",
    0x48: "SetEa",
    0x50: "FlushBuffers",
    0x60: "SetVolumeInformation",
    0x68: "DirectoryControl",       # IOCTL-like surface
    0x70: "FileSystemControl",      # IOCTL-like surface
    0x78: "DeviceControl",          # Direct IOCTL equivalent
    0x80: "InternalDeviceControl",
    0x88: "Shutdown",
    0x90: "LockControl",
    0x98: "Cleanup",
    0xA0: "CreateMailslot",
    0xA8: "QuerySecurity",
    0xB0: "SetSecurity",
    0xB8: "QueryQuota",
    0xC0: "SetQuota",
    0xC8: "Pnp",
}

# APIs that identify a MiniFilter driver
MINIFILTER_REGISTER_APIS = {
    "FltRegisterFilter",
    "FltStartFiltering",
    "FltUnregisterFilter",
}


def detect_minifilter(ir: DisassemblyResult) -> None:
    """Detect MiniFilter driver and populate ir.minifilter_handlers.

    Strategy:
    1. Check for FltRegisterFilter/FltStartFiltering in imports or function APIs
    2. If detected, scan all functions for PFLT_REGISTRATION struct setup
       (mov [reg+offset], funcptr patterns at callback offsets)
    3. Mark callback targets as entry points
    """
    # Step 1: Check if this is a MiniFilter driver
    for func_addr, apis in ir.function_apis.items():
        if set(apis) & MINIFILTER_REGISTER_APIS:
            ir.is_minifilter = True
            break

    # Also check imports
    if not ir.is_minifilter:
        for api_name in ir.import_addresses.values():
            base = api_name.split(".")[-1] if "." in api_name else api_name
            if base in MINIFILTER_REGISTER_APIS:
                ir.is_minifilter = True
                break

    if not ir.is_minifilter:
        return

    # Step 2: Scan for PFLT_REGISTRATION struct setup
    # Look for mov [reg+offset], imm/funcptr at known callback offsets
    all_funcs = list(ir.functions.values())
    all_cfgs = list(ir.cfgs.values()) + list(ir.simple_cfgs.values())

    for cfg in all_cfgs:
        for block in cfg.blocks.values():
            for insn in block.instructions:
                if insn.mnemonic != "mov":
                    continue
                op_str = insn.operands
                if "ptr" not in op_str:
                    continue
                for off, name in MINIFILTER_CALLBACK_OFFSETS.items():
                    if re.search(rf'\[\s*\w+\s*\+\s*(?:0x{off:X}|{off})\s*\]', op_str):
                        ir.minifilter_handlers[off] = insn.address

    # Step 3: Ensure callback targets are in the functions dict
    handler_addrs = set(ir.minifilter_handlers.values())
    for addr in handler_addrs:
        if addr not in ir.functions:
            func = Function(name=f"flt_cb_{addr:X}", address=addr, size=0)
            ir.functions[addr] = func
