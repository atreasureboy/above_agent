"""
Generate a minimal mock .sys driver file for testing.

Creates a PE file that mimics a WDM driver with:
- IMAGE_SUBSYSTEM_NATIVE (1)
- .text section with minimal x64 code
- Import table referencing ntoskrnl.exe with dangerous APIs
- WDM-style IRP handler registration pattern in code
"""

import struct
from pathlib import Path


def create_mock_driver(output_path: Path) -> None:
    """Create a mock WDM driver .sys file."""

    FILE_ALIGNMENT = 0x200
    SECTION_ALIGNMENT = 0x1000

    api_names = [
        "MmMapIoSpace",
        "MmMapLockedPagesSpecifyCache",
        "ZwMapViewOfSection",
        "KeWriteMsr",
        "MmCopyVirtualMemory",
        "ZwOpenProcess",
        "PsGetCurrentProcessId",
        "IoCompleteRequest",
    ]

    # === Build .text section ===
    code = bytearray()
    code += b"\x55\x48\x89\xe5\x48\x83\xec\x20"  # DriverEntry prologue
    code += b"\x48\xc7\xc0\x00\x20\x00\x00"       # mov rax, 0x2000
    code += b"\x48\x89\x41\x70"                    # mov [rcx+0x70], rax (DEVICE_CONTROL)
    code += b"\x48\xc7\xc0\x00\x21\x00\x00"       # mov rax, 0x2100
    code += b"\x48\x89\x41\x68"                    # mov [rcx+0x68], rax (CREATE)
    code += b"\x48\xc7\xc0\x00\x22\x00\x00"       # mov rax, 0x2200
    code += b"\x48\x89\x41\x6c"                    # mov [rcx+0x6C], rax (CLOSE)
    code += b"\x31\xc0\xc9\xc3"                    # xor eax,eax; leave; ret

    while len(code) < 0x200:
        code += b"\xcc"

    # DeviceControl handler
    code += b"\x55\x48\x89\xe5"                    # prologue
    code += b"\x3d\x00\x20\x22\x00"                # cmp eax, 0x222000
    code += b"\x75\x0a"                            # jne +0x0a
    code += b"\xff\x15\xf8\x07\x00\x00"            # call [rip+0x7F8] (IAT[0])
    code += b"\x3d\x04\x20\x22\x00"                # cmp eax, 0x222004
    code += b"\x75\x0a"                            # jne
    code += b"\xff\x15\xf8\x07\x00\x00"            # call [rip+0x7F8] (IAT[1])
    code += b"\x3d\x08\x20\x22\x00"                # cmp eax, 0x222008
    code += b"\x75\x0a"
    code += b"\xff\x15\xf8\x07\x00\x00"            # call [rip+0x7F8] (IAT[2])
    code += b"\xff\x15\xf8\x07\x00\x00"            # call [rip+0x7F8] (IAT[3])
    code += b"\xff\x15\xf8\x07\x00\x00"            # call [rip+0x7F8] (IAT[4])
    code += b"\xff\x15\xf8\x07\x00\x00"            # call [rip+0x7F8] (IAT[5])
    code += b"\x31\xc0\xc9\xc3"                    # ret

    while len(code) < 0x800:
        code += b"\x00"

    # IAT thunk entries (8 bytes each, x64) — these will be filled by loader
    for i in range(8):
        code += struct.pack("<Q", 0)

    while len(code) < 0x1000:
        code += b"\x00"

    # === Build .rdata section (pre-allocated 4096 bytes) ===
    rdata = bytearray(0x1000)

    # Layout within .rdata:
    #   0x000-0x013: Import descriptor 1
    #   0x014-0x027: Import descriptor 2 (null terminator)
    #   0x028-0x057: ILT entries (8 bytes each, PE32+)
    #   0x060-0x0FF: API name strings (hint + name)
    #   0x100-0x10B: DLL name "ntoskrnl.exe"
    #   0x110-0x1FF: Device/device link strings

    rdata_base = 0x2000
    ilt_rva = rdata_base + 0x028
    iat_rva = rdata_base + 0x300  # Separate IAT location (moved further from names)
    dll_name_rva = rdata_base + 0x110  # DLL name with gap after API names
    name_start_rva = rdata_base + 0x060

    # Import descriptor 1 — DLL name RVA set later, after we know where the string is
    struct.pack_into("<I", rdata, 0x000, ilt_rva)       # ILT RVA
    struct.pack_into("<I", rdata, 0x004, 0)              # TimeDateStamp
    struct.pack_into("<I", rdata, 0x008, 0)              # ForwarderChain
    struct.pack_into("<I", rdata, 0x00C, 0)              # DLL name RVA (set later)
    struct.pack_into("<I", rdata, 0x010, iat_rva)        # IAT RVA (DIFFERENT from ILT)

    # Import descriptor 2 (null terminator) — already zeros

    # IAT (initialized with same RVAs as ILT — in a real binary, the loader fills this)
    current_rva = name_start_rva
    for i, api in enumerate(api_names):
        struct.pack_into("<Q", rdata, 0x300 + i * 8, current_rva)
        current_rva += 2 + len(api) + 1

    # ILT entries
    current_rva = name_start_rva
    for i, api in enumerate(api_names):
        struct.pack_into("<Q", rdata, 0x028 + i * 8, current_rva)
        current_rva += 2 + len(api) + 1
    # ILT terminator
    struct.pack_into("<Q", rdata, 0x028 + len(api_names) * 8, 0)

    # API name strings
    name_offset = 0x060
    for api in api_names:
        struct.pack_into("<H", rdata, name_offset, 0)
        name_offset += 2
        api_bytes = api.encode("ascii")
        rdata[name_offset:name_offset + len(api_bytes)] = api_bytes
        name_offset += len(api_bytes) + 1

    # DLL name
    # DLL name (at a safe offset past API names and ILT/IAT)
    rdata[0x400:0x400 + 13] = b"ntoskrnl.exe\x00"
    # Now set the correct DLL name RVA in the import descriptor
    struct.pack_into("<I", rdata, 0x00C, rdata_base + 0x400)

    # === Build PE header ===
    pe = bytearray()

    # DOS Header
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew
    pe += bytes(dos)

    # PE Signature
    pe += b"PE\x00\x00"

    # COFF Header
    pe += struct.pack("<H", 0x8664)       # Machine: AMD64
    pe += struct.pack("<H", 3)            # NumberOfSections
    pe += struct.pack("<I", 0x66666666)   # TimeDateStamp
    pe += struct.pack("<I", 0)            # PointerToSymbolTable
    pe += struct.pack("<I", 0)            # NumberOfSymbols
    pe += struct.pack("<H", 0xF0)         # SizeOfOptionalHeader
    pe += struct.pack("<H", 0x22)         # Characteristics

    # Optional Header (PE32+, 240 bytes)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0x00, 0x20B)           # Magic
    struct.pack_into("<H", opt, 0x02, 0x0E)            # LinkerVersion
    struct.pack_into("<I", opt, 0x04, len(code))       # SizeOfCode
    struct.pack_into("<I", opt, 0x08, len(rdata))      # SizeOfInitializedData
    struct.pack_into("<I", opt, 0x10, 0x1000)          # AddressOfEntryPoint
    struct.pack_into("<I", opt, 0x14, 0x1000)          # BaseOfCode
    struct.pack_into("<Q", opt, 0x18, 0xFFFFF80000000000)  # ImageBase
    struct.pack_into("<I", opt, 0x20, SECTION_ALIGNMENT)
    struct.pack_into("<I", opt, 0x24, FILE_ALIGNMENT)
    struct.pack_into("<H", opt, 0x28, 0x0602)          # MajorOSVersion
    struct.pack_into("<H", opt, 0x30, 0x0602)          # MajorSubsystemVersion
    struct.pack_into("<I", opt, 0x38, 0x4000)          # SizeOfImage
    struct.pack_into("<I", opt, 0x3C, 0x200)           # SizeOfHeaders
    struct.pack_into("<H", opt, 0x44, 1)               # Subsystem: NATIVE
    struct.pack_into("<H", opt, 0x46, 0x8160)          # DllCharacteristics
    struct.pack_into("<Q", opt, 0x48, 0x100000)        # SizeOfStackReserve
    struct.pack_into("<Q", opt, 0x50, 0x1000)          # SizeOfStackCommit
    struct.pack_into("<Q", opt, 0x58, 0x100000)        # SizeOfHeapReserve
    struct.pack_into("<Q", opt, 0x60, 0x1000)          # SizeOfHeapCommit
    struct.pack_into("<I", opt, 0x6C, 16)              # NumberOfRvaAndSizes

    # Data directories
    struct.pack_into("<I", opt, 0x70, 0)               # Export RVA
    struct.pack_into("<I", opt, 0x74, 0)               # Export Size
    struct.pack_into("<I", opt, 0x78, 0x2000)          # Import RVA
    struct.pack_into("<I", opt, 0x7C, len(rdata))      # Import Size
    struct.pack_into("<I", opt, 0xA0, iat_rva)         # IAT RVA (directory 12)
    struct.pack_into("<I", opt, 0xA4, 64)              # IAT Size

    pe += bytes(opt)

    # Section headers (40 bytes each)
    def write_section_header(name, virt_size, virt_addr, raw_size, raw_ptr, characteristics):
        """Write a proper 40-byte PE section header."""
        hdr = bytearray(40)
        hdr[0:8] = name.ljust(8, b'\x00')[:8]
        struct.pack_into("<I", hdr, 8, virt_size)
        struct.pack_into("<I", hdr, 12, virt_addr)
        struct.pack_into("<I", hdr, 16, raw_size)
        struct.pack_into("<I", hdr, 20, raw_ptr)
        struct.pack_into("<I", hdr, 24, 0)  # PointerToRelocations
        struct.pack_into("<I", hdr, 28, 0)  # PointerToLinenumbers
        struct.pack_into("<H", hdr, 32, 0)  # NumberOfRelocations
        struct.pack_into("<H", hdr, 34, 0)  # NumberOfLinenumbers
        struct.pack_into("<I", hdr, 36, characteristics)
        return bytes(hdr)

    pe += write_section_header(b".text", len(code), 0x1000, len(code), 0x200, 0x60000020)
    pe += write_section_header(b".rdata", len(rdata), 0x2000, len(rdata), 0x200 + len(code), 0x40000040)
    pe += write_section_header(b".pdata", 0x20, 0x3000, 0x200, 0x200 + len(code) + len(rdata), 0x40000040)

    # Pad to file alignment
    while len(pe) < 0x200:
        pe += b"\x00"

    # Section data
    pe += bytes(code)
    pe += bytes(rdata)
    pe += b"\x00" * 0x200

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(bytes(pe))
    print(f"Created mock driver: {output_path} ({len(pe)} bytes)")


if __name__ == "__main__":
    import sys
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("samples/unknown/mock_driver.sys")
    create_mock_driver(path)
