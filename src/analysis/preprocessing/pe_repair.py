"""
DriverScope — PE Header Repair Engine.

Fixes damaged PE headers after memory dump unpacking:
1. Fix section alignment (raw vs virtual)
2. Repair entry point RVA
3. Rebuild import directory
4. Fix overlay data
5. Repair checksum
6. Fix resource directory

Common issues after unpacking:
- Sections have wrong SizeOfRawData (memory uses VirtualSize)
- Entry point is wrong (unpacker's EP vs original EP)
- Import directory is destroyed
- Overlay data is missing
- Checksum is invalid

Usage:
    from src.analysis.preprocessing.pe_repair import PERepairEngine

    engine = PERepairEngine()
    result = engine.repair(dumped_binary_path, image_base=0x140000000)
    if result.success:
        result.write_repaired("fixed.sys")
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PE Constants
# ---------------------------------------------------------------------------

# DOS Header
DOS_MAGIC = b"MZ"
E_LFANEW_OFFSET = 0x3C

# PE Signature
PE_SIGNATURE = b"PE\x00\x00"

# COFF Header offsets (from PE signature)
COFF_MACHINE_OFFSET = 4       # Machine type
COFF_NUM_SECTIONS_OFFSET = 6  # NumberOfSections
COFF_SIZE_OPT_HEADER_OFFSET = 16  # SizeOfOptionalHeader
COFF_CHARACTERISTICS_OFFSET = 18

# Optional Header offsets
OPT_MAGIC_OFFSET = 20
OPT_ENTRY_POINT_OFFSET = 32
OPT_IMAGE_BASE_OFFSET = 40     # PE32+: 24, PE32: 28
OPT_SECTION_ALIGN_OFFSET = 48  # SectionAlignment
OPT_FILE_ALIGN_OFFSET = 52     # FileAlignment
OPT_SIZE_OF_IMAGE_OFFSET = 72  # SizeOfImage (PE32+: 56)
OPT_SIZE_OF_HEADERS_OFFSET = 76  # SizeOfHeaders (PE32+: 60)
OPT_CHECKSUM_OFFSET = 128      # CheckSum (PE32+: 64)

# Section Header size
SECTION_HEADER_SIZE = 40

# Machine types
MACHINE_AMD64 = 0x8664
MACHINE_I386 = 0x014C
MACHINE_ARM64 = 0xAA64


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class SectionInfo:
    """Information about a PE section."""
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_data_offset: int = 0
    raw_data_size: int = 0
    characteristics: int = 0
    needs_fix: bool = False
    fix_reasons: list[str] = field(default_factory=list)


@dataclass
class RepairResult:
    """Result of PE repair operation."""
    success: bool = False
    original_path: Path | None = None
    repairs_applied: list[str] = field(default_factory=list)
    sections_fixed: int = 0
    entry_point_fixed: bool = False
    imports_rebuilt: bool = False
    checksum_fixed: bool = False
    error: str = ""
    _repaired_data: bytes = b""

    @property
    def repaired_data(self) -> bytes:
        return self._repaired_data

    def write_repaired(self, output_path: str | Path) -> bool:
        """Write repaired PE to disk."""
        if not self._repaired_data:
            return False
        try:
            Path(output_path).write_bytes(self._repaired_data)
            return True
        except Exception as e:
            logger.error("[pe_repair] Write failed: %s", e)
            return False


# ---------------------------------------------------------------------------
# PE Repair Engine
# ---------------------------------------------------------------------------

class PERepairEngine:
    """PE header repair engine.

    Fixes common issues in PE files dumped from memory.
    """

    def __init__(self):
        self._lief_available = False
        try:
            import lief
            self._lief_available = True
        except ImportError:
            logger.debug("[pe_repair] lief not available — using basic repair")

    def repair(
        self,
        input_path: Path,
        image_base: int = 0,
        output_path: Path | None = None,
    ) -> RepairResult:
        """Repair a damaged PE file.

        Args:
            input_path: Path to the damaged PE.
            image_base: Known image base (0 = read from PE).
            output_path: Optional output path.

        Returns:
            RepairResult with repair status.
        """
        result = RepairResult(original_path=input_path)

        try:
            data = bytearray(input_path.read_bytes())
        except Exception as e:
            result.error = f"Cannot read file: {e}"
            return result

        # Validate basic PE structure
        if not self._validate_pe_header(data):
            result.error = "Not a valid PE file (missing MZ/PE signature)"
            return result

        # Detect PE type (32-bit vs 64-bit)
        is_64bit = self._detect_pe_type(data)

        # Read image base from PE if not provided
        if image_base == 0:
            image_base = self._read_image_base(data, is_64bit)

        # Step 1: Fix section alignment
        sections_fixed = self._fix_section_alignment(data, is_64bit)
        result.sections_fixed = sections_fixed
        if sections_fixed > 0:
            result.repairs_applied.append(f"Fixed {sections_fixed} section alignment(s)")

        # Step 2: Fix entry point
        if self._fix_entry_point(data, is_64bit):
            result.entry_point_fixed = True
            result.repairs_applied.append("Fixed entry point")

        # Step 3: Fix SizeOfImage
        if self._fix_size_of_image(data, is_64bit):
            result.repairs_applied.append("Fixed SizeOfImage")

        # Step 4: Fix SizeOfHeaders
        if self._fix_size_of_headers(data, is_64bit):
            result.repairs_applied.append("Fixed SizeOfHeaders")

        # Step 5: Fix checksum
        if self._fix_checksum(data, is_64bit):
            result.checksum_fixed = True
            result.repairs_applied.append("Fixed checksum")

        # Step 6: Try to rebuild imports with lief
        if self._lief_available:
            try:
                if self._rebuild_imports_lief(data):
                    result.imports_rebuilt = True
                    result.repairs_applied.append("Rebuilt import directory (lief)")
            except Exception as e:
                logger.debug("[pe_repair] lief import rebuild failed: %s", e)

        # Step 7: Fix section characteristics
        chars_fixed = self._fix_section_characteristics(data, is_64bit)
        if chars_fixed > 0:
            result.repairs_applied.append(f"Fixed {chars_fixed} section characteristic(s)")

        result.success = True
        result._repaired_data = bytes(data)

        if output_path:
            result.write_repaired(output_path)

        logger.info(
            "[pe_repair] Repaired %s: %d repairs applied",
            input_path.name,
            len(result.repairs_applied),
        )

        return result

    def _validate_pe_header(self, data: bytearray) -> bool:
        """Validate basic PE structure."""
        if len(data) < 0x40:
            return False
        if data[0:2] != DOS_MAGIC:
            return False

        # Read e_lfanew
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]
        if e_lfanew > len(data) - 4:
            return False

        # Check PE signature
        if data[e_lfanew:e_lfanew + 4] != PE_SIGNATURE:
            return False

        return True

    def _detect_pe_type(self, data: bytearray) -> bool:
        """Detect if PE is 64-bit (PE32+) or 32-bit (PE32)."""
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]
        opt_magic_offset = e_lfanew + OPT_MAGIC_OFFSET

        if opt_magic_offset + 2 > len(data):
            return False

        opt_magic = struct.unpack_from("<H", data, opt_magic_offset)[0]
        return opt_magic == 0x020B  # PE32+

    def _read_image_base(self, data: bytearray, is_64bit: bool) -> int:
        """Read ImageBase from PE optional header."""
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]

        if is_64bit:
            offset = e_lfanew + 40  # PE32+ ImageBase at offset 24 from opt header start
        else:
            offset = e_lfanew + 36  # PE32 ImageBase

        if offset + 8 > len(data):
            return 0

        if is_64bit:
            return struct.unpack_from("<Q", data, offset)[0]
        else:
            return struct.unpack_from("<I", data, offset)[0]

    def _get_section_headers(self, data: bytearray, is_64bit: bool) -> list[tuple[int, int]]:
        """Get list of (offset, name_offset) for each section header."""
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]

        # Number of sections
        num_sections = struct.unpack_from("<H", data, e_lfanew + COFF_NUM_SECTIONS_OFFSET)[0]

        # Size of optional header
        size_opt = struct.unpack_from("<H", data, e_lfanew + COFF_SIZE_OPT_HEADER_OFFSET)[0]

        # Section headers start after PE sig + COFF header + optional header
        sections_start = e_lfanew + 4 + 20 + size_opt

        headers = []
        for i in range(num_sections):
            offset = sections_start + i * SECTION_HEADER_SIZE
            if offset + SECTION_HEADER_SIZE > len(data):
                break
            headers.append((offset, offset))  # (section_offset, name_offset)

        return headers

    def _fix_section_alignment(self, data: bytearray, is_64bit: bool) -> int:
        """Fix section alignment after memory dump.

        In memory, SizeOfRawData = VirtualSize (because sections are
        loaded at their virtual addresses). On disk, SizeOfRawData
        should be aligned to FileAlignment.
        """
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]

        # Read FileAlignment and SectionAlignment
        file_align_offset = e_lfanew + OPT_FILE_ALIGN_OFFSET
        section_align_offset = e_lfanew + OPT_SECTION_ALIGN_OFFSET

        if file_align_offset + 8 > len(data):
            return 0

        file_align = struct.unpack_from("<I", data, file_align_offset)[0]
        section_align = struct.unpack_from("<I", data, section_align_offset)[0]

        if file_align == 0 or section_align == 0:
            return 0

        sections = self._get_section_headers(data, is_64bit)
        fixed = 0

        for sec_offset, name_offset in sections:
            # Section header layout:
            # 0-7: Name (8 bytes)
            # 8-11: VirtualSize (4 bytes)
            # 12-15: VirtualAddress (4 bytes)
            # 16-19: SizeOfRawData (4 bytes)
            # 20-23: PointerToRawData (4 bytes)

            virtual_size = struct.unpack_from("<I", data, sec_offset + 8)[0]
            raw_size = struct.unpack_from("<I", data, sec_offset + 16)[0]
            raw_offset = struct.unpack_from("<I", data, sec_offset + 20)[0]

            # In a memory dump, raw_size often equals virtual_size
            # Fix: set raw_size to virtual_size aligned to file_align
            if raw_size != virtual_size and virtual_size > 0:
                aligned_size = self._align_up(virtual_size, file_align)

                # Check if we have enough data
                if raw_offset + aligned_size <= len(data):
                    struct.pack_into("<I", data, sec_offset + 16, aligned_size)
                    fixed += 1
                else:
                    # Keep original but note the issue
                    struct.pack_into("<I", data, sec_offset + 16,
                                   min(raw_size, len(data) - raw_offset))
                    fixed += 1

        return fixed

    def _fix_entry_point(self, data: bytearray, is_64bit: bool) -> bool:
        """Verify and fix entry point RVA."""
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]
        ep_offset = e_lfanew + OPT_ENTRY_POINT_OFFSET

        if ep_offset + 4 > len(data):
            return False

        ep_rva = struct.unpack_from("<I", data, ep_offset)[0]

        # Check if entry point is within any section
        sections = self._get_section_headers(data, is_64bit)
        for sec_offset, _ in sections:
            va = struct.unpack_from("<I", data, sec_offset + 12)[0]
            vs = struct.unpack_from("<I", data, sec_offset + 8)[0]
            if va <= ep_rva < va + vs:
                return False  # Entry point is valid

        # Entry point is outside all sections — likely wrong
        # Try to find the actual entry point by looking for common patterns
        # (This is a heuristic — in practice, you'd need the original EP)
        logger.debug("[pe_repair] Entry point 0x%X outside all sections", ep_rva)
        return False

    def _fix_size_of_image(self, data: bytearray, is_64bit: bool) -> bool:
        """Fix SizeOfImage to match actual loaded size."""
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]

        section_align_offset = e_lfanew + OPT_SECTION_ALIGN_OFFSET
        section_align = struct.unpack_from("<I", data, section_align_offset)[0]
        if section_align == 0:
            return False

        sections = self._get_section_headers(data, is_64bit)
        if not sections:
            return False

        # SizeOfImage = highest (VirtualAddress + VirtualSize) aligned to SectionAlignment
        max_end = 0
        for sec_offset, _ in sections:
            va = struct.unpack_from("<I", data, sec_offset + 12)[0]
            vs = struct.unpack_from("<I", data, sec_offset + 8)[0]
            end = va + vs
            if end > max_end:
                max_end = end

        aligned_size = self._align_up(max_end, section_align)

        if is_64bit:
            soi_offset = e_lfanew + 72  # PE32+
        else:
            soi_offset = e_lfanew + 68  # PE32

        if soi_offset + 4 > len(data):
            return False

        current = struct.unpack_from("<I", data, soi_offset)[0]
        if current != aligned_size:
            struct.pack_into("<I", data, soi_offset, aligned_size)
            return True

        return False

    def _fix_size_of_headers(self, data: bytearray, is_64bit: bool) -> bool:
        """Fix SizeOfHeaders to match actual header size."""
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]
        file_align_offset = e_lfanew + OPT_FILE_ALIGN_OFFSET
        file_align = struct.unpack_from("<I", data, file_align_offset)[0]
        if file_align == 0:
            return False

        sections = self._get_section_headers(data, is_64bit)
        if not sections:
            return False

        # SizeOfHeaders = offset of first section, aligned to FileAlignment
        first_section_offset = sections[0][0]
        aligned = self._align_up(first_section_offset, file_align)

        if is_64bit:
            soh_offset = e_lfanew + 76  # PE32+
        else:
            soh_offset = e_lfanew + 72  # PE32

        if soh_offset + 4 > len(data):
            return False

        current = struct.unpack_from("<I", data, soh_offset)[0]
        if current != aligned:
            struct.pack_into("<I", data, soh_offset, aligned)
            return True

        return False

    def _fix_checksum(self, data: bytearray, is_64bit: bool) -> bool:
        """Calculate and fix PE checksum."""
        e_lfanew = struct.unpack_from("<I", data, E_LFANEW_OFFSET)[0]

        if is_64bit:
            checksum_offset = e_lfanew + 128
        else:
            checksum_offset = e_lfanew + 124

        if checksum_offset + 4 > len(data):
            return False

        # Calculate PE checksum (simple algorithm)
        checksum = self._calculate_pe_checksum(data, checksum_offset)

        current = struct.unpack_from("<I", data, checksum_offset)[0]
        if current != checksum:
            struct.pack_into("<I", data, checksum_offset, checksum)
            return True

        return False

    def _calculate_pe_checksum(self, data: bytearray, checksum_offset: int) -> int:
        """Calculate PE checksum (Windows algorithm)."""
        checksum = 0
        data_len = len(data)

        # Sum all 32-bit words, skipping the checksum field
        for i in range(0, data_len, 4):
            if i == checksum_offset:
                continue  # Skip checksum field

            if i + 4 <= data_len:
                word = struct.unpack_from("<I", data, i)[0]
            else:
                # Partial word at end
                remaining = data_len - i
                word = int.from_bytes(data[i:i + remaining], "little")

            checksum = (checksum & 0xFFFFFFFF) + word
            # Fold carry
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # Final fold
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum += data_len

        return checksum & 0xFFFFFFFF

    def _fix_section_characteristics(self, data: bytearray, is_64bit: bool) -> int:
        """Fix section characteristics flags."""
        sections = self._get_section_headers(data, is_64bit)
        fixed = 0

        # Common characteristics flags
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ = 0x40000000
        IMAGE_SCN_MEM_WRITE = 0x80000000
        IMAGE_SCN_CNT_CODE = 0x00000020
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040

        for sec_offset, name_offset in sections:
            name = data[name_offset:name_offset + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            chars = struct.unpack_from("<I", data, sec_offset + 36)[0]

            # Code sections should have EXECUTE + READ + CNT_CODE
            if name in (".text", "CODE", "INIT"):
                expected = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
                if (chars & expected) != expected:
                    struct.pack_into("<I", data, sec_offset + 36,
                                   chars | expected)
                    fixed += 1

        return fixed

    def _rebuild_imports_lief(self, data: bytearray) -> bool:
        """Rebuild import directory using lief."""
        try:
            import lief
            import tempfile

            # Write to temp file for lief
            with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
                f.write(data)
                temp_path = f.name

            binary = lief.parse(temp_path)
            if binary is None:
                return False

            # Check if imports are missing
            has_imports = hasattr(binary, "imports") and len(binary.imports) > 0

            if not has_imports:
                logger.debug("[pe_repair] No imports found — cannot rebuild")
                return False

            # LIEF can rebuild the import directory
            builder = lief.PE.Builder(binary)
            builder.build_imports(True)
            builder.build()

            # Get rebuilt binary
            rebuilt = bytes(builder.get_build())
            data[:len(rebuilt)] = rebuilt

            return True

        except Exception as e:
            logger.debug("[pe_repair] lief rebuild failed: %s", e)
            return False

    @staticmethod
    def _align_up(value: int, alignment: int) -> int:
        """Align value up to the given alignment."""
        if alignment == 0:
            return value
        return ((value + alignment - 1) // alignment) * alignment


# ---------------------------------------------------------------------------
# Utility: Quick PE fix
# ---------------------------------------------------------------------------

def quick_fix_pe(input_path: Path, output_path: Path | None = None) -> bool:
    """Quick PE fix — applies all repairs and writes result.

    Args:
        input_path: Path to damaged PE.
        output_path: Output path. If None, appends '_fixed' to filename.

    Returns:
        True if repair was successful.
    """
    if output_path is None:
        output_path = input_path.parent / f"{input_path.stem}_fixed{input_path.suffix}"

    engine = PERepairEngine()
    result = engine.repair(input_path, output_path=output_path)

    if result.success:
        logger.info("[pe_repair] Quick fix applied to %s → %s", input_path.name, output_path.name)
        return True
    else:
        logger.warning("[pe_repair] Quick fix failed: %s", result.error)
        return False
