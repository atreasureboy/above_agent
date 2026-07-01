"""
DriverScope — Sample ingestion.

Layer 1: Parse .sys files, extract PE metadata, determine driver type,
verify signatures, deduplicate, and output standardized Sample objects.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import pefile

from .signature import verify_signature
from ..models import Architecture, Sample, SignatureStatus


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_architecture(pe: pefile.PE) -> Architecture:
    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        return Architecture.X86
    elif machine == 0x8664:
        return Architecture.X64
    elif machine == 0xAA64:
        return Architecture.ARM64
    return Architecture.UNKNOWN


def is_driver_pe(pe: pefile.PE) -> bool:
    """Check if a PE file is a kernel driver (.sys)."""
    # Check subsystem — drivers use IMAGE_SUBSYSTEM_NATIVE (1)
    try:
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        if subsystem == 1:  # IMAGE_SUBSYSTEM_NATIVE
            return True
    except Exception as e:
        logging.warning("[pe_parser] Failed to read PE subsystem: %s", e)

    # Check if it exports DriverEntry
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and b"DriverEntry" in exp.name:
                return True
    except Exception as e:
        logging.warning("[pe_parser] Failed to read PE exports: %s", e)

    # Check for .sys extension as fallback
    return False


def extract_version_info(pe: pefile.PE) -> dict[str, str]:
    """Extract version information from PE resources."""
    info = {}
    try:
        if hasattr(pe, "VS_FIXEDFILEINFO"):
            ffi = pe.VS_FIXEDFILEINFO[0]
            info["version"] = "{}.{}.{}.{}".format(
                (ffi.ProductVersionMS >> 16) & 0xFFFF,
                ffi.ProductVersionMS & 0xFFFF,
                (ffi.ProductVersionLS >> 16) & 0xFFFF,
                ffi.ProductVersionLS & 0xFFFF,
            )
    except Exception:
        info["version"] = "unknown"

    # StringFileInfo
    try:
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                if file_info.Key == b"StringFileInfo":
                    for st in file_info.StringTable:
                        for key, value in st.entries.items():
                            info[key.decode("utf-8", errors="replace")] = value.decode(
                                "utf-8", errors="replace"
                            )
    except Exception as e:
        logging.warning("[pe_parser] Failed to extract StringFileInfo: %s", e)

    return info


def extract_imports(pe: pefile.PE) -> list[str]:
    """Extract imported DLL names."""
    imports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            imports.append(dll_name)
    except Exception as e:
        logging.warning("[pe_parser] Failed to extract imports: %s", e)
    return imports


def extract_exports(pe: pefile.PE) -> list[str]:
    """Extract exported symbol names."""
    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="replace"))
    except Exception as e:
        logging.warning("[pe_parser] Failed to extract exports: %s", e)
    return exports


def extract_sections(pe: pefile.PE) -> list[str]:
    """Extract section names."""
    return [section.Name.decode("utf-8", errors="replace").rstrip("\x00") for section in pe.sections]


def detect_driver_type(pe: pefile.PE, imports: list[str], exports: list[str]) -> str:
    """Heuristically detect driver type (WDM, WDF/KMDF, WDF/UMDF).

    Detection order:
    1. UMDF: WUDFPlatform/WUDF.dll imports
    2. KMDF: WdfLdr/Wdf01000 imports
    3. WDF strings in .rdata: WdfDriverCreate, WdfVersion
    4. WDM: ntoskrnl.exe + hal.dll imports
    5. UNKNOWN: fallback
    """
    imports_lower = [imp.lower() for imp in imports]

    # WDF/UMDF detection — imports WUDFPlatform or WUDF.dll
    for imp in imports_lower:
        if "wudf" in imp:
            return "WDF/UMDF"

    # WDF/KMDF detection — imports WdfLdr or Wdf01000
    for imp in imports:
        if "wdfldr" in imp.lower() or "wdf01000" in imp.lower():
            return "WDF/KMDF"

    # Secondary WDF detection — check for WDF API imports from ntoskrnl
    # WDF drivers often import WdfDriverCreate, WdfIoQueueCreate etc.
    wdf_api_prefixes = ("wdf", "fx")
    for imp in imports_lower:
        dll_part = imp.split(".")[0] if "." in imp else imp
        for prefix in wdf_api_prefixes:
            if dll_part.startswith(prefix):
                return "WDF/KMDF"

    # WDM detection — typical WDM imports
    wdm_indicators = ["ntoskrnl.exe", "hal.dll", "wmilib.sys"]
    if any(ind.lower() in imports_lower for ind in wdm_indicators):
        return "WDM"

    # Fallback
    return "UNKNOWN"


def extract_debug_path(pe: pefile.PE) -> str:
    """Extract PDB path from debug directory if present."""
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                if debug_entry.entry and hasattr(debug_entry.entry, "CvHeader"):
                    cv_header = debug_entry.entry.CvHeader
                    if hasattr(cv_header, "CvSignature") and cv_header.CvSignature == 0x53445352:  # RSDS
                        # RSDS format: signature, guid, age, pdb_path
                        entries = debug_entry.entry.entries
                        if entries:
                            for entry in entries:
                                if entry.key == b"pdb_path" or hasattr(entry, "value"):
                                    val = getattr(entry, "value", b"")
                                    if isinstance(val, bytes) and b".pdb" in val:
                                        return val.decode("utf-8", errors="replace").rstrip("\x00")
                elif debug_entry.entry:
                    # Try raw data parsing for RSDS
                    struct_type = getattr(debug_entry.struct, "Type", -1)
                    if struct_type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                        addr = getattr(debug_entry.struct, "PointerToRawData", 0)
                        size = getattr(debug_entry.struct, "SizeOfData", 0)
                        if addr and size and size < 500:
                            data = pe.__data__[addr:addr + size]
                            if b"RSDS" in data:
                                rsds_idx = data.index(b"RSDS")
                                pdb_data = data[rsds_idx + 4:]
                                null_idx = pdb_data.find(b"\x00")
                                if null_idx > 0:
                                    return pdb_data[:null_idx].decode("utf-8", errors="replace")
    except Exception as e:
        logging.warning("[pe_parser] Failed to extract PDB path: %s", e)
    return ""


def ingest(sample_path: Path) -> Sample:
    """Ingest a single .sys file into a standardized Sample object.

    Args:
        sample_path: Path to the driver .sys file.

    Returns:
        Sample object with PE metadata populated.

    Raises:
        ValueError: If the file is not a valid PE or not a driver.
    """
    if not sample_path.exists():
        raise FileNotFoundError(f"Sample not found: {sample_path}")

    raw = sample_path.read_bytes()

    try:
        pe = pefile.PE(data=raw, fast_load=True)
    except pefile.PEFormatError as e:
        raise ValueError(f"Not a valid PE file: {sample_path}") from e

    if not is_driver_pe(pe):
        raise ValueError(f"Not a kernel driver: {sample_path}")

    version_info = extract_version_info(pe)
    imports = extract_imports(pe)
    exports = extract_exports(pe)

    compile_ts = 0
    try:
        compile_ts = pe.FILE_HEADER.TimeDateStamp
    except Exception as e:
        logging.warning("[pe_parser] Failed to read PE timestamp: %s", e)

    sig_status, signer_name = verify_signature(sample_path)

    return Sample(
        path=sample_path,
        name=version_info.get("OriginalFilename", sample_path.stem),
        company=version_info.get("CompanyName", ""),
        version=version_info.get("version", "unknown"),
        arch=detect_architecture(pe),
        sha256=compute_sha256(raw),
        size=len(raw),
        imports=imports,
        exports=exports,
        sections=extract_sections(pe),
        entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        compile_timestamp=compile_ts,
        debug_path=extract_debug_path(pe),
        is_driver=True,
        driver_type=detect_driver_type(pe, imports, exports),
        subsystem="NATIVE",
        signature_status=sig_status,
        signer_name=signer_name,
    )


def ingest_any_pe(sample_path: Path) -> Sample:
    """Ingest any PE file (.sys, .exe, .dll). Auto-detects kernel vs user-mode.

    Kernel drivers are parsed via ingest() (full driver analysis).
    User-mode binaries are parsed via ingest_usermode() (imports, exports,
    COM interfaces, service entry points, embedded resources).
    """
    pe = pefile.PE(str(sample_path), fast_load=True)
    try:
        if is_driver_pe(pe):
            pe.close()
            return ingest(sample_path)
        else:
            pe.close()
            from src.ingestion.usermode_parser import ingest_usermode
            return ingest_usermode(sample_path)
    except Exception:
        pe.close()
        raise


def ingest_directory(directory: Path) -> list[Sample]:
    """Ingest .sys files from a directory or a single .sys file path.

    Args:
        directory: Path to a directory containing .sys files, or a single .sys file.

    Returns:
        List of Sample objects. Skips non-driver files.

    Note:
        Caps at 2000 files to avoid OOM on massive directories (e.g. DriverStore).
        Files beyond the cap are silently skipped — the funnel can still analyze
        whatever it received.
    """
    samples = []
    max_files = 2000
    count = 0

    # Handle single file path
    if directory.is_file() and directory.suffix.lower() == ".sys":
        try:
            samples.append(ingest(directory))
        except (ValueError, FileNotFoundError) as e:
            print(f"[ingestion] Skipping {directory}: {e}")
        return samples

    # Handle directory path
    for f in directory.rglob("*.sys"):
        if count >= max_files:
            print(f"[ingestion] Reached {max_files} file cap, skipping remaining files")
            break
        count += 1
        try:
            samples.append(ingest(f))
        except (ValueError, FileNotFoundError) as e:
            print(f"[ingestion] Skipping {f}: {e}")
    return samples
