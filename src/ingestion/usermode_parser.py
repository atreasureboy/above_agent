"""
DriverScope — User-mode PE ingestion.

Parse .exe/.dll files, extract PE metadata, detect user-mode characteristics
(service entries, COM interfaces, embedded resources), and output standardized
Sample objects with is_usermode=True.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pefile

from ..models import Architecture, Sample, SignatureStatus
from .signature import verify_signature


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
        logging.warning("[usermode_parser] Failed to extract StringFileInfo: %s", e)

    return info


def extract_imports(pe: pefile.PE) -> list[str]:
    imports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            imports.append(dll_name)
            # Also extract individual API function names
            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode("utf-8", errors="replace")
                    imports.append(api_name)
    except Exception as e:
        logging.warning("[usermode_parser] Failed to extract imports: %s", e)
    return imports


def extract_exports(pe: pefile.PE) -> list[str]:
    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="replace"))
    except Exception as e:
        logging.warning("[usermode_parser] Failed to extract exports: %s", e)
    return exports


def extract_sections(pe: pefile.PE) -> list[str]:
    return [s.Name.decode("utf-8", errors="replace").rstrip("\x00") for s in pe.sections]


def detect_binary_type(pe: pefile.PE, exports: list[str]) -> str:
    """Detect binary type: exe, dll, sys."""
    try:
        characteristics = pe.FILE_HEADER.Characteristics
        if characteristics & 0x2000:  # IMAGE_FILE_DLL
            return "dll"
    except Exception:
        pass
    return "exe"


def detect_com_interfaces(exports: list[str]) -> list[str]:
    """Detect COM-related exports: DllGetClassObject, DllCanUnloadNow, etc."""
    com_exports = [
        "DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer",
        "DllUnregisterServer", "CGetClassObject", "DllGetClassObjectFromHr",
    ]
    found = []
    exports_lower = {e.lower(): e for e in exports}
    for pattern in com_exports:
        if pattern.lower() in exports_lower:
            found.append(exports_lower[pattern.lower()])
    return found


def detect_service_entrypoints(exports: list[str]) -> dict:
    """Detect Windows service registration entry points."""
    service_exports = []
    for exp in exports:
        exp_lower = exp.lower()
        if "servicemain" in exp_lower or "svchost" in exp_lower or "startservice" in exp_lower:
            service_exports.append(exp)

    return {
        "service_exports": service_exports,
        "has_service_entry": len(service_exports) > 0,
    }


def extract_embedded_resources(pe: pefile.PE, sample_path: Path) -> list[Path]:
    """Extract embedded PE files from resource section (e.g. embedded .sys drivers)."""
    embedded = []
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return embedded

        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, "directory"):
                for entry in resource_type.directory.entries:
                    if hasattr(entry, "directory") and hasattr(entry.directory, "entries"):
                        for data_entry in entry.directory.entries:
                            if hasattr(data_entry, "data") and hasattr(data_entry.data, "struct"):
                                rva = data_entry.data.struct.OffsetToData
                                size = data_entry.data.struct.Size
                                if size < 100:
                                    continue
                                data = pe.get_data(rva, size)
                                if len(data) >= 2 and data[0] == 0x4D and data[1] == 0x5A:  # MZ header
                                    embedded.append(sample_path)
    except Exception as e:
        logging.warning("[usermode_parser] Failed to scan embedded resources: %s", e)
    return embedded


def detect_dangerous_usermode_imports(imports: list[str]) -> list[str]:
    """Identify dangerous user-mode DLL imports.

    pefile extracts DLL names from the IAT (e.g. 'kernel32.dll'),
    not individual API names. This function flags imports of DLLs
    known to export dangerous APIs.
    """
    dangerous_dlls = {
        "kernel32.dll",
        "ntdll.dll",
        "advapi32.dll",
    }
    found = []
    for imp in imports:
        imp_lower = imp.lower()
        if imp_lower in dangerous_dlls or imp_lower.endswith(".dll"):
            for dll in dangerous_dlls:
                if imp_lower == dll or imp_lower.endswith("\\" + dll):
                    found.append(imp)
                    break
    return found


def ingest_usermode(sample_path: Path) -> Sample:
    """Ingest a user-mode .exe or .dll file into a standardized Sample object.

    Args:
        sample_path: Path to the .exe or .dll file.

    Returns:
        Sample object with is_usermode=True and user-mode metadata populated.

    Raises:
        ValueError: If the file is not a valid PE.
    """
    if not sample_path.exists():
        raise FileNotFoundError(f"Sample not found: {sample_path}")

    raw = sample_path.read_bytes()

    try:
        pe = pefile.PE(data=raw, fast_load=True)
        pe.parse_data_directories()
    except pefile.PEFormatError as e:
        raise ValueError(f"Not a valid PE file: {sample_path}") from e

    version_info = extract_version_info(pe)
    imports = extract_imports(pe)
    exports = extract_exports(pe)

    compile_ts = 0
    try:
        compile_ts = pe.FILE_HEADER.TimeDateStamp
    except Exception as e:
        logging.warning("[usermode_parser] Failed to read PE timestamp: %s", e)

    binary_type = detect_binary_type(pe, exports)
    sig_status, signer_name = verify_signature(sample_path)

    com_interfaces = detect_com_interfaces([
        e.decode("utf-8", errors="replace") if isinstance(e, bytes) else e
        for e in exports
    ])
    service_info = detect_service_entrypoints([
        e.decode("utf-8", errors="replace") if isinstance(e, bytes) else e
        for e in exports
    ])
    embedded_files = extract_embedded_resources(pe, sample_path)

    subsystem_map = {
        0: "UNKNOWN", 1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
        5: "OS2_CUI", 7: "POSIX_CUI", 8: "NATIVE_WINDOWS", 9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM", 14: "XBOX", 16: "BOOT_APPLICATION",
    }
    try:
        subsystem = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN")
    except Exception:
        subsystem = "UNKNOWN"

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
        debug_path="",
        is_driver=False,
        driver_type="",
        subsystem=subsystem,
        signature_status=sig_status,
        signer_name=signer_name,
        is_usermode=True,
        binary_type=binary_type,
        com_interfaces=com_interfaces,
        service_info=service_info,
        embedded_files=embedded_files,
    )


def ingest_directory_usermode(directory: Path, include_nested: bool = True) -> list[Sample]:
    """Ingest all .exe and .dll files in a directory.

    Args:
        directory: Path to directory to scan.
        include_nested: Whether to recurse into subdirectories.

    Returns:
        List of Sample objects. Skips non-PE files.
    """
    samples = []
    max_files = 2000
    count = 0
    extensions = {"*.exe", "*.dll"}

    glob_func = directory.rglob if include_nested else directory.glob
    for ext in extensions:
        for f in glob_func(ext):
            if count >= max_files:
                print(f"[usermode_parser] Reached {max_files} file cap, skipping remaining")
                break
            count += 1
            try:
                samples.append(ingest_usermode(f))
            except (ValueError, FileNotFoundError) as e:
                logging.debug("[usermode_parser] Skipping %s: %s", f, e)
    return samples
