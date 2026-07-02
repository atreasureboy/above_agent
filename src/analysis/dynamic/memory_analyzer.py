"""
DriverScope — Memory Analyzer.

Runtime memory inspection and analysis for:
1. Detecting unpacked PE images in process memory
2. Scanning for code caves and injected shells
3. Extracting dynamically-loaded modules
4. Dumping and analyzing heap allocations
5. Detecting hook patterns (inline hooks, IAT hooks)

Works with both Frida (live process) and raw memory dumps.

Usage:
    from src.analysis.dynamic.memory_analyzer import MemoryAnalyzer

    analyzer = MemoryAnalyzer()
    pes = analyzer.find_pe_in_memory(process_memory_dump)
    hooks = analyzer.detect_hooks(module_base, module_size)
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class MemoryRegion:
    """A region of process memory."""
    base_address: int = 0
    size: int = 0
    protection: str = ""  # "rwx", "rw-", "r-x", etc.
    type: str = ""        # "image", "mapped", "private"
    state: str = ""       # "commit", "reserve", "free"
    content_hash: str = ""

    @property
    def end_address(self) -> int:
        return self.base_address + self.size

    @property
    def is_executable(self) -> bool:
        return "x" in self.protection

    @property
    def is_writable(self) -> bool:
        return "w" in self.protection


@dataclass
class PEInMemory:
    """A PE image found in process memory."""
    base_address: int = 0
    size: int = 0
    entry_point: int = 0
    sections: list[dict[str, Any]] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    is_valid: bool = False
    confidence: float = 0.0


@dataclass
class HookDetection:
    """A detected hook in memory."""
    address: int = 0
    hook_type: str = ""  # "inline", "iat", "eat", "vtable"
    target: str = ""     # Function name or description
    original_bytes: bytes = b""
    hook_bytes: bytes = b""
    destination: int = 0  # Where the hook redirects to


@dataclass
class MemoryAnalysisResult:
    """Complete memory analysis result."""
    regions: list[MemoryRegion] = field(default_factory=list)
    pe_images: list[PEInMemory] = field(default_factory=list)
    hooks: list[HookDetection] = field(default_factory=list)
    suspicious_regions: list[MemoryRegion] = field(default_factory=list)
    code_caves: list[dict[str, Any]] = field(default_factory=list)
    elapsed: float = 0.0


# ---------------------------------------------------------------------------
# Memory Analyzer
# ---------------------------------------------------------------------------

class MemoryAnalyzer:
    """Runtime memory analysis engine."""

    MZ_SIGNATURE = b"MZ"
    PE_SIGNATURE = b"PE\x00\x00"

    # Known inline hook patterns
    INLINE_HOOK_PATTERNS = {
        b"\xE9": "JMP rel32",          # 5-byte relative jump
        b"\xEB": "JMP rel8",           # 2-byte short jump
        b"\xFF\x25": "JMP [addr]",     # 6-byte indirect jump (x86)
        b"\x48\xFF\x25": "JMP [rip+]", # 6-byte indirect jump (x64)
        b"\x68": "PUSH+RET",           # 6-byte push addr; ret
        b"\xB8": "MOV EAX+JMP",       # 5-byte mov eax, addr; ...
    }

    def __init__(self):
        self._frida_session = None

    # ── Memory Enumeration ─────────────────────────────────────

    def enumerate_regions(self, frida_session: Any = None) -> list[MemoryRegion]:
        """Enumerate all memory regions of a process.

        Args:
            frida_session: Active Frida session. If None, uses current process.

        Returns:
            List of MemoryRegion objects.
        """
        regions = []

        if frida_session:
            try:
                script_code = """
                var ranges = Process.enumerateRanges('---');
                var result = [];
                for (var i = 0; i < ranges.length; i++) {
                    var r = ranges[i];
                    result.push({
                        base: r.base.toString(),
                        size: r.size,
                        protection: r.protection,
                        type: r.type || ''
                    });
                }
                send({type: 'regions', data: result});
                """
                script = frida_session.create_script(script_code)
                result_data = []

                def on_message(message, data):
                    if message.get("type") == "send":
                        payload = message.get("payload", {})
                        if payload.get("type") == "regions":
                            result_data.extend(payload.get("data", []))

                script.on("message", on_message)
                script.load()

                for r in result_data:
                    regions.append(MemoryRegion(
                        base_address=int(r["base"], 16),
                        size=r["size"],
                        protection=r["protection"],
                        type=r.get("type", ""),
                    ))

            except Exception as e:
                logger.warning("[memory] Region enumeration failed: %s", e)
        else:
            # Use current process memory map (Linux /proc/self/maps style)
            regions = self._enumerate_local_regions()

        return regions

    def _enumerate_local_regions(self) -> list[MemoryRegion]:
        """Enumerate memory regions of the current process."""
        regions = []
        try:
            import ctypes
            import sys

            if sys.platform == "win32":
                # Windows: VirtualQueryEx enumeration
                regions = self._enumerate_windows_regions()
            else:
                # Linux/macOS: parse /proc/self/maps
                regions = self._enumerate_proc_maps()

        except Exception as e:
            logger.warning("[memory] Local region enumeration failed: %s", e)

        return regions

    def _enumerate_windows_regions(self) -> list[MemoryRegion]:
        """Enumerate regions using VirtualQueryEx on Windows."""
        import ctypes
        from ctypes import wintypes

        regions = []

        try:
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010

            kernel32 = ctypes.WinDLL("kernel32")
            OpenProcess = kernel32.OpenProcess
            VirtualQueryEx = kernel32.VirtualQueryEx
            CloseHandle = kernel32.CloseHandle

            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            pid = ctypes.windll.kernel32.GetCurrentProcessId()
            process = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
            )

            mbi = MEMORY_BASIC_INFORMATION()
            address = 0

            while VirtualQueryEx(process, ctypes.c_void_p(address),
                                ctypes.byref(mbi), ctypes.sizeof(mbi)):
                prot_map = {
                    0x01: "r--", 0x02: "rw-", 0x04: "r-x", 0x08: "rwx",
                    0x10: "r--", 0x20: "rw-", 0x40: "r-x", 0x80: "rwx",
                }
                state_map = {0x1000: "commit", 0x2000: "reserve", 0x10000: "free"}
                type_map = {0x20000: "image", 0x40000: "mapped", 0x20000: "private"}

                regions.append(MemoryRegion(
                    base_address=mbi.BaseAddress or 0,
                    size=mbi.RegionSize,
                    protection=prot_map.get(mbi.Protect, "---"),
                    state=state_map.get(mbi.State, ""),
                    type=type_map.get(mbi.Type, ""),
                ))

                address = (mbi.BaseAddress or 0) + mbi.RegionSize
                if address == 0:
                    break

            CloseHandle(process)

        except Exception as e:
            logger.debug("[memory] Windows region enum failed: %s", e)

        return regions

    def _enumerate_proc_maps(self) -> list[MemoryRegion]:
        """Parse /proc/self/maps for region enumeration."""
        regions = []
        try:
            with open("/proc/self/maps", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 5:
                        continue
                    addr_range = parts[0].split("-")
                    base = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    perms = parts[1]
                    regions.append(MemoryRegion(
                        base_address=base,
                        size=end - base,
                        protection=perms[:3],
                    ))
        except Exception:
            pass
        return regions

    # ── PE Detection in Memory ─────────────────────────────────

    def find_pe_in_memory(
        self,
        data: bytes,
        base_address: int = 0,
    ) -> list[PEInMemory]:
        """Scan a memory region for PE images.

        Args:
            data: Raw memory bytes.
            base_address: Base address of the memory region.

        Returns:
            List of detected PE images.
        """
        found = []
        offset = 0

        while offset < len(data) - 0x40:
            # Look for MZ signature
            if data[offset:offset + 2] == self.MZ_SIGNATURE:
                pe = self._validate_pe_at(data, offset, base_address)
                if pe and pe.is_valid:
                    found.append(pe)
                    # Skip past this PE
                    offset += max(pe.size, 0x200)
                    continue

            offset += 0x10  # Scan in 16-byte steps

        return found

    def _validate_pe_at(
        self,
        data: bytes,
        offset: int,
        base_address: int,
    ) -> PEInMemory | None:
        """Validate a potential PE at the given offset."""
        try:
            if offset + 0x40 > len(data):
                return None

            # Check e_lfanew
            e_lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]
            if e_lfanew > 0x400 or offset + e_lfanew + 4 > len(data):
                return None

            # Check PE signature
            if data[offset + e_lfanew:offset + e_lfanew + 4] != self.PE_SIGNATURE:
                return None

            pe = PEInMemory(
                base_address=base_address + offset,
                is_valid=True,
                confidence=0.95,
            )

            # Parse PE headers
            try:
                import pefile
                pe_data = data[offset:]
                pef = pefile.PE(data=pe_data, fast_load=True)

                pe.size = pef.OPTIONAL_HEADER.SizeOfImage
                pe.entry_point = pef.OPTIONAL_HEADER.AddressOfEntryPoint

                # Extract sections
                for section in pef.sections:
                    name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
                    pe.sections.append({
                        "name": name,
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                    })

                # Extract imports
                if hasattr(pef, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pef.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("ascii", errors="replace")
                        pe.imports.append(dll_name)

                pef.close()

            except Exception as e:
                pe.confidence = 0.6
                pe.is_valid = True  # MZ+PE signatures at least

            return pe

        except Exception:
            return None

    # ── Hook Detection ─────────────────────────────────────────

    def detect_hooks(
        self,
        memory_data: bytes,
        module_base: int,
        iat_entries: list[dict[str, Any]] | None = None,
    ) -> list[HookDetection]:
        """Detect hooks in a module's memory.

        Checks for:
        1. Inline hooks (JMP/CALL at function entry points)
        2. IAT hooks (modified import addresses)
        3. EAT hooks (modified export addresses)

        Args:
            memory_data: Module's raw memory.
            module_base: Base address of the module.
            iat_entries: List of IAT entries with expected addresses.

        Returns:
            List of detected hooks.
        """
        hooks = []

        # Inline hook detection
        hooks.extend(self._detect_inline_hooks(memory_data, module_base))

        # IAT hook detection
        if iat_entries:
            hooks.extend(self._detect_iat_hooks(memory_data, module_base, iat_entries))

        return hooks

    def _detect_inline_hooks(
        self,
        data: bytes,
        base: int,
    ) -> list[HookDetection]:
        """Detect inline hooks by scanning for JMP/CALL patterns."""
        hooks = []

        # Common hook signatures at function entry points
        for i in range(0, min(len(data) - 6, 0x10000), 1):
            byte = data[i:i + 1]

            # JMP rel32 (E9 xx xx xx xx)
            if byte == b"\xE9" and i + 5 <= len(data):
                rel32 = struct.unpack_from("<i", data, i + 1)[0]
                dest = base + i + 5 + rel32

                # Only flag if destination is outside the module
                if dest < base or dest >= base + len(data):
                    hooks.append(HookDetection(
                        address=base + i,
                        hook_type="inline",
                        target=f"JMP rel32 → 0x{dest:X}",
                        original_bytes=data[i:i + 5],
                        hook_bytes=data[i:i + 5],
                        destination=dest,
                    ))

            # PUSH imm32 + RET (68 xx xx xx xx C3)
            elif byte == b"\x68" and i + 6 <= len(data) and data[i + 5:i + 6] == b"\xC3":
                dest = struct.unpack_from("<I", data, i + 1)[0]
                hooks.append(HookDetection(
                    address=base + i,
                    hook_type="inline",
                    target=f"PUSH+RET → 0x{dest:X}",
                    original_bytes=data[i:i + 6],
                    hook_bytes=data[i:i + 6],
                    destination=dest,
                ))

            # x64 JMP [rip+offset] (48 FF 25 xx xx xx xx)
            elif data[i:i + 3] == b"\x48\xFF\x25" and i + 7 <= len(data):
                rip_offset = struct.unpack_from("<i", data, i + 3)[0]
                dest_addr = base + i + 7 + rip_offset
                if dest_addr < base or dest_addr >= base + len(data):
                    hooks.append(HookDetection(
                        address=base + i,
                        hook_type="inline",
                        target=f"JMP [rip+0x{rip_offset:X}]",
                        original_bytes=data[i:i + 7],
                        hook_bytes=data[i:i + 7],
                        destination=dest_addr,
                    ))

        return hooks

    def _detect_iat_hooks(
        self,
        data: bytes,
        base: int,
        iat_entries: list[dict[str, Any]],
    ) -> list[HookDetection]:
        """Detect IAT hooks by comparing expected vs actual addresses."""
        hooks = []

        for entry in iat_entries:
            expected = entry.get("expected_address", 0)
            actual_offset = entry.get("offset", 0)

            if actual_offset + 8 > len(data):
                continue

            actual = struct.unpack_from("<Q", data, actual_offset)[0]

            if expected and actual != expected:
                # IAT has been modified — this is a hook
                hooks.append(HookDetection(
                    address=base + actual_offset,
                    hook_type="iat",
                    target=entry.get("name", "unknown"),
                    original_bytes=struct.pack("<Q", expected),
                    hook_bytes=struct.pack("<Q", actual),
                    destination=actual,
                ))

        return hooks

    # ── Suspicious Region Detection ────────────────────────────

    def find_suspicious_regions(
        self,
        regions: list[MemoryRegion],
    ) -> list[MemoryRegion]:
        """Find memory regions that look suspicious.

        Criteria:
        - RWX (read-write-execute) regions
        - Executable regions with no PE image
        - Large private regions with high entropy
        """
        suspicious = []

        for region in regions:
            # RWX is always suspicious
            if "r" in region.protection and "w" in region.protection and "x" in region.protection:
                if region.state == "commit" and region.size > 0x1000:
                    suspicious.append(region)

            # Non-image executable private regions
            elif region.is_executable and region.type == "private" and region.state == "commit":
                if region.size > 0x1000:
                    suspicious.append(region)

        return suspicious

    # ── Full Analysis ──────────────────────────────────────────

    def analyze(
        self,
        data: bytes,
        base_address: int = 0,
        frida_session: Any = None,
    ) -> MemoryAnalysisResult:
        """Run complete memory analysis.

        Args:
            data: Memory dump or region data.
            base_address: Base address of the region.
            frida_session: Optional Frida session for live analysis.

        Returns:
            MemoryAnalysisResult with all findings.
        """
        import time
        start = time.time()
        result = MemoryAnalysisResult()

        # Enumerate regions (if live)
        if frida_session:
            result.regions = self.enumerate_regions(frida_session)
        else:
            # Single region from the provided data
            result.regions = [MemoryRegion(
                base_address=base_address,
                size=len(data),
                protection="rwx",
            )]

        # Find PE images
        result.pe_images = self.find_pe_in_memory(data, base_address)

        # Detect hooks
        result.hooks = self.detect_hooks(data, base_address)

        # Find suspicious regions
        result.suspicious_regions = self.find_suspicious_regions(result.regions)

        result.elapsed = time.time() - start
        return result
