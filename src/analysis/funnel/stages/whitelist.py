"""L1: Signature-based whitelist filter stage.

Filters out Microsoft-signed drivers and known system components.
Fast string/regex checks — no disassembly or crypto.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pefile

from src.config.defaults import (
    SYSTEM_DRIVER_WHITELIST,
    WHITELIST_DIR_PATTERNS,
    MICROSOFT_CN_KEYWORDS,
    WHITELIST_MAX_SIZE_KB,
)
from src.analysis.funnel.stages import FilterStage, FilterResult
from src.models import Sample



def _matches_system_driver(filename: str) -> bool:
    """Check if filename matches a known system driver (with glob support)."""
    name = filename.lower()
    for pattern in SYSTEM_DRIVER_WHITELIST:
        pat = pattern.lower()
        if name == pat:
            return True
        if name + ".sys" == pat:
            return True
        if pat.endswith(".sys") and name == pat[:-4]:
            return True
        if "*" in pat or "?" in pat:
            if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(name + ".sys", pat):
                return True
    return False


def _get_pe_company(pe_path: Path) -> str | None:
    """Extract CompanyName from PE via pefile VERSION_INFO first,
    then fall back to raw-byte scan of the .rsrc section only."""
    try:
        # Skip large files to avoid OOM
        if pe_path.stat().st_size > 200 * 1024 * 1024:
            return None

        # Try pefile's VERSION_INFO parser first (authoritative source)
        raw = pe_path.read_bytes()
        pe = pefile.PE(data=raw, fast_load=True)
        pe.parse_data_directories()
        for file_info in getattr(pe, "FileInfo", []):
            if file_info.Key == b"StringFileInfo":
                for st in file_info.StringTable:
                    for key, value in st.entries.items():
                        if key.lower() == b"companyname":
                            pe.close()
                            return value.decode("utf-8", errors="replace")
        pe.close()

        # Fallback: scan .rsrc section only (not the entire file)
        pe2 = pefile.PE(data=raw, fast_load=True)
        for section in pe2.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
            if name == ".rsrc":
                rsrc_data = section.get_data()
                for marker in (b"Microsoft Corporation", b"Microsoft Windows"):
                    if marker in rsrc_data:
                        pe2.close()
                        return marker.decode("ascii")
                for marker in (b"Company", b"CompanyName"):
                    idx = rsrc_data.find(marker)
                    if idx >= 0:
                        nearby = rsrc_data[idx:idx + 256]
                        for ms in (b"Microsoft", b"microsoft"):
                            if ms in nearby:
                                pe2.close()
                                return "Microsoft"
                break
        pe2.close()
    except Exception:
        pass
    return None


def _is_in_whitelisted_dir(path: Path) -> bool:
    """Check if file is in a whitelisted directory.

    Anchors patterns from the drive letter forward to avoid matching
    unrelated paths that happen to contain the same substring
    (e.g. ``C:\\malware\\Windows\\System32\\DriverStore\\evil.sys``).
    """
    path_str = str(path).lower()
    for pat in WHITELIST_DIR_PATTERNS:
        # Match from the drive letter (e.g. "C:\Windows\...")
        if re.search(r'^[a-z]:.*' + pat, path_str):
            return True
    return False


class WhitelistStage(FilterStage):
    """L1: Filter known system drivers by name, company, and directory."""

    def __init__(self, max_size_kb: int = WHITELIST_MAX_SIZE_KB) -> None:
        self.max_size_kb = max_size_kb

    @property
    def name(self) -> str:
        return "L1: Signature whitelist"

    @property
    def cost(self) -> str:
        return "ms"

    def apply(self, samples: list[Sample]) -> FilterResult:
        passed: list[Sample] = []
        rejected: list[tuple[Sample, str]] = []

        for sample in samples:
            if _matches_system_driver(sample.name):
                rejected.append((sample, "Known system driver"))
                continue

            size_kb = sample.size / 1024
            if size_kb > self.max_size_kb:
                rejected.append((sample, f"Too large ({size_kb:.0f}KB > {self.max_size_kb}KB)"))
                continue

            # Use company name from ingestion (PE VERSION_INFO) first.
            # Only fall back to raw-byte scan if ingestion couldn't extract it.
            company = sample.company
            if not company:
                company = _get_pe_company(sample.path)
            if company and any(kw in company.lower() for kw in MICROSOFT_CN_KEYWORDS):
                rejected.append((sample, f"Microsoft company: {company}"))
                continue

            if _is_in_whitelisted_dir(sample.path):
                rejected.append((sample, "Whitelisted directory"))
                continue

            passed.append(sample)

        return FilterResult(passed=passed, rejected=rejected)
