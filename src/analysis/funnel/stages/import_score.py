"""L3: Import table + string scoring filter stage.

Scores samples based on dangerous kernel API imports without disassembly.
Filters out samples below a score threshold.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pefile

from src.config.defaults import (
    DANGEROUS_API_WEIGHTS,
    USER_MODE_ACCESS_STRINGS,
    IMPORT_SCORE_DEFAULT_THRESHOLD,
)
from src.analysis.funnel.stages import FilterStage, FilterResult
from src.models import Sample


# Backwards-compat alias so existing imports still work
L2_DANGEROUS_API_WEIGHTS = DANGEROUS_API_WEIGHTS
L2_DEFAULT_THRESHOLD = IMPORT_SCORE_DEFAULT_THRESHOLD


def _score_imports(pe_path: Path) -> dict[str, Any]:
    """Parse PE imports and strings, return scored info."""
    imported_apis: list[str] = []
    all_imports: list[str] = []
    strings: list[str] = []
    dlls: list[str] = []

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories()

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                dlls.append(dll_name.lower())
                for thunk in entry.imports:
                    if thunk.name:
                        api_name = thunk.name.decode("utf-8", errors="replace")
                        all_imports.append(api_name)
                        if dll_name.lower() in ("ntoskrnl.exe", "hal.dll", "ntkrnlpa.exe"):
                            imported_apis.append(api_name)

        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00").lower()
            if name in (".rdata", ".data", ".rodata"):
                raw_data = section.get_data()
                for m in re.finditer(rb"[\x20-\x7e]{4,}", raw_data):
                    strings.append(m.group(0).decode("ascii", errors="replace"))

        pe.close()
    except Exception:
        pass

    dangerous_apis = [api for api in imported_apis if api in L2_DANGEROUS_API_WEIGHTS]

    return {
        "imported_apis": imported_apis,
        "all_imports": all_imports,
        "dlls": dlls,
        "strings": strings,
        "dangerous_apis": dangerous_apis,
    }


def _score_imports_fast(pe_path: Path) -> dict[str, Any]:
    """Parse PE imports only (no string extraction) for fast scoring.

    Skips expensive string extraction from .rdata/.data sections.
    Returns the same dict structure but with empty strings list.
    """
    imported_apis: list[str] = []
    all_imports: list[str] = []
    dlls: list[str] = []

    try:
        # Reject excessively large files to prevent OOM
        if pe_path.stat().st_size > 200 * 1024 * 1024:
            return {
                "imported_apis": [],
                "all_imports": [],
                "dlls": [],
                "strings": [],
                "dangerous_apis": [],
            }

        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories()

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                dlls.append(dll_name.lower())
                for thunk in entry.imports:
                    if thunk.name:
                        api_name = thunk.name.decode("utf-8", errors="replace")
                        all_imports.append(api_name)
                        if dll_name.lower() in ("ntoskrnl.exe", "hal.dll", "ntkrnlpa.exe"):
                            imported_apis.append(api_name)

        pe.close()
    except Exception:
        pass

    dangerous_apis = [api for api in imported_apis if api in L2_DANGEROUS_API_WEIGHTS]

    return {
        "imported_apis": imported_apis,
        "all_imports": all_imports,
        "dlls": dlls,
        "strings": [],
        "dangerous_apis": dangerous_apis,
    }


def _compute_import_score(imported_apis: list[str]) -> int:
    """Compute weighted score based on dangerous API imports."""
    return sum(L2_DANGEROUS_API_WEIGHTS.get(api, 0) for api in imported_apis)


def _check_user_mode_strings(strings: list[str]) -> bool:
    """Check if any strings suggest user-mode device accessibility."""
    for s in strings:
        for pattern in USER_MODE_ACCESS_STRINGS:
            if re.search(pattern, s, re.IGNORECASE):
                return True
    return False


class ImportScoreStage(FilterStage):
    """L3: Score samples by dangerous API imports, filter below threshold."""

    def __init__(self, threshold: int = L2_DEFAULT_THRESHOLD) -> None:
        self.threshold = threshold

    @property
    def name(self) -> str:
        return "L3: Import table scoring"

    @property
    def cost(self) -> str:
        return "ms"

    def apply(self, samples: list[Sample]) -> FilterResult:
        passed: list[dict] = []
        rejected: list = []

        for sample in samples:
            # Use fast import-only scoring (skip expensive string extraction).
            # User-mode access string detection is a secondary signal that
            # doesn't affect the primary import score.
            score_info = _score_imports_fast(sample.path)
            score_info["sample"] = sample
            score_info["import_score"] = _compute_import_score(score_info["imported_apis"])
            score_info["has_user_mode_access"] = False  # Requires full string extraction

            if score_info["import_score"] >= self.threshold:
                passed.append(score_info)
            else:
                rejected.append((
                    sample,
                    f"import_score={score_info['import_score']} < {self.threshold}",
                ))

        # Sort by import_score descending
        passed.sort(key=lambda x: x["import_score"], reverse=True)

        return FilterResult(passed=passed, rejected=rejected)
