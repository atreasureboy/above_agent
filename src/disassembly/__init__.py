"""Disassembly layer — backend abstraction for Ghidra/IDA/radare2/Capstone."""

from __future__ import annotations

from pathlib import Path
from typing import Type

from src.disassembly.backend import DisassemblyBackend
from src.disassembly.capstone_backend import CapstoneBackend
from src.disassembly.ghidra_backend import GhidraBackend

# Registry of available backends — add new ones here.
BACKEND_REGISTRY: dict[str, Type[DisassemblyBackend]] = {
    "capstone": CapstoneBackend,
    "ghidra": GhidraBackend,
}


def get_backend(name: str = "auto") -> DisassemblyBackend:
    """Get a disassembly backend by name.

    Args:
        name: Backend name or 'auto' to pick the best available.

    Returns:
        An initialized backend instance.

    Raises:
        ValueError: If the named backend is not found.
        RuntimeError: If 'auto' mode and no backend is available.
    """
    if name == "auto":
        # Prefer Ghidra for precision, fall back to Capstone for speed
        for backend_name in ("ghidra", "capstone"):
            cls = BACKEND_REGISTRY.get(backend_name)
            if cls:
                instance = cls()
                if instance.is_available():
                    return instance
        raise RuntimeError("No disassembly backend available")

    cls = BACKEND_REGISTRY.get(name)
    if not cls:
        raise ValueError(f"Unknown backend: {name}. Available: {list(BACKEND_REGISTRY.keys())}")
    return cls()
