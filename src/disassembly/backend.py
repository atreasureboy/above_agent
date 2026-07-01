"""
DriverScope — Disassembly backend interface.

This layer abstracts the disassembly engine so that backends
(Ghidra, IDA, radare2, Binary Ninja) can be swapped without
changing analysis code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from src.models import DisassemblyResult


class DisassemblyBackend(ABC):
    """Base class for disassembly backends.

    Implementations: GhidraBackend, IDABackend, Radare2Backend, BinjaBackend.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend name, e.g. 'ghidra', 'ida', 'radare2'."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend's dependencies are installed."""

    @abstractmethod
    def analyze(self, sample_path: Path) -> DisassemblyResult:
        """Run disassembly on a .sys file.

        Args:
            sample_path: Path to the driver .sys file.

        Returns:
            DisassemblyResult containing functions, CFGs, import map, etc.
        """

    @abstractmethod
    def get_version(self) -> str:
        """Return backend version string."""
