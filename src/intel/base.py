"""Base interfaces for threat intelligence providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class MatchResult:
    """Result of a threat intel match."""
    source: str             # "loldrivers", "msft_blocklist", ...
    driver_id: str          # Provider-specific ID (LOLDrivers UUID)
    confidence: float       # 1.0 = SHA256 exact match, 0.7 = filename+company
    tags: list[str]         # ["vulnerable_driver", "T1068", ...]
    details: dict           # Raw provider data
    match_reason: str = ""  # "sha256_match", "filename_company_match", ...


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence data sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name, e.g. 'loldrivers'."""
        ...

    @abstractmethod
    def refresh(self) -> int:
        """Fetch latest data from source and update local cache.

        Returns:
            Number of entries in the local cache after refresh.
        """
        ...

    @abstractmethod
    def match(
        self,
        sha256: str,
        company: str = "",
        filename: str = "",
    ) -> MatchResult | None:
        """Check if a driver matches any known threat intel entry.

        Args:
            sha256: SHA256 hash of the driver file.
            company: Company name from PE VERSION_INFO.
            filename: Original filename of the driver.

        Returns:
            MatchResult if found, None if clean.
        """
        ...

    @abstractmethod
    def is_loaded(self) -> bool:
        """Check if the provider has data loaded (refresh has been called)."""
        ...
