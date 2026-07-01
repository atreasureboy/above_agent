"""Tests for LOLDrivers provider matching logic."""

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


def test_import_loldrivers_provider():
    """Verify LOLDrivers provider can be imported."""
    from src.intel.loldrivers import LOLDriversProvider
    assert LOLDriversProvider is not None


def test_import_base_classes():
    """Verify base classes can be imported."""
    from src.intel.base import ThreatIntelProvider, MatchResult
    assert ThreatIntelProvider is not None
    assert MatchResult is not None


def test_loldrivers_init_creates_db():
    """Verify provider creates SQLite cache on init."""
    from src.intel.loldrivers import LOLDriversProvider

    with tempfile.TemporaryDirectory() as tmpdir:
        provider = LOLDriversProvider(cache_dir=Path(tmpdir))
        assert provider.db_path.exists()
        assert provider.name == "loldrivers"


def test_loldrivers_refresh_populates_db():
    """Verify refresh inserts data from mocked API response."""
    from src.intel.loldrivers import LOLDriversProvider

    mock_data = [
        {
            "Id": "test-driver-1",
            "Tags": ["vulnerable_driver", "T1068"],
            "MitreID": "T1068",
            "Category": "vulnerable",
            "Created": "2024-01-01",
            "KnownVulnerableSamples": [
                {
                    "SHA256": "a" * 64,
                    "Filename": "test.sys",
                    "Company": "Test Corp",
                }
            ],
        }
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("src.intel.loldrivers.LOLDriversProvider._fetch_remote", return_value=mock_data):
            provider = LOLDriversProvider(cache_dir=Path(tmpdir))
            count = provider.refresh(force=True)

        assert count == 1
        assert provider.is_loaded()


def test_loldrivers_sha256_match():
    """Verify exact SHA256 match returns confidence 1.0."""
    from src.intel.loldrivers import LOLDriversProvider

    mock_data = [
        {
            "Id": "driver-abc",
            "Tags": ["vulnerable_driver"],
            "MitreID": "T1068",
            "Category": "vulnerable",
            "Created": "2024-01-01",
            "KnownVulnerableSamples": [
                {
                    "SHA256": "abcdef1234567890" * 4,
                    "Filename": "evil.sys",
                    "Company": "Evil Corp",
                }
            ],
        }
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("src.intel.loldrivers.LOLDriversProvider._fetch_remote", return_value=mock_data):
            provider = LOLDriversProvider(cache_dir=Path(tmpdir))
            provider.refresh(force=True)

        result = provider.match(sha256="abcdef1234567890" * 4)
        assert result is not None
        assert result.confidence == 1.0
        assert result.source == "loldrivers"
        assert result.driver_id == "driver-abc"
        assert result.match_reason == "sha256_match"


def test_loldrivers_no_match():
    """Verify unknown hash returns None."""
    from src.intel.loldrivers import LOLDriversProvider

    mock_data = [
        {
            "Id": "driver-xyz",
            "Tags": [],
            "MitreID": "",
            "Category": "vulnerable",
            "Created": "2024-01-01",
            "KnownVulnerableSamples": [
                {
                    "SHA256": "1" * 64,
                    "Filename": "known.sys",
                    "Company": "Known Corp",
                }
            ],
        }
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("src.intel.loldrivers.LOLDriversProvider._fetch_remote", return_value=mock_data):
            provider = LOLDriversProvider(cache_dir=Path(tmpdir))
            provider.refresh(force=True)

        result = provider.match(sha256="2" * 64)
        assert result is None


def test_loldrivers_stats():
    """Verify stats returns correct counts."""
    from src.intel.loldrivers import LOLDriversProvider

    mock_data = [
        {
            "Id": "d1",
            "Tags": [],
            "MitreID": "",
            "Category": "vulnerable",
            "Created": "2024-01-01",
            "KnownVulnerableSamples": [
                {"SHA256": "a" * 64, "Filename": "a.sys", "Company": "A"},
                {"SHA256": "b" * 64, "Filename": "b.sys", "Company": "B"},
            ],
        }
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("src.intel.loldrivers.LOLDriversProvider._fetch_remote", return_value=mock_data):
            provider = LOLDriversProvider(cache_dir=Path(tmpdir))
            provider.refresh(force=True)

        stats = provider.stats()
        assert stats["loaded"] is True
        assert stats["total_entries"] == 2
        assert stats["unique_sha256"] == 2


def test_match_result_dataclass():
    """Verify MatchResult dataclass fields."""
    from src.intel.base import MatchResult

    result = MatchResult(
        source="loldrivers",
        driver_id="test-123",
        confidence=1.0,
        tags=["vulnerable_driver"],
        details={"key": "value"},
        match_reason="sha256_match",
    )

    assert result.source == "loldrivers"
    assert result.confidence == 1.0
    assert "vulnerable_driver" in result.tags
    assert result.details == {"key": "value"}
