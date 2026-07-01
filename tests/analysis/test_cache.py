"""Tests for analysis cache — Phase 3."""

import pytest
import time
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.analysis.cache import AnalysisCache


class TestAnalysisCache:
    def test_put_and_get(self):
        cache = AnalysisCache()
        cache.put("sha256abc", "capstone", "0.0.7", {"risk_score": 7.5, "finding_count": 3})
        result = cache.get("sha256abc", "capstone", "0.0.7")
        assert result is not None
        assert result["risk_score"] == 7.5
        assert result["finding_count"] == 3

    def test_cache_miss(self):
        cache = AnalysisCache()
        result = cache.get("nonexistent", "capstone", "0.0.7")
        assert result is None

    def test_cache_miss_wrong_backend(self):
        cache = AnalysisCache()
        cache.put("sha256xyz", "capstone", "0.0.7", {"risk_score": 5.0})
        result = cache.get("sha256xyz", "ghidra", "0.0.7")
        assert result is None

    def test_cache_miss_wrong_version(self):
        cache = AnalysisCache()
        cache.put("sha256ver", "capstone", "0.0.6", {"risk_score": 5.0})
        result = cache.get("sha256ver", "capstone", "0.0.7")
        assert result is None

    def test_clear_expired(self):
        cache = AnalysisCache()
        cache.put("sha256old", "capstone", "0.0.7", {"risk_score": 1.0})
        # Should not raise, and should not crash
        cache.clear_expired()

    def test_stats(self):
        cache = AnalysisCache()
        cache.put("sha1", "capstone", "0.0.7", {"risk_score": 1.0})
        cache.put("sha2", "capstone", "0.0.7", {"risk_score": 2.0})
        stats = cache.stats()
        assert stats["total_entries"] >= 2

    def test_overwrite_existing(self):
        cache = AnalysisCache()
        cache.put("sha_over", "capstone", "0.0.7", {"risk_score": 1.0})
        cache.put("sha_over", "capstone", "0.0.7", {"risk_score": 9.0})
        result = cache.get("sha_over", "capstone", "0.0.7")
        assert result["risk_score"] == 9.0

    def test_default_path_exists(self):
        cache = AnalysisCache()
        db_path = Path(cache.db_path)
        assert db_path.parent.exists()
