"""Analysis result cache — SHA256-based SQLite cache for completed analyses.

Cache location: ~/.driverscope/cache/analysis.db
TTL: 7 days (configurable via DRIVERSCOPE_CACHE_TTL env var).
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path.home() / ".driverscope" / "cache"
DEFAULT_TTL_SECONDS = 7 * 24 * 3600  # 7 days


class AnalysisCache:
    """SQLite-based analysis result cache."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "analysis.db"
        self.ttl = ttl_seconds or int(
            os.environ.get("DRIVERSCOPE_CACHE_TTL", str(DEFAULT_TTL_SECONDS))
        )
        self._init_db()

    def _init_db(self) -> None:
        """Create SQLite table if it doesn't exist."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    sha256 TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    version TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    cached_at REAL NOT NULL,
                    PRIMARY KEY (sha256, backend, version)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cached_at ON analyses(cached_at)")
            conn.commit()
        finally:
            conn.close()

    def get(self, sha256: str, backend: str, version: str) -> dict[str, Any] | None:
        """Get cached analysis result, or None if not found or expired."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            cur = conn.execute(
                "SELECT result_json, cached_at FROM analyses "
                "WHERE sha256 = ? AND backend = ? AND version = ?",
                (sha256.lower(), backend, version),
            )
            row = cur.fetchone()
            if row:
                result_json, cached_at = row
                if (time.time() - cached_at) < self.ttl:
                    return json.loads(result_json)
                # Expired — delete
                conn.execute(
                    "DELETE FROM analyses WHERE sha256 = ? AND backend = ? AND version = ?",
                    (sha256.lower(), backend, version),
                )
                conn.commit()
        finally:
            conn.close()
        return None

    def put(self, sha256: str, backend: str, version: str, result: dict[str, Any]) -> None:
        """Cache an analysis result."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO analyses "
                "(sha256, backend, version, result_json, cached_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (sha256.lower(), backend, version, json.dumps(result), time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    def clear_expired(self) -> int:
        """Delete expired entries. Returns count of deleted rows."""
        cutoff = time.time() - self.ttl
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            cur = conn.execute(
                "DELETE FROM analyses WHERE cached_at < ?", (cutoff,)
            )
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    def stats(self) -> dict:
        """Return cache statistics."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            cur = conn.execute("SELECT COUNT(*) FROM analyses")
            total = cur.fetchone()[0]
            if total == 0:
                return {"total_entries": 0, "size_kb": 0}
            cur = conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE cached_at >= ?",
                (time.time() - self.ttl,)
            )
            valid = cur.fetchone()[0]
            size_bytes = self.db_path.stat().st_size
        finally:
            conn.close()
        return {
            "total_entries": total,
            "valid_entries": valid,
            "size_kb": round(size_bytes / 1024, 1),
        }
