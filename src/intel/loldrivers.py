"""LOLDrivers threat intel provider.

Auto-fetches https://www.loldrivers.io/api/drivers.json and caches
entries in a local SQLite database for fast matching.

Cache location: ~/.driverscope/intel/loldrivers.db
TTL: 24 hours (configurable via environment variable DRIVERSCOPE_INTEL_TTL)
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.request
from pathlib import Path

from src.intel.base import MatchResult, ThreatIntelProvider

LOLDRIVERS_API = "https://www.loldrivers.io/api/drivers.json"
DEFAULT_CACHE_DIR = Path.home() / ".driverscope" / "intel"
DEFAULT_TTL_SECONDS = 24 * 3600  # 24 hours


class LOLDriversProvider(ThreatIntelProvider):
    """LOLDrivers database provider with SQLite local cache."""

    @property
    def name(self) -> str:
        return "loldrivers"

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "loldrivers.db"
        self.ttl = ttl_seconds or int(
            os.environ.get("DRIVERSCOPE_INTEL_TTL", str(DEFAULT_TTL_SECONDS))
        )
        self._init_db()

    def _init_db(self) -> None:
        """Create SQLite tables if they don't exist. Migrate old schema if needed."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            # Check if old schema (id PK) exists and needs migration
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='drivers'"
            )
            if cur.fetchone():
                # Table exists — check if it has the old schema
                cur = conn.execute("PRAGMA table_info(drivers)")
                columns = [row[1] for row in cur.fetchall()]
                if "id" in columns and "sha256" not in columns:
                    # Old schema: id was PK. Need to recreate.
                    conn.execute("DROP TABLE drivers")
                    conn.execute("DROP TABLE IF EXISTS metadata")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS drivers (
                    sha256 TEXT PRIMARY KEY,
                    driver_id TEXT NOT NULL,
                    filename TEXT,
                    company TEXT,
                    tags TEXT,
                    mitre_id TEXT,
                    category TEXT,
                    raw_json TEXT,
                    created_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_driver_id ON drivers(driver_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_filename ON drivers(filename)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_last_refresh(self) -> float:
        """Get timestamp of last successful refresh."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            cur = conn.execute(
                "SELECT value FROM metadata WHERE key = 'last_refresh'"
            )
            row = cur.fetchone()
            if row:
                try:
                    return float(row[0])
                except (ValueError, TypeError):
                    return 0.0
        finally:
            conn.close()
        return 0.0

    def _set_last_refresh(self, ts: float) -> None:
        """Set timestamp of last successful refresh."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_refresh', ?)",
                (str(ts),),
            )
            conn.commit()
        finally:
            conn.close()

    def _fetch_remote(self) -> list[dict]:
        """Fetch LOLDrivers JSON from API."""
        req = urllib.request.Request(
            LOLDRIVERS_API,
            headers={"User-Agent": "DriverScope/0.0.1"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def refresh(self, force: bool = False) -> int:
        """Fetch latest LOLDrivers data and update local cache.

        Args:
            force: Ignore TTL and always refresh.

        Returns:
            Number of entries in the local cache after refresh.
        """
        last = self._get_last_refresh()
        if not force and last > 0 and (time.time() - last) < self.ttl:
            # Cache is still valid
            conn = sqlite3.connect(self.db_path, timeout=10)
            try:
                cur = conn.execute("SELECT COUNT(*) FROM drivers")
                return cur.fetchone()[0]
            finally:
                conn.close()

        print(f"[intel] Fetching LOLDrivers from {LOLDRIVERS_API}...")
        try:
            data = self._fetch_remote()
        except Exception as e:
            print(f"[intel] Warning: Failed to fetch LOLDrivers: {e}")
            conn = sqlite3.connect(self.db_path, timeout=10)
            try:
                cur = conn.execute("SELECT COUNT(*) FROM drivers")
                count = cur.fetchone()[0]
            finally:
                conn.close()
            if count > 0:
                print(f"[intel] Using cached data ({count} entries)")
                return count
            return 0

        # Parse and insert
        entries = 0
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute("DELETE FROM drivers")  # Clear old data

            for entry in data:
                if not isinstance(entry, dict):
                    continue
                driver_id = entry.get("Id", "")
                tags = json.dumps(entry.get("Tags", []))
                mitre_id = entry.get("MitreID", "")
                category = entry.get("Category", "")
                created = entry.get("Created", "")

                # Extract all KnownVulnerableSamples
                known_samples = entry.get("KnownVulnerableSamples", [])
                if not isinstance(known_samples, list):
                    continue
                for sample in known_samples:
                    if not isinstance(sample, dict):
                        continue
                    sha256 = sample.get("SHA256", "")
                    if not sha256 or not isinstance(sha256, str):
                        continue
                    # Validate SHA256 is a proper hex string (64 chars)
                    sha256 = sha256.strip().lower()
                    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
                        continue

                    filename = sample.get("Filename", "")
                    company = sample.get("Company", "")

                    conn.execute(
                        "INSERT OR IGNORE INTO drivers "
                        "(sha256, driver_id, filename, company, tags, mitre_id, category, raw_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            sha256.lower(),
                            driver_id,
                            filename,
                            company,
                            tags,
                            mitre_id,
                            category,
                            json.dumps(sample, ensure_ascii=False),
                            created,
                        ),
                    )
                    entries += 1

            conn.commit()
            self._set_last_refresh(time.time())
        finally:
            conn.close()

        print(f"[intel] LOLDrivers cache updated: {entries} samples from {len(data)} drivers")
        return entries

    def match(
        self,
        sha256: str,
        company: str = "",
        filename: str = "",
    ) -> MatchResult | None:
        """Check if a driver matches LOLDrivers entries.

        Priority:
        1. SHA256 exact match → confidence 1.0
        2. Filename + Company match → confidence 0.7
        """
        if not self.is_loaded():
            return None

        sha256 = sha256.lower()

        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            # Check 1: SHA256 exact match
            cur = conn.execute(
                "SELECT driver_id, filename, company, tags, mitre_id, category, raw_json "
                "FROM drivers WHERE sha256 = ?",
                (sha256,),
            )
            row = cur.fetchone()
            if row:
                return MatchResult(
                    source="loldrivers",
                    driver_id=row[0],
                    confidence=1.0,
                    tags=json.loads(row[3]) if row[3] else [],
                    details={
                        "filename": row[1],
                        "company": row[2],
                        "mitre_id": row[4],
                        "category": row[5],
                    },
                    match_reason="sha256_match",
                )

            # Check 2: Filename + Company match
            if filename and company:
                cur = conn.execute(
                    "SELECT driver_id, sha256, tags, mitre_id, category, raw_json "
                    "FROM drivers WHERE LOWER(filename) = LOWER(?) AND company = ?",
                    (filename, company),
                )
                row = cur.fetchone()
                if row:
                    return MatchResult(
                        source="loldrivers",
                        driver_id=row[0],
                        confidence=0.7,
                        tags=json.loads(row[2]) if row[2] else [],
                        details={
                            "matched_sha256": row[1],
                            "mitre_id": row[3],
                            "category": row[4],
                        },
                        match_reason="filename_company_match",
                    )

            # Check 3: Filename-only match (lower confidence)
            if filename:
                cur = conn.execute(
                    "SELECT driver_id, sha256, company, tags, mitre_id, category "
                    "FROM drivers WHERE LOWER(filename) = LOWER(?)",
                    (filename,),
                )
                row = cur.fetchone()
                if row:
                    return MatchResult(
                        source="loldrivers",
                        driver_id=row[0],
                        confidence=0.5,
                        tags=json.loads(row[3]) if row[3] else [],
                        details={
                            "matched_sha256": row[1],
                            "matched_company": row[2],
                            "mitre_id": row[4],
                            "category": row[5],
                        },
                        match_reason="filename_match",
                    )
        finally:
            conn.close()

        return None

    def is_loaded(self) -> bool:
        """Check if cache has data."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            cur = conn.execute("SELECT COUNT(*) FROM drivers")
            return cur.fetchone()[0] > 0
        finally:
            conn.close()

    def stats(self) -> dict:
        """Return cache statistics."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            cur = conn.execute("SELECT COUNT(*) FROM drivers")
            count = cur.fetchone()[0]
            if count == 0:
                return {"loaded": False}
            cur = conn.execute("SELECT COUNT(DISTINCT sha256) FROM drivers")
            unique_sha256 = cur.fetchone()[0]
        finally:
            conn.close()

        return {
            "loaded": True,
            "total_entries": count,
            "unique_sha256": unique_sha256,
            "last_refresh": self._get_last_refresh(),
            "ttl_hours": self.ttl / 3600,
        }
