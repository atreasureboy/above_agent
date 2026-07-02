"""
DriverScope — CAPE Sandbox Bridge.

Integrates with CAPE (Configurable Automated Packer Environment) sandbox
for automated unpacking and behavioral analysis.

CAPE is the most advanced open-source malware sandbox. It provides:
- Automatic unpacking (multiple unpacker modules)
- Behavioral API monitoring
- Network traffic capture
- Memory dump collection
- MITRE ATT&CK mapping

Requirements:
    - CAPE running locally or on a remote server
    - pip install requests
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CAPEBridge:
    """Bridge to CAPE Sandbox API for automated unpacking."""

    def __init__(self, cape_url: str = "http://localhost:8090"):
        """Initialize the CAPE bridge.

        Args:
            cape_url: Base URL of the CAPE web API.
        """
        self.api_url = cape_url.rstrip("/")

    def is_available(self) -> bool:
        """Check if CAPE is reachable."""
        try:
            import requests
            resp = requests.get(f"{self.api_url}/api/tasks/list/", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def submit_and_unpack(
        self,
        sample_path: Path,
        output_dir: str = "",
        timeout: int = 300,
    ) -> Path | None:
        """Submit sample to CAPE and retrieve the unpacked binary.

        Args:
            sample_path: Path to the packed sample.
            output_dir: Where to save the unpacked binary.
            timeout: Max seconds to wait for analysis.

        Returns:
            Path to unpacked binary, or None on failure.
        """
        try:
            task_id = self._submit_task(sample_path)
            if not task_id:
                return None

            # Wait for completion
            report = self._wait_for_completion(task_id, timeout)
            if not report:
                return None

            # Get the unpacked binary
            return self._retrieve_unpacked(task_id, output_dir, sample_path)

        except Exception as e:
            logger.error("[cape] submit_and_unpack failed: %s", e)
            return None

    def _submit_task(self, sample_path: Path) -> str | None:
        """Submit a file analysis task to CAPE."""
        try:
            import requests

            with open(sample_path, "rb") as f:
                files = {"file": (sample_path.name, f)}
                data = {
                    "timeout": 120,
                    "options": "unpacker=yes,procmon=yes",
                    "enforce_timeout": "true",
                }
                resp = requests.post(
                    f"{self.api_url}/api/tasks/create/file",
                    files=files,
                    data=data,
                    timeout=30,
                )

            if resp.status_code == 200:
                task_id = resp.json().get("task_id")
                logger.info("[cape] Task submitted: %s", task_id)
                return str(task_id)
            else:
                logger.warning("[cape] Submit failed: %s", resp.text[:200])
                return None

        except Exception as e:
            logger.error("[cape] Submit error: %s", e)
            return None

    def _wait_for_completion(self, task_id: str, timeout: int = 300) -> dict | None:
        """Wait for CAPE task to complete."""
        try:
            import requests

            start = time.time()
            while time.time() - start < timeout:
                resp = requests.get(
                    f"{self.api_url}/api/tasks/view/{task_id}",
                    timeout=10,
                )
                if resp.status_code != 200:
                    time.sleep(5)
                    continue

                task = resp.json().get("task", {})
                status = task.get("status", "")

                if status == "reported":
                    logger.info("[cape] Task %s completed", task_id)
                    return task
                elif status in ("failed", "error"):
                    logger.warning("[cape] Task %s failed: %s", task_id, status)
                    return None

                time.sleep(5)

            logger.warning("[cape] Task %s timed out", task_id)
            return None

        except Exception as e:
            logger.error("[cape] Wait error: %s", e)
            return None

    def _retrieve_unpacked(
        self,
        task_id: str,
        output_dir: str,
        original_path: Path,
    ) -> Path | None:
        """Retrieve the unpacked binary from CAPE results."""
        try:
            import requests

            # Get the "dropped" files (CAPE's unpacked output)
            resp = requests.get(
                f"{self.api_url}/api/tasks/get/dropped/{task_id}",
                timeout=30,
            )

            if resp.status_code != 200:
                return None

            dropped = resp.json()
            if not dropped:
                return None

            # Get the first dropped file (usually the unpacked binary)
            for item in dropped:
                sha256 = item.get("sha256", "")
                if not sha256:
                    continue

                # Download the file
                dl_resp = requests.get(
                    f"{self.api_url}/api/files/get/{sha256}",
                    timeout=60,
                )
                if dl_resp.status_code != 200:
                    continue

                # Save to output
                if output_dir:
                    out_path = Path(output_dir) / f"{original_path.stem}_cape_unpacked{original_path.suffix}"
                    Path(output_dir).mkdir(parents=True, exist_ok=True)
                else:
                    import tempfile
                    out_path = Path(tempfile.mkdtemp()) / f"{original_path.stem}_cape_unpacked{original_path.suffix}"

                out_path.write_bytes(dl_resp.content)
                logger.info("[cape] Unpacked binary saved: %s", out_path)
                return out_path

            return None

        except Exception as e:
            logger.warning("[cape] Retrieve error: %s", e)
            return None

    def get_api_trace(self, task_id: str) -> list[dict]:
        """Get the API call trace from CAPE analysis."""
        try:
            import requests

            resp = requests.get(
                f"{self.api_url}/api/tasks/get/report/{task_id}",
                timeout=30,
            )
            if resp.status_code != 200:
                return []

            report = resp.json()
            behavior = report.get("behavior", {})
            processes = behavior.get("processes", [])

            api_calls = []
            for proc in processes:
                for call in proc.get("calls", []):
                    api_calls.append({
                        "api": call.get("api", ""),
                        "category": call.get("category", ""),
                        "arguments": call.get("arguments", {}),
                        "return": call.get("return", ""),
                        "timestamp": call.get("timestamp", ""),
                    })

            return api_calls

        except Exception as e:
            logger.warning("[cape] API trace error: %s", e)
            return []
