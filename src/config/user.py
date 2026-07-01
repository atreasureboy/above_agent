"""DEVOPS_driver — User configuration.

Supports ~/.devops_driver/config.json for overriding defaults.

Configurable:
  - DriverScope: backend, timeout, workers, cache, funnel, analyzers
  - OVOIDA: api_url, api_key, model, max_iter, output_mode
  - Pipeline: risk_threshold, max_deep_targets, report_formats
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_DEFAULT_CONFIG_PATH = Path.home() / ".devops_driver" / "config.json"

_SCHEMA: dict[str, Any] = {
    # DriverScope
    "backend": "capstone",
    "timeout": 30,
    "workers": 0,
    "cache": True,
    "funnel": True,
    "enabled_analyzers": [],
    "disabled_analyzers": [],
    "category_weights": {},
    "dangerous_api_weights": {},
    # OVOIDA
    "ov_api_url": "",
    "ov_api_key": "",
    "ov_model": "",
    "ov_max_iter": 30,
    "ov_output_mode": "pseudocode",
    # Pipeline
    "risk_threshold": 5.0,
    "max_deep_targets": 5,
    "report_formats": ["json", "markdown"],
}


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load user configuration from JSON file."""
    config_path = path or _DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return dict(_SCHEMA)

    try:
        user = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return dict(_SCHEMA)

    merged = dict(_SCHEMA)
    for key in _SCHEMA:
        if key in user:
            merged[key] = user[key]
    return merged


def get_config_path() -> Path:
    """Return the default config file path."""
    return _DEFAULT_CONFIG_PATH


def create_default_config(path: Path | None = None) -> Path:
    """Write a default config.json and return its path."""
    config_path = path or _DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(
            {
                "backend": "capstone",
                "timeout": 30,
                "workers": 0,
                "cache": True,
                "funnel": True,
                "ov_api_url": "https://api.openai.com/v1",
                "ov_api_key": "sk-...",
                "ov_model": "gpt-4o",
                "ov_max_iter": 30,
                "ov_output_mode": "pseudocode",
                "risk_threshold": 5.0,
                "max_deep_targets": 5,
                "report_formats": ["json", "markdown"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return config_path
