"""Tests for user configuration — Phase 4."""

import json
import tempfile
from pathlib import Path

from src.config.user import load_config, get_config_path, create_default_config


def _write_temp_config(data: dict) -> Path:
    """Write data to a temp JSON file and return the path."""
    tmp_dir = Path(tempfile.gettempdir())
    import os
    fd, path = tempfile.mkstemp(suffix=".json", dir=tmp_dir)
    try:
        os.write(fd, json.dumps(data).encode("utf-8"))
    finally:
        os.close(fd)
    return Path(path)


class TestUserConfig:
    def test_default_config_returns_all_keys(self):
        cfg = load_config()
        assert "backend" in cfg
        assert "timeout" in cfg
        assert "workers" in cfg
        assert "cache" in cfg
        assert "funnel" in cfg
        assert "enabled_analyzers" in cfg
        assert "disabled_analyzers" in cfg
        assert "category_weights" in cfg
        assert "dangerous_api_weights" in cfg

    def test_default_values(self):
        cfg = load_config()
        assert cfg["backend"] == "capstone"
        assert cfg["timeout"] == 30
        assert cfg["workers"] == 0
        assert cfg["cache"] is True
        assert cfg["funnel"] is True

    def test_loads_user_config(self):
        path = _write_temp_config({
            "backend": "ghidra",
            "timeout": 60,
            "workers": 4,
            "cache": False,
        })
        try:
            cfg = load_config(path)
        finally:
            path.unlink(missing_ok=True)
        assert cfg["backend"] == "ghidra"
        assert cfg["timeout"] == 60
        assert cfg["workers"] == 4
        assert cfg["cache"] is False

    def test_invalid_json_returns_defaults(self):
        tmp_dir = Path(tempfile.gettempdir())
        import os
        fd, path_str = tempfile.mkstemp(suffix=".json", dir=tmp_dir)
        os.write(fd, b"{invalid json")
        os.close(fd)
        try:
            cfg = load_config(Path(path_str))
        finally:
            Path(path_str).unlink(missing_ok=True)
        assert cfg["backend"] == "capstone"

    def test_nonexistent_file_returns_defaults(self):
        cfg = load_config(Path("/nonexistent/path/config.json"))
        assert cfg["backend"] == "capstone"

    def test_create_default_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            result = create_default_config(path)
            assert result == path
            assert path.exists()
            data = json.loads(path.read_text(encoding="utf-8"))
            assert data["backend"] == "capstone"

    def test_partial_user_config_preserves_defaults(self):
        path = _write_temp_config({"timeout": 120})
        try:
            cfg = load_config(path)
        finally:
            path.unlink(missing_ok=True)
        assert cfg["timeout"] == 120
        assert cfg["backend"] == "capstone"  # Default preserved

    def test_get_config_path(self):
        path = get_config_path()
        assert path.name == "config.json"
        assert ".devops_driver" in str(path)
