"""Tests for dynamic_report.py."""

import json
from pathlib import Path

from src.report.dynamic_report import (
    generate_dynamic_report,
    generate_dynamic_json,
)


class TestDynamicReport:
    def test_generate_html_basic(self):
        results = [
            {
                "sample_name": "test.sys",
                "driver_path": "C:\\test.sys",
                "sandbox_used": True,
                "debugger_used": False,
                "poc_executed": False,
                "crash_detected": False,
                "findings_validated": 2,
                "new_findings": [],
                "system_changes": {},
                "error": "",
                "elapsed": 5.2,
            }
        ]
        html = generate_dynamic_report(results)
        assert "Dynamic Analysis Report" in html
        assert "test.sys" in html
        assert "Total Tests" in html
        assert "<table>" in html

    def test_generate_html_crash(self):
        results = [
            {
                "sample_name": "crash.sys",
                "driver_path": "C:\\crash.sys",
                "sandbox_used": True,
                "debugger_used": True,
                "poc_executed": True,
                "crash_detected": True,
                "findings_validated": 1,
                "new_findings": [{"category": "crash", "severity": "critical", "description": "BSOD"}],
                "system_changes": {"new_devices": ["DeviceX"]},
                "error": "",
                "elapsed": 30.0,
            }
        ]
        html = generate_dynamic_report(results)
        assert "CRASH" in html
        assert "critical" in html
        assert "BSOD" in html

    def test_generate_html_output_path(self, tmp_path):
        results = []
        out = tmp_path / "report.html"
        generate_dynamic_report(results, output_path=out)
        assert out.exists()
        assert "Dynamic Analysis Report" in out.read_text(encoding="utf-8")

    def test_generate_dynamic_json(self):
        results = [
            {
                "sample_name": "test.sys",
                "driver_path": "",
                "sandbox_used": False,
                "debugger_used": False,
                "poc_executed": False,
                "crash_detected": False,
                "findings_validated": 0,
                "new_findings": [],
                "system_changes": {},
                "error": "",
                "elapsed": 1.0,
            }
        ]
        json_str = generate_dynamic_json(results)
        data = json.loads(json_str)
        assert data["summary"]["total_tests"] == 1
        assert data["summary"]["crashes"] == 0
        assert len(data["results"]) == 1

    def test_json_with_multiple(self):
        results = [
            {"sample_name": "a.sys", "crash_detected": True, "poc_executed": True, "new_findings": [1], "sandbox_used": True, "debugger_used": True, "driver_path": "", "findings_validated": 0, "system_changes": {}, "error": "", "elapsed": 0},
            {"sample_name": "b.sys", "crash_detected": False, "poc_executed": False, "new_findings": [], "sandbox_used": True, "debugger_used": False, "driver_path": "", "findings_validated": 1, "system_changes": {}, "error": "", "elapsed": 0},
            {"sample_name": "c.sys", "crash_detected": True, "poc_executed": True, "new_findings": [1, 2], "sandbox_used": True, "debugger_used": True, "driver_path": "", "findings_validated": 2, "system_changes": {}, "error": "", "elapsed": 0},
        ]
        json_str = generate_dynamic_json(results)
        data = json.loads(json_str)
        assert data["summary"]["crashes"] == 2
        assert data["summary"]["poc_executed"] == 2
        assert data["summary"]["new_findings"] == 3
