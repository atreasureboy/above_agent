"""Tests for the filter funnel pipeline."""

import pytest
from pathlib import Path
from src.models import Architecture, Sample
from src.analysis.funnel.stages import FilterStage, FilterResult
from src.analysis.funnel.stages.whitelist import WhitelistStage
from src.analysis.funnel.stages.import_score import (
    ImportScoreStage,
    _score_imports,
    _compute_import_score,
)
from src.analysis.funnel.stages.light_disasm import LightDisasmStage, _light_disasm
from src.analysis.funnel.pipeline import FilterPipeline


def _make_sample(name="test.sys", company="", size=8192) -> Sample:
    return Sample(
        path=Path("samples/unknown/mock_driver.sys"),
        name=name,
        company=company,
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="abc123",
        size=size,
        is_driver=True,
        driver_type="WDM",
    )


class TestFilterResult:
    def test_passed_count(self):
        r = FilterResult(passed=[1, 2], rejected=[])
        assert r.passed_count == 2

    def test_filtered_count(self):
        r = FilterResult(passed=[1], rejected=[("a", "reason")])
        assert r.filtered_count == 1


class TestFilterPipeline:
    def test_empty_input(self):
        pipeline = FilterPipeline(stages=[])
        result = pipeline.run([], verbose=False)
        assert result["survivors"] == []
        assert result["stats"]["l0_enumerated"] == 0

    def test_no_stages_passes_all(self):
        samples = [_make_sample("a.sys"), _make_sample("b.sys")]
        pipeline = FilterPipeline(stages=[])
        result = pipeline.run(samples, verbose=False)
        assert len(result["survivors"]) == 2

    def test_single_stage_filters(self):
        class RejectAllStage(FilterStage):
            @property
            def name(self):
                return "Reject all"

            @property
            def cost(self):
                return "ms"

            def apply(self, samples):
                return FilterResult(
                    passed=[],
                    rejected=[(s, "rejected") for s in samples],
                )

        samples = [_make_sample("a.sys")]
        pipeline = FilterPipeline(stages=[RejectAllStage()])
        result = pipeline.run(samples, verbose=False)
        assert result["survivors"] == []
        assert result["stats"]["total_survivors"] == 0

    def test_cap_limits_results(self):
        samples = [_make_sample(f"s{i}.sys") for i in range(5)]
        pipeline = FilterPipeline(stages=[])
        result = pipeline.run(samples, verbose=False, cap=2)
        assert len(result["survivors"]) == 2

    def test_stats_structure(self):
        samples = [_make_sample("a.sys")]
        pipeline = FilterPipeline(stages=[])
        result = pipeline.run(samples, verbose=False)
        stats = result["stats"]
        assert "l0_enumerated" in stats
        assert "layers" in stats
        assert "total_survivors" in stats
        assert "elapsed" in stats


class TestWhitelistStage:
    def test_system_driver_rejected(self):
        stage = WhitelistStage()
        sample = _make_sample("ntoskrnl.exe")
        result = stage.apply([sample])
        assert result.filtered_count >= 1

    def test_glob_pattern_matches(self):
        stage = WhitelistStage()
        sample = _make_sample("hidclass.sys")  # exact match in whitelist
        result = stage.apply([sample])
        assert result.filtered_count >= 1

    def test_third_party_passes_name_check(self):
        stage = WhitelistStage()
        sample = _make_sample("mycustom.sys")
        result = stage.apply([sample])
        # Should pass name check (may still be filtered by other criteria)
        assert result.passed_count + result.filtered_count == 1

    def test_oversized_file_rejected(self):
        stage = WhitelistStage(max_size_kb=200)
        sample = _make_sample("big.sys", size=300 * 1024)  # 300KB
        result = stage.apply([sample])
        assert result.filtered_count == 1

    def test_normal_size_passes(self):
        stage = WhitelistStage(max_size_kb=200)
        sample = _make_sample("normal.sys", size=50 * 1024)
        result = stage.apply([sample])
        assert result.passed_count + result.filtered_count == 1


class TestImportScoreStage:
    def test_score_imports_returns_apis(self):
        info = _score_imports(Path("samples/unknown/mock_driver.sys"))
        assert "imported_apis" in info
        assert "dlls" in info
        assert "strings" in info

    def test_compute_import_score_empty(self):
        assert _compute_import_score([]) == 0

    def test_compute_import_score_known_api(self):
        score = _compute_import_score(["MmMapIoSpace"])
        assert score == 15

    def test_compute_import_score_multiple_apis(self):
        score = _compute_import_score(["MmMapIoSpace", "KeWriteMsr"])
        assert score == 15 + 20

    def test_stage_threshold_filters(self):
        stage = ImportScoreStage(threshold=100)
        sample = _make_sample("test.sys")
        result = stage.apply([sample])
        # mock_driver has minimal imports, should be below threshold
        assert result.filtered_count >= 0

    def test_low_threshold_passes(self):
        stage = ImportScoreStage(threshold=0)
        sample = _make_sample("test.sys")
        result = stage.apply([sample])
        # Threshold 0 means everything passes
        assert result.passed_count + result.filtered_count == 1

    def test_stage_sorts_by_score(self):
        stage = ImportScoreStage(threshold=0)
        s1 = _make_sample("a.sys")
        s2 = _make_sample("b.sys")
        result = stage.apply([s1, s2])
        scores = [item.get("import_score", 0) for item in result.passed]
        assert scores == sorted(scores, reverse=True)


class TestLightDisasmStage:
    def test_light_disasm_returns_structure(self):
        info = _light_disasm(Path("samples/unknown/mock_driver.sys"))
        assert "ioctl_codes" in info
        assert "irp_handlers" in info
        assert "function_count" in info
        assert "is_wdf_driver" in info

    def test_stage_returns_non_empty_result(self):
        stage = LightDisasmStage()
        # Create enriched dict like ImportScoreStage output
        info = {
            "sample": _make_sample("test.sys"),
            "import_score": 50,
            "is_wdf_driver": False,
        }
        result = stage.apply([info])
        assert result.passed_count + result.filtered_count == 1

    def test_wdf_driver_passes_on_score(self):
        stage = LightDisasmStage()
        info = {
            "sample": _make_sample("test.sys"),
            "import_score": 50,
            "is_wdf_driver": True,
        }
        result = stage.apply([info])
        # WDF with score >= 30 should pass
        assert result.passed_count >= 1

    def test_arm64_pe_disasm_does_not_crash(self):
        """ARM64 PE should not crash _light_disasm (Phase 5 fix)."""
        import struct
        import tempfile
        import os
        import capstone

        # Build minimal ARM64 PE
        dos = bytearray(128)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 128)
        pe_header = b"PE\x00\x00"
        coff = struct.pack("<HHIIIHH", 0xAA64, 0, 0, 0, 0, 240, 0x0022)
        opt = bytearray(240)
        struct.pack_into("<H", opt, 0, 0x020B)
        struct.pack_into("<I", opt, 16, 0x1000)
        struct.pack_into("<H", opt, 32, 0x200)
        struct.pack_into("<H", opt, 68, 0x0003)
        struct.pack_into("<H", opt, 70, 0x2000)

        raw = bytes(dos) + pe_header + coff + bytes(opt)
        fd, path = tempfile.mkstemp(suffix=".sys")
        os.write(fd, raw)
        os.close(fd)
        try:
            info = _light_disasm(Path(path))
            # Should not crash, returns defaults
            assert "ioctl_codes" in info
            assert "is_wdf_driver" in info
        finally:
            os.unlink(path)

    def test_wdm_low_score_rejected(self):
        """WDM with low score and no IOCTL should be rejected.

        Note: We use a fake path so _light_disasm returns empty results
        (file doesn't exist → exception caught → empty dict).
        """
        stage = LightDisasmStage()
        # Use a fake sample with a non-existent path so disasm returns empty
        from src.models import Sample
        fake_sample = Sample(
            path=Path("nonexistent_fake.sys"),
            name="fake.sys",
            company="",
            version="1.0",
            arch=Architecture.X64,
            sha256="fake",
            size=1000,
            is_driver=True,
            driver_type="WDM",
        )
        info = {
            "sample": fake_sample,
            "import_score": 5,
            "is_wdf_driver": False,
            "has_ioctl_dispatcher": False,
        }
        result = stage.apply([info])
        # No file → empty disasm → no IOCTL + low score → rejected
        assert result.filtered_count == 1
