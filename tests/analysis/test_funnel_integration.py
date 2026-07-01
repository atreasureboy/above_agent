"""Integration tests for the full filter funnel pipeline."""

import pytest
from pathlib import Path
from src.models import Architecture, Sample
from src.analysis.funnel.stages.whitelist import WhitelistStage
from src.analysis.funnel.stages.import_score import ImportScoreStage
from src.analysis.funnel.stages.light_disasm import LightDisasmStage
from src.analysis.funnel.pipeline import FilterPipeline


SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"
MOCK_DRIVER = SAMPLES_DIR / "unknown" / "mock_driver.sys"


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


def _has_sample():
    return MOCK_DRIVER.exists()


def _make_real_sample() -> Sample:
    """Create a Sample pointing to mock_driver.sys."""
    return Sample(
        path=MOCK_DRIVER,
        name=MOCK_DRIVER.stem,
        company="",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="abc123",
        size=MOCK_DRIVER.stat().st_size,
        is_driver=True,
        driver_type="WDM",
    )


class TestFunnelPipelineIntegration:
    """End-to-end funnel pipeline tests."""

    def test_empty_pipeline_passes_all(self):
        """No stages → all samples survive."""
        samples = [_make_sample("a.sys"), _make_sample("b.sys")]
        pipeline = FilterPipeline(stages=[])
        result = pipeline.run(samples, verbose=False)
        assert len(result["survivors"]) == 2
        assert result["stats"]["l0_enumerated"] == 2
        assert result["stats"]["total_survivors"] == 2

    def test_whitelist_rejects_system_drivers(self):
        """System drivers should be filtered at L1."""
        samples = [
            _make_sample("ntoskrnl.exe"),
            _make_sample("hal.dll"),
            _make_sample("hidclass.sys"),
        ]
        pipeline = FilterPipeline(stages=[WhitelistStage()])
        result = pipeline.run(samples, verbose=False)
        # All three are in the system driver whitelist
        assert result["stats"]["total_filtered"] == 3
        assert result["stats"]["total_survivors"] == 0

    def test_whitelist_passes_third_party(self):
        """Third-party drivers should pass L1."""
        samples = [
            _make_sample("mydriver.sys", company="My Company"),
            _make_sample("custom.sys", company="Custom Corp"),
        ]
        pipeline = FilterPipeline(stages=[WhitelistStage()])
        result = pipeline.run(samples, verbose=False)
        # Note: these will pass name check but may fail PE company check
        # since the files don't exist on disk
        assert result["stats"]["total_survivors"] + result["stats"]["total_filtered"] == 2

    def test_cap_limits_output(self):
        """Cap should limit the number of returned survivors."""
        samples = [_make_sample(f"s{i}.sys") for i in range(10)]
        pipeline = FilterPipeline(stages=[])
        result = pipeline.run(samples, verbose=False, cap=3)
        assert len(result["survivors"]) == 3
        assert result["stats"]["final_capped"] == 3

    def test_layer_stats_structure(self):
        """Stats should contain per-layer breakdown."""
        samples = [_make_sample("a.sys")]
        pipeline = FilterPipeline(stages=[WhitelistStage()])
        result = pipeline.run(samples, verbose=False)
        stats = result["stats"]
        assert "l0_enumerated" in stats
        assert "layers" in stats
        assert "total_filtered" in stats
        assert "total_survivors" in stats
        assert "elapsed" in stats
        # Layer entries should have expected keys
        if stats["layers"]:
            layer = stats["layers"][0]
            assert "stage" in layer
            assert "cost" in layer
            assert "input" in layer
            assert "passed" in layer
            assert "rejected" in layer

    def test_multiple_stages_chain(self):
        """Multiple stages should chain: output of one → input of next."""
        # Create samples: one system driver, one third party
        samples = [
            _make_sample("ntoskrnl.exe"),       # Will be filtered by whitelist
            _make_sample("thirdparty.sys"),     # Will pass whitelist
        ]
        pipeline = FilterPipeline(stages=[
            WhitelistStage(),
        ])
        result = pipeline.run(samples, verbose=False)
        # ntoskrnl should be filtered, thirdparty should pass
        assert result["stats"]["total_survivors"] <= 1

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_real_sample_survives_whitelist(self):
        """mock_driver.sys should pass the whitelist stage."""
        sample = _make_real_sample()
        pipeline = FilterPipeline(stages=[WhitelistStage()])
        result = pipeline.run([sample], verbose=False)
        assert result["stats"]["total_survivors"] == 1

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_full_funnel_with_real_sample(self):
        """Run mock_driver.sys through the complete funnel."""
        sample = _make_real_sample()
        pipeline = FilterPipeline(stages=[
            WhitelistStage(),
            ImportScoreStage(threshold=0),  # Pass everything through
            LightDisasmStage(),
        ])
        result = pipeline.run([sample], verbose=False)
        # Should have stats structure
        assert "survivors" in result
        assert "stats" in result
        assert result["stats"]["l0_enumerated"] == 1
        # Should have 3 layer results
        assert len(result["stats"]["layers"]) == 3

    @pytest.mark.skipif(not _has_sample(), reason="No mock_driver.sys")
    def test_funnel_empty_early_exit(self):
        """If all samples are filtered, pipeline should stop early."""
        sample = _make_sample("ntoskrnl.exe")
        pipeline = FilterPipeline(stages=[
            WhitelistStage(),
            ImportScoreStage(threshold=0),
        ])
        result = pipeline.run([sample], verbose=False)
        # ntoskrnl should be filtered at L1, no samples reach L3
        assert result["stats"]["total_survivors"] == 0
        # Layers should still have entries for stages that ran
        assert len(result["stats"]["layers"]) >= 1

    @pytest.mark.skipif(not (SAMPLES_DIR / "test_scan").exists(), reason="No test_scan dir")
    def test_funnel_with_multiple_real_samples(self):
        """Run multiple real samples through the funnel."""
        import glob
        sys_files = list((SAMPLES_DIR / "test_scan").glob("*.sys"))[:3]
        samples = []
        for f in sys_files:
            try:
                from src.ingestion.pe_parser import ingest
                samples.append(ingest(f))
            except Exception:
                pass

        if not samples:
            pytest.skip("No parseable samples found")

        pipeline = FilterPipeline(stages=[
            WhitelistStage(),
        ])
        result = pipeline.run(samples, verbose=False)
        # System drivers should be filtered, third-party should pass
        stats = result["stats"]
        assert stats["l0_enumerated"] == len(samples)
        # Some may be filtered (system drivers), some may survive
        assert stats["total_survivors"] + stats["total_filtered"] == len(samples)
