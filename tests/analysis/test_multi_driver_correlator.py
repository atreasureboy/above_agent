"""Tests for multi_driver_correlator.py."""

import pytest
from pathlib import Path

from src.analysis.core.multi_driver_correlator import (
    MultiDriverCorrelator,
    DEVICE_PATH_RE,
    ALPC_PORT_RE,
    NAMED_PIPE_RE,
)
from src.models import Architecture, DisassemblyResult, FindingCategory, Sample, Severity


def _make_sample(name: str, strings: list[str], ioctl_codes: list[int] | None = None) -> Sample:
    ir = DisassemblyResult(
        sample_path=Path(name),
        backend="capstone",
        strings=strings,
        ioctl_codes=ioctl_codes or [],
    )
    return Sample(
        path=Path(name),
        name=name,
        company="TestCorp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=1024,
        is_driver=True,
        disassembly_result=ir,
    )


class TestRegexPatterns:
    def test_device_path(self):
        m = DEVICE_PATH_RE.search(r"\Device\TestDevice")
        assert m is not None

    def test_alpc_port(self):
        m = ALPC_PORT_RE.search(r"\RPC Control\TestPort")
        assert m is not None

    def test_named_pipe(self):
        m = NAMED_PIPE_RE.search(r"\\.\pipe\TestPipe")
        assert m is not None


class TestMultiDriverCorrelator:
    def setup_method(self):
        self.correlator = MultiDriverCorrelator()

    def test_no_findings_for_single_driver(self):
        sample = _make_sample("driver.sys", strings=[r"\Device\Test"])
        findings = self.correlator.analyze_cluster([sample])
        assert len(findings) == 0

    def test_shared_device_detection(self):
        shared = r"\Device\SharedDevice"
        s1 = _make_sample("driver_a.sys", strings=[shared])
        s2 = _make_sample("driver_b.sys", strings=[shared, r"\Device\Other"])
        findings = self.correlator.analyze_cluster([s1, s2])

        shared_dev = [f for f in findings if f.category == FindingCategory.CROSS_DRIVER_SHARED_DEVICE]
        assert len(shared_dev) >= 1

    def test_shared_alpc_detection(self):
        shared_port = r"\RPC Control\SharedPort"
        s1 = _make_sample("driver_a.sys", strings=[shared_port])
        s2 = _make_sample("driver_b.sys", strings=[shared_port])
        findings = self.correlator.analyze_cluster([s1, s2])

        alpc = [f for f in findings if f.category == FindingCategory.CROSS_DRIVER_ALPC]
        assert len(alpc) >= 1

    def test_shared_pipe_detection(self):
        shared_pipe = r"\\.\pipe\SharedPipe"
        s1 = _make_sample("driver_a.sys", strings=[shared_pipe])
        s2 = _make_sample("driver_b.sys", strings=[shared_pipe])
        findings = self.correlator.analyze_cluster([s1, s2])

        pipes = [f for f in findings if f.category == FindingCategory.CROSS_DRIVER_NAMED_PIPE]
        assert len(pipes) >= 1

    def test_shared_ioctl_detection(self):
        ioctl_code = 0x22E004
        s1 = _make_sample("driver_a.sys", strings=[], ioctl_codes=[ioctl_code])
        s2 = _make_sample("driver_b.sys", strings=[], ioctl_codes=[ioctl_code, 0x22E008])
        findings = self.correlator.analyze_cluster([s1, s2])

        ioctls = [f for f in findings if f.category == FindingCategory.SHARED_IOCTL_PROTOCOL]
        assert len(ioctls) >= 1

    def test_attack_chain_detection(self):
        """When multiple drivers share multiple resources, an attack chain is formed."""
        shared_dev = r"\Device\SharedDev"
        shared_port = r"\RPC Control\SharedPort"
        s1 = _make_sample("drv_a.sys", strings=[shared_dev, shared_port])
        s2 = _make_sample("drv_b.sys", strings=[shared_dev, shared_port])
        s3 = _make_sample("drv_c.sys", strings=[shared_dev])
        findings = self.correlator.analyze_cluster([s1, s2, s3])

        chains = [f for f in findings if f.category == FindingCategory.CROSS_DRIVER_ATTACK_CHAIN]
        assert len(chains) >= 1

    def test_no_findings_for_unrelated_drivers(self):
        s1 = _make_sample("driver_a.sys", strings=[r"\Device\DeviceA"])
        s2 = _make_sample("driver_b.sys", strings=[r"\Device\DeviceB"])
        findings = self.correlator.analyze_cluster([s1, s2])
        assert len(findings) == 0

    def test_build_clusters(self):
        shared = r"\Device\ClusterDevice"
        s1 = _make_sample("a.sys", strings=[shared])
        s2 = _make_sample("b.sys", strings=[shared])
        s3 = _make_sample("c.sys", strings=[r"\Device\Alone"])
        clusters = self.correlator.build_clusters([s1, s2, s3])
        assert len(clusters) >= 1
        assert "a.sys" in clusters[0].members
        assert "b.sys" in clusters[0].members
