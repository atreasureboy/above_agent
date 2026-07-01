"""Tests for protocol_analyzer.py."""

from pathlib import Path

from src.analysis.core.protocol_analyzer import (
    ProtocolAnalyzer,
    decode_ioctl,
    METHOD_BUFFERED,
    METHOD_NEITHER,
)
from src.models import Architecture, DisassemblyResult, FindingCategory, Sample


def _make_sample(name: str, ioctl_codes: list[int]) -> Sample:
    ir = DisassemblyResult(
        sample_path=Path(name),
        backend="capstone",
        ioctl_codes=ioctl_codes,
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


class TestDecodeIoctl:
    def test_decode_standard_ioctl(self):
        # IOCTL_CTL_CODE(0x22, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
        # = (0x22 << 16) | (0 << 14) | (0x800 << 2) | 0
        code = (0x22 << 16) | (0x800 << 2) | METHOD_BUFFERED
        decoded = decode_ioctl(code)
        assert decoded["device_type"] == "0x22"
        assert decoded["function"] == 0x800
        assert decoded["method"] == "METHOD_BUFFERED"
        assert decoded["access"] == "FILE_ANY_ACCESS"

    def test_decode_method_neither(self):
        code = (0x22 << 16) | (0x900 << 2) | METHOD_NEITHER
        decoded = decode_ioctl(code)
        assert decoded["method"] == "METHOD_NEITHER"

    def test_decode_raw_field(self):
        code = 0x22E004
        decoded = decode_ioctl(code)
        assert decoded["raw"] == "0x22e004"


class TestProtocolAnalyzer:
    def setup_method(self):
        self.analyzer = ProtocolAnalyzer()

    def test_no_findings_for_single_driver(self):
        s = _make_sample("a.sys", ioctl_codes=[0x22E004])
        findings = self.analyzer.analyze([s])
        assert len(findings) == 0

    def test_shared_protocol_detection(self):
        # Two drivers with same device_type + function
        code = (0x22 << 16) | (0x800 << 2) | METHOD_BUFFERED
        s1 = _make_sample("a.sys", ioctl_codes=[code])
        s2 = _make_sample("b.sys", ioctl_codes=[code])
        findings = self.analyzer.analyze([s1, s2])

        shared = [f for f in findings if f.category == FindingCategory.SHARED_IOCTL_PROTOCOL]
        assert len(shared) >= 1

    def test_ioctl_collision_detection(self):
        # Exact same IOCTL code in two drivers
        code = 0x22E004
        s1 = _make_sample("a.sys", ioctl_codes=[code])
        s2 = _make_sample("b.sys", ioctl_codes=[code])
        findings = self.analyzer.analyze([s1, s2])

        collisions = [f for f in findings if f.category == FindingCategory.CROSS_DRIVER_ATTACK_CHAIN]
        assert len(collisions) >= 1

    def test_no_findings_for_different_ioctls(self):
        s1 = _make_sample("a.sys", ioctl_codes=[0x22E004])
        s2 = _make_sample("b.sys", ioctl_codes=[0x22E008])
        findings = self.analyzer.analyze([s1, s2])
        assert len(findings) == 0

    def test_build_protocol_groups(self):
        code1 = (0x22 << 16) | (0x800 << 2) | METHOD_BUFFERED
        code2 = (0x22 << 16) | (0x801 << 2) | METHOD_BUFFERED
        s1 = _make_sample("a.sys", ioctl_codes=[code1])
        s2 = _make_sample("b.sys", ioctl_codes=[code2])
        groups = self.analyzer.build_protocol_groups([s1, s2])
        assert len(groups) >= 1
        assert groups[0].device_type == "0x22"
