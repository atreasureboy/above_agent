"""Tests for dependency_graph.py."""

from pathlib import Path

from src.analysis.core.dependency_graph import DependencyGraph, DependencyNode
from src.models import Architecture, DisassemblyResult, Sample


def _make_sample(name: str, strings: list[str] | None = None, ioctl_codes: list[int] | None = None) -> Sample:
    ir = DisassemblyResult(
        sample_path=Path(name),
        backend="capstone",
        strings=strings or [],
        ioctl_codes=ioctl_codes or [],
    )
    s = Sample(
        path=Path(name),
        name=name,
        company="TestCorp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=1024,
        is_driver=True,
        disassembly_result=ir,
        risk_score=5.0,
    )
    return s


class TestDependencyGraph:
    def test_add_driver(self):
        g = DependencyGraph()
        s = _make_sample("test.sys", strings=[r"\Device\Test"])
        node = g.add_driver(s)
        assert "test.sys" in g.nodes
        assert r"\Device\Test" in node.device_paths

    def test_build_edges_shared_device(self):
        g = DependencyGraph()
        shared = r"\Device\SharedDev"
        g.add_driver(_make_sample("a.sys", strings=[shared]))
        g.add_driver(_make_sample("b.sys", strings=[shared]))
        edges = g.build_edges()
        assert len(edges) >= 1
        assert any(e.relationship == "shared_device" for e in edges)

    def test_build_edges_shared_alpc(self):
        g = DependencyGraph()
        shared = r"\RPC Control\SharedPort"
        g.add_driver(_make_sample("a.sys", strings=[shared]))
        g.add_driver(_make_sample("b.sys", strings=[shared]))
        edges = g.build_edges()
        assert any(e.relationship == "alpc_client" for e in edges)

    def test_build_edges_shared_pipe(self):
        g = DependencyGraph()
        shared = r"\\.\pipe\SharedPipe"
        g.add_driver(_make_sample("a.sys", strings=[shared]))
        g.add_driver(_make_sample("b.sys", strings=[shared]))
        edges = g.build_edges()
        assert any(e.relationship == "pipe_client" for e in edges)

    def test_build_edges_shared_ioctl(self):
        g = DependencyGraph()
        g.add_driver(_make_sample("a.sys", ioctl_codes=[0x22E004]))
        g.add_driver(_make_sample("b.sys", ioctl_codes=[0x22E004]))
        edges = g.build_edges()
        assert any(e.relationship == "shared_ioctl" for e in edges)

    def test_no_edges_for_unrelated(self):
        g = DependencyGraph()
        g.add_driver(_make_sample("a.sys", strings=[r"\Device\A"]))
        g.add_driver(_make_sample("b.sys", strings=[r"\Device\B"]))
        edges = g.build_edges()
        assert len(edges) == 0

    def test_topological_sort(self):
        g = DependencyGraph()
        g.add_driver(_make_sample("a.sys"))
        g.add_driver(_make_sample("b.sys"))
        order = g.topological_sort()
        assert len(order) == 2
        assert set(order) == {"a.sys", "b.sys"}

    def test_to_dot_format(self):
        g = DependencyGraph()
        g.add_driver(_make_sample("a.sys", strings=[r"\Device\X"]))
        g.add_driver(_make_sample("b.sys", strings=[r"\Device\X"]))
        g.build_edges()
        dot = g.to_dot()
        assert "digraph DriverDependency" in dot
        assert "a.sys" in dot
        assert "b.sys" in dot

    def test_to_dict_format(self):
        g = DependencyGraph()
        s = _make_sample("a.sys", strings=[r"\Device\X"])
        s.risk_score = 7.5
        g.add_driver(s)
        d = g.to_dict()
        assert "nodes" in d
        assert d["nodes"]["a.sys"]["risk_score"] == 7.5
        assert "edges" in d
        assert "topological_order" in d
