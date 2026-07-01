"""Tests for attack_graph.py."""

from pathlib import Path

from src.report.attack_graph import (
    AttackGraph,
    AttackNode,
    AttackEdge,
    build_attack_graph_from_findings,
    build_cross_driver_graph,
    graph_to_dot,
    export_attack_graph,
    score_to_severity,
)
from src.models import (
    Architecture, Confidence, DisassemblyResult, Finding, FindingCategory,
    Sample, Severity,
)


def _make_sample(name: str, risk_score: float = 5.0) -> Sample:
    return Sample(
        path=Path(name),
        name=name,
        company="TestCorp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=1024,
        is_driver=True,
        risk_score=risk_score,
    )


def _make_finding(category: FindingCategory, severity: Severity,
                  func_addr: int = 0x1000, api_name: str = "") -> Finding:
    return Finding(
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        description=f"Test: {category.value}",
        function_address=func_addr,
        api_name=api_name,
    )


class TestScoreToSeverity:
    def test_critical(self):
        assert score_to_severity(9.5) == "critical"

    def test_high(self):
        assert score_to_severity(7.5) == "high"

    def test_medium(self):
        assert score_to_severity(5.0) == "medium"

    def test_low(self):
        assert score_to_severity(2.0) == "low"

    def test_none(self):
        assert score_to_severity(0.0) == "info"


class TestAttackGraph:
    def test_add_node(self):
        g = AttackGraph(name="test")
        g.add_node("n1", "Entry", "entry", "info")
        assert len(g.nodes) == 1
        assert g.nodes[0].label == "Entry"

    def test_add_edge(self):
        g = AttackGraph(name="test")
        g.add_edge("n1", "n2", "flow", "flow")
        assert len(g.edges) == 1
        assert g.edges[0].source == "n1"
        assert g.edges[0].target == "n2"

    def test_graph_to_dot(self):
        g = AttackGraph(name="test")
        g.add_node("root", "Driver", "driver", "info")
        g.add_node("crash", "CRASH", "crash", "critical")
        g.add_edge("root", "crash", "exploit", "exploit", "bold")
        dot = graph_to_dot(g)
        assert "digraph" in dot
        assert "root" in dot
        assert "crash" in dot
        assert "->" in dot
        assert "doubleoctagon" in dot


class TestBuildAttackGraphFromFindings:
    def test_basic_path(self):
        findings = [
            _make_finding(FindingCategory.IOCTL_DISPATCHER_FOUND, Severity.INFO, func_addr=0x1000),
            _make_finding(FindingCategory.ARBITRARY_MEMORY_MAP, Severity.CRITICAL, func_addr=0x2000, api_name="MmMapIoSpaceEx"),
        ]
        sample = _make_sample("test.sys")
        graph = build_attack_graph_from_findings(findings, sample)
        assert len(graph.nodes) >= 3  # root + 2 function nodes
        assert len(graph.edges) >= 2

    def test_crash_node(self):
        findings = [
            _make_finding(FindingCategory.ARBITRARY_MEMORY_MAP, Severity.CRITICAL, func_addr=0x1000),
            _make_finding(FindingCategory.DYNAMIC_CRASH_CONFIRMED, Severity.CRITICAL),
        ]
        sample = _make_sample("crash.sys")
        graph = build_attack_graph_from_findings(findings, sample)
        node_ids = [n.node_id for n in graph.nodes]
        assert "crash" in node_ids

    def test_no_findings(self):
        graph = build_attack_graph_from_findings([], _make_sample("clean.sys"))
        # Should at least have the root node
        assert len(graph.nodes) == 1
        assert graph.nodes[0].node_id == "root"


class TestBuildCrossDriverGraph:
    def test_two_drivers_with_correlation(self):
        samples = [
            _make_sample("a.sys", risk_score=8.0),
            _make_sample("b.sys", risk_score=6.0),
        ]
        correlations = [
            Finding(
                category=FindingCategory.CROSS_DRIVER_ALPC,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Shared ALPC port",
                context={"drivers": ["a.sys", "b.sys"]},
            )
        ]
        graph = build_cross_driver_graph(samples, correlations)
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        assert graph.edges[0].source == "a.sys"
        assert graph.edges[0].target == "b.sys"

    def test_attack_chain_edge(self):
        samples = [
            _make_sample("a.sys", risk_score=9.0),
            _make_sample("b.sys", risk_score=7.0),
        ]
        correlations = [
            Finding(
                category=FindingCategory.CROSS_DRIVER_ATTACK_CHAIN,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Attack chain",
                context={"drivers": ["a.sys", "b.sys"]},
            )
        ]
        graph = build_cross_driver_graph(samples, correlations)
        assert graph.edges[0].edge_type == "exploit"


class TestExportAttackGraph:
    def test_export_to_file(self, tmp_path):
        g = AttackGraph(name="test")
        g.add_node("n1", "Test", "entry")
        output = tmp_path / "graph.dot"
        result = export_attack_graph(g, output)
        assert result.exists()
        assert "digraph" in result.read_text(encoding="utf-8")
