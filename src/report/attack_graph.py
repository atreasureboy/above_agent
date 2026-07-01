"""
DriverScope -- Attack Path Visualization.

Generates DOT/Graphviz representations of:
1. Single-driver attack paths: User input -> dangerous API -> vulnerability
2. Multi-driver attack chains: Driver A -> (communication) -> Driver B -> exploit
3. Dynamic validation overlay: static paths + crash confirmation

Output formats: DOT, HTML+SVG (via Graphviz rendering)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models import Finding, FindingCategory, Sample, Severity


@dataclass
class AttackNode:
    """A node in the attack path graph."""
    node_id: str
    label: str
    node_type: str  # "entry", "primitive", "sink", "crash", "driver"
    severity: str = "info"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    """An edge in the attack path graph."""
    source: str
    target: str
    label: str = ""
    edge_type: str = "flow"  # "flow", "call", "exploit", "communication"
    style: str = "solid"


@dataclass
class AttackGraph:
    """A complete attack path visualization."""
    name: str
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)

    def add_node(self, node_id: str, label: str, node_type: str,
                 severity: str = "info", details: dict | None = None) -> None:
        self.nodes.append(AttackNode(
            node_id=node_id, label=label, node_type=node_type,
            severity=severity, details=details or {},
        ))

    def add_edge(self, source: str, target: str, label: str = "",
                 edge_type: str = "flow", style: str = "solid") -> None:
        self.edges.append(AttackEdge(
            source=source, target=target, label=label,
            edge_type=edge_type, style=style,
        ))


SEVERITY_COLORS = {
    "critical": "#d32f2f",
    "high": "#f44336",
    "medium": "#ff9800",
    "low": "#4caf50",
    "info": "#2196f3",
}

NODE_SHAPES = {
    "entry": "ellipse",
    "primitive": "diamond",
    "sink": "box",
    "crash": "doubleoctagon",
    "driver": "cylinder",
    "communication": "hexagon",
}

EDGE_COLORS = {
    "flow": "#666666",
    "call": "#1976d2",
    "exploit": "#d32f2f",
    "communication": "#7b1fa2",
}


def build_attack_graph_from_findings(
    findings: list[Finding],
    sample: Sample | None = None,
) -> AttackGraph:
    """Build an attack path graph from analysis findings.

    Maps finding categories to attack path nodes and creates edges
    based on data flow relationships.
    """
    driver_name = sample.name if sample else "unknown"
    graph = AttackGraph(name=f"Attack Path: {driver_name}")

    # Root node: driver entry point
    graph.add_node(
        node_id="root",
        label=f"{driver_name}\n(Entry Point)",
        node_type="entry",
        severity="info",
    )

    # Group findings by function address for path construction
    func_findings: dict[int, list[Finding]] = {}
    for f in findings:
        addr = f.function_address
        if addr:
            func_findings.setdefault(addr, []).append(f)

    # Build nodes from findings
    prev_node = "root"
    for addr, addr_findings in sorted(func_findings.items()):
        func_id = f"func_{addr:X}"
        severity = max(
            (f.severity.value for f in addr_findings),
            key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0),
        )

        # Determine node type from category
        categories = {f.category for f in addr_findings}
        if any(c in categories for c in [
            FindingCategory.ARBITRARY_MEMORY_MAP,
            FindingCategory.MSR_ACCESS,
            FindingCategory.PHYSICAL_MEMORY_ACCESS,
            FindingCategory.KERNEL_RW_PRIMITIVE,
        ]):
            node_type = "primitive"
        elif any(c in categories for c in [
            FindingCategory.UNVALIDATED_USER_INPUT,
            FindingCategory.MISSING_SIZE_CHECK,
            FindingCategory.MISSING_PRIVILEGE_CHECK,
        ]):
            node_type = "sink"
        else:
            node_type = "primitive"

        api_names = ", ".join(f.api_name for f in addr_findings if f.api_name)
        graph.add_node(
            node_id=func_id,
            label=f"sub_{addr:X}\n{api_names}" if api_names else f"sub_{addr:X}",
            node_type=node_type,
            severity=severity,
            details={"categories": [c.value for c in categories]},
        )

        graph.add_edge(
            source=prev_node,
            target=func_id,
            label=f"{len(addr_findings)} findings",
            edge_type="flow",
        )
        prev_node = func_id

    # Add crash node if crash findings exist
    crash_findings = [
        f for f in findings
        if f.category == FindingCategory.DYNAMIC_CRASH_CONFIRMED
    ]
    if crash_findings:
        graph.add_node(
            node_id="crash",
            label=f"CRASH CONFIRMED\n{len(crash_findings)} crash(es)",
            node_type="crash",
            severity="critical",
        )
        graph.add_edge(
            source=prev_node,
            target="crash",
            label="crashes system",
            edge_type="exploit",
            style="bold",
        )

    return graph


def build_cross_driver_graph(
    samples: list[Sample],
    correlations: list[Finding],
) -> AttackGraph:
    """Build a cross-driver attack chain graph."""
    graph = AttackGraph(name="Cross-Driver Attack Chain")

    # Add driver nodes
    for sample in samples:
        risk = sample.risk_score
        graph.add_node(
            node_id=sample.name,
            label=f"{sample.name}\nRisk: {risk:.1f}",
            node_type="driver",
            severity=score_to_severity(risk),
            details={"risk_score": risk},
        )

    # Add communication edges from correlations
    for f in correlations:
        if f.category in (
            FindingCategory.CROSS_DRIVER_ALPC,
            FindingCategory.CROSS_DRIVER_NAMED_PIPE,
            FindingCategory.CROSS_DRIVER_SHARED_DEVICE,
            FindingCategory.CROSS_DRIVER_ATTACK_CHAIN,
        ):
            drivers = f.context.get("drivers", [])
            if len(drivers) >= 2:
                edge_type = "communication"
                if f.category == FindingCategory.CROSS_DRIVER_ATTACK_CHAIN:
                    edge_type = "exploit"
                for i in range(len(drivers) - 1):
                    graph.add_edge(
                        source=drivers[i],
                        target=drivers[i + 1],
                        label=f.category.value,
                        edge_type=edge_type,
                    )

    return graph


def score_to_severity(score: float) -> str:
    """Map risk score to severity string."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"


def graph_to_dot(graph: AttackGraph) -> str:
    """Export attack graph as DOT/Graphviz format."""
    lines = [
        f'digraph "{graph.name}" {{',
        "  rankdir=TB;",
        "  node [fontname=\"Segoe UI\", fontsize=10];",
        "  edge [fontname=\"Segoe UI\", fontsize=8];",
        "",
    ]

    # Nodes
    for node in graph.nodes:
        shape = NODE_SHAPES.get(node.node_type, "box")
        color = SEVERITY_COLORS.get(node.severity, "#666666")
        label = node.label.replace('"', "'")
        lines.append(
            f'  "{node.node_id}" [shape={shape}, style=filled, '
            f'fillcolor="{color}", fontcolor=white, label="{label}"];'
        )

    lines.append("")

    # Edges
    for edge in graph.edges:
        color = EDGE_COLORS.get(edge.edge_type, "#666666")
        label = edge.label.replace('"', "'")
        style = edge.style
        lines.append(
            f'  "{edge.source}" -> "{edge.target}" '
            f'[color={color}, label="{label}", style={style}];'
        )

    lines.append("}")
    return "\n".join(lines)


def export_attack_graph(
    graph: AttackGraph,
    output_path: Path,
) -> Path:
    """Export attack graph to DOT file.

    Args:
        graph: The AttackGraph to export.
        output_path: Output .dot file path.

    Returns:
        The output path.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    dot = graph_to_dot(graph)
    output_path.write_text(dot, encoding="utf-8")
    return output_path
