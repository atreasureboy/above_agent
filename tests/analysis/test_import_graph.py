"""Tests for import_graph.py."""

from pathlib import Path

from src.analysis.core.import_graph import ImportGraph, ModuleNode


class TestImportGraph:
    def test_add_module(self):
        g = ImportGraph()
        node = ModuleNode(path=Path("a.exe"), name="a.exe", imports=["kernel32.dll"], exports=[])
        g.add_module(node)
        assert "a.exe" in g.nodes

    def test_build_edges(self):
        g = ImportGraph()
        g.add_module(ModuleNode(
            path=Path("app.exe"), name="app.exe",
            imports=["helper.dll"], exports=["Main"]
        ))
        g.add_module(ModuleNode(
            path=Path("helper.dll"), name="helper.dll",
            imports=[], exports=["helper.dll", "HelperFunc"]
        ))
        edges = g.build_edges()
        assert len(edges) >= 1
        assert edges[0].source == "app.exe"
        assert edges[0].target == "helper.dll"

    def test_no_edges_without_shared_imports(self):
        g = ImportGraph()
        g.add_module(ModuleNode(
            path=Path("a.exe"), name="a.exe",
            imports=["unrelated.dll"], exports=[]
        ))
        g.add_module(ModuleNode(
            path=Path("b.dll"), name="b.dll",
            imports=[], exports=["SomethingElse"]
        ))
        edges = g.build_edges()
        assert len(edges) == 0

    def test_get_dependencies(self):
        g = ImportGraph()
        g.add_module(ModuleNode(
            path=Path("a.exe"), name="a.exe",
            imports=["b.dll"], exports=[]
        ))
        g.add_module(ModuleNode(
            path=Path("b.dll"), name="b.dll",
            imports=[], exports=["b.dll"]
        ))
        g.build_edges()
        deps = g.get_dependencies("a.exe")
        assert "b.dll" in deps

    def test_get_dependents(self):
        g = ImportGraph()
        g.add_module(ModuleNode(
            path=Path("a.exe"), name="a.exe",
            imports=["b.dll"], exports=[]
        ))
        g.add_module(ModuleNode(
            path=Path("b.dll"), name="b.dll",
            imports=[], exports=["b.dll"]
        ))
        g.build_edges()
        dependents = g.get_dependents("b.dll")
        assert "a.exe" in dependents

    def test_find_bridge_modules(self):
        g = ImportGraph()
        # Module B imports from C and exports for A
        g.add_module(ModuleNode(
            path=Path("a.exe"), name="a.exe",
            imports=["b.dll"], exports=[]
        ))
        g.add_module(ModuleNode(
            path=Path("b.dll"), name="b.dll",
            imports=["c.dll"], exports=["b.dll"]
        ))
        g.add_module(ModuleNode(
            path=Path("c.dll"), name="c.dll",
            imports=[], exports=["c.dll"]
        ))
        g.build_edges()
        bridges = g.find_bridge_modules()
        assert "b.dll" in bridges

    def test_to_dot_format(self):
        g = ImportGraph()
        g.add_module(ModuleNode(
            path=Path("a.exe"), name="a.exe",
            imports=["b.dll"], exports=[]
        ))
        g.add_module(ModuleNode(
            path=Path("b.dll"), name="b.dll",
            imports=[], exports=["b.dll"]
        ))
        g.build_edges()
        dot = g.to_dot()
        assert "digraph ImportGraph" in dot
        assert "a.exe" in dot
        assert "b.dll" in dot
        assert "->" in dot

    def test_to_dict_format(self):
        g = ImportGraph()
        g.add_module(ModuleNode(
            path=Path("a.exe"), name="a.exe",
            imports=["b.dll"], exports=["Main"],
            is_driver=False, is_usermode=True,
        ))
        g.add_module(ModuleNode(
            path=Path("b.dll"), name="b.dll",
            imports=[], exports=["b.dll"],
            is_driver=False, is_usermode=True,
        ))
        g.build_edges()
        d = g.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert "bridge_modules" in d
        assert d["nodes"]["a.exe"]["is_usermode"] is True

    def test_driver_node_shape_in_dot(self):
        g = ImportGraph()
        g.add_module(ModuleNode(
            path=Path("drv.sys"), name="drv.sys",
            imports=[], exports=["DriverEntry"],
            is_driver=True,
        ))
        dot = g.to_dot()
        assert "cylinder" in dot
