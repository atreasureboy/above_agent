"""DriverScope GUI — 结果展示组件（中文）。"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from collections import defaultdict

from src.gui.styles import (
    SEVERITY_COLORS, SEVERITY_BG, CARD_BG, BORDER_COLOR,
    FONT_BOLD, FONT_MONO, FONT_LABEL, FONT_VALUE,
)


class SummaryCards(tk.Frame):
    """汇总指标卡片。"""

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self._cards: dict[str, tk.Label] = {}
        self._build()

    def _build(self):
        metrics = [
            ("scanned", "已扫描", "#333"),
            ("critical", "严重", SEVERITY_COLORS["critical"]),
            ("high", "高危", SEVERITY_COLORS["high"]),
            ("medium", "中危", SEVERITY_COLORS["medium"]),
            ("avg_score", "平均分", "#0d6efd"),
        ]
        for i, (key, label, color) in enumerate(metrics):
            card = tk.Frame(self, bg=CARD_BG, relief="solid", bd=1)
            card.grid(row=0, column=i, padx=6, pady=6, sticky="nsew")
            self.columnconfigure(i, weight=1)

            tk.Label(
                card, text=label, font=FONT_LABEL, fg="#888", bg=CARD_BG
            ).pack(pady=(8, 2))
            lbl_value = tk.Label(
                card, text="—", font=FONT_VALUE, fg=color, bg=CARD_BG
            )
            lbl_value.pack(pady=(0, 8))
            self._cards[key] = lbl_value

    def update(self, scanned=0, critical=0, high=0, medium=0, avg_score=0.0):
        self._cards["scanned"].config(text=str(scanned))
        self._cards["critical"].config(text=str(critical))
        self._cards["high"].config(text=str(high))
        self._cards["medium"].config(text=str(medium))
        self._cards["avg_score"].config(text=f"{avg_score:.1f}")


class SampleTable(tk.Frame):
    """样本表格 Treeview。"""

    def __init__(self, master, on_select=None, **kw):
        super().__init__(master, **kw)
        self.on_select = on_select
        self._build()

    def _build(self):
        columns = ("name", "score", "level", "findings", "type", "arch")
        self.tree = ttk.Treeview(
            self, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "name": ("文件名", 280),
            "score": ("评分", 70),
            "level": ("等级", 80),
            "findings": ("发现数", 80),
            "type": ("类型", 100),
            "arch": ("架构", 60),
        }
        for col, (text, width) in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, minwidth=50)

        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._row_data: dict[str, dict] = {}

    def populate(self, samples: list[dict]):
        """从扫描结果填充表格。"""
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._row_data.clear()

        for i, s in enumerate(samples):
            score = s.get("risk_score", 0)
            level = self._score_level(score)
            findings = s.get("finding_count", 0)
            iid = f"s{i}"
            values = (
                s.get("name", "?"),
                f"{score:.1f}",
                self._level_cn(level),
                str(findings),
                s.get("driver_type", ""),
                s.get("arch", ""),
            )
            self.tree.insert("", "end", iid=iid, values=values)
            self._row_data[iid] = s
            tag = level.lower()
            self.tree.item(iid, tags=(tag,))

        self.tree.tag_configure("critical", foreground=SEVERITY_COLORS["critical"])
        self.tree.tag_configure("high", foreground=SEVERITY_COLORS["high"])
        self.tree.tag_configure("medium", foreground=SEVERITY_COLORS["medium"])
        self.tree.tag_configure("low", foreground=SEVERITY_COLORS["low"])

    def get_selected(self) -> dict | None:
        sel = self.tree.selection()
        if sel:
            return self._row_data.get(sel[0])
        return None

    def _on_select(self, event):
        if self.on_select:
            data = self.get_selected()
            if data:
                self.on_select(data)

    @staticmethod
    def _score_level(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score >= 1.0:
            return "LOW"
        return "INFO"

    @staticmethod
    def _level_cn(level: str) -> str:
        mapping = {
            "CRITICAL": "严重",
            "HIGH": "高危",
            "MEDIUM": "中危",
            "LOW": "低危",
            "INFO": "信息",
        }
        return mapping.get(level, level)


class FindingsView(tk.Frame):
    """发现详情展示。"""

    def __init__(self, master, **kw):
        super().__init__(master, **kw)
        self._build()

    def _build(self):
        self.text = tk.Text(
            self, wrap="word", font=FONT_MONO, state="disabled",
            bg="#fafafa", relief="flat",
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)
        self.text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for sev, color in SEVERITY_COLORS.items():
            self.text.tag_configure(sev, foreground=color, font=("Segoe UI", 9, "bold"))
        self.text.tag_configure("api", foreground="#d63384")
        self.text.tag_configure("func", foreground="#6c757d")
        self.text.tag_configure("evidence", background="#f0f0f0", font=("Consolas", 8))
        self.text.tag_configure("title", font=("Segoe UI", 11, "bold"))

    def show(self, sample_data: dict):
        """显示样本的发现详情。"""
        self.text.config(state="normal")
        self.text.delete("1.0", "end")

        name = sample_data.get("name", "?")
        score = sample_data.get("risk_score", 0)
        self.text.insert("end", f"{name}  —  评分: {score:.1f}/10\n\n", "title")

        findings = sample_data.get("findings", [])
        if not findings:
            self.text.insert("end", "未发现安全问题。\n")
            self.text.config(state="disabled")
            return

        by_sev: dict[str, list] = defaultdict(list)
        for f in findings:
            sev = f.get("severity", "info")
            by_sev[sev].append(f)

        sev_cn = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危",
            "info": "信息",
        }

        for sev in ("critical", "high", "medium", "low", "info"):
            items = by_sev.get(sev, [])
            if not items:
                continue
            self.text.insert("end", f"\n{'='*60}\n")
            self.text.insert("end", f"  {sev_cn.get(sev, sev).upper()} ({len(items)} 项)\n", sev)
            self.text.insert("end", f"{'='*60}\n\n")

            for f in items:
                desc = f.get("description", "")
                api = f.get("api_name", "")
                func_addr = f.get("function_address", 0)
                category = f.get("category", "")

                if desc:
                    self.text.insert("end", f"  [{category}] {desc}\n")
                if api:
                    self.text.insert("end", f"    API: ", "api")
                    self.text.insert("end", f"{api}\n")
                if func_addr:
                    addr = int(func_addr) if isinstance(func_addr, (int, float)) else 0
                    if addr:
                        self.text.insert("end", f"    函数: 0x{addr:X}\n", "func")

                for ev in f.get("evidence", []):
                    snippet = ev.get("snippet", "")
                    rule = ev.get("rule_id", "")
                    location = ev.get("location", "")
                    if snippet:
                        self.text.insert("end", f"    [{rule}] {location}: ", "evidence")
                        self.text.insert("end", f"{snippet}\n", "evidence")

                self.text.insert("end", "\n")

        self.text.config(state="disabled")
        self.text.see("1.0")
