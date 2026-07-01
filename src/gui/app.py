"""DriverScope GUI — Agent 聊天界面。"""

from __future__ import annotations

import json
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from src.gui.agent import AgentBrain, AgentResponse, ToolCall
from src.gui.controller import AnalysisController
from src.gui.styles import (
    BG_COLOR, CARD_BG, DANGER_BTN, LOG_BG, LOG_FG, PRIMARY_BTN, SUCCESS_COLOR,
    FONT_BOLD, FONT_MONO, FONT_MONO_SMALL, FONT_UI, FONT_VALUE,
    SEVERITY_COLORS,
    apply_styles,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_DIR = PROJECT_ROOT / "workspace_gui"


class AgentChatWindow:
    """Agent 聊天窗口。"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DriverScope — 驱动漏洞分析 Agent")
        self.root.geometry("800x700")
        self.root.minsize(600, 500)
        self.style = apply_styles(self.root)

        self.controller = AnalysisController()
        self.agent = AgentBrain()
        self._last_result: dict | None = None
        self._last_output_path: str | None = None

        # Agent 配置（设置）
        self._ov_url = ""
        self._ov_key = ""
        self._ov_model = ""
        self._backend = "capstone"
        self._score_engine = "default"
        self._threshold = 5.0
        self._use_cache = True
        self._workers = 0
        self._deep_analysis = False

        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
        self._temp_dir = WORKSPACE_DIR / "temp"
        self._temp_dir.mkdir(parents=True, exist_ok=True)

        self._build_ui()
        self._poll_queues()

        # 欢迎消息
        self._add_agent_msg(
            "你好！我是驱动漏洞分析 Agent。\n\n"
            "我能帮你：\n"
            "📂 扫描驱动文件 • 深度分析 • 完整流水线\n"
            "📊 导出报告 • 查看分析器 • 环境检查\n\n"
            "试试说：「扫描 samples/small5/」或直接告诉我你想做什么 👇"
        )

    def run(self):
        self.root.mainloop()

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _build_ui(self):
        # 顶部状态栏
        top = tk.Frame(self.root, bg="#1e1e2e", height=36)
        top.pack(side="top", fill="x")
        top.pack_propagate(False)

        tk.Label(
            top, text="🔬  DriverScope Agent",
            fg="#cdd6f4", bg="#1e1e2e", font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=12, pady=6)

        self._status_label = tk.Label(
            top, text="就绪",
            fg="#a6adc8", bg="#1e1e2e", font=FONT_MONO_SMALL,
        )
        self._status_label.pack(side="right", padx=12, pady=6)

        # 进度条（隐藏，运行时显示）
        self._progress = ttk.Progressbar(self.root, mode="indeterminate")
        self._progress.pack(fill="x")

        # 聊天区域
        chat_frame = tk.Frame(self.root, bg=BG_COLOR)
        chat_frame.pack(fill="both", expand=True)

        self.chat_canvas = tk.Canvas(chat_frame, bg=BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(chat_frame, orient="vertical", command=self.chat_canvas.yview)
        self.chat_frame_inner = tk.Frame(self.chat_canvas, bg=BG_COLOR)

        self.chat_frame_inner.bind(
            "<Configure>",
            lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        )
        self.chat_canvas.create_window((0, 0), window=self.chat_frame_inner, anchor="nw")
        self.chat_canvas.configure(yscrollcommand=scrollbar.set)

        self.chat_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 输入区域
        input_frame = tk.Frame(self.root, bg="#f0f0f0", height=56)
        input_frame.pack(side="bottom", fill="x")
        input_frame.pack_propagate(False)

        self.input_var = tk.StringVar()
        self.input_entry = tk.Entry(
            input_frame, textvariable=self.input_var,
            font=("Segoe UI", 11), bg="#fff", relief="solid", bd=1,
        )
        self.input_entry.pack(side="left", fill="x", expand=True, padx=(8, 4), pady=8)
        self.input_entry.bind("<Return>", self._on_send)

        self.send_btn = tk.Button(
            input_frame, text="发送", bg=PRIMARY_BTN, fg="white",
            font=FONT_BOLD, relief="flat", padx=16, pady=6,
            command=self._on_send,
        )
        self.send_btn.pack(side="right", padx=8, pady=8)

        self.cancel_btn = tk.Button(
            input_frame, text="取消", bg=DANGER_BTN, fg="white",
            font=FONT_BOLD, relief="flat", padx=12, pady=6,
            command=self._do_cancel, state="disabled",
        )
        self.cancel_btn.pack(side="right", padx=4, pady=8)

        # 消息气泡存储
        self._message_widgets: list[tk.Frame] = []

    # ------------------------------------------------------------------
    # 消息气泡
    # ------------------------------------------------------------------

    def _add_bubble(self, text: str, is_user: bool = True, is_log: bool = False):
        """添加消息气泡到聊天区域。"""
        frame = tk.Frame(self.chat_frame_inner, bg=BG_COLOR)
        frame.pack(fill="x", padx=12, pady=3, anchor="e" if is_user else "w")

        if is_log:
            # 日志样式
            bg = "#2d2d2d"
            fg = "#d4d4d4"
            align = "w"
            font = FONT_MONO_SMALL
            max_w = 720
            justify = "left"
        elif is_user:
            # 用户消息
            bg = "#0d6efd"
            fg = "#ffffff"
            align = "e"
            font = ("Segoe UI", 10)
            max_w = 500
            justify = "right"
        else:
            # Agent 消息
            bg = "#ffffff"
            fg = "#1e1e1e"
            align = "w"
            font = ("Segoe UI", 10)
            max_w = 600
            justify = "left"

        # 文本内容
        if is_log:
            lbl = tk.Text(
                frame, font=font, bg=bg, fg=fg, relief="flat",
                wrap="word", height=6, state="normal",
            )
            lbl.insert("1.0", text)
            lbl.config(state="disabled")
            lbl.pack(fill="x", padx=6, pady=4)
        else:
            lbl = tk.Label(
                frame, text=text, font=font, fg=fg, bg=bg,
                justify=justify, wraplength=max_w, anchor=align,
                padx=12, pady=8,
            )
            lbl.pack(fill="x")

        self._message_widgets.append(frame)

        # 自动滚动到底部
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)
        return frame

    def _add_user_msg(self, text: str):
        self._add_bubble(text, is_user=True)

    def _add_agent_msg(self, text: str):
        self._add_bubble(text, is_user=False)

    def _add_log(self, text: str) -> tk.Frame:
        return self._add_bubble(text, is_user=False, is_log=True)

    def _update_log(self, frame: tk.Frame, text: str):
        """在日志气泡中追加文本。"""
        for child in frame.winfo_children():
            if isinstance(child, tk.Text):
                child.config(state="normal")
                child.insert("end", text)
                child.see("end")
                child.config(state="disabled")
                break
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    # ------------------------------------------------------------------
    # 发送消息
    # ------------------------------------------------------------------

    def _on_send(self, event=None):
        text = self.input_var.get().strip()
        if not text:
            return
        self.input_var.set("")

        if self.controller.is_running:
            self._add_agent_msg("⏳ 当前任务正在运行中，请等待或点击「取消」。")
            return

        self._add_user_msg(text)

        # Agent 处理
        resp = self.agent.process(text)
        self._add_agent_msg(resp.reply)

        # 处理设置
        if resp.reply.startswith("SETTING:"):
            key, val = resp.reply.split(":", 1)
            self._apply_setting(key, val)
            return

        # 执行工具
        if resp.tool_call:
            self._execute_tool(resp.tool_call)

    def _apply_setting(self, key: str, val: str):
        """应用设置。"""
        settings_map = {
            "ov_url": ("ov_url", "API URL"),
            "ov_key": ("ov_key", "API Key"),
            "ov_model": ("ov_model", "模型"),
            "backend": ("_backend", "分析后端"),
            "score_engine": ("_score_engine", "评分引擎"),
        }
        if key in settings_map:
            attr, label = settings_map[key]
            if attr == "ov_url":
                self._ov_url = val
            elif attr == "ov_key":
                self._ov_key = val
            elif attr == "ov_model":
                self._ov_model = val
            elif attr == "_backend":
                self._backend = val
            elif attr == "_score_engine":
                self._score_engine = val
            self._add_agent_msg(f"✅ {label} 已设置为: {val}")
            # 更新状态栏
            backends = {"capstone": "Capstone", "ghidra": "Ghidra"}
            engines = {"default": "BYOVD", "exploitability": "利用性"}
            agent_status = "Agent ✗" if not self._ov_key else "Agent ✓"
            self._status_label.config(
                text=f"后端: {backends.get(self._backend, '?')} | "
                     f"引擎: {engines.get(self._score_engine, '?')} | "
                     f"{agent_status}"
            )

    # ------------------------------------------------------------------
    # 工具执行
    # ------------------------------------------------------------------

    def _next_output(self) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return str(self._temp_dir / f"report_{ts}.json")

    def _set_running(self, running: bool):
        if running:
            self.send_btn.config(state="disabled")
            self.cancel_btn.config(state="normal")
            self.input_entry.config(state="disabled")
            self._progress.start(10)
        else:
            self.send_btn.config(state="normal")
            self.cancel_btn.config(state="disabled")
            self.input_entry.config(state="normal")
            self.input_entry.focus_set()
            self._progress.stop()

    def _do_cancel(self):
        self.controller.cancel()
        self._add_agent_msg("🛑 已取消任务。")
        self._set_running(False)

    def _execute_tool(self, tool: ToolCall):
        """执行解析出的工具调用。"""
        args = tool.args
        self._set_running(True)

        if tool.name == "scan":
            target = args.get("target", "")
            if not target:
                # 弹出文件/目录选择
                target = self._ask_target()
                if not target:
                    self._set_running(False)
                    return
            backend = args.get("backend", self._backend)
            self._add_agent_msg(f"📂 扫描 {target} (后端: {backend})...")
            output = self._next_output()
            self._last_output_path = output
            log_frame = self._add_log("")
            self._attach_log(log_frame, lambda: self.controller.run_scan(
                target=target, output_path=output, backend=backend,
                workers=self._workers, use_cache=self._use_cache,
                score_engine=self._score_engine, threshold=self._threshold,
            ))

        elif tool.name == "deep":
            target = args.get("target", "")
            if not target:
                target = self._ask_target_file()
                if not target:
                    self._set_running(False)
                    return
            self._add_agent_msg("🔬 启动 Ghidra 深度分析...")
            output = self._next_output()
            self._last_output_path = output
            log_frame = self._add_log("")
            self._attach_log(log_frame, lambda: self.controller.run_deep(
                target=target, output_path=output,
            ))

        elif tool.name == "pipeline":
            target = args.get("target", "")
            if not target:
                target = self._ask_target()
                if not target:
                    self._set_running(False)
                    return
            backend = args.get("backend", self._backend)
            ws = str(WORKSPACE_DIR / "pipeline_run")
            output = self._next_output()
            self._last_output_path = output
            self._add_agent_msg(f"🚀 完整流水线: {target} (后端: {backend})...")
            log_frame = self._add_log("")
            self._attach_log(log_frame, lambda: self.controller.run_pipeline(
                target=target, workspace=ws, output_path=output,
                backend=backend, workers=self._workers, use_cache=self._use_cache,
                score_engine=self._score_engine, threshold=self._threshold,
                ovoida_api_url=self._ov_url, ovoida_api_key=self._ov_key,
                ovoida_model=self._ov_model, deep_analysis=self._deep_analysis,
                deep_threshold=self._threshold, deep_max=5, max_deep=5,
                formats=["json", "html", "markdown"],
            ))

        elif tool.name == "list_analyzers":
            log_frame = self._add_log("")
            self._attach_log(log_frame, self.controller.run_list_analyzers)

        elif tool.name == "check_env":
            log_frame = self._add_log("")
            self._attach_log(log_frame, self.controller.run_check_env)

        elif tool.name == "report":
            self._set_running(False)
            self._export_report(args.get("format", "html"))

        elif tool.name == "status":
            self._set_running(False)
            self._show_status()

        else:
            self._set_running(False)

    def _ask_target(self) -> str:
        """弹出对话框选择文件或目录。"""
        dialog = tk.Toplevel(self.root)
        dialog.title("选择目标")
        dialog.geometry("350x140")
        dialog.transient(self.root)
        dialog.grab_set()

        result = {"path": ""}

        def pick_file():
            p = filedialog.askopenfilename(filetypes=[("驱动文件", "*.sys"), ("所有文件", "*.*")])
            if p:
                result["path"] = p
                dialog.destroy()

        def pick_dir():
            p = filedialog.askdirectory()
            if p:
                result["path"] = p
                dialog.destroy()

        tk.Label(dialog, text="请选择扫描目标：", font=FONT_BOLD).pack(pady=12)
        tk.Button(dialog, text="📄 选择文件", command=pick_file, width=20).pack(pady=4)
        tk.Button(dialog, text="📁 选择目录", command=pick_dir, width=20).pack(pady=4)

        self.root.wait_window(dialog)
        return result["path"]

    def _ask_target_file(self) -> str:
        """仅选择文件。"""
        return filedialog.askopenfilename(filetypes=[("驱动文件", "*.sys"), ("所有文件", "*.*")])

    def _attach_log(self, log_frame: tk.Frame, run_func):
        """启动任务，日志实时写入 log_frame。"""
        # 重定向 controller 的日志到 UI
        original_put = self.controller.log_queue.put

        def stream_to_ui():
            """定期检查 log_queue 并更新 UI。"""
            while self.controller.is_running:
                try:
                    line = self.controller.log_queue.get_nowait()
                    self._update_log(log_frame, line)
                except Exception:
                    pass
                self.root.after(50, stream_to_ui)

        # 启动流式显示
        stream_to_ui()

        # 启动任务
        run_func()

        # 启动结果轮询
        self._poll_task_result(log_frame)

    def _poll_task_result(self, log_frame: tk.Frame):
        """轮询任务结果。"""
        try:
            result = self.controller.result_queue.get_nowait()
        except Exception:
            self.root.after(200, lambda: self._poll_task_result(log_frame))
            return

        self._set_running(False)
        if result is not None:
            self._last_result = result
            self._summarize_result(result)
        else:
            self._add_agent_msg("任务完成（无结构化结果）。")

    def _summarize_result(self, result: dict):
        """将分析结果转为 Agent 回复。"""
        summary = result.get("summary", {})
        top = result.get("top_samples", [])

        scanned = summary.get("scanned", len(top))
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        avg = summary.get("avg_score", 0.0)

        lines = [f"✅ 扫描完成！共分析 {scanned} 个驱动。\n"]

        if critical > 0:
            lines.append(f"🔴 严重: {critical} 个")
        if high > 0:
            lines.append(f"🟠 高危: {high} 个")
        if medium > 0:
            lines.append(f"🟡 中危: {medium} 个")
        if avg > 0:
            lines.append(f"📊 平均风险评分: {avg:.1f}/10")

        if top:
            lines.append("\n📋 样本列表：")
            for s in top[:10]:
                name = s.get("name", "?")
                score = s.get("risk_score", 0)
                level = self._score_label(score)
                lines.append(f"  • {name}  {score:.1f}  {level}")

        lines.append("\n想做什么？可以：")
        lines.append("• 深度分析某个驱动")
        lines.append("• 导出报告")
        lines.append("• 换其他目录扫描")

        self._add_agent_msg("\n".join(lines))

    @staticmethod
    def _score_label(score: float) -> str:
        if score >= 9.0:
            return "严重"
        if score >= 7.0:
            return "高危"
        if score >= 4.0:
            return "中危"
        if score >= 1.0:
            return "低危"
        return "安全"

    def _show_status(self):
        backends = {"capstone": "Capstone (快速)", "ghidra": "Ghidra (精确)"}
        engines = {"default": "BYOVD 专用", "exploitability": "利用性分析"}
        agent_status = "已配置 ✓" if (self._ov_url and self._ov_key) else "未配置 ✗"

        text = (
            f"📊 当前配置：\n\n"
            f"分析后端: {backends.get(self._backend, self._backend)}\n"
            f"评分引擎: {engines.get(self._score_engine, self._score_engine)}\n"
            f"风险阈值: {self._threshold}\n"
            f"分析缓存: {'开启' if self._use_cache else '关闭'}\n"
            f"OVOIDA Agent: {agent_status}"
        )
        if self._ov_url:
            text += f"\nAPI URL: {self._ov_url}"
        if self._ov_model:
            text += f"\n模型: {self._ov_model}"

        self._add_agent_msg(text)

    def _export_report(self, fmt: str = "html"):
        if not self._last_output_path or not Path(self._last_output_path).exists():
            self._add_agent_msg("还没有分析结果，请先运行一次扫描。")
            return

        out_path = filedialog.asksaveasfilename(
            title=f"导出 {fmt.upper()} 报告",
            defaultextension=f".{fmt}",
            filetypes=[
                ("JSON", "*.json"), ("HTML", "*.html"),
                ("Markdown", "*.md"), ("所有文件", "*.*"),
            ],
            initialfile=f"report.{fmt}",
        )
        if not out_path:
            return

        try:
            data = json.loads(Path(self._last_output_path).read_text(encoding="utf-8"))
            out = Path(out_path)
            if fmt == "json":
                out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            elif fmt == "html":
                from src.models import Report
                from src.report.html import generate_html
                report = Report(samples=[], tool_version="DriverScope Agent", backend=self._backend)
                out.write_text(generate_html(report), encoding="utf-8")
            elif fmt in ("markdown", "md"):
                from src.models import Report
                from src.report.markdown import generate_markdown
                report = Report(samples=[], tool_version="DriverScope Agent", backend=self._backend)
                out.write_text(generate_markdown(report), encoding="utf-8")
            self._add_agent_msg(f"✅ 报告已导出: {out}")
        except Exception as e:
            self._add_agent_msg(f"❌ 导出失败: {e}")

    # ------------------------------------------------------------------
    # 队列轮询（备用，处理非流式任务的日志）
    # ------------------------------------------------------------------

    def _poll_queues(self):
        while True:
            try:
                line = self.controller.log_queue.get_nowait()
            except Exception:
                break
            # 如果有正在运行的日志气泡，追加到这里
        self.root.after(100, self._poll_queues)
