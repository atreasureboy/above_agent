"""DEVOPS_driver — GUI 一键启动器"""
import sys
import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
from pathlib import Path

# 项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path.home() / ".devops_driver" / "config.json"


def load_config():
    """加载用户配置"""
    import json
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


class LauncherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DEVOPS_driver — Windows 驱动 BYOVD 分析平台")
        self.root.geometry("720x620")
        self.root.resizable(True, True)

        self.config = load_config()
        self.running = False

        self._build_ui()
        self._apply_config()

    def _build_ui(self):
        # ── 顶部：标题 ──
        title = ttk.Label(
            self.root,
            text="DEVOPS_driver — DriverScope + OVOIDA",
            font=("Microsoft YaHei UI", 16, "bold"),
        )
        title.pack(pady=(12, 4))

        sub = ttk.Label(
            self.root,
            text="Windows 内核驱动 BYOVD 漏洞自动化挖掘工具",
            font=("Microsoft YaHei UI", 9),
            foreground="#666",
        )
        sub.pack(pady=(0, 10))

        # ── 配置区 ──
        frame = ttk.LabelFrame(self.root, text="  扫描配置  ", padding=12)
        frame.pack(fill="x", padx=16, pady=4)

        # 目标目录
        row1 = ttk.Frame(frame)
        row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="目标目录", width=10).pack(side="left")
        self.target_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.target_var, width=50).pack(
            side="left", padx=6, fill="x", expand=True
        )
        ttk.Button(row1, text="浏览...", command=self._browse_target).pack(side="left")

        # 输出目录
        row2 = ttk.Frame(frame)
        row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="输出目录", width=10).pack(side="left")
        self.workspace_var = tk.StringVar(value="workspace")
        ttk.Entry(row2, textvariable=self.workspace_var, width=50).pack(
            side="left", padx=6, fill="x", expand=True
        )
        ttk.Button(row2, text="浏览...", command=self._browse_workspace).pack(side="left")

        # 风险阈值 & 深度数量
        row3 = ttk.Frame(frame)
        row3.pack(fill="x", pady=4)
        ttk.Label(row3, text="风险阈值", width=10).pack(side="left")
        self.threshold_var = tk.DoubleVar(value=5.0)
        ttk.Spinbox(row3, from_=0, to=10, increment=0.5, textvariable=self.threshold_var, width=8).pack(side="left", padx=6)

        ttk.Label(row3, text="深度分析上限", width=10).pack(side="left", padx=(16, 0))
        self.max_deep_var = tk.IntVar(value=5)
        ttk.Spinbox(row3, from_=0, to=100, increment=1, textvariable=self.max_deep_var, width=8).pack(side="left", padx=6)

        # API 状态
        row4 = ttk.Frame(frame)
        row4.pack(fill="x", pady=4)
        ttk.Label(row4, text="API 状态", width=10).pack(side="left")
        api_url = self.config.get("ov_api_url", "未配置")
        api_masked = self._mask_key(self.config.get("ov_api_key", ""))
        self.api_status_var = tk.StringVar(value=f"{api_url}  |  Key: {api_masked}")
        ttk.Label(row4, textvariable=self.api_status_var, foreground="#2a7").pack(side="left", padx=6)
        ttk.Button(row4, text="配置...", command=self._configure_api).pack(side="left", padx=12)

        # 模式选择
        row5 = ttk.Frame(frame)
        row5.pack(fill="x", pady=4)
        self.mode_var = tk.StringVar(value="full")
        ttk.Radiobutton(row5, text="全链路扫描 (Phase 1+2+3)", variable=self.mode_var, value="full").pack(side="left")
        ttk.Radiobutton(row5, text="仅 DriverScope (Phase 1)", variable=self.mode_var, value="scan").pack(side="left", padx=12)

        # ── 启动按钮 ──
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(8, 2))
        self.start_btn = ttk.Button(btn_frame, text="  开始扫描  ", command=self._start)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(btn_frame, text="  停止  ", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(btn_frame, text="  打开报告目录  ", command=self._open_report).pack(side="left", padx=4)

        # ── 日志区 ──
        log_frame = ttk.LabelFrame(self.root, text="  运行日志  ", padding=8)
        log_frame.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=16,
            font=("Cascadia Code", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="#d4d4d4",
        )
        self.log_text.pack(fill="both", expand=True)

    def _mask_key(self, key):
        if len(key) > 8:
            return key[:4] + "..." + key[-4:]
        return "***" if key else "未配置"

    def _configure_api(self):
        """弹出 API 配置对话框"""
        import json

        dlg = tk.Toplevel(self.root)
        dlg.title("API 配置")
        dlg.geometry("420x220")
        dlg.transient(self.root)
        dlg.grab_set()

        # Center on parent
        x = self.root.winfo_x() + 80
        y = self.root.winfo_y() + 80
        dlg.geometry(f"+{x}+{y}")

        ttk.Label(dlg, text="API Endpoint URL:").pack(anchor="w", padx=16, pady=(12, 2))
        url_var = tk.StringVar(value=self.config.get("ov_api_url", "https://api.deepseek.com/v1"))
        ttk.Entry(dlg, textvariable=url_var, width=50).pack(anchor="w", padx=16)

        ttk.Label(dlg, text="API Key:").pack(anchor="w", padx=16, pady=(8, 2))
        key_var = tk.StringVar(value=self.config.get("ov_api_key", ""))
        ttk.Entry(dlg, textvariable=key_var, width=50, show="*").pack(anchor="w", padx=16)

        ttk.Label(dlg, text="Model:").pack(anchor="w", padx=16, pady=(8, 2))
        model_var = tk.StringVar(value=self.config.get("ov_model", "deepseek-chat"))
        ttk.Entry(dlg, textvariable=model_var, width=50).pack(anchor="w", padx=16)

        def _save():
            url = url_var.get().strip()
            key = key_var.get().strip()
            model = model_var.get().strip()
            if not key:
                messagebox.showwarning("警告", "API Key 不能为空", parent=dlg)
                return
            cfg = {
                "ov_api_url": url,
                "ov_api_key": key,
                "ov_model": model,
            }
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            self.config = cfg
            self.api_status_var.set(f"{url}  |  Key: {self._mask_key(key)}")
            dlg.destroy()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(anchor="e", padx=16, pady=12)
        ttk.Button(btn_frame, text="取消", command=dlg.destroy).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="保存", command=_save).pack(side="left", padx=4)

    def _apply_config(self):
        self.target_var.set("")

    def _browse_target(self):
        path = filedialog.askdirectory(title="选择 .sys 驱动样本目录")
        if path:
            self.target_var.set(path)

    def _browse_workspace(self):
        path = filedialog.askdirectory(title="选择输出目录")
        if path:
            self.workspace_var.set(path)

    def _open_report(self):
        ws = self.workspace_var.get().strip()
        report_dir = Path(ws) / "reports"
        if report_dir.exists():
            os.startfile(str(report_dir))
        else:
            messagebox.showinfo("提示", "报告目录尚未生成，请先运行一次扫描。")

    def _log(self, msg):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")
        self.root.update_idletasks()

    def _start(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("警告", "请先选择目标目录！")
            return
        if not Path(target).exists():
            messagebox.showerror("错误", f"目录不存在：{target}")
            return

        # Check API key before starting
        if not self.config.get("ov_api_key"):
            messagebox.showwarning("警告", "请先配置 API Key！点击 '配置...' 按钮。")
            return

        self.running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log_text.delete("1.0", "end")
        self._log("=" * 60)
        self._log("  DEVOPS_driver 一键启动")
        self._log(f"  目标: {target}")
        self._log(f"  输出: {self.workspace_var.get()}")
        self._log(f"  模式: {'全链路' if self.mode_var.get() == 'full' else '仅 DriverScope'}")
        self._log("=" * 60)

        t = threading.Thread(target=self._run_pipeline, args=(target,), daemon=True)
        t.start()

    def _stop(self):
        self.running = False
        self._log("\n[!] 用户请求停止...")

    def _run_pipeline(self, target):
        try:
            os.chdir(str(PROJECT_ROOT))

            if self.mode_var.get() == "full":
                cmd = [
                    sys.executable, "-m", "src", "pipeline",
                    target,
                    "-w", self.workspace_var.get(),
                    "-t", str(self.threshold_var.get()),
                    "--max-deep", str(self.max_deep_var.get()),
                ]
            else:
                cmd = [
                    sys.executable, "-m", "src", "scan",
                    target,
                    "-o", str(Path(self.workspace_var.get()) / "scan_report.json"),
                ]

            self._log(f"\n[>] 执行命令: {' '.join(cmd)}\n")

            proc = __import__("subprocess").Popen(
                cmd,
                stdout=__import__("subprocess").PIPE,
                stderr=__import__("subprocess").STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(PROJECT_ROOT),
            )

            for line in proc.stdout:
                if not self.running:
                    proc.kill()
                    self._log("\n[!] 已停止。")
                    break
                self._log(line.rstrip())

            proc.wait()
            if self.running:
                self._log(f"\n[√] 完成！退出码: {proc.returncode}")
        except Exception as e:
            self._log(f"\n[!] 错误: {e}")
        finally:
            self.running = False
            self.root.after(0, lambda: self.start_btn.config(state="normal"))
            self.root.after(0, lambda: self.stop_btn.config(state="disabled"))


def main():
    root = tk.Tk()
    LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
