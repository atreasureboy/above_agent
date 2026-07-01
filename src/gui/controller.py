"""DriverScope GUI — 子进程控制器，Agent 专用。"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from pathlib import Path


class AnalysisController:
    """Agent 驱动的子进程控制器。"""

    def __init__(self) -> None:
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.result_queue: queue.Queue[dict | None] = queue.Queue()
        self._process: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._cancel_flag = threading.Event()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def cancel(self) -> None:
        self._cancel_flag.set()
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
            except OSError:
                pass

    def run_scan(
        self,
        target: str,
        output_path: str,
        backend: str = "capstone",
        workers: int = 0,
        use_cache: bool = True,
        score_engine: str = "default",
        threshold: float = 5.0,
    ) -> None:
        args = [
            sys.executable, "-m", "src", "scan", target,
            "--backend", backend,
            "--timeout", "0",
            "--output", output_path,
            "--score-engine", score_engine,
            "--threshold", str(threshold),
        ]
        if workers > 0:
            args += ["-j", str(workers)]
        if not use_cache:
            args.append("--no-cache")
        self._start(args)

    def run_deep(
        self,
        target: str,
        output_path: str,
    ) -> None:
        args = [
            sys.executable, "-m", "src", "deep", target,
            "--timeout", "0",
            "--output", output_path,
        ]
        self._start(args)

    def run_pipeline(
        self,
        target: str,
        workspace: str,
        output_path: str,
        backend: str = "capstone",
        workers: int = 0,
        use_cache: bool = True,
        score_engine: str = "default",
        threshold: float = 5.0,
        ovoida_api_url: str = "",
        ovoida_api_key: str = "",
        ovoida_model: str = "",
        deep_analysis: bool = False,
        deep_threshold: float = 5.0,
        deep_max: int = 5,
        max_deep: int = 5,
        formats: list[str] | None = None,
    ) -> None:
        fmt = formats or ["json", "markdown"]
        args = [
            sys.executable, "-m", "src", "pipeline", target,
            "--workspace", workspace,
            "--backend", backend,
            "--timeout", "0",
            "--threshold", str(threshold),
            "--max-deep", str(max_deep),
            "--format", *fmt,
            "--score-engine", score_engine,
            "--deep-threshold", str(deep_threshold),
            "--deep-max", str(deep_max),
            "--deep-timeout", "0",
        ]
        if ovoida_api_url:
            args += ["--ov-url", ovoida_api_url]
        if ovoida_api_key:
            args += ["--ov-key", ovoida_api_key]
        if ovoida_model:
            args += ["--ov-model", ovoida_model]
        if not deep_analysis:
            args.append("--no-ovoida")
        if workers > 0:
            args += ["-j", str(workers)]
        if not use_cache:
            args.append("--no-cache")
        self._start(args)

    def run_list_analyzers(self) -> None:
        args = [sys.executable, "-m", "src", "list-analyzers"]
        self._start(args)

    def run_check_env(self) -> None:
        args = [sys.executable, "-m", "src", "check-env"]
        self._start(args)

    def _start(self, args: list[str]) -> None:
        if self._running:
            self.log_queue.put("[GUI] 已有任务正在运行，请等待完成。\n")
            return
        self._cancel_flag.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._run_subprocess, args=(args,), daemon=True
        )
        self._thread.start()

    def _run_subprocess(self, args: list[str]) -> None:
        result_data: dict | None = None
        output_path: str | None = None
        for i, arg in enumerate(args):
            if arg == "--output" and i + 1 < len(args):
                output_path = args[i + 1]
                break

        try:
            self.log_queue.put(f"> 执行: {' '.join(args)}\n")
            self._process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(Path(__file__).resolve().parents[2]),  # 项目根目录，非 src/
            )
            for line in iter(self._process.stdout.readline, ""):
                if self._cancel_flag.is_set():
                    self._process.terminate()
                    self.log_queue.put("[已取消]\n")
                    break
                self.log_queue.put(line)

            rc = self._process.wait()
            self._process = None

            if rc != 0:
                self.log_queue.put(f"[完成] 退出码 {rc}\n")
            else:
                self.log_queue.put("[完成] 分析结束\n")

            # 无论退出码如何，都尝试读取结果文件
            if output_path and Path(output_path).exists():
                try:
                    result_data = json.loads(
                        Path(output_path).read_text(encoding="utf-8")
                    )
                except Exception as e:
                    self.log_queue.put(f"[错误] 解析输出失败: {e}\n")
        except Exception as e:
            self.log_queue.put(f"[错误] {e}\n")
        finally:
            self._running = False
            self.result_queue.put(result_data)
