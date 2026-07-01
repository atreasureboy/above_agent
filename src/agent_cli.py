"""通用逆向 CLI Agent — 交互式 REPL 入口。"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

try:
    # Windows color support
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
except Exception:
    pass

# ANSI colors
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Chat bubble chars
USER_BUBBLE = "┃"
AGENT_BUBBLE = "│"


def _term_width(default: int = 100) -> int:
    """获取终端宽度，非交互环境 fallback。"""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return default


def _wrap(text: str, width: int = 80) -> str:
    """智能换行，保留换行符。"""
    lines = []
    for line in text.split("\n"):
        lines.extend(textwrap.wrap(line, width=width) or [""])
    return "\n".join(lines)


def _print_user_msg(text: str):
    """打印用户消息（右侧蓝色气泡风格）。"""
    width = max(40, _term_width() - 5)
    wrapped = _wrap(text, width - 4)
    for line in wrapped.split("\n"):
        print(f"{GRAY}  {USER_BUBBLE} {GREEN}{line}{RESET}")
    print()


def _print_agent_msg(text: str):
    """打印 Agent 回复（左侧白色气泡风格）。"""
    width = max(40, _term_width() - 5)
    wrapped = _wrap(text, width - 4)
    for line in wrapped.split("\n"):
        print(f" {AGENT_BUBBLE}  {CYAN}{line}{RESET}")
    print()


def _print_log_line(line: str):
    """打印日志行（灰色缩进）。"""
    stripped = line.rstrip("\n")
    if stripped:
        print(f"   {GRAY}│ {stripped}{RESET}")


class AgentCLI:
    """CLI Agent REPL —— 对话式逆向分析调度器。"""

    def __init__(self):
        from src.gui.agent import AgentBrain
        from src.gui.controller import AnalysisController

        self.agent = AgentBrain()
        self.controller = AnalysisController()
        self._workspace = str(project_root / "workspace")
        os.makedirs(self._workspace, exist_ok=True)

    @property
    def _banner(self) -> str:
        term_w = _term_width()
        sep = "─" * min(term_w, 70)
        return (
            f"\n{BOLD}{CYAN}  逆向分析 Agent CLI{RESET}\n"
            f"  {GRAY}{sep}{RESET}\n"
            f"  告诉我要分析什么文件，我来调度工具\n"
            f"  输入 {YELLOW}帮助{RESET} 查看功能 | {YELLOW}退出{RESET} 结束会话\n\n"
        )

    def run(self):
        """主 REPL 循环。"""
        print(self._banner)
        try:
            while True:
                try:
                    user_input = input(f"{BOLD}{GREEN}你 > {RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{GRAY}再见 👋{RESET}")
                    break

                if not user_input:
                    continue
                if user_input in ("退出", "exit", "quit", "q"):
                    print(f"\n{GRAY}再见 👋{RESET}")
                    break

                # Agent 处理
                _print_user_msg(user_input)
                resp = self.agent.process(user_input)

                # 设置操作
                if resp.reply.startswith("SETTING:"):
                    self._apply_setting(resp.reply)
                    _print_agent_msg(f"已保存设置。{resp.reply.split('=', 1)[0].replace('SETTING:', '')} = {resp.reply.split('=', 1)[1] if '=' in resp.reply else ''}")
                    continue

                _print_agent_msg(resp.reply)

                # 执行工具
                if resp.tool_call:
                    self._execute_tool(resp.tool_call)
        finally:
            pass

    def _apply_setting(self, setting: str):
        """应用设置。"""
        key, _, value = setting[len("SETTING:"):].partition("=")
        if key == "ov_url":
            self.agent._ov_url = value
        elif key == "ov_key":
            self.agent._ov_key = value
        elif key == "ov_model":
            self.agent._ov_model = value
        elif key == "backend":
            self.agent._backend = value
        elif key == "score_engine":
            self.agent._score_engine = value

    def _execute_tool(self, tool_call):
        """执行工具调用。"""
        from datetime import datetime

        name = tool_call.name
        args = tool_call.args
        target = args.get("target", "")

        # 需要目标但未提供时，提示用户
        if name in ("scan", "deep", "pipeline") and not target:
            _print_agent_msg("你需要分析哪个文件或目录？告诉我路径即可。")
            return

        # 生成输出文件名
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = Path(target).name.replace(".", "_") if target else "target"
        output_path = str(Path(self._workspace) / f"result_{safe_name}_{ts}.json")

        # 映射工具到控制器方法
        try:
            if name == "scan":
                backend = args.get("backend", getattr(self.agent, "_backend", "capstone"))
                _print_agent_msg(f"开始扫描 {target}（后端: {backend}）...")
                self.controller.run_scan(
                    target=target,
                    output_path=output_path,
                    backend=backend,
                    score_engine=getattr(self.agent, "_score_engine", "default"),
                )
            elif name == "deep":
                _print_agent_msg(f"开始深度分析 {target}...")
                self.controller.run_deep(
                    target=target,
                    output_path=output_path,
                )
            elif name == "pipeline":
                backend = args.get("backend", getattr(self.agent, "_backend", "capstone"))
                _print_agent_msg(f"开始完整流水线 {target}...")
                self.controller.run_pipeline(
                    target=target,
                    workspace=self._workspace,
                    output_path=output_path,
                    backend=backend,
                    ovoida_api_url=getattr(self.agent, "_ov_url", ""),
                    ovoida_api_key=getattr(self.agent, "_ov_key", ""),
                    ovoida_model=getattr(self.agent, "_ov_model", ""),
                    score_engine=getattr(self.agent, "_score_engine", "default"),
                )
            elif name == "list_analyzers":
                self.controller.run_list_analyzers()
            elif name == "check_env":
                self.controller.run_check_env()
            elif name == "report":
                _print_agent_msg("报告功能尚未在 CLI 中实现，结果已保存到 workspace/ 目录。")
                return
            else:
                _print_agent_msg(f"工具 {name} 尚未实现。")
                return
        except Exception as e:
            _print_agent_msg(f"执行出错: {e}")
            return

        # 流式日志
        self._stream_logs()

        # 等待结果
        try:
            result = self.controller.result_queue.get(timeout=300)
            if result:
                self._summarize_result(result)
            else:
                _print_agent_msg("分析完成，但未能解析结果文件。")
        except Exception:
            _print_agent_msg("分析完成（结果文件请查看 workspace/ 目录）。")

    def _stream_logs(self):
        """从队列流式打印日志到终端。"""
        import time

        _print_agent_msg("运行中，实时日志：")
        while self.controller.is_running:
            try:
                line = self.controller.log_queue.get(timeout=0.1)
                _print_log_line(line)
            except Exception:
                continue

    def _summarize_result(self, result: dict):
        """将 JSON 结果总结为 Agent 回复。"""
        # 适配多种输出格式
        samples = result.get("samples", result.get("top_samples", []))
        summary = result.get("summary", {})

        if not samples:
            _print_agent_msg("分析完成，未发现任何样本。")
            return

        count = len(samples)
        total_findings = sum(s.get("finding_count", 0) for s in samples)
        scores = [s.get("risk_score", 0) for s in samples]
        avg_score = summary.get("avg_score", sum(scores) / max(len(scores), 1))
        max_score = max(scores) if scores else 0

        # 按严重级别统计
        critical = summary.get("critical", sum(1 for s in scores if s >= 9.0))
        high = summary.get("high", sum(1 for s in scores if 7.0 <= s < 9.0))
        medium = sum(1 for s in scores if 4.0 <= s < 7.0)

        reply = f"分析完成！共分析 {count} 个文件，发现 {total_findings} 项问题。\n"
        reply += f"  平均评分: {avg_score:.1f}/10  最高: {max_score:.1f}/10\n"
        if critical:
            reply += f"  {RED}严重: {critical}{RESET}  "
        if high:
            reply += f"  {YELLOW}高危: {high}{RESET}  "
        if medium:
            reply += f"  中危: {medium}  "

        # 列出高危样本
        risky = [s for s in samples if s.get("risk_score", 0) >= 4.0]
        if risky:
            reply += "\n\n  关注样本:\n"
            for s in sorted(risky, key=lambda x: x.get("risk_score", 0), reverse=True)[:5]:
                name = s.get("name", "?")
                score = s.get("risk_score", 0)
                reply += f"    {name}: {score:.1f}/10\n"

        _print_agent_msg(reply)


def main():
    cli = AgentCLI()
    cli.run()


if __name__ == "__main__":
    main()
