"""通用逆向 CLI Agent — 意图解析 + 工具调度。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    """解析出的工具调用。"""
    name: str
    args: dict = field(default_factory=dict)


@dataclass
class AgentResponse:
    """Agent 响应。"""
    reply: str              # 回复用户的文本
    tool_call: ToolCall | None = None  # 要执行的工具


class AgentBrain:
    """Agent 意图解析引擎：从自然语言中提取工具调用。"""

    def __init__(self):
        self._tools = self._build_tools()
        self._history: list[tuple[str, str]] = []  # (user, agent) 对话历史

    def _build_tools(self) -> dict[str, dict]:
        return {
            "pipeline": {
                "desc": "完整流水线（扫描 + OVOIDA Agent + 报告）",
                "patterns": [
                    r"完整(?:流水|流|全)?线?\s*(.*)",
                    r"全(?:面|套)?分析\s*(.+)?",
                    r"跑一[遍下]\s*(.*)",
                    r"完整流程\s*(.*)",
                ],
            },
            "deep": {
                "desc": "Ghidra 深度逆向分析单个二进制文件",
                "patterns": [
                    r"深[度]?\s*分析\s*(.+)",
                    r"ghidra\s*(.+)",
                    r"(?:反编译|伪代码|逆向)\s*(.+)",
                    r"深度\s*(.+)",
                    r"反汇编\s*(.+)",
                ],
            },
            "scan": {
                "desc": "快速扫描二进制文件（静态分析）",
                "patterns": [
                    r"扫(?:描|一[下份])?\s*(.+)",
                    r"(?:运行|启动|执?行)?\s*快[速]?扫(?:描)?\s*(.+)?",
                ],
            },
            "report": {
                "desc": "导出/查看报告",
                "patterns": [
                    r"(?:导出|生成|保存)\s*(?:html|json|markdown|md)?报告",
                    r"(?:查看|显示|打开)\s*报告",
                    r"导出\s*(html|json|markdown|md)",
                    r"报告",
                ],
            },
            "list_analyzers": {
                "desc": "列出所有分析器",
                "patterns": [
                    r"分析器列表",
                    r"列出?\s*分析器",
                    r"有哪些分析器",
                    r"什么分析器",
                ],
            },
            "check_env": {
                "desc": "检查动态分析环境",
                "patterns": [
                    r"环境检查",
                    r"检查环境",
                    r"环境状态",
                    r"qemu",
                ],
            },
            "status": {
                "desc": "查看当前状态/配置",
                "patterns": [
                    r"(?:当前)?状态",
                    r"(?:当前)?配置",
                    r"设置",
                    r"现在(?:怎样|如何)",
                ],
            },
            "help": {
                "desc": "显示帮助信息",
                "patterns": [
                    r"(?:帮助|help|怎么用?|能做什[么么]|功能)",
                ],
            },
        }

    def process(self, user_input: str) -> AgentResponse:
        """处理用户输入，返回 AgentResponse。"""
        text = user_input.strip().lower()
        if not text:
            return AgentResponse(reply="请输入你想让我做什么 😊")

        # 存储历史
        self._history.append((user_input, ""))

        # 1. 优先检测设置操作（在工具匹配之前）
        settings_response = self._handle_settings(user_input.strip().lower())
        if settings_response:
            self._history[-1] = (user_input, settings_response)
            return AgentResponse(reply=settings_response)

        # 2. 检测工具调用
        tool_call = self._match_tool(text)
        if tool_call:
            response = self._format_tool_response(tool_call)
            self._history[-1] = (user_input, response.reply)
            return response

        # 3. 模糊匹配
        response = self._fuzzy_match(text)
        self._history[-1] = (user_input, response.reply)
        return response

    def _match_tool(self, text: str) -> ToolCall | None:
        """匹配工具调用。"""
        for tool_name, tool_info in self._tools.items():
            for pattern in tool_info["patterns"]:
                m = re.search(pattern, text)
                if m:
                    args = self._extract_args(text, m)
                    return ToolCall(name=tool_name, args=args)
        return None

    def _extract_args(self, text: str, match: re.Match) -> dict:
        """从匹配中提取参数（文件路径等）。"""
        args: dict = {}
        # 提取 Windows 路径 — 支持所有二进制类型和目录
        path_patterns = [
            r'["\']([^"\']+\.(?:sys|exe|dll|ocx|drv|com|bin|elf|so|macho))["\']',  # 引号包裹
            r'([a-zA-Z]:[\\\/][\w\\\/\._\-]+\.(?:sys|exe|dll|ocx|drv|com|bin))',  # 绝对路径 PE
            r'([a-zA-Z]:[\\\/][\w\\\/\._\-]+)',  # 绝对路径（目录）
            r'((?:samples?|workspace|targets?|builds?|output)[\\\/][\w\\\/\._\-]*)',  # 常见相对路径
            r'([\w\-]+\.(?:sys|exe|dll|bin|elf|so))',  # 仅文件名
            r'((?:samples?|workspace|targets?|builds?|output)[\w\\\/]*)',  # 裸目录名
        ]
        for pp in path_patterns:
            m = re.search(pp, text)
            if m:
                args["target"] = m.group(1)
                break

        # 自动检测文件类型
        if "target" in args:
            args["file_type"] = self._detect_file_type(args["target"])

        # 提取后端
        if "ghidra" in text or "精确" in text:
            args["backend"] = "ghidra"
        elif "capstone" in text or "快速" in text:
            args["backend"] = "capstone"

        # 提取导出格式
        for fmt in ("html", "json", "markdown", "md"):
            if fmt in text:
                args["format"] = fmt
                break

        return args

    @staticmethod
    def _detect_file_type(path: str) -> str:
        """根据扩展名检测文件类型。"""
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        mapping = {
            "sys": "Windows 驱动",
            "exe": "可执行文件",
            "dll": "动态链接库",
            "ocx": "ActiveX 控件",
            "drv": "驱动文件",
            "com": "COM 可执行",
            "bin": "二进制文件",
        }
        if ext in mapping:
            return mapping[ext]
        return "目录" if not ext else "文件"

    def _format_tool_response(self, tool_call: ToolCall) -> AgentResponse:
        """格式化工具调用的回复。"""
        replies = {
            "scan": {
                "args": tool_call.args,
                "reply": self._scan_reply(tool_call.args),
            },
            "deep": {
                "args": tool_call.args,
                "reply": self._deep_reply(tool_call.args),
            },
            "pipeline": {
                "args": tool_call.args,
                "reply": self._pipeline_reply(tool_call.args),
            },
            "report": {
                "args": tool_call.args,
                "reply": "好的，我来导出报告。",
            },
            "list_analyzers": {
                "args": {},
                "reply": "好的，列出所有分析器。",
            },
            "check_env": {
                "args": {},
                "reply": "正在检查动态分析环境...",
            },
            "status": {
                "args": {},
                "reply": "让我查看当前状态和配置。",
            },
            "help": {
                "args": {},
                "reply": self._help_text(),
            },
        }
        info = replies.get(tool_call.name)
        if info:
            return AgentResponse(reply=info["reply"], tool_call=tool_call)
        return AgentResponse(reply="抱歉，我不太明白你的意思。输入「帮助」查看我能做什么。")

    def _scan_reply(self, args: dict) -> str:
        target = args.get("target", "")
        ftype = args.get("file_type", "")
        if target:
            type_desc = f"（{ftype}）" if ftype and ftype != "目录" else ""
            return f"好的，扫描 {target}{type_desc}。使用静态分析，马上开始。"
        return "请告诉我你想扫描哪个文件或目录？例如：\n• 扫描 samples/small5/\n• 扫描 notepad.exe\n• 扫描 360AntiAttack64.sys"

    def _deep_reply(self, args: dict) -> str:
        target = args.get("target", "")
        ftype = args.get("file_type", "")
        if target:
            type_desc = f"（{ftype}）" if ftype and ftype != "目录" else ""
            return f"好的，对 {target}{type_desc} 进行 Ghidra 深度逆向。这可能需要几分钟..."
        return "请指定要深度分析的文件。例如：\n• 深度分析 ntdll.dll\n• 逆向 360Anti.sys"

    def _pipeline_reply(self, args: dict) -> str:
        target = args.get("target", "")
        ftype = args.get("file_type", "")
        if target:
            type_desc = f"（{ftype}）" if ftype and ftype != "目录" else ""
            return f"好的，对 {target}{type_desc} 运行完整分析流水线（扫描 → Agent 分析 → 报告）。"
        return "请告诉我你想分析哪个目录或文件？例如：\n• 完整分析 samples/test_scan/"

    @staticmethod
    def _help_text() -> str:
        return (
            "我能帮你分析各种二进制文件和目录：\n\n"
            "📂 扫描分析\n"
            "  • 扫描 samples/small5/       — 快速扫描目录\n"
            "  • 扫描 notepad.exe           — 扫描 PE 文件\n"
            "  • 逆向 ntdll.dll             — Ghidra 深度逆向\n"
            "  • 深度分析 driver.sys        — 完整反编译\n"
            "  • 完整流水线 samples/        — 完整分析流程\n\n"
            "📊 报告查看\n"
            "  • 导出报告 / 导出 HTML 报告\n"
            "  • 查看报告\n\n"
            "🔧 系统操作\n"
            "  • 分析器列表\n"
            "  • 环境检查\n"
            "  • 当前状态\n\n"
            "⚙️ 设置\n"
            "  • 设置 API URL https://...\n"
            "  • 设置 API Key sk-xxx\n"
            "  • 设置模型 gpt-4o\n"
            "  • 切换后端 ghidra/capstone\n"
            "  • 切换评分引擎 default/exploitability"
        )

    def _handle_settings(self, text: str) -> str:
        """处理设置相关的输入。"""
        # API URL
        url_match = re.search(r"(?:设置\s*)?(?:api\s*)?(?:url|地址|接口)\s*(https?://\S+)", text)
        if url_match:
            return f"SETTING:ov_url={url_match.group(1)}"

        # API Key
        key_match = re.search(r"(?:设置\s*)?(?:api\s*)?(?:key|密钥|token)\s*(\S+)", text)
        if key_match:
            return f"SETTING:ov_key={key_match.group(1)}"

        # Model
        model_match = re.search(r"(?:设置\s*)?(?:模型|model)\s*(\S+)", text)
        if model_match:
            return f"SETTING:ov_model={model_match.group(1)}"

        # Backend
        if "切换后端" in text or "切换分析后端" in text:
            if "ghidra" in text:
                return "SETTING:backend=ghidra"
            elif "capstone" in text:
                return "SETTING:backend=capstone"

        # Score engine
        if "切换评分" in text:
            if "exploitability" in text or "利用" in text:
                return "SETTING:score_engine=exploitability"
            elif "default" in text or "默认" in text:
                return "SETTING:score_engine=default"

        return ""

    def _fuzzy_match(self, text: str) -> AgentResponse:
        """模糊匹配，当没有精确匹配时的回复。"""
        # 包含文件/路径关键词
        if any(kw in text for kw in (".sys", ".exe", ".dll", "驱动", "samples", "逆向", "分析", "文件")):
            return AgentResponse(
                reply="你想分析哪个文件或目录？可以这样告诉我：\n"
                      "• 扫描 samples/small5/\n"
                      "• 逆向 notepad.exe\n"
                      "• 深度分析 ntdll.dll\n"
                      "• 完整分析 samples/test_scan/"
            )
        # 包含报告
        if any(kw in text for kw in ("报告", "report", "导出", "html")):
            return AgentResponse(
                reply="好的，我来处理报告。你可以说：\n"
                      "• 导出报告\n"
                      "• 导出 HTML 报告",
                tool_call=ToolCall(name="report"),
            )
        return AgentResponse(
            reply="我不太确定你的意思。输入「帮助」看看我能做什么 😊"
        )

    def get_last_result(self) -> str:
        """获取最近一次 Agent 回复。"""
        if self._history:
            return self._history[-1][1]
        return ""
