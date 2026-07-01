<div align="center">

# DEVOPS_driver

### 🛡️ Windows 驱动 BYOVD 漏洞自动化挖掘平台

**DriverScope 静态分析引擎 + OVOIDA AI 逆向 Agent + 动态验证框架**

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Ghidra](https://img.shields.io/badge/Ghidra-11.3%20|%2012.1-green.svg)](https://ghidra-sre.org/)
[![Analyzers](https://img.shields.io/badge/Analyzers-37%20Plugins-orange.svg)]()
[![Tests](https://img.shields.io/badge/Tests-2100+-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20|%20ARM64-lightgrey.svg)]()

> 🚀 一键启动逆向分析: `python -m src reverse target.exe --ov-key sk-xxx`
>
> 🔍 一键启动 BYOVD 扫描: `python -m src pipeline samples/ --threshold 5.0`

</div>

---

## 📋 目录

- [项目简介](#-项目简介)
- [完整架构全景图](#-完整架构全景图)
- [核心模块详解](#-核心模块详解)
- [快速开始](#-快速开始)
- [使用模式](#-使用模式)
- [项目结构](#-项目结构)
- [设计决策](#-设计决策)
- [技术栈](#-技术栈)
- [测试](#-测试)
- [安全声明](#-安全声明)

---

## 🔍 项目简介

DEVOPS_driver 是一个面向 **Windows 内核驱动 BYOVD（Bring Your Own Vulnerable Driver）漏洞挖掘** 的全链路自动化平台，同时支持**通用 PE 文件 AI 逆向分析**。

### 核心能力

- **🔬 37 个分析插件** — 覆盖 IOCTL 暴露面、危险内核原语、DKOM、Hook、DSE/PG bypass、回调注册、MiniFilter、ALPC/NamedPipe、反混淆、VMX/EPT 等全部已知 BYOVD 攻击面
- **🧠 AI 深度逆向（OVOIDA Agent）** — 集成 DeepSeek/GPT 等大模型，对高风险驱动进行综合研判 + PoC 自动生成
- **⚡ 双后端反汇编** — Capstone（快速模式匹配）+ Ghidra（全量反编译 + 污点追踪）
- **🔗 全链路污点分析** — 用户输入 → IOCTL handler → 危险 API 调用，完整 taint source → sink 验证
- **🎯 自动 PoC 生成** — 基于攻击链自动生成 Python ctypes / C 语言的漏洞利用 PoC
- **🖥️ 动态验证框架** — QEMU 沙箱 + WinDbg 内核调试 + KDNET 远程调试
- **📊 多格式报告** — JSON / HTML / Markdown / SARIF / DOT 攻击图
- **🤖 对话式 Agent CLI** — 自然语言交互："扫描 samples/"、"逆向 ntdll.dll"
- **🌐 通用逆向模式** — `reverse` 命令跳过 BYOVD 评分，直接对任意 PE 做 AI 深度分析

### 与传统方案的本质区别

| 维度 | 传统驱动分析 | DEVOPS_driver |
|------|-------------|---------------|
| 分析深度 | 人工 IDA 逆向，数天/驱动 | 37 个插件自动并行，分钟级 |
| 漏洞发现 | 依赖分析师经验 | 规则引擎 + 污点追踪 + AI 研判三重保障 |
| 利用验证 | 手动编写 PoC | 自动生成 ctypes PoC，一键复现 |
| AI 集成 | 无 | OVOIDA Agent 综合研判 + PoC 生成 |
| 覆盖面 | 单驱动分析 | 多驱动关联 + 跨驱动攻击链检测 |

---

## 🏗️ 完整架构全景图

```
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                       DEVOPS_driver — 完整架构全景图                                   ║
╠══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                      ║
║   输入: .sys / .exe / .dll / .ocx (单文件或目录)                                       ║
║        │                                                                             ║
║        ▼                                                                             ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐    ║
║  │                           CLI / GUI 入口层                                   │    ║
║  │  python -m src  pipeline | scan | deep | reverse | agent | validate         │    ║
║  │  launcher.py (Tkinter GUI)  │  agent_cli.py (对话式 REPL)                    │    ║
║  └────────────────────────────────┬────────────────────────────────────────────┘    ║
║                                   │                                                ║
║              ┌────────────────────┼────────────────────┐                            ║
║              ▼                    ▼                    ▼                             ║
║  ┌─────────────────┐ ┌─────────────────────┐ ┌──────────────────────┐              ║
║  │  Phase 1:        │ │  Phase 2:           │ │  reverse 模式        │              ║
║  │  DriverScope     │ │  OVOIDA Agent       │ │  (跳过评分)          │              ║
║  │  静态批量扫描     │ │  AI 深度逆向        │ │  直接调用 LLM API    │              ║
║  └────────┬────────┘ └──────────┬──────────┘ └──────────┬───────────┘              ║
║           │                     │                        │                          ║
║           ▼                     ▼                        ▼                          ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐    ║
║  │                        Layer 1: 样本摄取 (ingestion/)                        │    ║
║  │  pe_parser.py (内核驱动)  │  usermode_parser.py (用户态 PE)                   │    ║
║  │  signature.py (签名验证)  │  自动检测: sys/exe/dll/ocx + 架构 + 编译时间      │    ║
║  └────────────────────────────────┬────────────────────────────────────────────┘    ║
║                                   │                                                ║
║                                   ▼                                                ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐    ║
║  │                     Layer 2: 反汇编 & IR (disassembly/)                      │    ║
║  │  ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────┐    │    ║
║  │  │  Capstone Backend    │  │  Ghidra Backend      │  │  API Resolver   │    │    ║
║  │  │  快速模式匹配        │  │  全量反编译 + CFG     │  │  IAT/EAT 解析   │    │    ║
║  │  │  指令级语义分析       │  │  伪代码 + 类型推断    │  │  vtable 解析    │    │    ║
║  │  └──────────────────────┘  └──────────────────────┘  └─────────────────┘    │    ║
║  │  minifilter_detector.py  │  vtable_resolver.py                               │    ║
║  └────────────────────────────────┬────────────────────────────────────────────┘    ║
║                                   │                                                ║
║                                   ▼                                                ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐    ║
║  │                    Layer 3: 分析引擎 (analysis/) — 37 个插件                  │    ║
║  │                                                                              │    ║
║  │  ┌─── Core Analyzers (28 个) ──────────────────────────────────────────┐    │    ║
║  │  │  ioctl_analyzer         structure_analyzer       primitive_analyzer  │    │    ║
║  │  │  hook_analyzer          dkom_detector            integrity_detector  │    │    ║
║  │  │  semantic_analyzer      anti_obfuscation         vmp_detector        │    │    ║
║  │  │  vmx_detector           apc_detector             alpc_detector       │    │    ║
║  │  │  namedpipe_detector     object_callback_detector registry_callback   │    │    ║
║  │  │  string_analyzer        pseudocode_analyzer      coverage            │    │    ║
║  │  │  correlator             multi_driver_correlator  protocol_analyzer   │    │    ║
║  │  │  api_hash_bruteforce    string_decryptor         usermode_analyzer   │    │    ║
║  │  │  arm64                  dependency_graph         fp_baseline         │    │    ║
║  │  │  anti_debug_detector    constraint_solver        deobfuscation       │    │    ║
║  │  │  import_graph           cfg_utils                                    │    │    ║
║  │  └──────────────────────────────────────────────────────────────────────┘    │    ║
║  │                                                                              │    ║
║  │  ┌─── Deep Analyzers (16 个) ──────────────────────────────────────────┐    │    ║
║  │  │  call_chain_analyzer    callback_resolver        cff_analyzer        │    │    ║
║  │  │  comm_protocol_analyzer comparison_tracer        data_content        │    │    ║
║  │  │  data_structure         dkom_detector            dse_pg_detector     │    │    ║
║  │  │  filter_driver          memory_map_analyzer      minifilter_rules    │    │    ║
║  │  │  stack_string           struct_inference         wide_string         │    │    ║
║  │  │  xref_tracker           ovoida_engine                                │    │    ║
║  │  └──────────────────────────────────────────────────────────────────────┘    │    ║
║  │                                                                              │    ║
║  │  ┌─── Dataflow ──────────────┐  ┌─── Dynamic ──────────────────────┐        │    ║
║  │  │  input_tracker (taint)    │  │  sandbox (QEMU)  │  debugger      │        │    ║
║  │  │  struct_tracker           │  │  monitor         │  validator     │        │    ║
║  │  └───────────────────────────┘  │  service         │  sandbox_setup │        │    ║
║  │                                  └──────────────────────────────────┘        │    ║
║  │                                                                              │    ║
║  │  ┌─── Filter Funnel ────────────────────────────────────────────────┐       │    ║
║  │  │  L0: 枚举 → L1: 签名白名单 → L2: Import 评分 → L3: 轻量反汇编    │       │    ║
║  │  │  → L4: LolDrivers 匹配 → L5: 白名单过滤 → 最终候选               │       │    ║
║  │  └──────────────────────────────────────────────────────────────────┘       │    ║
║  └────────────────────────────────┬────────────────────────────────────────────┘    ║
║                                   │                                                ║
║                                   ▼                                                ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐    ║
║  │                     Layer 4: 评分 & 报告 (scoring/ + report/)                │    ║
║  │  scoring/engine.py (BYOVD 风险评分)  │  exploitability_scorer.py             │    ║
║  │  calibration.py (评分校准)           │                                      │    ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐     │    ║
║  │  │  JSON    │ │  HTML    │ │ Markdown │ │  SARIF   │ │ Attack Graph │     │    ║
║  │  │  报告    │ │  报告    │ │  报告    │ │ CodeQL   │ │  DOT 攻击图  │     │    ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────┘     │    ║
║  │  poc_generator.py (PoC 自动生成: Python ctypes / C)                         │    ║
║  └────────────────────────────────┬────────────────────────────────────────────┘    ║
║                                   │                                                ║
║                                   ▼                                                ║
║  ┌─────────────────────────────────────────────────────────────────────────────┐    ║
║  │                        基础设施层                                             │    ║
║  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐     │    ║
║  │  │ models   │ │ config   │ │ intel/   │ │ cache    │ │ utils/       │     │    ║
║  │  │ 数据模型  │ │ 配置管理  │ │ LolDrivers│ │ 分析缓存  │ │ IOCTL 工具   │     │    ║
║  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────┘     │    ║
║  │  ┌──────────────────────────────────────────────────────────────────┐      │    ║
║  │  │  components/ovoida (Node.js TypeScript Agent) — AI 深度逆向引擎  │      │    ║
║  │  │  components/BYOVD_detect (Python 分析引擎备份)                     │      │    ║
║  │  └──────────────────────────────────────────────────────────────────┘      │    ║
║  └─────────────────────────────────────────────────────────────────────────────┘    ║
║                                                                                      ║
║   输出: workspace/reports/  (JSON + HTML + Markdown + SARIF + DOT)                    ║
║          workspace/sessions/ (OVOIDA 会话: context.json + findings + PoC)             ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 🧩 核心模块详解

### Phase 1: DriverScope 静态扫描引擎

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        DriverScope 静态扫描引擎                           │
│                                                                          │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────┐  │
│  │  Ingestion │ -> │ Disassembly│ -> │  37 Plugins│ -> │  Scoring   │  │
│  │  PE 解析    │    │ Capstone/  │    │  并行执行   │    │  风险评分   │  │
│  │  签名验证   │    │ Ghidra     │    │  37 个分析器 │    │  0-10 分   │  │
│  └────────────┘    └────────────┘    └────────────┘    └────────────┘  │
│                                                                          │
│  IOCTL 暴露面  │  内核原语检测  │  污点追踪  │  攻击链构建  │  PoC 生成  │
└──────────────────────────────────────────────────────────────────────────┘
```

**37 个分析器分类：**

| 类别 | 分析器 | 检测能力 |
|------|--------|----------|
| **IOCTL 入口面** | `ioctl_analyzer`, `structure_analyzer`, `protocol_analyzer` | IOCTL code 提取、handler 映射、transfer method 识别 |
| **危险内核原语** | `primitive_analyzer`, `semantic_analyzer`, `correlator` | MmMapIoSpace, KeWriteMsr, MmCopyVirtualMemory 等 50+ 危险 API |
| **内核对象操作** | `dkom_detector`, `hook_analyzer`, `integrity_detector` | DKOM、inline/SSDT/IDT hook、代码完整性自检 |
| **进程/线程注入** | `apc_detector`, `alpc_detector`, `namedpipe_detector` | APC 注入、ALPC 通信、命名管道 IPC |
| **回调 & 注册** | `object_callback_detector`, `registry_callback_detector`, `callback_resolver` | ObRegisterCallbacks, CmRegisterCallback |
| **文件系统** | `filter_driver_analyzer`, `minifilter_rule_extractor` | MiniFilter FLT_REGISTRATION 解析 |
| **反分析 & 保护** | `anti_obfuscation`, `anti_debug_detector`, `vmp_detector`, `string_decryptor` | 控制流平坦化、VMProtect、字符串加密 |
| **虚拟化 & 底层** | `vmx_detector`, `ept_vm_detector`, `arm64` | VT-x/EPT、ARM64 特殊指令 |
| **深度分析** | `call_chain_analyzer`, `xref_tracker`, `struct_inference` | IOCTL → API 调用链、交叉引用、结构推断 |
| **用户态** | `usermode_analyzer` | 危险导入检测（CreateRemoteThread, WriteProcessMemory 等） |
| **关联分析** | `multi_driver_correlator`, `dependency_graph`, `import_graph` | 跨驱动攻击链、依赖图、导入图 |

### Phase 2: OVOIDA AI 深度逆向 Agent

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     OVOIDA AI 深度逆向 Agent                              │
│                                                                          │
│  Phase 1 结果                                                            │
│       │                                                                  │
│       ▼                                                                  │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────┐  │
│  │  Context   │ -> │  LLM API   │ -> │  综合研判   │ -> │  PoC 生成  │  │
│  │  构建       │    │ DeepSeek/  │    │  置信度评估  │    │  Python/C  │  │
│  │  结构化输入  │    │ GPT/Claude │    │  链验证     │    │  ctypes    │  │
│  └────────────┘    └────────────┘    └────────────┘    └────────────┘  │
│                                                                          │
│  输入: findings + functions + IOCTL handlers + taint data                │
│  输出: findings.json + findings.md + poc.py + triage.txt                 │
└──────────────────────────────────────────────────────────────────────────┘
```

- 支持 **DeepSeek / OpenAI / Claude** 等任意 OpenAI 兼容 API
- 自动构建结构化 context.json（完整 findings、函数列表、IOCTL 映射）
- AI 对每条攻击链给出置信度评估（High / Medium / Low）
- 自动生成可执行的 ctypes PoC 代码

### reverse 模式: 通用 AI 逆向

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     reverse 模式 (通用 PE 逆向)                           │
│                                                                          │
│  任意 PE 文件                                                            │
│       │                                                                  │
│       ▼                                                                  │
│  ┌────────────┐    ┌────────────┐    ┌────────────────────────────────┐ │
│  │  PE 解析    │ -> │ 上下文构建  │ -> │  LLM API (直接调用, 无评分)   │ │
│  │  导入/导出  │    │ imports +  │    │  功能分析 + 技术细节 + 风险    │ │
│  │  字符串提取  │    │ exports +  │    │  评估 + 综合结论               │ │
│  └────────────┘    │ strings    │    └────────────────────────────────┘ │
│                     └────────────┘                                      │
│                                                                          │
│  输出: AI 详细分析报告 (中文)                                             │
│  适用: .exe / .dll / .sys — 不区分驱动还是用户态                          │
└──────────────────────────────────────────────────────────────────────────┘
```

**跳过 BYOVD 评分**，直接把 PE 的 imports/exports/strings 发给 AI 做全面分析。适合逆向分析普通 exe/dll。

### 动态验证框架

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       动态验证框架 (dynamic/)                             │
│                                                                          │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────┐  │
│  │   QEMU     │    │   WinDbg   │    │   KDNET    │    │  Sandbox   │  │
│  │   沙箱      │    │   内核调试  │    │  远程调试   │    │  隔离环境   │  │
│  └────────────┘    └────────────┘    └────────────┘    └────────────┘  │
│                                                                          │
│  monitor.py  │  debugger.py  │  sandbox.py  │  validator.py             │
└──────────────────────────────────────────────────────────────────────────┘
```

### 报告 & PoC 生成

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       报告 & PoC 生成                                     │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │  JSON    │  │  HTML    │  │ Markdown │  │  SARIF   │  │  DOT    │ │
│  │  结构化   │  │  可视化   │  │  可读性   │  │  CodeQL  │  │ 攻击图  │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                                          │
│  poc_generator.py: 基于攻击链自动生成 PoC                                 │
│  ├── Python ctypes PoC (CreateFile + DeviceIoControl)                    │
│  ├── C PoC (Win32 API 直接调用)                                          │
│  └── 支持 50+ 危险 API 的专用 payload 模板                               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### 环境要求

**必需：**
- **Python 3.10+** — [下载地址](https://www.python.org/downloads/)
  - ⚠️ 安装时勾选 **"Add Python to PATH"**
- **Node.js 18+** (LTS) — [下载地址](https://nodejs.org/)（OVOIDA AI Agent 需要）
- **Windows 10/11** (x64/ARM64)
- **Git** — [下载地址](https://git-scm.com/)

**可选：**
- **Ghidra 11.3+** — [下载地址](https://ghidra-sre.org/)（深度反编译需要，放到项目根目录即可）

### 方式 1：一键安装（推荐）

```powershell
# 1. 克隆仓库
git clone https://github.com/yourusername/DEVOPS_driver.git
cd DEVOPS_driver

# 2. 运行安装向导（自动完成所有配置）
.\setup.ps1
```

**setup.ps1 会自动完成：**
- ✅ 检查 Python 3.10+ 和 Node.js
- ✅ 安装 Python 依赖（`pip install -e .`）
- ✅ 安装 OVOIDA 依赖（`npm install`）
- ✅ 构建 OVOIDA（`npm run build`）
- ✅ 交互式配置 API Key（保存到 `~/.devops_driver/config.json`）
- ✅ 启动 GUI 界面

### 方式 2：手动安装

```powershell
# 1. 克隆仓库
git clone https://github.com/yourusername/DEVOPS_driver.git
cd DEVOPS_driver

# 2. 安装 Python 依赖（开发模式）
pip install -e .

# 3. 安装 OVOIDA（可选，AI 功能需要）
cd components\ovoida
npm install
npm run build
cd ..\..

# 4. 验证安装
python -m src --help
python -m src list-analyzers  # 应显示 37 个分析器
```

### 配置 AI API

**方式 1：环境变量（永久生效）**

```powershell
# PowerShell（管理员）
[System.Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-xxx", "User")
[System.Environment]::SetEnvironmentVariable("OPENAI_BASE_URL", "https://api.deepseek.com/v1", "User")
# 重启终端生效
```

**方式 2：命令行参数（临时）**

```powershell
python -m src reverse target.exe --ov-url https://api.deepseek.com/v1 --ov-key sk-xxx
```

**方式 3：配置文件（推荐）**

setup.ps1 会自动创建 `~/.devops_driver/config.json`：

```json
{
  "ov_api_url": "https://api.deepseek.com/v1",
  "ov_api_key": "sk-xxx",
  "ov_model": "deepseek-chat"
}
```

### 快速验证

```powershell
# 测试 1：检查环境
python -m src check-env

# 测试 2：列出所有分析器（应显示 37 个）
python -m src list-analyzers

# 测试 3：扫描示例驱动
python -m src scan samples/ --output test_report.json

# 测试 4：逆向单个文件（需要 API Key）
python -m src reverse target.exe --ov-key sk-xxx
```

### 常见问题

**Q: `pip install -e .` 报错**
```powershell
# 确保 Python 3.10+ 且已添加到 PATH
python --version  # 应显示 3.10+
pip install --upgrade pip setuptools wheel
pip install -e .
```

**Q: OVOIDA 构建失败**
```powershell
# 确保 Node.js 18+ 已安装
node --version  # 应显示 v18+
cd components\ovoida
rm -r node_modules  # 清理后重试
npm install
npm run build
```

**Q: Ghidra 反编译超时**
- 确保 Ghidra 已下载并解压到项目根目录
- 或设置环境变量：`$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"`

---

## 📖 使用模式

### 1. 通用 AI 逆向（推荐入门）

跳过 BYOVD 评分，直接对任意 PE 文件做 AI 深度分析：

```bash
# 逆向分析单个 exe
python -m src reverse target.exe \
  --ov-url https://api.deepseek.com/v1 \
  --ov-key sk-xxx \
  --ov-model deepseek-chat

# 逆向分析 DLL
python -m src reverse module.dll \
  --ov-key sk-xxx --output report.json
```

### 2. 对话式 Agent CLI

自然语言交互，Agent 自动调度工具：

```bash
python -m src agent
```

```
你 > 扫描 samples/
你 > 逆向 C:\Windows\System32\drivers\null.sys
你 > 完整流水线 samples/
你 > 设置 API URL https://api.deepseek.com/v1
你 > 设置 API Key sk-xxx
你 > 帮助
```

### 3. BYOVD 驱动漏洞扫描

```bash
# 快速扫描 (仅 Phase 1)
python -m src scan samples/ --output report.json

# 完整流水线 (Phase 1 + 2 + 3)
python -m src pipeline samples/ \
  --workspace workspace \
  --threshold 5.0 \
  --max-deep 3 \
  --ov-url https://api.deepseek.com/v1 \
  --ov-key sk-xxx \
  --format json html markdown

# 包含用户态 PE
python -m src scan samples/ --usermode --output report.json
```

### 4. Ghidra 深度反编译

```bash
python -m src deep driver.sys --timeout 300 --output deep_result.json
```

### 5. 动态验证

```bash
python -m src validate driver.sys --sandbox --poc poc.py
python -m src validate driver.sys --debugger --windbg "C:\path\to\windbgx.exe"
```

### 6. GUI 界面

```bash
python launcher.py
```

### 7. 环境检查

```bash
python -m src check-env    # 检查 QEMU/WinDbg/KDNET 是否就绪
python -m src list-analyzers  # 列出 37 个分析器
```

---

## 📁 项目结构

```
DEVOPS_driver/
├── src/                              # 核心源码 (120+ 文件)
│   ├── __main__.py                   # CLI 入口
│   ├── main.py                       # 命令解析 + 子命令路由
│   ├── agent_cli.py                  # 对话式 Agent CLI (REPL)
│   ├── models.py                     # 数据模型 (Sample, Finding, Report, ...)
│   │
│   ├── ingestion/                    # Layer 1: 样本摄取
│   │   ├── pe_parser.py              #   内核驱动 PE 解析 (.sys)
│   │   ├── usermode_parser.py        #   用户态 PE 解析 (.exe/.dll)
│   │   └── signature.py              #   Authenticode 签名验证
│   │
│   ├── disassembly/                  # Layer 2: 反汇编 & IR
│   │   ├── backend.py                #   抽象后端接口
│   │   ├── capstone_backend.py       #   Capstone 快速反汇编
│   │   ├── ghidra_backend.py         #   Ghidra 全量反编译
│   │   ├── api_resolver.py           #   IAT/EAT API 解析
│   │   ├── vtable_resolver.py        #   C++ vtable 解析
│   │   └── minifilter_detector.py    #   MiniFilter 结构检测
│   │
│   ├── analysis/                     # Layer 3: 分析引擎
│   │   ├── analyzer.py               #   分析器基类
│   │   ├── cache.py                  #   分析缓存
│   │   ├── pipeline.py               #   批量分析 pipeline
│   │   ├── core/                     #   28 个核心分析器
│   │   │   ├── ioctl_analyzer.py     #     IOCTL 暴露面分析
│   │   │   ├── primitive_analyzer.py #     危险内核原语检测
│   │   │   ├── hook_analyzer.py      #     Hook 检测 (inline/SSDT/IDT)
│   │   │   ├── dkom_detector.py      #     DKOM 检测
│   │   │   ├── semantic_analyzer.py  #     指令级语义分析
│   │   │   ├── anti_obfuscation.py   #     反混淆检测
│   │   │   ├── vmp_detector.py       #     VMProtect 检测
│   │   │   ├── vmx_detector.py       #     VT-x/EPT 检测
│   │   │   ├── usermode_analyzer.py  #     用户态危险 API 检测
│   │   │   └── ...                   #     (共 28 个)
│   │   ├── deep/                     #   16 个深度分析器
│   │   │   ├── call_chain_analyzer.py#     IOCTL → API 调用链
│   │   │   ├── ovoida_engine.py      #     Python OVOIDA 引擎
│   │   │   ├── dse_pg_detector.py    #     DSE/PG bypass 检测
│   │   │   └── ...                   #     (共 16 个)
│   │   ├── dataflow/                 #   数据流分析
│   │   │   ├── input_tracker.py      #     污点追踪 (taint)
│   │   │   └── struct_tracker.py     #     结构体追踪
│   │   ├── dynamic/                  #   动态验证
│   │   │   ├── sandbox.py            #     QEMU 沙箱
│   │   │   ├── debugger.py           #     WinDbg 调试器
│   │   │   ├── monitor.py            #     行为监控
│   │   │   └── validator.py          #     PoC 验证器
│   │   └── funnel/                   #   漏斗式过滤
│   │       └── stages/               #     L0->L1->L2->L3->L4->L5
│   │
│   ├── scoring/                      # Layer 4: 评分
│   │   ├── engine.py                 #   BYOVD 风险评分引擎
│   │   ├── exploitability_scorer.py  #   可利用性评分
│   │   └── calibration.py            #   评分校准
│   │
│   ├── report/                       # 报告生成
│   │   ├── html.py                   #   HTML 可视化报告
│   │   ├── markdown.py               #   Markdown 报告
│   │   ├── sarif.py                  #   SARIF (CodeQL 格式)
│   │   ├── poc_generator.py          #   PoC 自动生成
│   │   ├── attack_graph.py           #   DOT 攻击图
│   │   └── cfg_visualizer.py         #   CFG 可视化
│   │
│   ├── pipeline/                     # 三阶段流水线编排
│   │   └── __init__.py               #   Phase 1 + 1.5 + 2 + 3
│   │
│   ├── gui/                          # GUI 界面
│   │   ├── app.py                    #   Tkinter 主窗口
│   │   ├── agent.py                  #   Agent 意图解析引擎
│   │   ├── controller.py             #   子进程控制器
│   │   ├── result_widgets.py         #   结果展示组件
│   │   └── styles.py                 #   样式常量
│   │
│   ├── config/                       # 配置管理
│   │   ├── defaults.py               #   默认配置 + 规则集
│   │   ├── user.py                   #   用户配置加载
│   │   └── dynamic.py                #   动态配置
│   │
│   ├── intel/                        # 威胁情报
│   │   ├── loldrivers.py             #   LolDrivers 已知恶意驱动匹配
│   │   └── base.py                   #   情报接口
│   │
│   └── utils/                        # 工具函数
│       └── ioctl.py                  #   IOCTL code 编解码
│
├── components/
│   ├── ovoida/                       # OVOIDA Node.js Agent (TypeScript)
│   │   ├── dist/bin/ovogogogo.js     #   编译后的 Agent 入口
│   │   └── src/                      #   TypeScript 源码
│   └── BYOVD_detect/                 # Python 分析引擎 (备份)
│
├── tests/                            # 测试套件 (2100+ tests)
│   ├── analysis/                     #   分析器单元测试
│   ├── disassembly/                  #   反汇编测试
│   ├── ingestion/                    #   PE 解析测试
│   ├── scoring/                      #   评分测试
│   ├── report/                       #   报告生成测试
│   └── ...
│
├── ghidra_11.3.1_PUBLIC/             # Ghidra 反汇编器 (via junction)
├── ghidra_12.1_PUBLIC/               # Ghidra 最新版 (via junction)
├── docs/                             # 项目文档
├── rules/                            # 分析规则集
├── signatures/                       # 签名规则库
├── tools/                            # 辅助工具
├── scripts/                          # 脚本
├── samples/                          # 测试样本
├── workspace/                        # 输出目录
│   ├── reports/                      #   分析报告
│   └── sessions/                     #   OVOIDA 会话
│
├── launcher.py                       # GUI 启动器
├── setup.ps1                         # 一键安装脚本
├── 启动.bat                          # Windows 快捷启动
└── pyproject.toml                    # Python 项目配置
```

---

## 💡 设计决策

### 为什么分 4 层 Pipeline？

传统工具通常是一步到位（输入 → 输出），DEVOPS_driver 采用 4 层流水线设计：

1. **Ingestion → Disassembly → Analysis → Scoring** — 每层独立可替换
2. **好处**: 可以单独升级某一层（如换 Ghidra 后端），不影响其他层
3. **对比**: IDA Pro 是单体架构，难以扩展

### 为什么用 Capstone + Ghidra 双后端？

- **Capstone**: 速度快（毫秒级），适合批量扫描 + 模式匹配
- **Ghidra**: 全量反编译 + 类型推断，适合单驱动深度分析
- **策略**: 先用 Capstone 批量筛选 → 高风险的用 Ghidra 深入

### 为什么 OVOIDA 用 Node.js Agent？

- Node.js 的 async/streaming 生态更适合长连接 LLM API 调用
- TypeScript 的类型安全适合构建复杂 Agent 工具链
- Python 侧负责确定性分析（IR/CFG/污点），Node.js 侧负责 AI 研判

### 为什么 reverse 模式跳过评分？

- BYOVD 评分专为内核驱动设计（IOCTL 暴露面、内核原语等）
- 普通 exe/dll 没有 IOCTL handler，评分无意义
- reverse 模式直接发 AI 做全面分析，更实用

### 为什么用 Filter Funnel？

- 大量驱动中，大部分是安全的（微软签名、已知白名单）
- 漏斗式过滤（L0→L1→...→L5）快速淘汰安全驱动
- 只把高风险候选送入耗时的深度分析阶段

---

## 🛠️ 技术栈

| 组件 | 技术 | 用途 |
|------|------|------|
| **语言** | Python 3.10+ | 主引擎 |
| **反汇编** | Capstone | 快速模式匹配 + 指令级分析 |
| **反编译** | Ghidra 11.3 / 12.1 | 全量反编译 + CFG + 伪代码 |
| **PE 解析** | pefile | PE 格式解析、IAT/EAT/资源提取 |
| **AI Agent** | OVOIDA (Node.js/TS) | LLM 驱动的逆向分析 Agent |
| **LLM API** | DeepSeek / OpenAI / Claude | AI 研判 + PoC 生成 |
| **GUI** | Tkinter + ttk | 桌面操作界面 |
| **CLI Agent** | 自研 REPL | 对话式逆向分析 |
| **沙箱** | QEMU | 动态分析隔离环境 |
| **调试器** | WinDbg + KDNET | 内核调试 |
| **报告** | JSON / HTML / Markdown / SARIF / DOT | 多格式输出 |
| **测试** | pytest | 2100+ 单元测试 |
| **CI/CD** | GitHub Actions | 自动化测试 |

---

## 🧪 测试

```bash
# 运行全部测试
python -m pytest tests/ -v

# 运行特定模块测试
python -m pytest tests/analysis/ -v
python -m pytest tests/scoring/ -v

# 覆盖率
python -m pytest tests/ --cov=src --cov-report=html
```

**测试覆盖**: 2100+ tests, 覆盖全部 37 个分析器 + 评分引擎 + 报告生成 + CLI 命令

---

## 🔒 安全声明

本工具仅用于**安全研究和授权测试**。

- ⚠️ 不得用于未授权系统的漏洞挖掘
- ⚠️ 生成的 PoC 仅用于验证漏洞存在，不得用于实际攻击
- ⚠️ 使用者需自行承担法律责任

---

## 📄 License

MIT License

---

<div align="center">

**⭐ 如果这个项目对你有帮助，请给个 Star！**

[GitHub](https://github.com/atreasureboy/above_agent) | [Issues](https://github.com/atreasureboy/above_agent/issues) | [Docs](docs/)

</div>
