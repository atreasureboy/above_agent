# 动态分析增强方案 — 混淆/加壳样本处理

> **目标**：让 DriverScope 具备处理高度混淆、加壳样本的完整能力链
> **原则**：在现有架构上增量迭代，不破坏已稳定的静态分析管线

---

## 一、现状评估

### 已有能力（✅ 可直接利用）

| 模块 | 文件 | 状态 |
|------|------|------|
| 壳/混淆**检测** | `src/analysis/core/anti_obfuscation.py` | ✅ 完整（UPX/MPRESS 签名、熵分析、CFF、死代码注入、API hashing、字符串加密） |
| QEMU 沙箱框架 | `src/analysis/dynamic/sandbox.py` | ⚠️ 骨架完整，但 `copy_file_to_vm` / `execute_command` 是 stub |
| WinDbg 调试器 | `src/analysis/dynamic/debugger.py` | ✅ 基本可用（断点管理、寄存器转储、崩溃检测） |
| 系统状态监控 | `src/analysis/dynamic/monitor.py` | ✅ 可用（WMI 查询设备/进程/注册表 diff） |
| 驱动服务控制 | `src/analysis/dynamic/service.py` | ✅ 可用（ctypes 直调 SCM API，加载/卸载内核驱动） |
| 动态验证编排 | `src/analysis/dynamic/validator.py` | ✅ 编排层已就位 |
| 环境检查 | `src/analysis/dynamic/sandbox_setup.py` | ✅ 可用 |

### 缺失能力（❌ 需要新增）

```
                        当前管线
                        ═══════
输入 .sys ──→ [静态分析 37 个分析器] ──→ 评分报告
                  ↑ 遇到加壳/混淆样本时：
                  只能报告"检测到 VMProtect"
                  无法继续分析壳内代码

                        需要的管线
                        ════════
输入 .sys ──→ [Phase 0: 预处理] ──→ [静态分析] ──→ [动态分析] ──→ 评分报告
               脱壳/反混淆            ↑ 干净二进制    ↑ 行为验证
```

---

## 二、总体架构设计

### 新增 Phase 0：预处理层（Pre-processing Layer）

```
src/analysis/
├── preprocessing/                   ← 新增目录
│   ├── __init__.py
│   ├── packer_classifier.py         ← 壳分类器（扩展 anti_obfuscation.py 的检测结果）
│   ├── static_unpacker.py           ← 静态脱壳引擎
│   │   ├── UPXUnpacker              ← UPX 自动脱壳
│   │   ├── MPRESSUnpacker           ← MPRESS 脱壳
│   │   └── GenericPEUnpacker        ← 通用 PE 重建
│   ├── dynamic_unpacker.py          ← 动态脱壳引擎
│   │   ├── OEPDetector              ← OEP 自动检测
│   │   ├── IATReconstructor         ← IAT 重建
│   │   └── MemoryDumper             ← 内存转储 + PE 修复
│   ├── deobfuscator.py              ← 反混淆引擎
│   │   ├── CFFDeflatten             ← 控制流平坦化展平
│   │   ├── DeadCodeRemover          ← 死代码移除
│   │   ├── StringDecryptor          ← 字符串解密（已部分存在于 deep/）
│   │   └── APIHashResolver          ← API hash 解析（已部分存在于 deep/）
│   └── pipeline.py                  ← 预处理管线编排
│
├── dynamic/                         ← 现有目录，需要增强
│   ├── sandbox.py                   ← 修复 stub + 增强反检测
│   ├── debugger.py                  ← 增强 x64dbg 集成
│   ├── frida_engine.py              ← 【新增】Frida 动态插桩
│   ├── anti_evasion.py              ← 【新增】反反分析引擎
│   ├── memory_analyzer.py           ← 【新增】内存分析引擎
│   └── cape_bridge.py               ← 【新增】CAPE sandbox 桥接
│
└── existing files...
```

---

## 三、分阶段实施计划

### 🟢 第一阶段：QEMU 沙箱补全 + 静态脱壳（2-3 天）

**目标**：让现有沙箱真正可用 + 处理简单壳

#### 1.1 修复 QEMU Sandbox Stubs

**文件**：`src/analysis/dynamic/sandbox.py`

```python
# 当前 stub:
def copy_file_to_vm(self, host_path, guest_path):
    logging.info("[sandbox] Would copy %s -> %s", host_path, guest_path)
    return True  # ← 什么都没做！

# 修复方案：通过 QEMU Guest Agent 实现真实文件传输
def copy_file_to_vm(self, host_path: str, guest_path: str) -> bool:
    """通过 virtio-serial + guest agent 传输文件"""
    # 方案 A: QEMU Guest Agent (qga) via virtio-serial
    #   需要 VM 内安装 qemu-ga.msi
    #   通过 qemu monitor socket 发送 guest-file-open/write/close
    
    # 方案 B: 9p virtio 共享目录
    #   启动 QEMU 时挂载 -virtfs local,path=/shared,mount_tag=host0
    #   Windows guest 内安装 VirtIO-Win 驱动
    
    # 方案 C: 通过已有网络（user mode SLIRP）+ SMB/WinRM
    #   最简单但需要 guest 网络配置
    
    # 推荐：方案 B (9p) + 方案 A (qga) 双保险
```

**同时修复 `execute_command`**：
```python
def execute_command(self, cmd: str, timeout: int = 30) -> str:
    """通过 QEMU Guest Agent 执行命令"""
    # qemu monitor → guest-exec → guest-exec-status → 获取输出
    # 或通过 WinRM/SSH 连接 guest
```

#### 1.2 静态脱壳引擎

**文件**：`src/analysis/preprocessing/static_unpacker.py`

```python
class UPXUnpacker:
    """UPX 自动脱壳 — 纯 Python 实现"""
    
    # UPX 是最常见的壳，有成熟的开源方案
    # 方案 A: 调用 upx -d（需要 upx 二进制）
    # 方案 B: 纯 Python UPX 解压（解析 LZMA/NRV2B 压缩段）
    # 推荐：方案 A 为主 + 方案 B 为 fallback
    
    def can_handle(self, sample: Sample) -> bool:
        """检查是否是 UPX 壳"""
        # 检查 section names: UPX0, UPX1, UPX2
        # 检查 imports: 只有 kernel32.dll 的几个 API
        # 检查 entropy: UPX 段 entropy > 6.5
    
    def unpack(self, sample_path: Path) -> Path:
        """执行脱壳，返回解压后的 PE 路径"""
        # 1. upx -d sample.sys -o sample_unpacked.sys
        # 2. 验证解压后的 PE 有效性
        # 3. 返回新路径


class GenericPEUnpacker:
    """通用 PE 重建 — 处理未知壳的基础"""
    
    def rebuild_pe(self, memory_dump: bytes, image_base: int) -> Path:
        """从内存 dump 重建 PE 文件"""
        # 1. 解析 PE headers（从 image_base 偏移）
        # 2. 按 section alignment 对齐各段
        # 3. 修复 IAT（如果已解析）
        # 4. 重建 import table
        # 5. 设置正确的 entry point
```

#### 1.3 反混淆引擎（利用已有代码）

**文件**：`src/analysis/preprocessing/deobfuscator.py`

```python
# 项目中已有部分能力：
# - src/analysis/deep/string_decryptor.py → 字符串解密
# - src/analysis/deep/api_hash_bruteforce.py → API hash 解析
# - src/analysis/core/anti_obfuscation.py → CFF 检测

# 需要新增：
class CFFDeflatten:
    """控制流平坦化还原"""
    # 基于已有的 CFG 分析能力
    # 识别 state variable + dispatch block
    # 将平坦化的 switch-case 还原为原始顺序
    
    def deflatten(self, func_addr: int, ir: DisassemblyResult) -> str:
        """返回去平坦化后的伪代码"""
        # 1. 识别 dispatch block（已有检测逻辑）
        # 2. 提取各 real block 之间的执行顺序
        # 3. 重建原始控制流
        # 4. 输出简化后的伪代码
```

---

### 🟡 第二阶段：动态脱壳 + Frida 集成（3-5 天）

**目标**：处理 VMProtect/Themida 等商业壳

#### 2.1 Frida 动态插桩引擎

**文件**：`src/analysis/dynamic/frida_engine.py`

```python
class FridaEngine:
    """Frida 动态插桩 — 处理复杂加壳样本"""
    
    # Frida 是目前最强的动态插桩框架
    # 可以在运行时 hook 任意函数、dump 内存、追踪执行流
    
    def __init__(self):
        self.device = None
        self.session = None
    
    def attach_to_process(self, pid: int) -> bool:
        """附加到目标进程"""
        import frida
        self.device = frida.get_local_device()
        self.session = self.device.attach(pid)
    
    def trace_oep(self, target_path: str) -> int:
        """追踪 OEP（Original Entry Point）"""
        # 1. 在 VirtualProtect/PAGE_EXECUTE 上设置断点
        # 2. 监控代码段首次变为可执行
        # 3. 记录该地址 = OEP
        
        script = """
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualProtect'), {
            onEnter: function(args) {
                var size = args[2].toInt32();
                var protect = args[3].toInt32();
                // PAGE_EXECUTE_READWRITE = 0x40
                if ((protect & 0x40) && size > 0x1000) {
                    send({type: 'oep_candidate', addr: args[0], size: size});
                }
            }
        });
        """
        # 返回检测到的 OEP 地址
    
    def dump_unpacked_memory(self, pid: int, image_base: int, size: int) -> bytes:
        """从内存中 dump 脱壳后的代码"""
        script = f"""
        var base = ptr(0x{image_base:X});
        var data = base.readByteArray(0x{size:X});
        send({{type: 'memory_dump', data: data}});
        """
        # 返回原始内存数据
    
    def hook_api_calls(self, pid: int) -> list[dict]:
        """Hook 关键 API 调用，记录行为"""
        apis = [
            'NtCreateFile', 'NtWriteFile', 'NtReadFile',
            'NtOpenKey', 'NtSetValueKey',
            'NtCreateThreadEx', 'NtWriteVirtualMemory',
            'DeviceIoControl',
        ]
        # 对每个 API 设置 hook，记录参数和调用栈
```

#### 2.2 动态脱壳引擎

**文件**：`src/analysis/preprocessing/dynamic_unpacker.py`

```python
class DynamicUnpacker:
    """动态脱壳 — 在沙箱中执行并 dump 脱壳后的二进制"""
    
    def __init__(self, sandbox: SandboxManager, frida: FridaEngine):
        self.sandbox = sandbox
        self.frida = frida
    
    def unpack(self, sample_path: Path) -> Path:
        """完整动态脱壳流程"""
        # 1. 将样本复制到 QEMU VM 内
        # 2. 在 VM 内启动样本（作为服务加载或用户态执行）
        # 3. Frida 附加到进程
        # 4. OEPDetector 检测原始入口点
        # 5. OEP 到达时 MemoryDumper dump 内存
        # 6. IATReconstructor 重建导入表
        # 7. 从 VM 中取回 dump 文件
        # 8. 返回修复后的 PE 文件路径
    
    def _detect_oep_frida(self) -> int:
        """Frida 方式检测 OEP"""
        # 监控 PAGE_EXECUTE 变化
        # 或监控最后一次 pushad/popad 后的 JMP
    
    def _detect_oep_debugger(self) -> int:
        """WinDbg 方式检测 OEP"""
        # 使用 WinDbg 的 sxe ld 断点
        # 或使用 Step-Into 追踪到 OEP


class IATReconstructor:
    """导入地址表重建"""
    
    def rebuild(self, dump_data: bytes, original_imports: list[str]) -> bytes:
        """重建 IAT"""
        # 1. 扫描 dump 中的 thunk 数组
        # 2. 解析每个 thunk 指向的 API
        # 3. 重建 Import Directory Table
        # 4. 修复 ILT/IAT 指针
```

---

### 🔴 第三阶段：反反分析 + CAPE 集成（3-5 天）

**目标**：对抗样本的反调试/反VM 技术

#### 3.1 反反分析引擎

**文件**：`src/analysis/dynamic/anti_evasion.py`

```python
class AntiEvasionEngine:
    """反反分析 — 让样本无法检测分析环境"""
    
    # 样本常见的反分析技术：
    # 1. IsDebuggerPresent / NtQueryInformationProcess
    # 2. 检查注册表中的 VM 标志
    # 3. 检查 MAC 地址（VMware/VirtualBox OUI）
    # 4. CPUID 指令检测 hypervisor
    # 5. 检查进程名（wireshark, procmon, x64dbg...）
    # 6. 时间差检测（rdtsc 指令）
    
    class DebuggerHider:
        """隐藏调试器"""
        
        PATCHES = {
            # kernel32.dll!IsDebuggerPresent → mov eax, 0; ret
            'IsDebuggerPresent': b'\\x31\\xC0\\xC3',
            # kernel32.dll!CheckRemoteDebuggerPresent → mov [rdx], 0; mov eax, 1; ret
            'CheckRemoteDebuggerPresent': b'\\xC7\\x02\\x00\\x00\\x00\\x00\\x31\\xC0\\xC3',
            # NtQueryInformationProcess → 修改 ProcessDebugPort 返回 0
        }
        
        def apply_patches(self, target_pid: int):
            """Frida inline patch — 在目标进程内 patch API"""
    
    class VMHider:
        """隐藏虚拟化环境"""
        
        # QEMU/KVM 反检测：
        # 1. 修改 SMBIOS 数据（去掉 QEMU 标识）
        # 2. 修改 CPUID hypervisor vendor
        # 3. 修改注册表中的硬件 ID
        # 4. 修改 MAC 地址为真实网卡 OUI
        
        QEMU_SIGNATURES = [
            b'QEMU', b'Bochs', b'QEMU CPU',
            b'virtio', b'red hat',
        ]
        
        def scrub_vm_artifacts(self, sandbox: SandboxManager):
            """清除 VM 内的虚拟化痕迹"""
    
    class TimingDefeater:
        """绕过时间检测"""
        
        def accelerate_time(self, sandbox: SandboxManager, factor: int = 10):
            """加速 VM 内的时间流逝"""
            # 修改 rdtsc 的返回值
            # 或修改 Windows 定时器分辨率


class AntiAntiDebug:
    """对抗反调试技术的专用模块"""
    
    def patch_ntquery(self, frida_session):
        """
        Hook NtQueryInformationProcess:
        - ProcessDebugPort (0x07) → 返回 0
        - ProcessDebugObjectHandle (0x1E) → 返回 STATUS_PORT_NOT_SET
        - ProcessDebugFlags (0x1F) → 返回 1 (PROCESS_DEBUG_INACTIVE)
        """
    
    def patch_output_debug_string(self, frida_session):
        """
        Hook OutputDebugString:
        某些反调试利用 OutputDebugString + GetLastError
        """
    
    def hook_set_info_thread(self, frida_session):
        """
        Hook NtSetInformationThread:
        ThreadHideFromDebugger (0x11) → 阻止样本隐藏线程
        """
```

#### 3.2 CAPE Sandbox 桥接

**文件**：`src/analysis/dynamic/cape_bridge.py`

```python
class CAPEBridge:
    """CAPE Sandbox 集成 — 全自动行为分析"""
    
    # CAPE 是目前最先进的恶意软件行为分析沙箱
    # 可以自动：
    # - 脱壳（内置多种 unpacker）
    # - 行为监控（API call trace）
    # - 网络抓包
    # - 内存 dump
    # - 生成 MITRE ATT&CK 映射
    
    def __init__(self, cape_url: str = "http://localhost:8090"):
        self.api_url = cape_url
    
    def submit_sample(self, sample_path: Path, timeout: int = 300) -> str:
        """提交样本到 CAPE，返回 task_id"""
        import requests
        files = {"file": open(sample_path, "rb")}
        data = {"timeout": timeout, "options": "unpacker=yes"}
        resp = requests.post(f"{self.api_url}/tasks/create/file",
                           files=files, data=data)
        return resp.json()["task_id"]
    
    def wait_for_result(self, task_id: str, timeout: int = 600) -> dict:
        """等待分析完成，返回完整报告"""
    
    def get_unpacked_binary(self, task_id: str) -> Path:
        """获取 CAPE 自动脱壳后的二进制"""
    
    def get_api_trace(self, task_id: str) -> list[dict]:
        """获取完整 API 调用追踪"""
    
    def get_memory_dumps(self, task_id: str) -> list[Path]:
        """获取内存 dump 文件"""
```

---

### 🔵 第四阶段：管线集成 + 智能路由（2-3 天）

**目标**：将所有能力串成自动化管线

#### 4.1 智能路由决策

```python
class PreprocessingRouter:
    """根据样本特征选择最优分析路径"""
    
    def route(self, sample: Sample) -> AnalysisPlan:
        """决定如何处理这个样本"""
        
        # Step 1: 检查是否加壳
        packer_info = detect_packer(sample.path)
        
        if packer_info["packer_name"] == "UPX":
            return AnalysisPlan(
                steps=[
                    ("static_unpack", "UPXUnpacker"),  # 直接静态脱壳
                    ("static_analysis", "full_pipeline"),  # 然后正常分析
                ]
            )
        
        elif packer_info["packer_name"] in ("VMProtect", "Themida"):
            return AnalysisPlan(
                steps=[
                    ("anti_evasion", "full_stealth"),  # 先准备反检测
                    ("dynamic_unpack", "frida_oep"),  # 动态脱壳
                    ("iat_reconstruct", "auto"),  # IAT 重建
                    ("static_analysis", "full_pipeline"),  # 分析脱壳后
                    ("dynamic_validate", "sandbox"),  # 行为验证
                ]
            )
        
        elif packer_info["high_entropy_sections"]:
            # 未知壳 — 先尝试静态，失败则动态
            return AnalysisPlan(
                steps=[
                    ("static_unpack", "generic"),
                    ("fallback_dynamic_unpack", "auto"),
                    ("static_analysis", "full_pipeline"),
                ]
            )
        
        else:
            # 无壳 — 直接分析
            return AnalysisPlan(
                steps=[("static_analysis", "full_pipeline")]
            )
```

#### 4.2 管线集成

修改 `src/pipeline/__init__.py`：

```python
# 在 Phase 1 之前插入 Phase 0
def run_full_pipeline(config: PipelineConfig) -> PipelineResult:
    """完整管线：Phase 0 → Phase 1 → Phase 2 → Phase 3"""
    
    # Phase 0: 预处理（新增）
    if config.enable_preprocessing:
        from src.analysis.preprocessing import run_preprocessing
        preprocessed = run_preprocessing(config.target)
        # preprocessed 包含：脱壳后的路径、反混淆结果、分类信息
        config.target = preprocessed.cleaned_target
    
    # Phase 1: DriverScope 静态分析（已有）
    scan_result = run_phase1_scan(config)
    
    # Phase 2: OVOIDA 深度分析（已有）
    deep_results = run_phase2_deep(config, scan_result)
    
    # Phase 3: 统一报告（已有）
    return build_unified_report(config, scan_result, deep_results)
```

---

## 四、新增配置项

修改 `src/config/defaults.py`：

```python
# ---------------------------------------------------------------------------
# Phase 0: 预处理配置
# ---------------------------------------------------------------------------

# 启用自动脱壳
ENABLE_AUTO_UNPACK = True

# 静态脱壳工具路径
UPX_BINARY_PATH = ""  # 自动检测 PATH 中的 upx

# 动态脱壳配置
DYNAMIC_UNPACK_TIMEOUT = 120  # 秒
DYNAMIC_UNPACK_BACKEND = "frida"  # "frida" | "debugger" | "cape"

# Frida 配置
FRIDA_SERVER_PATH = ""  # frida-server 路径
FRIDA_PORT = 27042

# CAPE Sandbox 配置
CAPE_API_URL = "http://localhost:8090"
CAPE_SUBMIT_TIMEOUT = 600

# 反反分析配置
ANTI_EVASION_LEVEL = 2
# 0 = 关闭
# 1 = 基本（patch IsDebuggerPresent）
# 2 = 中等（+ VM 痕迹清除）
# 3 = 高级（+ 时间加速 + CPUID spoofing）

# 沙箱反检测
SANDBOX_STEALTH_MODE = True
VM_SMBIOS_SCRUB = True
VM_CPUID_HIDE = True
```

---

## 五、依赖关系

### 新增外部依赖

```toml
# pyproject.toml 新增
[project.optional-dependencies]
dynamic = [
    "frida>=16.0.0",           # 动态插桩
    "frida-tools>=12.0.0",     # Frida CLI 工具
    "capstone>=5.0.1",         # 已有
    "unicorn>=2.0.0",          # CPU 模拟器（用于辅助脱壳）
    "lief>=0.14.0",            # PE/ELF 操作库（IAT 重建）
    "pyvmidump>=0.1",          # VM 内存 dump 解析
]

# 可选外部工具（需手动安装）：
# - QEMU >= 8.0（沙箱执行）
# - WinDbg Preview（内核调试）
# - CAPE Sandbox（行为分析）
# - UPX（静态脱壳）
# - Frida server（VM 内插桩）
```

---

## 六、实施优先级

| 优先级 | 阶段 | 预计时间 | 价值 |
|--------|------|----------|------|
| **P0** | QEMU stub 修复 | 1 天 | 🔥 让现有沙箱真正可用 |
| **P0** | UPX 静态脱壳 | 1 天 | 🔥 处理 60% 的简单壳样本 |
| **P1** | Frida 集成 | 2-3 天 | 🔥 处理商业壳 |
| **P1** | 反反分析引擎 | 2 天 | 🔥 对抗样本反检测 |
| **P2** | CAPE 集成 | 1-2 天 | 全自动行为分析 |
| **P2** | CFF 去平坦化 | 2-3 天 | 处理控制流混淆 |
| **P3** | 智能路由 | 1 天 | 自动化决策 |
| **P3** | 管线集成 | 1 天 | 串联全流程 |

**总计**：约 12-16 天（可分批迭代）

---

## 七、与你现有项目的关系

```
                    你的红队项目体系
                    ════════════════
    
    ┌─────────────┐    ┌──────────────┐    ┌─────────────┐
    │ 靶场自动化    │    │ DEVOPS_driver │    │  Havoc C2   │
    │ (V9 系列)    │    │ (DriverScope) │    │ (修改版)     │
    │             │    │              │    │             │
    │ 外网侦察     │    │ 样本分析      │    │ 后渗透控制   │
    │ 资产发现     │    │ 漏洞挖掘      │    │ 持久化      │
    │ nuclei/ffuf │    │ BYOVD 检测   │    │             │
    └─────────────┘    └──────────────┘    └─────────────┘
                              ↑
                     本次增强的目标
                     让 DriverScope 能处理
                     高度混淆/加壳的样本
```

---

## 八、下一步

**建议从 P0 开始**：
1. 先修复 QEMU sandbox 的两个 stub 方法（1 天）
2. 再加 UPX 静态脱壳（1 天）
3. 这两步完成后，简单壳的样本就能自动处理了

然后逐步迭代 P1（Frida + 反反分析），处理 VMProtect/Themida 级别的商业壳。

你觉得这个方案怎么样？要不要先从 P0 开始动手？
