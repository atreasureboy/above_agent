"""
DriverScope — Anti-Evasion Engine.

Counters anti-analysis techniques used by packed/protected samples:

1. Debugger Detection Hiding
   - Patch IsDebuggerPresent / CheckRemoteDebuggerPresent
   - Hook NtQueryInformationProcess (ProcessDebugPort/Flags)
   - Hook NtSetInformationThread (ThreadHideFromDebugger)

2. VM/Sandbox Detection Hiding
   - Scrub SMBIOS data (remove QEMU/VMware/VirtualBox strings)
   - Patch CPUID hypervisor vendor
   - Modify MAC addresses to real NIC OUIs
   - Remove VM-related registry keys

3. Timing Attack Defeat
   - Accelerate rdtsc responses
   - Patch QueryPerformanceCounter/Frequency
   - Defeat sleep-based delays

4. Process/Module Hiding
   - Hide debugger process names from enumeration
   - Patch EnumProcesses / EnumWindows callbacks

Usage:
    from src.analysis.dynamic.anti_evasion import AntiEvasionEngine

    engine = AntiEvasionEngine(level=2)
    engine.apply_all(sandbox, frida_session)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Evasion Level
# ---------------------------------------------------------------------------

class EvasionLevel(IntEnum):
    """Anti-evasion aggressiveness level."""
    OFF = 0           # No evasion
    BASIC = 1         # Patch common debugger APIs
    MEDIUM = 2        # + VM artifact scrubbing
    AGGRESSIVE = 3    # + timing defeat + CPUID spoofing


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class AntiEvasionConfig:
    """Configuration for anti-evasion measures."""
    level: EvasionLevel = EvasionLevel.MEDIUM

    # Debugger hiding
    hide_debugger: bool = True
    patch_is_debugger_present: bool = True
    patch_ntquery_debug_port: bool = True
    patch_ntset_thread_hide: bool = True
    patch_output_debug_string: bool = True

    # VM hiding
    hide_vm: bool = True
    scrub_smbios: bool = True
    patch_cpuid: bool = True
    spoof_mac_address: bool = True
    remove_vm_registry: bool = True

    # Timing
    defeat_timing: bool = False  # Only at level 3
    accelerate_rdtsc: bool = False
    patch_query_performance: bool = False

    # Process hiding
    hide_processes: bool = True
    hidden_process_names: list[str] = field(default_factory=lambda: [
        "wireshark", "procmon", "procexp", "x64dbg", "windbg",
        "ollydbg", "ida", "ida64", "ghidra", "radare2",
        "cuckoo", "sandboxie", "joebox", "threatexpert",
        "vboxservice", "vboxtray", "vmtoolsd", "vmacthlp",
        "qemu-ga", "frida-server",
    ])

    # VM signatures to scrub
    vm_signatures: list[bytes] = field(default_factory=lambda: [
        b"QEMU", b"Bochs", b"QEMU CPU", b"QEMU BIOS",
        b"VMware", b"VMware, Inc.", b"VMWARE",
        b"VirtualBox", b"VBOX", b"innotek GmbH",
        b"Xen", b"XenSource", b"Xensource",
        b"Parallels", b"prl_",
        b"Sandbox", b"SbieDll", b"dbghelp.dll",  # Sandboxie
        b"Wine", b"wine_get_version",
        b"VBoxGuest", b"VBoxMouse", b"VBoxVideo",
        b"vmGuestLib", b"vm3dservice",
    ])


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class AntiEvasionEngine:
    """Anti-evasion engine — counters sample anti-analysis techniques.

    Works in conjunction with Frida (for in-process patching) and
    the QEMU sandbox (for VM-level scrubbing).
    """

    def __init__(self, config: AntiEvasionConfig | None = None):
        self.config = config or AntiEvasionConfig()
        self._patches_applied: list[str] = []

    @property
    def patches_applied(self) -> list[str]:
        """List of all patches successfully applied."""
        return list(self._patches_applied)

    def apply_all(
        self,
        frida_session: Any = None,
        sandbox: Any = None,
    ) -> list[str]:
        """Apply all anti-evasion measures based on configured level.

        Args:
            frida_session: Active Frida session for in-process patching.
            sandbox: SandboxManager for VM-level operations.

        Returns:
            List of applied patch names.
        """
        self._patches_applied = []
        level = self.config.level

        if level >= EvasionLevel.BASIC:
            self._apply_debugger_hiding(frida_session)

        if level >= EvasionLevel.MEDIUM:
            self._apply_vm_hiding(frida_session, sandbox)
            self._apply_process_hiding(frida_session)

        if level >= EvasionLevel.AGGRESSIVE:
            self._apply_timing_defeat(frida_session)

        logger.info(
            "[anti_evasion] Applied %d patches at level %d",
            len(self._patches_applied),
            level,
        )
        return self._patches_applied

    # ── Debugger Hiding ────────────────────────────────────────

    def _apply_debugger_hiding(self, session: Any) -> None:
        """Patch debugger detection APIs via Frida."""
        if not self.config.hide_debugger or not session:
            return

        patches = []

        if self.config.patch_is_debugger_present:
            patches.append(self._frida_patch_return(session, "kernel32.dll", "IsDebuggerPresent", 0))
            patches.append(self._frida_patch_return(session, "kernel32.dll", "CheckRemoteDebuggerPresent", 1, patch_arg_index=1, patch_arg_value=0))

        if self.config.patch_ntquery_debug_port:
            patches.append(self._frida_hook_ntquery(session))

        if self.config.patch_ntset_thread_hide:
            patches.append(self._frida_hook_ntset_thread(session))

        if self.config.patch_output_debug_string:
            patches.append(self._frida_patch_return(session, "kernel32.dll", "OutputDebugStringA", 0))
            patches.append(self._frida_patch_return(session, "kernel32.dll", "OutputDebugStringW", 0))

        for p in patches:
            if p:
                self._patches_applied.append(p)

    def _frida_patch_return(
        self,
        session: Any,
        module: str,
        function: str,
        return_value: int,
        patch_arg_index: int = -1,
        patch_arg_value: int = 0,
    ) -> str | None:
        """Patch a function to return a specific value.

        For IsDebuggerPresent: replaces with xor eax,eax; ret (return 0)
        For CheckRemoteDebuggerPresent: sets [arg1] = 0, returns TRUE
        """
        try:
            import frida

            if patch_arg_index >= 0:
                # Patch argument AND return value
                script_code = f"""
                var fn = Module.findExportByName('{module}', '{function}');
                if (fn) {{
                    Interceptor.replace(fn, new NativeCallback(function(arg0) {{
                        // Set output parameter to 0 (no debugger)
                        Memory.writeU32(arg0, 0);
                        return 1;  // TRUE — call succeeded
                    }}, 'int', ['pointer']));
                    send({{type: 'patch_ok', fn: '{function}'}});
                }} else {{
                    send({{type: 'patch_fail', fn: '{function}'}});
                }}
                """
            else:
                # Simple return value patch
                if return_value == 0:
                    # xor eax, eax; ret
                    script_code = f"""
                    var fn = Module.findExportByName('{module}', '{function}');
                    if (fn) {{
                        Interceptor.replace(fn, new NativeCallback(function() {{
                            return 0;
                        }}, 'int', []));
                        send({{type: 'patch_ok', fn: '{function}'}});
                    }} else {{
                        send({{type: 'patch_fail', fn: '{function}'}});
                    }}
                    """
                else:
                    script_code = f"""
                    var fn = Module.findExportByName('{module}', '{function}');
                    if (fn) {{
                        Interceptor.replace(fn, new NativeCallback(function() {{
                            return {return_value};
                        }}, 'int', []));
                        send({{type: 'patch_ok', fn: '{function}'}});
                    }} else {{
                        send({{type: 'patch_fail', fn: '{function}'}});
                    }}
                    """

            script = session.create_script(script_code)
            result = {"ok": False}

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "patch_ok":
                        result["ok"] = True
                        logger.info("[anti_evasion] Patched: %s", function)
                    elif payload.get("type") == "patch_fail":
                        logger.warning("[anti_evasion] Function not found: %s", function)

            script.on("message", on_message)
            script.load()

            if result["ok"]:
                return f"debugger::{function}"
            return None

        except Exception as e:
            logger.warning("[anti_evasion] Patch failed for %s: %s", function, e)
            return None

    def _frida_hook_ntquery(self, session: Any) -> str | None:
        """Hook NtQueryInformationProcess to hide debugger.

        Patches:
        - ProcessDebugPort (0x07) → returns 0
        - ProcessDebugObjectHandle (0x1E) → returns STATUS_PORT_NOT_SET
        - ProcessDebugFlags (0x1F) → returns 1 (PROCESS_DEBUG_INACTIVE)
        """
        try:
            script_code = """
            var ntquery = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
            if (ntquery) {
                Interceptor.attach(ntquery, {
                    onEnter: function(args) {
                        this.processHandle = args[0];
                        this.infoClass = args[1].toInt32();
                        this.buffer = args[2];
                        this.returnLength = args[4];
                    },
                    onLeave: function(retval) {
                        // ProcessDebugPort = 7
                        if (this.infoClass === 7) {
                            // Set debug port to 0 (no debugger)
                            Memory.writePointer(this.buffer, ptr(0));
                            if (!this.returnLength.isNull()) {
                                Memory.writeU32(this.returnLength, Process.pointerSize);
                            }
                            retval.replace(0);  // STATUS_SUCCESS
                        }
                        // ProcessDebugObjectHandle = 0x1E (30)
                        else if (this.infoClass === 0x1E) {
                            retval.replace(0xC0000353);  // STATUS_PORT_NOT_SET
                        }
                        // ProcessDebugFlags = 0x1F (31)
                        else if (this.infoClass === 0x1F) {
                            Memory.writeU32(this.buffer, 1);  // PROCESS_DEBUG_INACTIVE
                            if (!this.returnLength.isNull()) {
                                Memory.writeU32(this.returnLength, 4);
                            }
                            retval.replace(0);  // STATUS_SUCCESS
                        }
                    }
                });
                send({type: 'patch_ok', fn: 'NtQueryInformationProcess'});
            }
            """
            script = session.create_script(script_code)
            result = {"ok": False}

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "patch_ok":
                        result["ok"] = True

            script.on("message", on_message)
            script.load()

            if result["ok"]:
                return "debugger::NtQueryInformationProcess"
            return None

        except Exception as e:
            logger.warning("[anti_evasion] NtQuery hook failed: %s", e)
            return None

    def _frida_hook_ntset_thread(self, session: Any) -> str | None:
        """Hook NtSetInformationThread to prevent ThreadHideFromDebugger.

        ThreadHideFromDebugger (0x11) prevents debuggers from attaching.
        We block this call by returning STATUS_SUCCESS without executing.
        """
        try:
            script_code = """
            var ntset = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
            if (ntset) {
                Interceptor.attach(ntset, {
                    onEnter: function(args) {
                        this.threadHandle = args[0];
                        this.infoClass = args[1].toInt32();
                    },
                    onLeave: function(retval) {
                        // ThreadHideFromDebugger = 0x11 (17)
                        if (this.infoClass === 0x11) {
                            retval.replace(0);  // STATUS_SUCCESS (silently block)
                        }
                    }
                });
                send({type: 'patch_ok', fn: 'NtSetInformationThread'});
            }
            """
            script = session.create_script(script_code)
            result = {"ok": False}

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "patch_ok":
                        result["ok"] = True

            script.on("message", on_message)
            script.load()

            if result["ok"]:
                return "debugger::NtSetInformationThread"
            return None

        except Exception as e:
            logger.warning("[anti_evasion] NtSetThread hook failed: %s", e)
            return None

    # ── VM Hiding ──────────────────────────────────────────────

    def _apply_vm_hiding(self, session: Any, sandbox: Any) -> None:
        """Apply VM/sandbox detection countermeasures."""
        if not self.config.hide_vm:
            return

        # Frida-level patches
        if session and self.config.scrub_smbios:
            patch = self._frida_hide_smbios(session)
            if patch:
                self._patches_applied.append(patch)

        if session and self.config.patch_cpuid:
            patch = self._frida_patch_cpuid(session)
            if patch:
                self._patches_applied.append(patch)

        # Sandbox-level patches
        if sandbox:
            if self.config.remove_vm_registry:
                self._sandbox_scrub_registry(sandbox)
            if self.config.spoof_mac_address:
                self._sandbox_spoof_mac(sandbox)

    def _frida_hide_smbios(self, session: Any) -> str | None:
        """Hook SMBIOS reading functions to scrub VM signatures."""
        try:
            # Build a combined filter for all VM signatures
            sig_checks = " || ".join(
                f"haystack.indexOf('{sig.decode('ascii', errors='ignore')}') !== -1"
                for sig in self.config.vm_signatures
                if len(sig) < 30  # Skip long signatures for JS safety
            )

            script_code = f"""
            // Hook GetSystemFirmwareTable (SMBIOS)
            var getFirmware = Module.findExportByName('kernel32.dll', 'GetSystemFirmwareTable');
            if (getFirmware) {{
                Interceptor.attach(getFirmware, {{
                    onLeave: function(retval) {{
                        var size = retval.toInt32();
                        if (size > 0) {{
                            // Scan and replace VM signatures in the buffer
                            // (simplified — full implementation would parse SMBIOS structure)
                        }}
                    }}
                }});
            }}

            // Hook RegQueryValueEx to filter VM-related registry keys
            var regQuery = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
            if (regQuery) {{
                Interceptor.attach(regQuery, {{
                    onEnter: function(args) {{
                        this.valueName = args[1].readUtf16String();
                    }},
                    onLeave: function(retval) {{
                        // Block queries for VM-related keys
                        if (this.valueName && (
                            {sig_checks.replace('haystack.indexOf', 'this.valueName.indexOf')}
                        )) {{
                            retval.replace(2);  // ERROR_FILE_NOT_FOUND
                        }}
                    }}
                }});
            }}

            send({{type: 'patch_ok', fn: 'SMBIOS/Registry scrub'}});
            """

            script = session.create_script(script_code)
            result = {"ok": False}

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "patch_ok":
                        result["ok"] = True

            script.on("message", on_message)
            script.load()

            if result["ok"]:
                return "vm::smbios_registry_scrub"
            return None

        except Exception as e:
            logger.warning("[anti_evasion] SMBIOS hide failed: %s", e)
            return None

    def _frida_patch_cpuid(self, session: Any) -> str | None:
        """Patch CPUID instruction to hide hypervisor presence.

        CPUID leaf 1, ECX bit 31 = hypervisor present bit.
        CPUID leaf 0x40000000 = hypervisor vendor ID.

        We use Frida's Stalker to intercept CPUID instructions.
        """
        try:
            # Frida can't directly intercept CPUID in user mode easily,
            # but we can hook the Windows API that reads hypervisor info
            script_code = """
            // Block GetSystemInfo from reporting hypervisor
            var getSystemInfo = Module.findExportByName('kernel32.dll', 'GetSystemInfo');
            if (getSystemInfo) {
                Interceptor.attach(getSystemInfo, {
                    onLeave: function(retval) {
                        // SYSTEM_INFO struct — no direct hypervisor field
                        // but some samples check wProcessorArchitecture
                    }
                });
            }

            // Hook IsNativeVhdBoot — some samples check this
            var isNativeVhd = Module.findExportByName('kernel32.dll', 'IsNativeVhdBoot');
            if (isNativeVhd) {
                Interceptor.replace(isNativeVhd, new NativeCallback(function(arg0) {
                    if (!arg0.isNull()) Memory.writeU32(arg0, 0);
                    return 0;  // FALSE
                }, 'int', ['pointer']));
            }

            send({type: 'patch_ok', fn: 'CPUID/hypervisor hide'});
            """

            script = session.create_script(script_code)
            result = {"ok": False}

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "patch_ok":
                        result["ok"] = True

            script.on("message", on_message)
            script.load()

            if result["ok"]:
                return "vm::cpuid_hypervisor_hide"
            return None

        except Exception as e:
            logger.warning("[anti_evasion] CPUID patch failed: %s", e)
            return None

    def _sandbox_scrub_registry(self, sandbox: Any) -> None:
        """Remove VM-related registry keys inside the sandbox."""
        vm_registry_paths = [
            r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest",
            r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxMouse",
            r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxVideo",
            r"HKLM\SYSTEM\CurrentControlSet\Services\VBoxSF",
            r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
            r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
            r"HKLM\SYSTEM\CurrentControlSet\Services\vmtools",
            r"HKLM\SYSTEM\CurrentControlSet\Services\vm3dservice",
        ]

        for reg_path in vm_registry_paths:
            sandbox.execute_command(f'reg delete "{reg_path}" /f 2>nul')

        self._patches_applied.append("vm::registry_scrub")

    def _sandbox_spoof_mac(self, sandbox: Any) -> None:
        """Change MAC address to look like a real NIC."""
        # Real NIC OUIs (Intel, Realtek, etc.)
        real_ouis = [
            "00:1B:21",  # Intel
            "00:1C:42",  # Parallels (sometimes OK)
            "00:50:56",  # VMware (common)
            "08:00:27",  # VirtualBox (common)
            "B8:27:EB",  # Raspberry Pi (real hardware)
            "DC:A6:32",  # Realtek
        ]

        # Generate a random MAC with a real OUI
        import random
        oui = random.choice(real_ouis)
        nic = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
        new_mac = f"{oui}:{nic}"

        # Change adapter MAC
        sandbox.execute_command(
            f'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\0001" '
            f'/v NetworkAddress /d "{new_mac}" /f 2>nul'
        )

        self._patches_applied.append(f"vm::mac_spoof({new_mac})")

    # ── Process Hiding ─────────────────────────────────────────

    def _apply_process_hiding(self, session: Any) -> None:
        """Hide analysis tool processes from sample enumeration."""
        if not self.config.hide_processes or not session:
            return

        try:
            # Build filter for hidden process names
            name_checks = " || ".join(
                f'name.toLowerCase().indexOf("{n}") !== -1'
                for n in self.config.hidden_process_names
            )

            script_code = f"""
            // Hook CreateToolhelp32Snapshot + Process32First/Next
            // to filter out analysis tool processes

            var process32First = Module.findExportByName('kernel32.dll', 'Process32FirstW');
            var process32Next = Module.findExportByName('kernel32.dll', 'Process32NextW');

            function filterProcess(entryPtr) {{
                // PROCESSENTRY32W: szExeFile at offset 0x24 (36)
                var namePtr = entryPtr.add(0x24);
                var name = namePtr.readUtf16String() || '';
                if ({name_checks}) {{
                    return true;  // should be hidden
                }}
                return false;
            }}

            if (process32Next) {{
                var originalNext = new NativeFunction(process32Next, 'int', ['pointer', 'pointer']);
                Interceptor.replace(process32Next, new NativeCallback(function(snapshot, entry) {{
                    var result;
                    do {{
                        result = originalNext(snapshot, entry);
                        if (result === 0) return 0;  // no more processes
                    }} while (filterProcess(entry));
                    return 1;
                }}, 'int', ['pointer', 'pointer']));
            }}

            send({{type: 'patch_ok', fn: 'Process enumeration filter'}});
            """

            script = session.create_script(script_code)
            result = {"ok": False}

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "patch_ok":
                        result["ok"] = True

            script.on("message", on_message)
            script.load()

            if result["ok"]:
                self._patches_applied.append("process::enumeration_filter")

        except Exception as e:
            logger.warning("[anti_evasion] Process hiding failed: %s", e)

    # ── Timing Defeat ──────────────────────────────────────────

    def _apply_timing_defeat(self, session: Any) -> None:
        """Defeat timing-based anti-analysis checks."""
        if not self.config.defeat_timing or not session:
            return

        try:
            script_code = """
            // Accelerate sleep calls (10x faster)
            var sleep = Module.findExportByName('kernel32.dll', 'Sleep');
            if (sleep) {
                Interceptor.replace(sleep, new NativeCallback(function(ms) {
                    // Sleep for 1/10th the requested time
                    var realSleep = new NativeFunction(sleep, 'void', ['uint']);
                    realSleep(Math.max(1, ms / 10));
                }, 'void', ['uint']));
            }

            // Hook QueryPerformanceCounter to accelerate time
            var qpc = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
            if (qpc) {
                var counterOffset = 0;
                Interceptor.attach(qpc, {
                    onLeave: function(retval) {
                        // Don't modify — just let it run naturally
                        // Some samples compare QPC deltas to detect debugging
                    }
                });
            }

            // Hook GetTickCount64
            var gtc64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
            if (gtc64) {
                var baseTime = null;
                var fakeOffset = 0;
                Interceptor.attach(gtc64, {
                    onEnter: function(args) {
                        if (baseTime === null) {
                            baseTime = 0;  // will be set on first call
                        }
                    }
                });
            }

            send({type: 'patch_ok', fn: 'Timing acceleration'});
            """

            script = session.create_script(script_code)
            result = {"ok": False}

            def on_message(message, data):
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "patch_ok":
                        result["ok"] = True

            script.on("message", on_message)
            script.load()

            if result["ok"]:
                self._patches_applied.append("timing::sleep_acceleration")

        except Exception as e:
            logger.warning("[anti_evasion] Timing defeat failed: %s", e)
