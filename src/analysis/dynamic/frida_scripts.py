"""
DriverScope — Frida Script Library.

Ready-to-use Frida scripts for common unpacking and analysis scenarios.
Each script returns JavaScript source code that can be injected via Frida.

Categories:
1. OEP Detection — find Original Entry Point in packed samples
2. Memory Dumping — dump unpacked code from memory
3. IAT Reconstruction — dump and rebuild Import Address Table
4. API Tracing — trace API calls during execution
5. Anti-Debug Bypass — comprehensive anti-debug patches
6. Unpacking Helpers — specialized scripts for known packers

Usage:
    from src.analysis.dynamic.frida_scripts import get_oep_detection_script

    script_code = get_oep_detection_script(method="virtualprotect")
    session.create_script(script_code)
"""

from __future__ import annotations


# ═══════════════════════════════════════════════════════════════
# 1. OEP Detection Scripts
# ═══════════════════════════════════════════════════════════════

def get_oep_detection_script(
    method: str = "virtualprotect",
    image_base: int = 0,
    image_size: int = 0,
) -> str:
    """Generate OEP detection script.

    Methods:
    - virtualprotect: Monitor VirtualProtect for code section becoming executable
    - pushad_popad: Detect pushad/popad + jmp pattern (classic UPX-style)
    - write_watch: Monitor writes to code section
    - single_step: Step from loader entry to find OEP

    Args:
        method: Detection method.
        image_base: Image base address (0 = auto-detect).
        image_size: Image size (0 = auto-detect).

    Returns:
        JavaScript source code for Frida.
    """
    if method == "virtualprotect":
        return _OEP_VIRTUALPROTECT.format(
            image_base=hex(image_base),
            image_size=hex(image_size) if image_size else "0x0",
        )
    elif method == "pushad_popad":
        return _OEP_PUSHAD_POPAD
    elif method == "write_watch":
        return _OEP_WRITE_WATCH.format(
            image_base=hex(image_base),
            image_size=hex(image_size) if image_size else "0x0",
        )
    else:
        raise ValueError(f"Unknown OEP detection method: {method}")


_OEP_VIRTUALPROTECT = """
// OEP Detection via VirtualProtect monitoring
// Detects when the code section becomes executable

var imageBase = {image_base};
var imageSize = {image_size};

// Auto-detect image base if not provided
if (imageBase === 0) {{
    var mainModule = Process.enumerateModules()[0];
    imageBase = mainModule.base.toInt32();
    imageSize = mainModule.size;
    send({{type: 'info', msg: 'Auto-detected image: ' + mainModule.name +
          ' base=0x' + imageBase.toString(16) + ' size=0x' + imageSize.toString(16)}});
}}

var codeSectionFound = false;
var lastProtectAddr = 0;

Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualProtect'), {{
    onEnter: function(args) {{
        this.addr = args[0];
        this.size = args[2].toInt32();
        this.newProtect = args[3].toInt32();
        this.oldProtectPtr = args[4];
    }},
    onLeave: function(retval) {{
        // PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20,
        // PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80
        var isExecutable = (this.newProtect & 0xF0) !== 0;

        if (isExecutable && this.size > 0x1000) {{
            var addrInt = this.addr.toInt32();

            // Check if within image
            if (imageBase === 0 ||
                (addrInt >= imageBase && addrInt < imageBase + imageSize)) {{

                send({{
                    type: 'oep_candidate',
                    address: this.addr.toString(),
                    size: this.size,
                    protect: this.newProtect,
                    reason: 'VirtualProtect: section became executable'
                }});

                // Breakpoint at the entry of this newly executable region
                try {{
                    Interceptor.attach(this.addr, {{
                        onEnter: function(args) {{
                            send({{
                                type: 'oep_hit',
                                address: this.context.pc ? this.context.pc.toString() :
                                         this.context.rip ? this.context.rip.toString() : 'unknown',
                                reason: 'First execution in new code section'
                            }});
                        }}
                    }});
                }} catch(e) {{}}
            }}
        }}
    }}
}});

// Also monitor NtProtectVirtualMemory (native API)
var ntProtect = Module.findExportByName('ntdll.dll', 'NtProtectVirtualMemory');
if (ntProtect) {{
    Interceptor.attach(ntProtect, {{
        onEnter: function(args) {{
            this.baseAddr = args[1];
            this.sizePtr = args[2];
            this.newProtect = args[3];
        }},
        onLeave: function(retval) {{
            if (retval.toInt32() === 0) {{  // STATUS_SUCCESS
                var addr = this.baseAddr.readPointer();
                var size = this.sizePtr.readU32();
                var prot = this.newProtect.readU32();

                if ((prot & 0xF0) && size > 0x1000) {{
                    send({{
                        type: 'oep_candidate',
                        address: addr.toString(),
                        size: size,
                        protect: prot,
                        reason: 'NtProtectVirtualMemory: section became executable'
                    }});
                }}
            }}
        }}
    }});
}}

send({{type: 'ready', msg: 'OEP detection (VirtualProtect) armed'}});
"""

_OEP_PUSHAD_POPAD = """
// OEP Detection via pushad/popad pattern
// Classic unpacker signature: pushad ... popad ... jmp OEP

var found = false;

// Scan all executable modules for pushad/popad patterns
Process.enumerateModules().forEach(function(mod) {
    if (found) return;

    Memory.scan(mod.base, mod.size, {
        patterns: [
            // pushad (0x60) followed within 64 bytes by popad (0x61) followed by jmp (0xE9 or 0xFF)
            {
                pattern: '60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61',
                onMatch: function(address, size) {
                    // Found pushad...popad within range
                    // Now look for jmp after popad
                    var afterPopad = address.add(64);
                    var nextBytes = afterPopad.readByteArray(16);
                    var bytes = new Uint8Array(nextBytes);

                    for (var i = 0; i < 16; i++) {
                        // JMP rel32
                        if (bytes[i] === 0xE9) {
                            var offset = new DataView(nextBytes).getInt32(i + 1, true);
                            var target = afterPopad.add(i + 5 + offset);
                            send({
                                type: 'oep_candidate',
                                address: target.toString(),
                                reason: 'pushad...popad + JMP rel32 pattern'
                            });
                            found = true;
                            return 'stop';
                        }
                        // JMP [reg]
                        if (bytes[i] === 0xFF && (bytes[i+1] & 0xF8) === 0xE0) {
                            send({
                                type: 'oep_candidate',
                                address: afterPopad.add(i).toString(),
                                reason: 'pushad...popad + JMP [reg] pattern'
                            });
                            found = true;
                            return 'stop';
                        }
                    }
                },
                offset: 0
            }
        ],
        onError: function(reason) {},
        onComplete: function() {}
    });
});

send({type: 'ready', msg: 'OEP detection (pushad/popad scan) complete'});
"""

_OEP_WRITE_WATCH = """
// OEP Detection via write watch on code section
// Monitors writes to the original code section

var imageBase = {image_base};
var imageSize = {image_size};

if (imageBase === 0) {{
    var mainModule = Process.enumerateModules()[0];
    imageBase = mainModule.base.toInt32();
    imageSize = mainModule.size;
}}

// Hook WriteProcessMemory to detect unpacker writing to code section
var wpm = Module.findExportByName('kernel32.dll', 'WriteProcessMemory');
if (wpm) {{
    Interceptor.attach(wpm, {{
        onEnter: function(args) {{
            this.targetAddr = args[1];
            this.size = args[3].toInt32();
        }},
        onLeave: function(retval) {{
            if (retval.toInt32() !== 0) {{
                var addrInt = this.targetAddr.toInt32();
                // Check if writing to code section
                if (addrInt >= imageBase && addrInt < imageBase + imageSize) {{
                    send({{
                        type: 'write_detected',
                        address: this.targetAddr.toString(),
                        size: this.size,
                        reason: 'WriteProcessMemory into image code section'
                    }});
                }}
            }}
        }}
    }});
}}

// Hook NtWriteVirtualMemory
var ntwvm = Module.findExportByName('ntdll.dll', 'NtWriteVirtualMemory');
if (ntwvm) {{
    Interceptor.attach(ntwvm, {{
        onEnter: function(args) {{
            this.targetAddr = args[1];
            this.size = args[3].toInt32();
        }},
        onLeave: function(retval) {{
            if (retval.toInt32() === 0) {{
                var addrInt = this.targetAddr.toInt32();
                if (addrInt >= imageBase && addrInt < imageBase + imageSize) {{
                    send({{
                        type: 'write_detected',
                        address: this.targetAddr.toString(),
                        size: this.size,
                        reason: 'NtWriteVirtualMemory into image code section'
                    }});
                }}
            }}
        }}
    }});
}}

send({{type: 'ready', msg: 'OEP detection (write watch) armed'}});
"""


# ═══════════════════════════════════════════════════════════════
# 2. Memory Dumping Scripts
# ═══════════════════════════════════════════════════════════════

def get_memory_dump_script(
    address: int,
    size: int,
    chunk_size: int = 0x100000,
) -> str:
    """Generate memory dump script.

    Args:
        address: Start address to dump.
        size: Total size to dump.
        chunk_size: Size of each chunk (for large dumps).

    Returns:
        JavaScript source code.
    """
    return _MEMORY_DUMP.format(
        address=hex(address),
        size=hex(size),
        chunk_size=hex(chunk_size),
    )


_MEMORY_DUMP = """
// Memory Dump Script
// Dumps a memory region and sends it back in chunks

var startAddr = ptr({address});
var totalSize = {size};
var chunkSize = {chunk_size};

send({{type: 'dump_start', address: startAddr.toString(), size: totalSize}});

var offset = 0;
while (offset < totalSize) {{
    var currentSize = Math.min(chunkSize, totalSize - offset);
    try {{
        var data = startAddr.add(offset).readByteArray(currentSize);
        send({{
            type: 'dump_chunk',
            offset: offset,
            size: currentSize,
            data: data
        }});
    }} catch(e) {{
        send({{
            type: 'dump_error',
            offset: offset,
            error: e.toString()
        }});
        break;
    }}
    offset += currentSize;
}}

send({{type: 'dump_complete', total_dumped: offset}});
"""


# ═══════════════════════════════════════════════════════════════
# 3. IAT Reconstruction Scripts
# ═══════════════════════════════════════════════════════════════

def get_iat_dump_script(
    search_start: int = 0,
    search_size: int = 0,
) -> str:
    """Generate IAT dump script.

    Scans memory for thunk arrays (sequences of pointers to known exports)
    and reports the resolved imports.

    Args:
        search_start: Start address for scanning (0 = scan all modules).
        search_size: Size of region to scan (0 = all loaded modules).

    Returns:
        JavaScript source code.
    """
    return _IAT_DUMP.format(
        search_start=hex(search_start),
        search_size=hex(search_size),
    )


_IAT_DUMP = """
// IAT Dump Script
// Scans for thunk arrays and resolves API names

var searchStart = ptr({search_start});
var searchSize = {search_size};

function resolveExport(moduleName, addr) {{
    try {{
        var mod = Process.getModuleByName(moduleName);
        if (!mod) return null;

        var exports = Module.enumerateExports(moduleName);
        for (var i = 0; i < exports.length; i++) {{
            if (exports[i].address.equals(addr)) {{
                return {{
                    dll: moduleName,
                    api: exports[i].name,
                    ordinal: exports[i].ordinal || 0
                }};
            }}
        }}
    }} catch(e) {{}}
    return null;
}}

// Scan all loaded modules for thunk arrays
var modules = Process.enumerateModules();
var imports = [];
var ptrSize = Process.pointerSize;

modules.forEach(function(mod) {{
    if (searchStart !== 0 &&
        (mod.base.toInt32() < searchStart.toInt32() ||
         mod.base.toInt32() > searchStart.add(searchSize).toInt32())) {{
        return;
    }}

    // Scan module's IAT region (typically near the beginning)
    var scanSize = Math.min(mod.size, 0x10000);

    try {{
        Memory.scan(mod.base, scanSize, {{
            patterns: [{{
                pattern: ptrSize === 8 ? '?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00' :
                                         '?? ?? ?? ?? 00 00 00 00',
                onMatch: function(address, size) {{
                    // Potential end of thunk array
                    // Walk backwards to find the start
                    var thunkStart = address;
                    var thunks = [];

                    for (var i = 1; i < 100; i++) {{
                        var prevAddr = address.sub(i * ptrSize);
                        try {{
                            var val = prevAddr.readPointer();
                            if (val.isNull()) break;

                            // Try to resolve this address as an export
                            for (var j = 0; j < modules.length; j++) {{
                                var resolved = resolveExport(modules[j].name, val);
                                if (resolved) {{
                                    thunks.unshift({{
                                        thunk_addr: prevAddr.toString(),
                                        target_addr: val.toString(),
                                        dll: resolved.dll,
                                        api: resolved.api
                                    }});
                                    break;
                                }}
                            }}
                        }} catch(e) {{ break; }}
                    }}

                    if (thunks.length >= 2) {{
                        send({{
                            type: 'thunk_array',
                            base: thunks[0].thunk_addr,
                            count: thunks.length,
                            imports: thunks
                        }});
                    }}
                }},
                offset: 0
            }}]
        }});
    }} catch(e) {{}}
}});

send({{type: 'iat_scan_complete'}});
"""


# ═══════════════════════════════════════════════════════════════
# 4. API Tracing Scripts
# ═══════════════════════════════════════════════════════════════

def get_api_trace_script(
    apis: list[str] | None = None,
    log_args: bool = True,
    log_stack: bool = False,
) -> str:
    """Generate API tracing script.

    Hooks specified APIs and logs calls with arguments.

    Args:
        apis: List of API names to trace. If None, traces common dangerous APIs.
        log_args: Log function arguments.
        log_stack: Log call stack.

    Returns:
        JavaScript source code.
    """
    if apis is None:
        apis = [
            # Memory management
            "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPages",
            "MmMapLockedPagesSpecifyCache", "MmCopyVirtualMemory",
            "MmGetPhysicalAddress", "ZwMapViewOfSection",
            # MSR
            "KeWriteMsr", "KeReadMsr",
            # Thread/process
            "ZwCreateThreadEx", "PsCreateSystemThread",
            "ZwWriteVirtualMemory", "ZwReadVirtualMemory",
            "KeInsertQueueApc", "KeInitializeApc",
            # IOCTL
            "DeviceIoControl", "IoCallDriver",
            "IoBuildDeviceIoControlRequest",
            # Security
            "SeSinglePrivilegeCheck", "ExGetPreviousMode",
            "ProbeForRead", "ProbeForWrite",
            # Handle
            "ObReferenceObjectByHandle", "ZwOpenProcess",
            "ZwDuplicateObject",
        ]

    api_hooks = []
    for api in apis:
        api_hooks.append(_API_HOOK_TEMPLATE.format(
            api_name=api,
            log_args="true" if log_args else "false",
            log_stack="true" if log_stack else "false",
        ))

    return _API_TRACE_HEADER + "\n".join(api_hooks)


_API_TRACE_HEADER = """
// API Tracing Script
// Hooks dangerous kernel APIs and logs calls

var callLog = [];

"""

_API_HOOK_TEMPLATE = """
(function() {{
    var apiName = '{api_name}';
    var logArgs = {log_args};
    var logStack = {log_stack};

    // Try ntoskrnl first, then kernel32
    var addr = null;
    try {{ addr = Module.findExportByName('ntoskrnl.exe', apiName); }} catch(e) {{}}
    if (!addr) try {{ addr = Module.findExportByName('kernel32.dll', apiName); }} catch(e) {{}}
    if (!addr) try {{ addr = Module.findExportByName('ntdll.dll', apiName); }} catch(e) {{}}

    if (addr) {{
        Interceptor.attach(addr, {{
            onEnter: function(args) {{
                var entry = {{
                    api: apiName,
                    timestamp: Date.now(),
                    thread_id: Process.getCurrentThreadId()
                }};

                if (logArgs) {{
                    entry.args = [];
                    for (var i = 0; i < 4; i++) {{
                        try {{
                            entry.args.push(args[i].toString());
                        }} catch(e) {{
                            entry.args.push('N/A');
                        }}
                    }}
                }}

                if (logStack) {{
                    entry.stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .slice(0, 5)
                        .map(DebugSymbol.fromAddress)
                        .map(function(s) {{ return s.toString(); }});
                }}

                callLog.push(entry);
                send({{type: 'api_call', data: entry}});
            }}
        }});
    }}
}})();
"""


# ═══════════════════════════════════════════════════════════════
# 5. Anti-Debug Bypass Scripts
# ═══════════════════════════════════════════════════════════════

def get_antidebug_bypass_script(level: int = 2) -> str:
    """Generate comprehensive anti-debug bypass script.

    Levels:
    - 1: Basic (IsDebuggerPresent, CheckRemoteDebuggerPresent)
    - 2: Medium (+ NtQueryInformationProcess, NtSetInformationThread)
    - 3: Aggressive (+ timing defeat, PEB patching, process hiding)

    Args:
        level: Bypass aggressiveness level.

    Returns:
        JavaScript source code.
    """
    parts = [_ANTIDEBUG_HEADER]

    if level >= 1:
        parts.append(_ANTIDEBUG_BASIC)
    if level >= 2:
        parts.append(_ANTIDEBUG_MEDIUM)
    if level >= 3:
        parts.append(_ANTIDEBUG_AGGRESSIVE)

    return "\n".join(parts)


_ANTIDEBUG_HEADER = """
// Anti-Debug Bypass Script
// Patches common debugger detection APIs

send({type: 'info', msg: 'Anti-debug bypass armed'});
"""

_ANTIDEBUG_BASIC = """
// ── Basic: IsDebuggerPresent / CheckRemoteDebuggerPresent ──

var idp = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
if (idp) {{
    Interceptor.replace(idp, new NativeCallback(function() {{
        return 0;  // FALSE — no debugger
    }}, 'int', []));
}}

var crdp = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
if (crdp) {{
    Interceptor.replace(crdp, new NativeCallback(function(processHandle, result) {{
        Memory.writeU32(result, 0);  // No remote debugger
        return 1;  // TRUE — call succeeded
    }}, 'int', ['pointer', 'pointer']));
}}

// Patch PEB.BeingDebugged directly
try {{
    var pbi = Process.enumerateModules()[0];
    var teb = Memory.readPointer(fs.read('/proc/self/task/' +
        Process.getCurrentThreadId() + '/status'));
    // PEB offset for BeingDebugged varies by OS
    // Windows 10: PEB+0x02
}} catch(e) {{}}

// Block OutputDebugString (some anti-debug uses it with GetLastError)
var ods = Module.findExportByName('kernel32.dll', 'OutputDebugStringA');
if (ods) {{
    Interceptor.replace(ods, new NativeCallback(function() {{}}, 'void', ['pointer']));
}}
var odsW = Module.findExportByName('kernel32.dll', 'OutputDebugStringW');
if (odsW) {{
    Interceptor.replace(odsW, new NativeCallback(function() {{}}, 'void', ['pointer']));
}}
"""

_ANTIDEBUG_MEDIUM = """
// ── Medium: NtQueryInformationProcess / NtSetInformationThread ──

var ntquery = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
if (ntquery) {{
    Interceptor.attach(ntquery, {{
        onEnter: function(args) {{
            this.infoClass = args[1].toInt32();
            this.buffer = args[2];
            this.returnLength = args[4];
        }},
        onLeave: function(retval) {{
            if (this.infoClass === 7) {{
                // ProcessDebugPort → return 0
                Memory.writePointer(this.buffer, ptr(0));
                if (!this.returnLength.isNull()) {{
                    Memory.writeU32(this.returnLength, Process.pointerSize);
                }}
                retval.replace(0);
            }} else if (this.infoClass === 0x1E) {{
                // ProcessDebugObjectHandle → STATUS_PORT_NOT_SET
                retval.replace(0xC0000353);
            }} else if (this.infoClass === 0x1F) {{
                // ProcessDebugFlags → return 1 (PROCESS_DEBUG_INACTIVE)
                Memory.writeU32(this.buffer, 1);
                if (!this.returnLength.isNull()) {{
                    Memory.writeU32(this.returnLength, 4);
                }}
                retval.replace(0);
            }}
        }}
    }});
}}

var ntset = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
if (ntset) {{
    Interceptor.attach(ntset, {{
        onEnter: function(args) {{
            this.infoClass = args[1].toInt32();
        }},
        onLeave: function(retval) {{
            if (this.infoClass === 0x11) {{
                // ThreadHideFromDebugger → block silently
                retval.replace(0);
            }}
        }}
    }});
}}

// Block NtClose with invalid handle (anti-debug trick)
var ntclose = Module.findExportByName('ntdll.dll', 'NtClose');
if (ntclose) {{
    Interceptor.attach(ntclose, {{
        onEnter: function(args) {{
            this.handle = args[0];
        }},
        onLeave: function(retval) {{
            // If the handle is a known debug object handle, return success
        }}
    }});
}}
"""

_ANTIDEBUG_AGGRESSIVE = """
// ── Aggressive: Timing defeat + PEB patching + process hiding ──

// Accelerate Sleep
var sleepFn = Module.findExportByName('kernel32.dll', 'Sleep');
if (sleepFn) {{
    Interceptor.replace(sleepFn, new NativeCallback(function(ms) {{
        // Sleep 1/100th of requested time
        var realSleep = new NativeFunction sleepFn, 'void', ['uint']);
        realSleep(Math.max(1, ms / 100));
    }}, 'void', ['uint']));
}}

// Patch GetTickCount64 to accelerate perceived time
var gtc64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
if (gtc64) {{
    var baseTime = null;
    var fakeOffset = 0;
    Interceptor.attach(gtc64, {{
        onLeave: function(retval) {{
            if (baseTime === null) baseTime = retval.toInt32();
            // Return time * 100 to defeat timing checks
            var real = retval.toInt32();
            var fake = baseTime + (real - baseTime) * 100;
            retval.replace(ptr(fake));
        }}
    }});
}}

// Patch NtQuerySystemInformation to hide processes
var ntqsi = Module.findExportByName('ntdll.dll', 'NtQuerySystemInformation');
if (ntqsi) {{
    Interceptor.attach(ntqsi, {{
        onLeave: function(retval) {{
            // Could filter process list here
            // but complex — left as exercise
        }}
    }});
}}

// Hide common debugger/analysis process names
var hiddenNames = [
    'x64dbg', 'windbg', 'ollydbg', 'ida', 'ida64',
    'procmon', 'procexp', 'wireshark', 'tcpview',
    'cuckoo', 'sandboxie', 'joebox', 'vboxservice',
    'vmtoolsd', 'qemu-ga', 'frida-server'
];

var createToolHelp = Module.findExportByName('kernel32.dll', 'Process32FirstW');
var createToolHelpNext = Module.findExportByName('kernel32.dll', 'Process32NextW');

if (createToolHelpNext) {{
    var origNext = new NativeFunction(createToolHelpNext, 'int', ['pointer', 'pointer']);
    Interceptor.replace(createToolHelpNext, new NativeCallback(function(snapshot, entry) {{
        var result;
        do {{
            result = origNext(snapshot, entry);
            if (result === 0) return 0;

            // PROCESSENTRY32W.szExeFile at offset 0x24
            var namePtr = entry.add(0x24);
            var name = namePtr.readUtf16String() || '';
            var lowerName = name.toLowerCase();

            var hidden = false;
            for (var i = 0; i < hiddenNames.length; i++) {{
                if (lowerName.indexOf(hiddenNames[i]) !== -1) {{
                    hidden = true;
                    break;
                }}
            }}
            if (!hidden) return 1;
        }} while (true);
    }}, 'int', ['pointer', 'pointer']));
}}

send({{type: 'info', msg: 'Aggressive anti-debug bypass active'}});
"""


# ═══════════════════════════════════════════════════════════════
# 6. Unpacking Helpers
# ═══════════════════════════════════════════════════════════════

def get_upx_unpack_helper_script() -> str:
    """Generate UPX-specific unpacking helper script."""
    return """
// UPX Unpacking Helper
// Monitors UPX stub execution and captures unpacked state

// UPX uses VirtualProtect to make unpacked code executable
// Then jumps to the original entry point

var unpacked = false;

Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualProtect'), {
    onEnter: function(args) {
        this.addr = args[0];
        this.size = args[2].toInt32();
        this.protect = args[3].toInt32();
    },
    onLeave: function(retval) {
        if (!unpacked && (this.protect & 0x20)) {  // PAGE_EXECUTE_READ
            if (this.size > 0x1000) {
                unpacked = true;
                send({
                    type: 'upx_unpacked',
                    code_address: this.addr.toString(),
                    code_size: this.size
                });

                // Schedule a dump after the unpacker finishes
                setTimeout(function() {
                    var mod = Process.enumerateModules()[0];
                    try {
                        var data = mod.base.readByteArray(mod.size);
                        send({
                            type: 'full_dump',
                            base: mod.base.toString(),
                            size: mod.size,
                            data: data
                        });
                    } catch(e) {
                        send({type: 'dump_error', error: e.toString()});
                    }
                }, 100);
            }
        }
    }
});

send({type: 'ready', msg: 'UPX unpack helper armed'});
"""


def get_vmprotect_detection_script() -> str:
    """Generate VMProtect detection/analysis script."""
    return """
// VMProtect Detection and Analysis
// VMProtect uses virtualization + mutation + packing

// VMProtect signatures
var vmSignatures = [
    'VMProtectBegin',
    'VMProtectEnd',
    'VMProtectIsDebuggerPresent',
    'VMProtectIsVirtualMachinePresent',
    'VMProtectIsValidImageCRC'
];

var found = [];

// Check for VMProtect imports
vmSignatures.forEach(function(name) {
    var addr = null;
    Process.enumerateModules().forEach(function(mod) {
        try {
            var exports = Module.enumerateExports(mod.name);
            for (var i = 0; i < exports.length; i++) {
                if (exports[i].name.indexOf(name) !== -1) {
                    found.push({
                        name: exports[i].name,
                        module: mod.name,
                        address: exports[i].address.toString()
                    });
                }
            }
        } catch(e) {}
    });
});

// Check for VMProtect sections
Process.enumerateModules().forEach(function(mod) {
    try {
        var sections = Module.enumerateSections ? Module.enumerateSections(mod.name) : [];
        sections.forEach(function(sec) {
            if (sec.name.indexOf('.vmp') !== -1 ||
                sec.name.indexOf('.vmp0') !== -1 ||
                sec.name.indexOf('.vmp1') !== -1) {
                found.push({
                    name: 'section:' + sec.name,
                    module: mod.name,
                    address: sec.address || mod.base.toString()
                });
            }
        });
    } catch(e) {}
});

send({
    type: 'vmprotect_scan',
    detected: found.length > 0,
    findings: found
});

// If VMProtect detected, monitor its handler dispatch
if (found.length > 0) {
    send({type: 'info', msg: 'VMProtect detected — ' + found.length + ' indicators found'});

    // Hook the VM handler to trace virtualized code execution
    // VMProtect uses a VM dispatch loop with handlers for each bytecode
    // This is complex to analyze — log handler transitions
}
"""
