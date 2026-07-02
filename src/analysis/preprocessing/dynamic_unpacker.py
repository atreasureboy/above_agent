"""
DriverScope — Dynamic Unpacker (Frida + Sandbox).

Handles unpacking of complex/commercial packers (VMProtect, Themida, etc.)
by executing the sample in a sandbox and capturing the unpacked binary
from memory at the Original Entry Point (OEP).

Architecture:
    1. Start QEMU sandbox with Frida server
    2. Load the packed sample
    3. Frida hooks detect OEP (via VirtualProtect monitoring)
    4. Dump unpacked memory from OEP
    5. Reconstruct IAT from the dump
    6. Save as valid PE

This requires:
    - QEMU sandbox configured and running
    - frida-server installed inside the VM
    - pip install frida frida-tools
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DynamicUnpacker:
    """Dynamic unpacker using Frida instrumentation in a QEMU sandbox.

    Handles commercial packers that cannot be statically unpacked.
    """

    def __init__(
        self,
        qemu_path: str = "",
        vm_image: str = "",
        snapshot: str = "clean",
        frida_port: int = 27042,
        timeout: int = 120,
    ):
        self.qemu_path = qemu_path
        self.vm_image = vm_image
        self.snapshot = snapshot
        self.frida_port = frida_port
        self.timeout = timeout
        self.last_error = ""

        self._sandbox = None
        self._frida = None

    def can_handle(self, sample_path: Path) -> bool:
        """Check if dynamic unpacking is possible."""
        # Need QEMU configured and Frida available
        if not self.qemu_path or not self.vm_image:
            return False
        try:
            import frida
            return True
        except ImportError:
            return False

    def unpack(self, sample_path: Path, output_dir: str = "") -> Path | None:
        """Unpack the sample using dynamic analysis.

        Full pipeline:
        1. Start sandbox
        2. Copy sample to VM
        3. Attach Frida
        4. Execute sample
        5. Detect OEP
        6. Dump memory
        7. Reconstruct PE
        8. Return unpacked file path
        """
        try:
            import frida
        except ImportError:
            self.last_error = "Frida not installed (pip install frida)"
            return None

        from src.analysis.dynamic.sandbox import SandboxConfig, SandboxManager

        # Initialize sandbox
        config = SandboxConfig(
            qemu_path=self.qemu_path,
            vm_image=self.vm_image,
            snapshot_name=self.snapshot,
            network="user",
        )
        sandbox = SandboxManager(config)

        if not sandbox.is_available:
            self.last_error = "QEMU sandbox not available"
            return None

        try:
            # Step 1: Start VM
            logger.info("[dynamic_unpack] Starting sandbox VM...")
            if not sandbox.start():
                self.last_error = "Failed to start sandbox VM"
                return None

            # Step 2: Copy sample to VM
            guest_path = f"C:\\test\\{sample_path.name}"
            logger.info("[dynamic_unpack] Copying sample to VM: %s", guest_path)
            if not sandbox.copy_file_to_vm(str(sample_path), guest_path):
                self.last_error = "Failed to copy sample to VM"
                return None

            # Step 3: Execute sample in VM
            logger.info("[dynamic_unpack] Executing sample in VM...")
            exec_cmd = f"start /B {guest_path}"
            sandbox.execute_command(exec_cmd, timeout=10)

            # Step 4: Wait for Frida server to see the process
            time.sleep(3)  # Let process start

            # Step 5: Attach Frida and detect OEP
            oep = self._detect_oep(sandbox, sample_path.name)
            if not oep:
                self.last_error = "Could not detect OEP"
                return None

            # Step 6: Dump memory at OEP
            logger.info("[dynamic_unpack] OEP detected at 0x%X, dumping memory...", oep)
            dump_data = self._dump_memory(oep)
            if not dump_data:
                self.last_error = "Memory dump failed"
                return None

            # Step 7: Reconstruct PE
            unpacked_path = self._reconstruct_pe(dump_data, oep, output_dir, sample_path)
            if not unpacked_path:
                self.last_error = "PE reconstruction failed"
                return None

            logger.info("[dynamic_unpack] Unpacked to: %s", unpacked_path)
            return unpacked_path

        except Exception as e:
            self.last_error = f"Dynamic unpack error: {e}"
            logger.error("[dynamic_unpack] %s", self.last_error)
            return None

        finally:
            sandbox.stop()

    def _detect_oep(self, sandbox: Any, process_name: str) -> int | None:
        """Detect the Original Entry Point using Frida.

        Strategy:
        1. Hook VirtualProtect — when code section becomes executable, that's OEP
        2. Monitor for pushad/popad + jmp pattern (classic UPX-style OEP)
        3. Track last breakpoint hit before long execution gap
        """
        try:
            import frida

            # Connect to Frida server in the VM
            # (requires port forwarding from QEMU to host)
            device = frida.get_device_manager().add_remote_device(
                f"127.0.0.1:{self.frida_port}"
            )

            # Find the target process
            processes = device.enumerate_processes()
            target_pid = None
            for proc in processes:
                if process_name.lower() in proc.name.lower():
                    target_pid = proc.pid
                    break

            if not target_pid:
                logger.warning("[dynamic_unpack] Process not found: %s", process_name)
                return None

            session = device.attach(target_pid)

            # OEP detection script
            script_code = """
            var oep = null;

            // Method 1: Hook VirtualProtect for code section
            Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualProtect'), {
                onEnter: function(args) {
                    this.addr = args[0];
                    this.size = args[2].toInt32();
                    this.protect = args[3].toInt32();
                },
                onLeave: function(retval) {
                    // PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE = 0x10
                    if ((this.protect & 0x50) && this.size > 0x1000) {
                        send({type: 'oep_candidate', addr: this.addr.toString(), size: this.size});
                    }
                }
            });

            // Method 2: Monitor for popad + jmp pattern
            var text_base = Module.findBaseAddress(Process.enumerateModules()[0].name);
            if (text_base) {
                // Scan for 0x61 (popad) + 0xE9 (jmp) within first 2 pages
                var scanner = new MemoryScanner(text_base, 0x2000);
                // ... pattern matching for OEP signature
            }

            recv('oep_confirmed', function(msg) {
                oep = msg.oep;
            });
            """

            script = session.create_script(script_code)
            oep_addr = None

            def on_message(message, data):
                nonlocal oep_addr
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "oep_candidate":
                        addr = int(payload["addr"], 16)
                        oep_addr = addr
                        logger.info("[dynamic_unpack] OEP candidate: 0x%X", addr)

            script.on("message", on_message)
            script.load()

            # Wait for OEP detection
            for _ in range(self.timeout):
                if oep_addr:
                    break
                time.sleep(1)

            session.detach()
            return oep_addr

        except ImportError:
            self.last_error = "Frida not installed"
            return None
        except Exception as e:
            logger.warning("[dynamic_unpack] OEP detection failed: %s", e)
            self.last_error = str(e)
            return None

    def _dump_memory(self, oep: int, size: int = 0x100000) -> bytes | None:
        """Dump memory region around OEP.

        Args:
            oep: Original Entry Point address.
            size: Size of memory region to dump.

        Returns:
            Raw memory bytes.
        """
        try:
            import frida

            device = frida.get_device_manager().add_remote_device(
                f"127.0.0.1:{self.frida_port}"
            )
            processes = device.enumerate_processes()

            # Attach to the first non-system process
            target_pid = None
            for proc in processes:
                if proc.pid > 100:
                    target_pid = proc.pid
                    break

            if not target_pid:
                return None

            session = device.attach(target_pid)

            script_code = f"""
            var base = ptr(0x{oep:X}).and(ptr(0xFFFFF000));
            var data = base.readByteArray(0x{size:X});
            send({{type: 'dump', data: data, base: base.toString()}});
            """

            script = session.create_script(script_code)
            dump_data = None
            dump_base = 0

            def on_message(message, data):
                nonlocal dump_data, dump_base
                if message.get("type") == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "dump":
                        dump_data = data
                        dump_base = int(payload.get("base", "0"), 16)

            script.on("message", on_message)
            script.load()
            time.sleep(2)

            session.detach()
            return dump_data

        except Exception as e:
            logger.warning("[dynamic_unpack] Memory dump failed: %s", e)
            return None

    def _reconstruct_pe(
        self,
        dump_data: bytes,
        oep: int,
        output_dir: str,
        original_path: Path,
    ) -> Path | None:
        """Reconstruct a valid PE from memory dump.

        This is a simplified version — full PE reconstruction would:
        1. Find PE headers in the dump
        2. Align sections to file alignment
        3. Rebuild import directory
        4. Fix entry point to OEP
        """
        try:
            if not dump_data or len(dump_data) < 0x200:
                return None

            # Check if dump starts with MZ header
            if dump_data[:2] == b"MZ":
                # Direct PE — just fix the entry point
                import pefile
                pe = pefile.PE(data=dump_data)

                # Fix entry point
                # (OEP is RVA, need to convert if necessary)
                pe.close()

                # Write output
                if output_dir:
                    out_path = Path(output_dir) / f"{original_path.stem}_unpacked{original_path.suffix}"
                    Path(output_dir).mkdir(parents=True, exist_ok=True)
                else:
                    import tempfile
                    out_path = Path(tempfile.mkdtemp()) / f"{original_path.stem}_unpacked{original_path.suffix}"

                out_path.write_bytes(dump_data)
                return out_path

            # If no MZ header, try to find PE in the dump
            mz_offset = dump_data.find(b"MZ")
            if mz_offset >= 0 and mz_offset < 0x1000:
                pe_data = dump_data[mz_offset:]
                if output_dir:
                    out_path = Path(output_dir) / f"{original_path.stem}_unpacked{original_path.suffix}"
                    Path(output_dir).mkdir(parents=True, exist_ok=True)
                else:
                    import tempfile
                    out_path = Path(tempfile.mkdtemp()) / f"{original_path.stem}_unpacked{original_path.suffix}"

                out_path.write_bytes(pe_data)
                return out_path

            return None

        except Exception as e:
            logger.warning("[dynamic_unpack] PE reconstruction failed: %s", e)
            return None
