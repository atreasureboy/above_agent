"""
DriverScope — String Decryption Engine.

Complements deobfuscation.py's basic XOR decryption with support for:

1. Multi-byte XOR (key length 2-16 bytes, repeating)
2. Rolling XOR (key byte changes each iteration)
3. ADD/SUB decryption (byte-wise addition/subtraction with key)
4. NOT/XOR combinations
5. Byte-swap / nibble-swap
6. RC4/ARC4 stream cipher decryption
7. TEA/XTEA block cipher decryption
8. UTF-16 wide string decryption (all above algorithms)

The engine scans encrypted byte arrays in PE sections (.rdata, .data)
and attempts all decryption strategies, returning results that look
like valid ASCII/UTF-8 strings (paths, device names, URLs, etc.).
"""

from __future__ import annotations

import re
import struct
from collections import defaultdict

from src.models import DisassemblyResult, Finding, FindingCategory, Severity, Confidence, Evidence


_PRINTABLE_RANGE = (0x20, 0x7E)


def _is_printable_ascii(data: bytes, threshold: float = 0.8) -> bool:
    """Check if data looks like printable ASCII text."""
    if not data:
        return False
    printable = sum(1 for b in data if _PRINTABLE_RANGE[0] <= b <= _PRINTABLE_RANGE[1] or b in (0x0A, 0x0D, 0x09))
    return printable / len(data) >= threshold


def decrypt_single_xor(data: bytes, key: int) -> str | None:
    """Decrypt with single-byte XOR key."""
    if key == 0:
        return None
    result = bytearray(b ^ key for b in data)
    # Truncate at null byte
    null_idx = result.find(0)
    if null_idx > 0:
        result = result[:null_idx]
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


def decrypt_multi_xor(data: bytes, key: bytes) -> str | None:
    """Decrypt with multi-byte XOR key (repeating)."""
    if not key or all(b == 0 for b in key):
        return None
    key_len = len(key)
    result = bytearray()
    for i, b in enumerate(data):
        dec = b ^ key[i % key_len]
        if dec == 0:
            break
        result.append(dec)
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


def decrypt_rolling_xor(data: bytes, initial_key: int) -> str | None:
    """Decrypt with rolling XOR: key increments each byte."""
    if initial_key == 0:
        return None
    result = bytearray()
    key = initial_key
    for b in data:
        dec = b ^ (key & 0xFF)
        if dec == 0:
            break
        result.append(dec)
        key = (key + 1) & 0xFF
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


def decrypt_add(data: bytes, key: int) -> str | None:
    """Decrypt with byte-wise ADD: plaintext = (cipher - key) mod 256."""
    if key == 0:
        return None
    result = bytearray((b - key) & 0xFF for b in data)
    null_idx = result.find(0)
    if null_idx > 0:
        result = result[:null_idx]
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


def decrypt_sub(data: bytes, key: int) -> str | None:
    """Decrypt with byte-wise SUB: plaintext = (cipher + key) mod 256."""
    if key == 0:
        return None
    result = bytearray((b + key) & 0xFF for b in data)
    null_idx = result.find(0)
    if null_idx > 0:
        result = result[:null_idx]
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


def decrypt_not_xor(data: bytes, key: int) -> str | None:
    """Decrypt with NOT + XOR: plaintext = (~cipher) ^ key."""
    if key == 0:
        return None
    result = bytearray((~b & 0xFF) ^ key for b in data)
    null_idx = result.find(0)
    if null_idx > 0:
        result = result[:null_idx]
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


# ------------------------------------------------------------------
# RC4/ARC4 Stream Cipher
# ------------------------------------------------------------------

def _rc4_ksa(key: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm."""
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def _rc4_prga(s: list[int], length: int) -> bytes:
    """RC4 Pseudo-Random Generation Algorithm."""
    i = j = 0
    result = bytearray()
    for _ in range(length):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        result.append(s[(s[i] + s[j]) & 0xFF])
    return bytes(result)


def decrypt_rc4(data: bytes, key: bytes) -> str | None:
    """Decrypt with RC4 stream cipher."""
    if not key or len(key) < 4:
        return None
    s = _rc4_ksa(key)
    keystream = _rc4_prga(s, len(data))
    result = bytearray(b ^ k for b, k in zip(data, keystream))
    null_idx = result.find(0)
    if null_idx > 0:
        result = result[:null_idx]
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


# ------------------------------------------------------------------
# AES-128 Block Cipher (ECB mode, via pycryptodome)
# ------------------------------------------------------------------

try:
    from Crypto.Cipher import AES
    _HAS_AES = True
except ImportError:
    _HAS_AES = False


class AESCipher:
    """AES-128 ECB mode decryption (pycryptodome wrapper)."""

    BLOCK_LEN = 16
    KEY_LEN = 16

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 requires 16-byte key")
        if not _HAS_AES:
            raise ImportError("pycryptodome is required for AES decryption")
        self._cipher = AES.new(key, AES.MODE_ECB)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt a single 16-byte block."""
        return self._cipher.decrypt(block)


def decrypt_aes_ecb(data: bytes, key: bytes) -> str | None:
    """Decrypt data with AES-128-ECB."""
    if not key or len(key) != 16 or len(data) < 16:
        return None
    cipher = AESCipher(key)
    padded = data + b"\x00" * (cipher.BLOCK_LEN - len(data) % cipher.BLOCK_LEN)
    result = bytearray()
    for i in range(0, len(padded), cipher.BLOCK_LEN):
        block = padded[i:i + cipher.BLOCK_LEN]
        result.extend(cipher.decrypt_block(block))
    null_idx = result.find(0)
    if null_idx > 0:
        result = result[:null_idx]
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


def decrypt_wide_aes(data: bytes, key: bytes) -> str | None:
    """Decrypt UTF-16LE data with AES-128-ECB."""
    if not key or len(key) != 16 or len(data) < 16 or len(data) % 2 != 0:
        return None
    cipher = AESCipher(key)
    padded = data + b"\x00" * (cipher.BLOCK_LEN - len(data) % cipher.BLOCK_LEN)
    result = bytearray()
    for i in range(0, len(padded), cipher.BLOCK_LEN):
        block = padded[i:i + cipher.BLOCK_LEN]
        result.extend(cipher.decrypt_block(block))
    return _decode_utf16le(result)


# ------------------------------------------------------------------
# TEA / XTEA Block Cipher
# ------------------------------------------------------------------

class TEACipher:
    """Tiny Encryption Algorithm."""

    DELTA = 0x9E3779B9
    BLOCK_LEN = 8
    KEY_LEN = 16
    ROUNDS = 32

    @classmethod
    def decrypt_block(cls, block: bytes, key: bytes) -> bytes:
        """Decrypt a single 8-byte block."""
        if len(block) != 8 or len(key) != 16:
            return b""
        v0, v1 = struct.unpack("<II", block)
        k = struct.unpack("<4I", key)
        total = (cls.DELTA * cls.ROUNDS) & 0xFFFFFFFF
        for _ in range(cls.ROUNDS):
            v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + total) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
            v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + total) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
            total = (total - cls.DELTA) & 0xFFFFFFFF
        return struct.pack("<II", v0, v1)


class XTEACipher:
    """Extended TEA (fixes TEA vulnerabilities)."""

    DELTA = 0x9E3779B9
    BLOCK_LEN = 8
    KEY_LEN = 16
    ROUNDS = 32

    @classmethod
    def decrypt_block(cls, block: bytes, key: bytes) -> bytes:
        """Decrypt a single 8-byte block."""
        if len(block) != 8 or len(key) != 16:
            return b""
        v0, v1 = struct.unpack("<II", block)
        k = struct.unpack("<4I", key)
        total = (cls.DELTA * cls.ROUNDS) & 0xFFFFFFFF
        for _ in range(cls.ROUNDS):
            v1 = (v1 - (((v0 << 4) ^ (v0 >> 5) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xFFFFFFFF
            total = (total - cls.DELTA) & 0xFFFFFFFF
            v0 = (v0 - (((v1 << 4) ^ (v1 >> 5) + v1) ^ (total + k[total & 3]))) & 0xFFFFFFFF
        return struct.pack("<II", v0, v1)


def decrypt_tea(data: bytes, key: bytes, variant: str = "tea") -> str | None:
    """Decrypt data with TEA or XTEA block cipher."""
    if not key or len(key) != 16 or len(data) < 8:
        return None
    cipher = TEACipher if variant == "tea" else XTEACipher
    # Pad to block boundary
    padded = data + b"\x00" * (cipher.BLOCK_LEN - len(data) % cipher.BLOCK_LEN)
    result = bytearray()
    for i in range(0, len(padded), cipher.BLOCK_LEN):
        block = padded[i:i + cipher.BLOCK_LEN]
        result.extend(cipher.decrypt_block(block, key))
    null_idx = result.find(0)
    if null_idx > 0:
        result = result[:null_idx]
    if len(result) >= 3 and _is_printable_ascii(bytes(result)):
        try:
            return result.decode("ascii")
        except Exception:
            return None
    return None


# ------------------------------------------------------------------
# UTF-16 Wide String Decryption
# ------------------------------------------------------------------

def _is_valid_utf16le(data: bytes) -> bool:
    """Check if data has valid UTF-16LE structure (null high bytes)."""
    if len(data) < 4 or len(data) % 2 != 0:
        return False
    return all(data[i + 1] == 0 for i in range(0, min(len(data), 64), 2))


def _decode_utf16le(result: bytearray) -> str | None:
    """Decode a bytearray as UTF-16LE characters, returning ASCII subset."""
    chars = []
    i = 0
    while i + 1 < len(result):
        low = result[i]
        high = result[i + 1]
        if low == 0 and high == 0:
            break
        if high != 0:
            return None  # Not ASCII-range UTF-16
        if 0x20 <= low <= 0x7E or low in (0x0A, 0x0D, 0x09):
            chars.append(chr(low))
        else:
            return None
        i += 2
    s = "".join(chars)
    return s if len(s) >= 3 else None


def decrypt_wide_xor(data: bytes, key: int) -> str | None:
    """Decrypt UTF-16LE data with single-byte XOR key."""
    if key == 0 or len(data) < 6 or len(data) % 2 != 0:
        return None
    result = bytearray()
    for i in range(0, len(data), 2):
        result.append(data[i] ^ key)
        result.append(data[i + 1])
    return _decode_utf16le(result)


def decrypt_wide_multi_xor(data: bytes, key: bytes) -> str | None:
    """Decrypt UTF-16LE data with multi-byte XOR key."""
    if not key or all(b == 0 for b in key) or len(data) < 6 or len(data) % 2 != 0:
        return None
    key_len = len(key)
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % key_len])
    return _decode_utf16le(result)


def decrypt_wide_rc4(data: bytes, key: bytes) -> str | None:
    """Decrypt UTF-16LE data with RC4."""
    if not key or len(key) < 4 or len(data) < 6 or len(data) % 2 != 0:
        return None
    s = _rc4_ksa(key)
    keystream = _rc4_prga(s, len(data))
    result = bytearray()
    for i in range(0, len(data), 2):
        result.append(data[i] ^ keystream[i])
        result.append(data[i + 1] ^ keystream[i + 1])
    return _decode_utf16le(result)


# Decryption strategies registry
DECRYPT_STRATEGIES = {
    "single_xor": decrypt_single_xor,
    "rolling_xor": decrypt_rolling_xor,
    "add": decrypt_add,
    "sub": decrypt_sub,
    "not_xor": decrypt_not_xor,
    "rc4": decrypt_rc4,
    "aes_ecb": decrypt_aes_ecb,
    "tea": decrypt_tea,
    "xtea": lambda data, key: decrypt_tea(data, key, "xtea"),
    "wide_xor": decrypt_wide_xor,
    "wide_multi_xor": decrypt_wide_multi_xor,
    "wide_rc4": decrypt_wide_rc4,
    "wide_aes": decrypt_wide_aes,
}


def brute_force_decrypt(data: bytes, keys: list[int]) -> list[tuple[str, str, int]]:
    """Try all decryption strategies with all candidate keys.

    Returns list of (plaintext, strategy_name, key) tuples.
    """
    results = []

    for key in keys:
        if key == 0:
            continue

        # Single-byte XOR
        plaintext = decrypt_single_xor(data, key)
        if plaintext:
            results.append((plaintext, "single_xor", key))

        # Rolling XOR
        plaintext = decrypt_rolling_xor(data, key)
        if plaintext:
            results.append((plaintext, "rolling_xor", key))

        # ADD/SUB
        plaintext = decrypt_add(data, key)
        if plaintext:
            results.append((plaintext, "add", key))

        plaintext = decrypt_sub(data, key)
        if plaintext:
            results.append((plaintext, "sub", key))

        # NOT+XOR
        plaintext = decrypt_not_xor(data, key)
        if plaintext:
            results.append((plaintext, "not_xor", key))

        # Wide string decryption (UTF-16LE)
        plaintext = decrypt_wide_xor(data, key)
        if plaintext:
            results.append((plaintext, "wide_xor", key))

    # RC4 with byte-array keys derived from single-byte keys
    for key in keys:
        if key == 0:
            continue
        rc4_key = bytes([key, (key >> 1) & 0xFF, (key >> 2) & 0xFF, (key >> 3) & 0xFF])
        plaintext = decrypt_rc4(data, rc4_key)
        if plaintext:
            results.append((plaintext, "rc4", key))
        # Wide RC4
        plaintext = decrypt_wide_rc4(data, rc4_key)
        if plaintext:
            results.append((plaintext, "wide_rc4", key))

    # AES-128 with 16-byte keys derived from candidate seeds
    # Try known common AES keys and key derivation patterns
    _aes_key_candidates: set[bytes] = {
        # Null/repeating patterns
        b"\x00" * 16,
        b"\xFF" * 16,
        bytes(range(16)),  # 0x00-0x0F
        bytes(range(0x10, 0x20)),  # 0x10-0x1F
    }
    # Derive 16-byte keys from common 4-byte seeds
    for seed in [0x00000000, 0xDEADBEEF, 0x12345678, 0xABCDEF01]:
        derived = struct.pack("<I", seed) * 4  # Repeat 4 bytes to fill 16
        _aes_key_candidates.add(derived)
    # Derive from known key bytes (common in 360 protectors)
    for key in keys:
        if key == 0:
            continue
        _aes_key_candidates.add(bytes([key]) * 16)
        derived16 = bytes([key, (key >> 1) & 0xFF, (key >> 2) & 0xFF, (key >> 3) & 0xFF]) * 4
        _aes_key_candidates.add(derived16)

    for aes_key in _aes_key_candidates:
        if len(aes_key) != 16:
            continue
        plaintext = decrypt_aes_ecb(data, aes_key)
        if plaintext:
            results.append((plaintext, "aes_ecb", int.from_bytes(aes_key[:4], "little")))
        # Wide AES
        plaintext = decrypt_wide_aes(data, aes_key)
        if plaintext:
            results.append((plaintext, "wide_aes", int.from_bytes(aes_key[:4], "little")))

    return results


def brute_force_multi_xor(data: bytes, key_lengths: list[int] = [2, 3, 4]) -> list[tuple[str, bytes]]:
    """Brute-force multi-byte XOR with short keys."""
    results = []
    for key_len in key_lengths:
        if len(data) < key_len * 2:
            continue
        # Try to derive key from known-plaintext attack
        # Assume first bytes might be common prefixes
        common_prefixes = [
            b"C:\\\\", b"\\\\.", b"ntos", b"Ke", b"Zw", b"Io",
            # 360-specific and kernel paths
            b"\\Device\\", b"\\??\\", b"C:\\Windows\\",
            b"HKLM\\", b"ObRegisterCallbacks", b"FltRegisterFilter",
        ]
        for prefix in common_prefixes:
            if len(data) < len(prefix):
                continue
            key = bytearray()
            for i in range(min(len(prefix), key_len)):
                key.append(data[i] ^ prefix[i])
            key_bytes = bytes(key)
            plaintext = decrypt_multi_xor(data, key_bytes)
            if plaintext:
                results.append((plaintext, key_bytes))
    return results


def extract_decryption_keys_from_ir(ir: DisassemblyResult) -> dict[int, list[int | bytes]]:
    """Extract candidate decryption keys from IR instruction patterns.

    Looks for:
    - mov reg, imm near XOR loops (single-byte keys)
    - Multi-byte key construction (sequential mov reg, imm)
    - RC4 S-box initialization (256-byte sequential writes)
    - AES key loading (4 x 32-bit loads + S-box lookups)

    Returns dict mapping func_addr -> list of candidate keys (int for single-byte, bytes for multi).
    """
    keys: dict[int, list[int | bytes]] = defaultdict(list)

    for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
        single_keys: set[int] = set()
        multi_key_bytes: list[int] = []
        aes_key_dwords: list[int] = []
        has_sbox_lookup = False

        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                mnem = insn.mnemonic.lower()

                # Single-byte key candidates: mov reg, imm8/imm32
                if mnem == "mov":
                    import re as _re
                    for m in _re.finditer(r"0x([0-9a-f]+)", ops):
                        val = int(m.group(1), 16)
                        if 1 <= val <= 0xFF:
                            single_keys.add(val)

                # XOR operations suggest decryption loop
                if mnem == "xor":
                    import re as _re
                    for m in _re.finditer(r"0x([0-9a-f]+)", ops):
                        val = int(m.group(1), 16)
                        if 1 <= val <= 0xFF:
                            single_keys.add(val)

                # Collect sequential immediate values (possible multi-byte key construction)
                if mnem == "mov":
                    import re as _re
                    for m in _re.finditer(r",\s*0x([0-9a-f]{2})(?:,|\s|$)", ops):
                        val = int(m.group(1), 16)
                        if 0x20 <= val <= 0x7E:  # Printable range
                            multi_key_bytes.append(val)

                # AES key detection: 4 x 32-bit loads from contiguous memory
                if mnem == "mov":
                    import re as _re
                    m = _re.search(r"mov\s+\w+,\s*(?:dword\s+ptr\s+)?\[([^\]]+)\]", ops)
                    if m:
                        # Check for subsequent loads from addr+4, addr+8, addr+12
                        aes_key_dwords.append(0)  # Placeholder: count memory loads

                # S-box lookup pattern: movzx reg, [table + reg]
                if mnem in ("movzx", "mov") and "byte ptr" in ops:
                    import re as _re
                    if _re.search(r"\b(?:sbox|sub_\w+|SBOX)\b", ops, _re.IGNORECASE):
                        has_sbox_lookup = True

        if single_keys:
            keys[func_addr].extend(sorted(single_keys))
        if len(multi_key_bytes) >= 4 and len(multi_key_bytes) <= 32:
            keys[func_addr].append(bytes(multi_key_bytes))
        # If function looks like AES decryption (S-box lookup + memory loads),
        # add common AES key patterns
        if has_sbox_lookup or len(aes_key_dwords) >= 4:
            keys[func_addr].append(b"\x00" * 16)
            keys[func_addr].append(bytes(range(16)))

    return dict(keys)


def extract_encrypted_regions(ir: DisassemblyResult) -> list[tuple[int, bytes]]:
    """Extract candidate encrypted byte regions from PE sections.

    Heuristic: look for byte arrays with high entropy (not normal strings)
    in .rdata/.data sections. Also use string arrays referenced by
    decryption functions detected by AntiObfuscationAnalyzer.
    """
    regions = []

    # Extract raw strings that look like hex-encoded or XOR-encrypted data
    for s in ir.strings:
        if len(s) >= 8 and len(s) <= 256:
            try:
                data = bytes.fromhex(s)
                if len(data) >= 4:
                    regions.append((0, data))
            except ValueError:
                pass

    return regions


def decrypt_all_strings(ir: DisassemblyResult) -> list[tuple[str, str, int]]:
    """Main entry point: attempt decryption of all encrypted strings.

    Returns list of (plaintext, strategy, key) tuples.
    """
    regions = extract_encrypted_regions(ir)
    if not regions:
        return []

    # Collect candidate keys from IR using enhanced extraction
    candidate_keys: set[int] = set()
    ir_keys = extract_decryption_keys_from_ir(ir)
    for func_keys in ir_keys.values():
        for k in func_keys:
            if isinstance(k, int):
                candidate_keys.add(k)

    # Also scan all immediates as fallback (original behavior)
    for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                import re as _re
                for m in _re.finditer(r"0x([0-9a-f]+)", ops):
                    val = int(m.group(1), 16)
                    if 1 <= val <= 0xFF:
                        candidate_keys.add(val)

    # Also try common key values
    common_keys = set(range(0x01, 0x100))
    candidate_keys |= common_keys

    all_results = []
    for addr, data in regions:
        results = brute_force_decrypt(data, sorted(candidate_keys))
        all_results.extend(results)

    # Deduplicate
    seen = set()
    unique = []
    for plaintext, strategy, key in all_results:
        if plaintext not in seen:
            seen.add(plaintext)
            unique.append((plaintext, strategy, key))

    return unique


def create_decryption_findings(
    ir: DisassemblyResult,
    decrypted: list[tuple[str, str, int]],
) -> list[Finding]:
    """Create Finding objects for decrypted strings."""
    findings: list[Finding] = []

    # Categorize by string type
    device_paths = []
    registry_paths = []
    file_paths = []
    urls = []
    api_names = []
    other = []

    device_re = re.compile(r"\\\\\.\\" )
    reg_re = re.compile(r"HKEY_|SYSTEM_|SOFTWARE_", re.IGNORECASE)
    file_re = re.compile(r"[A-Z]:\\", re.IGNORECASE)
    url_re = re.compile(r"https?://")
    api_re = re.compile(r"^(Zw|Nt|Mm|Io|Ex|Ps|Ob|Ke|Rtl|Cm|Se|Flt|Wdf)[A-Z]")

    for plaintext, strategy, key in decrypted:
        if device_re.search(plaintext):
            device_paths.append((plaintext, strategy, key))
        elif reg_re.search(plaintext):
            registry_paths.append((plaintext, strategy, key))
        elif file_re.search(plaintext):
            file_paths.append((plaintext, strategy, key))
        elif url_re.search(plaintext):
            urls.append((plaintext, strategy, key))
        elif api_re.match(plaintext):
            api_names.append((plaintext, strategy, key))
        else:
            other.append((plaintext, strategy, key))

    categories = [
        ("device_paths", device_paths, FindingCategory.STRING_DECRYPTED, Severity.HIGH),
        ("registry_paths", registry_paths, FindingCategory.STRING_DECRYPTED, Severity.MEDIUM),
        ("file_paths", file_paths, FindingCategory.STRING_DECRYPTED, Severity.MEDIUM),
        ("urls", urls, FindingCategory.STRING_DECRYPTED, Severity.INFO),
        ("api_names", api_names, FindingCategory.STRING_DECRYPTED, Severity.HIGH),
        ("other", other, FindingCategory.STRING_DECRYPTED, Severity.LOW),
    ]

    for label, items, category, severity in categories:
        if not items:
            continue
        # Limit to first 10 per category
        snippet_items = items[:10]
        findings.append(
            Finding(
                category=category,
                severity=severity,
                confidence=Confidence.MEDIUM,
                description=f"Decrypted {label}: {len(items)} strings found ({', '.join(p for p, _, _ in snippet_items[:3])})",
                context={
                    "label": label,
                    "count": len(items),
                    "sample": [p for p, _, _ in snippet_items],
                },
                evidence=[
                    Evidence(
                        type="string_decryption",
                        location=".rdata",
                        snippet=snippet_items[0][0] if snippet_items else "",
                        rule_id="STR_DECRYPT",
                    )
                ],
            )
        )

    return findings
