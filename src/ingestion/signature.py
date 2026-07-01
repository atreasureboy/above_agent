"""
DriverScope — PE Digital Signature Verification.

Uses Windows WinVerifyTrust API (ctypes) to check Authenticode signatures
of .sys files. Extracts signer name from the certificate chain.

On non-Windows platforms, returns (UNSIGNED, "").
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import platform
import subprocess
from pathlib import Path

from ..models import SignatureStatus


class _GUID(ctypes.Structure):
    """GUID structure for Win32 API calls."""
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# WinTrust constants
_TRUST_E_CERT_EXPIRED = 0x800B0101
_TRUST_E_NOSIGNATURE = 0x800B0100

WTH_CHOICEOFDATA_FILE = 1
WTH_STATEACTION_VERIFY = 1
WTH_STATEACTION_CLOSE = 2
WTH_UICHOICE_NONE = 2
WTH_REVOCATION_CHECK_NONE = 10
WTH_SAFORCEFLAG_ASK = 4

WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


def verify_signature(file_path: Path) -> tuple[SignatureStatus, str]:
    """Verify the Authenticode signature of a PE file.

    Returns:
        (SignatureStatus, signer_name): The verification status and the
        name of the signer. On non-Windows or for unsigned files,
        returns (UNSIGNED, "").
    """
    if platform.system() != "Windows":
        return SignatureStatus.UNSIGNED, ""

    if not file_path.exists():
        return SignatureStatus.UNSIGNED, ""

    try:
        trust_status = _win_verify_trust(file_path)
    except Exception:
        return SignatureStatus.SIGNED_INVALID, ""

    if trust_status == 0:
        signer = _extract_signer_name(file_path)
        return SignatureStatus.SIGNED_VALID, signer
    elif trust_status == _TRUST_E_CERT_EXPIRED:
        signer = _extract_signer_name(file_path)
        return SignatureStatus.SIGNED_EXPIRED, signer
    elif trust_status == _TRUST_E_NOSIGNATURE:
        return SignatureStatus.UNSIGNED, ""
    else:
        return SignatureStatus.SIGNED_UNTRUSTED, ""


def _win_verify_trust(file_path: Path) -> int:
    """Call WinVerifyTrust to verify Authenticode signature.

    Returns the HRESULT (as unsigned 32-bit integer).
    """
    wintrust = ctypes.windll.Wintrust

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.wintypes.DWORD),
            ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
            ("hFile", ctypes.wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(_GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.wintypes.DWORD),
            ("fdwRevocationChecks", ctypes.wintypes.DWORD),
            ("dwUnionChoice", ctypes.wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.wintypes.DWORD),
            ("hWVTStateData", ctypes.wintypes.HANDLE),
            ("pwszURLReference", ctypes.wintypes.LPCWSTR),
            ("dwProvFlags", ctypes.wintypes.DWORD),
            ("dwUIContext", ctypes.wintypes.DWORD),
        ]

    wfi = WINTRUST_FILE_INFO()
    wfi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    wfi.pcwszFilePath = str(file_path)
    wfi.hFile = None
    wfi.pgKnownSubject = None

    wtd = WINTRUST_DATA()
    wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    wtd.dwUIChoice = WTH_UICHOICE_NONE
    wtd.fdwRevocationChecks = WTH_REVOCATION_CHECK_NONE
    wtd.dwUnionChoice = WTH_CHOICEOFDATA_FILE
    wtd.pFile = ctypes.pointer(wfi)
    wtd.dwStateAction = WTH_STATEACTION_VERIFY
    wtd.hWVTStateData = None
    wtd.pwszURLReference = None
    wtd.dwProvFlags = WTH_SAFORCEFLAG_ASK
    wtd.dwUIContext = 0

    result = wintrust.WinVerifyTrust(
        None,
        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.pointer(wtd),
    )

    # Close the trust handle
    wtd.dwStateAction = WTH_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(
        None,
        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.pointer(wtd),
    )

    # Convert to unsigned 32-bit (ctypes may return signed negative
    # for HRESULTs with the high bit set).
    return result & 0xFFFFFFFF


def _extract_signer_name(file_path: Path) -> str:
    """Extract the signer's name from a PE file's Authenticode signature.

    Uses signtool verify via subprocess as the most reliable cross-
    approach method (works for both embedded and catalog signatures).
    Falls back to PowerShell Get-AuthenticodeSignature if signtool is
    unavailable.
    """
    # Try signtool first
    name = _extract_via_signtool(file_path)
    if name:
        return name

    # Fallback to PowerShell
    name = _extract_via_powershell(file_path)
    if name:
        return name

    return ""


def _extract_via_signtool(file_path: Path) -> str:
    """Try to extract signer name using signtool verify /pa /v."""
    try:
        result = subprocess.run(
            ["signtool", "verify", "/pa", "/v", str(file_path)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            # Look for "Issued to:" line in verbose output
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Issued to:"):
                    return line.split(":", 1)[1].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return ""


def _extract_via_powershell(file_path: Path) -> str:
    """Fallback: extract signer name using PowerShell Get-AuthenticodeSignature."""
    try:
        ps_cmd = (
            f'$sig = Get-AuthenticodeSignature "{file_path}"; '
            f'$cert = $sig.SignerCertificate; '
            f'if ($cert) {{ $cert.SubjectName.Name }}'
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10,
        )
        name = result.stdout.strip()
        if name and name != "None":
            # Clean up CN= prefix if present
            if name.startswith("CN="):
                name = name[3:]
            # Take the first comma-separated component (usually CN)
            parts = name.split(",")
            return parts[0].strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""
