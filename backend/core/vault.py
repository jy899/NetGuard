"""Encryption of stored secrets: device credentials, SNMPv3 passphrases and collected configurations.

Secrets are encrypted with AES-256-GCM under a random 256-bit vault key kept in data/vault.key.
On Windows the vault key itself is protected with the Windows Data Protection API (DPAPI, CryptProtectData),
so the file is useless when copied to another Windows account or computer. On other systems the key file is
created readable by the owner only. Secrets are decrypted only when NetGuard connects to a device and are never
logged or returned by the API.

Values written by earlier versions ("enc1:" prefix, Fernet under a key derived from the token secret) are still
readable and are re-encrypted by init_db.reencrypt_legacy().
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import secrets
import sys
import threading

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc2:"
LEGACY_PREFIX = "enc1:"
_ENTROPY = b"NetGuard credential vault"
_lock = threading.Lock()
_key_cache: dict[str, bytes] = {}


# ------------------------------------------------------------------ Windows DPAPI
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _Blob:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))


def dpapi_available() -> bool:
    return sys.platform == "win32"


def dpapi_protect(data: bytes) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32  # type: ignore[attr-defined]
    out = _Blob()
    if not crypt32.CryptProtectData(ctypes.byref(_blob(data)), "NetGuard vault key", ctypes.byref(_blob(_ENTROPY)),
                                    None, None, 0x01, ctypes.byref(out)):  # CRYPTPROTECT_UI_FORBIDDEN
        raise OSError("Windows DPAPI could not protect the NetGuard vault key")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def dpapi_unprotect(data: bytes) -> bytes:
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32  # type: ignore[attr-defined]
    out = _Blob()
    if not crypt32.CryptUnprotectData(ctypes.byref(_blob(data)), None, ctypes.byref(_blob(_ENTROPY)),
                                      None, None, 0x01, ctypes.byref(out)):
        raise OSError("Windows DPAPI could not unlock the NetGuard vault key (different Windows account or computer?)")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


# ------------------------------------------------------------------ vault key
def _key_path():
    from backend.core.config import DATA_DIR

    return os.getenv("NETGUARD_VAULT_KEY_FILE") or str(DATA_DIR / "vault.key")


def protection() -> str:
    return "Windows DPAPI" if dpapi_available() else "owner-only key file"


def vault_key() -> bytes:
    path = _key_path()
    with _lock:
        if path in _key_cache:
            return _key_cache[path]
        if os.path.exists(path):
            raw = open(path, "rb").read()
            kind, _, payload = raw.partition(b":")
            blob = base64.b64decode(payload)
            key = dpapi_unprotect(blob) if kind == b"dpapi" else blob
        else:
            key = secrets.token_bytes(32)
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            stored = b"dpapi:" + base64.b64encode(dpapi_protect(key)) if dpapi_available() else b"raw:" + base64.b64encode(key)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(stored)
        if len(key) != 32:
            raise OSError("The NetGuard vault key file is damaged")
        _key_cache[path] = key
        return key


def _legacy_fernet() -> Fernet:
    from backend.core.config import get_settings

    digest = hashlib.sha256(("netguard-vault:" + get_settings().secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


# ------------------------------------------------------------------ public API
def encrypt(value: str | None) -> str | None:
    if value is None or value == "":
        return value
    nonce = secrets.token_bytes(12)
    sealed = AESGCM(vault_key()).encrypt(nonce, value.encode(), b"netguard")
    return PREFIX + base64.urlsafe_b64encode(nonce + sealed).decode()


def decrypt(value: str | None) -> str | None:
    """The secret, or None when it cannot be decrypted (for example after the vault key was replaced)."""
    if value is None or value == "":
        return value
    if value.startswith(PREFIX):
        try:
            raw = base64.urlsafe_b64decode(value[len(PREFIX):].encode())
            return AESGCM(vault_key()).decrypt(raw[:12], raw[12:], b"netguard").decode()
        except (InvalidTag, ValueError, OSError):
            return None
    if value.startswith(LEGACY_PREFIX):
        try:
            return _legacy_fernet().decrypt(value[len(LEGACY_PREFIX):].encode()).decode()
        except InvalidToken:
            return None
    return value  # a value saved before encryption was added


def is_legacy(value: str | None) -> bool:
    return bool(value) and not value.startswith(PREFIX)
