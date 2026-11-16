"""Separate credential namespaces with memory and Windows DPAPI storage."""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

from .model import InputError, fingerprint
from .reports import atomic_write


@dataclass(frozen=True)
class Credential:
    kind: str
    value: str
    name: str = ""
    expires: str | None = None

    def __repr__(self):
        return f"Credential(kind={self.kind!r}, expires={self.expires!r})"

    def check(self):
        if self.kind not in {"bearer", "basic", "key", "cookie", "provider"} or not self.value:
            raise InputError("Select a supported authentication method and supply a secret.")
        if self.expires:
            try:
                expires = datetime.fromisoformat(self.expires)
                if expires.tzinfo is None:
                    raise ValueError
            except ValueError:
                raise InputError("Credential expiry requires an ISO 8601 timestamp with time zone.") from None
            if expires <= datetime.now(timezone.utc):
                raise InputError("Authentication profile has expired. Replace the credential.")


class MemorySecrets:
    def __init__(self):
        self._entries = {}

    def put(self, scope, credential):
        credential.check()
        self._entries[tuple(scope)] = credential

    def get(self, scope):
        value = self._entries.get(tuple(scope))
        if value is None:
            raise InputError("Authentication profile has no local credential.")
        value.check()
        return value

    def delete(self, scope):
        self._entries.pop(tuple(scope), None)


def dpapi(payload, protect):
    import ctypes as c
    from ctypes import wintypes as wt

    class Blob(c.Structure):
        _fields_ = [("size", wt.DWORD), ("data", c.POINTER(c.c_ubyte))]

    buffer = (c.c_ubyte * len(payload)).from_buffer_copy(payload)
    source = Blob(len(payload), buffer)
    result = Blob()
    crypt = c.WinDLL("crypt32", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    operation = crypt.CryptProtectData if protect else crypt.CryptUnprotectData
    operation.argtypes = [c.POINTER(Blob), c.c_void_p, c.c_void_p, c.c_void_p,
                          c.c_void_p, wt.DWORD, c.POINTER(Blob)]
    operation.restype = wt.BOOL
    kernel.LocalFree.argtypes = [c.c_void_p]
    kernel.LocalFree.restype = c.c_void_p
    try:
        if not operation(c.byref(source), None, None, None, None, 1, c.byref(result)):
            raise InputError("Windows could not access the protected credential.")
        return c.string_at(result.data, result.size)
    finally:
        c.memset(buffer, 0, len(payload))
        if result.data:
            c.memset(result.data, 0, result.size)
            kernel.LocalFree(result.data)


class WindowsSecrets:
    def __init__(self, path):
        self.path = Path(path)

    def entry(self, scope):
        return self.path / (fingerprint(list(scope)) + ".dpapi")

    def put(self, scope, credential):
        credential.check()
        payload = json.dumps(credential.__dict__, ensure_ascii=True).encode("ascii")
        self.path.mkdir(parents=True, exist_ok=True)
        atomic_write(self.entry(scope), dpapi(payload, True).hex(), replace=True)

    def get(self, scope):
        entry = self.entry(scope)
        if not entry.is_file():
            raise InputError("Authentication profile has no local credential.")
        try:
            if entry.stat().st_size > 131072:
                raise ValueError
            value = Credential(**json.loads(dpapi(bytes.fromhex(entry.read_text("ascii")), False)))
        except (ValueError, OSError, TypeError):
            raise InputError("The stored credential could not be read. Replace it.") from None
        value.check()
        return value

    def delete(self, scope):
        self.entry(scope).unlink(missing_ok=True)
