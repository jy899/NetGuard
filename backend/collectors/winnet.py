"""Native Windows network probes through the IP Helper API (iphlpapi.dll), with no process per address.

Spawning ping.exe for every address of a /24 (the earlier approach) is slow on Windows and, under load or with
endpoint protection inspecting every new process, makes most probes time out: a scan then reports
"0 of 254 address(es) answered" even for this computer itself. The IP Helper API is what Windows' own tools and
LAN scanners use, needs no administrator rights and releases the GIL while it waits, so a thread pool scales:

* IcmpSendEcho: one ICMP echo with a TTL; the reply status and TTL (also used hop by hop for traceroute).
* SendARP: an ARP request for an on-link address. A host that drops ICMP and every TCP port still answers ARP,
  so this finds firewalled Windows PCs, phones and IoT devices on the same segment.

Every function returns None when the API is not available, so callers fall back to the portable probes.
"""
from __future__ import annotations

import platform
import socket
import threading

IS_WINDOWS = platform.system() == "Windows"
IP_SUCCESS = 0
IP_TTL_EXPIRED_TRANSIT = 11013
IP_DEST_HOST_UNREACHABLE = 11003

_lib = None
_lock = threading.Lock()
_types = None


def _load():
    """The iphlpapi bindings, or None off Windows or when the API cannot be loaded."""
    global _lib, _types
    if not IS_WINDOWS:
        return None
    with _lock:
        if _lib is not None:
            return _lib or None
        try:
            import ctypes
            from ctypes import wintypes

            class IpOptionInformation(ctypes.Structure):
                _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                            ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

            class IcmpEchoReply(ctypes.Structure):
                _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                            ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                            ("Options", IpOptionInformation)]

            lib = ctypes.WinDLL("iphlpapi.dll")
            lib.IcmpCreateFile.restype = wintypes.HANDLE
            lib.IcmpCreateFile.argtypes = []
            lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
            lib.IcmpCloseHandle.restype = wintypes.BOOL
            lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, wintypes.WORD,
                                         ctypes.POINTER(IpOptionInformation), ctypes.c_void_p, wintypes.DWORD,
                                         wintypes.DWORD]
            lib.IcmpSendEcho.restype = wintypes.DWORD
            lib.SendARP.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            lib.SendARP.restype = wintypes.DWORD
            _types = (ctypes, IpOptionInformation, IcmpEchoReply)
            _lib = lib
        except (OSError, AttributeError, ImportError):
            _lib = False
            return None
    return _lib


def available() -> bool:
    return _load() is not None


def _ipaddr(ip: str) -> int:
    """IPAddr as the API expects it: the network-order bytes read as a native (little-endian) ULONG."""
    return int.from_bytes(socket.inet_aton(ip), "little")


def _ip_from(value: int) -> str:
    return socket.inet_ntoa(int(value).to_bytes(4, "little"))


def echo(ip: str, timeout_ms: int = 800, ttl: int = 128) -> tuple[int, str, int] | None:
    """One ICMP echo. Returns (status, address that answered, reply TTL), or None if nothing answered or the
    API is unavailable. status is IP_SUCCESS for an echo reply or IP_TTL_EXPIRED_TRANSIT from a router hop."""
    lib = _load()
    if lib is None:
        return None
    ctypes, IpOptionInformation, IcmpEchoReply = _types
    handle = lib.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None
    try:
        payload = b"NetGuard-discovery"
        data = ctypes.create_string_buffer(payload, len(payload))
        size = ctypes.sizeof(IcmpEchoReply) + len(payload) + 8 + 64
        reply = ctypes.create_string_buffer(size)
        options = IpOptionInformation(Ttl=ttl)
        count = lib.IcmpSendEcho(handle, _ipaddr(ip), data, len(payload), ctypes.byref(options), reply, size,
                                 int(timeout_ms))
        parsed = IcmpEchoReply.from_buffer_copy(reply.raw[:ctypes.sizeof(IcmpEchoReply)])
        # A TTL-expired answer may be returned with a count of 0 and the reply written to the buffer.
        if not count and not parsed.Address:
            return None
        if parsed.Status not in (IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT):
            return None
        return int(parsed.Status), _ip_from(parsed.Address), int(parsed.Options.Ttl)
    except (OSError, ValueError):
        return None
    finally:
        lib.IcmpCloseHandle(handle)


def ping_ttl(ip: str, timeout_ms: int = 800) -> int | None:
    result = echo(ip, timeout_ms)
    if result is None or result[0] != IP_SUCCESS or result[1] != ip:
        return None
    return result[2]


def arp_resolve(ip: str) -> str | None:
    """MAC address of an on-link host through an ARP request (SendARP); None when it does not answer."""
    lib = _load()
    if lib is None:
        return None
    ctypes = _types[0]
    buffer = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(6)
    try:
        if lib.SendARP(_ipaddr(ip), 0, buffer, ctypes.byref(length)) != 0 or length.value != 6:
            return None
    except OSError:
        return None
    mac = ":".join(f"{b:02x}" for b in bytes(buffer)[:6])
    return None if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else mac


def traceroute(ip: str, max_hops: int = 12, timeout_ms: int = 900) -> list[str | None] | None:
    """Router hops towards ip (TTL-limited echoes); None per hop that did not answer. None if unavailable."""
    if _load() is None:
        return None
    hops: list[str | None] = []
    for ttl in range(1, max_hops + 1):
        result = echo(ip, timeout_ms, ttl)
        hops.append(result[1] if result else None)
        if result and result[0] == IP_SUCCESS:
            break
    return hops
