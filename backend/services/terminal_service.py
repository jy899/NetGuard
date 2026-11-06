"""EVE-NG-style device interaction: an interactive CLI terminal (SSH, Telnet, laboratory console) bridged to the
browser over a WebSocket, with governance for production devices.

Flow: an authenticated POST /api/devices/{id}/terminal checks the permission, resolves the transport and the
credentials (entered, a saved profile, the device's assignment, or none for a lab console) and returns a one-time
ticket valid for 60 seconds. The browser opens /api/terminal/ws?ticket=... and xterm.js talks to the device.

Governance:
* Laboratory devices get a full session.
* Production (real-network) devices get a read-only session unless the user's group has device.terminal_config:
  every typed line is checked against the platform's configuration commands (drivers.Driver.blocked) before Enter
  reaches the device; history recall and cursor editing are disabled so the checked line is the line sent.
  Changes to production devices belong in Validation & Changes (approval, backup, verification, rollback).
* Every session is recorded in the history: who, which device, transport, mode, duration, every entered line and
  the output transcript (bounded).
* SSH host keys are pinned on first use (data/known_hosts.json); a changed key refuses the session until the user
  accepts the new key explicitly.
"""
from __future__ import annotations

import json
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from backend.collectors import drivers
from backend.core.errors import ForbiddenError, ValidationFailed

TICKET_TTL = 60
IDLE_TIMEOUT = 30 * 60
TRANSCRIPT_LIMIT = 200_000
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\r")
_tickets: dict[str, "Ticket"] = {}
_lock = threading.Lock()


@dataclass
class Ticket:
    user_id: int
    username: str
    device_id: int
    device_name: str
    network_id: int
    host: str
    port: int
    transport: str            # ssh | telnet
    platform: str
    username_device: str = ""
    password: str = ""
    guarded: bool = False
    production: bool = False
    accept_new_key: bool = False
    created: float = field(default_factory=time.monotonic)


def issue(ticket: Ticket) -> str:
    token = secrets.token_urlsafe(32)
    with _lock:
        now = time.monotonic()
        for key in [k for k, t in _tickets.items() if now - t.created > TICKET_TTL]:
            _tickets.pop(key, None)
        _tickets[token] = ticket
    return token


def redeem(token: str) -> Ticket | None:
    with _lock:
        ticket = _tickets.pop(token or "", None)
    if ticket is None or time.monotonic() - ticket.created > TICKET_TTL:
        return None
    return ticket


# ------------------------------------------------------------------ host keys (trust on first use)
def _known_hosts_path() -> Path:
    from backend.core.config import get_settings

    return Path(get_settings().settings_file).with_name("known_hosts.json")


def _known_hosts() -> dict:
    try:
        return json.loads(_known_hosts_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _pin(host: str, port: int, fingerprint: str) -> None:
    data = _known_hosts()
    data[f"{host}:{port}"] = fingerprint
    path = _known_hosts_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


class HostKeyChanged(Exception):
    def __init__(self, known: str, offered: str):
        super().__init__(f"The SSH host key changed (pinned {known}, offered {offered}).")
        self.known, self.offered = known, offered


# ------------------------------------------------------------------ device channels
class Channel:
    def send(self, data: bytes) -> None: ...
    def recv(self) -> bytes: ...
    def resize(self, cols: int, rows: int) -> None: ...
    def close(self) -> None: ...


class SshChannel(Channel):
    def __init__(self, t: Ticket, cols: int = 120, rows: int = 32):
        import paramiko

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        try:
            self.client.connect(t.host, t.port, username=t.username_device, password=t.password, timeout=12,
                                banner_timeout=12, auth_timeout=12, look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException:
            raise ValidationFailed("The device rejected the supplied credentials.") from None
        except (OSError, paramiko.SSHException) as exc:
            raise ValidationFailed(f"No SSH session to {t.host}:{t.port}: {str(exc)[:160]}") from None
        key = self.client.get_transport().get_remote_server_key()
        fingerprint = f"{key.get_name()} SHA256:{__import__('base64').b64encode(__import__('hashlib').sha256(key.asbytes()).digest()).decode().rstrip('=')}"
        known = _known_hosts().get(f"{t.host}:{t.port}")
        if known and known != fingerprint and not t.accept_new_key:
            self.client.close()
            raise HostKeyChanged(known, fingerprint)
        if known != fingerprint:
            _pin(t.host, t.port, fingerprint)
        self.fingerprint = fingerprint
        self.chan = self.client.invoke_shell(term="xterm-256color", width=cols, height=rows)
        self.chan.settimeout(0.5)

    def send(self, data: bytes) -> None:
        self.chan.sendall(data)

    def recv(self) -> bytes:
        try:
            data = self.chan.recv(8192)
        except socket.timeout:
            return b""
        if not data and (self.chan.closed or self.chan.exit_status_ready()):
            raise EOFError
        return data

    def resize(self, cols: int, rows: int) -> None:
        try:
            self.chan.resize_pty(width=cols, height=rows)
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:  # noqa: BLE001
            pass


IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA, NAWS, TTYPE = 1, 3, 31, 24


class TelnetChannel(Channel):
    """Minimal RFC 854 client: accepts the server's ECHO and SUPPRESS-GO-AHEAD, offers NAWS (window size) and
    TERMINAL-TYPE, refuses everything else. Used for laboratory consoles (EVE-NG/GNS3) and Telnet-only devices."""

    def __init__(self, t: Ticket, cols: int = 120, rows: int = 32):
        try:
            self.sock = socket.create_connection((t.host, t.port), timeout=10)
        except OSError as exc:
            raise ValidationFailed(f"No Telnet session to {t.host}:{t.port}: {exc}") from None
        self.sock.settimeout(0.5)
        self.cols, self.rows, self.naws = cols, rows, False
        self.fingerprint = None
        self._pending = b""

    def _reply(self, *parts: int) -> None:
        self.sock.sendall(bytes(parts))

    def _naws(self) -> None:
        size = bytes([self.cols >> 8, self.cols & 255, self.rows >> 8, self.rows & 255]).replace(b"\xff", b"\xff\xff")
        self.sock.sendall(bytes([IAC, SB, NAWS]) + size + bytes([IAC, SE]))

    def send(self, data: bytes) -> None:
        self.sock.sendall(data.replace(b"\xff", b"\xff\xff"))

    def recv(self) -> bytes:
        try:
            data = self.sock.recv(8192)
        except socket.timeout:
            return b""
        if not data:
            raise EOFError
        data = self._pending + data
        self._pending = b""
        out, i = bytearray(), 0
        while i < len(data):
            b = data[i]
            if b != IAC:
                out.append(b)
                i += 1
                continue
            if i + 1 >= len(data):
                self._pending = data[i:]
                break
            cmd = data[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
            elif cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= len(data):
                    self._pending = data[i:]
                    break
                opt = data[i + 2]
                if cmd == DO:
                    if opt == NAWS:
                        self._reply(IAC, WILL, NAWS)
                        self.naws = True
                        self._naws()
                    elif opt == TTYPE:
                        self._reply(IAC, WILL, TTYPE)
                    else:
                        self._reply(IAC, WONT, opt)
                elif cmd == WILL:
                    self._reply(IAC, DO if opt in (ECHO, SGA) else DONT, opt)
                i += 3
            elif cmd == SB:
                end = data.find(bytes([IAC, SE]), i)
                if end < 0:
                    self._pending = data[i:]
                    break
                if data[i + 2:i + 4] == bytes([TTYPE, 1]):
                    self.sock.sendall(bytes([IAC, SB, TTYPE, 0]) + b"XTERM" + bytes([IAC, SE]))
                i = end + 2
            else:
                i += 2
        return bytes(out)

    def resize(self, cols: int, rows: int) -> None:
        self.cols, self.rows = cols, rows
        if self.naws:
            try:
                self._naws()
            except OSError:
                pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def open_channel(t: Ticket, cols: int, rows: int) -> Channel:
    return SshChannel(t, cols, rows) if t.transport == "ssh" else TelnetChannel(t, cols, rows)


# ------------------------------------------------------------------ read-only guard
BLOCKED_KEYS = {b"\x1b[A": "history recall", b"\x1b[B": "history recall", b"\x10": "history recall",
                b"\x0e": "history recall", b"\x1b[C": "cursor editing", b"\x1b[D": "cursor editing",
                b"\x01": "cursor editing", b"\x05": "cursor editing", b"\t": "completion"}


class Guard:
    """Line discipline for read-only sessions: keeps the typed line, blocks configuration commands at Enter."""

    def __init__(self, platform: str, active: bool):
        self.driver = drivers.get(platform)
        self.active = active
        self.line = ""
        self.lines: list[str] = []

    def feed(self, data: bytes) -> tuple[bytes, str | None]:
        """(bytes to send to the device, a message for the user or None)."""
        if not self.active:
            text = data.decode("utf-8", "replace")
            for ch in text:
                if ch in "\r\n":
                    if self.line.strip():
                        self.lines.append(self.line.strip()[:300])
                    self.line = ""
                elif ch in "\x7f\x08":
                    self.line = self.line[:-1]
                elif ch >= " ":
                    self.line += ch
            return data, None
        if data in BLOCKED_KEYS:
            return b"", f"{BLOCKED_KEYS[data]} is disabled in a read-only session (type the full command)."
        out = bytearray()
        for ch in data.decode("utf-8", "replace"):
            if ch in "\r\n":
                line = self.line
                self.line = ""
                if self.driver.guard(line):
                    out += b"\x15"  # Ctrl-U: erase the typed line on the device
                    self.lines.append(f"[blocked] {line.strip()[:300]}")
                    return bytes(out) + b"\r", (f"'{line.strip()[:60]}' is a configuration command. This is a read-only "
                                               "session on a production device: propose the change in Validation & "
                                               "Changes (approval, backup, verification, rollback).")
                if line.strip():
                    self.lines.append(line.strip()[:300])
                out += b"\r"
            elif ch in "\x7f\x08":
                self.line = self.line[:-1]
                out += ch.encode()
            elif ch in "\x03\x15":
                self.line = ""
                out += ch.encode()
            elif ch == "\x1b":
                return b"", "Escape sequences are disabled in a read-only session."
            elif ch >= " ":
                self.line += ch
                out += ch.encode()
        return bytes(out), None


def clean_transcript(text: str) -> str:
    return _ANSI.sub("", text)


# ------------------------------------------------------------------ session setup
def prepare(db, user, device, data: dict) -> dict:
    """Validate permissions, resolve transport and credentials, and issue a ticket."""
    from backend.core.permissions import TERMINAL, TERMINAL_CONFIG, has
    from backend.services import collection_service, remediation_service

    if not has(user, TERMINAL):
        raise ForbiddenError("Your user group does not have the permission to open device terminals.")
    transport = (data.get("transport") or "auto").lower()
    console = collection_service.console_target(device) if device.is_lab else None
    username, password, _secret, port = remediation_service._credentials(db, user, device, data)
    if data.get("port"):
        port = int(data["port"])
    discovery = {}
    try:
        from backend.models import Network

        network = db.get(Network, device.network_id)
        discovery = next((f for f in ((network.metadata_json or {}).get("discovery") or {}).values()
                          if f.get("ip") == device.management_ip), {})
    except Exception:  # noqa: BLE001
        discovery = {}
    if transport == "auto":
        transport = "console" if console and not (username and password and device.management_ip) else "ssh"
        if transport == "ssh" and not discovery.get("ssh_port") and 23 in _open_ports(discovery):
            transport = "telnet"
    if transport == "console":
        if console is None:
            raise ValidationFailed(f"{device.name} has no laboratory console.")
        host, port = console
        wire = "telnet"
    else:
        if not device.management_ip:
            raise ValidationFailed(f"{device.name} has no management IP address.")
        host, wire = device.management_ip, "telnet" if transport == "telnet" else "ssh"
        if wire == "ssh":
            port = int(data.get("port") or discovery.get("ssh_port") or port or 22)
            if not username or not password:
                raise ValidationFailed("Enter the device username and password, or choose a saved profile.")
        else:
            port = int(data.get("port") or 23)
    production = not device.is_lab
    guarded = production and not has(user, TERMINAL_CONFIG)
    if production and data.get("mode") == "read-only":
        guarded = True
    platform = device.platform if device.platform in drivers.DRIVERS else drivers.detect(
        device.vendor, device.model, discovery.get("ssh_banner"))
    ticket = Ticket(user_id=user.id, username=user.username, device_id=device.id, device_name=device.name,
                    network_id=device.network_id, host=host, port=int(port), transport=wire, platform=platform,
                    username_device=username if wire == "ssh" else "", password=password if wire == "ssh" else "",
                    guarded=guarded, production=production, accept_new_key=bool(data.get("accept_new_key")))
    token = issue(ticket)
    return {"ticket": token, "transport": "console" if transport == "console" else wire, "host": host, "port": int(port),
            "platform": drivers.get(platform).label, "mode": "read-only" if guarded else "full",
            "production": production, "expires_in": TICKET_TTL,
            "notice": _notice(guarded, production, wire == "telnet" and transport != "console")}


def _notice(guarded: bool, production: bool, cleartext: bool) -> str:
    if guarded:
        text = ("Read-only session: configuration commands are blocked on this production device; every entered line "
                "is recorded.")
    elif production:
        text = "Full session on a production device: every entered line is recorded in the history."
    else:
        text = "Laboratory session (recorded in the history)."
    if cleartext:
        text += " Telnet is unencrypted: the login and every command cross the network in clear text; prefer SSH."
    return text


def _open_ports(discovery: dict) -> set[int]:
    ports = set()
    for service in discovery.get("open_services") or []:
        m = re.search(r"TCP (\d+)", service)
        if m:
            ports.add(int(m.group(1)))
    return ports


def record(ticket: Ticket, started: float, guard: Guard, transcript: str, reason: str, fingerprint: str | None) -> None:
    from backend.database.session import SessionLocal
    from backend.models import User
    from backend.services import history_service

    try:
        with SessionLocal() as db:
            user = db.get(User, ticket.user_id)
            history_service.record(db, user, ticket.network_id, "terminal",
                                   f"Terminal session: {ticket.device_name} ({ticket.transport})",
                                   {"device_id": ticket.device_id, "device": ticket.device_name, "host": ticket.host,
                                    "port": ticket.port, "transport": ticket.transport,
                                    "mode": "read-only" if ticket.guarded else "full", "production": ticket.production,
                                    "duration_s": round(time.monotonic() - started), "commands": len(guard.lines),
                                    "blocked": sum(1 for line in guard.lines if line.startswith("[blocked]")),
                                    "closed": reason, "host_key": fingerprint},
                                   {"lines": guard.lines[-500:], "transcript": clean_transcript(transcript)[-TRANSCRIPT_LIMIT:]})
    except Exception:  # noqa: BLE001 - recording never breaks the session teardown
        import logging

        logging.getLogger("netguard.terminal").exception("The terminal session could not be recorded")
