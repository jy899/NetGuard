"""Test-only Cisco IOS command-line emulator served over SSH (paramiko) and a Telnet console.

It lets the test suite exercise NetGuard's real Netmiko transport, parsers and laboratory remediation without
network equipment: show commands return recorded outputs, the running configuration is rendered from its lines,
and configuration mode edits those lines (enough for the change types NetGuard generates). It is never imported
by the application.
"""
from __future__ import annotations

import re
import socket
import socketserver
import threading

import paramiko

ABBREV = {"gi": "GigabitEthernet", "fa": "FastEthernet", "te": "TenGigabitEthernet", "e": "Ethernet",
          "eth": "Ethernet", "lo": "Loopback", "vl": "Vlan", "po": "Port-channel"}


def full_if(name: str) -> str:
    m = re.match(r"([A-Za-z-]+)\s*([\d/.:]+)$", name.strip())
    if not m:
        return name.strip()
    word, num = m.groups()
    for full in ABBREV.values():
        if full.lower() == word.lower():
            return full + num
    return ABBREV.get(word.lower(), word) + num


class Device:
    def __init__(self, hostname: str, config: str, outputs: dict[str, str] | None = None,
                 username: str = "netguard", password: str = "Lab-Pass1", reject: tuple[str, ...] = (),
                 rewrite: dict[str, str] | None = None):
        self.hostname, self.username, self.password = hostname, username, password
        self.outputs = outputs or {}
        self.lines = [line.rstrip() for line in config.splitlines() if line.strip() and line.strip() != "end"]
        self.reject = reject  # configuration commands answered with "% Invalid input" (failure tests)
        self.rewrite = rewrite or {}  # configuration commands silently replaced by others (verification tests)
        self.history: list[str] = []
        self.startup = list(self.lines)  # what "write memory" saved; a reload would restore it
        self.exec_history: list[str] = []
        self.lock = threading.Lock()

    # ------------------------------------------------------------ configuration
    def running(self) -> str:
        body = "\n".join(self.lines)
        return f"Building configuration...\n\nCurrent configuration : {len(body)} bytes\n!\n{body}\n!\nend"

    def _block(self, header: str) -> tuple[int, int]:
        for i, line in enumerate(self.lines):
            if not line.startswith(" ") and line.strip().lower() == header.lower():
                j = i + 1
                while j < len(self.lines) and self.lines[j].startswith(" "):
                    j += 1
                return i, j
        self.lines.append(header)
        return len(self.lines) - 1, len(self.lines)

    def configure(self, ctx: str | None, command: str) -> tuple[str | None, str]:
        cmd = command.strip()
        self.history.append(cmd)
        cmd = self.rewrite.get(cmd, cmd)
        if any(cmd.startswith(r) for r in self.reject):
            return ctx, "% Invalid input detected at '^' marker."
        words = cmd.split()
        if not words:
            return ctx, ""
        if words[0] == "interface":
            return "interface " + full_if(" ".join(words[1:])), ""
        if words[:2] == ["router", "ospf"] or (words[0] == "vlan" and len(words) == 2) or words[:2] == ["ip", "access-list"]:
            return cmd, ""
        if words[0] == "exit":
            return None, ""
        if ctx and not cmd.startswith(("ip route", "no ip route", "hostname", "access-list", "no access-list")):
            with self.lock:
                start, end = self._block(ctx)
                negate = words[0] == "no"
                body = words[1:] if negate else words
                key = " ".join(body[:3] if body[:2] == ["ip", "ospf"] else body[:2]) if len(body) > 1 else body[0]
                kept = [line for line in self.lines[start + 1:end] if not line.strip().startswith(key)]
                if not negate:
                    kept.append(" " + cmd)
                self.lines[start + 1:end] = kept
            return ctx, ""
        with self.lock:
            if words[0] == "no":
                target = " ".join(words[1:])
                kept, skipping = [], False
                for line in self.lines:  # removing a section header removes its child lines, as on IOS
                    if not line.startswith(" "):
                        skipping = line.strip() == target
                    if not skipping:
                        kept.append(line)
                self.lines = kept
            else:
                self.lines.append(cmd)
        return None, ""

    def show(self, command: str) -> str:
        cmd = " ".join(command.split())
        if cmd in ("show running-config", "show run"):
            return self.running()
        if cmd in ("show startup-config", "show start"):
            body = "\n".join(self.startup)
            return f"Using {len(body)} out of 262144 bytes\n!\n{body}\n!\nend"
        for key, value in self.outputs.items():
            if cmd == key:
                return value
        return "% Invalid input detected at '^' marker."


class Session:
    """Line discipline shared by the SSH and Telnet servers."""

    def __init__(self, device: Device, write):
        self.device, self.write = device, write
        self.mode, self.ctx = "exec", None

    @property
    def prompt(self) -> str:
        if self.mode == "exec":
            return f"{self.device.hostname}#"
        if self.ctx and self.ctx.startswith("interface"):
            return f"{self.device.hostname}(config-if)#"
        if self.ctx:
            return f"{self.device.hostname}(config-sub)#"
        return f"{self.device.hostname}(config)#"

    def line(self, text: str) -> None:
        cmd = text.strip()
        out = ""
        if self.mode == "exec":
            if cmd in ("configure terminal", "conf t", "config term"):
                self.mode = "config"
                out = "Enter configuration commands, one per line.  End with CNTL/Z."
            elif cmd.startswith(("terminal ", "terminal")) or cmd == "":
                out = ""
            elif cmd.startswith("show"):
                out = self.device.show(cmd)
            elif cmd in ("write memory", "write", "copy running-config startup-config"):
                self.device.exec_history.append(cmd)
                self.device.startup = list(self.device.lines)
                out = "Building configuration...\n[OK]"
            elif cmd.startswith("reload in ") or cmd == "reload cancel":
                self.device.exec_history.append(cmd)
                out = "Reload scheduled." if cmd != "reload cancel" else "***\n*** --- SHUTDOWN ABORTED ---\n***"
            elif cmd in ("exit", "logout"):
                raise EOFError
            else:
                out = "% Invalid input detected at '^' marker."
        else:
            if cmd in ("end", "\x1a"):
                self.mode, self.ctx = "exec", None
            elif cmd == "exit" and self.ctx is None:
                self.mode = "exec"
            elif cmd:
                self.ctx, out = self.device.configure(self.ctx, cmd)
        self.write(("\r\n" + out.replace("\n", "\r\n") if out else "") + "\r\n" + self.prompt)


# ------------------------------------------------------------------ SSH
class _Server(paramiko.ServerInterface):
    def __init__(self, device: Device):
        self.device = device
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        ok = username == self.device.username and password == self.device.password
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, *args):
        return True


_HOST_KEY = None


def _host_key():
    global _HOST_KEY
    if _HOST_KEY is None:
        _HOST_KEY = paramiko.RSAKey.generate(1024)
    return _HOST_KEY


def _serve_channel(channel, device: Device) -> None:
    session = Session(device, lambda text: channel.sendall(text.encode()))
    channel.sendall(f"\r\n{session.prompt}".encode())
    buffer, last_cr = "", False
    try:
        while True:
            data = channel.recv(1024)
            if not data:
                break
            for ch in data.decode("utf-8", "replace"):
                if ch in "\r\n":
                    if ch == "\n" and last_cr:
                        last_cr = False
                        continue
                    last_cr = ch == "\r"
                    channel.sendall(buffer.encode())
                    line, buffer = buffer, ""
                    session.line(line)
                else:
                    last_cr = False
                    buffer += ch
    except (EOFError, OSError):
        pass
    finally:
        channel.close()


class SshEmulator:
    """One listening port per device, on 127.0.0.1 or another loopback address (127.0.0.2, ...)."""

    def __init__(self, device: Device, host: str = "127.0.0.1", port: int = 0):
        self.device, self.host = device, host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while self.running:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-Cisco-1.25"
        transport.add_server_key(_host_key())
        server = _Server(self.device)
        try:
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is None:
                return
            server.event.wait(10)
            _serve_channel(channel, self.device)
        except Exception:  # noqa: BLE001 - client went away
            pass
        finally:
            transport.close()

    def close(self):
        self.running = False
        self.sock.close()


# ------------------------------------------------------------------ Telnet console (no authentication, like EVE-NG)
class TelnetEmulator:
    def __init__(self, device: Device):
        device_ref = device

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                session = Session(device_ref, lambda text: sock.sendall(text.encode()))
                sock.sendall(f"\r\n{session.prompt}".encode())
                buffer, last_cr, iac = "", False, 0
                try:
                    while True:
                        data = sock.recv(1024)
                        if not data:
                            return
                        for byte in data:
                            if iac:  # skip telnet option negotiation
                                iac = iac - 1 if byte not in (251, 252, 253, 254) else 1
                                continue
                            if byte == 255:
                                iac = 2
                                continue
                            ch = chr(byte)
                            if ch in "\r\n\x00":
                                if ch != "\r" and last_cr:
                                    last_cr = False
                                    continue
                                last_cr = ch == "\r"
                                if ch == "\x00":
                                    continue
                                sock.sendall(buffer.encode())
                                line, buffer = buffer, ""
                                session.line(line)
                            else:
                                last_cr = False
                                buffer += ch
                except (EOFError, OSError):
                    return

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
