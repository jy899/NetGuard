"""Credential-free network probes: ICMP echo, TCP management ports, service banners, ARP, DNS and the gateway.

Every probe is read-only and targets only addresses inside the authorised workspace range. Nothing here sends a
username, password or SNMP community string.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import ssl
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = platform.system() == "Windows"
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW: no console flashes from the desktop app

# Management and identification ports probed on every responding address.
MANAGEMENT_PORTS = {22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 830: "NETCONF", 8443: "HTTPS-alt"}
# Web management portals of network devices listen on many more ports than 80/443 (FortiGate admin on 8443 or
# 10443, SSL-VPN portals on 4443/10443, UniFi on 8443, MikroTik webfig on 80/8291 Winbox, appliances on 8080...).
WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt", 10443: "HTTPS (FortiGate/SSL-VPN)",
             4443: "HTTPS-alt", 8000: "HTTP-alt", 8008: "HTTP-alt", 8081: "HTTP-alt", 8888: "HTTP-alt",
             9443: "HTTPS-alt", 7443: "HTTPS-alt", 81: "HTTP-alt", 8291: "Winbox (MikroTik)", 8880: "HTTP-alt"}
HOST_PORTS = {135: "MS-RPC", 139: "NetBIOS-SSN", 445: "SMB", 3389: "RDP", 9100: "JetDirect", 631: "IPP",
              554: "RTSP", 5060: "SIP", 53: "DNS", 5900: "VNC", 161: "SNMP"}
HOST_PORTS.pop(161)  # SNMP is UDP: probed by SNMPv3 engine discovery, never as a TCP port
SWEEP_PORTS = (22, 23, 80, 443, 8080, 8443)  # also used to find hosts that drop ICMP


def _run(args: list[str], timeout: float) -> str:
    """stdout of a system command; console code pages are decoded leniently (localised Windows output)."""
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=_NO_WINDOW)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    raw = result.stdout or b""
    for encoding in (("oem", "mbcs") if IS_WINDOWS else ()) + ("utf-8",):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("latin-1", "replace")


def ping_available() -> bool:
    from backend.collectors import winnet

    return winnet.available() or shutil.which("ping") is not None


def ping_method() -> str:
    from backend.collectors import winnet

    if winnet.available():
        return "Windows IP Helper API (IcmpSendEcho, SendARP)"
    return "system ping" if shutil.which("ping") else "TCP only"


def sweep_workers() -> int:
    """Concurrent probes: native API calls scale; one ping process per address does not."""
    from backend.collectors import winnet

    return 128 if winnet.available() or not IS_WINDOWS else 24


def ping_ttl(ip: str, timeout_ms: int = 800) -> int | None:
    """One ICMP echo (Windows IP Helper API, else the system ping without raw-socket privilege); the reply's TTL."""
    from backend.collectors import winnet

    if winnet.available():
        return winnet.ping_ttl(ip, timeout_ms)
    if IS_WINDOWS:
        out = _run(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout_ms / 1000 + 5)
    else:
        out = _run(["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip], timeout_ms / 1000 + 2)
    # Windows prints "Reply from <gateway>: Destination host unreachable" with exit code 0, so require a TTL.
    match = re.search(r"ttl[=\s](\d+)", out, re.I)
    return int(match.group(1)) if match else None


def ping(ip: str, timeout_ms: int = 800) -> bool:
    return ping_ttl(ip, timeout_ms) is not None


def arp_ping(ip: str) -> str | None:
    """MAC of an on-link host from an explicit ARP request (Windows SendARP). Elsewhere the ARP cache filled by
    the ICMP/TCP sweep is read instead (arp_table), because sending ARP needs raw-socket privilege."""
    from backend.collectors import winnet

    return winnet.arp_resolve(ip) if winnet.available() else None


def traceroute(ip: str, max_hops: int = 12) -> list[str | None]:
    """Layer-3 hops towards ip (None for a hop that did not answer). Empty when no method is available."""
    from backend.collectors import winnet

    hops = winnet.traceroute(ip, max_hops) if winnet.available() else None
    if hops is not None:
        return hops
    if IS_WINDOWS:
        out = _run(["tracert", "-d", "-h", str(max_hops), "-w", "800", ip], max_hops * 3 + 5)
        rows = re.findall(r"^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+|Request timed out)", out, re.M)
    elif shutil.which("traceroute"):
        out = _run(["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), ip], max_hops * 2 + 5)
        rows = re.findall(r"^\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)", out, re.M)
    elif shutil.which("tracepath"):
        out = _run(["tracepath", "-n", "-m", str(max_hops), ip], max_hops * 2 + 5)
        rows = re.findall(r"^\s*(\d+)\??:\s+(\d+\.\d+\.\d+\.\d+|no reply)", out, re.M)
    else:
        return []
    hops: dict[int, str | None] = {}
    for number, address in rows:
        hops.setdefault(int(number), address if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", address) else None)
    return [hops[n] for n in sorted(hops)]


def mdns_name(ip: str, timeout: float = 0.8) -> str | None:
    """The host's mDNS/Bonjour name from a unicast reverse-PTR query to its port 5353 (Apple, Linux/Avahi,
    printers, Chromecast and many IoT devices answer legacy unicast queries)."""
    import secrets
    import struct

    try:
        reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        qname = b"".join(bytes([len(p)]) + p.encode() for p in reverse.split(".")) + b"\x00"
        tid = secrets.randbelow(0xFFFF)
        packet = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, 5353))
            data, _ = sock.recvfrom(2048)
    except (OSError, ValueError):
        return None
    try:
        if len(data) < 12 or struct.unpack(">H", data[6:8])[0] == 0:
            return None

        def read_name(offset: int, depth: int = 0) -> tuple[str, int]:
            labels, jumped, end = [], False, offset
            while depth < 20:
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if length & 0xC0 == 0xC0:
                    pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
                    if not jumped:
                        end = offset + 2
                    jumped, offset, depth = True, pointer, depth + 1
                    continue
                labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
                offset += length + 1
            return ".".join(labels), (end if jumped else offset)
        offset = 12
        for _ in range(struct.unpack(">H", data[4:6])[0]):  # skip questions
            _, offset = read_name(offset)
            offset += 4
        _, offset = read_name(offset)
        rtype = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 10
        if rtype != 12:
            return None
        name, _ = read_name(offset)
    except (IndexError, struct.error):
        return None
    name = name.removesuffix(".local").strip(".")
    return name[:63] or None


def ttl_hint(ttl: int | None) -> str | None:
    """The usual initial TTL family of a reply (a hint, never an identification)."""
    if ttl is None:
        return None
    if ttl <= 64:
        return "initial TTL 64 (Linux, macOS, Android, iOS or embedded systems)"
    if ttl <= 128:
        return "initial TTL 128 (Windows)"
    return "initial TTL 255 (network operating systems such as Cisco IOS, or Solaris)"


def netbios_status(ip: str, timeout: float = 1.0, port: int = 137) -> dict | None:
    """NetBIOS node status (NBSTAT, UDP 137): the computer name, workgroup and adapter MAC a Windows/Samba host
    publishes to anyone who asks. No credential is involved."""
    import secrets
    import struct

    tid = secrets.randbelow(0xFFFF)
    encoded = bytes([0x20]) + b"CK" + b"A" * 30 + b"\x00"  # the wildcard name "*"
    packet = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0) + encoded + struct.pack(">HH", 0x21, 0x01)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(2048)
    except OSError:
        return None
    try:
        if len(data) < 57 or struct.unpack(">H", data[:2])[0] != tid:
            return None
        offset = 12
        while data[offset] != 0:  # skip the echoed name
            offset += data[offset] + 1
        offset += 1 + 2 + 2 + 4  # terminator, type, class, TTL
        offset += 2  # rdlength
        count = data[offset]
        offset += 1
        names, workgroup, computer = [], None, None
        for _ in range(count):
            raw_name = data[offset:offset + 15].decode("ascii", "replace").strip()
            suffix, flags = data[offset + 15], struct.unpack(">H", data[offset + 16:offset + 18])[0]
            offset += 18
            group = bool(flags & 0x8000)
            names.append((raw_name, suffix, group))
            if suffix == 0x00 and not group and computer is None:
                computer = raw_name
            if suffix == 0x00 and group and workgroup is None:
                workgroup = raw_name
        mac = ":".join(f"{b:02x}" for b in data[offset:offset + 6]) if offset + 6 <= len(data) else None
    except (IndexError, struct.error):
        return None
    if not computer:
        return None
    return {"name": computer, "workgroup": workgroup, "mac": None if mac in (None, "00:00:00:00:00:00") else mac,
            "services": sorted({f"0x{s:02x}" for _, s, _ in names})}


def ssdp_discover(scope, timeout: float = 2.5) -> dict[str, dict]:
    """UPnP devices answering an SSDP M-SEARCH on this computer's segment: IP -> server, device type and location.
    Only answers from addresses inside `scope` (an IPv4 network) are kept."""
    message = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
               "ST: ssdp:all\r\n\r\n").encode()
    found: dict[str, dict] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(0.5)
            sock.sendto(message, ("239.255.255.250", 1900))
            import time as _time
            end = _time.monotonic() + timeout
            while _time.monotonic() < end:
                try:
                    data, (ip, _) = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                if ipaddress.IPv4Address(ip) not in scope:
                    continue
                headers = {}
                for line in data.decode("latin-1", "replace").splitlines()[1:]:
                    key, _, value = line.partition(":")
                    if key:
                        headers[key.strip().lower()] = value.strip()
                row = found.setdefault(ip, {"server": None, "location": None, "types": set()})
                row["server"] = row["server"] or headers.get("server")
                row["location"] = row["location"] or headers.get("location")
                if headers.get("st", "").startswith("urn:"):
                    row["types"].add(headers["st"])
    except OSError:
        return {}
    for row in found.values():
        row["types"] = sorted(row["types"])
    return found


def upnp_description(location: str, scope, timeout: float = 2.0) -> dict | None:
    """friendlyName, manufacturer and model from a UPnP device description (HTTP GET inside the scope only)."""
    import urllib.parse
    import urllib.request

    try:
        host = urllib.parse.urlparse(location).hostname
        if not host or ipaddress.IPv4Address(host) not in scope:
            return None
        with urllib.request.urlopen(location, timeout=timeout) as response:  # noqa: S310 - in-scope device URL
            body = response.read(65536).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    fields = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType"):
        match = re.search(rf"<{tag}>\s*([^<]{{1,120}})\s*</{tag}>", body)
        if match:
            fields[tag] = match.group(1).strip()
    return fields or None


def http_title(ip: str, port: int, tls: bool, timeout: float = 2.0) -> str | None:
    """The <title> of the web page a device serves on / (often names the product)."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = raw
        if tls:
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=ip)
        with sock:
            sock.settimeout(timeout)
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetGuard\r\n\r\n".encode())
            data = b""
            while len(data) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
    except (OSError, ssl.SSLError):
        return None
    match = re.search(rb"<title[^>]*>([^<]{1,120})</title>", data, re.I)
    return match.group(1).decode("utf-8", "replace").strip() or None if match else None


def tcp_open(ip: str, port: int, timeout: float = 0.7) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_banner(ip: str, port: int = 22, timeout: float = 2.0) -> str | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256).decode("ascii", "replace")
            line = data.splitlines()[0].strip() if data else ""
            return line[:120] if line.startswith("SSH-") else None
    except OSError:
        return None


def http_server(ip: str, port: int, tls: bool, timeout: float = 2.0) -> str | None:
    """The Server header (or HTTP status line) of a HEAD request; certificate errors are expected on devices."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = raw
        if tls:
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=ip)
        with sock:
            sock.settimeout(timeout)
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetGuard\r\n\r\n".encode())
            data = sock.recv(2048).decode("latin-1", "replace")
    except (OSError, ssl.SSLError):
        return None
    server = re.search(r"^Server:\s*(.+)$", data, re.I | re.M)
    if server:
        return server.group(1).strip()[:80]
    status = data.splitlines()[0].strip() if data else ""
    return status[:80] or None


def tls_subject(ip: str, port: int = 443, timeout: float = 2.0) -> dict | None:
    """Subject and issuer names of the certificate presented on a TLS port (not verified)."""
    try:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw, \
                context.wrap_socket(raw, server_hostname=ip) as sock:
            der = sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(der)

        def name(n):
            parts = {a.oid: a.value for a in n}
            return parts.get(NameOID.COMMON_NAME) or parts.get(NameOID.ORGANIZATION_NAME)
        return {"subject": name(cert.subject), "issuer": name(cert.issuer)}
    except Exception:  # noqa: BLE001 - a malformed device certificate is not fatal
        return None


def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return name if name and name != ip else None


_MAC = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    digits = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(digits) != 12:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def arp_table() -> dict[str, str]:
    """The operating system's ARP/neighbour cache: IP -> MAC (complete entries only)."""
    entries: dict[str, str] = {}
    if IS_WINDOWS:
        for line in _run(["arp", "-a"], 5).splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]) and _MAC.fullmatch(parts[1]):
                entries[parts[0]] = normalize_mac(parts[1])
        return entries
    try:
        with open("/proc/net/arp", encoding="ascii") as handle:
            for line in handle.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] != "0x0" and _MAC.fullmatch(parts[3]) and parts[3] != "00:00:00:00:00:00":
                    entries[parts[0]] = normalize_mac(parts[3])
    except OSError:
        for line in _run(["ip", "neigh"], 5).splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+) .*lladdr (\S+)", line)
            if m:
                entries[m.group(1)] = normalize_mac(m.group(2))
    return {ip: mac for ip, mac in entries.items() if mac}


def default_gateway() -> str | None:
    if IS_WINDOWS:
        out = _run(["route", "print", "-4", "0.0.0.0"], 5)
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        return m.group(1) if m else None
    try:
        with open("/proc/net/route", encoding="ascii") as handle:
            for line in handle.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    return str(ipaddress.IPv4Address(bytes.fromhex(parts[2])[::-1]))
    except (OSError, ValueError):
        return None
    return None


def oui_vendor(mac: str | None) -> str | None:
    """Organisation registered for the MAC prefix (IEEE registry bundled with netaddr)."""
    if not mac:
        return None
    first = int(mac.split(":")[0], 16)
    if first & 0x02:
        return None  # locally administered: no registered vendor
    try:
        from netaddr import EUI

        return EUI(mac).oui.registration().org.strip()
    except Exception:  # noqa: BLE001 - unregistered prefix
        return None


def parallel(func, items, workers: int = 64):
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as pool:
        return list(pool.map(func, items))


# ------------------------------------------------------------------ this computer's networks
_VIRTUAL = ("loopback", "vmware", "virtualbox", "vbox", "hyper-v", "vethernet", "docker", "wsl", "tailscale",
            "zerotier", "npcap", "bluetooth", "teredo", "isatap", "pseudo")


def local_networks(max_prefix: int = 22) -> dict:
    """Active IPv4 interfaces of this computer, their subnets and the default gateway.

    Each subnet larger than /max_prefix is reduced to the /max_prefix around this computer's address (the discovery
    limit). The interface that holds the default route is listed first and suggested as the scan target."""
    gateway = default_gateway()
    rows = []
    try:
        import psutil

        stats = psutil.net_if_stats()
        for name, addresses in psutil.net_if_addrs().items():
            if not stats.get(name) or not stats[name].isup:
                continue
            for address in addresses:
                if address.family != socket.AF_INET or not address.netmask:
                    continue
                iface = ipaddress.IPv4Interface(f"{address.address}/{address.netmask}")
                if iface.ip.is_loopback or iface.ip.is_link_local:
                    continue
                network = iface.network
                if network.prefixlen < max_prefix:
                    network = ipaddress.IPv4Interface(f"{iface.ip}/{max_prefix}").network
                rows.append({"interface": name, "address": str(iface.ip), "prefix": iface.network.prefixlen,
                             "network": str(iface.network), "scan_target": str(network),
                             "gateway": gateway if gateway and ipaddress.IPv4Address(gateway) in iface.network else None,
                             "virtual": any(word in name.lower() for word in _VIRTUAL),
                             "speed_mbps": stats[name].speed or None})
    except ImportError:
        pass
    if not rows:
        # Without psutil: the address used to reach the internet (no packet is sent by a UDP connect).
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("192.0.2.1", 9))
                address = sock.getsockname()[0]
            network = ipaddress.IPv4Interface(f"{address}/24").network
            rows.append({"interface": "default", "address": address, "prefix": 24, "network": str(network),
                         "scan_target": str(network), "gateway": gateway, "virtual": False, "speed_mbps": None})
        except OSError:
            pass
    rows.sort(key=lambda r: (r["gateway"] is None, r["virtual"], r["interface"]))
    return {"interfaces": rows, "gateway": gateway, "suggested": rows[0]["scan_target"] if rows else None}


def private(ip: str) -> bool:
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return address.is_private and not (address.is_loopback or address.is_link_local or address.is_multicast)


# ------------------------------------------------------------------ this computer and its Wi-Fi association
def wifi_status() -> list[dict]:
    """Wi-Fi associations of this computer: interface, SSID, BSSID (the access point radio's MAC), signal, channel
    and radio type. Read from the operating system (netsh on Windows, iw/nmcli on Linux); no packet is sent."""
    rows: list[dict] = []
    if IS_WINDOWS:
        current: dict = {}
        for line in _run(["netsh", "wlan", "show", "interfaces"], 6).splitlines():
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if not value:
                continue
            if key in ("name", "nom", "nombre", "名称"):
                if current.get("bssid"):
                    rows.append(current)
                current = {"interface": value}
            elif "bssid" in key:
                mac = _MAC.search(line)
                if mac:
                    current["bssid"] = normalize_mac(mac.group(0))
            elif key == "ssid" or key.endswith(" ssid") and "bssid" not in key:
                current["ssid"] = value
            elif key.startswith(("signal", "señal", "signal ")) and value.endswith("%"):
                current["signal"] = value
            elif "radio" in key:
                current["radio"] = value
            elif key.startswith(("channel", "canal", "kanal")):
                current["channel"] = value
            elif key.startswith(("receive rate", "transmit rate")):
                current.setdefault("rate_mbps", value)
        if current.get("bssid"):
            rows.append(current)
        return rows
    if shutil.which("iw"):
        for name in re.findall(r"Interface (\S+)", _run(["iw", "dev"], 4)):
            out = _run(["iw", "dev", name, "link"], 4)
            bssid = re.search(r"Connected to ([0-9a-f:]{17})", out, re.I)
            if bssid:
                ssid = re.search(r"SSID: (.+)", out)
                signal = re.search(r"signal: (-?\d+ dBm)", out)
                freq = re.search(r"freq: (\d+)", out)
                rows.append({"interface": name, "bssid": normalize_mac(bssid.group(1)),
                             "ssid": ssid.group(1).strip() if ssid else None, "signal": signal.group(1) if signal else None,
                             "channel": f"{freq.group(1)} MHz" if freq else None})
    return rows


def this_computer(scope) -> dict | None:
    """The computer running NetGuard, when one of its addresses is inside the scanned range: address, adapter,
    MAC, host name, operating system and (for a wireless adapter) its Wi-Fi association. A computer never answers
    its own ARP cache, so without this the scanning host is missing from its own discovery."""
    try:
        import psutil

        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except ImportError:
        return None
    for name, entries in addresses.items():
        if not stats.get(name) or not stats[name].isup:
            continue
        # Loopback addresses belong to local services (laboratory emulators), not to this computer's LAN identity.
        ipv4 = next((e for e in entries if e.family == socket.AF_INET and e.address and
                     not ipaddress.IPv4Address(e.address).is_loopback and ipaddress.IPv4Address(e.address) in scope), None)
        if ipv4 is None:
            continue
        link = next((e.address for e in entries if e.family == getattr(psutil, "AF_LINK", -1)), None)
        wifi = next((w for w in wifi_status() if w.get("interface") == name), None)
        wireless = wifi is not None or name.lower().startswith("wl") or any(
            word in name.lower() for word in ("wi-fi", "wifi", "wlan", "wireless"))
        mac = normalize_mac(link)
        return {"ip": ipv4.address, "mask": ipv4.netmask, "interface": name,
                "mac": None if mac in (None, "00:00:00:00:00:00") else mac,
                "hostname": socket.gethostname().split(".")[0] or None, "os": f"{platform.system()} {platform.release()}".strip(),
                "speed_mbps": stats[name].speed or None, "wireless": wireless, "wifi": wifi}
    return None


def mac_distance(a: str | None, b: str | None) -> int | None:
    """How far apart two MACs are when they share the first 5 bytes (ignoring the locally-administered bit):
    an access point radio's BSSID is usually its LAN MAC plus a small offset. None when unrelated."""
    if not a or not b:
        return None
    x, y = bytes.fromhex(a.replace(":", "")), bytes.fromhex(b.replace(":", ""))
    if (x[0] & ~0x02) != (y[0] & ~0x02) or x[1:5] != y[1:5]:
        return None
    return abs(x[5] - y[5])


def port_scan(ip: str, ports, timeout: float = 0.5, workers: int = 400, stop=None, progress=None) -> list[int]:
    """TCP connect scan of the given ports (the full range on request). Read-only: each connection is closed at
    once. stop() can end the scan early; progress(done, total) is called as it advances."""
    ports = list(ports)
    found: list[int] = []
    done = [0]
    lock = threading.Lock()

    def check(port):
        if stop is not None and stop():
            return
        if tcp_open(ip, port, timeout):
            with lock:
                found.append(port)
        with lock:
            done[0] += 1
            if progress is not None and done[0] % 256 == 0:
                progress(done[0], len(ports))
    parallel(check, ports, workers)
    return sorted(found)
