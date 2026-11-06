"""Configuration parsers for non-IOS platforms, producing the same vendor-neutral device model (config_import.Dev)
that every analysis rule, the forwarding simulator and the change detector work on.

Supported: FortiOS ("config system interface ... edit ... set ip"), pfSense/OPNsense config.xml, EdgeOS/VyOS and
Junos "set" commands, ArubaOS-Switch (ProCurve) VLAN-centric configuration, Huawei VRP, MikroTik RouterOS
"/export", D-Link DES/DGS CLI. IOS-family syntaxes (Cisco IOS/IOS-XE/NX-OS/ASA, Ruijie, TP-Link JetStream, Aruba
AOS-CX, EdgeSwitch) use the IOS parser in config_import.

Each parser models what it can represent (hostname, interfaces with addresses, VLAN membership, administrative
state, static routes, VLANs and management exposure facts) and reports anything else as not modelled; it never
invents values that the configuration does not contain.
"""
from __future__ import annotations

import ipaddress as ipa
import re
import xml.etree.ElementTree as ET  # noqa: S405 - parsing a configuration collected from the operator's own device

from backend.services.config_import import Dev, Iface


def detect_format(text: str) -> str | None:
    """The configuration syntax of `text`, or None for IOS-family syntax."""
    head = text[:20000]
    if re.search(r"^\s*config system (global|interface)\b", head, re.M) or "#config-version=" in head:
        return "fortios"
    if re.search(r"<(pfsense|opnsense)>", head):
        return "pfsense"
    if re.search(r"^set (interfaces|system host-name|protocols|service)\b", head, re.M):
        return "junos" if re.search(r"^set (system host-name|interfaces \S+ unit)", head, re.M) and \
            re.search(r"\bunit \d+ family", head) else "edgeos"
    if re.search(r"^/(interface|ip address|system identity)\b", head, re.M) or "# software id" in head.lower():
        return "mikrotik"
    if re.search(r"^\s*sysname\s+\S+", head, re.M):
        return "huawei"
    if re.search(r"^config ipif\b|^create vlan \S+ tag \d+", head, re.M):
        return "dlink"
    if re.search(r"^\s*(untagged|tagged)\s+[\dA-Za-z/,-]+\s*$", head, re.M) and re.search(r"^vlan \d+\s*$", head, re.M) \
            and not re.search(r"^\s*switchport\b", head, re.M):
        return "procurve"
    return None


def parse(text: str, parser: str | None = None, hostname: str | None = None) -> Dev | None:
    fmt = parser if parser not in (None, "ios", "frr", "none") else detect_format(text or "")
    func = {"fortios": _fortios, "pfsense": _pfsense, "edgeos": _set_style, "junos": _set_style,
            "procurve": _procurve, "huawei": _huawei, "mikrotik": _mikrotik, "dlink": _dlink}.get(fmt or "")
    if func is None or not (text or "").strip():
        return None
    try:
        dev = func(text, hostname)
    except (ValueError, IndexError, ET.ParseError):
        return None
    if dev is not None:
        dev.platform = {"edgeos": "edgeos", "junos": "juniper-junos", "pfsense": "pfsense", "procurve": "aruba-os-switch",
                        "huawei": "huawei-vrp", "mikrotik": "mikrotik-routeros", "dlink": "dlink-ds",
                        "fortios": "fortios"}[fmt]
    return dev


def _mask(prefix: int | str) -> str:
    return str(ipa.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def _cidr(value: str) -> tuple[str, str] | None:
    try:
        iface = ipa.IPv4Interface(value)
    except ValueError:
        return None
    return str(iface.ip), str(iface.netmask)


def _ports(spec: str) -> list[str]:
    """ProCurve/D-Link port lists: 1-4,A1,25 -> ['1','2','3','4','A1','25']."""
    out = []
    for part in re.split(r"[,\s]+", spec.strip()):
        m = re.fullmatch(r"([A-Za-z]*)(\d+)-\1?(\d+)", part)
        if m:
            out += [f"{m.group(1)}{n}" for n in range(int(m.group(2)), int(m.group(3)) + 1)][:128]
        elif part:
            out.append(part)
    return out


# ------------------------------------------------------------------ FortiOS
def _fortios(text: str, hostname: str | None) -> Dev:
    name = re.search(r'^\s*set hostname "?([^"\n]+)"?', text, re.M)
    dev = Dev((name.group(1).strip() if name else hostname) or "FortiGate", kind="firewall")
    dev.platform = "fortios"
    stack: list[tuple[str, str | None]] = []
    current: dict = {}
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("config "):
            stack.append((s[7:], None))
            continue
        if s.startswith("edit ") and stack:
            stack[-1] = (stack[-1][0], s[5:].strip().strip('"'))
            current = {}
            continue
        if s == "next" and stack:
            _fortios_entry(dev, stack[-1][0], stack[-1][1], current)
            stack[-1] = (stack[-1][0], None)
            current = {}
            continue
        if s == "end" and stack:
            if stack[-1][1] is not None:
                _fortios_entry(dev, stack[-1][0], stack[-1][1], current)
            stack.pop()
            current = {}
            continue
        if s.startswith(("set ", "unset ")) and stack:
            words = re.findall(r'"[^"]*"|\S+', s)
            current[words[1]] = [w.strip('"') for w in words[2:]]
            if stack[-1][1] is None and stack[-1][0] == "system global" and words[1] == "admin-server-cert":
                pass
    dev.ip_routing = True
    return dev


def _fortios_entry(dev: Dev, section: str, key: str | None, values: dict) -> None:
    if section == "system interface" and key:
        iface = dev.ifs.setdefault(key, Iface(key))
        if "ip" in values and len(values["ip"]) >= 2 and values["ip"][0] != "0.0.0.0":
            iface.ip, iface.mask = values["ip"][0], values["ip"][1]
        elif "ip" in values and len(values["ip"]) == 1 and "/" in values["ip"][0]:
            parsed = _cidr(values["ip"][0])
            if parsed:
                iface.ip, iface.mask = parsed
        if values.get("status") == ["down"]:
            iface.down = True
        if "vlanid" in values:
            iface.vlan = int(values["vlanid"][0])
            iface.description = f"VLAN {iface.vlan} on {values.get('interface', ['?'])[0]}"
        if "mtu" in values and values.get("mtu-override") == ["enable"]:
            iface.mtu = int(values["mtu"][0])
        if "description" in values or "alias" in values:
            iface.description = " ".join(values.get("description") or values.get("alias"))[:120]
        access = values.get("allowaccess", [])
        if "http" in access:
            dev.facts["http_server"] = True
        if "https" in access:
            dev.facts["https_server"] = True
        if "telnet" in access:
            dev.facts["vty"].append({"kind": "vty", "lines": f"interface {key}", "transport": ["telnet"],
                                     "access_class": None})
        if "ssh" in access:
            dev.facts["ssh_version"] = 2
        iface.used = True
    elif section == "router static":
        dst = values.get("dst", ["0.0.0.0", "0.0.0.0"])
        gateway = values.get("gateway", [None])[0]
        if gateway:
            mask = dst[1] if len(dst) > 1 else _mask(dst[0].split("/")[1]) if "/" in dst[0] else "255.255.255.255"
            network = ipa.IPv4Network(f"{dst[0].split('/')[0]}/{mask}", strict=False)
            dev.routes.append((str(network), gateway))
            if network.prefixlen == 0:
                dev.gw = gateway
    elif section == "system snmp community" and key:
        dev.facts["snmp_communities"].append({"kind": "v2c", "access": "ro"})
    elif section == "system admin" and key:
        dev.facts["local_users"].append({"user": key, "storage": "fortios-hash"})


# ------------------------------------------------------------------ pfSense / OPNsense config.xml
def _pfsense(text: str, hostname: str | None) -> Dev:
    start = text.find("<?xml")
    if start < 0:
        start = min((i for i in (text.find("<pfsense>"), text.find("<opnsense>")) if i >= 0), default=0)
    root = ET.fromstring(text[start:].strip())  # noqa: S314
    host = root.findtext("system/hostname") or hostname or "pfSense"
    dev = Dev(host, kind="firewall")
    for node in list(root.find("interfaces") or []):
        name = node.findtext("if") or node.tag
        iface = dev.ifs.setdefault(name, Iface(name, description=(node.findtext("descr") or node.tag.upper())[:120]))
        ip, bits = node.findtext("ipaddr"), node.findtext("subnet")
        if ip and bits and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
            iface.ip, iface.mask = ip, _mask(bits)
        if node.find("enable") is None:
            iface.down = True
        iface.used = True
    for vlan in root.findall("vlans/vlan"):
        tag = vlan.findtext("tag")
        if tag and tag.isdigit():
            dev.vlans[int(tag)] = vlan.findtext("descr") or None
    gateways = {g.findtext("name"): g.findtext("gateway") for g in root.findall("gateways/gateway_item")}
    for route in root.findall("staticroutes/route"):
        network, gw = route.findtext("network"), gateways.get(route.findtext("gateway"))
        if network and gw and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", gw):
            dev.routes.append((str(ipa.IPv4Network(network, strict=False)), gw))
    default = next((g.findtext("gateway") for g in root.findall("gateways/gateway_item")
                    if g.find("defaultgw") is not None), None) or next(iter(gateways.values()), None)
    if default and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", default):
        dev.gw = default
    webgui = root.find("system/webgui")
    if webgui is not None:
        dev.facts["https_server" if (webgui.findtext("protocol") or "https") == "https" else "http_server"] = True
    if root.find("system/ssh/enable") is not None or root.find("system/enablesshd") is not None:
        dev.facts["ssh_version"] = 2
    for community in root.findall("snmpd/rocommunity"):
        if community.text:
            dev.facts["snmp_communities"].append({"kind": "v2c", "access": "ro"})
    dev.ip_routing = True
    return dev


# ------------------------------------------------------------------ EdgeOS / VyOS and Junos "set" commands
def _set_style(text: str, hostname: str | None) -> Dev:
    host = re.search(r"^set system host-name '?([^'\s]+)'?", text, re.M)
    dev = Dev((host.group(1) if host else hostname) or "router", kind="router")
    for raw in text.splitlines():
        words = [w.strip("'") for w in re.findall(r"'[^']*'|\S+", raw.strip())]
        if len(words) < 3 or words[0] != "set":
            continue
        if words[1] == "interfaces":
            # VyOS: set interfaces ethernet eth0 [vif 10] address 10.0.0.1/24
            # Junos: set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
            rest = words[2:]
            if rest[0] in ("ethernet", "bonding", "switch", "bridge", "loopback", "pppoe", "wireguard", "openvpn",
                           "vti", "tunnel", "wireless") and len(rest) >= 2:
                name, rest = rest[1], rest[2:]
            else:
                name, rest = rest[0], rest[1:]
            if len(rest) >= 2 and rest[0] in ("vif", "unit"):
                unit = rest[1]
                name = f"{name}.{unit}" if unit != "0" or rest[0] == "vif" else name
                if rest[0] == "vif":
                    dev.ifs.setdefault(name, Iface(name)).vlan = int(unit) if unit.isdigit() else None
                rest = rest[2:]
            iface = dev.ifs.setdefault(name, Iface(name))
            iface.used = True
            if "address" in rest:
                value = rest[rest.index("address") + 1] if rest.index("address") + 1 < len(rest) else ""
                parsed = _cidr(value)
                if parsed:
                    iface.ip, iface.mask = parsed
            if rest[:1] == ["disable"]:
                iface.down = True
            if rest[:1] == ["description"] and len(rest) > 1:
                iface.description = " ".join(rest[1:])[:120]
            if rest[:1] == ["mtu"] and len(rest) > 1 and rest[1].isdigit():
                iface.mtu = int(rest[1])
            if "vlan-id" in rest:
                value = rest[rest.index("vlan-id") + 1]
                iface.vlan = int(value) if value.isdigit() else iface.vlan
        elif words[1] == "protocols" and words[2] == "static" and len(words) >= 7 and words[3] == "route":
            # VyOS: set protocols static route 0.0.0.0/0 next-hop 10.0.0.1
            if words[5] == "next-hop":
                dev.routes.append((str(ipa.IPv4Network(words[4], strict=False)), words[6]))
        elif words[1:4] == ["routing-options", "static", "route"] and len(words) >= 7 and words[5] == "next-hop":
            dev.routes.append((str(ipa.IPv4Network(words[4], strict=False)), words[6]))
        elif words[1:4] == ["service", "gui", "http-port"] or words[1:3] == ["system", "services"] and "http" in words:
            dev.facts["http_server"] = True
        elif words[1:3] == ["service", "telnet"] or words[1:4] == ["system", "services", "telnet"]:
            dev.facts["vty"].append({"kind": "vty", "lines": "telnet service", "transport": ["telnet"], "access_class": None})
        elif words[1:3] == ["service", "ssh"] or words[1:4] == ["system", "services", "ssh"]:
            dev.facts["ssh_version"] = 2
    for destination, hop in dev.routes:
        if destination == "0.0.0.0/0":
            dev.gw = hop
    dev.ip_routing = True
    return dev


# ------------------------------------------------------------------ ArubaOS-Switch (ProCurve)
def _procurve(text: str, hostname: str | None) -> Dev:
    host = re.search(r'^hostname "?([^"\n]+)"?', text, re.M)
    dev = Dev((host.group(1).strip() if host else hostname) or "switch", kind="switch")
    vlan = None
    for raw in text.splitlines():
        s = raw.strip()
        m = re.fullmatch(r"vlan (\d+)", s)
        if m:
            vlan = int(m.group(1))
            dev.vlans.setdefault(vlan, None)
            continue
        if not raw.startswith(" ") and s and not s.startswith(("vlan", ";")):
            if s == "exit":
                vlan = None
            m = re.match(r"interface (\S+)", s)
            if m:
                dev.ifs.setdefault(m.group(1), Iface(m.group(1))).used = True
            if s.startswith("ip route "):
                w = s.split()
                if len(w) >= 5:
                    dev.routes.append((str(ipa.IPv4Network(f"{w[2]}/{w[3]}", strict=False)), w[4]))
            if s.startswith("ip default-gateway "):
                dev.gw = s.split()[2]
            if s == "ip routing":
                dev.ip_routing = True
            if s.startswith("telnet-server") and "no " not in s:
                pass
            if s == "no telnet-server":
                dev.facts["telnet_disabled"] = True
            if s.startswith("web-management") and "ssl" not in s and not s.startswith("no "):
                dev.facts["http_server"] = True
            continue
        if vlan is None:
            continue
        if s.startswith("name "):
            dev.vlans[vlan] = s[5:].strip('"')
        elif s.startswith("untagged "):
            for port in _ports(s[9:]):
                iface = dev.ifs.setdefault(port, Iface(port))
                iface.mode, iface.vlan, iface.used = "access", vlan, True
        elif s.startswith("tagged "):
            for port in _ports(s[7:]):
                iface = dev.ifs.setdefault(port, Iface(port))
                iface.mode = "trunk"
                iface.allowed = sorted(set(iface.allowed or []) | {vlan})
                iface.used = True
        elif s.startswith("ip address "):
            w = s.split()
            if len(w) >= 4:
                name = f"Vlan{vlan}"
                iface = dev.ifs.setdefault(name, Iface(name))
                iface.ip, iface.mask, iface.vlan, iface.used = w[2], w[3], vlan, True
            elif len(w) == 3 and "/" in w[2]:
                parsed = _cidr(w[2])
                if parsed:
                    iface = dev.ifs.setdefault(f"Vlan{vlan}", Iface(f"Vlan{vlan}"))
                    iface.ip, iface.mask, iface.vlan = parsed[0], parsed[1], vlan
    if not dev.facts.get("telnet_disabled"):
        dev.facts["vty"].append({"kind": "vty", "lines": "telnet-server (default enabled)", "transport": ["telnet"],
                                 "access_class": None})
    return dev


# ------------------------------------------------------------------ Huawei VRP
def _huawei(text: str, hostname: str | None) -> Dev:
    host = re.search(r"^\s*sysname\s+(\S+)", text, re.M)
    dev = Dev((host.group(1) if host else hostname) or "huawei", kind="router")
    iface = None
    switchport = False
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("#") or not s:
            iface = None if s.startswith("#") else iface
            continue
        m = re.match(r"^interface (\S+)", s)
        if m and not raw.startswith(" "):
            name = m.group(1)
            iface = dev.ifs.setdefault(name, Iface(name))
            iface.used = True
            continue
        w = s.split()
        if iface is not None and raw.startswith(" "):
            if w[:2] == ["ip", "address"] and len(w) >= 4:
                iface.ip = w[2]
                iface.mask = w[3] if "." in w[3] else _mask(w[3])
            elif w[0] == "shutdown":
                iface.down = True
            elif w[0] == "description":
                iface.description = " ".join(w[1:])[:120]
            elif w[:2] == ["port", "link-type"] and len(w) >= 3:
                iface.mode = "access" if w[2] == "access" else "trunk" if w[2] in ("trunk", "hybrid") else None
                switchport = True
            elif w[:3] == ["port", "default", "vlan"] and len(w) >= 4:
                iface.vlan = int(w[3])
                iface.mode = iface.mode or "access"
                switchport = True
            elif w[:4] == ["port", "trunk", "allow-pass", "vlan"]:
                vlans = []
                tokens = w[4:]
                i = 0
                while i < len(tokens):
                    if tokens[i] == "all":
                        vlans = None
                        break
                    if i + 2 < len(tokens) and tokens[i + 1] == "to":
                        vlans += list(range(int(tokens[i]), int(tokens[i + 2]) + 1))
                        i += 3
                    else:
                        vlans.append(int(tokens[i]))
                        i += 1
                iface.allowed = vlans
            elif w[:2] == ["mtu"] or w[0] == "mtu" and len(w) > 1 and w[1].isdigit():
                iface.mtu = int(w[1])
            continue
        iface = None
        if w[:2] == ["vlan", "batch"]:
            for token in w[2:]:
                if token.isdigit():
                    dev.vlans.setdefault(int(token), None)
        elif w[0] == "vlan" and len(w) == 2 and w[1].isdigit():
            dev.vlans.setdefault(int(w[1]), None)
        elif w[:2] == ["ip", "route-static"] and len(w) >= 5:
            mask = w[3] if "." in w[3] else _mask(w[3])
            network = ipa.IPv4Network(f"{w[2]}/{mask}", strict=False)
            dev.routes.append((str(network), w[4]))
            if network.prefixlen == 0:
                dev.gw = w[4]
        elif w[:3] == ["telnet", "server", "enable"]:
            dev.facts["vty"].append({"kind": "vty", "lines": "telnet server", "transport": ["telnet"], "access_class": None})
        elif w[:2] == ["http", "server"] and "enable" in w or w[:3] == ["http", "server", "enable"]:
            dev.facts["http_server"] = True
        elif w[:3] == ["stelnet", "server", "enable"]:
            dev.facts["ssh_version"] = 2
    if switchport or dev.vlans and not any(i.ip for i in dev.ifs.values() if not i.name.lower().startswith("vlanif")):
        dev.kind = "switch"
    for i in dev.ifs.values():
        m = re.fullmatch(r"Vlanif(\d+)", i.name, re.I)
        if m:
            i.vlan = int(m.group(1))
            dev.ip_routing = True
    return dev


# ------------------------------------------------------------------ MikroTik RouterOS /export
def _mikrotik(text: str, hostname: str | None) -> Dev:
    host = re.search(r"^/system identity\s+set name=(\S+)|^/system identity set name=(\S+)", text, re.M)
    name = (host.group(1) or host.group(2)) if host else None
    if not name:
        m = re.search(r"/system identity[^\n]*\n\s*set name=(\S+)", text)
        name = m.group(1) if m else None
    dev = Dev((name or hostname or "MikroTik").strip('"'), kind="router")
    section = None
    for raw in text.replace("\\\n", " ").splitlines():
        s = raw.strip()
        if s.startswith("/"):
            parts = s.split(" add ", 1) if " add " in s else s.split(" set ", 1) if " set " in s else [s, ""]
            section = parts[0].strip()
            s = ("add " + parts[1]) if " add " in raw else ("set " + parts[1]) if " set " in raw else ""
        if not s:
            continue
        attrs = dict(re.findall(r'(\S+?)=("[^"]*"|\S+)', s))
        attrs = {k: v.strip('"') for k, v in attrs.items()}
        if section == "/ip address" and s.startswith("add") and "address" in attrs:
            parsed = _cidr(attrs["address"])
            port = attrs.get("interface", "ether1")
            iface = dev.ifs.setdefault(port, Iface(port))
            if parsed:
                iface.ip, iface.mask = parsed
            iface.used = True
            if attrs.get("disabled") == "yes":
                iface.down = True
        elif section == "/interface vlan" and s.startswith("add"):
            port = attrs.get("name", f"vlan{attrs.get('vlan-id')}")
            iface = dev.ifs.setdefault(port, Iface(port))
            iface.vlan = int(attrs["vlan-id"]) if attrs.get("vlan-id", "").isdigit() else None
            iface.used = True
        elif section in ("/interface ethernet",) and s.startswith("set") and attrs.get("disabled") == "yes":
            port = attrs.get("default-name") or attrs.get("name") or attrs.get("[", "")
            if port:
                dev.ifs.setdefault(port, Iface(port)).down = True
        elif section == "/ip route" and s.startswith("add") and "gateway" in attrs:
            dst = attrs.get("dst-address", "0.0.0.0/0")
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", attrs["gateway"]):
                dev.routes.append((str(ipa.IPv4Network(dst, strict=False)), attrs["gateway"]))
                if dst == "0.0.0.0/0":
                    dev.gw = attrs["gateway"]
        elif section == "/ip service" and s.startswith("set"):
            service = attrs.get("[") or next((k for k in ("telnet", "www", "api", "ftp") if k in s.split()), None)
            enabled = attrs.get("disabled") != "yes"
            if "telnet" in s and enabled:
                dev.facts["vty"].append({"kind": "vty", "lines": "ip service telnet", "transport": ["telnet"], "access_class": None})
            if re.search(r"\bwww\b(?!-ssl)", s) and enabled:
                dev.facts["http_server"] = True
            del service
        elif section == "/interface bridge vlan" and s.startswith("add") and attrs.get("vlan-ids", "").isdigit():
            dev.vlans.setdefault(int(attrs["vlan-ids"]), None)
    dev.ip_routing = True
    return dev


# ------------------------------------------------------------------ D-Link DES/DGS
def _dlink(text: str, hostname: str | None) -> Dev:
    host = re.search(r'^config snmp system_name\s+"?([^"\n]+)"?', text, re.M)
    dev = Dev((host.group(1).strip() if host else hostname) or "D-Link", kind="switch")
    names: dict[str, int] = {}
    for raw in text.splitlines():
        s = raw.strip()
        m = re.match(r"create vlan (\S+) tag (\d+)", s)
        if m:
            names[m.group(1)] = int(m.group(2))
            dev.vlans[int(m.group(2))] = m.group(1)
            continue
        m = re.match(r"config vlan (\S+) add (untagged|tagged) (\S+)", s)
        if m and (m.group(1) in names or m.group(1) == "default"):
            vid = names.get(m.group(1), 1)
            for port in _ports(m.group(3)):
                iface = dev.ifs.setdefault(port, Iface(port))
                iface.used = True
                if m.group(2) == "untagged":
                    iface.mode, iface.vlan = "access", vid
                else:
                    iface.mode = "trunk"
                    iface.allowed = sorted(set(iface.allowed or []) | {vid})
            continue
        m = re.match(r"config ipif (\S+) ipaddress (\S+)(?: vlan (\S+))?", s)
        if m:
            parsed = _cidr(m.group(2))
            iface = dev.ifs.setdefault(m.group(1), Iface(m.group(1)))
            if parsed:
                iface.ip, iface.mask = parsed
            iface.vlan = names.get(m.group(3) or "default", 1)
            continue
        m = re.match(r"create iproute default (\S+)|create iproute (\S+) (\S+) (\S+)", s)
        if m:
            if m.group(1):
                dev.gw = m.group(1)
                dev.routes.append(("0.0.0.0/0", m.group(1)))
            else:
                dev.routes.append((str(ipa.IPv4Network(f"{m.group(2)}/{m.group(3)}", strict=False)), m.group(4)))
            continue
        if s == "enable telnet" or s.startswith("enable telnet "):
            dev.facts["vty"].append({"kind": "vty", "lines": "telnet", "transport": ["telnet"], "access_class": None})
        if s == "enable web" or s.startswith("enable web "):
            dev.facts["http_server"] = True
        if s == "enable ssh":
            dev.facts["ssh_version"] = 2
    return dev
