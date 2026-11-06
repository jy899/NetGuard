"""Builds a network from Cisco IOS / IOS-XE / FRRouting configurations: `show running-config` plus optional
`show cdp neighbors`, an endpoint list (PCs, servers, internet) and required flows.

Links come from CDP neighbours, then from two L3 interfaces sharing a subnet, then
from the endpoint list. Access lists are kept as named lists and filter where an interface applies them
(`ip access-group NAME in|out`). A switch with `ip routing` keeps its SVIs (interface VlanX) and routed ports
and routes between them like a router.
"""
from __future__ import annotations

import ipaddress as ipa
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field

from pydantic import ValidationError
from sqlalchemy.orm import Session

from backend.core.errors import ValidationFailed
from backend.models import AclRule, Device, Interface, Link, Network, NetworkIntent, StaticRoute, User, Vlan
from backend.schemas.config import AclRuleCreate
from backend.schemas.interface import InterfaceCreate
from backend.schemas.validators import validate_ipv4, validate_port
from backend.services.demo_topology import _available_name
from backend.services.interface_naming import canonical_name

_PORTS = {"www": 80, "http": 80, "https": 443, "domain": 53, "ftp": 21, "ssh": 22, "telnet": 23,
          "smtp": 25, "pop3": 110, "snmp": 161, "ntp": 123, "tftp": 69, "bootps": 67, "isakmp": 500}
_TYPES = ("pc", "server", "internet")
DESCRIPTION_MAX = 120  # matches the Interface.description column
_IPV4 = re.compile(r"\d+\.\d+\.\d+\.\d+")


def ifname(raw: str) -> str:
    return canonical_name(raw, "cisco-ios")


@dataclass
class Iface:
    name: str
    ip: str | None = None
    mask: str | None = None
    vlan: int | None = None
    mode: str | None = None
    down: bool = False
    area: int | None = None
    acls: list[str] = field(default_factory=list)
    used: bool = False
    description: str | None = None
    allowed: list[int] | None = None  # trunk allowed VLANs; None = all (the IOS default)
    native: int | None = None
    speed: int | None = None
    duplex: str | None = None
    mtu: int | None = None
    hello: int | None = None
    dead: int | None = None
    acl_in: str | None = None
    acl_out: str | None = None

    @property
    def net(self):
        return ipa.IPv4Interface(f"{self.ip}/{self.mask}").network if self.ip else None


@dataclass
class Dev:
    name: str
    kind: str = "router"
    mgmt: str | None = None
    gw: str | None = None
    ifs: dict[str, Iface] = field(default_factory=dict)
    vlans: dict[int, str | None] = field(default_factory=dict)
    routes: list[tuple[str, str]] = field(default_factory=list)
    acls: dict[str, list[tuple]] = field(default_factory=dict)
    ospf: list[tuple[ipa.IPv4Network, int]] = field(default_factory=list)
    cdp: list[tuple[str, str, str]] = field(default_factory=list)  # local if, neighbour, neighbour if
    ip_routing: bool = False
    ospf_process: int | None = None
    platform: str = "cisco-ios"
    # Security and hygiene facts. Secrets (community strings, password hashes) are never kept, only their kind.
    facts: dict = field(default_factory=lambda: {"vty": [], "http_server": False, "https_server": False,
                                                 "snmp_communities": [], "snmp_v3_users": 0, "enable": None,
                                                 "password_encryption": False, "local_users": [],
                                                 "acl_references": [], "ssh_version": None})


def _wild(addr: str, wc: str) -> str:
    mask = ipa.IPv4Address(int(ipa.IPv4Address(wc)) ^ 0xFFFFFFFF)
    return str(ipa.IPv4Network(f"{addr}/{mask}", strict=False))


def _area(value: str) -> int:
    # IOS accepts either a decimal area or its dotted-decimal representation.
    area = int(ipa.IPv4Address(value)) if "." in value else int(value)
    if not 0 <= area <= 65535:
        raise ValueError("This prototype supports OSPF area values between 0 and 65535")
    return area


def _addr(tok: list[str]) -> str:
    """Consumes an ACL address (any | host A | A W) from the front of tok."""
    if not tok:
        raise ValueError("ACL address is missing")
    t = tok.pop(0)
    if t == "any":
        return "any"
    if t == "host":
        if not tok:
            raise ValueError("ACL host address is missing")
        return str(ipa.IPv4Network(f"{tok.pop(0)}/32"))
    if tok and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tok[0]):
        return _wild(t, tok.pop(0))
    return str(ipa.IPv4Network(f"{t}/32"))


def _ace(words: list[str], std: bool) -> tuple | None:
    """Read only ACL semantics represented by the model; never broaden a rule silently."""
    w = list(words)
    if not w or w[0] == "remark":
        return None
    if w[0] not in ("permit", "deny"):
        raise ValueError(f"Unsupported ACL entry '{' '.join(w)}'")
    act = w.pop(0)
    if std:
        src = _addr(w)
        if any(token not in ("log", "log-input") for token in w):
            raise ValueError("Unsupported standard ACL qualifier; import supports an address and optional log only")
        return act, "ip", src, "any", None
    proto = w.pop(0) if w else "ip"
    if proto not in ("ip", "tcp", "udp", "icmp"):
        raise ValueError(f"Unsupported ACL protocol '{proto}'")
    src = _addr(w)
    if w and w[0] in ("eq", "range", "gt", "lt", "neq"):  # source port: not modelled
        raise ValueError("ACL source-port conditions are not supported by this model")
    dst = _addr(w)
    port = None
    if len(w) >= 2 and w[0] == "eq":
        service = w[1]
        port = int(service) if service.isdigit() else _PORTS.get(service)
        if port is None:
            raise ValueError(f"Unsupported ACL service '{service}'; use a numeric destination port")
        validate_port(port, proto)
        del w[:2]
    if any(token not in ("log", "log-input") for token in w):
        raise ValueError("Unsupported ACL qualifier; only one destination eq port and optional log are supported")
    return act, proto, src, dst, port


def _vlan_list(text: str) -> list[int]:
    """Expand an IOS VLAN list such as 10,20-30,40 (VLANs 1-4094)."""
    vlans: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        low, _, high = part.partition("-")
        if not low.isdigit() or (high and not high.isdigit()):
            raise ValueError(f"invalid VLAN list '{text}'")
        start, end = int(low), int(high or low)
        if not 1 <= start <= end <= 4094:
            raise ValueError(f"VLAN range '{part}' must be within 1-4094")
        vlans.update(range(start, end + 1))
    return sorted(vlans)


def _trunk_allowed(iface: Iface, words: list[str]) -> None:
    """switchport trunk allowed vlan [add|remove|except] LIST | all | none."""
    every = list(range(1, 4095))
    if not words:
        raise ValueError("trunk allowed VLAN list is missing")
    verb, rest = (words[0], words[1:]) if words[0] in ("add", "remove", "except") else (None, words)
    if verb is None and rest == ["all"]:
        iface.allowed = None
    elif verb is None and rest == ["none"]:
        iface.allowed = []
    else:
        listed = _vlan_list("".join(rest))
        current = every if iface.allowed is None else iface.allowed
        if verb is None:
            iface.allowed = listed
        elif verb == "add":
            iface.allowed = None if iface.allowed is None else sorted(set(current) | set(listed))
        elif verb == "remove":
            iface.allowed = sorted(set(current) - set(listed))
        else:  # except
            iface.allowed = sorted(set(every) - set(listed))


def _cdp(dev: Dev, line: str) -> None:
    t = line.split()
    if len(t) < 5 or t[0] in ("Device", "Capability", "Total") or "#" in t[0]:
        return
    nbr = t[0]
    if len(t) >= 3 and re.fullmatch(r"[A-Za-z-]+", t[1]) and re.fullmatch(r"[\d/.]+", t[2]):
        loc, rest = ifname(t[1] + t[2]), t[3:]
    elif re.fullmatch(r"[A-Za-z-]+[\d/.]+", t[1]):
        loc, rest = ifname(t[1]), t[2:]
    else:
        return
    if len(rest) >= 2 and re.fullmatch(r"[\d/.]+", rest[-1]) and re.fullmatch(r"[A-Za-z-]+", rest[-2]):
        rem = ifname(rest[-2] + rest[-1])
    elif rest and re.fullmatch(r"[A-Za-z-]+[\d/.]+", rest[-1]):
        rem = ifname(rest[-1])
    else:
        return
    dev.cdp.append((loc, nbr, rem))


def _parse_configs(text: str, lenient: bool = False) -> tuple[dict[str, Dev], list[str]]:
    from backend.services import vendor_parsers

    fmt = vendor_parsers.detect_format(text)
    if fmt is not None:
        hint = re.match(r"^hostname\s+(\S+)\s*\n", text)
        dev = vendor_parsers.parse(text, fmt, hint.group(1) if hint else None)
        if dev is None:
            raise ValueError(f"the {fmt} configuration could not be read")
        return {dev.name: dev}, [f"{dev.name}: {fmt} configuration translated to the vendor-neutral model "
                                 "(interfaces, addresses, VLANs, static routes and management exposure)."]
    devs: dict[str, Dev] = {}
    warn: list[str] = []
    dev = ctx = None  # ctx: ("if", Iface) | ("acl", name, standard) | ("ospf",) | ("vlan", id) | ("cdp",)
    frr = False  # FRRouting prints "frr version" before its hostname line
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("!"):
            continue
        if re.match(r"^frr (version|defaults)\b", s):
            frr = True
        m = re.match(r"^hostname\s+(\S+)", line) or re.match(r"^([\w.-]+)[#>]", s)
        if m:
            dev = devs.setdefault(m.group(1), Dev(m.group(1)))
            if frr:
                dev.platform, frr = "frr", False
            ctx = ("cdp",) if re.search(r"[#>]\s*sh(ow)?\s+cdp\s+nei", s) else None
            continue
        if dev is None:
            continue
        if s.startswith("Device ID") and "Port ID" in s:
            ctx = ("cdp",)
            continue
        if ctx and ctx[0] == "cdp":
            _cdp(dev, s)
            continue
        try:
            ctx = _parse_line(dev, ctx, line, s, warn)
        except (ValueError, IndexError) as exc:
            if not lenient:
                raise ValueError(f"{dev.name}: line '{s[:80]}': {exc}") from None
            # Collected configurations are read as they are: an unsupported statement is reported, not fatal.
            warn.append(f"{dev.name}: line '{s[:80]}' not modelled ({exc})")
    return devs, warn


def _parse_line(dev: Dev, ctx, line: str, s: str, warn: list[str]):
    """One configuration line of `dev`; returns the new sub-command context."""
    w = s.split()
    sub = line.startswith(" ")
    if sub and ctx:
        kind = ctx[0]
        if kind == "if":
            i = ctx[1]
            if w[0] == "description":
                # IOS allows 240 characters; NetGuard stores 120, so shorten instead of rejecting the import.
                text = " ".join(w[1:]) or None
                if text and len(text) > DESCRIPTION_MAX:
                    warn.append(f"{dev.name} {i.name}: description shortened to {DESCRIPTION_MAX} characters.")
                    text = text[:DESCRIPTION_MAX].rstrip()
                i.description = text
            elif w[:2] == ["ip", "address"] and len(w) >= 3 and "/" in w[2] and "secondary" not in w:
                net = ipa.IPv4Interface(w[2])  # FRRouting: ip address A.B.C.D/len
                i.ip, i.mask = str(net.ip), str(net.netmask)
            elif w[:2] == ["ip", "address"] and len(w) >= 4 and "secondary" not in w:
                i.ip, i.mask = w[2], w[3]
            elif w == ["shutdown"]:
                i.down = True
            elif w[:2] == ["encapsulation", "dot1Q"] and len(w) >= 3:
                i.vlan = int(w[2])
            elif w == ["no", "switchport"]:
                i.mode = None  # routed port on a multilayer switch
            elif w[:2] == ["switchport", "mode"] and len(w) >= 3 and w[2] in ("access", "trunk"):
                i.mode = w[2]
            elif w[:3] == ["switchport", "access", "vlan"] and len(w) >= 4:
                i.vlan, i.mode = int(w[3]), i.mode or "access"
            elif w[:2] == ["vlan", "access"] and len(w) >= 3 and w[2].isdigit():  # Aruba AOS-CX
                i.vlan, i.mode = int(w[2]), "access"
            elif w[:3] == ["vlan", "trunk", "native"] and len(w) >= 4 and w[3].isdigit():
                i.native, i.mode = int(w[3]), "trunk"
            elif w[:3] == ["vlan", "trunk", "allowed"] and len(w) >= 4:
                i.mode = "trunk"
                _trunk_allowed(i, w[3:])
            elif w[:2] == ["switchport", "pvid"] and len(w) >= 3 and w[2].isdigit():  # TP-Link JetStream
                i.vlan, i.mode = int(w[2]), i.mode or "access"
            elif w[:2] == ["ip", "access-group"] and len(w) >= 3:
                i.acls.append(w[2])
                if len(w) >= 4 and w[3] == "out":
                    i.acl_out = w[2]
                else:
                    i.acl_in = w[2]
                dev.facts["acl_references"].append({"acl": w[2], "where": f"interface {i.name}"})
            elif w[:2] == ["ip", "ospf"] and "area" in w:
                i.area = _area(w[w.index("area") + 1])
            elif w[:4] == ["switchport", "trunk", "allowed", "vlan"]:
                _trunk_allowed(i, w[4:])
            elif w[:4] == ["switchport", "trunk", "native", "vlan"] and len(w) >= 5:
                i.native = int(w[4])
            elif w[0] == "speed" and len(w) == 2 and w[1].isdigit():
                i.speed = int(w[1])
            elif w[0] == "duplex" and len(w) == 2 and w[1] in ("full", "half", "auto"):
                i.duplex = w[1]
            elif (w[0] == "mtu" and len(w) == 2 and w[1].isdigit()) or (w[:2] == ["ip", "mtu"] and len(w) == 3 and w[2].isdigit()):
                i.mtu = int(w[-1])
            elif w[:3] == ["ip", "ospf", "hello-interval"] and len(w) == 4 and w[3].isdigit():
                i.hello = int(w[3])
            elif w[:3] == ["ip", "ospf", "dead-interval"] and len(w) == 4 and w[3].isdigit():
                i.dead = int(w[3])
        elif kind == "acl":
            ace = _ace(w[1:] if w[0].isdigit() else w, ctx[2])
            if ace:
                dev.acls.setdefault(ctx[1], []).append((int(w[0]) if w[0].isdigit() else None, *ace))
        elif kind == "ospf" and w[0] == "network" and len(w) >= 5 and w[3] == "area":
            dev.ospf.append((ipa.IPv4Network(_wild(w[1], w[2])), _area(w[4])))
        elif kind == "ospf" and w[0] == "network" and len(w) >= 4 and "/" in w[1] and w[2] == "area":
            dev.ospf.append((ipa.IPv4Network(w[1], strict=False), _area(w[3])))  # FRRouting form
        elif kind == "vlan" and w[0] == "name" and len(w) >= 2:
            dev.vlans[ctx[1]] = " ".join(w[1:])[:32]
        elif kind == "line":
            entry = ctx[1]
            if w[:2] == ["transport", "input"]:
                entry["transport"] = w[2:]
            elif w[0] == "access-class" and len(w) >= 2:
                entry["access_class"] = w[1]
                dev.facts["acl_references"].append({"acl": w[1], "where": f"line {entry['lines']}"})
            elif w[0] == "password":
                entry["password"] = "type 7" if len(w) >= 3 and w[1] == "7" else "cleartext"
            elif w[0] == "login":
                entry["login"] = " ".join(w[1:]) or "password"
            elif w[0] == "no" and w[1:2] == ["login"]:
                entry["login"] = "none"
        return ctx
    ctx = None
    if w[0] == "interface" and len(w) >= 2:
        name = w[1] if dev.platform == "frr" else ifname("".join(w[1:]))
        ctx = ("if", dev.ifs.setdefault(name, Iface(name)))
    elif w[0] == "vlan" and len(w) == 2 and w[1].isdigit():
        dev.vlans.setdefault(int(w[1]), None)
        ctx = ("vlan", int(w[1]))
    elif w[:2] == ["ip", "route"] and len(w) >= 3 and w[2] == "vrf":
        warn.append(f"{dev.name}: VRF route '{s}' skipped (VRFs are not modelled)")
    elif w[:2] == ["ip", "route"] and len(w) >= 4 and "/" in w[2]:
        # FRRouting: ip route A.B.C.D/len NEXT-HOP|INTERFACE
        if _IPV4.fullmatch(w[3]):
            dev.routes.append((str(ipa.IPv4Network(w[2], strict=False)), w[3]))
        else:
            warn.append(f"{dev.name}: route {w[2]} via {w[3]} skipped (next-hop IP needed)")
    elif w[:2] == ["ip", "route"] and len(w) >= 5:
        if _IPV4.fullmatch(w[4]):
            next_hop = w[4]
        elif len(w) >= 6 and _IPV4.fullmatch(w[5]):
            next_hop = w[5]  # ip route NET MASK <interface> <next hop>: the next hop decides forwarding
        else:
            next_hop = None
            what = "a null (discard) route" if w[4].lower().startswith("null") else f"via interface {w[4]}"
            warn.append(f"{dev.name}: route {w[2]} {w[3]} {what} skipped (next-hop IP needed)")
        if next_hop:
            dev.routes.append((str(ipa.IPv4Network(f"{w[2]}/{w[3]}", strict=False)), next_hop))
    elif w[:2] == ["frr", "version"] or w[:2] == ["frr", "defaults"]:
        dev.platform = "frr"
    elif w[0] in ("exit", "exit-vrf", "end"):
        ctx = None
    elif w[:2] == ["router", "ospf"]:
        ctx = ("ospf",)
        if len(w) >= 3 and w[2].isdigit():
            dev.ospf_process = dev.ospf_process or int(w[2])
    elif w[0] == "access-list" and len(w) >= 3 and dev.platform == "frr":
        warn.append(f"{dev.name}: FRRouting access-list {w[1]} is a route filter, not a packet filter; not modelled")
    elif w[0] == "access-list" and len(w) >= 3:
        num = int(w[1]) if w[1].isdigit() else 0
        ace = _ace(w[2:], num < 100 or 1300 <= num < 2000)
        if ace:
            dev.acls.setdefault(w[1], []).append((None, *ace))
    elif w[:2] == ["ip", "access-list"] and len(w) >= 4 and w[2] in ("standard", "extended"):
        ctx = ("acl", w[3], w[2] == "standard")
    elif w == ["ip", "routing"]:
        dev.ip_routing = True
    elif w[0] == "line" and len(w) >= 2 and w[1] in ("vty", "console", "con", "aux"):
        entry = {"lines": " ".join(w[1:]), "kind": "vty" if w[1] == "vty" else "console",
                 "transport": None, "access_class": None, "login": None, "password": None}
        dev.facts["vty"].append(entry)
        ctx = ("line", entry)
    elif w[:3] == ["ip", "http", "server"]:
        dev.facts["http_server"] = True
    elif w[:4] == ["no", "ip", "http", "server"]:
        dev.facts["http_server"] = False
    elif w[:3] == ["ip", "http", "secure-server"]:
        dev.facts["https_server"] = True
    elif w[:2] == ["snmp-server", "community"] and len(w) >= 3:
        # The community string is a credential: record only that one exists and its access mode.
        mode = "RW" if "RW" in w[3:] or "rw" in w[3:] else "RO"
        acl = next((t for t in w[3:] if t not in ("RO", "RW", "ro", "rw", "view") and not t.isdigit()), None)
        dev.facts["snmp_communities"].append({"mode": mode, "restricted": bool(acl) or any(t.isdigit() for t in w[3:])})
    elif w[:2] == ["snmp-server", "user"] and "v3" in w:
        dev.facts["snmp_v3_users"] += 1
    elif w[:2] == ["enable", "secret"]:
        dev.facts["enable"] = f"secret {w[2]}" if len(w) >= 4 and w[2].isdigit() else "secret 5"
    elif w[:2] == ["enable", "password"]:
        dev.facts["enable"] = "password 7" if len(w) >= 4 and w[2] == "7" else "password 0"
    elif w[:2] == ["service", "password-encryption"]:
        dev.facts["password_encryption"] = True
    elif w[0] == "username" and len(w) >= 3:
        kind = next((f"{t} {w[k + 1]}" if k + 1 < len(w) - 1 and w[k + 1].isdigit() else
                     ("secret 5" if t == "secret" else "password 0")
                     for k, t in enumerate(w) if t in ("secret", "password")), "none")
        dev.facts["local_users"].append({"user": w[1], "storage": kind})
    elif w[:3] == ["ip", "ssh", "version"] and len(w) == 4:
        dev.facts["ssh_version"] = w[3]
    elif w[:2] == ["spanning-tree", "vlan"] and len(w) >= 5 and w[3] == "priority" and w[4].isdigit():
        priorities = dev.facts.setdefault("stp_priority", {})
        for vlan in _vlan_list(w[2]):
            priorities[str(vlan)] = int(w[4])
    elif w[:2] == ["spanning-tree", "mode"] and len(w) >= 3:
        dev.facts["stp_mode"] = w[2]
    return ctx


def parse_configs(text: str, lenient: bool = False) -> tuple[dict[str, Dev], list[str]]:
    """Reject malformed or unsupported represented settings before any database write.

    lenient=True is used for configurations collected from devices: anything the model cannot represent is
    dropped with a warning instead of rejecting the whole configuration.
    """
    if lenient:
        devs, warnings = _parse_configs(text, lenient=True)
        for dev in devs.values():
            _sanitize(dev, warnings)
        return devs, warnings
    try:
        devs, warnings = _parse_configs(text)
        for dev in devs.values():
            for iface in dev.ifs.values():
                InterfaceCreate(name=iface.name, description=iface.description, ip_address=iface.ip, subnet_mask=iface.mask,
                                vlan_id=iface.vlan, ospf_area=iface.area, mode=iface.mode,
                                status="admin-down" if iface.down else "up", allowed_vlans=iface.allowed,
                                native_vlan=iface.native, speed_mbps=iface.speed)
            for vlan in dev.vlans:
                if not 1 <= vlan <= 4094:
                    raise ValueError(f"{dev.name}: VLAN must be between 1 and 4094")
            for _, next_hop in dev.routes:
                validate_ipv4(next_hop)
            for entries in dev.acls.values():
                for sequence, action, proto, src, dst, port in entries:
                    AclRuleCreate(sequence=sequence if sequence is not None else 10, action=action, protocol=proto,
                                  source=src, destination=dst, port=port)
        return devs, warnings
    except ValidationError as exc:
        detail = "; ".join(str(error["msg"]).removeprefix("Value error, ") for error in exc.errors())
        raise ValidationFailed(f"Configuration import: {detail}") from None
    except (ValueError, IndexError) as exc:
        raise ValidationFailed(f"Configuration import: {exc}") from None


def _sanitize(dev: Dev, warn: list[str]) -> None:
    """Drop values the database schema would reject (lenient parsing of collected configurations)."""
    for name, iface in list(dev.ifs.items()):
        try:
            InterfaceCreate(name=iface.name, description=iface.description, ip_address=iface.ip, subnet_mask=iface.mask,
                            vlan_id=iface.vlan, ospf_area=iface.area, mode=iface.mode,
                            status="admin-down" if iface.down else "up", allowed_vlans=iface.allowed,
                            native_vlan=iface.native, speed_mbps=iface.speed)
        except ValidationError as exc:
            warn.append(f"{dev.name} {name}: not modelled ({exc.errors()[0]['msg'].removeprefix('Value error, ')})")
            del dev.ifs[name]
    dev.vlans = {v: n for v, n in dev.vlans.items() if 1 <= v <= 4094}
    good = []
    for dst, nh in dev.routes:
        try:
            validate_ipv4(nh)
            good.append((dst, nh))
        except ValueError:
            warn.append(f"{dev.name}: route {dst} via {nh} not modelled")
    dev.routes = good
    for acl, entries in dev.acls.items():
        kept = []
        for entry in entries:
            sequence, action, proto, src, dst, port = entry
            try:
                AclRuleCreate(sequence=sequence if sequence is not None else 10, action=action, protocol=proto,
                              source=src, destination=dst, port=port)
                kept.append(entry)
            except ValidationError:
                warn.append(f"{dev.name}: ACL {acl} entry not modelled")
        dev.acls[acl] = kept


def named_acls(d: Dev, warn: list[str]) -> list[tuple]:
    """Every defined access list as (name, sequence, action, protocol, source, destination, port) entries.

    A list filters only where an interface applies it; lists referenced only by a line access-class (management)
    or not referenced at all are kept for the rule checks (shadowed entries) and filter no routed traffic."""
    applied = {a for i in d.ifs.values() for a in i.acls}
    out = []
    for acl, entries in d.acls.items():
        used = set()
        for seq, *ace in entries:
            if seq is None or seq in used:
                seq = max(used, default=0) + 10
            used.add(seq)
            out.append((acl, seq, *ace))
        if acl not in applied and not any(ref["acl"] == acl for ref in d.facts.get("acl_references", [])):
            warn.append(f"{d.name}: access list {acl} is defined but not applied anywhere")
    for acl in sorted(applied - set(d.acls)):
        warn.append(f"{d.name}: access list {acl} is applied but not defined (it filters nothing)")
    return out


def undefined_acls(d: Dev) -> list[dict]:
    """ACL references (interface access-group, line access-class) whose ACL is not defined on the device."""
    return [ref for ref in d.facts.get("acl_references", []) if ref["acl"] not in d.acls]


def _classify(dev: Dev, text_has_switchport: bool, warn: list[str]) -> None:
    n = dev.name.lower()
    if n.startswith(("fw", "asa")) or "firewall" in n:
        dev.kind = "firewall"
    elif text_has_switchport:
        dev.kind = "switch"
    routing = dev.kind == "switch" and dev.ip_routing
    dev.facts["ip_routing"] = bool(routing)
    for i in list(dev.ifs.values()):
        if i.name.lower().startswith("vlan") and dev.kind == "switch" and not routing:
            dev.mgmt = dev.mgmt or i.ip  # SVI on a Layer-2 switch = management address
            del dev.ifs[i.name]
            continue
        if i.name.lower().startswith("vlan") and routing:
            digits = "".join(ch for ch in i.name if ch.isdigit())
            i.vlan, i.mode = (int(digits) if digits else None), None  # SVI: routes for its VLAN
            dev.mgmt = dev.mgmt or i.ip
            if i.vlan:
                dev.vlans.setdefault(i.vlan, None)
        if i.ip and i.area is None:
            i.area = next((a for net, a in dev.ospf if ipa.IPv4Address(i.ip) in net), None)


def _endpoints(text: str, devs: dict[str, Dev], warn: list[str]) -> list[tuple[str, str, str, str]]:
    """Lines: name, type, ip/prefix, gateway, device interface  ->  links to make."""
    links = []
    for n, line in enumerate(text.splitlines(), 1):
        f = [x.strip() for x in line.split(",")]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(f) < 5 or f[1].lower() not in _TYPES:
            warn.append(f"Endpoint line {n} skipped: use name, pc|server|internet, ip/prefix, gateway, device interface")
            continue
        name, kind, cidr, gw, att = f[0], f[1].lower(), f[2], f[3] or None, f[4].split()
        try:
            ip = ipa.IPv4Interface(cidr) if cidr else None
        except ValueError:
            warn.append(f"Endpoint {name}: invalid address {cidr}")
            continue
        try:
            validate_ipv4(gw)
            InterfaceCreate(name="eth0", ip_address=str(ip.ip) if ip else None,
                            subnet_mask=str(ip.netmask) if ip else None)
        except ValueError as exc:
            warn.append(f"Endpoint {name} skipped: {exc}")
            continue
        d = devs.setdefault(name, Dev(name, kind))
        d.kind, d.gw = kind, gw
        port = "isp" if kind == "internet" else "eth0"
        d.ifs[port] = Iface(port, str(ip.ip) if ip else None, str(ip.netmask) if ip else None)
        if len(att) == 2:
            links.append((name, port, att[0], ifname(att[1])))
    return links


def _flows(text: str, devs: dict[str, Dev], warn: list[str]) -> list[tuple]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        f = [x.strip() for x in line.split(",")]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(f) != 7 or f[1] not in devs or f[2] not in devs or f[3] not in ("ip", "tcp", "udp", "icmp") \
                or f[5] not in ("allow", "deny") or f[6] not in ("low", "medium", "high", "critical"):
            warn.append(f"Flow line {n} skipped: use name, source, destination, ip|tcp|udp|icmp, port, "
                        "allow|deny, low|medium|high|critical (devices must exist)")
            continue
        try:
            if f[4] and not f[4].isdigit():
                raise ValueError("use a numeric destination port or leave it blank")
            port = validate_port(int(f[4]) if f[4] else None, f[3])
            if f[1] == f[2]:
                raise ValueError("source and destination must be different")
        except ValueError as exc:
            warn.append(f"Flow line {n} skipped: {exc}")
            continue
        out.append((f[0], f[1], f[2], f[3], port, f[5], f[6]))
    return out


def _links(devs: dict[str, Dev], extra: list[tuple], warn: list[str]) -> list[tuple]:
    links, taken = [], set()

    def add(a, ai, b, bi, kind=None):
        if a == b or (a, ai) in taken or (b, bi) in taken:
            return
        for d, i in ((a, ai), (b, bi)):
            if i not in devs[d].ifs:
                devs[d].ifs[i] = Iface(i)
            devs[d].ifs[i].used = True
        taken.update({(a, ai), (b, bi)})
        links.append((a, ai, b, bi, kind))

    reported = {(d.name, loc, nbr if nbr in devs else nbr.split(".")[0], rem) for d in devs.values() for loc, nbr, rem in d.cdp}

    for d in devs.values():
        for loc, nbr, rem in d.cdp:
            nbr = nbr if nbr in devs else nbr.split(".")[0]
            if nbr in devs:
                add(d.name, loc, nbr, rem, "cdp-both" if (nbr, rem, d.name, loc) in reported else "cdp")
            else:
                warn.append(f"{d.name} {loc}: CDP neighbour {nbr} has no config, link skipped")
    by_net = defaultdict(list)
    for d in devs.values():
        if d.kind in ("router", "firewall"):
            for i in d.ifs.values():
                if i.net and "." not in i.name:
                    by_net[i.net].append((d.name, i.name))
    for net, ends in by_net.items():
        if len(ends) == 2 and ends[0][0] != ends[1][0]:
            add(*ends[0], *ends[1], "subnet")
    for a, ai, b, bi in extra:
        if b not in devs:
            warn.append(f"Endpoint {a}: device {b} not found, link skipped")
        else:
            add(a, ai, b, bi)
    for d in devs.values():
        lonely = {i.name.split(".")[0] for i in d.ifs.values() if "." in i.name} - {n for n, i in d.ifs.items() if i.used}
        warn += [f"{d.name} {p}: sub-interfaces but no link found; paste `show cdp neighbors` or add the link by hand"
                 for p in sorted(lonely)]
    return links


def _layout(devs: dict[str, Dev], links: list[tuple]) -> dict[str, tuple[float, float]]:
    adj = defaultdict(set)
    for a, _, b, _, _ in links:
        adj[a].add(b)
        adj[b].add(a)
    rank = {"internet": 0, "firewall": 1, "router": 2, "switch": 3, "pc": 4, "server": 4}
    order = sorted(devs, key=lambda n: (rank[devs[n].kind], -len(adj[n]), n))
    depth: dict[str, int] = {}
    for root in order:
        if root in depth:
            continue
        depth[root], queue = (max(depth.values()) + 1 if depth else 0), [root]
        for n in queue:
            for m in sorted(adj[n]):
                if m not in depth:
                    depth[m] = depth[n] + 1
                    queue.append(m)
    pos: dict[str, tuple[float, float]] = {}
    for lvl in sorted(set(depth.values())):
        row = [n for n in depth if depth[n] == lvl]
        row.sort(key=lambda n: (sum(pos[p][0] for p in adj[n] if p in pos) / max(1, sum(p in pos for p in adj[n])), n))
        for k, n in enumerate(row):
            pos[n] = ((k - (len(row) - 1) / 2) * 240, lvl * 150 - 440)
    return pos


def import_network(db: Session, user: User | None, name: str, configs: str, endpoints: str = "",
                   flows: str = "", dry_run: bool = False) -> dict:
    devs, warn = parse_configs(configs)
    if not devs:
        raise ValidationFailed("No device found: each config must contain a `hostname` line")
    for d in devs.values():
        sect = re.search(rf"hostname\s+{re.escape(d.name)}\b(.*?)(?=^hostname\s|\Z)", configs, re.S | re.M)
        _classify(d, bool(sect and "switchport" in sect.group(1)), warn)
    warn += [f"{d.name}: no interfaces found; paste its show running-config" for d in devs.values() if not d.ifs]
    links = _links(devs, _endpoints(endpoints, devs, warn), warn)
    fl = _flows(flows, devs, warn)
    for d in devs.values():  # keep configured or linked ports, drop unused switch ports
        d.ifs = {k: i for k, i in d.ifs.items()
                 if i.used or i.ip or i.vlan or i.mode or i.acls or any(x.startswith(k + ".") for x in d.ifs)}
        for i in d.ifs.values():
            if d.kind == "switch" and i.mode == "access" and i.vlan:
                d.vlans.setdefault(i.vlan, None)
    rules = {d.name: named_acls(d, warn) for d in devs.values()}
    summary = {"devices": len(devs), "interfaces": sum(len(d.ifs) for d in devs.values()), "links": len(links),
               "vlans": sum(len(d.vlans) for d in devs.values()), "routes": sum(len(d.routes) for d in devs.values()),
               "acl_rules": sum(map(len, rules.values())), "flows": len(fl),
               "by_type": {k: sum(d.kind == k for d in devs.values()) for k in
                           ("router", "firewall", "switch", "pc", "server", "internet")}}
    if dry_run:
        return {"network_id": None, "summary": summary, "warnings": warn}

    net = Network(name=_available_name(db, name.strip() or "Imported network"),
                  description="Imported from device configurations", network_type="Enterprise",
                  source="config-import", metadata_json={"interface_naming_version": 1, "ospf_process": {
                      d.name: d.ospf_process for d in devs.values() if d.ospf_process}},
                  created_by=user.id if user else None)
    db.add(net)
    db.flush()
    pos = _layout(devs, links)
    ids, iids = {}, {}
    for d in devs.values():
        facts = None
        if d.kind in ("router", "switch", "firewall"):
            facts = {**d.facts, "undefined_acls": undefined_acls(d), "defined_acls": sorted(d.acls)}
        row = Device(network_id=net.id, name=d.name, device_type=d.kind, config_facts=facts,
                     platform=d.platform if d.kind in ("router", "switch", "firewall") else None,
                     vendor=__import__("backend.collectors.drivers", fromlist=["get"]).get(d.platform).vendor
                     if d.kind in ("router", "switch", "firewall") else None,
                     management_ip=d.mgmt, default_gateway=d.gw, x_position=pos[d.name][0], y_position=pos[d.name][1])
        db.add(row)
        db.flush()
        ids[d.name] = row.id
        for i in d.ifs.values():
            x = Interface(device_id=row.id, name=i.name, description=i.description, ip_address=i.ip,
                          subnet_mask=i.mask, vlan_id=i.vlan,
                          status="admin-down" if i.down else "up",
                          ospf_area=i.area if d.kind != "switch" or d.facts.get("ip_routing") else None,
                          mode=i.mode if d.kind == "switch" else None, speed_mbps=i.speed,
                          allowed_vlans=i.allowed if d.kind == "switch" and i.mode == "trunk" else None,
                          native_vlan=i.native if d.kind == "switch" and i.mode == "trunk" else None,
                          duplex=i.duplex, mtu=i.mtu, ospf_hello=i.hello, ospf_dead=i.dead, acl_in=i.acl_in,
                          acl_out=i.acl_out)
            db.add(x)
            db.flush()
            iids[d.name, i.name] = x.id
        db.add_all(Vlan(device_id=row.id, vlan_id=v, name=n) for v, n in sorted(d.vlans.items()))
        db.add_all(StaticRoute(device_id=row.id, destination=dst, next_hop=nh) for dst, nh in d.routes)
        db.add_all(AclRule(device_id=row.id, acl_name=n, sequence=s, action=a, protocol=p, source=src, destination=dst,
                           port=pt) for n, s, a, p, src, dst, pt in rules[d.name])
    def link_kind(kind, a, ai, b, bi):
        if kind in ("cdp", "cdp-both"):
            both = kind == "cdp-both"
            return "cdp", json.dumps({"evidence": [f"Imported show cdp neighbors: {a} {ai} is connected to {b} {bi}."
                                                   + (" Both devices report the neighbour." if both else "")],
                                      "missing": [] if both else [f"The matching CDP entry from {b}"],
                                      "origin": "config-import", "status": "confirmed" if both else "inferred",
                                      "grade": "Confirmed" if both else "Inferred"})
        if kind == "subnet":
            return "subnet", json.dumps({"evidence": [f"{a} {ai} and {b} {bi} share a routed subnet in the imported configurations."],
                                         "missing": ["Neighbour (CDP/LLDP) evidence of the physical connection"],
                                         "origin": "config-import", "status": "logical", "grade": "Logical"})
        return None, None
    for a, ai, b, bi, kind in links:
        stored_kind, evidence = link_kind(kind, a, ai, b, bi)
        db.add(Link(network_id=net.id, source_device_id=ids[a], source_interface_id=iids[a, ai], kind=stored_kind,
                    destination_device_id=ids[b], destination_interface_id=iids[b, bi], evidence_json=evidence))
    db.add_all(NetworkIntent(network_id=net.id, name=n, source_device_id=ids[s], destination_device_id=ids[t],
                             protocol=p, port=pt, expected_action=e, criticality=c) for n, s, t, p, pt, e, c in fl)
    db.commit()
    return {"network_id": net.id, "summary": summary, "warnings": warn}
