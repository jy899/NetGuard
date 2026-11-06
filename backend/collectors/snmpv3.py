"""SNMPv3 for discovery.

* engine_discovery(): the unauthenticated SNMPv3 discovery exchange of RFC 3414 section 4. NetGuard sends a
  GetRequest with an empty user name; an SNMPv3 agent answers with a Report that carries its snmpEngineID,
  whose enterprise number identifies the vendor. No community string or user name is ever tried.
* collect(): authenticated (authPriv only) read-only walks of standard MIBs with a user-supplied SNMPv3 user.
"""
from __future__ import annotations

import asyncio
import secrets
import socket

ENTERPRISES = {9: "Cisco", 11: "HPE", 43: "3Com", 311: "Microsoft", 674: "Dell", 1916: "Extreme Networks",
               2011: "Huawei", 2636: "Juniper Networks", 3375: "F5", 4526: "Netgear", 6486: "Alcatel-Lucent",
               6876: "VMware", 8072: "Net-SNMP", 9303: "Ubiquiti", 11863: "TP-Link", 12356: "Fortinet",
               14179: "Cisco (Airespace)", 14823: "Aruba", 14988: "MikroTik", 25461: "Palo Alto Networks",
               25506: "H3C", 30065: "Arista Networks", 41112: "Ubiquiti", 47196: "Aruba (HPE)"}


# ------------------------------------------------------------------ minimal BER
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _int(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return _tlv(0x02, raw)


def _octets(b: bytes) -> bytes:
    return _tlv(0x04, b)


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _decode(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    return tag, data[pos:pos + length], pos + length


def _children(data: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(data):
        tag, value, pos = _decode(data, pos)
        out.append((tag, value))
    return out


def discovery_request(msg_id: int, request_id: int) -> bytes:
    usm = _seq(_octets(b""), _int(0), _int(0), _octets(b""), _octets(b""), _octets(b""))
    pdu = _tlv(0xA0, _int(request_id) + _int(0) + _int(0) + _seq())
    scoped = _seq(_octets(b""), _octets(b""), pdu)
    header = _seq(_int(msg_id), _int(65507), _octets(b"\x04"), _int(3))
    return _seq(_int(3), header, _octets(usm), scoped)


def parse_engine_report(data: bytes) -> dict | None:
    try:
        tag, body, _ = _decode(data)
        if tag != 0x30:
            return None
        parts = _children(body)
        if len(parts) < 3 or parts[0] != (0x02, b"\x03"):
            return None
        usm = _children(_decode(parts[2][1])[1])
        engine_id = usm[0][1]
        boots = int.from_bytes(usm[1][1], "big") if len(usm) > 1 else None
    except (IndexError, ValueError):
        return None
    if not engine_id:
        return None
    return {"engine_id": engine_id.hex(), "engine_boots": boots, **describe_engine(engine_id)}


def describe_engine(engine_id: bytes) -> dict:
    if len(engine_id) >= 5 and engine_id[0] & 0x80:
        enterprise = int.from_bytes(engine_id[:4], "big") & 0x7FFFFFFF
        fmt, data = engine_id[4], engine_id[5:]
        detail = None
        if fmt == 1 and len(data) == 4:
            detail = "IPv4 " + ".".join(str(b) for b in data)
        elif fmt == 3 and len(data) == 6:
            detail = "MAC " + ":".join(f"{b:02x}" for b in data)
        elif fmt == 4:
            detail = data.decode("ascii", "replace")[:40]
        return {"enterprise": enterprise, "vendor": ENTERPRISES.get(enterprise), "engine_detail": detail}
    if len(engine_id) == 12:  # pre-RFC 3411 format: 4-byte enterprise + 8 bytes (Cisco IOS style)
        enterprise = int.from_bytes(engine_id[:4], "big")
        return {"enterprise": enterprise, "vendor": ENTERPRISES.get(enterprise), "engine_detail": None}
    return {"enterprise": None, "vendor": None, "engine_detail": None}


def engine_discovery(ip: str, port: int = 161, timeout: float = 1.5, retries: int = 1) -> dict | None:
    msg_id, request_id = secrets.randbelow(2**31 - 1) + 1, secrets.randbelow(2**31 - 1) + 1
    packet = discovery_request(msg_id, request_id)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for _ in range(retries + 1):
            try:
                sock.sendto(packet, (ip, port))
                data, _ = sock.recvfrom(4096)
            except OSError:
                continue
            report = parse_engine_report(data)
            if report:
                return report
    return None


# ------------------------------------------------------------------ authenticated collection
OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0", "sysObjectID": "1.3.6.1.2.1.1.2.0", "sysName": "1.3.6.1.2.1.1.5.0",
    "sysServices": "1.3.6.1.2.1.1.7.0", "ipForwarding": "1.3.6.1.2.1.4.1.0", "dot1dBaseNumPorts": "1.3.6.1.2.1.17.1.2.0",
    "dot1dBaseBridgeAddress": "1.3.6.1.2.1.17.1.1.0",
}
TABLES = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2", "ifSpeed": "1.3.6.1.2.1.2.2.1.5", "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7", "ifOperStatus": "1.3.6.1.2.1.2.2.1.8", "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20", "ifName": "1.3.6.1.2.1.31.1.1.1.1", "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ipAdEntIfIndex": "1.3.6.1.2.1.4.20.1.2", "ipAdEntNetMask": "1.3.6.1.2.1.4.20.1.3",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3", "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7", "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemSysDesc": "1.0.8802.1.1.2.1.4.1.1.10",
    "cdpCacheAddress": "1.3.6.1.4.1.9.9.23.1.2.1.1.4", "cdpCacheDeviceId": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "cdpCacheDevicePort": "1.3.6.1.4.1.9.9.23.1.2.1.1.7", "cdpCachePlatform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
    "dot1dBasePortIfIndex": "1.3.6.1.2.1.17.1.4.1.2", "dot1dTpFdbPort": "1.3.6.1.2.1.17.4.3.1.2",
    "dot1dStpPortState": "1.3.6.1.2.1.17.2.15.1.3", "dot1dStpPortDesignatedBridge": "1.3.6.1.2.1.17.2.15.1.8",
    "lldpRemManAddrIfSubtype": "1.0.8802.1.1.2.1.4.2.1.3",
    "ipNetToMediaPhysAddress": "1.3.6.1.2.1.4.22.1.2", "ipRouteNextHop": "1.3.6.1.2.1.4.21.1.7",
    "ipRouteMask": "1.3.6.1.2.1.4.21.1.11", "vtpVlanState": "1.3.6.1.4.1.9.9.46.1.3.1.1.2",
}
# Per-VLAN bridge tables (Cisco: SNMPv3 context "vlan-N", SNMPv2c community "community@N").
VLAN_TABLES = ("dot1dBasePortIfIndex", "dot1dTpFdbPort", "dot1dStpPortState", "dot1dStpPortDesignatedBridge")
MAX_VLAN_CONTEXTS = 64
AUTH_PROTOCOLS = ("SHA-256", "SHA-512")
PRIV_PROTOCOLS = ("AES-128", "AES-256")


class SnmpError(Exception):
    pass


def _user(username: str, auth_key: str, priv_key: str, protocols: tuple[str, str]):
    from pysnmp.hlapi.v3arch.asyncio import (UsmUserData, usmAesCfb128Protocol, usmAesCfb256Protocol,
                                             usmHMAC192SHA256AuthProtocol, usmHMAC384SHA512AuthProtocol)

    auth = {"SHA-256": usmHMAC192SHA256AuthProtocol, "SHA-512": usmHMAC384SHA512AuthProtocol}[protocols[0]]
    priv = {"AES-128": usmAesCfb128Protocol, "AES-256": usmAesCfb256Protocol}[protocols[1]]
    return UsmUserData(username, auth_key, priv_key, authProtocol=auth, privProtocol=priv)


async def _walk(engine, auth, target, context, base) -> dict:
    from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, walk_cmd

    rows = {}
    async for err, status, _, binds in walk_cmd(engine, auth, target, context, ObjectType(ObjectIdentity(base)),
                                                lexicographicMode=False):
        if err or status:
            break
        for oid, value in binds:
            rows[str(oid)[len(base) + 1:]] = value
    return rows


async def _collect(ip, port, user, timeout, only_system, community=None):
    from pysnmp.hlapi.v3arch.asyncio import (CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
                                             UdpTransportTarget, get_cmd, walk_cmd)

    engine = SnmpEngine()
    target = await UdpTransportTarget.create((ip, port), timeout=timeout, retries=1)
    result: dict = {"scalars": {}, "tables": {}, "vlan_tables": {}}
    if community is not None:
        user = CommunityData(community, mpModel=1)
    try:
        err, status, _, binds = await get_cmd(engine, user, target, ContextData(),
                                              *[ObjectType(ObjectIdentity(oid)) for oid in OIDS.values()])
        if err:
            raise SnmpError(str(err))
        if status:
            raise SnmpError(status.prettyPrint())
        for name, (oid, value) in zip(OIDS, binds):
            result["scalars"][name] = None if value.__class__.__name__ in ("NoSuchObject", "NoSuchInstance") else value
        if only_system:
            return result
        for name, base in TABLES.items():
            result["tables"][name] = await _walk(engine, user, target, ContextData(), base)
        vlans = sorted({int(s.split(".")[-1]) for s, v in result["tables"].get("vtpVlanState", {}).items()
                        if s.split(".")[-1].isdigit() and int(v) == 1 and int(s.split(".")[-1]) not in range(1002, 1006)})
        for vlan in vlans[:MAX_VLAN_CONTEXTS]:
            if community is not None:
                auth, context = CommunityData(f"{community}@{vlan}", mpModel=1), ContextData()
            else:
                auth, context = user, ContextData(contextName=f"vlan-{vlan}")
            tables = {name: await _walk(engine, auth, target, context, TABLES[name]) for name in VLAN_TABLES}
            if any(tables.values()):
                result["vlan_tables"][vlan] = tables
        return result
    finally:
        engine.close_dispatcher()


def _text(value) -> str:
    if value is None:
        return ""
    try:
        raw = bytes(value)
        if raw and all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
            return raw.decode("ascii").strip()
        return raw.hex() if raw else ""
    except TypeError:
        return value.prettyPrint()


def _mac(value) -> str | None:
    try:
        raw = bytes(value)
    except TypeError:
        return None
    if len(raw) == 6:
        return ":".join(f"{b:02x}" for b in raw)
    text = raw.decode("ascii", "ignore")
    from backend.collectors.netutil import normalize_mac
    return normalize_mac(text)


def collect(ip: str, username: str, auth_key: str, priv_key: str, protocols: tuple[str, str] = ("SHA-256", "AES-128"),
            port: int = 161, timeout: float = 2.0, only_system: bool = False) -> dict:
    """Authenticated read. Raises SnmpError when the agent rejects the user or does not answer."""
    if protocols[0] not in AUTH_PROTOCOLS or protocols[1] not in PRIV_PROTOCOLS:
        raise SnmpError("Unsupported SNMPv3 protocol")
    return _run(ip, port, _user(username, auth_key, priv_key, protocols), timeout, only_system, None)


def collect_v2c(ip: str, community: str, port: int = 161, timeout: float = 2.0, only_system: bool = False) -> dict:
    """Read-only SNMPv2c read with a community string the engineer saved (cleartext on the wire)."""
    if not community:
        raise SnmpError("Enter the read-only community string")
    return _run(ip, port, None, timeout, only_system, community)


def _run(ip, port, user, timeout, only_system, community) -> dict:
    try:
        raw = asyncio.run(_collect(ip, port, user, timeout, only_system, community))
    except SnmpError as exc:
        text = str(exc).lower()
        if any(k in text for k in ("digest", "unknown usm user", "decryption", "unsupported security level", "authorization")):
            raise SnmpError("The device rejected the SNMPv3 user, passphrases or protocols.") from None
        if "timeout" in text or "no snmp response" in text:
            if community is not None:
                raise SnmpError("No SNMPv2c response: the community string was not accepted or UDP 161 is filtered.") from None
            raise SnmpError("No SNMPv3 response to the authenticated request (check UDP 161 and the agent ACL).") from None
        raise
    except Exception as exc:  # noqa: BLE001 - transport errors become one readable message
        raise SnmpError(str(exc) or exc.__class__.__name__) from None
    sysname = _text(raw["scalars"].get("sysName"))
    if not raw["scalars"] or all(v is None for v in raw["scalars"].values()):
        raise SnmpError("No response to the authenticated request")
    return normalise(raw, sysname)


def normalise(raw: dict, sysname: str) -> dict:
    """Convert MIB rows to NetGuard observation facts."""
    tables = raw.get("tables", {})
    t = lambda name: tables.get(name, {})  # noqa: E731
    ifname = {idx: _text(v) for idx, v in t("ifName").items()} or {idx: _text(v) for idx, v in t("ifDescr").items()}
    ports = []
    for idx, name in ifname.items():
        speed_high = t("ifHighSpeed").get(idx)
        speed = int(speed_high) if speed_high is not None and int(speed_high) else (
            int(t("ifSpeed")[idx]) // 1_000_000 if idx in t("ifSpeed") else None)
        admin, oper = t("ifAdminStatus").get(idx), t("ifOperStatus").get(idx)
        errors = None
        if idx in t("ifInErrors") or idx in t("ifOutErrors"):
            errors = int(t("ifInErrors").get(idx, 0)) + int(t("ifOutErrors").get(idx, 0))
        ports.append({"port": name, "ifindex": int(idx), "speed": speed or None,
                      "admin": "up" if admin is not None and int(admin) == 1 else "down" if admin is not None else None,
                      "oper": "up" if oper is not None and int(oper) == 1 else "down" if oper is not None else None,
                      "errors": errors, "mac": _mac(t("ifPhysAddress").get(idx))})
    addresses = []
    for ip, idx in t("ipAdEntIfIndex").items():
        mask = t("ipAdEntNetMask").get(ip)
        addresses.append({"interface": ifname.get(str(int(idx))), "ip": ip,
                          "mask": mask.prettyPrint() if mask is not None else None})
    lldp = []
    loc = {idx: _text(v) for idx, v in t("lldpLocPortId").items()}
    # lldpRemManAddrTable is indexed by timeMark.localPort.index.addrSubtype.addrLen.address: the neighbour's
    # management IPv4 address is part of the OID (subtype 1, length 4).
    mgmt_of = {}
    for suffix in t("lldpRemManAddrIfSubtype"):
        parts = suffix.split(".")
        if len(parts) >= 9 and parts[3] == "1" and parts[4] == "4":
            mgmt_of.setdefault(".".join(parts[:3]), ".".join(parts[5:9]))
    for suffix, name in t("lldpRemSysName").items():
        parts = suffix.split(".")
        if len(parts) < 3:
            continue
        local = loc.get(parts[1]) or ifname.get(parts[1]) or parts[1]
        chassis = t("lldpRemChassisId").get(suffix)
        lldp.append({"local_port": local, "sys_name": _text(name), "port_id": _text(t("lldpRemPortId").get(suffix)),
                     "chassis_mac": _mac(chassis), "mgmt_ip": mgmt_of.get(".".join(parts[:3])),
                     "sys_descr": _text(t("lldpRemSysDesc").get(suffix))[:200], "protocol": "lldp"})
    for suffix, device_id in t("cdpCacheDeviceId").items():
        if_index = suffix.split(".")[0]
        address = t("cdpCacheAddress").get(suffix)
        mgmt = None
        try:
            raw_addr = bytes(address) if address is not None else b""
            mgmt = ".".join(str(b) for b in raw_addr) if len(raw_addr) == 4 else None
        except TypeError:
            pass
        lldp.append({"local_port": ifname.get(if_index, if_index), "sys_name": _text(device_id).split(".")[0],
                     "port_id": _text(t("cdpCacheDevicePort").get(suffix)), "chassis_mac": None, "mgmt_ip": mgmt,
                     "sys_descr": _text(t("cdpCachePlatform").get(suffix))[:200], "protocol": "cdp"})
    macs, stp, seen, designated = [], {}, set(), {}
    contexts = [(None, {k: t(k) for k in VLAN_TABLES})] + list(raw.get("vlan_tables", {}).items())
    for vlan, tables in contexts:
        bridge_if = {p: str(int(v)) for p, v in tables.get("dot1dBasePortIfIndex", {}).items()}
        for suffix, bridge_port in tables.get("dot1dTpFdbPort", {}).items():
            octets = suffix.split(".")
            if len(octets) != 6:
                continue
            mac = ":".join(f"{int(o):02x}" for o in octets)
            port = ifname.get(bridge_if.get(str(int(bridge_port)), ""), None)
            if port and (mac, port) not in seen:
                seen.add((mac, port))
                macs.append({"port": port, "mac": mac, "vlan": vlan})
        for bridge_port, state in tables.get("dot1dStpPortState", {}).items():
            port = ifname.get(bridge_if.get(bridge_port, ""), None)
            if port:
                # 2 blocking, 5 forwarding (BRIDGE-MIB); a port blocking in any VLAN is reported as blocking.
                value = {2: "blocking", 5: "forwarding"}.get(int(state))
                if value and stp.get(port) != "blocking":
                    stp[port] = value
        for bridge_port, bridge_id in tables.get("dot1dStpPortDesignatedBridge", {}).items():
            port = ifname.get(bridge_if.get(bridge_port, ""), None)
            try:
                raw_id = bytes(bridge_id)
            except TypeError:
                continue
            if port and len(raw_id) == 8 and port not in designated:
                # BridgeId: 2-byte priority + the designated bridge's MAC (the switch on the other end of the
                # segment when this port is not the designated port itself).
                designated[port] = ":".join(f"{b:02x}" for b in raw_id[2:])
    arp = []
    for suffix, value in t("ipNetToMediaPhysAddress").items():
        parts = suffix.split(".")
        if len(parts) == 5:
            mac = _mac(value)
            if mac and mac != "00:00:00:00:00:00":
                arp.append({"ip": ".".join(parts[1:]), "mac": mac, "interface": ifname.get(parts[0])})
    routes = []
    for dest, hop in t("ipRouteNextHop").items():
        next_hop = hop.prettyPrint() if hasattr(hop, "prettyPrint") else str(hop)
        if next_hop not in ("0.0.0.0",):
            mask = t("ipRouteMask").get(dest)
            routes.append({"destination": dest, "mask": mask.prettyPrint() if mask is not None else None,
                           "next_hop": next_hop})
    descr = _text(raw["scalars"].get("sysDescr"))

    def number(name):
        value = raw["scalars"].get(name)
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None
    bridge_mac = _mac(raw["scalars"].get("dot1dBaseBridgeAddress"))
    return {"system": {"hostname": sysname or None, "description": descr[:300], "bridge_mac": bridge_mac,
                       "services": number("sysServices"), "ip_forwarding": number("ipForwarding"),
                       "bridge_ports": number("dot1dBaseNumPorts"),
                       "object_id": raw["scalars"].get("sysObjectID").prettyPrint() if raw["scalars"].get("sysObjectID") is not None else None},
            "ports": ports, "addresses": addresses, "neighbours": lldp, "macs": macs, "stp": stp, "arp": arp,
            "routes": routes, "stp_designated": designated}
