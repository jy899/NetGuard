"""Writes collected device state into the stored network model.

A configuration collected from a device (or read from a laboratory definition) is the source of truth for that
device's configuration-derived fields: interfaces, addresses, VLANs, static routes, ACLs, OSPF and hygiene facts.
Operational facts (link state, speed, duplex, error counters) come from interface tables. Every configuration
snapshot is stored encrypted with its SHA-256 digest.
"""
from __future__ import annotations

import hashlib
import ipaddress as ipa

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.models import AclRule, Device, DeviceConfig, Interface, Network, StaticRoute, Vlan
from backend.services import config_import


def store_config(db: Session, device: Device, text: str, source: str, kind: str = "collected", user=None) -> DeviceConfig:
    row = DeviceConfig(device_id=device.id, kind=kind, source=source,
                       sha256=hashlib.sha256(text.encode()).hexdigest(), collected_by=user.id if user else None)
    row.text = text
    db.add(row)
    db.flush()
    return row


def latest_config(db: Session, device_id: int, kinds: tuple[str, ...] = ("collected", "post-change")) -> DeviceConfig | None:
    return db.scalar(select(DeviceConfig).where(DeviceConfig.device_id == device_id, DeviceConfig.kind.in_(kinds))
                     .order_by(DeviceConfig.id.desc()).limit(1))


def has_switchports(text: str) -> bool:
    import re

    return bool(re.search(r"^\s+switchport (mode|access|trunk)", text, re.M))


def parse_one(text: str, hostname_hint: str | None = None) -> tuple[config_import.Dev | None, list[str]]:
    if hostname_hint and "hostname " not in text:
        text = f"hostname {hostname_hint}\n" + text
    devs, warnings = config_import.parse_configs(text, lenient=True)
    if not devs:
        return None, warnings + ["The configuration has no hostname line."]
    # A collected configuration describes one device; keep the one that owns most interfaces.
    dev = max(devs.values(), key=lambda d: len(d.ifs))
    return dev, warnings


def _iface(db: Session, device: Device, name: str, cache: dict) -> Interface:
    row = cache.get(name)
    if row is None:
        row = Interface(device_id=device.id, name=name, status="up")
        db.add(row)
        db.flush()
        cache[name] = row
    return row


def apply_config(db: Session, device: Device, dev: config_import.Dev, warnings: list[str]) -> dict:
    """Replace the device's configuration-derived model with the parsed configuration."""
    network = db.get(Network, device.network_id)
    is_switch = device.device_type == "switch"
    routing = is_switch and dev.ip_routing
    for iface in list(dev.ifs.values()):
        if iface.ip and iface.area is None:
            iface.area = next((area for net, area in dev.ospf if ipa.IPv4Address(iface.ip) in net), None)
        if is_switch and iface.name.lower().startswith("vlan"):
            device.management_ip = device.management_ip or iface.ip
            if not routing:
                del dev.ifs[iface.name]  # SVI of a Layer-2 switch: management address only
                continue
            digits = "".join(ch for ch in iface.name if ch.isdigit())
            iface.vlan, iface.mode = (int(digits) if digits else None), None
    existing = {i.name: i for i in db.scalars(select(Interface).where(Interface.device_id == device.id))}
    for iface in dev.ifs.values():
        row = _iface(db, device, iface.name, existing)
        row.description = (iface.description or row.description)
        row.ip_address, row.subnet_mask = iface.ip, iface.mask
        svi = is_switch and iface.name.lower().startswith("vlan")
        row.vlan_id = iface.vlan if (is_switch and iface.mode != "trunk") or "." in iface.name else None
        row.mode = None if svi or (is_switch and iface.ip and not iface.mode) else \
            (iface.mode or ("access" if iface.vlan else None)) if is_switch else None
        if iface.down:
            row.status = "admin-down"
        elif row.status == "admin-down":
            row.status = "up"
        row.ospf_area = iface.area if not is_switch or routing else None
        row.allowed_vlans = iface.allowed if is_switch and iface.mode == "trunk" else None
        row.native_vlan = (iface.native or 1) if is_switch and iface.mode == "trunk" else None
        row.speed_mbps = iface.speed or row.speed_mbps
        row.duplex = iface.duplex or row.duplex
        row.mtu = iface.mtu or row.mtu
        row.ospf_hello, row.ospf_dead = iface.hello, iface.dead
        row.acl_in, row.acl_out = iface.acl_in, iface.acl_out
    if is_switch:
        db.execute(delete(Vlan).where(Vlan.device_id == device.id))
        vlans = dict(dev.vlans)
        for iface in dev.ifs.values():
            if iface.mode != "trunk" and iface.vlan:
                vlans.setdefault(iface.vlan, None)
        db.add_all(Vlan(device_id=device.id, vlan_id=v, name=n) for v, n in sorted(vlans.items()))
    db.execute(delete(StaticRoute).where(StaticRoute.device_id == device.id))
    db.add_all(StaticRoute(device_id=device.id, destination=dst, next_hop=nh) for dst, nh in dev.routes)
    db.execute(delete(AclRule).where(AclRule.device_id == device.id))
    db.add_all(AclRule(device_id=device.id, acl_name=n, sequence=s, action=a, protocol=p, source=src, destination=dst,
                       port=pt) for n, s, a, p, src, dst, pt in config_import.named_acls(dev, warnings))
    facts = dict(dev.facts)
    facts["ip_routing"] = bool(routing)
    facts["undefined_acls"] = config_import.undefined_acls(dev)
    facts["defined_acls"] = sorted(dev.acls)
    device.config_facts = facts
    device.platform = dev.platform
    if network is not None and dev.ospf_process:
        meta = dict(network.metadata_json or {})
        meta["ospf_process"] = {**meta.get("ospf_process", {}), device.name: dev.ospf_process}
        network.metadata_json = meta
    db.flush()
    return {"interfaces": len(dev.ifs), "routes": len(dev.routes), "acl_rules": sum(len(v) for v in dev.acls.values())}


def store_telemetry(device: Device, logs: list[str] | None, ports: list[dict] | None, at: str) -> None:
    """Recent syslog messages and interface counters from the last collection (for anomaly analysis)."""
    telemetry = dict(device.telemetry or {})
    if logs is not None:
        telemetry["syslog"] = list(logs)[-200:]
    if ports:
        telemetry["interfaces"] = {p["port"]: {k: p.get(k) for k in ("status", "speed", "duplex", "mtu", "errors")}
                                   for p in ports[:256] if p.get("port")}
    telemetry["collected_at"] = at
    device.telemetry = telemetry


def apply_operational(db: Session, device: Device, ports: list[dict], stp: dict[str, str] | None = None) -> None:
    """Link state and counters from show interfaces or IF-MIB; configuration fields stay as configured."""
    existing = {i.name: i for i in db.scalars(select(Interface).where(Interface.device_id == device.id))}
    for port in ports:
        row = existing.get(port["port"])
        if row is None:
            continue  # ports without configuration stay out of the model until a link or config needs them
        status = port.get("status") or ("admin-down" if port.get("admin") == "down" else
                                        "down" if port.get("oper") == "down" else "up" if port.get("oper") == "up" else None)
        if status:
            row.status = status
        if port.get("speed") and not row.speed_mbps:
            row.speed_mbps = port["speed"]
        if port.get("duplex") and not row.duplex:
            row.duplex = port["duplex"]
        if port.get("mtu") and not row.mtu:
            row.mtu = port["mtu"]
        if port.get("errors") is not None:
            row.error_count = port["errors"]
    for name, state in (stp or {}).items():
        row = existing.get(name)
        if row is not None and row.mode == "trunk" and state in ("forwarding", "blocking"):
            row.stp_state = state
    db.flush()


def parse_endpoint(text: str) -> dict:
    """Address, mask and gateway of an endpoint from a VPCS startup file, a Linux network configuration or the
    host lines Packet Tracer stores ("ip ADDRESS MASK GATEWAY")."""
    import re

    found: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        words = line.split()
        if not words or line.startswith(("#", "!")):
            continue
        if words[0] == "set" and words[1:2] == ["pcname"] and len(words) >= 3:
            found["name"] = words[2]
        elif words[0] == "ip" and len(words) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+(/\d+)?", words[1]):
            try:
                if "/" in words[1]:
                    iface = ipa.IPv4Interface(words[1])
                    found.update(ip=str(iface.ip), mask=str(iface.netmask))
                    rest = words[2:]
                else:
                    found.update(ip=words[1], mask=str(ipa.IPv4Network(f"0.0.0.0/{words[2]}").netmask))
                    rest = words[3:]
            except (ValueError, IndexError):
                continue
            if rest and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", rest[0]):
                found["gateway"] = rest[0]
        elif words[0] == "address" and len(words) >= 2:
            try:
                iface = ipa.IPv4Interface(words[1])
                found["ip"] = str(iface.ip)
                if "/" in words[1]:
                    found["mask"] = str(iface.netmask)
            except ValueError:
                pass
        elif words[0] == "netmask" and len(words) >= 2:
            found["mask"] = words[1]
        elif words[0] == "gateway" and len(words) >= 2:
            found["gateway"] = words[1]
        elif words[:3] == ["ip", "addr", "add"] and len(words) >= 4:
            try:
                iface = ipa.IPv4Interface(words[3])
                found.update(ip=str(iface.ip), mask=str(iface.netmask))
            except ValueError:
                pass
        elif words[:4] == ["ip", "route", "add", "default"] and "via" in words:
            found["gateway"] = words[words.index("via") + 1]
    if found.get("ip") and not found.get("mask"):
        found["mask"] = "255.255.255.0"
    return found


def apply_endpoint(db: Session, device: Device, text: str) -> bool:
    """Write an endpoint's address and gateway into its cabled interface (or its first interface)."""
    from backend.models import Link

    found = parse_endpoint(text)
    if not found.get("ip"):
        return False
    interfaces = list(db.scalars(select(Interface).where(Interface.device_id == device.id).order_by(Interface.id)))
    cabled = {i for l in db.scalars(select(Link).where((Link.source_device_id == device.id) | (Link.destination_device_id == device.id)))
              for i in (l.source_interface_id, l.destination_interface_id)}
    target = next((i for i in interfaces if i.id in cabled), interfaces[0] if interfaces else None)
    if target is None:
        target = Interface(device_id=device.id, name="eth0", status="up")
        db.add(target)
    target.ip_address, target.subnet_mask = found["ip"], found["mask"]
    if found.get("gateway"):
        device.default_gateway = found["gateway"]
    db.flush()
    return True
