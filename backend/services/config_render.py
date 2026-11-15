"""Cisco IOS style configuration text for a device of the network model.

Used when NetGuard has no collected configuration for a device (practice networks, devices added by hand), so a
backup and a download always reflect what NetGuard knows about the device. Only the modelled parts are written:
hostname, VLANs, interfaces, OSPF areas, static routes, access lists and the default gateway.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from backend.services.network_model import DeviceM


def _wildcard(mask: str) -> str:
    return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(mask)) ^ 0xFFFFFFFF))


def _addr(value: str) -> str:
    """ACL address: any, host x, or network + wildcard."""
    if not value or value == "any":
        return "any"
    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return value
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


def render(device: DeviceM) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"! {device.name} - configuration from the NetGuard model ({stamp})", "!", f"hostname {device.name}", "!"]
    if (device.facts or {}).get("ip_routing") or device.is_l3:
        lines += ["ip routing", "!"]
    for vlan_id, name in sorted(device.vlans.items()):
        lines.append(f"vlan {vlan_id}")
        if name:
            lines.append(f" name {name}")
    if device.vlans:
        lines.append("!")
    ospf_networks: dict[int, list[str]] = {}
    for iface in sorted(device.interfaces.values(), key=lambda i: i.name):
        lines.append(f"interface {iface.name}")
        if iface.description:
            lines.append(f" description {iface.description}")
        if iface.mode == "trunk":
            lines.append(" switchport mode trunk")
            if iface.native_vlan and iface.native_vlan != 1:
                lines.append(f" switchport trunk native vlan {iface.native_vlan}")
            if iface.allowed_vlans is not None:
                lines.append(f" switchport trunk allowed vlan {','.join(str(v) for v in sorted(iface.allowed_vlans)) or 'none'}")
        elif iface.vlan and device.is_switch and not iface.ip:
            lines += [" switchport mode access", f" switchport access vlan {iface.vlan}"]
        elif iface.vlan and "." in iface.name:
            lines.append(f" encapsulation dot1Q {iface.vlan}")
        if iface.ip and iface.mask:
            lines.append(f" ip address {iface.ip} {iface.mask}")
            if iface.ospf_area is not None:
                ospf_networks.setdefault(iface.ospf_area, []).append(
                    f"{ipaddress.IPv4Interface(f'{iface.ip}/{iface.mask}').network.network_address} {_wildcard(iface.mask)}")
        if iface.acl_in:
            lines.append(f" ip access-group {iface.acl_in} in")
        if iface.acl_out:
            lines.append(f" ip access-group {iface.acl_out} out")
        if iface.speed_mbps and iface.mode != "trunk" and not device.is_host:
            lines.append(f" speed {iface.speed_mbps}")
        if iface.duplex:
            lines.append(f" duplex {iface.duplex}")
        if iface.mtu and iface.mtu != 1500:
            lines.append(f" mtu {iface.mtu}")
        if iface.ospf_hello:
            lines.append(f" ip ospf hello-interval {iface.ospf_hello}")
        if iface.ospf_dead:
            lines.append(f" ip ospf dead-interval {iface.ospf_dead}")
        lines.append(" shutdown" if iface.status == "admin-down" else " no shutdown")
        lines.append("!")
    if ospf_networks:
        lines.append("router ospf 1")
        for area, nets in sorted(ospf_networks.items()):
            lines += [f" network {net} area {area}" for net in nets]
        lines.append("!")
    for route in device.routes:
        net = route.network
        lines.append(f"ip route {net.network_address} {net.netmask} {route.next_hop}")
    if device.gateway and not device.is_router:
        lines.append(f"ip default-gateway {device.gateway}")
    for name, rules in device.acl_lists().items():
        lines.append("!")
        lines.append(f"ip access-list extended {name or 'NETGUARD-ACL'}")
        for rule in rules:
            port = f" eq {rule.port}" if rule.port else ""
            lines.append(f" {rule.sequence} {rule.action} {rule.protocol} {_addr(rule.source)} {_addr(rule.destination)}{port}")
    lines += ["!", "end", ""]
    return "\n".join(lines)
