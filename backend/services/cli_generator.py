"""Generates platform-specific commands for a proposed change.

The commands are shown with every assessment. NetGuard sends them to a device only for an IT Manager-approved
change on a laboratory device (remediation_service), after a configuration backup; on any other device the
engineer applies them during an approved change window.
"""
from __future__ import annotations

import ipaddress
import re

from backend.services.change_detector import DetectedChange
from backend.services.network_model import NetworkModel
from backend.services.interface_naming import canonical_name, platform_for

OSPF_PROCESS = 1
HEADER = ("# Generated commands; sent automatically only for an approved change (laboratory devices, or production "
          "devices when permission-based self-healing is enabled).")


def _acl_address(spec: str) -> str:
    if spec == "any":
        return "any"
    net = ipaddress.IPv4Network(spec, strict=False)
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


def _cisco(device, iface, kind, p, ospf_process: int = OSPF_PROCESS) -> list[str]:
    name = canonical_name(iface.name, "cisco-ios") if iface else None
    lines: list[str] = []
    if kind == "ip_address":
        lines = [f"interface {name}", f" ip address {p['ip_address']} {p['subnet_mask']}"]
    elif kind == "interface_status":
        lines = [f"interface {name}", " no shutdown" if p["status"] == "up" else " shutdown"]
    elif kind in ("ospf_area", "ospf_network"):
        # Interface-level OSPF matches NetGuard's per-interface model and keeps working if the IP changes.
        new_area = p.get("area") if kind == "ospf_area" else (p["area"] if p["action"] == "advertise" else None)
        lines = [f"interface {name}"]
        if new_area is not None:
            lines.append(f" ip ospf {ospf_process} area {new_area}")
        elif iface.ospf_area is not None:
            lines.append(f" no ip ospf {ospf_process} area {iface.ospf_area}")
    elif kind == "static_route":
        def route(dest, nh):
            net = ipaddress.IPv4Network(dest, strict=False)
            return f"ip route {net.network_address} {net.netmask} {nh}"
        old = next((r for r in device.routes if r.id == p.get("route_id")), None)
        if old is not None:
            lines.append("no " + route(old.destination, old.next_hop))
        if p["action"] != "remove":
            lines.append(route(p["destination"], p["next_hop"]))
    elif kind == "acl_add":
        port = f" eq {p['port']}" if p.get("port") else ""
        name = p.get("acl_name") or acl_name(device)
        lines = [f"ip access-list extended {name}",
                 f" {p['sequence']} {p['action']} {p['protocol']} {_acl_address(p['source'])} "
                 f"{_acl_address(p['destination'])}{port}"]
        applied = {n for i in device.interfaces.values() for n in (i.acl_in, i.acl_out) if n}
        if not p.get("acl_name") and not device.acl and name not in applied:
            # A new unnamed list filters all routed traffic in the model: apply it inbound on every routed interface.
            for routed in sorted(device.interfaces.values(), key=lambda i: i.name):
                if routed.ip:
                    lines += [f"interface {canonical_name(routed.name, 'cisco-ios')}", f" ip access-group {name} in"]
    elif kind == "acl_remove":
        rule = next((r for r in device.acl if r.id == p["rule_id"]), None)
        lines = [f"ip access-list extended {(rule.acl_name if rule else None) or acl_name(device)}",
                 f" no {rule.sequence if rule else '?'}"]
    elif kind == "acl_reference":
        if p["action"] == "remove":
            if p["where"].startswith("interface "):
                target = device.iface_by_name(p["where"].removeprefix("interface ").strip())
                direction = "out" if target is not None and target.acl_out == p["acl"] else "in"
                lines = [p["where"].replace("interface ", "interface ", 1), f" no ip access-group {p['acl']} {direction}"]
            else:
                lines = [p["where"], f" no access-class {p['acl']} in"]
        else:
            lines = [f"ip access-list extended {p['acl']}", " 10 permit ip any any"]
    elif kind == "interface_settings":
        lines = [f"interface {name}"]
        if "speed" in p:
            lines.append(f" speed {p['speed']}")
        if "duplex" in p:
            lines.append(f" duplex {p['duplex']}")
        if "mtu" in p:
            lines.append(f" ip mtu {p['mtu']}" if iface.ip else f" mtu {p['mtu']}")
        if "ospf_hello" in p:
            lines.append(f" ip ospf hello-interval {p['ospf_hello']}")
        if "ospf_dead" in p:
            lines.append(f" ip ospf dead-interval {p['ospf_dead']}")
    elif kind == "trunk_settings":
        lines = [f"interface {name}", " switchport mode trunk"]
        if "native_vlan" in p:
            lines.append(f" switchport trunk native vlan {p['native_vlan']}")
        if "allowed_vlans" in p:
            allowed = "all" if p["allowed_vlans"] == "all" else _vlan_ranges(p["allowed_vlans"])
            lines.append(f" switchport trunk allowed vlan {allowed}")
    elif kind == "isolate_endpoint":
        lines = [f"vlan {p['vlan_id']}", f" name {p.get('name') or 'ISOLATED'}", f"interface {name}",
                 " switchport mode access", f" switchport access vlan {p['vlan_id']}"]
    elif kind == "stp_root":
        lines = ["spanning-tree mode rapid-pvst", f"spanning-tree vlan {p['vlan']} priority {p['priority']}"]
    elif kind == "mgmt_hardening":
        lines = _hardening(device, p)
    elif kind == "physical_remediation":
        lines = _physical(device, iface, p)
    elif kind == "access_vlan":
        lines = [f"interface {name}", " switchport mode access", f" switchport access vlan {p['vlan_id']}"]
    elif kind == "vlan_database":
        if p["action"] == "add":
            lines = [f"vlan {p['vlan_id']}"] + ([f" name {p['name']}"] if p.get("name") else [])
        else:
            lines = [f"no vlan {p['vlan_id']}"]
    return ["configure terminal", *lines, "end"] if lines else []


def _vlan_ranges(vlans) -> str:
    vlans, out = sorted(set(vlans)), []
    start = prev = None
    for v in vlans:
        if start is None:
            start = prev = v
        elif v == prev + 1:
            prev = v
        else:
            out.append(f"{start}-{prev}" if prev != start else str(start))
            start = prev = v
    if start is not None:
        out.append(f"{start}-{prev}" if prev != start else str(start))
    return ",".join(out)


def _vty_lines(device) -> list[str]:
    lines = [line["lines"] for line in (device.facts or {}).get("vty", []) if line.get("kind") == "vty"]
    return lines or ["vty 0 4"]


def _hardening(device, p) -> list[str]:
    action = p["action"]
    if action == "secure_management":
        return _hardening(device, {"action": "ssh_only"}) + (
            ["no ip http server"] if (device.facts or {}).get("http_server") else [])
    if action == "ssh_only":
        out = ["ip ssh version 2"]
        for lines in _vty_lines(device):
            out += [f"line {lines}", " transport input ssh"]
        return out
    if action == "disable_http":
        return ["no ip http server"]
    if action == "remove_snmp_communities":
        # The community strings are credentials and are never stored by NetGuard: the engineer enters them.
        count = max(1, len((device.facts or {}).get("snmp_communities", [])))
        return [f"no snmp-server community <COMMUNITY-{n}>" for n in range(1, count + 1)]
    if action == "restrict_vty":
        net = ipaddress.IPv4Network(p["permit"], strict=False)
        out = [f"ip access-list standard {p['acl']}", f" permit {net.network_address} {net.hostmask}", " deny any log"]
        for lines in _vty_lines(device):
            out += [f"line {lines}", f" access-class {p['acl']} in"]
        return out
    if action == "secure_passwords":
        out = ["service password-encryption", "enable algorithm-type scrypt secret <NEW-ENABLE-SECRET>"]
        for user in (device.facts or {}).get("local_users", []):
            if user.get("storage") in ("password 0", "password 7", "secret 5"):
                out.append(f"username {user['user']} algorithm-type scrypt secret <NEW-SECRET-{user['user']}>")
        return out
    if action == "shutdown_unused":
        out = []
        for port in p["interfaces"]:
            out += [f"interface {canonical_name(port, 'cisco-ios')}", " shutdown"]
        return out
    return []


def _physical(device, iface, p) -> list[str]:
    name = canonical_name(iface.name, "cisco-ios") if iface else ""
    if p["action"] == "clear_errors":
        return [f"! Work order: replace the cable on {device.name} {name}, then:", "end",
                f"clear counters {name}", f"! Verify: show interfaces {name} | include errors"]
    if p["action"] == "replace_media":
        return [f"! Work order: fit matching cable media or transceivers on {device.name} {name}, then:",
                f"interface {name}", " shutdown", " no shutdown"]
    if p["action"] == "move_port":
        target = canonical_name(p["port"], "cisco-ios")
        out = [f"! Work order: move the cable on {device.name} from {name} to {target}, then:", f"interface {target}"]
        if iface.mode == "access" or (iface.mode is None and iface.vlan):
            out += [" switchport mode access", f" switchport access vlan {iface.vlan}"]
        elif iface.mode == "trunk":
            out.append(" switchport mode trunk")
        if iface.ip:
            out.append(f" ip address {iface.ip} {iface.mask}")
        out += [" no shutdown", f"interface {name}", " shutdown"]
        return out
    return []


def acl_name(device) -> str:
    """The device's one applied named ACL (from its configuration), or NETGUARD-ACL for a new one."""
    applied = {i.acl_in for i in device.interfaces.values() if getattr(i, "acl_in", None)}
    applied |= {i.acl_out for i in device.interfaces.values() if getattr(i, "acl_out", None)}
    return next(iter(applied)) if len(applied) == 1 else "NETGUARD-ACL"


def automatable(device, kind: str, parameters: dict | None = None) -> tuple[bool, str | None]:
    """Whether generated commands can be sent as they are to the device (laboratory remediation)."""
    p = parameters or {}
    if kind == "default_gateway":
        return False, "host settings are not changed by NetGuard"
    if kind == "physical_remediation":
        return False, "a physical work order needs a person at the device"
    if kind == "mgmt_hardening" and p.get("action") in ("remove_snmp_communities", "secure_passwords"):
        return False, "the commands need secrets (community strings, new passwords) that NetGuard never stores"
    if device is not None and platform_of(device) in GUI_ONLY:
        return False, f"{getattr(device, 'platform', 'this platform')} is configured through its web GUI or controller"
    return True, None


def _aruba(iface, kind, p) -> list[str]:
    if kind == "access_vlan":
        return ["configure", f"vlan {p['vlan_id']}", f"untagged {iface.name}", "exit", "write memory"]
    if kind == "vlan_database":
        if p["action"] == "remove":
            return ["configure", f"no vlan {p['vlan_id']}", "write memory"]
        return ["configure", f"vlan {p['vlan_id']}", *([f"name {p['name']}"] if p.get("name") else []),
                "exit", "write memory"]
    if kind == "interface_status":
        return ["configure", f"interface {iface.name}", "enable" if p["status"] == "up" else "disable",
                "exit", "write memory"]
    if kind == "ip_address":
        vlan = re.fullmatch(r"vlan\s*(\d+)", iface.name, re.IGNORECASE)
        if vlan:
            return ["configure", f"vlan {vlan[1]}", f"ip address {p['ip_address']} {p['subnet_mask']}",
                    "exit", "write memory"]
    return []


def _fortios(device, iface, kind, p) -> list[str]:
    if kind in ("interface_status", "ip_address"):
        setting = (f"set status {'up' if p['status'] == 'up' else 'down'}" if kind == "interface_status"
                   else f"set ip {p['ip_address']} {p['subnet_mask']}")
        return ["config system interface", f'edit "{iface.name}"', setting, "next", "end"]
    if kind == "static_route" and p["action"] == "add":
        destination = ipaddress.IPv4Network(p["destination"], strict=False)
        gateway = ipaddress.IPv4Address(p["next_hop"])
        egress = [i for i in device.interfaces.values() if i.network and gateway in i.network]
        if not egress:
            return []
        outgoing = max(egress, key=lambda i: i.network.prefixlen)
        return ["config router static", "edit 0", f"set dst {destination.network_address} {destination.netmask}",
                f"set gateway {gateway}", f'set device "{outgoing.name}"', "next", "end"]
    # Database route ids are not FortiOS configuration sequence numbers.
    return []


def _prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def _route_net(dest: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(dest, strict=False)


def _huawei(device, iface, kind, p) -> list[str]:
    name = iface.name if iface else None
    if kind == "ip_address":
        return [f"interface {name}", f" ip address {p['ip_address']} {p['subnet_mask']}", " quit"]
    if kind == "interface_status":
        return [f"interface {name}", " undo shutdown" if p["status"] == "up" else " shutdown", " quit"]
    if kind == "static_route":
        out = []
        old = next((r for r in device.routes if r.id == p.get("route_id")), None)
        if old is not None:
            net = _route_net(old.destination)
            out.append(f"undo ip route-static {net.network_address} {net.netmask} {old.next_hop}")
        if p["action"] != "remove":
            net = _route_net(p["destination"])
            out.append(f"ip route-static {net.network_address} {net.netmask} {p['next_hop']}")
        return out
    if kind == "vlan_database":
        return [f"vlan {p['vlan_id']}", *([f" name {p['name']}"] if p.get("name") else []), " quit"] if p["action"] == "add" \
            else [f"undo vlan {p['vlan_id']}"]
    if kind == "access_vlan":
        return [f"interface {name}", " port link-type access", f" port default vlan {p['vlan_id']}", " quit"]
    if kind == "interface_settings" and "mtu" in p:
        return [f"interface {name}", f" mtu {p['mtu']}", " quit"]
    if kind == "mgmt_hardening" and p.get("action") in ("ssh_only", "secure_management", "disable_http"):
        out = ["undo telnet server enable", "stelnet server enable"] if p["action"] != "disable_http" else []
        return out + (["undo http server enable"] if p["action"] != "ssh_only" else [])
    return []


def _mikrotik(device, iface, kind, p) -> list[str]:
    name = iface.name if iface else None
    if kind == "ip_address":
        prefix = _prefix(p["subnet_mask"])
        return [f"/ip address remove [find interface={name}]", f"/ip address add address={p['ip_address']}/{prefix} interface={name}"]
    if kind == "interface_status":
        return [f"/interface {'enable' if p['status'] == 'up' else 'disable'} [find name={name}]"]
    if kind == "static_route":
        out = []
        old = next((r for r in device.routes if r.id == p.get("route_id")), None)
        if old is not None:
            out.append(f"/ip route remove [find dst-address={_route_net(old.destination)} gateway={old.next_hop}]")
        if p["action"] != "remove":
            out.append(f"/ip route add dst-address={_route_net(p['destination'])} gateway={p['next_hop']}")
        return out
    if kind == "mgmt_hardening" and p.get("action") in ("ssh_only", "secure_management", "disable_http"):
        return (["/ip service disable telnet"] if p["action"] != "disable_http" else []) + \
            (["/ip service disable www"] if p["action"] != "ssh_only" else [])
    return []


def _vyos(device, iface, kind, p) -> list[str]:
    name = iface.name if iface else None
    base = name.split(".")[0] if name else None
    path = f"interfaces ethernet {base}" + (f" vif {name.split('.')[1]}" if name and "." in name else "")
    if kind == "ip_address":
        return [f"delete {path} address", f"set {path} address {p['ip_address']}/{_prefix(p['subnet_mask'])}"]
    if kind == "interface_status":
        return [f"{'delete' if p['status'] == 'up' else 'set'} {path} disable"]
    if kind == "static_route":
        out = []
        old = next((r for r in device.routes if r.id == p.get("route_id")), None)
        if old is not None:
            out.append(f"delete protocols static route {_route_net(old.destination)} next-hop {old.next_hop}")
        if p["action"] != "remove":
            out.append(f"set protocols static route {_route_net(p['destination'])} next-hop {p['next_hop']}")
        return out
    if kind == "interface_settings" and "mtu" in p:
        return [f"set {path} mtu {p['mtu']}"]
    if kind == "mgmt_hardening" and p.get("action") in ("ssh_only", "secure_management"):
        return ["delete service telnet", "set service ssh port 22"]
    return []


def _junos(device, iface, kind, p) -> list[str]:
    name = iface.name if iface else None
    unit = name.split(".")[1] if name and "." in name else "0"
    base = name.split(".")[0] if name else None
    if kind == "ip_address":
        return [f"delete interfaces {base} unit {unit} family inet address",
                f"set interfaces {base} unit {unit} family inet address {p['ip_address']}/{_prefix(p['subnet_mask'])}"]
    if kind == "interface_status":
        return [f"{'delete' if p['status'] == 'up' else 'set'} interfaces {base} disable"]
    if kind == "static_route":
        out = []
        old = next((r for r in device.routes if r.id == p.get("route_id")), None)
        if old is not None:
            out.append(f"delete routing-options static route {_route_net(old.destination)} next-hop {old.next_hop}")
        if p["action"] != "remove":
            out.append(f"set routing-options static route {_route_net(p['destination'])} next-hop {p['next_hop']}")
        return out
    if kind == "mgmt_hardening" and p.get("action") in ("ssh_only", "secure_management", "disable_http"):
        return (["delete system services telnet", "set system services ssh"] if p["action"] != "disable_http" else []) + \
            (["delete system services web-management http"] if p["action"] != "ssh_only" else [])
    return []


def _dlink(device, iface, kind, p) -> list[str]:
    name = iface.name if iface else None
    if kind == "interface_status":
        return [f"config ports {name} state {'enable' if p['status'] == 'up' else 'disable'}"]
    if kind == "vlan_database":
        return [f"create vlan {p.get('name') or 'VLAN' + str(p['vlan_id'])} tag {p['vlan_id']}"] if p["action"] == "add" \
            else [f"delete vlan vlanid {p['vlan_id']}"]
    if kind == "access_vlan":
        return [f"config vlan vlanid {p['vlan_id']} add untagged {name}"]
    if kind == "static_route" and p["action"] != "remove":
        net = _route_net(p["destination"])
        return [f"create iproute default {p['next_hop']}"] if net.prefixlen == 0 else \
            [f"create iproute {net.network_address} {net.netmask} {p['next_hop']}"]
    if kind == "mgmt_hardening" and p.get("action") in ("ssh_only", "secure_management", "disable_http"):
        return (["disable telnet", "enable ssh"] if p["action"] != "disable_http" else []) + \
            (["disable web"] if p["action"] != "ssh_only" else [])
    return []


def _aoscx(device, iface, kind, p) -> list[str]:
    name = iface.name if iface else None
    if kind == "access_vlan":
        return [f"interface {name}", " no routing", f" vlan access {p['vlan_id']}", " exit"]
    if kind == "interface_status":
        return [f"interface {name}", " no shutdown" if p["status"] == "up" else " shutdown", " exit"]
    if kind == "ip_address":
        return [f"interface {name}", f" ip address {p['ip_address']}/{_prefix(p['subnet_mask'])}", " exit"]
    if kind == "vlan_database":
        return [f"vlan {p['vlan_id']}", *([f" name {p['name']}"] if p.get("name") else []), " exit"] if p["action"] == "add" \
            else [f"no vlan {p['vlan_id']}"]
    if kind == "static_route":
        out = []
        old = next((r for r in device.routes if r.id == p.get("route_id")), None)
        if old is not None:
            out.append(f"no ip route {_route_net(old.destination)} {old.next_hop}")
        if p["action"] != "remove":
            out.append(f"ip route {_route_net(p['destination'])} {p['next_hop']}")
        return out
    return []


# Driver ids whose configuration syntax is close enough to IOS for the IOS generator.
IOS_FAMILY = {"cisco-ios", "cisco-iosxe", "cisco-nxos", "ruijie-os", "tplink-jetstream", "edgeswitch"}
GENERATORS = {"huawei-vrp": _huawei, "mikrotik-routeros": _mikrotik, "edgeos": _vyos, "juniper-junos": _junos,
              "dlink-ds": _dlink, "aruba-cx": _aoscx}
GUI_ONLY = {"pfsense", "opnsense", "unifi", "fiberhome"}


def platform_of(device) -> str:
    """The configuration family used to generate commands for a device."""
    platform = getattr(device, "platform", None)
    if device.type in ("pc", "server", "printer", "camera", "phone", "unknown") and platform not in GENERATORS:
        return platform_for(device.vendor, getattr(device, "model", None), device.type)
    if platform in IOS_FAMILY:
        return "cisco-ios"
    if platform == "aruba-os-switch":
        return "arubaos-switch"
    if platform in GENERATORS or platform in GUI_ONLY or platform == "fortios":
        return platform
    return platform_for(device.vendor, getattr(device, "model", None), device.type)


def commands_for(model: NetworkModel, change: DetectedChange) -> list[str]:
    device = model.device(change.device_id)
    iface = device.interfaces.get(change.interface_id) if change.interface_id else None
    p, kind = change.parameters, change.change_type
    platform = platform_of(device)
    if platform in ("host", "cloud"):
        if kind == "default_gateway":
            setting = f"default gateway {p['gateway'] or '(none)'}"
        elif kind == "ip_address":
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{p['subnet_mask']}").prefixlen
            setting = f"{iface.name}: IP {p['ip_address']}/{prefix}"
        elif kind == "interface_status":
            setting = f"{iface.name}: status {p['status']}"
        else:
            setting = "apply this host setting manually"
        return [f"# Illustrative host setting on {device.name}: {setting}; never sent to a device."]
    if platform == "cisco-ios":
        # An imported configuration records each router's OSPF process ID; a second process must not be created.
        process = (model.observations.get("ospf_process") or {}).get(device.name) or OSPF_PROCESS
        lines = _cisco(device, iface, kind, p, process)
    elif platform == "arubaos-switch":
        lines = _aruba(iface, kind, p)
    elif platform == "fortios":
        lines = _fortios(device, iface, kind, p)
    elif platform in GENERATORS:
        lines = GENERATORS[platform](device, iface, kind, p)
    elif platform in GUI_ONLY:
        lines = []
        mark = "#"
        return [comment_line(HEADER, mark), f"{mark} {platform} is configured through its web GUI (or controller): "
                "apply this change there during the approved window, then record the deployment."]
    else:
        lines = []
    # IOS, ArubaOS and AOS-CX treat "!" as a comment; the other platforms' scripts use "#".
    mark = "!" if platform in ("cisco-ios", "arubaos-switch", "aruba-cx") else "#"
    return [comment_line(HEADER, mark),
            *(lines or [f"{mark} No {platform} command template for this change; apply manually"])]


def comment_line(text: str, mark: str) -> str:
    return mark + text[1:] if text.startswith("#") else f"{mark} {text}"
