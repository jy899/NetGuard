"""Fix Engine: proposes corrective changes for findings.

For each finding it generates one or more candidate fixes, expressed as
ordinary proposed changes (same change types as the Propose Change form).
The health service then verifies every candidate with the full analysis
pipeline, so a fix is only recommended when it resolves the issue without
breaking anything else. Nothing here touches the network.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, deque
from dataclasses import dataclass, field

from backend.services.forwarding import FlowAnalyzer, _expected_vlan, evaluate_acl
from backend.services.network_model import DeviceM, IfaceM, NetworkModel


@dataclass
class FixOption:
    label: str
    description: str
    device_id: int
    change_type: str
    parameters: dict
    interface_id: int | None = None
    verification: dict = field(default_factory=dict)
    # Set when the fix needs human review even if verification finds no problem: it is then
    # never "recommended" (the forwarding model cannot judge it, e.g. OSPF backbone design).
    caution: str | None = None

    @property
    def signature(self) -> tuple:
        import json
        return self.device_id, self.interface_id, self.change_type, json.dumps(self.parameters, sort_keys=True, default=str)


# ------------------------------------------------------------------ helpers
def _device(model: NetworkModel, name: str | None) -> DeviceM | None:
    return next((d for d in model.devices.values() if d.name == name), None)


def _iface(device: DeviceM | None, name: str | None) -> IfaceM | None:
    return device.iface_by_name(name) if device and name else None


def _split_label(label: str, device_name: str) -> str:
    """'R1 G0/0' -> 'G0/0' (device names may contain spaces)."""
    return label[len(device_name) + 1:] if label.startswith(device_name + " ") else label.split(" ", 1)[-1]


def _used_ips(model: NetworkModel) -> set[str]:
    return {i.ip for d in model.devices.values() for i in d.interfaces.values() if i.ip}


def _free_ip(model: NetworkModel, network: ipaddress.IPv4Network) -> str | None:
    used = _used_ips(model)
    for host in network.hosts():
        if str(host) not in used:
            return str(host)
    return None


def _free_sequence_below(device: DeviceM, target: int, acl_name: str | None = "*") -> int | None:
    used = {r.sequence for r in device.acl if acl_name == "*" or r.acl_name == acl_name}
    for seq in range(target - 1, 0, -1):
        if seq not in used:
            return seq
    return None


def _host_spec(ip: str | None) -> str:
    return f"{ip}/32" if ip else "any"


def _dominant_area(device: DeviceM) -> int:
    areas = Counter(i.ospf_area for i in device.interfaces.values() if i.ospf_area is not None)
    return areas.most_common(1)[0][0] if areas else 0


def _l3_neighbours(model: NetworkModel, device: DeviceM) -> list[tuple[DeviceM, IfaceM, IfaceM]]:
    result = []
    for link in model.links_of(device.id):
        peer_id, peer_if_id = link.other(device.id)
        peer, local = model.device(peer_id), model.iface(device.id, link.local_if(device.id))
        peer_if = model.iface(peer_id, peer_if_id)
        if peer.is_l3 and local and peer_if and local.ip and peer_if.ip:
            result.append((peer, peer_if, local))
    return result


def _backbone_caution(device: DeviceM, iface: IfaceM) -> str:
    return (f"Needs review: this takes {device.name} {iface.name} out of Area 0 and may split the OSPF "
            f"backbone (Area 0). On real routers a split backbone breaks routing between areas unless a "
            f"virtual link is added. NetGuard's routing model does not check this.")


# ---------------------------------------------------------------- per rule
def _fix_ospf001(model, analyzer, f):
    d = f.detail
    a, b = _device(model, d["a_dev"]), _device(model, d["b_dev"])
    ia, ib = _iface(a, d["a_if"]), _iface(b, d["b_if"])
    options = [
        FixOption(f"Set {a.name} {ia.name} to Area {d['b_area']}", f"Match {b.name} {ib.name} (Area {d['b_area']}).",
                  a.id, "ospf_area", {"area": d["b_area"]}, ia.id),
        FixOption(f"Set {b.name} {ib.name} to Area {d['a_area']}", f"Match {a.name} {ia.name} (Area {d['a_area']}).",
                  b.id, "ospf_area", {"area": d["a_area"]}, ib.id),
    ]
    # When one side is in the backbone (Area 0), only aligning the other side to Area 0 is safe to
    # recommend: moving the Area 0 side into another area can split the backbone.
    if d["a_area"] == 0:
        options[0].caution = _backbone_caution(a, ia)
    if d["b_area"] == 0:
        options[1].caution = _backbone_caution(b, ib)
    if d["a_area"] == 0 and d["b_area"] != 0:
        options.reverse()
    return options


def _fix_ospf002(model, analyzer, f):
    d = f.detail
    if "network" in d:  # destination network not advertised
        router = _device(model, d["router"])
        iface = _iface(router, d["interface"])
        area = _dominant_area(router)
        return [FixOption(f"Advertise {d['network']} on {router.name} {iface.name} in Area {area}",
                          "Add the network to OSPF so other routers learn a route to it.",
                          router.id, "ospf_network", {"action": "advertise", "area": area}, iface.id)]
    a, b = _device(model, d["a_dev"]), _device(model, d["b_dev"])
    ia, ib = _iface(a, d["a_if"]), _iface(b, d["b_if"])
    on, on_if, off, off_if = (a, ia, b, ib) if ia.ospf_area is not None else (b, ib, a, ia)
    return [
        FixOption(f"Enable OSPF on {off.name} {off_if.name} in Area {on_if.ospf_area}",
                  f"Match {on.name} {on_if.name} so the adjacency can form.",
                  off.id, "ospf_network", {"action": "advertise", "area": on_if.ospf_area}, off_if.id),
        FixOption(f"Remove OSPF from {on.name} {on_if.name}", "Make both sides consistent without OSPF.",
                  on.id, "ospf_network", {"action": "remove"}, on_if.id,
                  caution=_backbone_caution(on, on_if) if on_if.ospf_area == 0 else None),
    ]


def _fix_ip001(model, analyzer, f):
    d = f.detail
    if "host_cidr" in d:  # host vs its gateway interface
        host = model.device(f.device_ids[0])
        router = _device(model, d["router"])
        iface = _iface(router, d["interface"])
        nic = analyzer.attachment(host.id).nic
        options = []
        if host.gateway and nic and nic.network and ipaddress.IPv4Address(host.gateway) in nic.network:
            options.append(FixOption(
                f"Set {router.name} {iface.name} to {host.gateway}/{nic.network.prefixlen}",
                f"Restore the gateway address that {host.name} expects.",
                router.id, "ip_address", {"ip_address": host.gateway, "subnet_mask": nic.mask}, iface.id))
        free = _free_ip(model, iface.network) if iface.network else None
        if free and nic:
            options.append(FixOption(
                f"Re-address {host.name} {nic.name} to {free}/{iface.network.prefixlen}",
                f"Move the host into {router.name} {iface.name}'s subnet (its default gateway also needs updating).",
                host.id, "ip_address", {"ip_address": free, "subnet_mask": iface.mask}, nic.id))
        return options
    a, b = _device(model, d["a_dev"]), _device(model, d["b_dev"])
    ia, ib = _iface(a, _split_label(d["a"], a.name)), _iface(b, _split_label(d["b"], b.name))
    options = []
    for target, t_if, ref, r_if in ((b, ib, a, ia), (a, ia, b, ib)):
        free = _free_ip(model, r_if.network)
        if free:
            options.append(FixOption(
                f"Set {target.name} {t_if.name} to {free}/{r_if.network.prefixlen}",
                f"Put {target.name} in {ref.name} {r_if.name}'s subnet {r_if.network}.",
                target.id, "ip_address", {"ip_address": free, "subnet_mask": r_if.mask}, t_if.id))
    return options


def _fix_ip002(model, analyzer, f):
    host = model.device(f.device_ids[0])
    att = analyzer.attachment(host.id)
    if att.serving is None:
        return _reconnect_gateway(model, att, f.detail)  # else a subnet problem: fixed by IP001 / VLAN fixes
    router, iface = att.serving[0], att.serving[1]
    return [FixOption(f"Set {host.name} default gateway to {iface.ip}",
                      f"{router.name} {iface.name} ({iface.cidr}) is the router serving {host.name}'s segment.",
                      host.id, "default_gateway", {"gateway": iface.ip})]


def _reconnect_gateway(model, att, d) -> list[FixOption]:
    """The gateway interface exists but sits behind a switch port in another VLAN: move that port back."""
    if att.vlan is None or not d.get("owner"):
        return []
    owner = next(((dev, i) for dev, i in model.owner_of_ip(d["gateway"]) if dev.is_l3), None)
    if owner is None:
        return []
    router, iface = owner
    link = model.link_for_iface(router.id, iface)
    if link is None or iface.parent_name:
        return []  # sub-interfaces need a trunk, which is outside the prototype change types
    switch_id, port_id = link.other(router.id)
    switch, port = model.device(switch_id), model.iface(switch_id, port_id)
    if not switch.is_switch or port is None or (port.mode or ("access" if port.vlan else "trunk")) != "access":
        return []
    if port.vlan == att.vlan or att.vlan not in switch.vlans:
        return []
    return [FixOption(f"Set {switch.name} {port.name} to access VLAN {att.vlan}",
                      f"Put {router.name} {iface.name} back into VLAN {att.vlan}, the VLAN of {att.host.name}.",
                      switch.id, "access_vlan", {"vlan_id": att.vlan}, port.id)]


def _fix_ip003(model, analyzer, f):
    options = []
    for dev, iface in model.owner_of_ip(f.detail["ip"])[1:] + model.owner_of_ip(f.detail["ip"])[:1]:
        free = _free_ip(model, iface.network) if iface.network else None
        if free:
            options.append(FixOption(f"Change {dev.name} {iface.name} to {free}",
                                     f"Use a free address in {iface.network}.",
                                     dev.id, "ip_address", {"ip_address": free, "subnet_mask": iface.mask}, iface.id))
    return options[:2]


def _fix_vlan001(model, analyzer, f):
    d = f.detail
    switch = _device(model, d["switch"])
    port = _iface(switch, d["port"])
    return [FixOption(f"Set {switch.name} {port.name} to access VLAN {d['expected_vlan']}",
                      "Put the port back into the VLAN that matches the host's subnet.",
                      switch.id, "access_vlan", {"vlan_id": d["expected_vlan"]}, port.id)]


def _fix_vlan002(model, analyzer, f):
    d = f.detail
    switch = _device(model, d["switch"])
    port = _iface(switch, d["port"])
    options = [FixOption(f"Create VLAN {d['vlan']} on {switch.name}", "Define the VLAN the port is assigned to.",
                         switch.id, "vlan_database", {"action": "add", "vlan_id": d["vlan"]})]
    link = model.link_for_iface(switch.id, port) if port else None
    if link:
        host_id, _ = link.other(switch.id)
        nic = analyzer.attachment(host_id).nic
        expected = _expected_vlan(model, switch, nic.ip, exclude=d["vlan"]) if nic and nic.ip else None
        if expected is not None:
            options.insert(0, FixOption(
                f"Set {switch.name} {port.name} to access VLAN {expected}",
                f"VLAN {expected} matches the connected host's subnet.",
                switch.id, "access_vlan", {"vlan_id": expected}, port.id))
    return options


def _fix_route001(model, analyzer, f):
    d = f.detail
    device = _device(model, d["device"])
    route = next((r for r in device.routes if r.destination == d["destination"]), None)
    if route is None:
        return []
    probe = _probe_address(model, route.network)
    # Only neighbours that actually forward the traffic onwards (not back to this router) qualify.
    neighbours = [n for n in _l3_neighbours(model, device) if _forwards(analyzer, n[0], device, probe)]
    if route.network.prefixlen == 0:  # default route: prefer firewalls / non-OSPF exits
        neighbours.sort(key=lambda n: (n[0].type != "firewall", n[2].ospf_area is not None))
    options = [FixOption(f"Use next hop {peer_if.ip} ({peer.name})",
                         f"{peer.name} {peer_if.name} is directly connected to {device.name} {local.name}.",
                         device.id, "static_route",
                         {"action": "modify", "route_id": route.id, "destination": route.destination,
                          "next_hop": peer_if.ip})
               for peer, peer_if, local in neighbours[:3]]
    options.append(FixOption(f"Remove route {route.destination}", "Delete the invalid static route.",
                             device.id, "static_route", {"action": "remove", "route_id": route.id}))
    return options


def _probe_address(model: NetworkModel, network: ipaddress.IPv4Network) -> str:
    """A representative destination for a route: the internet endpoint for a default route."""
    if network.prefixlen == 0:
        external = next((i.ip for d in model.devices.values() if d.type == "internet"
                         for i in d.interfaces.values() if i.ip), None)
        return external or "8.8.8.8"
    return str(next(network.hosts(), network.network_address))


def _forwards(analyzer: FlowAnalyzer, neighbour: DeviceM, origin: DeviceM, probe: str) -> bool:
    decision = analyzer.router.lookup(neighbour, probe)
    if decision["kind"] == "connected":
        return True
    return decision["kind"] in ("static", "ospf") and decision["next"] != origin.id


def _fix_route002(model, analyzer, f):
    d = f.detail
    device = model.device(f.device_ids[0])
    owner = next(((dev, i) for dev in model.devices.values() if dev.is_l3 for i in dev.interfaces.values()
                  if i.network and i.ip and ipaddress.IPv4Address(d["destination"]) in i.network), None)
    if owner is None:
        return []
    target, target_if = owner
    # First hop towards the destination router over routed links (ignoring current routing).
    parents, queue = {device.id: None}, deque([device.id])
    while queue:
        node = queue.popleft()
        for peer, peer_if, _ in _l3_neighbours(model, model.device(node)):
            if peer.id not in parents:
                parents[peer.id] = (node, peer_if)
                queue.append(peer.id)
    if target.id not in parents or target.id == device.id:
        return []
    hop = target.id
    while parents[hop][0] != device.id:
        hop = parents[hop][0]
    next_hop = parents[hop][1].ip
    network = str(target_if.network)
    existing = next((r for r in device.routes if r.destination == network), None)
    params = {"action": "modify", "route_id": existing.id} if existing else {"action": "add"}
    return [FixOption(f"Add route {network} via {next_hop} on {device.name}",
                      f"Forward traffic for {network} towards {target.name}.",
                      device.id, "static_route", {**params, "destination": network, "next_hop": next_hop})]


def _intent_for(model, finding):
    key = finding.subject.split(":")[1]  # flow:intent-<id>[:<device id>]
    intent_id = int(key.split("-")[-1]) if key.startswith("intent-") else None
    return next((i for i in model.intents if i.id == intent_id), None)


def _fix_acl001(model, analyzer, f):
    d = f.detail
    device = _device(model, d["device"])
    intent = _intent_for(model, f)
    if device is None or intent is None:
        return []
    src = analyzer.attachment(intent.src).nic
    dst = analyzer.attachment(intent.dst).nic
    permit = {"action": "permit", "protocol": intent.protocol, "source": _host_spec(src.ip if src else None),
              "destination": _host_spec(dst.ip if dst else None), "port": intent.port}
    rule = next((r for r in device.acl if r.text() == d.get("rule")), None)
    acl = rule.acl_name if rule is not None else d.get("acl")
    permit["acl_name"] = acl
    options = []
    if rule is not None:
        seq = _free_sequence_below(device, rule.sequence, acl)
        if seq:
            options.append(FixOption(f"Permit {intent.name} before rule {rule.sequence} on {device.name}",
                                     "Adds a narrow permit for the required flow and keeps the deny rule.",
                                     device.id, "acl_add", {**permit, "sequence": seq}))
        options.append(FixOption(f"Remove rule {rule.sequence} on {device.name}", f"Delete '{rule.text()}'.",
                                 device.id, "acl_remove", {"rule_id": rule.id}))
    else:
        entries = device.sorted_acl(acl)
        last = max((r.sequence for r in entries), default=0)
        seq = min(last + 10, 9999)
        if seq in {r.sequence for r in entries}:
            return options
        if entries and all(r.action == "deny" for r in entries):
            # A deny-only ACL blocks everything else through its implicit deny: the usual intent
            # is "deny these, permit the rest".
            options.append(FixOption(f"Add 'permit ip any any' at the end of {device.name}'s ACL",
                                     "The ACL only has deny rules, so its implicit deny drops all other traffic.",
                                     device.id, "acl_add", {"sequence": seq, "action": "permit", "protocol": "ip",
                                                            "source": "any", "destination": "any", "port": None,
                                                            "acl_name": acl}))
        options.append(FixOption(f"Permit {intent.name} on {device.name}",
                                 "The flow is dropped by the implicit deny; add an explicit permit.",
                                 device.id, "acl_add", {**permit, "sequence": seq}))
    return options


def _fix_acl002(model, analyzer, f):
    d = f.detail
    device = _device(model, d.get("device"))
    if device is None:
        return []
    if f.subject.startswith("acl-shadow"):
        rule = next((r for r in device.acl if r.id == d.get("rule_id") or r.text() == d["rule"]), None)
        return [FixOption(f"Remove rule {rule.sequence} on {device.name}",
                          f"'{rule.text()}' overrides the deny rules after it.",
                          device.id, "acl_remove", {"rule_id": rule.id})] if rule else []
    intent = _intent_for(model, f)
    if intent is None:
        return []
    src = analyzer.attachment(intent.src).nic
    dst = analyzer.attachment(intent.dst).nic
    action, rule = None, None
    for acl_name in [None, *{r.acl_name for r in device.acl if r.acl_name}]:
        action, rule = evaluate_acl(device, src.ip if src else None, dst.ip if dst else None, intent.protocol,
                                    intent.port, acl_name)
        if rule is not None and action == "permit":
            break
    if rule is None:
        return []
    options = []
    seq = _free_sequence_below(device, rule.sequence, rule.acl_name)
    if seq:
        options.append(FixOption(f"Deny {intent.name} before rule {rule.sequence} on {device.name}",
                                 "Restores the required isolation with a narrow deny.",
                                 device.id, "acl_add",
                                 {"acl_name": rule.acl_name, "sequence": seq, "action": "deny", "protocol": intent.protocol,
                                  "source": _host_spec(src.ip if src else None),
                                  "destination": _host_spec(dst.ip if dst else None), "port": intent.port}))
    options.append(FixOption(f"Remove rule {rule.sequence} on {device.name}", f"Delete '{rule.text()}'.",
                             device.id, "acl_remove", {"rule_id": rule.id}))
    return options


def _fix_link001(model, analyzer, f):
    d = f.detail
    device = _device(model, d["device"])
    iface = _iface(device, d["interface"])
    return [FixOption(f"Bring {device.name} {iface.name} up", "Re-enable the interface (no shutdown).",
                      device.id, "interface_status", {"status": "up"}, iface.id)]


GENERATORS = {
    "OSPF001": _fix_ospf001, "OSPF002": _fix_ospf002, "IP001": _fix_ip001, "IP002": _fix_ip002,
    "IP003": _fix_ip003, "VLAN001": _fix_vlan001, "VLAN002": _fix_vlan002, "ROUTE001": _fix_route001,
    "ROUTE002": _fix_route002, "ACL001": _fix_acl001, "ACL002": _fix_acl002, "LINK001": _fix_link001,
}


def _fix_loop(model, analyzer, finding):
    """A forwarding cycle: make one switch the spanning-tree root so a redundant port blocks (preferred), or shut
    one redundant link as a temporary measure."""
    if not finding.link_ids:
        return []
    vlan = int(finding.subject.split(":")[1]) if finding.subject.startswith("vlan:") else None
    cycle = [model.device(d) for d in finding.device_ids if model.device(d).is_switch]
    options = []
    if vlan is not None and cycle:
        # The best root: the switch with the most trunk links (the core), then the lowest name.
        def trunks(sw):
            return sum(1 for l in model.links_of(sw.id) if model.device(l.other(sw.id)[0]).is_switch)
        root = sorted(cycle, key=lambda sw: (-trunks(sw), sw.name))[0]
        if vlan in root.vlans:
            options.append(FixOption(f"Make {root.name} the spanning-tree root for VLAN {vlan}",
                                     "Rapid PVST+ with priority 4096 on the core switch; one redundant port then blocks.",
                                     root.id, "stp_root", {"vlan": vlan, "priority": 4096}))
    link = model.links[finding.link_ids[-1]]
    iface = model.iface(link.a_dev, link.a_if)
    if iface is not None:
        options.append(FixOption(f"Isolate redundant link at {model.device(link.a_dev).name} {iface.name}",
                                 "Shut one redundant edge as a temporary measure until spanning tree is configured.",
                                 link.a_dev, "interface_status", {"status": "admin-down"}, iface.id,
                                 caution="Shutting a redundant link removes resilience; prefer the spanning-tree fix."))
    return options


def _ends(model, finding):
    link = model.links.get(finding.link_ids[0]) if finding.link_ids else None
    if link is None:
        return None
    return (link, model.device(link.a_dev), model.iface(link.a_dev, link.a_if),
            model.device(link.b_dev), model.iface(link.b_dev, link.b_if))


def _fix_vlan003(model, analyzer, f):
    found = _ends(model, f)
    if found is None:
        return []
    _, a, ia, b, ib = found
    options = []
    for target, t_if, ref, r_if in ((b, ib, a, ia), (a, ia, b, ib)):
        params = {}
        if r_if.native_vlan is not None and t_if.native_vlan is not None and r_if.native_vlan != t_if.native_vlan:
            params["native_vlan"] = r_if.native_vlan
        if r_if.allowed_vlans is not None and t_if.allowed_vlans is not None and set(r_if.allowed_vlans) != set(t_if.allowed_vlans):
            params["allowed_vlans"] = sorted(r_if.allowed_vlans)
        if params:
            options.append(FixOption(f"Match {target.name} {t_if.name} to {ref.name} {r_if.name}",
                                     "Use the same native VLAN and allowed VLAN list at both trunk ends.",
                                     target.id, "trunk_settings", params, t_if.id))
    return options


def _fix_ospf003(model, analyzer, f):
    d = f.detail
    a, b = _device(model, d["a_dev"]), _device(model, d["b_dev"])
    ia, ib = _iface(a, d["a_if"]), _iface(b, d["b_if"])
    options = []
    for target, t_if, ref, r_if, side in ((b, ib, a, ia, "a"), (a, ia, b, ib, "b")):
        if d["kind"] == "timer_mismatch":
            params = {"ospf_hello": d[f"{side}_hello"], "ospf_dead": d[f"{side}_dead"]}
            label = f"Set {target.name} {t_if.name} OSPF hello/dead to {params['ospf_hello']}/{params['ospf_dead']} s"
        else:
            if not d.get(f"{side}_mtu"):
                continue
            params = {"mtu": d[f"{side}_mtu"]}
            label = f"Set {target.name} {t_if.name} IP MTU to {params['mtu']}"
        options.append(FixOption(label, f"Match {ref.name} {r_if.name} so the OSPF neighbours form an adjacency.",
                                 target.id, "interface_settings", params, t_if.id))
    return options


def _fix_acl003(model, analyzer, f):
    d = f.detail
    device = _device(model, d.get("device"))
    rule = next((r for r in device.acl if r.id == d.get("rule_id")), None) if device else None
    if rule is None:
        return []
    return [FixOption(f"Remove unreachable rule {rule.sequence} on {device.name}",
                      f"'{rule.text()}' can never match because '{d['earlier']}' comes first; removing it changes nothing "
                      "in what the list permits or denies. If the entry was meant to take effect, move it above that rule.",
                      device.id, "acl_remove", {"rule_id": rule.id})]


def _fix_acl004(model, analyzer, f):
    d = f.detail
    device = _device(model, d.get("device"))
    if device is None:
        return []
    return [
        FixOption(f"Remove the reference to {d['acl']} on {device.name} {d['where']}",
                  "The list does not exist, so the reference filters nothing; removing it makes the configuration honest.",
                  device.id, "acl_reference", {"action": "remove", "acl": d["acl"], "where": d["where"]}),
        FixOption(f"Define {d['acl']} on {device.name} with 'permit ip any any'",
                  "Keeps the reference so the list can be tightened later.",
                  device.id, "acl_reference", {"action": "define_permit_all", "acl": d["acl"], "where": d["where"]},
                  caution="An all-permitting list is a placeholder: add the intended entries before relying on it."),
    ]


def _free_ports(model, device, media: str | None) -> list[str]:
    from backend.services.interface_naming import _ports, canonical_name

    catalogue = _ports((device.model or "").lower()) or {}
    cabled = {model.iface(device.id, l.local_if(device.id)).name for l in model.links_of(device.id)
              if model.iface(device.id, l.local_if(device.id))}
    return [name for name, (port_media, _, _) in catalogue.items()
            if (media is None or port_media == media) and canonical_name(name, "cisco-ios") not in cabled
            and name not in cabled]


def _fix_phy001(model, analyzer, f):
    from backend.services.physical_layer import link_ports
    link = model.links.get(f.link_ids[0]) if f.link_ids else None
    if link is None:
        return []
    (a, ia, info_a), (b, ib, info_b) = link_ports(model, link)
    options = [FixOption(f"Fit matching media between {a.name} {ia.name} and {b.name} {ib.name}",
                         "Replace the cable or fit transceivers so both ends use the same media (work order).",
                         a.id, "physical_remediation", {"action": "replace_media"}, ia.id)]
    for dev, iface, peer_info in ((b, ib, info_a), (a, ia, info_b)):
        free = _free_ports(model, dev, peer_info["media"])
        if free:
            options.append(FixOption(f"Move the cable to {dev.name} {free[0]} ({peer_info['media']})",
                                     f"{free[0]} uses the same media as the other end; its configuration is copied from {iface.name}.",
                                     dev.id, "physical_remediation", {"action": "move_port", "port": free[0]}, iface.id))
    return options


def _fix_phy002(model, analyzer, f):
    from backend.services.physical_layer import link_ports
    link = model.links.get(f.link_ids[0]) if f.link_ids else None
    if link is None:
        return []
    options = []
    for (dev, iface, info), (_, _, peer_info) in (tuple(link_ports(model, link)), tuple(reversed(link_ports(model, link)))):
        if iface is None or not info or info["exists"] is not False:
            continue
        free = _free_ports(model, dev, (peer_info or {}).get("media"))
        if free:
            options.append(FixOption(f"Move the cable to {dev.name} {free[0]}",
                                     f"{iface.name} does not exist on {dev.model}; {free[0]} does and is free.",
                                     dev.id, "physical_remediation", {"action": "move_port", "port": free[0]}, iface.id))
    return options


def _fix_phy003(model, analyzer, f):
    found = _ends(model, f)
    if found is None:
        return []
    _, a, ia, b, ib = found
    return [FixOption(f"Set {t.name} {ti.name} to {ri.speed_mbps} Mb/s", f"Match {r.name} {ri.name}.",
                      t.id, "interface_settings", {"speed": ri.speed_mbps}, ti.id)
            for t, ti, r, ri in ((b, ib, a, ia), (a, ia, b, ib)) if ri.speed_mbps]


def _fix_phy004(model, analyzer, f):
    found = _ends(model, f)
    if found is None:
        return []
    _, a, ia, b, ib = found
    options = []
    for t, ti, r, ri in ((a, ia, b, ib), (b, ib, a, ia)):
        if ti.duplex == "half" and ri.duplex == "full":
            options.append(FixOption(f"Set {t.name} {ti.name} to full duplex", f"Match {r.name} {ri.name} (full duplex).",
                                     t.id, "interface_settings", {"duplex": "full"}, ti.id))
    return options


def _fix_phy005(model, analyzer, f):
    found = _ends(model, f)
    if found is None:
        return []
    link, a, ia, b, ib = found
    dev, iface = (a, ia) if (ia and (ia.error_count or 0) >= (ib.error_count or 0 if ib else 0)) else (b, ib)
    return [FixOption(f"Replace the cable on {dev.name} {iface.name} and clear its counters",
                      "Errors usually come from a damaged cable, a bad transceiver or a duplex problem (work order).",
                      dev.id, "physical_remediation", {"action": "clear_errors"}, iface.id)]


GENERATORS.update({"L2001": _fix_loop, "VLAN003": _fix_vlan003, "OSPF003": _fix_ospf003, "ACL003": _fix_acl003,
                   "ACL004": _fix_acl004, "PHY001": _fix_phy001, "PHY002": _fix_phy002, "PHY003": _fix_phy003,
                   "PHY004": _fix_phy004, "PHY005": _fix_phy005})


# ------------------------------------------------------------------ advisories (security hygiene pack)
def _management_subnet(model, device) -> str | None:
    ip = device.management_ip or next((i.ip for i in device.interfaces.values() if i.ip), None)
    owner = next((i for i in device.interfaces.values() if i.ip == ip and i.network), None)
    if owner is not None:
        return str(owner.network)
    return f"{ip}/32" if ip else None


def advisory_options(model, analyzer, advisory: dict) -> list[FixOption]:
    rule = advisory["rule_id"]
    devices = [model.devices[d] for d in advisory.get("device_ids", []) if d in model.devices]
    if not devices:
        return []
    device = devices[0]
    facts = device.facts or {}
    if rule == "SEC002" and facts:
        return [FixOption(f"Allow only SSH and disable HTTP on {device.name}",
                          "transport input ssh on every VTY line, ip ssh version 2 and no ip http server.",
                          device.id, "mgmt_hardening", {"action": "secure_management"})]
    if rule == "SEC003":
        return [FixOption(f"Remove the SNMP community strings on {device.name}",
                          "Use SNMPv3 (authPriv) instead; the commands need the community strings, which NetGuard never stores.",
                          device.id, "mgmt_hardening", {"action": "remove_snmp_communities"},
                          caution="Configure an SNMPv3 user first so monitoring keeps working.")]
    if rule == "SEC004":
        return [FixOption(f"Encrypt the passwords on {device.name}",
                          "service password-encryption and type 9 (scrypt) secrets; you choose the new secrets.",
                          device.id, "mgmt_hardening", {"action": "secure_passwords"},
                          caution="Agree the new secrets before the change window.")]
    if rule == "SEC005":
        subnet = _management_subnet(model, device)
        if subnet:
            return [FixOption(f"Restrict {device.name} VTY access to {subnet}",
                              "A standard access list applied with access-class on every VTY line.",
                              device.id, "mgmt_hardening", {"action": "restrict_vty", "permit": subnet, "acl": "NETGUARD-MGMT"},
                              caution=f"Confirm that NetGuard and the administrators reach {device.name} from {subnet}.")]
    if rule == "SEC006" and device.is_switch:
        linked = {l.local_if(device.id) for l in model.links_of(device.id)}
        unused = sorted(i.name for i in device.interfaces.values()
                        if (i.mode == "access" or (i.mode is None and i.vlan)) and i.status == "down" and i.id not in linked)
        if unused:
            return [FixOption(f"Shut down {len(unused)} unused port(s) on {device.name}",
                              ", ".join(unused[:12]) + (" ..." if len(unused) > 12 else ""),
                              device.id, "mgmt_hardening", {"action": "shutdown_unused", "interfaces": unused[:48]})]
    if rule == "SEC001":
        return _isolation_options(model, analyzer, devices)
    return []


def _isolation_options(model, analyzer, devices) -> list[FixOption]:
    discovery = model.observations.get("discovery", {})
    options = []
    for dev in devices:
        role = str((discovery.get(str(dev.id)) or {}).get("role", "")).lower()
        if not any(w in role for w in ("guest", "camera", "phone", "unknown host", "access point")):
            continue
        att = analyzer.attachment(dev.id)
        if att.switch is None or att.port is None:
            continue
        vlan = next(v for v in range(900, 4095) if v not in att.switch.vlans)
        options.append(FixOption(f"Move {dev.name} to isolated VLAN {vlan} on {att.switch.name} {att.port.name}",
                                 "Separates the untrusted endpoint from the sensitive assets at Layer 2.",
                                 att.switch.id, "isolate_endpoint", {"vlan_id": vlan, "name": "ISOLATED"}, att.port.id,
                                 caution=f"VLAN {vlan} needs its own gateway (and DHCP) if {dev.name} still needs "
                                         "internet access; add it before the change."))
    return options[:2]


def options_for(model: NetworkModel, analyzer: FlowAnalyzer, finding) -> list[FixOption]:
    generator = GENERATORS.get(finding.rule_id)
    if generator is None:
        return []
    try:
        options = generator(model, analyzer, finding)
    except (AttributeError, KeyError, TypeError, ValueError, StopIteration):
        return []  # incomplete data: no automatic fix, the explanation still applies
    unique, seen = [], set()
    for option in options:
        if option.signature not in seen:
            seen.add(option.signature)
            unique.append(option)
    return unique
