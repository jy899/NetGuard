"""Topology / dependency analysis: simplified L2/L3 forwarding over a NetworkModel.

Brief 7.1 places this step between the Validation Engine and the Impact
Engine. It answers "can traffic from A reach B, along which path, and if not,
where and why does it stop?" using deterministic prototype semantics:

* Layer 2: a host attaches to a switch access port (VLAN) or directly to a
  routed interface. VLAN segments extend over switch-to-switch trunks; a
  router serves a VLAN through a routed port on an access port or through an
  802.1Q sub-interface (G0/1.10) behind a trunk.
* Layer 3: hop-by-hop longest-prefix match over connected networks, static
  routes and OSPF (on equal prefix: connected, then static, then OSPF). A
  static route with an unresolvable next hop is not installed, so the lookup
  falls back to the next best route. OSPF routes are learned only
  across adjacencies that are up (both sides in OSPF, same area, same subnet,
  interfaces up) and only for networks of interfaces placed in OSPF. An OSPF
  router with a valid static default route advertises it into OSPF (as if
  `default-information originate` were configured), so the other OSPF routers
  learn a default route towards it.
* Multilayer switches (`ip routing` with SVIs or routed ports) route like
  routers; an SVI serves its VLAN everywhere the VLAN is carried.
* Routers (and SVIs) that share a VLAN through Layer-2 switches are L3
  neighbours across those switches (transit adjacencies): static next hops
  and OSPF adjacencies are resolved through the switches, and a shut port or
  pruned VLAN on the way breaks the adjacency.
* ACL: access lists filter per interface and direction. At every routed hop
  the inbound list of the ingress interface (`ip access-group NAME in`) and
  the outbound list of the egress interface (`... out`) are evaluated, first
  match, implicit deny. A device's unnamed rule list (hand-built models)
  filters all traffic routed through it. A referenced but undefined list
  filters nothing (as on IOS).
* The return path is checked for routing (not ACL), so a broken reverse
  route or host gateway is also detected.

Known simplifications: flat OSPF areas and a stateless ACL check.
"""
from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass, field

from backend.services.network_model import DeviceM, IfaceM, LinkM, NetworkModel
from backend.services.physical_layer import media_problem

ENDPOINT_TYPES = ("pc", "server", "internet")


# --------------------------------------------------------------- helpers
def ip_in(ip: str | None, net: ipaddress.IPv4Network | None) -> bool:
    return bool(ip and net and ipaddress.IPv4Address(ip) in net)


def switchport_mode(iface: IfaceM) -> str:
    """access | trunk | routed (a switch port with an address and no switchport mode: `no switchport`)."""
    if iface.mode:
        return iface.mode
    if iface.vlan:
        return "access"
    return "routed" if iface.ip else "trunk"


def acl_matches_address(spec: str, ip: str | None) -> bool:
    if spec == "any":
        return True
    return ip_in(ip, ipaddress.IPv4Network(spec, strict=False))


def acl_rule_matches(rule, src_ip: str | None, dst_ip: str | None, protocol: str, port: int | None) -> bool:
    if rule.protocol != "ip" and rule.protocol != protocol:
        return False
    if rule.port is not None and rule.port != port:
        return False
    return acl_matches_address(rule.source, src_ip) and acl_matches_address(rule.destination, dst_ip)


def evaluate_acl(device: DeviceM, src_ip, dst_ip, protocol, port, acl_name: str | None = None):
    """Return (action, rule_or_None) for one access list (None: the unnamed device-wide list).

    A list without entries (not defined, or nothing configured) filters nothing."""
    rules = device.sorted_acl(acl_name)
    if not rules:
        return "permit", None
    for rule in rules:
        if acl_rule_matches(rule, src_ip, dst_ip, protocol, port):
            return rule.action, rule
    return "deny", None  # implicit deny


def evaluate_hop(device: DeviceM, ingress: IfaceM | None, egress: IfaceM | None, src_ip, dst_ip, protocol, port):
    """Filtering at one routed hop: the unnamed list, then the ingress `in` list, then the egress `out` list.

    Returns (action, rule_or_None, where) where `where` names the list and interface that decided."""
    checks = [(None, None, "device rule list")]
    if ingress is not None and ingress.acl_in:
        checks.append((ingress.acl_in, ingress, f"{ingress.acl_in} in on {ingress.name}"))
    if egress is not None and egress.acl_out:
        checks.append((egress.acl_out, egress, f"{egress.acl_out} out on {egress.name}"))
    for name, _, where in checks:
        if name is None and not device.sorted_acl(None):
            continue
        action, rule = evaluate_acl(device, src_ip, dst_ip, protocol, port, name)
        if action == "deny":
            return "deny", rule, where
    last = None
    for name, _, where in reversed(checks):
        action, rule = evaluate_acl(device, src_ip, dst_ip, protocol, port, name)
        if rule is not None:
            last = (action, rule, where)
            break
    return last or ("permit", None, None)


# ------------------------------------------------------------ attachment
@dataclass
class Problem:
    code: str
    detail: dict = field(default_factory=dict)


@dataclass
class Attachment:
    host: DeviceM
    nic: IfaceM | None = None
    switch: DeviceM | None = None
    port: IfaceM | None = None
    vlan: int | None = None
    segment: tuple | None = None
    candidates: list = field(default_factory=list)  # [(DeviceM, IfaceM, path_ids, link_ids)]
    serving: tuple | None = None  # candidate whose subnet contains the host IP
    gateway: tuple | None = None  # candidate matching the configured default gateway
    problems: list[Problem] = field(default_factory=list)
    fabric_parent: dict = field(default_factory=dict)  # switch id -> (prev switch id, link id)

    def has(self, *codes: str) -> bool:
        return any(p.code in codes for p in self.problems)

    def gateway_problem(self) -> Problem | None:
        """A fault on the path to the gateway only: routed traffic fails, same-VLAN traffic does not."""
        return next((p for p in self.problems if p.detail.get("scope") == "gateway"), None)

    @property
    def l2_ok(self) -> bool:
        return not any(p.code in ("not_connected", "incomplete", "no_ip", "interface_down", "vlan_unavailable", "media_mismatch")
                       and p.detail.get("scope") != "gateway" for p in self.problems)

    @property
    def l3_ok(self) -> bool:
        return self.l2_ok and not self.has("vlan_mismatch", "subnet_mismatch", "gateway_mismatch")

    def switch_path(self, target_switch: int) -> tuple[list[int], list[int]]:
        """Switch ids and link ids from the access switch to target_switch inside the fabric."""
        devices, links = [target_switch], []
        node = target_switch
        while node in self.fabric_parent and self.fabric_parent[node] is not None:
            prev, link_id = self.fabric_parent[node]
            devices.append(prev)
            links.append(link_id)
            node = prev
        devices.reverse()
        links.reverse()
        return devices, links


def _vlan_fabric(model: NetworkModel, start: DeviceM, vlan: int, require_up: bool = True) -> dict:
    """BFS over switch trunks that carry `vlan`. Returns {switch_id: (parent, link_id) | None}.

    require_up=False ignores interface status (used to find which shut link cut a segment).
    """
    parents = {start.id: None}
    queue = deque([start.id])
    while queue:
        sid = queue.popleft()
        switch = model.device(sid)
        for link in model.links_of(sid):
            if require_up and media_problem(model, link):
                continue
            peer_id, peer_if_id = link.other(sid)
            peer = model.device(peer_id)
            local_if = model.iface(sid, link.local_if(sid))
            peer_if = model.iface(peer_id, peer_if_id)
            if not (peer.is_switch and local_if and peer_if and (not require_up or (local_if.up and peer_if.up))):
                continue
            if switchport_mode(local_if) != "trunk" or switchport_mode(peer_if) != "trunk":
                continue
            if require_up and (local_if.stp_state in ("blocking", "discarding", "disabled")
                               or peer_if.stp_state in ("blocking", "discarding", "disabled")):
                continue
            if any(i.allowed_vlans is not None and vlan not in i.allowed_vlans for i in (local_if, peer_if)):
                continue
            if vlan not in peer.vlans or peer_id in parents or vlan not in switch.vlans:
                continue
            parents[peer_id] = (sid, link.id)
            queue.append(peer_id)
    return parents


def _vlan_gateways(model: NetworkModel, fabric: dict, vlan: int, require_up: bool = True) -> list:
    """Router/firewall interfaces and multilayer-switch SVIs serving `vlan` anywhere in the fabric.

    Each entry is (device, interface, switch id, link id); the link id is None for an SVI of switch `sid` itself."""
    found = []
    for sid in fabric:
        own = model.device(sid).svi(vlan)
        if own is not None and (not require_up or own.up):
            found.append((model.device(sid), own, sid, None))
        for link in model.links_of(sid):
            if require_up and media_problem(model, link):
                continue
            peer_id, peer_if_id = link.other(sid)
            peer = model.device(peer_id)
            local_if = model.iface(sid, link.local_if(sid))
            peer_if = model.iface(peer_id, peer_if_id)
            if not (peer.is_router and local_if and peer_if and (not require_up or (local_if.up and peer_if.up))):
                continue
            if peer.is_switch and switchport_mode(peer_if) != "routed":
                continue  # another switch in the fabric: its SVIs are found as `own`
            if switchport_mode(local_if) == "trunk":
                for sub in peer.subinterfaces(peer_if):
                    if sub.vlan == vlan and sub.ip and (not require_up or peer.effectively_up(sub)):
                        found.append((peer, sub, sid, link.id))
            elif local_if.vlan == vlan and peer_if.ip:
                found.append((peer, peer_if, sid, link.id))
    return found


def attach(model: NetworkModel, device_id: int) -> Attachment:
    host = model.device(device_id)
    att = Attachment(host=host)
    linked = [(i, model.link_for_iface(device_id, i)) for i in host.interfaces.values()]
    linked = [(i, l) for i, l in linked if l is not None]
    if not linked:
        att.problems.append(Problem("not_connected"))
        return att
    nic, link = next(((i, l) for i, l in linked if i.ip), linked[0])
    att.nic = nic
    if not nic.ip or not nic.mask:
        att.problems.append(Problem("no_ip"))
        return att
    peer_id, peer_if_id = link.other(device_id)
    peer, peer_if = model.device(peer_id), model.iface(peer_id, peer_if_id)
    if peer_if is None:
        att.problems.append(Problem("incomplete", {"link_id": link.id}))
        return att
    if problem := media_problem(model, link):
        att.problems.append(Problem("media_mismatch", problem))
        return att
    if not nic.up or not peer_if.up:
        down = nic if not nic.up else peer_if
        att.problems.append(Problem("interface_down", {
            "device": host.name if down is nic else peer.name, "interface": down.name, "link_id": link.id,
        }))
        return att

    if peer.is_l3 or (peer.l3_switch and switchport_mode(peer_if) == "routed"):
        att.segment = ("routed", peer.id, peer_if.id)
        if peer_if.ip:
            att.candidates = [(peer, peer_if, [host.id, peer.id], [link.id])]
    elif peer.is_switch:
        att.switch, att.port = peer, peer_if
        if switchport_mode(peer_if) != "access" or not peer_if.vlan:
            att.problems.append(Problem("incomplete", {"link_id": link.id}))
            return att
        att.vlan = peer_if.vlan
        if att.vlan not in peer.vlans:
            att.problems.append(Problem("vlan_unavailable", {
                "switch": peer.name, "port": peer_if.name, "vlan": att.vlan,
                "defined": sorted(peer.vlans), "link_id": link.id,
            }))
            return att
        fabric = _vlan_fabric(model, peer, att.vlan)
        att.fabric_parent = fabric
        att.segment = ("vlan", min(fabric), att.vlan)
        for router, iface, sid, router_link in _vlan_gateways(model, fabric, att.vlan):
            switches, sw_links = att.switch_path(sid)
            if router_link is None:  # the SVI of a switch on the path
                att.candidates.append((router, iface, [host.id, *switches], [link.id, *sw_links]))
            else:
                att.candidates.append((router, iface, [host.id, *switches, router.id], [link.id, *sw_links, router_link]))
    else:
        att.problems.append(Problem("incomplete", {"link_id": link.id}))
        return att

    host_net = nic.network
    att.serving = next((c for c in att.candidates if ip_in(nic.ip, c[1].network)), None)
    if att.serving is None and peer.is_switch:
        expected = _expected_vlan(model, peer, nic.ip, exclude=att.vlan)
        if expected is not None:
            att.problems.append(Problem("vlan_mismatch", {
                "switch": peer.name, "port": peer_if.name, "vlan": att.vlan, "expected_vlan": expected,
                "host_cidr": nic.cidr, "link_id": link.id,
            }))
    if att.serving is None and att.candidates and not att.has("vlan_mismatch"):
        router, iface = att.candidates[0][0], att.candidates[0][1]
        att.problems.append(Problem("subnet_mismatch", {
            "host_cidr": nic.cidr, "router": router.name, "interface": iface.name, "router_cidr": iface.cidr,
        }))

    if host.gateway and not att.has("vlan_mismatch"):
        if not ip_in(host.gateway, host_net):
            att.problems.append(Problem("gateway_mismatch", {
                "gateway": host.gateway, "host_cidr": nic.cidr, "reason": "outside_subnet",
            }))
        else:
            att.gateway = next((c for c in att.candidates if c[1].ip == host.gateway), None)
            if att.gateway is None:
                down = _down_gateway(model, host.gateway, nic) or _cut_segment(model, att, host.gateway)
                if down is not None:
                    # The gateway exists but its interface (or parent) is shut: the root cause is the interface.
                    att.problems.insert(0, Problem("media_mismatch" if down.get("reason") else "interface_down",
                                                   {**down, "scope": "gateway"}))
                    return att
                serving = att.serving or (att.candidates[0] if att.candidates else None)
                owner = next(((d, i) for d, i in model.owner_of_ip(host.gateway) if d.is_router), None)
                att.problems.append(Problem("gateway_mismatch", {
                    "gateway": host.gateway, "host_cidr": nic.cidr, "reason": "not_present",
                    "router": serving[0].name if serving else None,
                    "interface": serving[1].name if serving else None,
                    "router_cidr": serving[1].cidr if serving else None,
                    "owner": f"{owner[0].name} {owner[1].name}" if owner else None, "vlan": att.vlan,
                }))
    elif not host.is_host and att.serving is not None:
        att.gateway = att.serving  # internet / external endpoints forward to their upstream router
    return att


def _cut_segment(model: NetworkModel, att: Attachment, gateway: str) -> dict | None:
    """The gateway would be reachable in the VLAN if a shut link were up: return that link."""
    if att.switch is None or att.vlan is None:
        return None
    fabric = _vlan_fabric(model, att.switch, att.vlan, require_up=False)
    for router, iface, sid, router_link in _vlan_gateways(model, fabric, att.vlan, require_up=False):
        if iface.ip != gateway:
            continue
        node, links = sid, [router_link] if router_link is not None else []
        while fabric.get(node) is not None:
            node, link_id = fabric[node]
            links.append(link_id)
        for link_id in links:
            link = model.links[link_id]
            if problem := media_problem(model, link):
                return {**problem, "gateway": gateway}
            for dev_id, if_id in ((link.a_dev, link.a_if), (link.b_dev, link.b_if)):
                iface_down = model.iface(dev_id, if_id)
                if iface_down is not None and not iface_down.up:
                    return {"device": model.device(dev_id).name, "interface": iface_down.name, "link_id": link_id,
                            "gateway": gateway}
    return None


def _down_gateway(model: NetworkModel, gateway: str, nic: IfaceM) -> dict | None:
    """Gateway IP owned by a router interface in the host's subnet that is shut (or whose parent is)."""
    for device, iface in model.owner_of_ip(gateway):
        if not device.is_router or not ip_in(nic.ip, iface.network) or device.effectively_up(iface):
            continue
        parent = device.iface_by_name(iface.parent_name) if iface.parent_name else None
        down = iface if not iface.up else parent
        link = model.link_for_iface(device.id, iface)
        return {"device": device.name, "interface": down.name, "link_id": link.id if link else None,
                "gateway": gateway}
    return None


def _expected_vlan(model: NetworkModel, switch: DeviceM, ip: str, exclude: int | None) -> int | None:
    """Another VLAN on this switch whose gateway subnet contains the host IP."""
    for vlan in sorted(switch.vlans):
        if vlan == exclude:
            continue
        fabric = _vlan_fabric(model, switch, vlan)
        if any(ip_in(ip, iface.network) for _, iface, _, _ in _vlan_gateways(model, fabric, vlan)):
            return vlan
    return None


# ------------------------------------------------- L3 adjacency across switches
TRANSIT = "l2-transit"


def _l2_domains(model: NetworkModel, dev: DeviceM, iface: IfaceM) -> list[tuple[DeviceM, int, int | None]]:
    """Where an L3 interface enters a switched VLAN: [(first switch, VLAN, link id or None for an SVI)]."""
    if dev.l3_switch and iface.name.lower().startswith("vlan"):
        digits = "".join(ch for ch in iface.name if ch.isdigit())
        vlan = iface.vlan or (int(digits) if digits else None)
        return [(dev, vlan, None)] if vlan else []
    link = model.link_for_iface(dev.id, iface)
    if link is None:
        return []
    peer_id, peer_if_id = link.other(dev.id)
    peer, peer_if = model.device(peer_id), model.iface(peer_id, peer_if_id)
    if not peer.is_switch or peer_if is None:
        return []
    mode = switchport_mode(peer_if)
    if iface.parent_name:
        return [(peer, iface.vlan, link.id)] if mode == "trunk" and iface.vlan else []
    if mode == "access" and peer_if.vlan:
        return [(peer, peer_if.vlan, link.id)]
    return []


def _fabric_path(fabric: dict, target: int) -> tuple[list[int], list[int]]:
    devices, links, node = [target], [], target
    while fabric.get(node) is not None:
        prev, link_id = fabric[node]
        devices.append(prev)
        links.append(link_id)
        node = prev
    return list(reversed(devices)), list(reversed(links))


def transit_links(model: NetworkModel) -> dict[int, LinkM]:
    """Virtual L3 adjacencies between router interfaces (and SVIs) that share a VLAN through switches.

    Each carries the physical links and switches it uses ("via", "switches") and whether that Layer-2 path is
    intact now ("state"/"detail"), so routing across switches follows, and breaks with, the switched path."""
    found: dict[int, LinkM] = {}
    for dev in model.devices.values():
        if not dev.is_router:
            continue
        for iface in dev.interfaces.values():
            if not iface.ip:
                continue
            for start, vlan, first_link in _l2_domains(model, dev, iface):
                fabric = _vlan_fabric(model, start, vlan, require_up=False)
                fabric_up = _vlan_fabric(model, start, vlan, require_up=True)
                serving_up = {(p.id, i.id) for p, i, _, _ in _vlan_gateways(model, fabric_up, vlan, True)}
                for peer, peer_if, sid, last_link in _vlan_gateways(model, fabric, vlan, require_up=False):
                    if (peer.id, peer_if.id) == (dev.id, iface.id) or not peer_if.ip:
                        continue
                    low, high = sorted([iface.id, peer_if.id])
                    link_id = -(low * 10_000_000 + high)
                    if link_id in found:
                        continue
                    switches, switch_links = _fabric_path(fabric, sid)
                    via = [x for x in [first_link, *switch_links, last_link] if x is not None]
                    state, detail = "ok", {}
                    first_ok = first_link is None or not _physical_problem(model, model.links[first_link])
                    if (peer.id, peer_if.id) not in serving_up or not first_ok or not dev.effectively_up(iface):
                        state, detail = _first_break(model, via, dev, iface, vlan)
                    found[link_id] = LinkM(link_id, dev.id, iface.id, peer.id, peer_if.id, kind=TRANSIT,
                                           state="up" if state == "ok" else "down",
                                           observation={"via": via, "switches": [s for s in switches if s != dev.id],
                                                        "vlan": vlan, "state": state, "detail": detail})
    return found


def _physical_problem(model: NetworkModel, link: LinkM) -> tuple[str, dict] | None:
    if problem := media_problem(model, link):
        return "media_mismatch", problem
    for dev_id, if_id in ((link.a_dev, link.a_if), (link.b_dev, link.b_if)):
        iface = model.iface(dev_id, if_id)
        if iface is not None and not iface.up:
            return "link_down", {"device": model.device(dev_id).name, "interface": iface.name, "status": iface.status}
    return None


def _first_break(model: NetworkModel, via: list[int], dev: DeviceM, iface: IfaceM, vlan: int) -> tuple[str, dict]:
    if not dev.effectively_up(iface):
        return "link_down", {"device": dev.name, "interface": iface.name, "status": iface.status}
    for link_id in via:
        problem = _physical_problem(model, model.links[link_id])
        if problem:
            return problem[0], {**problem[1], "link_id": link_id}
    return "incomplete", {"reason": f"VLAN {vlan} is not carried on the switched path (pruned, blocked or undefined)",
                          "vlan": vlan}


# --------------------------------------------------------------- routing
def l3_link_state(model: NetworkModel, link: LinkM) -> tuple[str, dict]:
    if link.kind == TRANSIT:
        ia, ib = model.iface(link.a_dev, link.a_if), model.iface(link.b_dev, link.b_if)
        a, b = model.device(link.a_dev), model.device(link.b_dev)
        if link.observation.get("state", "ok") != "ok":
            return link.observation["state"], dict(link.observation.get("detail", {}))
        if ia.network != ib.network:
            return "subnet_mismatch", {"a": f"{a.name} {ia.name}", "a_cidr": ia.cidr, "b": f"{b.name} {ib.name}",
                                       "b_cidr": ib.cidr}
        return "ok", {}
    a, b = model.device(link.a_dev), model.device(link.b_dev)
    ia, ib = model.iface(a.id, link.a_if), model.iface(b.id, link.b_if)
    if ia is None or ib is None:
        return "incomplete", {}
    if problem := media_problem(model, link):
        return "media_mismatch", problem
    if not ia.up or not ib.up:
        down_dev, down_if = (a, ia) if not ia.up else (b, ib)
        return "link_down", {"device": down_dev.name, "interface": down_if.name, "status": down_if.status}
    if ia.ip and ib.ip and ia.network != ib.network:
        return "subnet_mismatch", {
            "a": f"{a.name} {ia.name}", "a_cidr": ia.cidr, "b": f"{b.name} {ib.name}", "b_cidr": ib.cidr,
        }
    if not ia.ip or not ib.ip:
        return "incomplete", {}
    return "ok", {}


def ospf_timers(iface) -> tuple[int, int]:
    """Effective OSPF hello and dead intervals (IOS and FRRouting broadcast defaults: 10 s and 4 x hello)."""
    hello = iface.ospf_hello or 10
    return hello, iface.ospf_dead or hello * 4


def ospf_adjacency(model: NetworkModel, link: LinkM) -> str:
    """'up', 'none' (no OSPF on either side), 'missing' (one side only), 'mismatch' (areas), 'timer_mismatch',
    'mtu_mismatch' or 'down'."""
    a, b = model.device(link.a_dev), model.device(link.b_dev)
    if not (a.is_router and b.is_router):
        return "none"
    ia, ib = model.iface(a.id, link.a_if), model.iface(b.id, link.b_if)
    if ia is None or ib is None:
        return "none"
    if ia.ospf_area is None and ib.ospf_area is None:
        return "none"
    if (ia.ospf_area is None) != (ib.ospf_area is None):
        return "missing"
    if ia.ospf_area != ib.ospf_area:
        return "mismatch"
    if ospf_timers(ia) != ospf_timers(ib):
        return "timer_mismatch"  # hello/dead intervals must match or no neighbour is formed
    if ia.mtu and ib.mtu and ia.mtu != ib.mtu:
        return "mtu_mismatch"  # the adjacency stalls in ExStart/Exchange
    state, _ = l3_link_state(model, link)
    return "up" if state == "ok" else "down"


class Router:
    """Route lookups over one model, with cached OSPF adjacency graph."""

    def __init__(self, model: NetworkModel):
        self.model = model
        self.transit = transit_links(model)
        self.all_links: dict[int, LinkM] = {**model.links, **self.transit}
        self.adjacent: dict[int, list[tuple[int, int]]] = {d: [] for d in model.devices}
        for link in self.all_links.values():
            if ospf_adjacency(model, link) == "up":
                self.adjacent[link.a_dev].append((link.b_dev, link.id))
                self.adjacent[link.b_dev].append((link.a_dev, link.id))

    def link(self, link_id: int) -> LinkM:
        return self.all_links[link_id]

    def physical(self, link_id: int) -> list[int]:
        """Physical link ids a (possibly transit) link uses."""
        link = self.all_links[link_id]
        return list(link.observation.get("via", [])) if link.kind == TRANSIT else [link_id]

    def links_of(self, device_id: int) -> list[LinkM]:
        return [l for l in self.all_links.values() if device_id in (l.a_dev, l.b_dev)]

    def l3_ends(self, link: LinkM, device_id: int) -> tuple[IfaceM | None, IfaceM | None]:
        """(local, peer) L3 interfaces of a link as seen from device_id (sub-interfaces on 802.1Q trunks)."""
        model = self.model
        peer_id, peer_if_id = link.other(device_id)
        local, peer = model.iface(device_id, link.local_if(device_id)), model.iface(peer_id, peer_if_id)
        if link.kind == TRANSIT or local is None or peer is None or (local.ip and peer.ip):
            return local, peer
        dev, pdev = model.device(device_id), model.device(peer_id)
        for sub in dev.subinterfaces(local):
            match = next((p for p in pdev.subinterfaces(peer) if p.network and p.network == sub.network), None)
            if match is not None:
                return sub, match
        return local, peer

    def ospf_enabled(self, dev: DeviceM) -> bool:
        return dev.is_router and any(i.ospf_area is not None and dev.effectively_up(i) and i.ip for i in dev.interfaces.values())

    def _ospf_bfs(self, start: int) -> dict:
        parents = {start: None}
        queue = deque([start])
        while queue:
            node = queue.popleft()
            for peer, link_id in self.adjacent[node]:
                if peer not in parents:
                    parents[peer] = (node, link_id)
                    queue.append(peer)
        return parents

    def default_route(self, dev: DeviceM):
        """The static default route of `dev`, as installed (kind 'static') or not ('invalid'), or None."""
        route = next((r for r in dev.routes if r.network.prefixlen == 0), None)
        return self._resolve_static(dev, route) if route is not None else None

    def originates_default(self, dev: DeviceM) -> bool:
        """An OSPF router with an installed static default route advertises it into OSPF."""
        installed = self.default_route(dev)
        return bool(installed and installed["kind"] == "static" and self.ospf_enabled(dev))

    def ospf_route(self, dev: DeviceM, dst_ip: str):
        """Best OSPF route: (prefixlen, next_hop_device_id, link_id, advertiser_id) or None."""
        if not self.ospf_enabled(dev):
            return None
        parents = self._ospf_bfs(dev.id)
        best = None
        for node in parents:  # BFS order: the nearest advertiser wins on equal prefix
            if node == dev.id:
                continue
            owner = self.model.device(node)
            prefixes = [iface.network.prefixlen for iface in owner.interfaces.values()
                        if iface.ospf_area is not None and iface.ip and owner.effectively_up(iface)
                        and ip_in(dst_ip, iface.network) and not self.media_down(owner, iface)]
            if best is None and self.originates_default(owner):
                prefixes.append(0)
            for prefixlen in prefixes:
                if best is None or prefixlen > best[0]:
                    hop = node
                    while parents[hop][0] != dev.id:
                        hop = parents[hop][0]
                    best = (prefixlen, hop, parents[hop][1], node)
        return best

    def media_down(self, dev: DeviceM, iface: IfaceM) -> bool:
        """The interface's cable cannot come up (copper/fibre mismatch), so it installs no connected route."""
        link = self.model.link_for_iface(dev.id, iface)
        return link is not None and media_problem(self.model, link) is not None

    def connected(self, dev: DeviceM, dst_ip: str, usable: bool = True) -> IfaceM | None:
        """Connected interface for dst_ip. usable=False also returns media-down interfaces (for diagnosis)."""
        return next(
            (i for i in dev.interfaces.values() if i.ip and dev.effectively_up(i) and ip_in(dst_ip, i.network)
             and not (usable and self.media_down(dev, i))), None
        )

    def lookup(self, dev: DeviceM, dst_ip: str) -> dict:
        """Longest-prefix match. Connected (AD 0) beats static (AD 1) beats OSPF (AD 110) on equal prefix.

        A static route whose next hop cannot be resolved is not installed (as on a real router),
        so the lookup falls back to the next best route; it is only returned when nothing else matches.
        """
        connected = self.connected(dev, dst_ip)
        conn_len = connected.network.prefixlen if connected else -1
        ospf = self.ospf_route(dev, dst_ip)
        ospf_len = ospf[0] if ospf else -1
        invalid = None
        for route in sorted((r for r in dev.routes if ip_in(dst_ip, r.network)),
                            key=lambda r: r.network.prefixlen, reverse=True):
            length = route.network.prefixlen
            if length < conn_len or length < ospf_len:
                break
            resolved = self._resolve_static(dev, route)
            if resolved["kind"] == "static":
                if length == conn_len:
                    break
                return resolved
            invalid = invalid or resolved
        if connected is not None and conn_len >= ospf_len:
            return {"kind": "connected", "interface": connected.name, "prefix": conn_len}
        if ospf:
            return {"kind": "ospf", "next": ospf[1], "link_id": ospf[2], "prefix": ospf[0]}
        if invalid:
            return invalid
        return {"kind": "none"}

    def _resolve_static(self, dev: DeviceM, route) -> dict:
        base = {"kind": "static", "route": f"{route.destination} via {route.next_hop}", "route_id": route.id,
                "next_hop": route.next_hop}
        local = self.connected(dev, route.next_hop, usable=False)
        if local is None:
            return {**base, "kind": "invalid", "reason": "not_connected"}
        link = self.model.link_for_iface(dev.id, local)
        if link is not None and media_problem(self.model, link):
            # A link that cannot come up cannot carry the route; a less specific working route may apply.
            return {**base, "kind": "invalid", "reason": "media_mismatch", "interface": local.name, "link_id": link.id}
        if link is not None:
            peer_id, peer_if_id = link.other(dev.id)
            peer_if = self.model.iface(peer_id, peer_if_id)
            if peer_if and peer_if.ip == route.next_hop:
                return {**base, "next": peer_id, "link_id": link.id}
        # Across switches: a router interface or SVI in the same VLAN owns the next hop.
        for transit in self.transit.values():
            if (dev.id, local.id) not in ((transit.a_dev, transit.a_if), (transit.b_dev, transit.b_if)):
                continue
            peer_id, peer_if_id = transit.other(dev.id)
            peer_if = self.model.iface(peer_id, peer_if_id)
            if peer_if and peer_if.ip == route.next_hop:
                return {**base, "next": peer_id, "link_id": transit.id}
        return {**base, "kind": "invalid", "reason": "unknown_host", "interface": local.name}


# ------------------------------------------------------------------ flows
@dataclass
class FlowResult:
    status: str  # reachable / blocked / unreachable
    code: str | None = None
    detail: dict = field(default_factory=dict)
    path: list[int] = field(default_factory=list)
    links: list[int] = field(default_factory=list)
    fail_device: int | None = None
    fail_link: int | None = None
    hops: dict = field(default_factory=dict)  # device id -> link id used (forward L3)
    hop_ifaces: list = field(default_factory=list)  # [(router id, ingress iface id, egress iface id)] forward

    @property
    def reachable(self) -> bool:
        return self.status == "reachable"


class FlowAnalyzer:
    def __init__(self, model: NetworkModel, baseline: "FlowAnalyzer | None" = None):
        self.model = model
        self.router = Router(model)
        self.baseline = baseline
        self._attach: dict[int, Attachment] = {}

    def attachment(self, device_id: int) -> Attachment:
        if device_id not in self._attach:
            self._attach[device_id] = attach(self.model, device_id)
        return self._attach[device_id]

    # ------------------------------------------------------------------
    def evaluate(self, src_id: int, dst_id: int, protocol: str = "ip", port: int | None = None) -> FlowResult:
        model = self.model
        src, dst = model.device(src_id), model.device(dst_id)
        a_src, a_dst = self.attachment(src_id), self.attachment(dst_id)
        for att, side in ((a_src, "source"), (a_dst, "destination")):
            if not att.l2_ok:
                problem = att.problems[0]
                return FlowResult("unreachable", problem.code, {**problem.detail, "side": side, "host": att.host.name},
                                  fail_device=att.host.id, fail_link=problem.detail.get("link_id"))

        # Each endpoint makes its own on-link decision. Unequal masks can make
        # the forward leg local while the reply still needs a working gateway.
        same_segment = a_src.segment == a_dst.segment
        direct_forward = same_segment and ip_in(a_dst.nic.ip, a_src.nic.network)
        direct_reverse = same_segment and ip_in(a_src.nic.ip, a_dst.nic.network)
        if direct_forward and direct_reverse:
            path, links = self._l2_path(a_src, a_dst)
            return FlowResult("reachable", path=path, links=links)

        for att, side, needs_gateway in ((a_src, "source", not direct_forward),
                                         (a_dst, "destination", not direct_reverse)):
            if not needs_gateway:
                continue
            if (problem := att.gateway_problem()) is not None:
                return FlowResult("unreachable", problem.code, {**problem.detail, "side": side, "host": att.host.name},
                                  fail_device=att.host.id, fail_link=problem.detail.get("link_id"))
            if not att.l3_ok:
                problem = next(p for p in att.problems if p.code in ("vlan_mismatch", "subnet_mismatch", "gateway_mismatch"))
                return FlowResult("unreachable", problem.code, {**problem.detail, "side": side, "host": att.host.name},
                                  fail_device=att.host.id, fail_link=problem.detail.get("link_id"))
            if att.gateway is None:
                return FlowResult("unreachable", "no_default_gateway", {"host": att.host.name, "side": side},
                                  fail_device=att.host.id)

        if direct_forward:
            path, links = self._l2_path(a_src, a_dst)
            forward = FlowResult("reachable", path=path, links=links)
        else:
            forward = self._route(a_src.gateway[0], self._targets(a_dst), a_dst.nic.ip, src_id, dst_id,
                                  ingress=a_src.gateway[1])
        if forward.status != "reachable":
            return forward
        if not direct_reverse:
            reverse = self._route(a_dst.gateway[0], self._targets(a_src), a_src.nic.ip, dst_id, src_id,
                                  ingress=a_dst.gateway[1])
            if reverse.status != "reachable":
                reverse.detail["direction"] = "return"
                return reverse

        if direct_forward:
            return forward  # No routed device or ACL on the forward leg.

        for dev_id, in_id, out_id in forward.hop_ifaces:
            device = model.device(dev_id)
            action, rule, where = evaluate_hop(device, device.interfaces.get(in_id), device.interfaces.get(out_id),
                                               a_src.nic.ip, a_dst.nic.ip, protocol, port)
            if action == "deny":
                full_path, full_links = self._assemble(a_src, a_dst, forward)
                return FlowResult("blocked", "acl_deny", {
                    "device": device.name, "rule": rule.text() if rule else None,
                    "rule_id": rule.id if rule else None, "implicit": rule is None, "where": where,
                    "acl": rule.acl_name if rule else (where.split(" ")[0] if where and where != "device rule list" else None),
                }, path=full_path, links=full_links, fail_device=dev_id, hops=forward.hops,
                    hop_ifaces=forward.hop_ifaces)

        full_path, full_links = self._assemble(a_src, a_dst, forward)
        return FlowResult("reachable", path=full_path, links=full_links, hops=forward.hops,
                          hop_ifaces=forward.hop_ifaces)

    @staticmethod
    def _targets(att: Attachment) -> set[int]:
        """Routers that deliver to this endpoint: those with an interface in its subnet on its segment."""
        return {c[0].id for c in att.candidates if ip_in(att.nic.ip, c[1].network)}

    def gateway_reachable(self, host_id: int) -> FlowResult:
        att = self.attachment(host_id)
        problem = att.gateway_problem()
        if problem is not None:
            return FlowResult("unreachable", problem.code, {**problem.detail, "host": att.host.name},
                              fail_device=host_id, fail_link=problem.detail.get("link_id"))
        if not att.l2_ok or not att.l3_ok:
            problem = next((p for p in att.problems), Problem("incomplete"))
            return FlowResult("unreachable", problem.code, {**problem.detail, "host": att.host.name},
                              fail_device=host_id, fail_link=problem.detail.get("link_id"))
        if att.gateway is None:
            return FlowResult("unreachable", "no_default_gateway", {"host": att.host.name}, fail_device=host_id)
        _, _, path, links = att.gateway
        return FlowResult("reachable", path=list(path), links=list(links))

    # ------------------------------------------------------------------
    def _route(self, start: DeviceM, targets: set[int], dst_ip: str, src_host: int, dst_host: int,
               ingress: IfaceM | None = None) -> FlowResult:
        model, router = self.model, self.router
        current = start
        path, links, hops = [start.id], [], {}
        hop_ifaces, in_if = [], ingress.id if ingress is not None else None
        while True:
            decision = router.lookup(current, dst_ip)
            if decision["kind"] == "connected":
                if current.id in targets:
                    egress = current.iface_by_name(decision["interface"])
                    hop_ifaces.append((current.id, in_if, egress.id if egress else None))
                    return FlowResult("reachable", path=path, links=links, hops=hops, hop_ifaces=hop_ifaces)
                # Directly connected here, but the destination host is not on this segment.
                return FlowResult("unreachable", "wrong_segment", {
                    "device": current.name, "interface": decision["interface"], "destination": dst_ip,
                }, path=path, links=links, fail_device=current.id)
            if decision["kind"] == "none":
                return self._diagnose_no_route(current, dst_ip, path, links, src_host, dst_host)
            if decision["kind"] == "invalid" and decision["reason"] == "media_mismatch":
                problem = media_problem(model, model.links[decision["link_id"]])
                return FlowResult("unreachable", "media_mismatch", {**problem, "route": decision["route"]},
                                  path=path, links=links, fail_device=current.id, fail_link=decision["link_id"])
            if decision["kind"] == "invalid":
                return FlowResult("unreachable", "invalid_next_hop", {
                    "device": current.name, "route": decision["route"], "next_hop": decision["next_hop"],
                    "reason": decision["reason"], "route_id": decision["route_id"],
                }, path=path, links=links, fail_device=current.id)
            link = router.link(decision["link_id"])
            state, detail = l3_link_state(model, link)
            if state != "ok":
                fail_link = detail.get("link_id") if link.kind == TRANSIT else link.id
                return FlowResult("unreachable", state, {**detail, "device": current.name}, path=path, links=links,
                                  fail_device=current.id, fail_link=fail_link)
            nxt = decision["next"]
            if not model.device(nxt).is_router:
                # The matching route points at an end device (e.g. a default route to the internet):
                # traffic for an internal destination leaves the routed network and is lost.
                return FlowResult("unreachable", "no_route", {
                    "device": current.name, "destination": dst_ip, "via": decision.get("route"),
                    "via_device": model.device(nxt).name,
                }, path=path, links=links, fail_device=current.id)
            if nxt in path:
                # A loop often follows a lost specific route (a broken OSPF adjacency, a network no
                # longer advertised) when a default route sends the traffic back and forth: report
                # that cause if there is one.
                cause = self._diagnose_no_route(model.device(path[0]), dst_ip, [path[0]], [], src_host, dst_host)
                if cause.code not in ("no_route", "invalid_next_hop"):
                    # The cause is reported from the start router, but forwarding was evaluated along `path`.
                    cause.detail["traversed"] = list(path)
                    return cause
                loop = [model.device(d).name for d in path[path.index(nxt):]] + [model.device(nxt).name]
                return FlowResult("unreachable", "routing_loop", {
                    "device": current.name, "destination": dst_ip, "loop": " → ".join(loop),
                }, path=path, links=links, fail_device=current.id, fail_link=(router.physical(link.id) or [None])[-1])
            local_l3, peer_l3 = router.l3_ends(link, current.id)
            hop_ifaces.append((current.id, in_if, local_l3.id if local_l3 else None))
            in_if = peer_l3.id if peer_l3 else None
            hops[current.id] = link.id
            if link.kind == TRANSIT:
                path.extend(link.observation.get("switches", []) if link.a_dev == current.id
                            else list(reversed(link.observation.get("switches", []))))
                links.extend(link.observation.get("via", []) if link.a_dev == current.id
                             else list(reversed(link.observation.get("via", []))))
            else:
                links.append(link.id)
            path.append(nxt)
            current = model.device(nxt)

    def _path_links(self, device_id: int, dst_ip: str) -> list[int]:
        """The routed links traffic from device_id took before the change, else the shortest physical path."""
        baseline_links = self.baseline.trace_links(device_id, dst_ip) if self.baseline is not None else []
        # No earlier state to compare with (health check) or no route before either:
        # use the shortest physical routed path towards the destination network.
        return baseline_links or self.physical_links(device_id, dst_ip)

    def _broken_hop(self, current: DeviceM, dst_ip: str, path, links=None) -> FlowResult | None:
        """The first hop on the path towards dst_ip that is now broken (link down, subnet or OSPF
        adjacency problem), as a failure at `current`; None when that path is intact."""
        model = self.model
        links = list(links or [])
        # "reach" = how many routed hops the traffic gets through before the failing hop (used to tell
        # whether a change moves the failure point of an already failing flow earlier or later).
        for index, link_id in enumerate(self._path_links(current.id, dst_ip)):
            if link_id not in self.router.all_links:
                continue
            link = self.router.all_links[link_id]
            state, detail = l3_link_state(model, link)
            adjacency = ospf_adjacency(model, link)
            if state != "ok":
                return FlowResult("unreachable", state, {"device": current.name, **detail, "destination": dst_ip,
                                                         "reach": len(path) + index},
                                  path=list(path), links=links, fail_device=current.id,
                                  fail_link=detail.get("link_id") if link.kind == TRANSIT else link.id)
            if adjacency in ("mismatch", "missing", "timer_mismatch", "mtu_mismatch"):
                return FlowResult("unreachable", "ospf_adjacency", {
                    "device": current.name, "destination": dst_ip, "state": adjacency, "link_id": link.id,
                    "reach": len(path) + index,
                    "link": f"{model.device(link.a_dev).name}–{model.device(link.b_dev).name}",
                }, path=list(path), links=links, fail_device=current.id, fail_link=self.router.physical(link.id)[0]
                    if self.router.physical(link.id) else None)
        return None

    def _diagnose_no_route(self, current: DeviceM, dst_ip: str, path, links, src_host, dst_host) -> FlowResult:
        """No route at `current`. Explain why by comparing with the baseline forwarding decision."""
        model = self.model
        # Follow the path the traffic took before the change; the first hop that is
        # now broken is the real cause.
        broken = self._broken_hop(current, dst_ip, path, links)
        if broken is not None:
            return broken
        result = FlowResult("unreachable", "no_route", {"device": current.name, "destination": dst_ip},
                            path=path, links=links, fail_device=current.id)
        result.detail["reach"] = len(path) + len(self._path_links(current.id, dst_ip))
        if self.baseline is not None and current.id in self.baseline.model.devices:
            before = self.baseline.router.ospf_route(self.baseline.model.device(current.id), dst_ip)
            if before is not None and before[0] == 0:  # it used a default route learned through OSPF
                result.detail["lost_default"] = self.baseline.model.device(before[3]).name
        # Destination network not advertised into OSPF anywhere? (Not for external destinations
        # such as the internet: those are reached through a default route.)
        dst_device = model.devices.get(dst_host)
        dst_dev = self.attachment(dst_host).serving if dst_device is not None else None
        if (dst_dev and dst_device.type != "internet" and self.router.ospf_enabled(current)
                and dst_dev[1].ospf_area is None):
            result.code = "ospf_network_missing"
            result.detail.update({"router": dst_dev[0].name, "interface": dst_dev[1].name, "network": str(dst_dev[1].network)})
            return result
        # An OSPF router whose static default route is invalid does not advertise a default route:
        # the invalid route is the cause (reported at that router).
        if self.router.ospf_enabled(current):
            for node in self.router._ospf_bfs(current.id):
                origin = model.device(node)
                default = self.router.default_route(origin)
                if node != current.id and default and default["kind"] == "invalid" and default["reason"] == "media_mismatch":
                    # The default route is not advertised because its link cannot come up.
                    result.code = "media_mismatch"
                    result.detail.update({**media_problem(model, model.links[default["link_id"]]),
                                          "route": default["route"], "advertised_to": current.name})
                    result.fail_device, result.fail_link = origin.id, default["link_id"]
                    return result
                if node != current.id and default and default["kind"] == "invalid":
                    result.code = "invalid_next_hop"
                    result.detail.update({"device": origin.name, "route": default["route"],
                                          "next_hop": default["next_hop"], "reason": default["reason"],
                                          "route_id": default["route_id"], "advertised_to": current.name})
                    result.fail_device = origin.id
                    return result
        return result

    def physical_links(self, device_id: int, dst_ip: str) -> list[int]:
        """Links of the shortest router-to-router path from device_id to the router owning dst_ip."""
        model = self.model
        targets = {d.id for d in model.devices.values() if d.is_router and self.router.connected(d, dst_ip)}
        if not targets:
            return []
        parents, queue = {device_id: None}, deque([device_id])
        while queue:
            node = queue.popleft()
            if node in targets:
                links = []
                while parents[node] is not None:
                    node, link_id = parents[node]
                    links.append(link_id)
                return list(reversed(links))
            for link in self.router.links_of(node):
                peer_id, _ = link.other(node)
                if model.device(peer_id).is_router and peer_id not in parents:
                    parents[peer_id] = (node, link.id)
                    queue.append(peer_id)
        return []

    def trace_links(self, device_id: int, dst_ip: str, max_hops: int = 32) -> list[int]:
        """Links used hop by hop from device_id towards dst_ip on this model."""
        if device_id not in self.model.devices:
            return []
        links, visited, current = [], {device_id}, self.model.device(device_id)
        for _ in range(max_hops):
            decision = self.router.lookup(current, dst_ip)
            if decision["kind"] not in ("ospf", "static") or decision["next"] in visited:
                break
            links.append(decision["link_id"])
            visited.add(decision["next"])
            current = self.model.device(decision["next"])
        return links

    def _l2_path(self, a: Attachment, b: Attachment) -> tuple[list[int], list[int]]:
        if a.switch is None or b.switch is None:
            return [a.host.id, b.host.id], []
        switches, sw_links = a.switch_path(b.switch.id)
        first = model_link(self.model, a.host.id, a.switch.id)
        last = model_link(self.model, b.host.id, b.switch.id)
        return [a.host.id, *switches, b.host.id], [x for x in [first, *sw_links, last] if x is not None]

    def _assemble(self, a_src: Attachment, a_dst: Attachment, forward: FlowResult) -> tuple[list[int], list[int]]:
        _, _, src_path, src_links = a_src.gateway
        last = forward.path[-1]
        delivering = next((c for c in a_dst.candidates if c[0].id == last and ip_in(a_dst.nic.ip, c[1].network)),
                          a_dst.serving)
        _, _, dst_path, dst_links = delivering
        path = [*src_path[:-1], *forward.path, *reversed(dst_path[:-1])]
        links = [*src_links, *forward.links, *reversed(dst_links)]
        return path, links


def model_link(model: NetworkModel, a: int, b: int) -> int | None:
    found = model.link_between(a, b)
    return found[0].id if found else None


def endpoint_ids(model: NetworkModel) -> list[int]:
    return [d.id for d in model.devices.values() if d.type in ("pc", "server")]
