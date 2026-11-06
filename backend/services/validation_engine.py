"""Validation Engine: runs the rule set over a network model.

Rules are evaluated on both the baseline and the candidate model. Only
findings that exist in the candidate but not in the baseline are attributed
to the proposed change (differential validation); findings present in both
are reported as pre-existing, and findings that disappear as resolved.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from backend.services.forwarding import FlowAnalyzer, evaluate_acl, l3_link_state, ospf_adjacency
from backend.services.network_model import NetworkModel
from backend.services.rules import RULES, pack_of


@dataclass
class Finding:
    rule_id: str
    subject: str
    message: str
    device_ids: list[int] = field(default_factory=list)
    link_ids: list[int] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    severity: str = ""  # effective severity, set by the risk engine
    related_flows: list[str] = field(default_factory=list)
    related_flow_keys: list = field(default_factory=list)  # unique flow keys behind related_flows

    def __post_init__(self):
        self.device_ids = list(dict.fromkeys(d for d in self.device_ids if d is not None))
        self.link_ids = list(dict.fromkeys(l for l in self.link_ids if l is not None))

    @property
    def key(self) -> tuple[str, str]:
        return self.rule_id, self.subject

    def to_dict(self, model: NetworkModel) -> dict:
        rule = RULES[self.rule_id]
        interfaces = [{"device_id": did, "device": model.devices[did].name, "interface": iface.name}
                      for lid in self.link_ids if lid in model.links
                      for did, iid in ((model.links[lid].a_dev, model.links[lid].a_if),
                                       (model.links[lid].b_dev, model.links[lid].b_if))
                      if did in model.devices and (iface := model.iface(did, iid)) is not None]
        confidence = min([model.links[lid].confidence for lid in self.link_ids
                          if lid in model.links and model.links[lid].confidence is not None] or [0.95])
        confidence = self.detail.get("confidence", confidence)
        root_cause = self.detail.get("root_cause", self.message)
        symptom = self.detail.get("symptom", rule.consequence.format(**self.detail) if "{" in rule.consequence else rule.consequence)
        evidence = [fact for fact in self.detail.get("evidence", [])
                    if fact.get("detail") not in (root_cause, symptom)]
        recommendation = self.detail.get("recommendation", rule.recommendation)
        return {
            "rule_id": self.rule_id, "subject": self.subject, "key": f"{self.rule_id}|{self.subject}",
            "name": rule.name, "category": rule.category, "pack": pack_of(self.rule_id), "risk": self.detail.get("risk"),
            "severity": self.severity or rule.severity, "base_severity": rule.severity_label,
            "impact_type": rule.impact_type, "message": self.message, "consequence": rule.consequence.format(**self.detail)
            if "{" in rule.consequence else rule.consequence,
            "recommendation": recommendation,
            "devices": [model.devices[d].name for d in self.device_ids if d in model.devices],
            "device_ids": self.device_ids, "link_ids": self.link_ids, "detail": self.detail,
            "related_flows": self.related_flows,
            "symptom": symptom, "evidence": evidence,
            "root_cause": root_cause,
            "certainty": self.detail.get("certainty", "confirmed" if confidence >= 0.8 else "suspected"),
            "confidence": confidence, "affected_interfaces": interfaces,
            "affected_link_ids": self.link_ids, "affected_device_ids": self.device_ids,
            "corrective_action": recommendation,
            "expected_outcome": self.detail.get("expected_outcome", "Re-run analysis after correction; this finding should clear without breaking required flows."),
        }


def _add(findings: dict, finding: Finding) -> None:
    findings.setdefault(finding.key, finding)


# Flow failure codes each rule can explain (None: location alone is sufficient).
_FAILURE_CODES = {
    "VLAN001": {"vlan_mismatch"}, "VLAN002": {"vlan_unavailable"}, "IP001": {"subnet_mismatch", "wrong_segment"},
    "IP002": {"gateway_mismatch", "no_default_gateway"}, "OSPF001": {"ospf_adjacency"}, "OSPF003": {"ospf_adjacency"},
    "OSPF002": {"ospf_network_missing", "no_route"}, "ROUTE001": {"invalid_next_hop", "no_route", "routing_loop"},
    "ROUTE002": {"no_route"}, "LINK001": {"interface_down", "link_down"},
    "LINK002": {"not_connected", "incomplete", "no_route"}, "ACL001": {"acl_deny"}, "ACL002": {"acl_deny"},
    "PHY001": {"media_mismatch"},
}


def _explain_findings(model, flows, which, findings):
    observable = {
        "OSPF001": "The connected routers cannot establish an OSPF adjacency and exchange routes on this link.",
        "OSPF002": "Required destinations cannot be learned through OSPF on the recorded path.",
        "OSPF003": "The connected routers never become OSPF neighbours because their timers or MTU differ.",
        "ACL001": "A required service is blocked by a policy decision on its forward path.",
        "ACL002": "Traffic intended to stay isolated can pass the recorded access policy.",
        "IP001": "Direct IP delivery fails on the affected segment.",
        "IP002": "The affected endpoint cannot use its recorded default gateway.",
        "IP003": "More than one interface answers for the same configured IP address in this model.",
        "VLAN001": "The affected endpoint cannot reach its gateway from its assigned access VLAN.",
        "VLAN002": "The access port cannot forward traffic in its assigned VLAN.",
        "VLAN003": "The connected trunk ends cannot carry the same set of VLAN traffic.",
        "ROUTE001": "Traffic cannot be forwarded using the affected static route.",
        "ROUTE002": "The forwarding path stops before reaching the required destination.",
        "LINK001": "The recorded connection cannot carry traffic through its disabled interface.",
        "LINK002": "The intended physical path is missing from the stored connection evidence.",
    }
    for finding in findings:
        finding.detail.setdefault("root_cause", finding.message)
        affected = {}  # flow key -> display name (names need not be unique)
        codes = _FAILURE_CODES.get(finding.rule_id)
        for flow in flows:
            result = getattr(flow, which)
            if flow.kind == "gateway" or flow.expected != "allow" or result.reachable:
                continue
            if finding.related_flow_keys or finding.related_flows:
                # Match by unique key when known: two flows can share a display name.
                if (flow.key in finding.related_flow_keys if finding.related_flow_keys
                        else flow.name in finding.related_flows):
                    affected[flow.key] = flow.name
                continue
            at_location = (result.fail_link in finding.link_ids or result.fail_device in finding.device_ids
                           and not finding.subject.startswith("link:") and not finding.rule_id.startswith("ACL"))
            # Same place is not enough: the flow must fail for a reason this rule explains.
            if at_location and (codes is None or result.code in codes):
                affected[flow.key] = flow.name
        symptom = observable.get(finding.rule_id, "The affected connection needs operator review.")
        if finding.rule_id == "VLAN001":
            hosts = [model.device(did) for did in finding.device_ids if model.device(did).is_host]
            if hosts:
                symptom = f"{hosts[0].name} cannot reach its gateway {hosts[0].gateway or '(not configured)'}."
        if affected:
            symptom += f" {len(affected)} required flow(s) fail: {', '.join(dict.fromkeys(affected.values()))}."
        finding.detail.setdefault("symptom", symptom)
        repeats = (finding.detail["root_cause"], finding.detail["symptom"])
        if not [fact for fact in finding.detail.get("evidence") or [] if fact.get("detail") not in repeats]:
            facts = []
            for did in finding.device_ids:
                dev = model.device(did)
                for iface in dev.interfaces.values():
                    linked = any(model.links.get(lid) and model.links[lid].local_if(did) == iface.id
                                 and did in (model.links[lid].a_dev, model.links[lid].b_dev) for lid in finding.link_ids)
                    if finding.link_ids and not linked and not dev.is_host:
                        continue
                    details = f"{dev.name} {iface.name}: status {iface.status}"
                    if iface.ip:
                        details += f", address {iface.cidr}"
                    if dev.is_host:
                        details += f", gateway {dev.gateway or 'none'}"
                    if iface.vlan is not None:
                        details += f", {iface.mode or 'interface'} VLAN {iface.vlan}"
                    if iface.ospf_area is not None:
                        details += f", OSPF area {iface.ospf_area}"
                    facts.append({"source": "stored endpoint record" if dev.is_host else "stored interface configuration", "detail": details + "."})
                if dev.routes and finding.rule_id.startswith("ROUTE"):
                    facts += [{"source": "stored static route configuration", "detail": f"{dev.name}: {route.destination} via {route.next_hop}."} for route in dev.routes]
                if dev.acl and finding.rule_id.startswith("ACL"):
                    facts += [{"source": "stored ACL configuration", "detail": f"{dev.name}: {rule.text()}."} for rule in dev.sorted_acl()]
            if finding.rule_id == "VLAN001":
                for dev in model.devices.values():
                    for iface in dev.interfaces.values():
                        if iface.ip and any(model.device(did).gateway == iface.ip for did in finding.device_ids):
                            facts.append({"source": "stored gateway interface and VLAN assignment", "detail": f"Gateway {iface.ip}: {dev.name} {iface.name}, VLAN {finding.detail.get('expected_vlan', iface.vlan)}."})
            finding.detail["evidence"] = facts or [{"source": "stored rule evaluation", "detail": f"{finding.rule_id}: affected devices {', '.join(model.device(did).name for did in finding.device_ids)}; subject {finding.subject}."}]


def run(model: NetworkModel, analyzer: FlowAnalyzer, flows: list, which: str) -> dict[tuple, Finding]:
    findings: dict[tuple, Finding] = {}
    _check_links(model, findings)
    _check_transit_adjacencies(model, analyzer, findings)
    _check_duplicate_ips(model, findings)
    _check_switchports(model, findings)
    _check_hosts(model, analyzer, findings)
    _check_static_routes(model, analyzer, findings)
    _check_acl_shadowing(model, findings)
    _check_acl_rules(model, findings)
    _check_flows(model, flows, which, findings)
    from backend.services.diagnostics import supplemental_findings
    # One fault, one finding: a host-level VLAN001 already covers its switch port.
    host_ports = {(f.detail.get("switch"), f.detail.get("port")) for f in findings.values()
                  if f.rule_id == "VLAN001" and f.subject.startswith("host:")}
    for finding in supplemental_findings(model):
        if finding.rule_id == "VLAN001" and finding.subject.startswith("observed-port:") and \
                (finding.detail.get("switch"), finding.detail.get("port")) in host_ports:
            continue
        _add(findings, finding)
    from backend.services.analysis_checks import physical_findings
    for finding in physical_findings(model):
        _add(findings, finding)
    _explain_findings(model, flows, which, findings.values())
    return findings


# ----------------------------------------------------------------- links
def _check_links(model: NetworkModel, findings: dict) -> None:
    for link in model.links.values():
        a, b = model.device(link.a_dev), model.device(link.b_dev)
        ia, ib = model.iface(a.id, link.a_if), model.iface(b.id, link.b_if)
        ends = [(a, ia), (b, ib)]
        for dev, iface in ends:
            if iface is None or not iface.up:
                continue
            # A shut 802.1Q sub-interface disables its VLAN on this link (the physical link stays up).
            for sub in dev.subinterfaces(iface):
                if not sub.up:
                    peer = b if dev is a else a
                    _add(findings, Finding("LINK001", f"subif:{dev.id}:{sub.id}",
                         f"{dev.name} {sub.name} is {sub.status}, so VLAN {sub.vlan} on the link between {a.name} and "
                         f"{b.name} is inactive.", [dev.id, peer.id], [link.id],
                         {"device": dev.name, "interface": sub.name, "peer": peer.name}))
        down = [(d, i) for d, i in ends if i is not None and not i.up]
        if down:
            dev, iface = down[0]
            peer = b if dev is a else a
            _add(findings, Finding("LINK001", f"link:{link.id}",
                 f"{dev.name} {iface.name} is {iface.status}, so the link between {a.name} and {b.name} is inactive.",
                 [dev.id, peer.id], [link.id], {"device": dev.name, "interface": iface.name, "peer": peer.name}))
            continue
        if ia is None or ib is None:
            continue
        routed = (a.is_l3 and b.is_l3) or (a.is_l3 and b.type == "internet") or (b.is_l3 and a.type == "internet")
        if not routed:
            continue
        state, detail = l3_link_state(model, link)
        if state == "subnet_mismatch":
            _add(findings, Finding("IP001", f"link:{link.id}",
                 f"{detail['a']} ({detail['a_cidr']}) and {detail['b']} ({detail['b_cidr']}) are directly connected "
                 f"but are in different subnets.", [a.id, b.id], [link.id], {**detail, "a_dev": a.name, "b_dev": b.name}))
        adjacency = ospf_adjacency(model, link)
        detail = {"a_dev": a.name, "b_dev": b.name, "a_if": ia.name, "b_if": ib.name,
                  "a_area": ia.ospf_area, "b_area": ib.ospf_area}
        if adjacency == "mismatch":
            _add(findings, Finding("OSPF001", f"link:{link.id}",
                 f"{a.name} {ia.name} is in OSPF Area {ia.ospf_area} while the connected {b.name} {ib.name} "
                 f"is in Area {ib.ospf_area}.", [a.id, b.id], [link.id], detail))
        elif adjacency in ("timer_mismatch", "mtu_mismatch"):
            from backend.services.forwarding import ospf_timers
            if adjacency == "timer_mismatch":
                (ha, da), (hb, db_) = ospf_timers(ia), ospf_timers(ib)
                what = f"hello/dead {ha}/{da} s on {a.name} {ia.name} versus {hb}/{db_} s on {b.name} {ib.name}"
            else:
                what = f"MTU {ia.mtu} on {a.name} {ia.name} versus {ib.mtu} on {b.name} {ib.name}"
            _add(findings, Finding("OSPF003", f"link:{link.id}",
                 f"The OSPF interfaces on the link between {a.name} and {b.name} disagree: {what}.",
                 [a.id, b.id], [link.id], {**detail, "kind": adjacency, "a_hello": ospf_timers(ia)[0],
                                           "a_dead": ospf_timers(ia)[1], "b_hello": ospf_timers(ib)[0],
                                           "b_dead": ospf_timers(ib)[1], "a_mtu": ia.mtu, "b_mtu": ib.mtu}))
        elif adjacency == "missing":
            on, off = ((a, ia), (b, ib)) if ia.ospf_area is not None else ((b, ib), (a, ia))
            _add(findings, Finding("OSPF002", f"link:{link.id}",
                 f"{on[0].name} {on[1].name} is in OSPF Area {on[1].ospf_area} but the connected "
                 f"{off[0].name} {off[1].name} is not in OSPF.", [a.id, b.id], [link.id], detail))


def _check_transit_adjacencies(model: NetworkModel, analyzer: FlowAnalyzer, findings: dict) -> None:
    """Routers (or SVIs) that share a VLAN through switches must agree on subnet and OSPF like a direct link."""
    for link in analyzer.router.transit.values():
        if link.observation.get("state") != "ok":
            continue  # a shut port or pruned VLAN on the way is reported by its own rule
        a, b = model.device(link.a_dev), model.device(link.b_dev)
        ia, ib = model.iface(a.id, link.a_if), model.iface(b.id, link.b_if)
        via = list(link.observation.get("via", []))
        across = f" (through {', '.join(model.device(s).name for s in link.observation.get('switches', []))})" \
            if link.observation.get("switches") else ""
        if ia.network != ib.network:
            continue  # two subnets on one VLAN are allowed; routing between them needs a router
        adjacency = ospf_adjacency(model, link)
        detail = {"a_dev": a.name, "b_dev": b.name, "a_if": ia.name, "b_if": ib.name,
                  "a_area": ia.ospf_area, "b_area": ib.ospf_area, "vlan": link.observation.get("vlan")}
        if adjacency == "mismatch":
            _add(findings, Finding("OSPF001", f"transit:{min(ia.id, ib.id)}:{max(ia.id, ib.id)}",
                 f"{a.name} {ia.name} is in OSPF Area {ia.ospf_area} while {b.name} {ib.name} on the same VLAN"
                 f"{across} is in Area {ib.ospf_area}.", [a.id, b.id], via, detail))
        elif adjacency == "missing":
            on, off = ((a, ia), (b, ib)) if ia.ospf_area is not None else ((b, ib), (a, ia))
            _add(findings, Finding("OSPF002", f"transit:{min(ia.id, ib.id)}:{max(ia.id, ib.id)}",
                 f"{on[0].name} {on[1].name} is in OSPF Area {on[1].ospf_area} but {off[0].name} {off[1].name} on the "
                 f"same VLAN{across} is not in OSPF.", [a.id, b.id], via, detail))
        elif adjacency in ("timer_mismatch", "mtu_mismatch"):
            from backend.services.forwarding import ospf_timers
            (ha, da), (hb, db_) = ospf_timers(ia), ospf_timers(ib)
            what = (f"hello/dead {ha}/{da} s versus {hb}/{db_} s" if adjacency == "timer_mismatch"
                    else f"MTU {ia.mtu} versus {ib.mtu}")
            _add(findings, Finding("OSPF003", f"transit:{min(ia.id, ib.id)}:{max(ia.id, ib.id)}",
                 f"{a.name} {ia.name} and {b.name} {ib.name}{across} disagree: {what}.", [a.id, b.id], via,
                 {**detail, "kind": adjacency, "a_hello": ha, "a_dead": da, "b_hello": hb, "b_dead": db_,
                  "a_mtu": ia.mtu, "b_mtu": ib.mtu}))


def _check_duplicate_ips(model: NetworkModel, findings: dict) -> None:
    owners = defaultdict(list)
    for dev in model.devices.values():
        for iface in dev.interfaces.values():
            if iface.ip:
                owners[iface.ip].append((dev, iface))
    for ip, entries in owners.items():
        if len(entries) > 1:
            names = " and ".join(f"{d.name} {i.name}" for d, i in entries)
            _add(findings, Finding("IP003", f"ip:{ip}", f"{ip} is configured on {names}.",
                 sorted({d.id for d, _ in entries}), [], {"ip": ip}))


def _check_switchports(model: NetworkModel, findings: dict) -> None:
    for dev in model.devices.values():
        if not dev.is_switch:
            continue
        for iface in dev.interfaces.values():
            mode = iface.mode or ("access" if iface.vlan else "trunk")
            if mode == "access" and iface.vlan and iface.vlan not in dev.vlans:
                defined = ", ".join(str(v) for v in sorted(dev.vlans)) or "none"
                link = model.link_for_iface(dev.id, iface)
                peer = model.device(link.other(dev.id)[0]) if link else None
                _add(findings, Finding("VLAN002", f"port:{dev.id}:{iface.id}",
                     f"{dev.name} {iface.name} is assigned to VLAN {iface.vlan}, but VLAN {iface.vlan} is not defined "
                     f"on {dev.name} (defined: {defined}).",
                     [dev.id] + ([peer.id] if peer else []), [link.id] if link else [],
                     {"switch": dev.name, "port": iface.name, "vlan": iface.vlan}))


def _check_hosts(model: NetworkModel, analyzer: FlowAnalyzer, findings: dict) -> None:
    for dev in model.devices.values():
        if not dev.is_host:
            continue
        att = analyzer.attachment(dev.id)
        gateway_ids = [c[0].id for c in att.candidates[:1]]
        links = [l for c in att.candidates[:1] for l in c[3]]
        for problem in att.problems:
            d = problem.detail
            if problem.code == "vlan_mismatch":
                _add(findings, Finding("VLAN001", f"host:{dev.id}",
                     f"{dev.name} ({d['host_cidr']}) is connected to {d['switch']} {d['port']} in access VLAN {d['vlan']}, "
                     f"but its subnet belongs to VLAN {d['expected_vlan']}.",
                     [dev.id, att.switch.id], [d["link_id"]], d))
            elif problem.code == "subnet_mismatch":
                _add(findings, Finding("IP001", f"host:{dev.id}",
                     f"{dev.name} ({d['host_cidr']}) and its gateway interface {d['router']} {d['interface']} "
                     f"({d['router_cidr']}) are in different subnets.", [dev.id, *gateway_ids], links, d))
            elif problem.code == "gateway_mismatch":
                if d["reason"] == "outside_subnet":
                    message = (f"{dev.name} uses default gateway {d['gateway']}, which is outside its own subnet "
                               f"{d['host_cidr']}.")
                elif d.get("router"):
                    message = (f"{dev.name} uses default gateway {d['gateway']}, but no router interface in its segment "
                               f"has that address ({d['router']} {d['interface']} is {d['router_cidr']}).")
                elif d.get("owner"):
                    message = (f"{dev.name} uses default gateway {d['gateway']} ({d['owner']}), but that interface is "
                               f"not reachable from {dev.name}'s segment; check the switch port or trunk towards it.")
                else:
                    message = f"{dev.name} uses default gateway {d['gateway']}, but no router serves its segment."
                _add(findings, Finding("IP002", f"host:{dev.id}", message, [dev.id, *gateway_ids], links, d))
        if not dev.gateway and att.l3_ok and att.serving is not None:
            router, iface = att.serving[0], att.serving[1]
            _add(findings, Finding("IP002", f"host:{dev.id}",
                 f"{dev.name} has no default gateway configured, so it cannot reach other subnets "
                 f"({router.name} {iface.name} {iface.ip} serves its segment).",
                 [dev.id, router.id], list(att.serving[3]),
                 {"gateway": None, "host_cidr": att.nic.cidr, "reason": "missing", "router": router.name,
                  "interface": iface.name, "router_cidr": iface.cidr}))


def _check_static_routes(model: NetworkModel, analyzer: FlowAnalyzer, findings: dict) -> None:
    for dev in model.devices.values():
        if not dev.is_router:
            continue
        for route in dev.routes:
            decision = analyzer.router._resolve_static(dev, route)
            if decision["kind"] != "invalid" or decision["reason"] == "media_mismatch":
                continue  # a route over a cable that cannot come up is a PHY001 fault, not a bad next hop
            if decision["reason"] == "not_connected":
                reason = f"{route.next_hop} is not in any connected subnet of {dev.name}"
            else:
                reason = f"no directly connected neighbour owns {route.next_hop} (via {decision['interface']})"
            _add(findings, Finding("ROUTE001", f"route:{dev.id}:{route.destination}",
                 f"{dev.name} static route {route.destination} via {route.next_hop} is invalid: {reason}.",
                 [dev.id], [], {"device": dev.name, "destination": route.destination, "next_hop": route.next_hop}))


def _check_acl_shadowing(model: NetworkModel, findings: dict) -> None:
    for dev in model.devices.values():
        for rules in dev.acl_lists().values():
            for index, rule in enumerate(rules):
                if rule.action != "permit" or rule.protocol != "ip" or rule.source != "any" or rule.destination != "any":
                    continue
                shadowed = [r for r in rules[index + 1:] if r.action == "deny"]
                if shadowed:
                    listed = ", ".join(str(r.sequence) for r in shadowed)
                    _add(findings, Finding("ACL002", f"acl-shadow:{dev.id}:{rule.acl_name or ''}:{rule.sequence}",
                         f"{dev.name} rule '{rule.text()}' permits all traffic before deny rule(s) {listed}, "
                         f"which can therefore never match.", [dev.id], [],
                         {"device": dev.name, "rule": rule.text(), "rule_id": rule.id, "acl": rule.acl_name}))


def _covers(outer, inner) -> bool:
    """True when every packet matched by ACL entry `inner` is also matched by `outer`."""
    import ipaddress

    def net(spec):
        return ipaddress.IPv4Network("0.0.0.0/0" if spec == "any" else spec, strict=False)
    if outer.protocol != "ip" and outer.protocol != inner.protocol:
        return False
    if outer.port is not None and (inner.protocol not in ("tcp", "udp") or inner.port != outer.port):
        return False
    try:
        return net(inner.source).subnet_of(net(outer.source)) and net(inner.destination).subnet_of(net(outer.destination))
    except ValueError:
        return False


def _check_acl_rules(model: NetworkModel, findings: dict) -> None:
    for dev in model.devices.values():
        for rules in dev.acl_lists().values():
            for index, rule in enumerate(rules):
                earlier = next((r for r in rules[:index] if r.action != rule.action and _covers(r, rule)), None)
                if earlier is None:
                    continue
                if earlier.action == "permit" and earlier.protocol == "ip" and earlier.source == "any" and earlier.destination == "any":
                    continue  # reported once as ACL002 (permit-any shadowing every later deny)
                _add(findings, Finding("ACL003", f"acl-shadowed:{dev.id}:{rule.acl_name or ''}:{rule.sequence}",
                     f"{dev.name} rule '{rule.text()}' can never match: the earlier rule '{earlier.text()}' already "
                     f"{earlier.action}s all of its traffic.", [dev.id], [],
                     {"device": dev.name, "rule": rule.text(), "earlier": earlier.text(), "rule_id": rule.id,
                      "acl": rule.acl_name}))
        for ref in (dev.facts or {}).get("undefined_acls", []):
            _add(findings, Finding("ACL004", f"acl-undefined:{dev.id}:{ref['acl']}:{ref['where']}",
                 f"{dev.name} {ref['where']} refers to ACL {ref['acl']}, which is not defined; the device applies no "
                 f"filtering there.", [dev.id], [], {"device": dev.name, "acl": ref["acl"], "where": ref["where"],
                                                     "confidence": 0.9}))


# ------------------------------------------------------------------ flows
def _flow_label(flow) -> str:
    proto = flow.protocol.upper() + (f"/{flow.port}" if flow.port else "")
    return f"{flow.src_name} → {flow.dst_name} ({proto})"


def _check_flows(model: NetworkModel, flows: list, which: str, findings: dict) -> None:
    for flow in flows:
        if flow.kind == "gateway" or flow.expected is None:
            continue
        result = flow.baseline if which == "baseline" else flow.candidate
        label = _flow_label(flow)
        if flow.expected == "allow" and result.code == "acl_deny":
            d = result.detail
            if d.get("implicit"):
                cause = f"is dropped by the implicit deny at the end of {d['device']}'s ACL (no rule permits it)"
            else:
                cause = f"is denied by {d['device']} ACL rule '{d['rule']}'"
            # One finding per blocking device: unblocking one ACL may reveal another on the same flow.
            _add(findings, Finding("ACL001", f"flow:{flow.key}:{result.fail_device}",
                 f"The required flow {label} {cause}.", [flow.src, flow.dst, result.fail_device], [],
                 {"flow": flow.name, "device": d["device"], "rule": d.get("rule")}, related_flows=[flow.name], related_flow_keys=[flow.key]))
        elif flow.expected == "deny" and result.reachable:
            permit = _permitting_rule(model, result, flow)
            cause = (f"is now permitted by {permit[0]} rule '{permit[1]}'" if permit
                     else "is now reachable because no ACL on its path denies it")
            _add(findings, Finding("ACL002", f"flow:{flow.key}",
                 f"{flow.name}: {label} must be isolated but {cause}.",
                 [flow.src, flow.dst] + ([permit[2]] if permit else []), [],
                 {"flow": flow.name, "device": permit[0] if permit else None}, related_flows=[flow.name], related_flow_keys=[flow.key]))
        elif flow.expected == "allow" and result.code in ("no_route", "ospf_network_missing"):
            d = result.detail
            if result.code == "ospf_network_missing":
                _add(findings, Finding("OSPF002", f"ospf-net:{d['router']}:{d['interface']}",
                     f"Network {d['network']} on {d['router']} {d['interface']} is not advertised into OSPF, so "
                     f"{d['device']} has no route to {d['destination']}.",
                     [result.fail_device, model_id(model, d["router"])], [], d, related_flows=[flow.name], related_flow_keys=[flow.key]))
            else:
                via = (f" Its only matching route ({d['via']}) sends the traffic to {d['via_device']}, out of the "
                       f"routed network." if d.get("via_device") else "")
                if d.get("lost_default"):
                    via = f" Before the change it used the default route that {d['lost_default']} advertises into OSPF."
                direction = " on the return path" if d.get("direction") == "return" else ""
                _add(findings, Finding("ROUTE002", f"no-route:{result.fail_device}:{d['destination']}",
                     f"{d['device']} has no route to {d['destination']}{direction} (required by {label}).{via}",
                     [result.fail_device], [], d, related_flows=[flow.name], related_flow_keys=[flow.key]))
        elif flow.expected == "allow" and result.code == "routing_loop":
            d = result.detail
            _add(findings, Finding("ROUTE002", f"no-route:{result.fail_device}:{d['destination']}",
                 f"Traffic for {d['destination']} loops ({d['loop']}), so {d['device']} has no valid route to it "
                 f"(required by {label}).", [result.fail_device], [result.fail_link], d, related_flows=[flow.name], related_flow_keys=[flow.key]))
        elif flow.expected == "allow" and result.code == "wrong_segment":
            d = result.detail
            _add(findings, Finding("IP001", f"overlap:{result.fail_device}:{d['interface']}",
                 f"{d['device']} {d['interface']} is in the same subnet as {d['destination']} but is not on its "
                 f"segment, so {d['device']} delivers the traffic to the wrong network (required by {label}).",
                 [result.fail_device], [], d, related_flows=[flow.name], related_flow_keys=[flow.key]))


def _permitting_rule(model: NetworkModel, result, flow):
    from backend.services.forwarding import evaluate_hop
    for dev_id, in_id, out_id in getattr(result, "hop_ifaces", []):
        dev = model.device(dev_id)
        if not dev.acl:
            continue
        action, rule, _ = evaluate_hop(dev, dev.interfaces.get(in_id), dev.interfaces.get(out_id), flow.src_ip,
                                       flow.dst_ip, flow.protocol, flow.port)
        if action == "permit" and rule is not None:
            return dev.name, rule.text(), dev.id
    return None


def model_id(model: NetworkModel, name: str) -> int | None:
    return next((d.id for d in model.devices.values() if d.name == name), None)


def diff(baseline: dict, candidate: dict) -> tuple[list[Finding], list[Finding], list[Finding]]:
    new = [f for k, f in candidate.items() if k not in baseline]
    existing = [f for k, f in candidate.items() if k in baseline]
    resolved = [f for k, f in baseline.items() if k not in candidate]
    return new, existing, resolved


def build_checks(new: list[Finding], existing: list[Finding]) -> list[dict]:
    """One row per rule: failed (introduced by the change), warning (pre-existing) or passed."""
    new_rules = defaultdict(list)
    for f in new:
        new_rules[f.rule_id].append(f.message)
    old_rules = defaultdict(list)
    for f in existing:
        old_rules[f.rule_id].append(f.message)
    checks = []
    for rule in RULES.values():
        if rule.category == "advisory":
            continue  # advisories are reported separately and never "pass" a validation
        if rule.id in new_rules:
            status, messages = "failed", new_rules[rule.id]
        elif rule.id in old_rules:
            status, messages = "warning", old_rules[rule.id]
        else:
            status, messages = "passed", []
        checks.append({"rule_id": rule.id, "name": rule.name, "category": rule.category,
                       "severity": rule.severity_label, "status": status, "messages": messages})
    return checks
