"""Feature extraction shared by dataset generation, training and run-time inference.

Change features describe a proposed change and its place in the topology using only the baseline model and the
baseline flow paths, never the simulated outcome, so the predictor is a real forecast of what the simulation (or
the network) will show. Link-pair tokens describe the two ends of one cable for the misconfiguration classifier.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import deque

from backend.services.change_detector import CHANGE_TYPES

CHANGE_TYPE_LIST = sorted(CHANGE_TYPES)
CATEGORIES = ("ip_interface", "routing", "acl", "vlan", "security", "physical")
CRIT_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}

CHANGE_FEATURES = (
    [f"type:{t}" for t in CHANGE_TYPE_LIST] + [f"category:{c}" for c in CATEGORIES] + [
        "effective", "dev_router", "dev_l3_switch", "dev_l2_switch", "dev_firewall", "dev_host",
        "dev_degree", "dev_infra_degree", "dev_path_share", "dev_critical_paths", "dev_is_cut_vertex",
        "iface_present", "iface_linked", "iface_to_infra", "iface_to_host", "iface_trunk", "iface_access",
        "iface_routed", "iface_path_share", "iface_link_is_bridge", "iface_trunk_vlans", "iface_down_proposed",
        "net_devices", "net_hosts", "net_links", "net_flows", "net_intents", "net_redundancy",
        "acl_deny", "acl_breadth", "acl_any_protocol", "acl_position", "acl_lists_applied",
        "route_prefix", "route_default", "ospf_leaves_backbone", "vlan_hosts_on_port", "params_count",
        "evidence_inferred_share",
    ])


def _degree_graph(model) -> dict[int, set[int]]:
    graph = {did: set() for did in model.devices}
    for link in model.links.values():
        if link.a_dev in graph and link.b_dev in graph and link.a_dev != link.b_dev:
            graph[link.a_dev].add(link.b_dev)
            graph[link.b_dev].add(link.a_dev)
    return graph


def _components(graph: dict[int, set[int]], skip_node: int | None = None, skip_edge: tuple | None = None) -> int:
    seen, count = set(), 0
    for start in graph:
        if start in seen or start == skip_node:
            continue
        count += 1
        queue = deque([start])
        seen.add(start)
        while queue:
            node = queue.popleft()
            for nxt in graph[node]:
                if nxt == skip_node or nxt in seen:
                    continue
                if skip_edge and {node, nxt} == set(skip_edge):
                    continue
                seen.add(nxt)
                queue.append(nxt)
    return count


def topology_context(model, flows) -> dict:
    """Per-device and per-link load from the baseline flow paths (computed once per network)."""
    graph = _degree_graph(model)
    paths = [f for f in flows if f.baseline is not None and f.kind != "gateway"]
    total = max(len(paths), 1)
    dev_load, link_load, dev_crit = {}, {}, {}
    for flow in paths:
        weight = CRIT_WEIGHT.get(flow.criticality, 2)
        for did in set(flow.baseline.path):
            dev_load[did] = dev_load.get(did, 0) + 1
            if flow.kind == "intent" and weight >= 3:
                dev_crit[did] = dev_crit.get(did, 0) + 1
        for lid in set(flow.baseline.links):
            link_load[lid] = link_load.get(lid, 0) + 1
    base_components = _components(graph)
    infra = [d for d in model.devices.values() if not d.is_host]
    redundancy = sum(1 for d in infra if len([n for n in graph[d.id] if not model.devices[n].is_host]) >= 2) / max(len(infra), 1)
    inferred = sum(1 for l in model.links.values() if l.kind in ("mac", "subnet", "logical", "cdp")) / max(len(model.links), 1)
    return {"graph": graph, "total": total, "dev_load": dev_load, "link_load": link_load, "dev_crit": dev_crit,
            "components": base_components, "redundancy": redundancy, "inferred": inferred,
            "intents": len(model.intents), "flows": len(paths),
            "fail_devices": {f.baseline.fail_device for f in paths if not f.baseline.reachable and f.baseline.fail_device}}


def change_features(model, ctx: dict, detected) -> dict[str, float]:
    x = dict.fromkeys(CHANGE_FEATURES, 0.0)
    x[f"type:{detected.change_type}"] = 1.0
    if detected.category in CATEGORIES:
        x[f"category:{detected.category}"] = 1.0
    x["effective"] = float(bool(detected.effective))
    device = model.devices[detected.device_id]
    graph = ctx["graph"]
    x["dev_router"] = float(device.type == "router")
    x["dev_firewall"] = float(device.type == "firewall")
    x["dev_l3_switch"] = float(device.l3_switch)
    x["dev_l2_switch"] = float(device.is_switch and not device.l3_switch)
    x["dev_host"] = float(device.is_host)
    x["dev_degree"] = float(len(graph.get(device.id, ())))
    x["dev_infra_degree"] = float(sum(1 for n in graph.get(device.id, ()) if not model.devices[n].is_host))
    x["dev_path_share"] = ctx["dev_load"].get(device.id, 0) / ctx["total"]
    x["dev_critical_paths"] = float(ctx["dev_crit"].get(device.id, 0))
    if not device.is_host and len(graph) <= 400:
        x["dev_is_cut_vertex"] = float(_components(graph, skip_node=device.id) > ctx["components"] + 0)
    iface = device.interfaces.get(detected.interface_id) if detected.interface_id else None
    p = detected.parameters or {}
    if iface is not None:
        x["iface_present"] = 1.0
        link = model.link_for_iface(device.id, iface)
        if link is not None:
            x["iface_linked"] = 1.0
            peer = model.devices.get(link.other(device.id)[0])
            x["iface_to_infra"] = float(bool(peer and not peer.is_host))
            x["iface_to_host"] = float(bool(peer and peer.is_host))
            x["iface_path_share"] = ctx["link_load"].get(link.id, 0) / ctx["total"]
            if len(graph) <= 400:
                x["iface_link_is_bridge"] = float(_components(graph, skip_edge=(link.a_dev, link.b_dev)) > ctx["components"]
                                                  and len(model.link_between(link.a_dev, link.b_dev)) == 1)
        x["iface_trunk"] = float(iface.mode == "trunk")
        x["iface_access"] = float(iface.mode == "access")
        x["iface_routed"] = float(bool(iface.ip))
        x["iface_trunk_vlans"] = float(len(iface.allowed_vlans or []))
        if iface.mode == "access" and iface.vlan is not None and device.is_switch:
            x["vlan_hosts_on_port"] = float(sum(1 for i in device.interfaces.values() if i.vlan == iface.vlan))
    x["iface_down_proposed"] = float(str(p.get("status", "")).lower() in ("down", "admin-down"))
    x["net_devices"] = float(len(model.devices))
    x["net_hosts"] = float(sum(1 for d in model.devices.values() if d.is_host))
    x["net_links"] = float(len(model.links))
    x["net_flows"] = float(ctx["flows"])
    x["net_intents"] = float(ctx["intents"])
    x["net_redundancy"] = ctx["redundancy"]
    x["evidence_inferred_share"] = ctx["inferred"]
    if detected.change_type in ("acl_add", "acl_remove", "acl_reference"):
        x["acl_lists_applied"] = float(sum(1 for i in device.interfaces.values() if i.acl_in or i.acl_out))
    if detected.change_type == "acl_add":
        x["acl_deny"] = float(str(p.get("action", "")).lower() == "deny")
        x["acl_breadth"] = (_breadth(p.get("source")) + _breadth(p.get("destination"))) / 2
        x["acl_any_protocol"] = float(str(p.get("protocol", "ip")).lower() == "ip")
        rules = device.sorted_acl(p.get("acl_name", "*"))
        seq = p.get("sequence") or 0
        x["acl_position"] = sum(1 for r in rules if r.sequence > seq) / max(len(rules), 1)
    if detected.change_type == "acl_remove":
        rule = next((r for r in device.acl if r.id == p.get("rule_id")), None)
        if rule is not None:
            x["acl_deny"] = float(rule.action == "deny")
            x["acl_breadth"] = (_breadth(rule.source) + _breadth(rule.destination)) / 2
            x["acl_any_protocol"] = float(rule.protocol == "ip")
    if detected.change_type == "static_route":
        destination = p.get("destination")
        if not destination and p.get("route_id") is not None:
            destination = next((r.destination for r in device.routes if r.id == p.get("route_id")), None)
        try:
            net = ipaddress.IPv4Network(destination, strict=False) if destination else None
        except ValueError:
            net = None
        if net is not None:
            x["route_prefix"] = float(net.prefixlen)
            x["route_default"] = float(net.prefixlen == 0)
    if detected.change_type in ("ospf_area", "ospf_network") and iface is not None:
        x["ospf_leaves_backbone"] = float(iface.ospf_area == 0 and (p.get("area") not in (0, None) or p.get("action") == "remove"))
    x["params_count"] = float(len([v for v in p.values() if v not in (None, "", [])]))
    return x


def _breadth(spec) -> float:
    """1.0 for 'any', smaller for narrower prefixes (host = 0)."""
    text = str(spec or "any").strip().lower()
    if text in ("any", "0.0.0.0/0"):
        return 1.0
    if text.startswith("host "):
        return 0.0
    try:
        return (32 - ipaddress.IPv4Network(text, strict=False).prefixlen) / 32
    except ValueError:
        return 0.5


PEER_METRICS = ("interfaces", "up_share", "acl_rules", "acl_lists", "vlans", "routes", "trunk_ports", "access_ports",
                "routed_ports", "errors", "half_duplex", "mtu_nonstandard", "ospf_ifaces", "hello_values")


def device_metrics(device) -> dict[str, float]:
    ifaces = list(device.interfaces.values())
    return {
        "interfaces": float(len(ifaces)),
        "up_share": sum(1 for i in ifaces if i.up) / max(len(ifaces), 1),
        "acl_rules": float(len(device.acl)), "acl_lists": float(len(device.acl_lists())),
        "vlans": float(len(device.vlans)), "routes": float(len(device.routes)),
        "trunk_ports": float(sum(1 for i in ifaces if i.mode == "trunk")),
        "access_ports": float(sum(1 for i in ifaces if i.mode == "access")),
        "routed_ports": float(sum(1 for i in ifaces if i.ip)),
        "errors": float(sum(i.error_count or 0 for i in ifaces)),
        "half_duplex": float(sum(1 for i in ifaces if i.duplex == "half")),
        "mtu_nonstandard": float(sum(1 for i in ifaces if i.mtu not in (None, 1500))),
        "ospf_ifaces": float(sum(1 for i in ifaces if i.ospf_area is not None)),
        "hello_values": float(len({i.ospf_hello or 10 for i in ifaces if i.ospf_area is not None})),
    }


def role_of(device) -> str:
    return "router" if device.type in ("router", "firewall") else "l3switch" if device.l3_switch else \
        "switch" if device.is_switch else "host"


RULE_FAMILIES = ("LINK", "IP", "ROUTE", "OSPF", "ACL", "VLAN", "L2", "PHY", "SEC", "NAME")
RCA_FEATURES = tuple(f"family:{f}" for f in RULE_FAMILIES) + (
    "severity", "risk_score", "explains_share", "explains_flows", "on_first_break", "on_broken_path",
    "devices", "links", "max_path_share", "infra_device", "host_device", "failing_flows", "findings_total",
    "same_device_findings")


def rca_features(model, ctx: dict, finding, failing: list, findings: list) -> dict[str, float]:
    """Features of one finding as a root-cause candidate for the failing flows of a network."""
    family = next((f for f in sorted(RULE_FAMILIES, key=len, reverse=True) if finding.rule_id.startswith(f)), "")
    x = dict.fromkeys(RCA_FEATURES, 0.0)
    if family:
        x[f"family:{family}"] = 1.0
    severity = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    x["severity"] = float(severity.get(finding.severity or "MEDIUM", 1))
    x["risk_score"] = float((finding.detail.get("risk") or {}).get("score", 0))
    x["explains_flows"] = float(len(finding.related_flows))
    x["explains_share"] = len(finding.related_flows) / max(len(failing), 1)
    devices = set(finding.device_ids)
    x["on_first_break"] = float(bool(devices & {f.baseline.fail_device for f in failing if f.baseline.fail_device}))
    x["on_broken_path"] = float(bool(devices & {d for f in failing for d in f.baseline.path}))
    x["devices"] = float(len(devices))
    x["links"] = float(len(finding.link_ids))
    x["max_path_share"] = max((ctx["dev_load"].get(d, 0) / ctx["total"] for d in devices), default=0.0)
    x["infra_device"] = float(any(not model.devices[d].is_host for d in devices if d in model.devices))
    x["host_device"] = float(any(model.devices[d].is_host for d in devices if d in model.devices))
    x["failing_flows"] = float(len(failing))
    x["findings_total"] = float(len(findings))
    x["same_device_findings"] = float(sum(1 for other in findings if other is not finding and devices & set(other.device_ids)))
    return x


def vector(x: dict[str, float], features=CHANGE_FEATURES) -> list[float]:
    return [float(x.get(f, 0.0)) for f in features]


# ------------------------------------------------------------------ link-pair tokens
def _norm(value, default=None):
    return "none" if value in (None, default) else str(value).lower()


def link_tokens(model, link) -> list[str]:
    a_dev, b_dev = model.devices.get(link.a_dev), model.devices.get(link.b_dev)
    a, b = model.iface(link.a_dev, link.a_if), model.iface(link.b_dev, link.b_if)
    if a is None or b is None or a_dev is None or b_dev is None:
        return []
    pair = lambda u, v: "|".join(sorted((u, v)))  # noqa: E731
    tokens = [f"types:{pair(a_dev.type, b_dev.type)}", f"mode:{pair(_norm(a.mode), _norm(b.mode))}"]
    tokens.append(f"duplex:{pair(_norm(a.duplex), _norm(b.duplex))}")
    tokens.append("speed:" + ("same" if a.speed_mbps == b.speed_mbps else "one-unset" if None in (a.speed_mbps, b.speed_mbps)
                              else f"diff-{_ratio(a.speed_mbps, b.speed_mbps)}"))
    tokens.append("mtu:" + ("same" if (a.mtu or 1500) == (b.mtu or 1500) else
                            "same-default" if a.mtu in (None, 1500) and b.mtu in (None, 1500) else "diff"))
    tokens.append(f"mtu-raw:{pair(_norm(a.mtu), _norm(b.mtu))}")
    if a.mode == "trunk" or b.mode == "trunk":
        tokens.append("native:" + ("same" if (a.native_vlan or 1) == (b.native_vlan or 1) else "diff"))
        sa, sb = set(a.allowed_vlans or []), set(b.allowed_vlans or [])
        tokens.append("allowed:" + ("same" if sa == sb else "subset" if sa < sb or sb < sa else "diff"))
    if a.mode == "access" and b.mode == "access":
        tokens.append("access-vlan:" + ("same" if (a.vlan or 1) == (b.vlan or 1) else "diff"))
    if a.ip and b.ip:
        same = a.network is not None and a.network == b.network
        tokens.append("subnet:" + ("same" if same else "diff"))
        if a.ospf_area is not None or b.ospf_area is not None:
            tokens.append("ospf-area:" + ("same" if a.ospf_area == b.ospf_area else "diff"))
            if a.ospf_area is not None and b.ospf_area is not None and 0 in (a.ospf_area, b.ospf_area) and a.ospf_area != b.ospf_area:
                tokens.append("ospf-area:backbone-vs-other")
            ha, hb = a.ospf_hello or 10, b.ospf_hello or 10
            da, db = a.ospf_dead or ha * 4, b.ospf_dead or hb * 4
            tokens.append("ospf-hello:" + ("same" if ha == hb else "diff"))
            tokens.append("ospf-dead:" + ("same" if da == db else "diff"))
    for side in (a, b):
        errors = side.error_count or 0
        tokens.append("errors:" + ("none" if errors == 0 else "low" if errors < 20 else "medium" if errors < 500 else "high"))
        tokens.append(f"status:{side.status}")
        if side.duplex == "half":
            tokens.append("half-duplex-side")
    return tokens


def _ratio(u, v) -> str:
    r = max(u, v) / max(min(u, v), 1)
    return "10x" if r >= 9 else "small"


# ------------------------------------------------------------------ syslog tokens
_MNEMONIC = re.compile(r"%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+)")
_NUMERIC = re.compile(r"\b\d+(\.\d+)*\b")


def syslog_tokens(line: str) -> list[str]:
    tokens = []
    m = _MNEMONIC.search(line)
    text = line
    if m:
        facility, severity, mnemonic = m.groups()
        tokens += [f"fac:{facility}", f"sev:{severity}", f"mn:{mnemonic}", f"fm:{facility}-{mnemonic}"]
        text = line[m.end():]
    text = re.sub(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", " MAC ", text.lower())
    text = _NUMERIC.sub(" N ", text)
    words = [w for w in re.findall(r"[a-z_\-]{3,}|MAC", text) if w not in ("the", "and", "for", "from", "with")]
    tokens += [f"w:{w}" for w in words]
    tokens += [f"b:{u}_{v}" for u, v in zip(words, words[1:])]
    return tokens


def log1p(value: float) -> float:
    return math.log1p(max(value, 0.0))
