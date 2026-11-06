"""Impact Engine: which flows, devices, links and paths does the change affect?

Flows evaluated:
  * required flows (network intents), when the network defines any;
  * otherwise every host-to-host pair that works today (implicit flows);
  * every host's reachability to its default gateway.
Each flow is evaluated on the baseline and the candidate model; the
difference is the impact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations

from backend.services.forwarding import FlowAnalyzer, FlowResult
from backend.services.network_model import NetworkModel

CRITICALITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

FAILURE_TEXT = {
    "media_mismatch": lambda d: d["reason"],
    "acl_deny": lambda d: (f"dropped by the implicit deny on {d['device']}" if d.get("implicit")
                           else f"denied by {d['device']} ACL rule '{d['rule']}'"),
    "interface_down": lambda d: (f"gateway {d['gateway']} is unavailable because {d['device']} {d['interface']} is down"
                                 if d.get("gateway") else f"{d['device']} {d['interface']} is down"),
    "link_down": lambda d: f"{d['device']} {d['interface']} is {d.get('status', 'down')}",
    "vlan_unavailable": lambda d: f"VLAN {d['vlan']} is not defined on {d['switch']}",
    "vlan_mismatch": lambda d: f"{d['host']} is in VLAN {d['vlan']} instead of VLAN {d['expected_vlan']}",
    "subnet_mismatch": lambda d: (f"{d['host']} ({d['host_cidr']}) and gateway {d['router']} {d['interface']} "
                                  f"({d['router_cidr']}) are in different subnets") if "host_cidr" in d
                                 else f"{d['a']} and {d['b']} are in different subnets",
    "gateway_mismatch": lambda d: f"{d['host']} default gateway {d['gateway']} is not reachable",
    "no_default_gateway": lambda d: f"{d['host']} has no usable default gateway",
    "ospf_adjacency": lambda d: (f"OSPF adjacency {d.get('link', 'on the path')} is down "
                                 f"({'area mismatch' if d['state'] == 'mismatch' else 'OSPF missing on one side'})"),
    "ospf_network_missing": lambda d: f"{d['network']} is not advertised into OSPF",
    "no_route": lambda d: (f"{d['device']} has no route to {d['destination']}"
                           + (f" (its default route leads to {d['via_device']})" if d.get("via_device") else "")),
    "invalid_next_hop": lambda d: f"{d['device']} route {d['route']} has an invalid next hop",
    "routing_loop": lambda d: f"routing loop ({d['loop']})" if d.get("loop") else f"routing loop at {d['device']}",
    "wrong_segment": lambda d: f"{d['device']} delivers {d['destination']} to the wrong segment ({d['interface']})",
    "incomplete": lambda d: "the topology data is incomplete",
    "not_connected": lambda d: "the device is not connected",
    "no_ip": lambda d: "the device has no IP address",
}


def describe_failure(result: FlowResult) -> str:
    if result.reachable:
        return "reachable"
    text = FAILURE_TEXT.get(result.code, lambda d: result.code or "unreachable")
    try:
        reason = text(result.detail)
    except KeyError:
        reason = result.code or "unreachable"
    if result.detail.get("direction") == "return":
        reason += " (return path)"
    return reason


@dataclass
class Flow:
    key: str
    name: str
    kind: str  # intent / implicit / gateway
    src: int
    dst: int | None
    src_name: str
    dst_name: str
    protocol: str = "ip"
    port: int | None = None
    expected: str | None = None
    criticality: str = "medium"
    src_ip: str | None = None
    dst_ip: str | None = None
    baseline: FlowResult | None = None
    candidate: FlowResult | None = None
    impact: dict = field(default_factory=dict)


def _ip_of(analyzer: FlowAnalyzer, device_id: int) -> str | None:
    att = analyzer.attachment(device_id)
    return att.nic.ip if att.nic else None


# Failures that do not mean "this flow should work": policy (ACL) or incomplete topology data.
_NOT_EXPECTED = {"acl_deny", "not_connected", "no_ip", "incomplete"}


def _audit_expectation(analyzer: FlowAnalyzer, flow: Flow) -> str | None:
    """Health check without required flows: which failing host pairs are still expected to work?

    With no earlier state to compare against, every host pair that fails for an addressing,
    VLAN, link or routing reason is treated as broken. Pairs denied by an ACL are assumed to be
    intentional, and hosts on a segment without any router are assumed to be isolated by design.
    """
    result = flow.baseline
    if result.reachable:
        return "allow"
    if result.code in _NOT_EXPECTED:
        return None
    if result.code == "no_default_gateway" and result.fail_device is not None:
        if not analyzer.attachment(result.fail_device).candidates:
            return None
    return "allow"


def build_flows(model: NetworkModel, analyzer: FlowAnalyzer, audit: bool = False) -> list[Flow]:
    """audit=True is the health-check mode (no proposed change): see _audit_expectation."""
    flows: list[Flow] = []
    names = {d.id: d.name for d in model.devices.values()}
    if model.intents:
        for intent in model.intents:
            flows.append(Flow(f"intent-{intent.id}", intent.name, "intent", intent.src, intent.dst,
                              names[intent.src], names[intent.dst], intent.protocol, intent.port,
                              intent.expected, intent.criticality))
    else:
        hosts = sorted((d for d in model.devices.values() if d.is_host), key=lambda d: d.name)
        for a, b in combinations(hosts, 2):
            flows.append(Flow(f"pair-{a.id}-{b.id}", f"{a.name} ↔ {b.name}", "implicit", a.id, b.id, a.name, b.name))
    for host in sorted((d for d in model.devices.values() if d.is_host), key=lambda d: d.name):
        flows.append(Flow(f"gw-{host.id}", f"{host.name} default gateway", "gateway", host.id, None,
                          host.name, host.gateway or "gateway", expected="allow", criticality="medium"))
    for flow in flows:
        flow.src_ip = _ip_of(analyzer, flow.src)
        flow.dst_ip = _ip_of(analyzer, flow.dst) if flow.dst else None
        flow.baseline = _evaluate(analyzer, flow)
        if flow.kind in ("implicit", "gateway"):
            flow.expected = (_audit_expectation(analyzer, flow) if audit
                             else ("allow" if flow.baseline.reachable else None))
    return flows


def _evaluate(analyzer: FlowAnalyzer, flow: Flow) -> FlowResult:
    if flow.kind == "gateway":
        return analyzer.gateway_reachable(flow.src)
    return analyzer.evaluate(flow.src, flow.dst, flow.protocol, flow.port)


def evaluate_candidate(flows: list[Flow], analyzer: FlowAnalyzer) -> None:
    for flow in flows:
        flow.candidate = _evaluate(analyzer, flow)


def compare(flows: list[Flow], baseline: NetworkModel, candidate: NetworkModel,
            evidence_incomplete: bool = False) -> list[dict]:
    """Build one impact record per flow (affected and unaffected).

    evidence_incomplete: the network comes from simulated discovery or lacks configuration,
    so missing connection/endpoint evidence is UNKNOWN rather than FAIL (as in health_service).
    """
    impacts = []
    for flow in flows:
        before, after = flow.baseline, flow.candidate
        worsened = (flow.expected == "allow" and not before.reachable and not after.reachable
                    and _progress(after) < _progress(before))
        if worsened:
            # Already failing, but the change adds a new failure earlier on the path.
            status = "broken"
        elif before.reachable and not after.reachable:
            # For an isolation (deny) intent, losing reachability restores the required policy.
            status = "restored" if flow.expected == "deny" else "broken"
        elif not before.reachable and after.reachable:
            status = "violation" if flow.expected == "deny" else "restored"
        elif before.reachable and after.reachable and before.path != after.path:
            status = "rerouted"
        else:
            status = "unchanged"
        shown = before if (status in ("broken",) or not after.path) else after
        model = baseline if shown is before else candidate
        proto = flow.protocol.upper() + (f"/{flow.port}" if flow.port else "")
        if worsened:
            explanation = (f"{flow.src_name} → {flow.dst_name} already failed ({describe_failure(before)}); the change "
                           f"adds a failure earlier on its path: {describe_failure(after)}.")
        elif status == "broken":
            explanation = f"{flow.src_name} → {flow.dst_name} is no longer reachable: {describe_failure(after)}."
        elif status == "violation":
            explanation = f"{flow.src_name} → {flow.dst_name} must be denied but is now reachable."
        elif status == "restored" and flow.expected == "deny":
            explanation = f"{flow.src_name} → {flow.dst_name} is isolated again as required ({describe_failure(after)})."
        elif status == "restored":
            explanation = f"{flow.src_name} → {flow.dst_name} becomes reachable after the change."
        elif status == "rerouted":
            explanation = f"{flow.src_name} → {flow.dst_name} still works but takes a different path."
        elif after.reachable:
            explanation = f"Unaffected: {flow.src_name} → {flow.dst_name} remains reachable."
        else:
            explanation = f"Unaffected: {flow.src_name} → {flow.dst_name} remains blocked ({describe_failure(after)})."
        # Same rule as the health check: missing evidence is UNKNOWN only where evidence can be incomplete.
        unknown = flow.expected is None or (evidence_incomplete and after.code in ("incomplete", "not_connected", "no_ip"))
        passed = not unknown and after.reachable == (flow.expected == "allow")
        impact = {
            "expected": flow.expected,
            "result": "unknown" if unknown else "passed" if passed else "failed",
            "reason": None if unknown or passed else
                      "Isolation intent is violated; the destination is reachable." if flow.expected == "deny" else describe_failure(after),
            "flow_key": flow.key, "service": flow.name, "kind": flow.kind,
            "source_device": flow.src_name, "destination_device": flow.dst_name,
            "protocol": flow.protocol if flow.kind != "gateway" else None,
            "port": flow.port, "protocol_label": proto if flow.kind != "gateway" else "gateway",
            "criticality": flow.criticality, "expected": flow.expected,
            "impact_type": {"gateway": "gateway_reachability", "intent": "service_flow"}.get(flow.kind, "connectivity"),
            "status": status, "affected": status != "unchanged",
            "baseline_status": before.status, "candidate_status": after.status,
            "explanation": explanation,
            "path": [model.devices[i].name for i in shown.path if i in model.devices],
            "path_device_ids": list(shown.path), "path_link_ids": list(shown.links),
            "failure_link_id": after.fail_link if status == "broken" else None,
            "failure_device": (candidate.devices[after.fail_device].name
                               if status == "broken" and after.fail_device in candidate.devices else None),
            "failure_reason": describe_failure(after) if status == "broken" else None,
        }
        flow.impact = impact
        impacts.append(impact)
    impacts.sort(key=lambda i: (not i["affected"], i["kind"] == "gateway",
                                CRITICALITY_ORDER.get(i["criticality"], 9), i["service"]))
    return impacts


def _progress(result: FlowResult) -> int:
    """How far a failing flow gets: host attachment < forward routing < return routing < ACL."""
    if result.code == "acl_deny":  # blocked after routing worked: later ACLs on the path rank higher
        return 1000 + (result.path.index(result.fail_device) if result.fail_device in result.path else 0)
    if not result.path:
        return 0
    return (500 if result.detail.get("direction") == "return" else 100) + result.detail.get("reach", len(result.path))


def progressed_flows(flows: list[Flow]) -> set[str]:
    """Required flows that failed before and still fail, but now get further than before.

    The change removed the first failure; the next failure was already there, hidden behind it.
    """
    return {
        flow.name for flow in flows
        if flow.expected == "allow" and flow.baseline and flow.candidate
        and not flow.baseline.reachable and not flow.candidate.reachable
        and _progress(flow.candidate) > _progress(flow.baseline)
    }


def summarise(impacts: list[dict], findings: list, baseline: NetworkModel) -> dict:
    affected = [i for i in impacts if i["affected"]]
    broken = [i for i in affected if i["status"] in ("broken", "violation")]
    device_ids, link_ids = set(), set()
    for finding in findings:
        device_ids.update(finding.device_ids)
        link_ids.update(finding.link_ids)
    for impact in broken:
        if impact["failure_link_id"]:
            link_ids.add(impact["failure_link_id"])
    names = [baseline.devices[d].name for d in device_ids if d in baseline.devices]
    paths = [i["path"] for i in broken if i["kind"] != "gateway" and i["path"]]
    return {
        "affected_device_ids": sorted(device_ids),
        "affected_devices": sorted(names),
        "affected_link_ids": sorted(link_ids),
        "affected_paths": paths,
        "affected_count": len(affected),
        "broken_count": len(broken),
        "evaluated_count": len(impacts),
    }
