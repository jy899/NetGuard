"""Builds NetGuard's training datasets (data/datasets/*.jsonl) by simulation on its own network model.

Topologies: synthetic campuses (backend.ai.synth.campus, imported through the configuration importer) and the
built-in example networks. Labels come from NetGuard's deterministic engines (forwarding, validation, risk) run on
a copy of each model, a "digital twin" labelling:

* change_outcomes.jsonl - a random proposed change: features from the baseline only; labels from the simulated
  candidate over every host pair (harm, number of broken flows and endpoints, new findings, deterministic risk).
* root_cause.jsonl      - for harmful changes: which validation findings lay on the broken paths (rule priors).
* fix_outcomes.jsonl    - a fault injected into a healthy network, each candidate fix from the Fix Engine, and
  whether applying it restores the original healthy state (a true root-cause repair, not a workaround).
* link_faults.jsonl     - cross-device link misconfigurations with benign variation (tokens + label).
* syslog.jsonl          - Cisco IOS syslog messages by fault category.

build() writes a manifest with counts, seeds and the generator version.
"""
from __future__ import annotations

import json
import os
import random
import tempfile
import time
from copy import deepcopy
from itertools import combinations
from pathlib import Path

from backend.ai import features as F
from backend.ai import synth

MAX_PAIRS = 90


def _flows(model, analyzer, rng):
    """Required flows plus a sample of every host pair (expectations from the healthy baseline)."""
    from backend.services.impact_engine import Flow, _evaluate, _ip_of, build_flows
    flows = [f for f in build_flows(model, analyzer, audit=False) if f.kind == "intent"]
    hosts = sorted((d for d in model.devices.values() if d.is_host), key=lambda d: d.name)
    pairs = list(combinations(hosts, 2))
    rng.shuffle(pairs)
    for a, b in pairs[:MAX_PAIRS]:
        flow = Flow(f"pair-{a.id}-{b.id}", f"{a.name} ↔ {b.name}", "implicit", a.id, b.id, a.name, b.name)
        flow.src_ip, flow.dst_ip = _ip_of(analyzer, a.id), _ip_of(analyzer, b.id)
        flow.baseline = _evaluate(analyzer, flow)
        flow.expected = "allow" if flow.baseline.reachable else None
        flows.append(flow)
    return flows


class Twin:
    """A healthy network model and its baseline evaluation, for simulating changes in memory."""

    def __init__(self, model, rng):
        from backend.services import validation_engine
        from backend.services.forwarding import FlowAnalyzer
        self.model, self.rng = model, rng
        self.analyzer = FlowAnalyzer(model)
        self.flows = _flows(model, self.analyzer, rng)
        self.findings = validation_engine.run(model, self.analyzer, self.flows, "baseline")
        self.ctx = F.topology_context(model, self.flows)

    def detect(self, change_type, device_id, interface_id, params, model=None):
        from backend.core.errors import NetGuardError
        from backend.services import change_detector
        try:
            return change_detector.detect(model or self.model, device_id, interface_id, change_type, params)
        except (NetGuardError, ValueError, KeyError, TypeError):
            return None

    def simulate(self, detected, base_model=None, base_flows=None, base_findings=None):
        """Outcome of a detected change on base_model (default: the healthy model)."""
        from backend.services import change_detector, impact_engine, risk_engine, validation_engine
        from backend.services.forwarding import FlowAnalyzer
        base_model = base_model or self.model
        base_flows = base_flows if base_flows is not None else self.flows
        base_findings = base_findings if base_findings is not None else self.findings
        candidate = change_detector.apply(base_model, detected)
        analyzer = FlowAnalyzer(candidate)
        for flow in base_flows:
            flow.candidate = impact_engine._evaluate(analyzer, flow)
        found = validation_engine.run(candidate, analyzer, base_flows, "candidate")
        new, _, resolved = validation_engine.diff(base_findings, found)
        impacts = impact_engine.compare(base_flows, base_model, candidate, False)
        risk_engine.relate(new, impacts, {d.name: d.id for d in candidate.devices.values()})
        risk = risk_engine.score(new, impacts, detected.effective, candidate)
        broken = [i for i in impacts if i["status"] in ("broken", "violation")]
        restored = [i for i in impacts if i["status"] == "restored"]
        endpoints = {name for i in broken for name in (i["source_device"], i["destination_device"])}
        failing = [f for f in base_flows if f.expected == "allow" and not f.candidate.reachable
                   or f.expected == "deny" and f.candidate.reachable]
        return {"candidate": candidate, "found": found, "new": new, "resolved": resolved, "impacts": impacts,
                "broken": broken, "restored": restored, "endpoints": endpoints, "risk": risk, "failing": failing}


# ------------------------------------------------------------------ random changes
def random_changes(model, rng, n: int):
    devices = list(model.devices.values())
    infra = [d for d in devices if not d.is_host]
    routers = [d for d in infra if d.is_router]
    switches = [d for d in infra if d.is_switch]
    hosts = [d for d in devices if d.is_host]
    out = []

    def pick_iface(dev, pred=lambda i: True):
        cands = [i for i in dev.interfaces.values() if pred(i)]
        return rng.choice(cands) if cands else None

    def subnet_ip(net):
        return str(net[rng.randint(2, max(2, net.num_addresses - 2))]) if net and net.num_addresses > 4 else None

    while len(out) < n:
        kind = rng.choice(("interface_status", "interface_status", "ip_address", "default_gateway", "ospf_area",
                           "ospf_network", "static_route", "acl_add", "acl_add", "acl_remove", "access_vlan",
                           "vlan_database", "interface_settings", "stp_root", "mgmt_hardening", "trunk_settings",
                           "isolate_endpoint"))
        if kind == "interface_status":
            dev = rng.choice(infra + hosts[:3])
            iface = pick_iface(dev)
            if iface:
                out.append((kind, dev.id, iface.id, {"status": "admin-down" if iface.up else "up"}))
        elif kind == "ip_address":
            dev = rng.choice(routers + hosts)
            iface = pick_iface(dev, lambda i: i.ip)
            if iface:
                mode = rng.random()
                if mode < 0.4 and hosts:  # duplicate another host's address
                    other = rng.choice(hosts)
                    ip = next((i.ip for i in other.interfaces.values() if i.ip), None)
                elif mode < 0.7:
                    ip = subnet_ip(iface.network)  # another address in the same subnet
                else:
                    ip = f"10.{rng.randint(60, 90)}.{rng.randint(0, 250)}.{rng.randint(2, 250)}"
                if ip:
                    out.append((kind, dev.id, iface.id, {"ip_address": ip, "subnet_mask": iface.mask}))
        elif kind == "default_gateway" and hosts:
            dev = rng.choice(hosts)
            nic = next((i for i in dev.interfaces.values() if i.ip), None)
            gw = subnet_ip(nic.network) if nic and rng.random() < 0.6 else f"10.{rng.randint(60, 90)}.0.1"
            out.append((kind, dev.id, None, {"gateway": gw}))
        elif kind == "ospf_area" and routers:
            dev = rng.choice(routers)
            iface = pick_iface(dev, lambda i: i.ospf_area is not None)
            if iface:
                out.append((kind, dev.id, iface.id, {"area": rng.choice((0, 1, 2))}))
        elif kind == "ospf_network" and routers:
            dev = rng.choice(routers)
            iface = pick_iface(dev, lambda i: i.ip)
            if iface:
                out.append((kind, dev.id, iface.id, {"action": "remove" if iface.ospf_area is not None else "advertise",
                                                      "area": 0}))
        elif kind == "static_route" and routers:
            dev = rng.choice(routers)
            if dev.routes and rng.random() < 0.4:
                out.append((kind, dev.id, None, {"action": "remove", "route_id": rng.choice(dev.routes).id}))
            else:
                hops = [i for d in routers if d.id != dev.id for i in d.interfaces.values() if i.ip]
                hop = rng.choice(hops).ip if hops and rng.random() < 0.7 else f"10.{rng.randint(60, 90)}.0.1"
                nets = [i.network for d in devices for i in d.interfaces.values() if i.network]
                dest = str(rng.choice(nets)) if nets and rng.random() < 0.7 else "0.0.0.0/0"
                out.append((kind, dev.id, None, {"action": "add", "destination": dest, "next_hop": hop}))
        elif kind == "acl_add" and routers:
            dev = rng.choice(routers)
            nets = [str(i.network) for d in devices for i in d.interfaces.values() if i.network]
            hosts_ip = [i.ip for d in hosts for i in d.interfaces.values() if i.ip]
            spec = lambda: rng.choice(("any", rng.choice(nets) if nets else "any",  # noqa: E731
                                       (rng.choice(hosts_ip) + "/32") if hosts_ip else "any"))
            protocol = rng.choice(("ip", "tcp", "tcp", "udp", "icmp"))
            params = {"action": rng.choice(("deny", "deny", "permit")), "protocol": protocol, "source": spec(),
                      "destination": spec(), "sequence": rng.choice((5, 15, 25, 105))}
            if protocol in ("tcp", "udp"):
                params["port"] = rng.choice((22, 53, 80, 443, 445))
            lists = [name for name in dev.acl_lists() if name]
            if lists:
                params["acl_name"] = rng.choice(lists)
            out.append((kind, dev.id, None, params))
        elif kind == "acl_remove":
            with_rules = [d for d in routers if d.acl]
            if with_rules:
                dev = rng.choice(with_rules)
                out.append((kind, dev.id, None, {"rule_id": rng.choice(dev.acl).id}))
        elif kind == "access_vlan" and switches:
            dev = rng.choice(switches)
            iface = pick_iface(dev, lambda i: i.mode == "access")
            if iface:
                vlans = list(dev.vlans) or [10]
                out.append((kind, dev.id, iface.id, {"vlan_id": rng.choice(vlans + [rng.randint(500, 600)])}))
        elif kind == "vlan_database" and switches:
            dev = rng.choice(switches)
            if dev.vlans and rng.random() < 0.6:
                out.append((kind, dev.id, None, {"action": "remove", "vlan_id": rng.choice(list(dev.vlans))}))
            else:
                out.append((kind, dev.id, None, {"action": "add", "vlan_id": rng.randint(300, 400), "name": "NEW"}))
        elif kind == "interface_settings":
            dev = rng.choice(infra)
            iface = pick_iface(dev)
            if iface:
                setting = rng.choice(("duplex", "mtu", "ospf_hello", "speed_mbps"))
                value = {"duplex": rng.choice(("half", "full", "auto")), "mtu": rng.choice((1400, 1500, 9000)),
                         "ospf_hello": rng.choice((5, 10, 30)), "speed_mbps": rng.choice((100, 1000))}[setting]
                out.append((kind, dev.id, iface.id, {setting: value}))
        elif kind == "stp_root" and switches:
            dev = rng.choice(switches)
            vlans = list(dev.vlans) or [1]
            out.append((kind, dev.id, None, {"vlan": rng.choice(vlans), "priority": rng.choice((0, 4096, 8192))}))
        elif kind == "mgmt_hardening":
            dev = rng.choice(infra)
            out.append((kind, dev.id, None, {"action": rng.choice(("ssh_only", "disable_http", "remove_snmp_communities"))}))
        elif kind == "trunk_settings" and switches:
            dev = rng.choice(switches)
            iface = pick_iface(dev, lambda i: i.mode == "trunk")
            if iface:
                allowed = list(iface.allowed_vlans or list(dev.vlans) or [1])
                if rng.random() < 0.5 and len(allowed) > 1:
                    allowed.remove(rng.choice(allowed))
                out.append((kind, dev.id, iface.id, {"allowed_vlans": allowed} if rng.random() < 0.7
                            else {"native_vlan": rng.choice((1, 99, 999))}))
        elif kind == "isolate_endpoint" and switches:
            dev = rng.choice(switches)
            iface = pick_iface(dev, lambda i: i.mode == "access")
            if iface:
                out.append((kind, dev.id, iface.id, {"vlan_id": rng.randint(700, 799), "name": "ISOLATED"}))
    return out


# ------------------------------------------------------------------ builders
def _networks(db, user, synthetic: int, seed: int):
    from backend.services import config_import, demo_topology
    from backend.services.network_model import load_model
    for scenario in ("healthy", "vlan", "routing", "interface", "acl", "loop", "ip-conflict", "missing-link", "mixed"):
        network = demo_topology.create_analysis_demo(db, user, scenario=scenario)
        yield f"example:{scenario}", load_model(db, network.id)
    for s in range(synthetic):
        campus = synth.campus(seed * 1000 + s)
        result = config_import.import_network(db, user, f"Synthetic campus {s}", campus["configs"], campus["endpoints"],
                                              campus["flows"])
        yield f"campus:{seed * 1000 + s}", load_model(db, result["network_id"])


def build(out_dir: Path, synthetic: int = 60, changes_per_network: int = 45, seed: int = 2026,
          log=print) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    tmp = tempfile.mkdtemp(prefix="netguard-datasets-")
    os.environ["NETGUARD_DATA_DIR"] = tmp
    os.environ["NETGUARD_DATABASE_URL"] = f"sqlite:///{Path(tmp, 'build.db').as_posix()}"
    from backend.database.init_db import init_db
    from backend.database.session import SessionLocal
    from backend.models import User
    init_db()
    rng = random.Random(seed)
    files = {name: (out_dir / f"{name}.jsonl").open("w", encoding="utf-8")
             for name in ("change_outcomes", "root_cause", "fix_outcomes", "link_faults", "syslog", "device_profiles")}
    counts = dict.fromkeys(files, 0)

    def write(name, row):
        files[name].write(json.dumps(row, separators=(",", ":")) + "\n")
        counts[name] += 1

    with SessionLocal() as db:
        user = db.query(User).first()
        for source, model in _networks(db, user, synthetic, seed):
            twin = Twin(model, rng)
            harmful_samples, background = [], []
            if source.startswith("campus:") or source == "example:healthy":
                for device in model.devices.values():
                    if not device.is_host:
                        write("device_profiles", {"source": source, "role": F.role_of(device), "m": F.device_metrics(device)})
            for change_type, device_id, interface_id, params in random_changes(model, rng, changes_per_network):
                detected = twin.detect(change_type, device_id, interface_id, params)
                if detected is None:
                    continue
                outcome = twin.simulate(detected)
                x = F.change_features(model, twin.ctx, detected)
                severe = any(f.severity in ("CRITICAL", "HIGH") for f in outcome["new"])
                harmful = bool(outcome["broken"]) or severe
                write("change_outcomes", {
                    "source": source, "change_type": change_type, "x": F.vector(x),
                    "harmful": int(harmful), "blast_flows": len(outcome["broken"]),
                    "blast_endpoints": len(outcome["endpoints"]), "new_findings": len(outcome["new"]),
                    "risk_level": outcome["risk"]["level"], "risk_total": outcome["risk"]["total"],
                    "evaluated_flows": len(twin.flows)})
                if harmful and outcome["broken"]:
                    harmful_samples.append(detected)
                elif outcome["new"] and not outcome["broken"]:
                    background.append(detected)  # findings that break nothing: distractors for root-cause analysis
            # Fault injection (with unrelated background findings): root-cause candidates and fix outcomes.
            for n, detected in enumerate(harmful_samples[:6]):
                noise = rng.sample(background, min(len(background), rng.choice((0, 1, 2, 2))))
                others = [h for h in harmful_samples if h.device_id != detected.device_id]
                second = rng.choice(others) if others and rng.random() < 0.4 else None
                _fix_rows(twin, detected, source, write, f"{source}#{n}",
                          [b for b in noise if b.device_id != detected.device_id], second)
            # Link faults on this topology.
            links = list(model.links.values())
            rng.shuffle(links)
            for link in links[:14]:
                a0, b0 = model.iface(link.a_dev, link.a_if), model.iface(link.b_dev, link.b_if)
                trials = 2 + (5 if a0 and b0 and "trunk" in (a0.mode, b0.mode) else 0) + \
                    (3 if a0 and b0 and a0.ip and b0.ip else 0)
                for _ in range(trials):
                    trial = deepcopy(model)
                    a, b = trial.iface(link.a_dev, link.a_if), trial.iface(link.b_dev, link.b_if)
                    if a is None or b is None:
                        continue
                    synth.benign_noise(rng, a, b)
                    fault = rng.choice([f for f in synth.LINK_FAULTS if synth.applicable(f, a, b)] + ["clean"] * 2)
                    if fault != "clean":
                        synth.inject_link_fault(rng, fault, a, b)
                    tokens = F.link_tokens(trial, trial.links[link.id])
                    if tokens:
                        write("link_faults", {"source": source, "tokens": tokens, "label": fault})
            log(f"{source}: {counts}")
        srng = random.Random(seed + 1)
        for category in synth.SYSLOG_CATEGORIES:
            for _ in range(450 if category != "normal" else 900):
                write("syslog", {"line": synth.syslog(srng, category), "label": category})
    for handle in files.values():
        handle.close()
    manifest = {"generator_version": synth.GENERATOR_VERSION, "seed": seed, "synthetic_campuses": synthetic,
                "example_networks": 9, "changes_per_network": changes_per_network, "counts": counts,
                "feature_names": list(F.CHANGE_FEATURES), "built_seconds": round(time.time() - started, 1),
                "provenance": "Synthetic. Topologies are generated Cisco IOS configurations and NetGuard's example "
                              "networks; labels come from NetGuard's deterministic forwarding, validation and risk "
                              "engines run on a copy of each model. Syslog lines follow Cisco IOS message formats "
                              "with randomised fields. No field data is included."}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _state(model, template_flows):
    """Evaluated flows, findings and failing flow keys of a model."""
    from backend.services import impact_engine, validation_engine
    from backend.services.forwarding import FlowAnalyzer
    analyzer = FlowAnalyzer(model)
    flows = deepcopy(template_flows)
    for flow in flows:
        flow.baseline = impact_engine._evaluate(analyzer, flow)
    findings = validation_engine.run(model, analyzer, flows, "baseline")
    failing = {f.key for f in flows if f.expected == "allow" and not f.baseline.reachable
               or f.expected == "deny" and f.baseline.reachable}
    return analyzer, flows, findings, failing


def _apply_all(model, changes):
    from backend.services import change_detector
    for change in changes:
        try:
            model = change_detector.apply(model, change)
        except Exception:  # noqa: BLE001 - a change that no longer applies is skipped
            continue
    return model


def _owns(fault, model, finding) -> bool:
    device = model.devices.get(fault.device_id)
    link = model.link_for_iface(fault.device_id, device.interfaces[fault.interface_id]) \
        if device is not None and fault.interface_id in device.interfaces else None
    return fault.device_id in finding.device_ids or (link is not None and link.id in finding.link_ids)


def _fix_rows(twin: Twin, fault, source: str, write, case: str, background=(), second=None) -> None:
    """Inject `fault` (and sometimes a second, unrelated fault) on top of harmless background findings, rank the
    findings as root-cause candidates and label each Fix Engine repair by whether it removes its own fault: the
    network then matches the state without that fault (the other fault may remain)."""
    from backend.services import fix_engine, risk_engine
    noisy = _apply_all(twin.model, background)
    _, _, noisy_findings, noisy_failing = _state(noisy, twin.flows)
    if noisy_failing:
        noisy = twin.model  # the background broke a flow after all: drop it
        noisy_findings = twin.findings
    healthy_keys = set(noisy_findings)
    faults = [fault] + ([second] if second is not None else [])
    faulty = _apply_all(noisy, faults)
    analyzer, flows, findings, failing_keys = _state(faulty, twin.flows)
    if not failing_keys:
        return
    failing_before = [f for f in flows if f.key in failing_keys]
    # Reference state for repairing each fault: the network with only the other faults.
    references = {}
    for i, f in enumerate(faults):
        ref_model = _apply_all(noisy, [g for j, g in enumerate(faults) if j != i])
        _, _, ref_findings, ref_failing = _state(ref_model, twin.flows)
        references[i] = (set(ref_findings), ref_failing)
    ctx = F.topology_context(faulty, flows)
    pseudo = [{"service": f.name, "status": "broken" if f.expected == "allow" else "violation",
               "failure_device": faulty.devices[f.baseline.fail_device].name if f.baseline.fail_device in faulty.devices else None,
               "failure_link_id": f.baseline.fail_link, "criticality": f.criticality,
               "impact_type": "service_flow" if f.kind == "intent" else "connectivity",
               "source_device": f.src_name, "destination_device": f.dst_name} for f in failing_before]
    every = list(findings.values())
    names = {d.name: d.id for d in faulty.devices.values()}
    risk_engine.relate(every, pseudo, names)
    for finding in every:
        risk_engine.score_finding(finding, pseudo, faulty, names)
    per_rule = {}
    owner = {}
    for finding in every:
        fault_index = next((i for i, f in enumerate(faults) if finding.key not in healthy_keys and _owns(f, faulty, finding)), None)
        owner[finding.key] = fault_index
        cause = fault_index is not None
        per_rule[(finding.rule_id, cause)] = per_rule.get((finding.rule_id, cause), 0) + 1
        if per_rule[(finding.rule_id, cause)] > 3:
            continue  # one finding per denied flow would otherwise dominate the dataset
        write("root_cause", {"source": source, "case": case, "faults": len(faults), "fault_type": fault.change_type,
                             "rule_id": finding.rule_id, "cause": int(cause),
                             "x": F.vector(F.rca_features(faulty, ctx, finding, failing_before, every), F.RCA_FEATURES)})
    issues = [f for f in every if owner.get(f.key) is not None]
    for finding in issues[:4]:
        ref_keys, ref_failing = references[owner[finding.key]]
        for option in fix_engine.options_for(faulty, analyzer, finding)[:4]:
            detected = twin.detect(option.change_type, option.device_id, option.interface_id, option.parameters, faulty)
            if detected is None:
                continue
            outcome = twin.simulate(detected, faulty, flows, findings)
            remaining = {k for k in outcome["found"] if k not in ref_keys}
            still = {f.key for f in outcome["failing"]} - ref_failing
            restores = not still and not remaining
            row = fix_features(faulty, ctx, finding, option, detected, outcome, len(failing_before))
            write("fix_outcomes", {"source": source, "faults": len(faults), "fault_type": fault.change_type,
                                   "rule_id": finding.rule_id, "fix_type": option.change_type, "x": row,
                                   "restores": int(restores)})


FIX_FEATURES = (
    "resolves_target", "also_resolves", "new_issues", "broken_flows", "restored_flows", "restored_share",
    "risk_total", "same_device", "same_interface", "on_first_break", "caution",
    "work_order", "params_count", "fix_routing", "fix_acl", "fix_vlan", "fix_interface",
    "fix_physical", "fix_security", "dev_path_share", "dev_router", "dev_switch", "dev_host",
)


def fix_features(model, ctx, finding, option, detected, outcome, failing_before: int) -> list[float]:
    """Features of one verified fix candidate (shared with the run-time ranker)."""
    resolved_keys = {f.key for f in outcome["resolved"]}
    first_break = ctx.get("fail_devices", set())
    device = model.devices.get(option.device_id)
    category = detected.category
    x = {
        "resolves_target": float(finding.key in resolved_keys),
        "also_resolves": float(len(resolved_keys - {finding.key})),
        "new_issues": float(len(outcome["new"])),
        "broken_flows": float(len(outcome["broken"])),
        "restored_flows": float(len(outcome["restored"])),
        "restored_share": min(len(outcome["restored"]) / max(len(finding.related_flows), 1), 1.0),
        "risk_total": float(outcome["risk"]["total"]),
        "same_device": float(option.device_id in finding.device_ids),
        "same_interface": float(option.interface_id is not None and option.interface_id == finding.detail.get("interface_id")),
        "on_first_break": float(option.device_id in first_break),
        "caution": float(bool(option.caution)),
        "work_order": float(option.change_type == "physical_remediation"),
        "params_count": float(len([v for v in (option.parameters or {}).values() if v not in (None, "", [])])),
        "fix_routing": float(category == "routing"), "fix_acl": float(category == "acl"),
        "fix_vlan": float(category == "vlan"), "fix_interface": float(category == "ip_interface"),
        "fix_physical": float(category == "physical"), "fix_security": float(category == "security"),
        "dev_path_share": ctx["dev_load"].get(option.device_id, 0) / ctx["total"],
        "dev_router": float(bool(device and device.is_router)), "dev_switch": float(bool(device and device.is_switch)),
        "dev_host": float(bool(device and device.is_host)),
    }
    return [x[k] for k in FIX_FEATURES]
