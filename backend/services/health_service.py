"""Network Health Check: audits the current network and proposes verified fixes.

1. Run every validation rule and every required flow on the stored network.
2. For each issue, ask the Fix Engine for candidate corrective changes.
3. Verify each candidate with the full analysis pipeline (as if it were a
   proposed change): it must resolve the issue and must not introduce new
   issues or break any flow. Candidates are ranked by that verification.

The health check never modifies the network. A fix is only applied when the
engineer reviews it and explicitly applies it (apply_service).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.errors import NetGuardError
from backend.services import analysis_service, demo_topology, fix_engine, impact_engine, network_service, risk_engine, validation_engine
from backend.services.forwarding import FlowAnalyzer
from backend.services.network_model import load_model, presentation_only
from backend.services.rules import RULES, SEVERITY_ORDER
from backend.services.analysis_checks import advisories, coverage_notes

VERDICT_ORDER = {"recommended": 0, "partial": 1, "unsafe": 2}


def _failing_flows(flows: list) -> list:
    failing = []
    for flow in flows:
        result = flow.baseline
        if flow.expected == "allow" and not result.reachable:
            failing.append((flow, "broken"))
        elif flow.expected == "deny" and result.reachable:
            failing.append((flow, "violation"))
    return failing


def _verify(db: Session, network_id: int, option: fix_engine.FixOption, issue_key: str,
            advisory_id: str | None = None) -> dict | None:
    spec = SimpleNamespace(network_id=network_id, device_id=option.device_id, interface_id=option.interface_id,
                           change_type=option.change_type, parameters=option.parameters, reason=None)
    try:
        result = analysis_service.run_pipeline(db, spec, audit=True)
    except NetGuardError:
        return None  # the option is not a valid change for this device
    resolved = [r["key"] for r in result["resolved"]]
    broken = [i for i in result["impacts"] if i["status"] in ("broken", "violation")]
    restored = [i for i in result["impacts"] if i["status"] == "restored"]
    new = result["findings"]
    resolves = issue_key in resolved if advisory_id is None else \
        advisory_id not in {a["id"] for a in result["advisories"]}
    if resolves and not new and not broken and not option.caution and result["validation_complete"]:
        verdict = "recommended"
    elif not new and not broken:
        verdict = "partial"  # also: safe in NetGuard's model but needs human review (option.caution)
    else:
        verdict = "unsafe"
    return {
        "verdict": verdict, "resolves": resolves, "caution": option.caution or
        ("Configuration evidence is incomplete; this candidate cannot be approved for deployment." if not result["validation_complete"] else None),
        "also_resolves": [r for r in result["resolved"] if r["key"] != issue_key],
        "new_issues": [{"rule_id": f["rule_id"], "name": f["name"], "message": f["message"]} for f in new],
        "reveals": [{"rule_id": f["rule_id"], "name": f["name"], "message": f["message"]} for f in result["revealed"]],
        "broken_flows": [f"{i['source_device']} → {i['destination_device']}" for i in broken],
        "restored_flows": [f"{i['source_device']} → {i['destination_device']}" for i in restored],
        "risk_level": result["risk"]["level"], "risk_score": result["risk"]["total"],
        "recommendation": result["decision"]["recommendation"],
        "current_value": result["detected"].current_value, "proposed_value": result["detected"].proposed_value,
        "target": result["detected"].target_name, "device": result["detected"].device_name,
        "commands": result["commands"], "work_order": option.change_type == "physical_remediation",
    }


def _inferred_notes(network, model, flow_rows) -> list[str]:
    """Smart discovery accepts MAC-table attachments (decision D4) but states which required flows depend on them."""
    if (network.metadata_json or {}).get("method") != "smart":
        return []
    inferred = {link.id for link in model.links.values() if link.kind == "mac"}
    names = [row["name"] for row in flow_rows if inferred & set(row["path_link_ids"])]
    other = [model.device(did).name for link in model.links.values() if link.kind == "mac" for did in (link.a_dev, link.b_dev)
             if model.device(did).is_host and not any(model.device(did).name in (row["source"], row["destination"]) for row in flow_rows)]
    notes = []
    if names:
        notes.append(f"{len(names)} required flow(s) use inferred attachments (switch MAC-table evidence; endpoint NIC not "
                     f"reported, shown as Unknown Port): {', '.join(names)}.")
    if other:
        notes.append(f"Inferred attachment not on a required flow path: {', '.join(sorted(set(other)))}.")
    return notes


def _legacy_sample_notes(network) -> list[str]:
    """Sample networks saved with legacy sample port names keep their original port names."""
    meta = network.metadata_json or {}
    # Built-in demos are recognised by their description and their sample device set, never by text alone.
    demo_names = {name for name, *_ in demo_topology._DEVICES}
    built_in_demo = (network.description in (demo_topology.DEMO_DESCRIPTION, demo_topology.FAULTY_DESCRIPTION)
                     and demo_names <= {device.name for device in network.devices})
    sample = network.source == "sample" or built_in_demo
    # Lab-tool snapshots use the user's own lab port names, not the sample catalogue.
    if not sample or network.network_type == "Lab" or meta.get("interface_naming_version"):
        return []
    return ["This sample network was saved with legacy sample port names "
            "(for example G0/x on ISR 4331 or office uplinks 21/22). Physical and naming findings may refer to them; "
            "create a new sample network to use the updated topology."]


OPEN_CHANGE_STATES = ("pending_approval", "approved", "awaiting_confirm")


def _link_open_changes(db: Session, network_id: int, rows: list[dict]) -> None:
    """Attach the submitted change behind each proposed fix, so an issue shows "waiting for approval" or "approved:
    apply it" instead of offering the same fix again. Approval alone never changes a device."""
    from backend.models import Change

    open_changes = db.scalars(select(Change).where(Change.network_id == network_id,
                                                   Change.status.in_(OPEN_CHANGE_STATES))
                              .order_by(Change.id.desc())).all()
    if not open_changes:
        return
    for row in rows:
        for fix in row.get("fixes", []):
            for change in open_changes:
                if (change.device_id, change.interface_id, change.change_type, change.parameters or {}) == \
                        (fix.get("device_id"), fix.get("interface_id"), fix.get("change_type"), fix.get("parameters") or {}):
                    fix["change"] = {"id": change.id, "status": change.status}
                    break


def _cabling_findings(network, model) -> list[dict]:
    """Cables the imported lab or project file defines that are no longer in the model.

    Without configurations or traffic tests nothing else would notice a removed cable, so the lab file is the design
    baseline: a missing cable is reported, and a device it leaves with no cable at all is a definite fault."""
    baseline = (network.metadata_json or {}).get("lab_cables")
    if not baseline:
        return []
    present = {frozenset({l.a_dev, l.b_dev}) for l in model.links.values()}
    had = {did for c in baseline for did in (c["a"], c["b"])}
    isolated = {did for did in had if did in model.devices and not model.links_of(did)}
    out = []
    for cable in baseline:
        a, b = cable["a"], cable["b"]
        if a not in model.devices or b not in model.devices or frozenset({a, b}) in present:
            continue
        name_a, name_b = model.device(a).name, model.device(b).name
        cut_off = [model.device(d).name for d in (a, b) if d in isolated]
        out.append({
            "code": "cable-removed", "severity": "HIGH" if cut_off else "MEDIUM", "device_ids": [a, b],
            "detail": f"Cable {name_a} {cable.get('a_port') or '?'} ↔ {name_b} {cable.get('b_port') or '?'} from the "
                      f"imported file is missing." + (f" {', '.join(cut_off)} now has no connection at all." if cut_off else ""),
            "next_step": "Reconnect it (Connect To…), or if the change is intended press Accept current cabling.",
        })
    return out


def _logical_link_count(db: Session, network_id: int) -> int:
    """Links drawn on the map that are not cables (same subnet, route hop): shown, but never analysed."""
    from backend.models import Link

    return sum(1 for link in db.scalars(select(Link).where(Link.network_id == network_id)) if presentation_only(link))


def run_health_check(db: Session, network_id: int, verify_fixes: bool = True) -> dict:
    started = time.perf_counter()
    network = network_service.get_network(db, network_id)
    model = load_model(db, network_id)
    analyzer = FlowAnalyzer(model)
    flows = impact_engine.build_flows(model, analyzer, audit=True)
    findings = list(validation_engine.run(model, analyzer, flows, "baseline").values())
    advisory_rows = advisories(model)
    failing = _failing_flows(flows)

    pseudo_impacts = [{
        "service": flow.name, "status": status,
        "failure_device": model.devices[flow.baseline.fail_device].name
        if flow.baseline.fail_device in model.devices else None,
        "failure_link_id": flow.baseline.fail_link, "criticality": flow.criticality,
        "impact_type": "service_flow" if flow.kind == "intent" else "connectivity",
        "source_device": flow.src_name, "destination_device": flow.dst_name,
    } for flow, status in failing]
    risk_engine.relate(findings, pseudo_impacts, {d.name: d.id for d in model.devices.values()})
    names = {d.name: d.id for d in model.devices.values()}
    for finding in findings:
        risk_engine.score_finding(finding, pseudo_impacts, model, names)
    # Highest risk first; among equals, root causes that break the most required flows first.
    findings.sort(key=lambda f: (-f.detail["risk"]["score"], -SEVERITY_ORDER[f.severity], -len(f.related_flows),
                                 f.rule_id, f.subject))

    issues = []
    for finding in findings:
        data = finding.to_dict(model)
        fixes = []
        for option in fix_engine.options_for(model, analyzer, finding):
            verification = _verify(db, network_id, option, data["key"]) if verify_fixes else {}
            if verify_fixes and verification is None:
                continue
            fixes.append({
                "label": option.label, "device_id": option.device_id,
                "description": f"{option.description} {option.caution}" if option.caution else option.description,
                "interface_id": option.interface_id, "change_type": option.change_type,
                "parameters": option.parameters, "verification": verification, "caution": option.caution,
            })
        # Safest first; among equally safe fixes, the one that also resolves the most other issues.
        fixes.sort(key=lambda f: (VERDICT_ORDER.get(f["verification"].get("verdict"), 9),
                                  -len(f["verification"].get("also_resolves", []))))
        data["fixes"] = fixes
        issues.append(data)
    ai = {"available": False}
    try:
        from backend.services import ai_engine
        if verify_fixes:
            ai_engine.rank_fixes(model, flows, issues)  # within each safety verdict, likely repairs first
        telemetry = {d.id: (d.name, d.telemetry) for d in network.devices if d.telemetry}
        ai = ai_engine.network_insights(model, flows, findings, issues, telemetry)
    except Exception:  # noqa: BLE001 - the advisory models never block the health check
        ai = {"available": False}
    for data in issues:
        data["fixes"] = data["fixes"][:3]
        data["recommended_fix"] = 0 if data["fixes"] and data["fixes"][0]["verification"].get("verdict") == "recommended" else None

    for advisory in advisory_rows:
        fixes = []
        for option in fix_engine.advisory_options(model, analyzer, advisory):
            verification = _verify(db, network_id, option, "", advisory["id"]) if verify_fixes else {}
            if verify_fixes and verification is None:
                continue
            fixes.append({"label": option.label, "device_id": option.device_id,
                          "description": f"{option.description} {option.caution}" if option.caution else option.description,
                          "interface_id": option.interface_id, "change_type": option.change_type,
                          "parameters": option.parameters, "verification": verification})
        advisory["fixes"] = fixes

    _link_open_changes(db, network.id, issues + advisory_rows)
    configuration_incomplete = bool((network.metadata_json or {}).get("configuration_incomplete"))
    flow_rows = []
    for flow in flows:
        # Required flows; for networks without any, the host pairs that are expected to work.
        if flow.kind == "gateway" or flow.expected is None:
            continue
        uncertain = (network.source == "discovery" or configuration_incomplete) and flow.baseline.code in ("incomplete", "not_connected", "no_ip")
        ok = None if uncertain else flow.baseline.reachable == (flow.expected == "allow")
        flow_rows.append({
            "intent_id": int(flow.key.removeprefix("intent-")) if flow.key.startswith("intent-") else None,
            "name": flow.name, "source": flow.src_name, "destination": flow.dst_name,
            "protocol": flow.protocol, "port": flow.port, "expected": flow.expected,
            "criticality": flow.criticality, "kind": flow.kind, "ok": ok,
            "status": "unknown" if uncertain else "passed" if ok else "failed",
            "reason": "Connection or endpoint evidence is incomplete; the flow cannot be verified." if uncertain else None if ok else ("isolation violated" if flow.expected == "deny"
                                       else impact_engine.describe_failure(flow.baseline)),
            "path_device_ids": list(flow.baseline.path), "path_link_ids": list(flow.baseline.links),
        })

    counts = {level: sum(1 for i in issues if i["severity"] == level) for level in ("CRITICAL", "HIGH", "MEDIUM")}
    gaps = []
    if not model.devices:
        gaps.append({"code": "no-devices", "detail": "There are no devices to analyze.",
                     "next_step": "Discover or import a network first."})
    smart = (network.metadata_json or {}).get("method") == "smart"
    if configuration_incomplete:
        facts = (network.metadata_json or {}).get("discovery", {})
        if smart:
            # Only reads that would still add important information (the credential advisor's view).
            missing_reads = [d.name for d in model.devices.values()
                             if (facts.get(str(d.id), {}).get("classification") or {}).get("auth") in ("required", "failed")
                             and any(g["important"] for g in (facts.get(str(d.id), {}).get("classification") or {}).get("gains", []))]
            next_step = ("Authenticate " + ", ".join(missing_reads) + " from the Discovery Report (optional; NetGuard "
                         "continues with credential-free evidence).") if missing_reads else "Review the Discovery Report."
        else:
            missing_reads = [d.name for d in model.devices.values()
                             if facts.get(str(d.id), {}).get("can_login") and
                             facts.get(str(d.id), {}).get("auth_status") != "success"]
            next_step = "Open Device Access and test the saved credentials to read the sample configuration."
        gaps.append({"code": "configuration", "detail": "Configuration reads are missing" +
                     (": " + ", ".join(missing_reads) if missing_reads else " for this model") + ".",
                     "next_step": next_step})
    elif not smart:
        # Any source (lab import, project file, manual model): a router or firewall without a single IP address has
        # no configuration in the model, so "no fault found" says nothing about it. Switches may run on defaults.
        unconfigured = sorted(d.name for d in model.devices.values()
                              if d.is_l3 and not any(i.ip for i in d.interfaces.values()) and not d.routes)
        if unconfigured:
            lab = network.source in ("eve-ng", "gns3")
            gaps.append({"code": "configuration",
                         "detail": f"No configuration was imported for {len(unconfigured)} router(s) or firewall(s): "
                                   + ", ".join(unconfigured) + ".",
                         "next_step": ("Use Collect Configs to read the running configurations from the lab consoles."
                                       if lab else "Import or enter the device configurations, then analyze again.")})
    if network.source != "discovery" and model.devices and not flow_rows:
        gaps.append({"code": "traffic-tests",
                     "detail": "No required flows and no addressed host pairs: end-to-end connectivity was not checked.",
                     "next_step": "Add host addressing and required flows (Manage Required Flows), then analyze again."})
    if network.source == "discovery":
        if not model.links:
            gaps.append({"code": "no-links", "detail": "No interface connections have been collected.",
                         "next_step": "Authenticate the switches to read their neighbour and MAC tables; an IP response "
                                      "never establishes a cable." if smart else
                                      "Use a neighbor-table discovery method; SSH-only discovery needs device access."})
        if smart:
            required = {name for row in flow_rows for name in (row["source"], row["destination"])}
            unplaced = [dev.name for dev in model.devices.values() if dev.name in required and not model.links_of(dev.id)]
            facts = (network.metadata_json or {}).get("discovery", {})
            # A device with lease-derived addressing but no cable yet is a connection gap, not an addressing gap.
            unaddressed = [dev.name for dev in model.devices.values() if dev.is_host and dev.name in required
                           and not (facts.get(str(dev.id)) or {}).get("lease")
                           and (not dev.gateway or not any(iface.ip and iface.mask for iface in dev.interfaces.values()))]
            firewall = next((dev.name for dev in model.devices.values() if dev.type == "firewall"), "the firewall")
            if unplaced and model.links:
                gaps.append({"code": "endpoint-connection", "detail": "Connection unknown for required-flow endpoints: " + ", ".join(unplaced) + ".",
                             "next_step": "Authenticate the switch these devices were located behind (see the Discovery Report)."})
            if unaddressed and model.links:
                gaps.append({"code": "endpoint-config", "detail": "Endpoint mask or gateway is unknown: " + ", ".join(unaddressed) + ".",
                             "next_step": f"Authenticate {firewall} to read its DHCP leases."})
        for link in model.links.values():
            missing = [model.device(did).name for did, iid in ((link.a_dev, link.a_if), (link.b_dev, link.b_if)) if iid is None]
            if missing:
                gaps.append({"code": "endpoint-port", "link_id": link.id,
                             "detail": "Interface name not reported for " + ", ".join(missing) + ".",
                             "next_step": "Review this link's evidence. Endpoint inventory or endpoint telemetry is needed; switch login alone cannot identify its NIC."})
        inferred = sum(link.kind == "mac" for link in model.links.values())
        if inferred and not smart:
            gaps.append({"code": "inferred-attachments", "detail": f"{inferred} MAC-based attachments are inferred, rather than verified direct cables.",
                         "next_step": "Collect reciprocal neighbor or physical inventory evidence to verify the direct path."})
        if not flow_rows:
            gaps.append({"code": "traffic-tests", "detail": "No endpoint traffic tests can be evaluated from the discovered model.",
                         "next_step": "Add endpoint IP/subnet configuration and required service flows before checking end-to-end connectivity."})
        elif any(row["ok"] is None for row in flow_rows):
            gaps.append({"code": "unverified-flows", "detail": "One or more required service flows could not be evaluated from the available evidence.",
                         "next_step": "Inspect the missing endpoint or connection evidence and repeat analysis."})
    cabling = _cabling_findings(network, model)
    incomplete = bool(gaps)
    failing_count = sum(1 for row in flow_rows if row["ok"] is False)
    status = "issues" if issues or failing_count or cabling else "incomplete" if incomplete else "healthy"
    return {
        "network_id": network.id, "network_name": network.name,
        "checked_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds"),
        "status": status,
        "advisories": advisory_rows, "advisory_count": len(advisory_rows),
        "summary": f"Connectivity {status.upper()} · {len(advisory_rows)} security & hygiene advisories",
        "coverage_notes": _legacy_sample_notes(network) + coverage_notes(model, flows) + _inferred_notes(network, model, flow_rows),
        "rules_checked": sum(1 for rule in RULES.values() if rule.category != "advisory"), "devices_checked": len(model.devices), "links_checked": len(model.links),
        "logical_links": _logical_link_count(db, network_id),
        "issue_count": len(issues), "counts": counts, "issues": issues, "flows": flow_rows,
        "failing_flow_count": failing_count, "unknown_flow_count": sum(1 for f in flow_rows if f["ok"] is None),
        "cabling_findings": cabling, "cabling_count": len(cabling),
        "analysis_complete": not incomplete,
        "coverage_gaps": gaps,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "simulated": network.is_simulated, "environment": network.environment,
        "modeling_assumptions": (network.metadata_json or {}).get("modeling_assumptions", []),
        "evidence_scope": "Checked on a copy of the stored configs and scan results.",
        "ai": ai,
    }
