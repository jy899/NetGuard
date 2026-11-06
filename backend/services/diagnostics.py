"""Evidence-driven checks shared by analysis and candidate validation.

Adapters supply observations. A ping response is never treated as cable evidence.
The checks below inspect the model and explicit observations; scenario names do
not choose the verdict.
"""
from __future__ import annotations

from collections import defaultdict

from backend.services.network_model import NetworkModel
from backend.services.physical_layer import media_problem


def supplemental_findings(model: NetworkModel):
    from backend.services.validation_engine import Finding

    findings = []
    # MAC-table attachment proves the local learned port, not the host NIC or
    # cable. Its VLAN can still be compared with an explicit approved baseline.
    for link in model.links.values():
        expected_vlan = link.observation.get("expected_vlan")
        if link.kind != "mac" or not isinstance(expected_vlan, int):
            continue
        for did, iid in ((link.a_dev, link.a_if), (link.b_dev, link.b_if)):
            device, iface = model.device(did), model.iface(did, iid)
            if not device.is_switch or iface is None or iface.mode != "access" or iface.vlan == expected_vlan:
                continue
            msg = f"{device.name} {iface.name} is in access VLAN {iface.vlan}; the approved endpoint assignment requires VLAN {expected_vlan}."
            findings.append(Finding("VLAN001", f"observed-port:{did}:{iid}", msg, [link.a_dev, link.b_dev], [link.id],
                {"switch": device.name, "port": iface.name, "vlan": iface.vlan, "expected_vlan": expected_vlan,
                 "certainty": "suspected", "confidence": link.confidence or 0.65,
                 "evidence": [{"source": "sample switch interface configuration", "detail": msg},
                              {"source": "sample MAC address table", "detail": "The endpoint MAC is learned on this local port; the endpoint interface and direct cable are not confirmed."}],
                 "expected_outcome": "The local access VLAN should match the approved assignment. Collect endpoint and path evidence before claiming end-to-end connectivity is restored."}))
    # Only compare observed, active trunk ends. Missing lists are unknown, not "all".
    for link in model.links.values():
        a, b = model.device(link.a_dev), model.device(link.b_dev)
        ia, ib = model.iface(a.id, link.a_if), model.iface(b.id, link.b_if)
        if not (ia and ib and ia.up and ib.up and ia.mode == ib.mode == "trunk"):
            continue
        problems = []
        if ia.native_vlan is not None and ib.native_vlan is not None and ia.native_vlan != ib.native_vlan:
            problems.append(f"native VLAN {ia.native_vlan} versus {ib.native_vlan}")
        if ia.allowed_vlans is not None and ib.allowed_vlans is not None and set(ia.allowed_vlans) != set(ib.allowed_vlans):
            problems.append(f"allowed VLANs {ia.allowed_vlans} versus {ib.allowed_vlans}")
        if problems:
            msg = f"{a.name} {ia.name} ↔ {b.name} {ib.name}: " + "; ".join(problems) + "."
            # One sourced fact per trunk end, so the evidence is not just the finding message again.
            evidence = [{"source": "trunk configuration",
                         "detail": f"{dev.name} {iface.name}: native VLAN {iface.native_vlan if iface.native_vlan is not None else 'unset'}, "
                                   f"allowed VLANs {iface.allowed_vlans if iface.allowed_vlans is not None else 'all'}."}
                        for dev, iface in ((a, ia), (b, ib))]
            findings.append(Finding("VLAN003", f"trunk:{link.id}", msg, [a.id, b.id], [link.id], {"evidence": evidence}))

    # Build one forwarding graph per VLAN. A protected redundant cycle has a
    # blocking/discarding port and therefore does not become a forwarding cycle.
    graphs = defaultdict(list)
    for link in model.links.values():
        a, b = model.device(link.a_dev), model.device(link.b_dev)
        ia, ib = model.iface(a.id, link.a_if), model.iface(b.id, link.b_if)
        if not (a.is_switch and b.is_switch and ia and ib and ia.up and ib.up):
            continue
        if link.state in ("down", "suspended") or ia.stp_state != "forwarding" or ib.stp_state != "forwarding":
            continue
        if media_problem(model, link):
            continue  # a copper/fibre mismatch cannot forward, so it cannot close a loop (PHY001 reports it)
        if ia.mode != "trunk" or ib.mode != "trunk":
            continue
        common = set(a.vlans) & set(b.vlans)
        for iface in (ia, ib):
            if iface.allowed_vlans is not None:
                common &= set(iface.allowed_vlans)
        for vlan in common:
            graphs[vlan].append(link)
    observations = model.observations or {}
    for vlan, edges in graphs.items():
        parents, tree = {}, defaultdict(list)
        def root(node):
            parents.setdefault(node, node)
            while parents[node] != node:
                node = parents[node]
            return node
        for edge in sorted(edges, key=lambda e: e.id):
            ra, rb = root(edge.a_dev), root(edge.b_dev)
            if ra != rb:
                parents[ra] = rb
                tree[edge.a_dev].append((edge.b_dev, edge.id))
                tree[edge.b_dev].append((edge.a_dev, edge.id))
                continue
            queue = [(edge.a_dev, [], [edge.a_dev])]
            visited = set()
            cycle_links, cycle_devices = [], []
            while queue:
                node, path, nodes = queue.pop(0)
                if node == edge.b_dev:
                    cycle_links, cycle_devices = path + [edge.id], nodes
                    break
                visited.add(node)
                queue += [(peer, path + [lid], nodes + [peer]) for peer, lid in tree[node] if peer not in visited]
            if not cycle_links:
                continue
            names = [model.device(did).name for did in cycle_devices]
            evidence = [{"source": "sample STP interface status",
                         "detail": f"VLAN {vlan}: every port on {' ↔ '.join(names + names[:1])} is forwarding; none is blocking."}]
            macs = [m for m in observations.get("mac_flaps", []) if m.get("vlan") == vlan
                    and m.get("count", 0) >= 2 and m.get("device") in names]
            broadcasts = [m for m in observations.get("broadcast_samples", []) if m.get("vlan") == vlan
                          and m.get("device") in names and m.get("pps", 0) > m.get("baseline_pps", 0) * 10
                          and m.get("baseline_pps", 0) > 0]
            for row in macs:
                evidence.append({"source": "sample MAC learning events",
                                 "detail": f"{row['device']} VLAN {vlan}: {row.get('mac')} moved between {', '.join(row.get('ports', []))} {row['count']} times in {row.get('window_seconds', 60)} seconds."})
            for row in broadcasts:
                evidence.append({"source": "sample interface counters",
                                 "detail": f"{row['device']} VLAN {vlan}: {row['pps']} broadcast packets/s; sample baseline {row['baseline_pps']} packets/s."})
            confirmed = bool(macs and broadcasts)
            findings.append(Finding("L2001", f"vlan:{vlan}:cycle:{','.join(map(str, sorted(cycle_links)))}",
                f"VLAN {vlan} has a forwarding cycle between {', '.join(names)}.", cycle_devices, cycle_links,
                {"certainty": "confirmed" if confirmed else "suspected", "confidence": 0.98 if confirmed else 0.7,
                 "evidence": evidence, "symptom": "Repeated MAC moves and elevated broadcasts in the sample observations." if confirmed else "An unprotected forwarding cycle is present; traffic evidence is incomplete.",
                 "root_cause": "The redundant switch path has no STP blocking port for this VLAN.",
                 "expected_outcome": "A reviewed redundant-link isolation or correct STP blocking state removes the forwarding cycle; repeat MAC and broadcast observations to confirm recovery."}))
    by_name = {device.name: device for device in model.devices.values()}
    for expected in observations.get("expected_connections", []):
        a = model.devices.get(expected.get("source_device_id")) or by_name.get(expected.get("source"))
        b = model.devices.get(expected.get("destination_device_id")) or by_name.get(expected.get("destination"))
        if not a or not b:
            continue
        def matches_baseline(link):
            if {link.a_dev, link.b_dev} != {a.id, b.id}:
                return False
            # Link orientation is irrelevant, but the exact endpoint ports in
            # an approved cable inventory are not interchangeable. A generic
            # device-to-device line cannot satisfy a port-to-port baseline.
            for device, key in ((a, "source_interface"), (b, "destination_interface")):
                port = expected.get(key)
                iface = model.iface(device.id, link.local_if(device.id))
                if port and (iface is None or iface.name != port):
                    return False
            return True
        if any(matches_baseline(link) for link in model.links.values()):
            continue
        evidence = [{"source": "approved sample connection baseline",
                     "detail": f"Expected {a.name} {expected.get('source_interface', 'Unknown')} ↔ {b.name} {expected.get('destination_interface', 'Unknown')}; no corresponding port-to-port link is available."}]
        findings.append(Finding("LINK002", f"expected:{a.id}:{b.id}",
            f"The expected connection between {a.name} {expected.get('source_interface', '')} and {b.name} {expected.get('destination_interface', '')} is absent from the current topology.", [a.id, b.id], [],
            {"certainty": "suspected", "confidence": 0.65, "evidence": evidence,
             "root_cause": "A missing cable, an unavailable neighbour observation, or a discovery access failure could explain the missing connection.",
             "expected_outcome": "Confirm the physical path and collect fresh neighbour information before marking the connection observed."}))
    return findings
