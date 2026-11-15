"""Hardware checks, evidence quality and advisory separation."""
import pytest

from backend.database.session import SessionLocal
from backend.services.analysis_checks import advisories, physical_findings
from backend.services.forwarding import FlowAnalyzer
from backend.services.network_model import DeviceM, IfaceM, IntentM, LinkM, NetworkModel


def interface(iid, did, name, ip=None, vlan=None, speed=1000, mode=None):
    return IfaceM(iid, did, name, ip, "255.255.255.0" if ip else None, vlan, "up", None, mode, speed)


def device(did, name, kind, vendor=None, model=None, interfaces=()):
    dev = DeviceM(did, name, kind, None, {iface.id: iface for iface in interfaces}, vendor=vendor, model=model)
    if kind == "switch":
        dev.vlans = {20: None, 30: None}
    return dev


def test_copper_fibre_cannot_forward_and_reports_physical_evidence():
    host = device(1, "PC", "pc", interfaces=[interface(1, 1, "eth0", "10.0.0.10")])
    switch = device(2, "SW", "switch", "HPE Aruba", "Aruba 2530-24G",
                    [interface(2, 2, "25", vlan=20, mode="access"), interface(3, 2, "1", vlan=20, mode="access")])
    switch.vlans = {20: "DATA"}
    destination = device(3, "SERVER", "server", interfaces=[interface(4, 3, "eth0", "10.0.0.20")])
    model = NetworkModel(1, {dev.id: dev for dev in (host, switch, destination)},
                         {1: LinkM(1, 1, 1, 2, 2), 2: LinkM(2, 2, 3, 3, 4)}, [])
    finding = physical_findings(model)[0].to_dict(model)
    assert finding["rule_id"] == "PHY001" and finding["severity"] == "HIGH"
    assert "compatible" in finding["recommendation"] and len(finding["evidence"]) == 2
    result = FlowAnalyzer(model).evaluate(1, 3)
    assert not result.reachable and result.code == "media_mismatch" and result.fail_link == 1
    assert "incompatible cable media" in result.detail["reason"]


@pytest.mark.parametrize("name,speed,expected", [("port1", 1000, {"PHY002"}), ("internal1", 100, {"PHY003"})])
def test_invalid_fortigate_port_and_mismatched_speed(name, speed, expected):
    firewall = device(1, "FW", "firewall", "Fortinet", "FortiGate 60F", [interface(1, 1, name, speed=speed)])
    router = device(2, "R", "router", "Cisco", "ISR 4331", [interface(2, 2, "Gi0/0/0")])
    model = NetworkModel(1, {1: firewall, 2: router}, {1: LinkM(1, 1, 1, 2, 2)}, [])
    findings = physical_findings(model)
    assert {finding.rule_id for finding in findings} == expected
    assert all(finding.to_dict(model)["affected_interfaces"] for finding in findings)


@pytest.mark.parametrize("nic", ["Fa0", "e0", "Ethernet", "NIC1"])
def test_host_nic_names_outside_the_sample_convention_are_not_hardware_faults(nic):
    # User-built and lab hosts may use their own NIC names; only catalogued hardware is checked.
    host = device(1, "PC", "pc", interfaces=[interface(1, 1, nic, "10.0.0.10")])
    switch = device(2, "SW", "switch", "HPE Aruba", "Aruba 2530-24G", [interface(2, 2, "3", vlan=20, mode="access")])
    model = NetworkModel(1, {1: host, 2: switch}, {1: LinkM(1, 1, 1, 2, 2)}, [])
    assert physical_findings(model) == []


def test_cisco_alias_is_an_advisory_and_unknown_models_are_silent():
    router = device(1, "R", "router", "Cisco", "ISR 4331", [interface(1, 1, "G0/0/1")])
    model = NetworkModel(1, {1: router}, {}, [])
    result = advisories(model)
    assert [row["rule_id"] for row in result] == ["NAME001"]
    assert result[0]["severity"] == "LOW" and "Gi0/0/1" in result[0]["recommendation"]
    # A legacy shorthand name like G0/1 has no Gi0/1 on an ISR 4331: no "use Gi0/1" advice
    # contradicting PHY002, which reports the absent port when it is cabled.
    router.interfaces[1].name = "G0/1"
    assert advisories(model) == []
    # Uncatalogued Cisco hardware: the alias is still advised (nothing proves Gi0/1 absent),
    # but no hardware finding is guessed; other vendors get neither.
    router.model = "Uncatalogued router"
    peer = device(2, "UNKNOWN", "switch", "Other vendor", "Unknown 24-port", [interface(2, 2, "fibre99", speed=100)])
    model.devices[2] = peer
    model.links[1] = LinkM(1, 1, 1, 2, 2)
    assert physical_findings(model) == []
    assert [(row["rule_id"], row["devices"]) for row in advisories(model)] == [("NAME001", ["R"])]


def test_security_advisories_use_stored_roles_services_and_isolation_intents():
    guest = device(1, "GUEST", "pc", interfaces=[interface(1, 1, "eth0", "10.0.0.10", vlan=20)])
    server = device(2, "FILE", "server", interfaces=[interface(2, 2, "eth0", "10.0.0.20", vlan=20)])
    # Both hosts are cabled to VLAN 20 access ports on one switch: attachment evidence for a shared segment.
    switch = device(3, "SW", "switch", "HPE Aruba", "Aruba 2530-24G",
                    [interface(3, 3, "1", vlan=20, mode="access"), interface(4, 3, "2", vlan=20, mode="access")])
    observations = {"discovery": {"1": {"role": "Guest workstation"}, "2": {"role": "File server"},
                                   "3": {"role": "Access switch", "open_services": ["HTTP 80", "SSH 22"]}}}
    model = NetworkModel(1, {dev.id: dev for dev in (guest, server, switch)},
                         {1: LinkM(1, 1, 1, 3, 3), 2: LinkM(2, 2, 2, 3, 4)}, [], observations)
    result = advisories(model)
    assert {row["rule_id"] for row in result} == {"SEC001", "SEC002"}
    segmentation = next(row for row in result if row["rule_id"] == "SEC001")
    assert "VLAN 20, subnet 10.0.0.0/24" in segmentation["evidence"][0]["detail"]
    assert set(segmentation["affected_devices"]) == {"GUEST", "FILE"}
    for src, dst, protocol, port in ((2, 1, "ip", None), (1, 2, "tcp", 443), (1, 2, "tcp", None)):
        model.intents = [IntentM(1, "Partial isolation", src, dst, protocol, port, "deny", "medium")]
        assert {row["rule_id"] for row in advisories(model)} == {"SEC001", "SEC002"}
    model.intents = [IntentM(1, "Guest isolation", 1, 2, "ip", None, "deny", "medium")]
    assert [row["rule_id"] for row in advisories(model)] == ["SEC002"]
    model.observations = {}
    assert advisories(model) == []


def test_cleartext_advisory_includes_ap_and_uses_exact_service_ports():
    ap = device(1, "AP", "switch", "HPE Aruba", "Aruba AP-505")
    model = NetworkModel(1, {1: ap}, {}, [], {"discovery": {"1": {
        "role": "Wireless access point", "open_services": ["HTTP 8080", "HTTP 8000", "HTTPS 443", "Telnet 2300"]}}})
    assert advisories(model) == []
    model.observations["discovery"]["1"]["open_services"] += ["HTTP 80", "Telnet 23"]
    rows = advisories(model)
    assert [row["rule_id"] for row in rows] == ["SEC002"]
    assert [fact["detail"] for fact in rows[0]["evidence"]] == ["HTTP 80", "Telnet 23"]


def health(client, auth, network_id):
    response = client.get(f"/api/networks/{network_id}/health-check", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()




@pytest.mark.parametrize("scenario", ["healthy", "mixed", "vlan", "routing", "interface", "acl", "loop", "missing-link", "ip-conflict"])
def test_virtual_samples_have_no_physical_or_security_advisories_and_distinct_explanations(client, auth, scenario):
    response = client.post("/api/networks/samples", headers=auth, json={"provider": "sample", "scenario": scenario})
    assert response.status_code == 201, response.text
    model = response.json()
    report = health(client, auth, model["network_id"])
    assert not report["advisories"]
    assert not any(row["rule_id"].startswith("PHY") for row in report["issues"])
    for finding in report["issues"]:
        assert finding["symptom"] != finding["root_cause"], finding
        assert finding["evidence"]
        assert all(fact["detail"] not in (finding["symptom"], finding["root_cause"]) for fact in finding["evidence"])
    if scenario == "mixed":
        assert "OSPF001" in {row["rule_id"] for row in report["issues"]}
        note = next(note for note in report["coverage_notes"] if "R1–R3 link" in note)
        # R1 forwarded the traffic before the loop was traced to the R1–R3 fault, so it is evaluated, not masked.
        unevaluated = note.split("beyond that point (")[1].split(")")[0]
        assert "were not evaluated" in note and "SW2" in unevaluated and "R3" in unevaluated
        assert "R1" not in unevaluated and "R2" not in unevaluated
        assert "Forwarding through FW1, R1, R2 was evaluated" in note
        assert all("ACL" not in note for note in report["coverage_notes"])






def test_pre_045_sample_networks_get_a_legacy_naming_note(client, auth):
    from backend.models import Network
    created = client.post("/api/networks/samples", headers=auth, json={"scenario": "healthy", "name": "Old demo"}).json()
    assert not any("legacy sample port names" in note for note in health(client, auth, created["network_id"])["coverage_notes"])
    with SessionLocal() as db:
        network = db.get(Network, created["network_id"])
        network.metadata_json = {k: v for k, v in network.metadata_json.items() if k != "interface_naming_version"}
        db.commit()
    assert any("legacy sample port names" in note for note in health(client, auth, created["network_id"])["coverage_notes"])


def _gateway_media_fault_model():
    # PC and SERVER share VLAN 20 on one switch; the router uplink joins a fibre SFP port to copper.
    pc = device(1, "PC", "pc", interfaces=[interface(1, 1, "eth0", "10.0.0.10")])
    server = device(2, "SERVER", "server", interfaces=[interface(2, 2, "eth0", "10.0.0.20")])
    switch = device(3, "SW", "switch", "HPE Aruba", "Aruba 2530-24G",
                    [interface(3, 3, "1", vlan=20, mode="access"), interface(4, 3, "2", vlan=20, mode="access"),
                     interface(5, 3, "25", vlan=20, mode="access")])
    switch.vlans = {20: "DATA"}
    router = device(4, "R", "router", "Cisco", "ISR 4331",
                    [interface(6, 4, "Gi0/0/0", "10.0.0.1"), interface(7, 4, "Gi0/0/1", "10.1.0.1")])
    remote = device(5, "REMOTE", "server", interfaces=[interface(8, 5, "eth0", "10.1.0.10")])
    for host in (pc, server):
        host.gateway = "10.0.0.1"
    remote.gateway = "10.1.0.1"
    links = {1: LinkM(1, 1, 1, 3, 3), 2: LinkM(2, 2, 2, 3, 4), 3: LinkM(3, 3, 5, 4, 6), 4: LinkM(4, 4, 7, 5, 8)}
    return NetworkModel(1, {dev.id: dev for dev in (pc, server, switch, router, remote)}, links, [])


def test_gateway_path_media_fault_blocks_routed_traffic_but_not_the_local_vlan():
    analyzer = FlowAnalyzer(_gateway_media_fault_model())
    assert analyzer.evaluate(1, 2).reachable  # same VLAN, never crosses the broken uplink
    routed = analyzer.evaluate(1, 5)
    assert not routed.reachable and routed.code == "media_mismatch"


def test_media_mismatched_trunk_cannot_close_a_forwarding_loop():
    from backend.services.diagnostics import supplemental_findings
    switches = [device(i, f"SW{i}", "switch", "Cisco", "Catalyst 2960X-24TS-L") for i in (1, 2, 3)]
    links, iid = {}, 0
    for index, sw in enumerate(switches):
        sw.vlans = {10: "V10"}
        peer = switches[(index + 1) % 3]
        # The SW3 -> SW1 ring edge lands on a fibre SFP port at one end: it cannot come up.
        local_name = "Gi1/0/25" if sw.name == "SW3" else "Gi1/0/22"
        local = IfaceM(iid + 1, sw.id, local_name, None, None, None, "up", None, "trunk", 1000, [10], 1, "forwarding")
        remote = IfaceM(iid + 2, peer.id, "Gi1/0/23", None, None, None, "up", None, "trunk", 1000, [10], 1, "forwarding")
        sw.interfaces[local.id], peer.interfaces[remote.id] = local, remote
        links[index + 1] = LinkM(index + 1, sw.id, local.id, peer.id, remote.id)
        iid += 2
    model = NetworkModel(1, {sw.id: sw for sw in switches}, links, [])
    assert not [f for f in supplemental_findings(model) if f.rule_id == "L2001"]
    assert [f.rule_id for f in physical_findings(model)] == ["PHY001"]


def test_segmentation_advisory_requires_a_shared_cabled_fabric():
    def site(offset, kind, role):
        host = device(offset + 1, f"{role.upper()}-{offset}", kind, interfaces=[interface(offset + 1, offset + 1, "eth0", "10.0.0.10")])
        switch = device(offset + 2, f"SW-{offset}", "switch", "HPE Aruba", "Aruba 2530-24G",
                        [interface(offset + 2, offset + 2, "1", vlan=20, mode="access")])
        return host, switch, LinkM(offset + 1, host.id, host.interfaces[offset + 1].id, switch.id, offset + 2)
    guest, sw_a, link_a = site(0, "pc", "guest")
    server, sw_b, link_b = site(10, "server", "server")
    observations = {"discovery": {str(guest.id): {"role": "Guest workstation"}, str(server.id): {"role": "File server"}}}
    devices = {dev.id: dev for dev in (guest, sw_a, server, sw_b)}
    # Same VLAN number and subnet, but two separate switch fabrics: not one broadcast domain.
    model = NetworkModel(1, devices, {1: link_a, 2: link_b}, [], observations)
    assert [row for row in advisories(model) if row["rule_id"] == "SEC001"] == []
    # Joining the fabrics with a switch-to-switch link makes it one segment.
    sw_a.interfaces[90] = interface(90, sw_a.id, "25", mode="trunk")
    sw_b.interfaces[91] = interface(91, sw_b.id, "25", mode="trunk")
    model.links[3] = LinkM(3, sw_a.id, 90, sw_b.id, 91)
    assert [row["rule_id"] for row in advisories(model) if row["rule_id"] == "SEC001"] == ["SEC001"]
    # No cabled access port means no attachment evidence.
    del model.links[1]
    assert [row for row in advisories(model) if row["rule_id"] == "SEC001"] == []


def test_acl_stop_reports_later_policy_hops_as_unevaluated(client, auth):
    created = client.post("/api/networks/samples", headers=auth, json={"scenario": "acl", "name": "ACL mask"}).json()
    nid = created["network_id"]
    topology = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    r2 = next(d for d in topology["devices"] if d["name"] == "R2")
    rule = client.post(f"/api/devices/{r2['id']}/acl-rules", headers=auth, json={
        "sequence": 1, "action": "deny", "protocol": "tcp", "source": "10.20.0.0/24", "destination": "192.168.30.10/32", "port": 443})
    assert rule.status_code == 201, rule.text
    notes = health(client, auth, nid)["coverage_notes"]
    assert any("stop at R2" in note and "R3" in note for note in notes)


def test_static_route_over_a_media_mismatch_is_unusable_but_not_a_next_hop_fault():
    from backend.services import validation_engine
    from backend.services.network_model import RouteM
    model = _gateway_media_fault_model()
    router = model.devices[4]
    router.routes = [RouteM(1, "10.9.0.0/24", "10.0.0.10")]
    analyzer = FlowAnalyzer(model)
    decision = analyzer.router._resolve_static(router, router.routes[0])
    assert decision["kind"] == "invalid" and decision["reason"] == "media_mismatch"
    findings = validation_engine.run(model, analyzer, [], "baseline")
    assert not [key for key in findings if key[0] == "ROUTE001"]
    assert [key for key in findings if key[0] == "PHY001"]


def test_segments_follow_trunk_vlan_carriage():
    guest = device(1, "GUEST", "pc", interfaces=[interface(1, 1, "eth0", "10.0.0.10")])
    server = device(2, "FILE", "server", interfaces=[interface(2, 2, "eth0", "10.0.0.20")])
    sw_a = device(3, "SW-A", "switch", "HPE Aruba", "Aruba 2530-24G",
                  [interface(3, 3, "1", vlan=20, mode="access"), interface(5, 3, "25", mode="trunk")])
    sw_b = device(4, "SW-B", "switch", "HPE Aruba", "Aruba 2530-24G",
                  [interface(4, 4, "1", vlan=20, mode="access"), interface(6, 4, "25", mode="trunk")])
    for port in (sw_a.interfaces[5], sw_b.interfaces[6]):
        port.allowed_vlans = [30]  # the inter-switch trunk does not carry the hosts' VLAN 20
    observations = {"discovery": {"1": {"role": "Guest workstation"}, "2": {"role": "File server"}}}
    model = NetworkModel(1, {dev.id: dev for dev in (guest, server, sw_a, sw_b)},
                         {1: LinkM(1, 1, 1, 3, 3), 2: LinkM(2, 2, 2, 4, 4), 3: LinkM(3, 3, 5, 4, 6)}, [], observations)
    assert not [row for row in advisories(model) if row["rule_id"] == "SEC001"]
    for port in (sw_a.interfaces[5], sw_b.interfaces[6]):
        port.allowed_vlans = [20, 30]
    assert [row["rule_id"] for row in advisories(model) if row["rule_id"] == "SEC001"] == ["SEC001"]


def test_cleartext_management_needs_service_evidence_not_a_role():
    switch = device(1, "SW", "switch", "HPE Aruba", "Aruba 2530-24G")
    model = NetworkModel(1, {1: switch}, {}, [], {"discovery": {"1": {"open_services": ["HTTP 80", "SSH 22"]}}})
    assert [row["rule_id"] for row in advisories(model)] == ["SEC002"]




def test_gateway_check_names_the_broken_gateway_link():
    result = FlowAnalyzer(_gateway_media_fault_model()).gateway_reachable(1)
    assert not result.reachable and result.code == "media_mismatch" and result.fail_link == 3


def test_routed_flow_over_a_media_mismatch_reports_the_cable_not_a_bad_next_hop():
    from backend.services.network_model import RouteM
    host_a = device(1, "HOST-A", "pc", interfaces=[interface(1, 1, "eth0", "10.1.0.10")])
    r1 = device(2, "R1", "router", "Cisco", "ISR 4331", [interface(2, 2, "Gi0/0/1", "10.1.0.1"), interface(3, 2, "Gi0/0/0", "10.5.0.1")])
    # An Aruba L3 switch modelled as a router: its port 25 is an SFP fibre port, R1 Gi0/0/0 is copper.
    r2 = device(3, "R2", "router", "HPE Aruba", "Aruba 2930F-24G-4SFP+", [interface(4, 3, "25", "10.5.0.2"), interface(5, 3, "1", "10.9.0.1")])
    host_b = device(4, "HOST-B", "server", interfaces=[interface(6, 4, "eth0", "10.9.0.10")])
    host_a.gateway, host_b.gateway = "10.1.0.1", "10.9.0.1"
    r1.routes = [RouteM(1, "10.9.0.0/24", "10.5.0.2")]
    r2.routes = [RouteM(2, "10.1.0.0/24", "10.5.0.1")]
    links = {1: LinkM(1, 1, 1, 2, 2), 2: LinkM(2, 2, 3, 3, 4), 3: LinkM(3, 3, 5, 4, 6)}
    model = NetworkModel(1, {dev.id: dev for dev in (host_a, r1, r2, host_b)}, links, [])
    result = FlowAnalyzer(model).evaluate(1, 4)
    assert not result.reachable and result.code == "media_mismatch" and result.fail_link == 2
    assert "incompatible cable media" in result.detail["reason"]


def test_shut_gateway_subinterface_is_reported_with_its_link(client, auth):
    demo = client.post("/api/networks/demo", headers=auth).json()
    topology = client.get(f"/api/networks/{demo['id']}/topology", headers=auth).json()
    r2 = next(d for d in topology["devices"] if d["name"] == "R2")
    sub = next(i for i in r2["interfaces"] if i["name"] == "Gi0/0/1.10")
    payload = {k: sub[k] for k in ("name", "ip_address", "subnet_mask", "vlan_id", "ospf_area", "mode")}
    assert client.put(f"/api/interfaces/{sub['id']}", headers=auth, json={**payload, "status": "admin-down"}).status_code == 200
    from backend.services.network_model import load_model
    with SessionLocal() as db:
        model = load_model(db, demo["id"])
    finance = next(d.id for d in model.devices.values() if d.name == "Finance-PC")
    gateway = FlowAnalyzer(model).gateway_reachable(finance)
    assert gateway.code == "interface_down" and gateway.fail_link is not None
    assert gateway.detail["interface"] == "Gi0/0/1.10"
    report = health(client, auth, demo["id"])
    erp = next(f for f in report["flows"] if f["name"] == "Finance ERP access (HTTPS)")
    assert erp["ok"] is False and "Gi0/0/1.10" in erp["reason"]


def test_legacy_note_needs_the_demo_device_set_and_covers_faulty_demos(client, auth):
    from backend.models import Network
    from backend.services.demo_topology import DEMO_DESCRIPTION
    manual = client.post("/api/networks", headers=auth, json={"name": "Hand built", "description": DEMO_DESCRIPTION}).json()
    assert not any("legacy sample port names" in note for note in health(client, auth, manual["id"])["coverage_notes"])
    faulty = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    with SessionLocal() as db:
        network = db.get(Network, faulty["id"])
        network.metadata_json, network.source, network.environment = {}, "manual", "manual"  # legacy sample record
        db.commit()
    assert any("legacy sample port names" in note for note in health(client, auth, faulty["id"])["coverage_notes"])


def _shared_vlan_model(guest_role=True, server_role=False):
    guest = device(1, "GUEST", "pc", interfaces=[interface(1, 1, "eth0", "10.0.0.10")])
    server = device(2, "FILE", "server", interfaces=[interface(2, 2, "eth0", "10.0.0.20")])
    switch = device(3, "SW", "switch", "HPE Aruba", "Aruba 2530-24G",
                    [interface(3, 3, "1", vlan=20, mode="access"), interface(4, 3, "2", vlan=20, mode="access")])
    discovery = {}
    if guest_role:
        discovery["1"] = {"role": "Guest workstation"}
    if server_role:
        discovery["2"] = {"role": "File server"}
    return NetworkModel(1, {dev.id: dev for dev in (guest, server, switch)},
                        {1: LinkM(1, 1, 1, 3, 3), 2: LinkM(2, 2, 2, 3, 4)}, [], {"discovery": discovery})


def test_manually_added_server_is_sensitive_but_untrusted_needs_a_discovered_role():
    rows = [row for row in advisories(_shared_vlan_model()) if row["rule_id"] == "SEC001"]
    assert len(rows) == 1 and set(rows[0]["affected_devices"]) == {"GUEST", "FILE"}
    assert "FILE (server (stored device type))" in rows[0]["evidence"][0]["detail"]
    # Without discovery evidence nothing is classified as untrusted.
    assert not [row for row in advisories(_shared_vlan_model(guest_role=False)) if row["rule_id"] == "SEC001"]


def test_segments_exclude_blocked_trunks_shut_ports_and_undefined_vlans():
    guest = device(1, "GUEST", "pc", interfaces=[interface(1, 1, "eth0", "10.0.0.10")])
    server = device(2, "FILE", "server", interfaces=[interface(2, 2, "eth0", "10.0.0.20")])
    sw_a = device(3, "SW-A", "switch", "HPE Aruba", "Aruba 2530-24G",
                  [interface(3, 3, "1", vlan=20, mode="access"), interface(5, 3, "25", mode="trunk")])
    sw_b = device(4, "SW-B", "switch", "HPE Aruba", "Aruba 2530-24G",
                  [interface(4, 4, "1", vlan=20, mode="access"), interface(6, 4, "25", mode="trunk")])
    observations = {"discovery": {"1": {"role": "Guest workstation"}, "2": {"role": "File server"}}}
    model = NetworkModel(1, {dev.id: dev for dev in (guest, server, sw_a, sw_b)},
                         {1: LinkM(1, 1, 1, 3, 3), 2: LinkM(2, 2, 2, 4, 4), 3: LinkM(3, 3, 5, 4, 6)}, [], observations)
    sec001 = lambda: [row for row in advisories(model) if row["rule_id"] == "SEC001"]
    assert len(sec001()) == 1
    # Spanning tree blocks the only inter-switch trunk: two separate forwarding domains.
    sw_b.interfaces[6].stp_state = "blocking"
    assert not sec001()
    sw_b.interfaces[6].stp_state = None
    # VLAN 20 not defined on SW-B: its access port forwards nothing.
    sw_b.vlans = {30: None}
    assert not sec001()
    sw_b.vlans = {20: None, 30: None}
    # A shut access port is not attachment evidence.
    sw_b.interfaces[4].status = "down"
    assert not sec001()


def test_logical_interfaces_are_not_reported_as_absent_ports():
    from backend.services.interface_naming import port_info
    for name in ("Po1", "Port-channel1", "Vlan20", "Lo0", "Tunnel0"):
        assert port_info("Cisco", "Catalyst 2960X-24TS-L", "switch", name)["exists"] is None, name
    assert port_info("HPE Aruba", "Aruba 2930F-24G-4SFP+", "switch", "Trk1")["exists"] is None
    # Physical names stay checked: FortiGate port1 is still absent, Gi9/9/9 too.
    assert port_info("Fortinet", "FortiGate 60F", "firewall", "port1")["exists"] is False
    assert port_info("Cisco", "Catalyst 2960X-24TS-L", "switch", "Gi9/9/9")["exists"] is False
    a = device(1, "SW-A", "switch", "Cisco", "Catalyst 2960X-24TS-L", [interface(1, 1, "port-channel1", mode="trunk")])
    b = device(2, "SW-B", "switch", "Cisco", "Catalyst 2960X-24TS-L", [interface(2, 2, "Po1", mode="trunk")])
    model = NetworkModel(1, {1: a, 2: b}, {1: LinkM(1, 1, 1, 2, 2)}, [], {})
    assert not [f for f in physical_findings(model) if f.rule_id == "PHY002"]
    # The alias still gets the canonical-name advisory.
    assert [row["rule_id"] for row in advisories(model)] == ["NAME001"]


def test_kiosk_and_reception_pcs_are_not_sensitive_assets():
    model = _shared_vlan_model(guest_role=True)
    model.devices[2].type = "pc"
    model.observations["discovery"]["2"] = {"role": "Reception kiosk PC"}
    assert not [row for row in advisories(model) if row["rule_id"] == "SEC001"]
    model.observations["discovery"]["2"] = {"role": "Finance workstation"}
    assert [row["rule_id"] for row in advisories(model) if row["rule_id"] == "SEC001"] == ["SEC001"]


def test_media_down_interface_installs_no_connected_route_so_a_working_route_is_used():
    from backend.services.network_model import RouteM
    host_a = device(1, "HOST-A", "pc", interfaces=[interface(1, 1, "eth0", "10.1.0.10")])
    r1 = device(2, "R1", "router", "Cisco", "ISR 4331", [interface(2, 2, "Gi0/0/1", "10.1.0.1"),
                interface(3, 2, "Gi0/0/0", "10.5.0.1"), interface(9, 2, "Gi0/0/2", "10.9.0.254")])
    r2 = device(3, "R2", "router", "Cisco", "ISR 4331", [interface(4, 3, "Gi0/0/0", "10.5.0.2"), interface(5, 3, "Gi0/0/1", "10.9.0.1")])
    host_b = device(4, "HOST-B", "server", interfaces=[interface(6, 4, "eth0", "10.9.0.10")])
    # R1 copper Gi0/0/2 is cabled to a fibre SFP port: that cable cannot come up.
    spare = device(5, "SW-X", "switch", "HPE Aruba", "Aruba 2930F-24G-4SFP+", [interface(7, 5, "25", vlan=20, mode="access")])
    host_a.gateway, host_b.gateway = "10.1.0.1", "10.9.0.1"
    r1.routes = [RouteM(1, "10.9.0.0/24", "10.5.0.2")]
    r2.routes = [RouteM(2, "10.1.0.0/24", "10.5.0.1")]
    links = {1: LinkM(1, 1, 1, 2, 2), 2: LinkM(2, 2, 3, 3, 4), 3: LinkM(3, 3, 5, 4, 6), 4: LinkM(4, 2, 9, 5, 7)}
    model = NetworkModel(1, {dev.id: dev for dev in (host_a, r1, r2, host_b, spare)}, links, [])
    result = FlowAnalyzer(model).evaluate(1, 4)
    assert result.reachable, (result.code, result.detail)
    assert 3 in result.path  # via R2, not the broken connected interface
    assert "PHY001" in {f.rule_id for f in physical_findings(model)}  # the cable fault is still reported


def test_sec001_uses_derived_access_mode_every_addressed_nic_and_user_identity():
    # Ports with an omitted mode but a VLAN are access ports (forwarding's switchport rule).
    model = _shared_vlan_model()
    for port in model.devices[3].interfaces.values():
        port.mode = None
    assert [row["rule_id"] for row in advisories(model) if row["rule_id"] == "SEC001"] == ["SEC001"]
    # An earlier addressed but uncabled NIC does not hide the cabled one.
    model = _shared_vlan_model()
    server = model.devices[2]
    cabled = server.interfaces.pop(2)
    server.interfaces[20] = interface(20, 2, "eth0", "10.0.0.21")  # addressed, not cabled
    cabled.name = "eth1"
    server.interfaces[2] = cabled
    assert list(server.interfaces)[0] == 20
    assert [row["rule_id"] for row in advisories(model) if row["rule_id"] == "SEC001"] == ["SEC001"]
    # A device the operator identified as a server is sensitive, not an "Unknown host".
    model = _shared_vlan_model()
    model.observations["discovery"]["1"] = {"role": "Unknown host"}
    model.observations["discovery"]["2"] = {"role": "Unknown host", "identity_source": "user supplied"}
    rows = [row for row in advisories(model) if row["rule_id"] == "SEC001"]
    assert len(rows) == 1 and set(rows[0]["affected_devices"]) == {"GUEST", "FILE"}


def test_flows_with_duplicate_names_are_counted_separately(client, auth):
    created = client.post("/api/networks/samples", headers=auth, json={"provider": "sample", "scenario": "mixed"}).json()
    nid = created["network_id"]
    intents = client.get(f"/api/networks/{nid}/intents", headers=auth).json()
    dns = next(i for i in intents if i["name"] == "Finance DNS resolution")
    payload = {k: dns[k] for k in ("source_device_id", "destination_device_id", "protocol", "port", "expected_action", "criticality")}
    assert client.put(f"/api/intents/{dns['id']}", headers=auth, json={**payload, "name": "Finance ERP access (HTTPS)"}).status_code == 200
    report = health(client, auth, nid)
    note = next(note for note in report["coverage_notes"] if "R1–R3 link" in note)
    assert note.startswith("2 required flow(s)")
    ospf = next(issue for issue in report["issues"] if issue["rule_id"] == "OSPF001")
    assert "2 required flow(s) fail" in ospf["symptom"]


def test_sec001_registers_every_connected_nic_of_a_device():
    guest = device(1, "GUEST", "pc", interfaces=[interface(1, 1, "eth0", "10.0.0.10")])
    # The server's first NIC is on management VLAN 10; only its second NIC shares the guest VLAN.
    server = device(2, "FILE", "server", interfaces=[interface(20, 2, "eth0", "10.10.0.20"), interface(2, 2, "eth1", "10.0.0.20")])
    switch = device(3, "SW", "switch", "HPE Aruba", "Aruba 2530-24G",
                    [interface(3, 3, "1", vlan=20, mode="access"), interface(4, 3, "2", vlan=20, mode="access"),
                     interface(5, 3, "3", vlan=10, mode="access")])
    switch.vlans = {10: None, 20: None}
    observations = {"discovery": {"1": {"role": "Guest workstation"}, "2": {"role": "File server"}}}
    model = NetworkModel(1, {dev.id: dev for dev in (guest, server, switch)},
                         {1: LinkM(1, 1, 1, 3, 3), 2: LinkM(2, 2, 2, 3, 4), 3: LinkM(3, 2, 20, 3, 5)}, [], observations)
    rows = [row for row in advisories(model) if row["rule_id"] == "SEC001"]
    assert len(rows) == 1 and set(rows[0]["affected_devices"]) == {"GUEST", "FILE"}


def _intent_payload(intent, **changes):
    keys = ("name", "source_device_id", "destination_device_id", "protocol", "port", "expected_action", "criticality")
    return {**{k: intent[k] for k in keys}, **changes}


def test_findings_relate_to_flow_keys_not_shared_names(client, auth):
    nid = client.post("/api/networks/samples", headers=auth, json={"provider": "sample", "scenario": "acl"}).json()["network_id"]
    intents = client.get(f"/api/networks/{nid}/intents", headers=auth).json()
    hr = next(i for i in intents if i["name"] == "HR ERP access (HTTPS)")
    assert client.put(f"/api/intents/{hr['id']}", headers=auth,
                      json=_intent_payload(hr, name="Finance ERP access (HTTPS)")).status_code == 200
    # HR now fails earlier, at its access VLAN, not at the ACL that blocks Finance.
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    sw1 = next(d for d in topo["devices"] if d["name"] == "SW1")
    port = next(i for i in sw1["interfaces"] if i["name"] == "Gi1/0/2")
    assert client.put(f"/api/interfaces/{port['id']}", headers=auth, json={"name": port["name"], "vlan_id": 30}).status_code == 200
    report = health(client, auth, nid)
    acl = next(issue for issue in report["issues"] if issue["rule_id"] == "ACL001")
    assert "1 required flow(s) fail" in acl["symptom"], acl["symptom"]
    vlan = next(issue for issue in report["issues"] if issue["rule_id"] == "VLAN002")
    assert "2 required flow(s) fail" in vlan["symptom"], vlan["symptom"]  # HR's two flows, not Finance's


def test_opposite_direction_failures_get_separate_consistent_coverage_notes(client, auth):
    nid = client.post("/api/networks/samples", headers=auth, json={"provider": "sample", "scenario": "routing"}).json()["network_id"]
    intents = client.get(f"/api/networks/{nid}/intents", headers=auth).json()
    erp = next(i for i in intents if i["name"] == "Finance ERP access (HTTPS)")
    created = client.post(f"/api/networks/{nid}/intents", headers=auth, json=_intent_payload(
        erp, name="ERP to Finance callback", source_device_id=erp["destination_device_id"], destination_device_id=erp["source_device_id"]))
    assert created.status_code == 201, created.text
    notes = [note for note in health(client, auth, nid)["coverage_notes"] if "R1–R3 link" in note]
    assert notes
    for note in notes:
        unevaluated = set(note.split("beyond that point (")[1].split(")")[0].split(", "))
        evaluated = set(note.split("Forwarding through ")[1].split(" was evaluated")[0].split(", ")) if "Forwarding through" in note else set()
        assert not unevaluated & evaluated, note




