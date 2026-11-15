"""Prototype validation scenarios (brief 7.7) and Golden Demo (brief 10.2) via the API."""
import pytest


@pytest.fixture()
def demo(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    devices = {d["name"]: d for d in topology["devices"]}

    def iface(device, name):
        return next(i["id"] for i in devices[device]["interfaces"] if i["name"] == name)

    def analyze(device, change_type, interface=None, **parameters):
        created = client.post("/api/changes", headers=auth, json={
            "device_id": devices[device]["id"], "change_type": change_type, "interface_id": interface,
            "parameters": parameters, "reason": "test"})
        assert created.status_code == 201, created.text
        result = client.post(f"/api/changes/{created.json()['id']}/analyze", headers=auth)
        assert result.status_code == 200, result.text
        return result.json()

    return {"network": network, "devices": devices, "iface": iface, "analyze": analyze}


def rules_of(assessment):
    return {f["rule_id"] for f in assessment["findings"]}


def affected(assessment):
    return {(i["source_device"], i["destination_device"]) for i in assessment["impacts"] if i["affected"]}


def test_baseline_has_no_findings_for_safe_change(demo):
    result = demo["analyze"]("SW1", "vlan_database", action="add", vlan_id=40, name="GUEST")
    assert result["risk_level"] == "LOW"
    assert result["recommendation"] == "DEPLOY"
    assert result["validation_result"] == "PASS"
    assert not result["findings"] and not affected(result)
    assert all(c["status"] == "passed" for c in result["checks"])


def test_scenario_a_ospf_area_mismatch_matches_brief(demo):
    result = demo["analyze"]("R1", "ospf_area", demo["iface"]("R1", "Gi0/0/0"), area=1)
    # Score = 100 x S x (1 + I + E) / 24: High severity, a critical intent broken, an internet flow affected.
    assert result["risk_factors"] == {"S": 3, "I": 3, "E": 1}
    assert result["risk_score"] == 62 and result["risk_level"] == "HIGH"
    assert result["issue"] == "OSPF_AREA_MISMATCH"
    assert sorted(result["affected_devices"]) == ["R1", "R2"]
    assert ["Finance-PC", "SW1", "R2", "R1", "R3", "SW2", "ERP"] in result["affected_paths"]
    assert result["recommendation"] == "DO_NOT_DEPLOY"
    assert "Area 0 to Area 1" in result["explanation"] and "OSPF adjacency" in result["explanation"]
    assert result["actions"][0] == "Keep both interfaces in Area 0, or"


def test_golden_demo_modify_and_reanalyse_then_save(client, auth, demo):
    r1 = demo["devices"]["R1"]
    g00 = demo["iface"]("R1", "Gi0/0/0")
    change = client.post("/api/changes", headers=auth, json={
        "device_id": r1["id"], "change_type": "ospf_area", "interface_id": g00, "parameters": {"area": 1}}).json()
    first = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert first["risk_level"] == "HIGH"
    modified = client.put(f"/api/changes/{change['id']}", headers=auth, json={
        "device_id": r1["id"], "change_type": "ospf_area", "interface_id": g00, "parameters": {"area": 0}})
    assert modified.json()["proposed_value"] == "Area 0"
    second = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert second["risk_level"] == "LOW" and second["validation_result"] == "PASS"
    saved = client.post(f"/api/assessments/{second['id']}/save", headers=auth).json()
    assert saved["saved"] is True
    history = client.get("/api/assessments?saved=true", headers=auth).json()
    assert [a["id"] for a in history] == [second["id"]]
    assert client.get(f"/api/changes/{change['id']}", headers=auth).json()["status"] == "saved"
    assert len(client.get(f"/api/assessments?change_id={change['id']}", headers=auth).json()) == 2


def test_scenario_b_acl_blocks_required_erp_flow(demo):
    result = demo["analyze"]("R3", "acl_add", sequence=10, action="deny", protocol="tcp",
                             source="10.20.0.0/24", destination="192.168.30.10", port=443)
    assert result["risk_level"] == "CRITICAL"
    assert rules_of(result) == {"ACL001"}
    assert affected(result) == {("Finance-PC", "ERP")}
    assert result["recommendation"] == "DO_NOT_DEPLOY"


def test_acl_on_router_without_acl_activates_implicit_deny(demo):
    result = demo["analyze"]("R1", "acl_add", sequence=10, action="deny", protocol="tcp",
                             source="10.20.0.0/24", destination="192.168.30.10", port=443)
    # Every routed flow through R1 hits the implicit deny, including Finance-PC → INTERNET.
    assert affected(result) == {("Finance-PC", "ERP"), ("Finance-PC", "DNS"), ("HR-PC", "ERP"), ("HR-PC", "DNS"),
                                ("Finance-PC", "INTERNET")}
    assert any("implicit deny" in f["message"] for f in result["findings"])


def test_scenario_c_access_vlan_change(demo):
    result = demo["analyze"]("SW1", "access_vlan", demo["iface"]("SW1", "Gi1/0/1"), vlan_id=20)
    assert result["risk_level"] == "HIGH"
    assert rules_of(result) == {"VLAN001"}
    assert ("Finance-PC", "ERP") in affected(result)


def test_vlan_unavailable(demo):
    result = demo["analyze"]("SW1", "access_vlan", demo["iface"]("SW1", "Gi1/0/1"), vlan_id=30)
    assert rules_of(result) == {"VLAN002"} and result["risk_level"] == "HIGH"


def test_scenario_d_gateway_subnet_mismatch(demo):
    result = demo["analyze"]("R3", "ip_address", demo["iface"]("R3", "Gi0/0/1"),
                             ip_address="192.168.40.1", subnet_mask="255.255.255.0")
    assert result["risk_level"] == "HIGH"
    assert rules_of(result) == {"IP001", "IP002"}
    assert ("ERP", "192.168.30.1") in affected(result)  # ERP-to-gateway affected


def test_scenario_e_invalid_static_next_hop(demo):
    route = demo["devices"]["R1"]["static_routes"][0]
    result = demo["analyze"]("R1", "static_route", action="modify", route_id=route["id"],
                             destination="0.0.0.0/0", next_hop="10.0.99.99")
    assert rules_of(result) == {"ROUTE001"} and result["risk_level"] == "HIGH"


def test_permissive_acl_breaks_isolation(demo):
    result = demo["analyze"]("R2", "acl_add", sequence=5, action="permit", protocol="ip", source="any", destination="any")
    assert rules_of(result) == {"ACL002"}
    assert ("HR-PC", "Finance-PC") in affected(result)


def test_duplicate_ip(demo):
    result = demo["analyze"]("R2", "ip_address", demo["iface"]("R2", "Gi0/0/0"), ip_address="10.0.13.1", subnet_mask="/30")
    assert "IP003" in rules_of(result)


def test_ospf_network_removed_and_link_shutdown_root_causes(demo):
    removed = demo["analyze"]("R3", "ospf_network", demo["iface"]("R3", "Gi0/0/1"), action="remove")
    assert rules_of(removed) == {"OSPF002"} and removed["risk_level"] == "HIGH"
    shut = demo["analyze"]("R1", "interface_status", demo["iface"]("R1", "Gi0/0/1"), status="admin-down")
    assert rules_of(shut) == {"LINK001"}
    assert shut["findings"][0]["severity"] == "HIGH"  # escalated: required flows break


def test_missing_route_when_static_route_removed(client, auth):
    """User-built static network without intents: implicit host-pair flows are protected."""
    net = client.post("/api/networks", headers=auth, json={"name": "Static Lab", "network_type": "Lab"}).json()

    def dev(name, dtype, gateway=None):
        return client.post(f"/api/networks/{net['id']}/devices", headers=auth,
                           json={"name": name, "device_type": dtype, "default_gateway": gateway}).json()

    def nic(device, name, ip):
        return client.post(f"/api/devices/{device['id']}/interfaces", headers=auth,
                           json={"name": name, "ip_address": ip, "subnet_mask": "/24"}).json()

    def link(a, ai, b, bi):
        client.post(f"/api/networks/{net['id']}/links", headers=auth, json={
            "source_device_id": a["id"], "source_interface_id": ai["id"],
            "destination_device_id": b["id"], "destination_interface_id": bi["id"]})

    ra, rb = dev("RA", "router"), dev("RB", "router")
    pa, pb = dev("PA", "pc", "10.1.0.1"), dev("PB", "pc", "10.2.0.1")
    link(ra, nic(ra, "lan", "10.1.0.1"), pa, nic(pa, "eth0", "10.1.0.10"))
    link(rb, nic(rb, "lan", "10.2.0.1"), pb, nic(pb, "eth0", "10.2.0.10"))
    link(ra, nic(ra, "wan", "10.9.0.1"), rb, nic(rb, "wan", "10.9.0.2"))
    route = client.post(f"/api/devices/{ra['id']}/static-routes", headers=auth,
                        json={"destination": "10.2.0.0/24", "next_hop": "10.9.0.2"}).json()
    client.post(f"/api/devices/{rb['id']}/static-routes", headers=auth,
                json={"destination": "10.1.0.0/24", "next_hop": "10.9.0.1"})

    change = client.post("/api/changes", headers=auth, json={
        "device_id": ra["id"], "change_type": "static_route", "parameters": {"action": "remove", "route_id": route["id"]}})
    result = client.post(f"/api/changes/{change.json()['id']}/analyze", headers=auth).json()
    assert rules_of(result) == {"ROUTE002"}
    assert ("PA", "PB") in affected(result)
    # High severity, implicit host flows only (I = 1), internal (E = 0): 100 x 3 x 2 / 24 = 25.
    assert result["risk_score"] == 25 and result["risk_level"] == "MEDIUM"
    assert result["recommendation"] == "DO_NOT_DEPLOY"  # it breaks working traffic


def test_change_validation_errors(client, auth, demo):
    r1 = demo["devices"]["R1"]
    bad = client.post("/api/changes", headers=auth, json={
        "device_id": r1["id"], "change_type": "ospf_area", "interface_id": demo["iface"]("R1", "Gi0/0/0"),
        "parameters": {"area": "abc"}})
    assert bad.status_code == 422
    wrong_device = client.post("/api/changes", headers=auth, json={
        "device_id": demo["devices"]["SW1"]["id"], "change_type": "ospf_area", "parameters": {"area": 1}})
    assert wrong_device.status_code == 422
    unknown = client.post("/api/changes", headers=auth, json={"device_id": r1["id"], "change_type": "bgp"})
    assert unknown.status_code == 422


def test_dashboard_counts_changes(client, auth, demo):
    demo["analyze"]("R1", "ospf_area", demo["iface"]("R1", "Gi0/0/0"), area=1)
    summary = client.get("/api/dashboard/summary", headers=auth).json()
    assert summary["pending_changes"] == 1 and summary["high_critical_changes"] == 1
    assert summary["recent_assessments"][0]["risk_level"] == "HIGH"


def test_deleting_device_keeps_change_history(client, auth, demo):
    result = demo["analyze"]("ERP", "default_gateway", gateway="192.168.30.254")
    client.delete(f"/api/devices/{demo['devices']['ERP']['id']}", headers=auth)
    kept = client.get(f"/api/assessments/{result['id']}", headers=auth)
    assert kept.status_code == 200 and kept.json()["change"]["device"] == "ERP"


def test_demo_has_internet_access_flow(client, auth, demo):
    intents = client.get(f"/api/networks/{demo['network']['id']}/intents", headers=auth).json()
    assert len(intents) == 6
    internet = next(i for i in intents if i["name"] == "Finance Internet access (HTTPS)")
    assert (internet["protocol"], internet["port"], internet["expected_action"], internet["criticality"]) == (
        "tcp", 443, "allow", "high")
    report = client.get(f"/api/networks/{demo['network']['id']}/health-check", headers=auth).json()
    flow = next(f for f in report["flows"] if f["name"] == "Finance Internet access (HTTPS)")
    assert flow["ok"] and (flow["source"], flow["destination"]) == ("Finance-PC", "INTERNET")
    names = {d["id"]: n for n, d in demo["devices"].items()}
    assert [names[i] for i in flow["path_device_ids"]] == ["Finance-PC", "SW1", "R2", "R1", "FW1", "INTERNET"]


def test_removing_default_route_cuts_internet_and_is_high_risk(demo):
    route = demo["devices"]["R1"]["static_routes"][0]
    assert route["destination"] == "0.0.0.0/0"
    result = demo["analyze"]("R1", "static_route", action="remove", route_id=route["id"])
    assert result["risk_level"] in ("HIGH", "CRITICAL") and result["recommendation"] == "DO_NOT_DEPLOY"
    assert affected(result) == {("Finance-PC", "INTERNET")}
    assert rules_of(result) == {"ROUTE002"}
    assert "default route that R1 advertises into OSPF" in result["findings"][0]["message"]


def test_shutting_the_wan_cuts_internet_and_is_high_risk(demo):
    result = demo["analyze"]("FW1", "interface_status", demo["iface"]("FW1", "wan1"), status="admin-down")
    assert result["risk_level"] in ("HIGH", "CRITICAL") and result["recommendation"] == "DO_NOT_DEPLOY"
    assert affected(result) == {("Finance-PC", "INTERNET")}


def test_golden_ospf_area_change_on_r1_g01(demo):
    result = demo["analyze"]("R1", "ospf_area", demo["iface"]("R1", "Gi0/0/1"), area=1)
    assert result["risk_level"] == "HIGH" and result["recommendation"] == "DO_NOT_DEPLOY"
    assert rules_of(result) == {"OSPF001"}
    assert ("Finance-PC", "INTERNET") not in affected(result)  # the internet path does not use R1–R3
