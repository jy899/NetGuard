"""Regression tests for the prototype correctness review (forwarding, risk, fixes, validation)."""
import pytest

from backend.services.forwarding import FlowAnalyzer
from backend.services.network_model import DeviceM, IfaceM, LinkM, NetworkModel
from backend.tests.helpers import approve, approve_and_apply  # noqa: E402


def _same_lan_model(second_ip="10.0.0.200", second_mask="255.255.255.128", routed_return=False):
    first = DeviceM(1, "PC-A", "pc", None, {
        11: IfaceM(11, 1, "eth0", "10.0.0.10", "255.255.255.0", None, "up", None, None)})
    second = DeviceM(2, "PC-B", "pc", "10.0.0.129" if routed_return else None, {
        21: IfaceM(21, 2, "eth0", second_ip, second_mask, None, "up", None, None)})
    switch = DeviceM(3, "SW", "switch", None, {
        31: IfaceM(31, 3, "Gi0/1", None, None, 10, "up", None, "access"),
        32: IfaceM(32, 3, "Gi0/2", None, None, 10, "up", None, "access")}, vlans={10: "LAN"})
    devices = {1: first, 2: second, 3: switch}
    links = {1: LinkM(1, 1, 11, 3, 31), 2: LinkM(2, 2, 21, 3, 32)}
    if routed_return:
        switch.interfaces[33] = IfaceM(33, 3, "Gi0/3", None, None, 10, "up", None, "access")
        devices[4] = DeviceM(4, "R", "router", None, {
            41: IfaceM(41, 4, "G0/0", "10.0.0.129", "255.255.255.0", None, "up", None, None)})
        links[3] = LinkM(3, 3, 33, 4, 41)
    return NetworkModel(1, devices, links, [])


def test_same_lan_requires_a_working_return_path_when_endpoint_masks_differ():
    analyzer = FlowAnalyzer(_same_lan_model())
    for src, dst in ((1, 2), (2, 1)):
        result = analyzer.evaluate(src, dst, "tcp", 443)
        assert not result.reachable
        assert result.code == "no_default_gateway" and result.detail["host"] == "PC-B"


@pytest.mark.parametrize("second_ip, second_mask", [
    ("10.0.0.200", "255.255.255.0"),
    ("10.0.0.20", "255.255.255.128"),
])
def test_mutually_on_link_hosts_do_not_need_a_gateway(second_ip, second_mask):
    analyzer = FlowAnalyzer(_same_lan_model(second_ip, second_mask))
    assert analyzer.evaluate(1, 2).reachable and analyzer.evaluate(2, 1).reachable


def test_asymmetric_on_link_decisions_work_when_the_other_leg_has_a_route():
    analyzer = FlowAnalyzer(_same_lan_model(routed_return=True))
    assert analyzer.evaluate(1, 2, "tcp", 443).reachable
    assert analyzer.evaluate(2, 1, "tcp", 443).reachable


# ------------------------------------------------------------------ helpers
@pytest.fixture()
def demo(client, auth):
    def make(faulty=False):
        network = client.post(f"/api/networks/demo?faulty={str(faulty).lower()}", headers=auth).json()
        return Net(client, auth, network["id"])
    return make


@pytest.fixture()
def lab(client, auth):
    """Static-routing lab: PC1 - RA - RB - PC2, RB - NET (internet). No OSPF, no ACLs."""
    def make(routes, intents=(), pc1_gateway="10.1.0.1"):
        nid = client.post("/api/networks", headers=auth, json={"name": f"lab {len(routes)} {pc1_gateway}"}).json()["id"]
        ids, iids = {}, {}
        for name, kind, gw in [("RA", "router", None), ("RB", "router", None), ("PC1", "pc", pc1_gateway),
                               ("PC2", "pc", "10.2.0.1"), ("NET", "internet", None)]:
            ids[name] = client.post(f"/api/networks/{nid}/devices", headers=auth,
                                    json={"name": name, "device_type": kind, "default_gateway": gw}).json()["id"]
        for dev, name, ip, mask in [("RA", "g0", "10.1.0.1", "24"), ("RA", "g1", "10.9.0.1", "30"),
                                    ("RB", "g0", "10.2.0.1", "24"), ("RB", "g1", "10.9.0.2", "30"),
                                    ("RB", "g2", "203.0.113.2", "30"), ("PC1", "eth0", "10.1.0.10", "24"),
                                    ("PC2", "eth0", "10.2.0.10", "24"), ("NET", "isp", "203.0.113.1", "30")]:
            response = client.post(f"/api/devices/{ids[dev]}/interfaces", headers=auth,
                                   json={"name": name, "ip_address": ip, "subnet_mask": mask})
            iids[(dev, name)] = response.json()["id"]
        for (a, ai), (b, bi) in [(("PC1", "eth0"), ("RA", "g0")), (("RA", "g1"), ("RB", "g1")),
                                 (("RB", "g0"), ("PC2", "eth0")), (("RB", "g2"), ("NET", "isp"))]:
            client.post(f"/api/networks/{nid}/links", headers=auth, json={
                "source_device_id": ids[a], "source_interface_id": iids[(a, ai)],
                "destination_device_id": ids[b], "destination_interface_id": iids[(b, bi)]})
        for dev, destination, next_hop in routes:
            assert client.post(f"/api/devices/{ids[dev]}/static-routes", headers=auth,
                               json={"destination": destination, "next_hop": next_hop}).status_code == 201
        for name, src, dst, protocol, port in intents:
            assert client.post(f"/api/networks/{nid}/intents", headers=auth, json={
                "name": name, "source_device_id": ids[src], "destination_device_id": ids[dst],
                "protocol": protocol, "port": port, "expected_action": "allow"}).status_code == 201
        return Net(client, auth, nid)
    return make


FULL_ROUTES = [("RA", "0.0.0.0/0", "10.9.0.2"), ("RB", "10.1.0.0/24", "10.9.0.1"), ("RB", "0.0.0.0/0", "203.0.113.1")]


class Net:
    def __init__(self, client, auth, network_id):
        self.client, self.auth, self.id = client, auth, network_id
        self.reload()

    def reload(self):
        topology = self.client.get(f"/api/networks/{self.id}/topology", headers=self.auth).json()
        self.devices = {d["name"]: d for d in topology["devices"]}

    def iface(self, device, name):
        return next(i["id"] for i in self.devices[device]["interfaces"] if i["name"] == name)

    def propose(self, device, change_type, interface=None, **parameters):
        return self.client.post("/api/changes", headers=self.auth, json={
            "device_id": self.devices[device]["id"], "change_type": change_type,
            "interface_id": self.iface(device, interface) if interface else None, "parameters": parameters})

    def analyze(self, device, change_type, interface=None, **parameters):
        created = self.propose(device, change_type, interface, **parameters)
        assert created.status_code == 201, created.text
        result = self.client.post(f"/api/changes/{created.json()['id']}/analyze", headers=self.auth)
        assert result.status_code == 200, result.text
        return result.json()

    def health(self):
        return self.client.get(f"/api/networks/{self.id}/health-check", headers=self.auth).json()

    def apply_fix(self, fix):
        change = self.client.post("/api/changes", headers=self.auth, json={
            "device_id": fix["device_id"], "interface_id": fix["interface_id"],
            "change_type": fix["change_type"], "parameters": fix["parameters"]}).json()
        return approve_and_apply(self.client, self.auth, change["id"])


def rules(result):
    return {f["rule_id"] for f in result["findings"]}


def broken(result):
    return {i["service"] for i in result["impacts"] if i["status"] in ("broken", "violation")}


# ------------------------------------------- risk never LOW when flows break
def test_removing_server_gateway_is_not_low_risk(demo):
    result = demo().analyze("ERP", "default_gateway", gateway="")
    assert result["risk_level"] == "HIGH" and result["recommendation"] == "DO_NOT_DEPLOY"
    assert rules(result) == {"IP002"}
    assert "no default gateway configured" in result["findings"][0]["message"]


def test_static_route_loop_is_detected(demo):
    # R1 sends server traffic to R2, R2 (OSPF) sends it back to R1.
    result = demo().analyze("R1", "static_route", action="add", destination="192.168.30.0/24", next_hop="10.0.12.2")
    assert result["risk_level"] == "HIGH" and rules(result) == {"ROUTE002"}
    assert "loops" in result["findings"][0]["message"]
    assert len(broken(result)) == 4


def test_shut_subinterface_is_a_link_issue(demo):
    result = demo().analyze("R2", "interface_status", "Gi0/0/1.10", status="admin-down")
    assert rules(result) == {"LINK001"} and result["risk_level"] == "HIGH"
    assert broken(result) == {"Finance ERP access (HTTPS)", "Finance DNS resolution", "Finance Internet access (HTTPS)",
                              "Finance-PC default gateway"}


def test_shut_trunk_port_reports_the_link_not_the_gateways(demo):
    result = demo().analyze("SW1", "interface_status", "Gi1/0/24", status="admin-down")
    assert rules(result) == {"LINK001"} and result["risk_level"] == "HIGH"
    assert result["issue"] == "ACTIVE_LINK_DISABLED"


# ------------------------------------------------------- deny intents
def test_restoring_isolation_is_not_a_violation(client, auth, demo):
    net = demo()
    r2 = net.devices["R2"]["id"]
    client.post(f"/api/devices/{r2}/acl-rules", headers=auth,
                json={"sequence": 5, "action": "permit", "protocol": "ip", "source": "any", "destination": "any"})
    report = net.health()
    issue = next(i for i in report["issues"] if i["subject"] == "flow:intent-5" or i["key"].startswith("ACL002|flow"))
    best = issue["fixes"][0]["verification"]
    assert best["verdict"] == "recommended" and not best["broken_flows"]
    assert "HR-PC → Finance-PC" in best["restored_flows"]
    assert net.apply_fix(issue["fixes"][0]).status_code == 200
    assert net.health()["status"] == "healthy"


# ------------------------------------------------------- forwarding model
def test_invalid_static_route_falls_back_to_default_route(lab):
    net = lab(FULL_ROUTES)
    result = net.analyze("RA", "static_route", action="add", destination="10.2.0.0/24", next_hop="10.9.0.9")
    assert rules(result) == {"ROUTE001"}
    assert not broken(result)  # the invalid route is not installed; the default route still carries the traffic


def test_internet_endpoint_can_be_a_flow_source(lab):
    net = lab(FULL_ROUTES, intents=[("web in", "NET", "PC1", "tcp", 80), ("web out", "PC1", "NET", "tcp", 443)])
    report = net.health()
    assert report["status"] == "healthy", report["flows"]


def test_default_route_to_internet_does_not_hide_a_missing_internal_route(lab):
    net = lab(FULL_ROUTES)
    route = next(r for r in net.devices["RB"]["static_routes"] if r["destination"] == "10.1.0.0/24")
    result = net.analyze("RB", "static_route", action="remove", route_id=route["id"])
    assert rules(result) == {"ROUTE002"} and result["risk_level"] in ("MEDIUM", "HIGH")
    assert result["recommendation"] == "DO_NOT_DEPLOY"
    assert "out of the routed network" in result["findings"][0]["message"]


# ------------------------------------------- health check without intents
def test_health_check_without_intents_finds_missing_return_route(lab):
    net = lab([("RA", "0.0.0.0/0", "10.9.0.2")])
    report = net.health()
    assert report["status"] == "issues"
    assert [i["rule_id"] for i in report["issues"]] == ["ROUTE002"]
    fix = report["issues"][0]["fixes"][0]
    assert fix["label"] == "Add route 10.1.0.0/24 via 10.9.0.1 on RB"
    assert fix["verification"]["verdict"] == "recommended"
    assert net.apply_fix(fix).status_code == 200
    assert net.health()["status"] == "healthy"


def test_health_check_flags_host_without_gateway(lab):
    net = lab(FULL_ROUTES, pc1_gateway=None)
    report = net.health()
    issue = report["issues"][0]
    assert issue["rule_id"] == "IP002" and "no default gateway" in issue["message"]
    assert issue["fixes"][0]["label"] == "Set PC1 default gateway to 10.1.0.1"
    assert report["flows"][0]["kind"] == "implicit" and not report["flows"][0]["ok"]


def test_deny_only_acl_gets_a_permit_any_fix(client, auth, demo):
    net = demo()
    r1 = net.devices["R1"]["id"]
    client.post(f"/api/devices/{r1}/acl-rules", headers=auth, json={
        "sequence": 1, "action": "deny", "protocol": "udp", "source": "any", "destination": "any", "port": 53})
    report = net.health()
    labels = [f["label"] for i in report["issues"] for f in i["fixes"]]
    assert "Add 'permit ip any any' at the end of R1's ACL" in labels
    for _ in range(4):  # Fix All, one recommended fix at a time
        fixable = [i for i in report["issues"] if i["fixes"] and i["fixes"][0]["verification"]["verdict"] == "recommended"]
        if not fixable:
            break
        assert net.apply_fix(fixable[0]["fixes"][0]).status_code == 200
        report = net.health()
    assert report["status"] == "healthy"


# --------------------------------------------------------- input checks
@pytest.mark.parametrize("ip, mask, message", [
    ("192.168.30.0", "24", "network address"),
    ("192.168.30.255", "255.255.255.0", "broadcast address"),
])
def test_network_and_broadcast_addresses_are_rejected(demo, client, auth, ip, mask, message):
    net = demo()
    response = net.propose("R3", "ip_address", "Gi0/0/1", ip_address=ip, subnet_mask=mask)
    assert response.status_code == 422 and message in response.json()["detail"]
    response = client.put(f"/api/interfaces/{net.iface('R3', 'Gi0/0/1')}", headers=auth,
                          json={"name": "Gi0/0/1", "ip_address": ip, "subnet_mask": mask})
    assert response.status_code == 422 and message in response.text


def test_overlapping_router_subnets_are_rejected(demo, client, auth):
    net = demo()
    response = net.propose("R1", "ip_address", "Gi0/0/1", ip_address="10.0.12.5", subnet_mask="24")
    assert response.status_code == 422 and "overlaps R1 Gi0/0/0" in response.json()["detail"]
    response = client.post(f"/api/devices/{net.devices['R1']['id']}/interfaces", headers=auth,
                           json={"name": "G0/3", "ip_address": "10.0.12.6", "subnet_mask": "16"})
    assert response.status_code == 422 and "overlaps Gi0/0/0" in response.json()["detail"]


def test_point_to_point_31_is_allowed(demo):
    net = demo()
    assert net.propose("R1", "ip_address", "Gi0/0/2", ip_address="10.0.1.0", subnet_mask="31").status_code == 201


def test_access_vlan_change_only_on_access_ports(demo):
    response = demo().propose("SW1", "access_vlan", "Gi1/0/24", vlan_id=10)
    assert response.status_code == 422 and "trunk port" in response.json()["detail"]


def test_ids_sent_as_strings_are_accepted(demo):
    net = demo()
    route = net.devices["R1"]["static_routes"][0]
    assert net.propose("R1", "static_route", action="remove", route_id=str(route["id"])).status_code == 201


# ------------------------------------------------------------ lifecycle
def test_applied_change_cannot_be_modified_and_keeps_status(client, auth, demo):
    net = demo(faulty=True)
    issue = next(i for i in net.health()["issues"] if i["rule_id"] == "IP002")
    fix = issue["fixes"][0]
    change = client.post("/api/changes", headers=auth, json={
        "device_id": fix["device_id"], "interface_id": fix["interface_id"],
        "change_type": fix["change_type"], "parameters": fix["parameters"]}).json()
    assert approve_and_apply(client, auth, change["id"]).status_code == 200
    modified = client.put(f"/api/changes/{change['id']}", headers=auth, json={
        "device_id": fix["device_id"], "change_type": "default_gateway", "parameters": {"gateway": "192.168.30.254"}})
    assert modified.status_code == 409
    again = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert again["change"]["status"] == "applied"
    assert client.post(f"/api/assessments/{again['id']}/save", headers=auth).json()["change"]["status"] == "applied"


# ------------------------------------------------------------- commands
def test_first_acl_rule_commands_apply_the_acl(demo):
    result = demo().analyze("R1", "acl_add", sequence=10, action="deny", protocol="tcp",
                            source="10.21.0.0/24", destination="192.168.30.10", port=443)
    commands = result["change"]["commands"]
    assert " 10 deny tcp 10.21.0.0 0.0.0.255 host 192.168.30.10 eq 443" in commands
    assert "interface Gi0/0/0" in commands and " ip access-group NETGUARD-ACL in" in commands
    assert "has no entries" in result["explanation"]


def test_fix_that_reveals_a_hidden_issue_is_still_recommended(lab):
    # PC1 has no gateway AND RB has no return route: the second problem is hidden behind the first.
    net = lab([("RA", "0.0.0.0/0", "10.9.0.2")], pc1_gateway=None)
    report = net.health()
    assert [i["rule_id"] for i in report["issues"]] == ["IP002"]
    fix = report["issues"][0]["fixes"][0]
    assert fix["verification"]["verdict"] == "recommended"
    assert [r["rule_id"] for r in fix["verification"]["reveals"]] == ["ROUTE002"]
    assert fix["verification"]["risk_level"] == "LOW"
    assert net.apply_fix(fix).status_code == 200
    report = net.health()
    assert [i["rule_id"] for i in report["issues"]] == ["ROUTE002"]
    assert net.apply_fix(report["issues"][0]["fixes"][0]).status_code == 200
    assert net.health()["status"] == "healthy"


def test_change_that_breaks_a_flow_earlier_is_not_hidden(demo):
    # Faulty demo: Finance -> ERP already fails at the R1-R3 OSPF mismatch. Shutting R2 Gi0/0/0 makes it
    # fail earlier on the path, which is a new problem caused by the change.
    result = demo(faulty=True).analyze("R2", "interface_status", "Gi0/0/0", status="admin-down")
    assert "LINK001" in rules(result) and result["risk_level"] == "HIGH"
