"""Regression tests for the October 2026 prototype audit (input validation, access control,
hardware catalogue, configuration import and lab data checks)."""
import pytest

from backend.tests.helpers import group_id

from backend.core.security import verify_password
from backend.services.config_import import parse_configs
from backend.services.interface_naming import port_info


def _demo(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    return network, {d["name"]: d for d in topology["devices"]}


def _second_user(client, auth, username="reviewer"):
    created = client.post("/api/accounts", headers=auth, json={"username": username, "password": "reviewer-password",
                                                                "group_id": group_id(client, auth, "Network Engineers")})
    assert created.status_code == 201, created.text
    token = client.post("/api/auth/login", json={"username": username, "password": "reviewer-password"}).json()
    return {"Authorization": f"Bearer {token['access_token']}"}


# ------------------------------------------------------------------ input validation
@pytest.mark.parametrize("parameters", [
    {"ip_address": 99999, "subnet_mask": "/24"}, {"ip_address": ["10.0.0.1"], "subnet_mask": "/24"},
    {"ip_address": True, "subnet_mask": 0}, {"ip_address": "10.0.0.1", "subnet_mask": {"bits": 24}},
])
def test_non_text_change_parameters_are_rejected_not_server_errors(client, auth, parameters):
    _, devices = _demo(client, auth)
    r1 = devices["R1"]
    response = client.post("/api/changes", headers=auth, json={
        "device_id": r1["id"], "interface_id": r1["interfaces"][0]["id"], "change_type": "ip_address",
        "parameters": parameters})
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("change_type, parameters", [
    ("default_gateway", {"gateway": 1.5}), ("default_gateway", {"gateway": [1]}),
    ("static_route", {"action": "add", "destination": 1.5, "next_hop": "10.0.1.1"}),
    ("vlan_database", {"action": "add", "vlan_id": 40, "name": 5}),
    ("vlan_database", {"action": "add", "vlan_id": 40, "name": "X" * 33}),
])
def test_malformed_parameters_for_other_change_types_are_rejected(client, auth, change_type, parameters):
    _, devices = _demo(client, auth)
    device = {"default_gateway": "Finance-PC", "static_route": "R1", "vlan_database": "SW1"}[change_type]
    response = client.post("/api/changes", headers=auth, json={
        "device_id": devices[device]["id"], "change_type": change_type, "parameters": parameters})
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("path", ["/api/networks/99999999999999999999", "/api/devices/99999999999999999999",
                                  "/api/history/99999999999999999999"])
def test_out_of_range_identifiers_return_a_client_error(client, auth, path):
    response = client.get(path, headers=auth)
    assert response.status_code == 422 and response.json()["error"] == "validation_error"


@pytest.mark.parametrize("mask, expected", [("0.0.0.255", "wildcard"), ("0", "between 1 and 32"),
                                            ("/0", "between 1 and 32"), ("0.0.0.0", "/0")])
def test_interface_masks_reject_wildcards_and_zero_length(client, auth, mask, expected):
    _, devices = _demo(client, auth)
    response = client.post(f"/api/devices/{devices['ERP']['id']}/interfaces", headers=auth,
                           json={"name": "eth1", "ip_address": "172.31.0.5", "subnet_mask": mask})
    assert response.status_code == 422 and expected in response.json()["detail"]


def test_valid_masks_are_still_normalised(client, auth):
    _, devices = _demo(client, auth)
    response = client.post(f"/api/devices/{devices['ERP']['id']}/interfaces", headers=auth,
                           json={"name": "eth1", "ip_address": "172.31.0.5", "subnet_mask": "/30"})
    assert response.status_code == 201 and response.json()["subnet_mask"] == "255.255.255.252"


def test_damaged_password_hash_never_authenticates():
    assert verify_password("admin", "pbkdf2_sha256$not-a-number$salt$abcd") is False
    assert verify_password("admin", None) is False


# ------------------------------------------------------------------ accounts and access control
def test_builtin_admin_is_labelled_administrator(client, auth):
    assert client.get("/api/auth/me", headers=auth).json()["role"] == "Administrators"


def test_account_names_are_unique_ignoring_case(client, auth):
    _second_user(client, auth, "bob")
    for body in ({"username": "Bob"}, {"username": "ADMIN"}):
        response = client.post("/api/accounts", headers=auth, json={**body, "password": "password-123",
                                                                    "group_id": group_id(client, auth, "Network Engineers")})
        assert response.status_code == 409, body


def test_shared_networks_are_readable_but_only_owner_or_admin_can_delete(client, auth):
    network, _ = _demo(client, auth)
    other = _second_user(client, auth)
    assert client.get(f"/api/networks/{network['id']}/topology", headers=other).status_code == 200
    assert client.delete(f"/api/networks/{network['id']}", headers=other).status_code == 403
    own = client.post("/api/networks", headers=other, json={"name": "Reviewer lab"}).json()
    assert client.delete(f"/api/networks/{own['id']}", headers=other).status_code == 204
    # an administrator can remove any network
    theirs = client.post("/api/networks", headers=other, json={"name": "Reviewer lab 2"}).json()
    assert client.delete(f"/api/networks/{theirs['id']}", headers=auth).status_code == 204


def test_other_users_can_read_a_discovery_but_not_act_on_it(client, auth):
    scan = client.post("/api/discovery/scan", headers=auth,
                       json={"target": "172.16.10.0/24", "authorized_scope": True}).json()
    other = _second_user(client, auth)
    network_id = scan["network_id"]
    result = client.get(f"/api/discovery/{network_id}", headers=other)
    assert result.status_code == 200 and result.json()["devices"]
    assert client.post(f"/api/discovery/{network_id}/skip", headers=other,
                       json={"all": True}).status_code == 403
    core = next(d for d in scan["devices"] if d["name"] == "CORE-SW-01")
    assert client.post(f"/api/discovery/{network_id}/authenticate", headers=other, json={
        "device_ids": [core["id"]], "method": "ssh", "username": "admin", "password": "admin"}).status_code == 403
    # the owner is unaffected
    assert client.post(f"/api/discovery/{network_id}/skip", headers=auth,
                       json={"all": True}).status_code == 200




# ------------------------------------------------------------------ hardware catalogue
def test_isr4331_port_types_follow_the_hardware():
    labels = {name: port_info("Cisco", "ISR 4331", "router", name)["label"] for name in ("Gi0/0/0", "Gi0/0/1", "Gi0/0/2")}
    assert "combo" in labels["Gi0/0/0"] and "SFP" not in labels["Gi0/0/1"] and "SFP slot" in labels["Gi0/0/2"]
    assert port_info("Cisco", "ISR 4331", "router", "Gi0/0/3")["exists"] is False


@pytest.mark.parametrize("port", ["a", "b", "internal5", "dmz", "wan2"])
def test_fortigate_60f_catalogue_includes_all_front_panel_ports(port):
    info = port_info("Fortinet", "FortiGate 60F", "firewall", port)
    assert info["exists"] is True and info["media"] == "copper"


def test_demo_network_has_no_physical_findings(client, auth):
    network, _ = _demo(client, auth)
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    assert report["status"] == "healthy"
    assert not [a for a in report["advisories"] if a["rule_id"].startswith("PHY")]


# ------------------------------------------------------------------ configuration import
SWITCH = """hostname SW7
ip routing
vlan 10
 name FINANCE USERS
vlan 20
interface GigabitEthernet1/0/24
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20-22
 switchport trunk allowed vlan add 30
 switchport trunk allowed vlan remove 21
 speed 1000
interface GigabitEthernet1/0/23
 switchport mode trunk
 switchport trunk allowed vlan except 1-4000
interface Vlan10
 ip address 10.10.0.1 255.255.255.0
interface Vlan20
 ip address 10.20.0.1 255.255.255.0
"""


def test_import_reads_trunk_vlans_native_vlan_speed_and_vlan_names():
    devs, warnings = parse_configs(SWITCH)
    sw = devs["SW7"]
    trunk = sw.ifs["Gi1/0/24"]
    assert trunk.allowed == [10, 20, 22, 30] and trunk.native == 99 and trunk.speed == 1000
    assert sw.ifs["Gi1/0/23"].allowed == list(range(4001, 4095))
    assert sw.vlans[10] == "FINANCE USERS"


def test_import_keeps_multilayer_switch_svis_as_routed_interfaces(client, auth):
    response = client.post("/api/networks/import", headers=auth, json={"name": "L3", "configs": SWITCH})
    assert response.status_code == 200
    topology = client.get(f"/api/networks/{response.json()['network_id']}/topology", headers=auth).json()
    switch = next(d for d in topology["devices"] if d["device_type"] == "switch")
    assert switch["config_facts"]["ip_routing"] is True
    assert any(i["name"].lower().startswith("vlan") and i["ip_address"] for i in switch["interfaces"])


def test_import_stores_trunk_settings_on_switch_ports(client, auth):
    response = client.post("/api/networks/import", headers=auth, json={"name": "Trunks", "configs": SWITCH})
    topology = client.get(f"/api/networks/{response.json()['network_id']}/topology", headers=auth).json()
    trunk = next(i for d in topology["devices"] for i in d["interfaces"] if i["name"] == "Gi1/0/24")
    assert trunk["allowed_vlans"] == [10, 20, 22, 30] and trunk["native_vlan"] == 99 and trunk["speed_mbps"] == 1000


def test_import_route_forms():
    devs, warnings = parse_configs("""hostname R5
interface GigabitEthernet0/0/0
 ip address 10.5.0.1 255.255.255.0
ip route 0.0.0.0 0.0.0.0 GigabitEthernet0/0/0 10.5.0.254
ip route 10.99.0.0 255.255.0.0 Null0
ip route vrf MGMT 0.0.0.0 0.0.0.0 192.0.2.1
ip route 172.16.0.0 255.240.0.0 10.5.0.2 250
""")
    assert devs["R5"].routes == [("0.0.0.0/0", "10.5.0.254"), ("172.16.0.0/12", "10.5.0.2")]
    assert any("null (discard)" in w for w in warnings) and any("VRF" in w for w in warnings)


def test_import_errors_name_the_device_and_line(client, auth):
    response = client.post("/api/networks/import", headers=auth, json={"name": "Bad", "dry_run": True, "configs":
        "hostname EDGE\naccess-list 120 permit tcp any any established\n"})
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "EDGE" in detail and "access-list 120 permit tcp any any established" in detail


def test_import_keeps_each_access_list_separate(client, auth):
    devs_text = """hostname R6
interface GigabitEthernet0/0/0
 ip address 10.6.0.1 255.255.255.0
 ip access-group FIRST in
interface GigabitEthernet0/0/1
 ip address 10.7.0.1 255.255.255.0
 ip access-group SECOND in
ip access-list extended FIRST
 100 deny tcp any any eq 23
 110 permit ip any any
ip access-list extended SECOND
 10 deny ip any host 10.6.0.50
"""
    response = client.post("/api/networks/import", headers=auth, json={"name": "ACL order", "configs": devs_text})
    assert response.status_code == 200
    topology = client.get(f"/api/networks/{response.json()['network_id']}/topology", headers=auth).json()
    device = topology["devices"][0]
    # Each list keeps its own name and sequence numbers; each filters only on the interface that applies it.
    lists = {}
    for rule in device["acl_rules"]:
        lists.setdefault(rule["acl_name"], []).append(rule["sequence"])
    assert {name: sorted(seqs) for name, seqs in lists.items()} == {"FIRST": [100, 110], "SECOND": [10]}
    assert {i["name"]: (i["acl_in"], i["acl_out"]) for i in device["interfaces"]}["Gi0/0/1"] == ("SECOND", None)


# ------------------------------------------------------------------ lab data




def test_ospf_commands_use_the_imported_process_id(client, auth):
    configs = """hostname RA
interface GigabitEthernet0/0/0
 ip address 10.1.12.1 255.255.255.252
router ospf 7
 network 10.1.12.0 0.0.0.3 area 0
hostname RB
interface GigabitEthernet0/0/0
 ip address 10.1.12.2 255.255.255.252
router ospf 7
 network 10.1.12.0 0.0.0.3 area 0
"""
    imported = client.post("/api/networks/import", headers=auth, json={"name": "OSPF 7", "configs": configs}).json()
    topology = client.get(f"/api/networks/{imported['network_id']}/topology", headers=auth).json()
    ra = next(d for d in topology["devices"] if d["name"] == "RA")
    change = client.post("/api/changes", headers=auth, json={"device_id": ra["id"], "interface_id": ra["interfaces"][0]["id"],
                                                             "change_type": "ospf_area", "parameters": {"area": 1}}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    commands = assessment["change"]["commands"]
    assert " ip ospf 7 area 1" in commands and not any("ospf 1 " in line for line in commands)
