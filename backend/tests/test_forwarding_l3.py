"""Per-interface ACL direction, multilayer-switch (SVI) routing and routing between routers across switches."""
import pytest

TRANSIT = """hostname R1
interface GigabitEthernet0/0
 ip address 10.1.0.1 255.255.255.0
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
ip route 10.2.0.0 255.255.255.0 10.0.0.2
R1#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
SW-CORE          Gig 0/1           150             S I     WS-C      Gig 0/1
!
hostname R2
interface GigabitEthernet0/0
 ip address 10.2.0.1 255.255.255.0
 ip access-group EDGE {direction}
interface GigabitEthernet0/1
 ip address 10.0.0.2 255.255.255.0
ip route 10.1.0.0 255.255.255.0 10.0.0.1
ip access-list extended EDGE
 10 deny icmp host 10.1.0.10 any
 20 permit ip any any
R2#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
SW-CORE          Gig 0/1           150             S I     WS-C      Gig 0/2
!
hostname SW-CORE
vlan 100
 name TRANSIT
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 100
interface GigabitEthernet0/2
 switchport mode access
 switchport access vlan 100
"""
ENDPOINTS = """PC1, pc, 10.1.0.10/24, 10.1.0.1, R1 Gi0/0
PC2, pc, 10.2.0.10/24, 10.2.0.1, R2 Gi0/0"""
FLOWS = "Ping, PC1, PC2, icmp, , allow, critical"


def _import(client, auth, configs, endpoints, flows, name="L3"):
    response = client.post("/api/networks/import", headers=auth,
                           json={"name": name, "configs": configs, "endpoints": endpoints, "flows": flows})
    assert response.status_code == 200, response.text
    return response.json()["network_id"]


def _flow(client, auth, nid):
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    return report, report["flows"][0]


@pytest.mark.parametrize("direction, blocked", [("in", False), ("out", True)])
def test_acl_applies_only_in_its_direction_and_routes_cross_the_switch(client, auth, direction, blocked):
    nid = _import(client, auth, TRANSIT.format(direction=direction), ENDPOINTS, FLOWS, f"Transit {direction}")
    device = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "R2")
    assert {r["acl_name"] for r in device["acl_rules"]} == {"EDGE"}
    report, flow = _flow(client, auth, nid)
    assert flow["ok"] is (not blocked), flow
    if blocked:
        acl = next(i for i in report["issues"] if i["rule_id"] == "ACL001")
        assert "EDGE" in acl["message"]
    else:
        # PC1 -> R1 -> SW-CORE -> R2 -> PC2: the static next hop 10.0.0.2 is resolved through the switch.
        names = {d["id"]: d["name"] for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"]}
        assert [names[i] for i in flow["path_device_ids"]] == ["PC1", "R1", "SW-CORE", "R2", "PC2"]


def test_a_shut_switch_port_breaks_the_routed_path_through_the_switch(client, auth):
    nid = _import(client, auth, TRANSIT.format(direction="in"), ENDPOINTS, FLOWS, "Transit shut")
    sw = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "SW-CORE")
    port = next(i for i in sw["interfaces"] if i["name"] == "Gi0/2")
    change = client.post("/api/changes", headers=auth, json={"device_id": sw["id"], "interface_id": port["id"],
                                                             "change_type": "interface_status",
                                                             "parameters": {"status": "admin-down"}}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert assessment["recommendation"] == "DO_NOT_DEPLOY"
    broken = next(i for i in assessment["impacts"] if i["status"] == "broken")
    assert "SW-CORE" in broken["explanation"] or "Gi0/2" in broken["explanation"]


MLS = """hostname L3SW
ip routing
vlan 10
 name USERS
vlan 20
 name SERVERS
interface Vlan10
 ip address 10.10.0.1 255.255.255.0
interface Vlan20
 ip address 10.20.0.1 255.255.255.0
 ip access-group SRV {direction}
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
ip access-list extended SRV
 10 deny tcp any host 10.20.0.10 eq 22
 20 permit ip any any
"""
MLS_HOSTS = """PC10, pc, 10.10.0.10/24, 10.10.0.1, L3SW Gi1/0/1
SRV20, server, 10.20.0.10/24, 10.20.0.1, L3SW Gi1/0/2"""
MLS_FLOWS = """Web, PC10, SRV20, tcp, 443, allow, high
SSH, PC10, SRV20, tcp, 22, allow, medium"""


@pytest.mark.parametrize("direction", ["in", "out"])
def test_multilayer_switch_routes_between_svis_with_per_direction_acls(client, auth, direction):
    nid = _import(client, auth, MLS.format(direction=direction), MLS_HOSTS, MLS_FLOWS, f"MLS {direction}")
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    switch = next(d for d in topo["devices"] if d["name"] == "L3SW")
    assert switch["device_type"] == "switch" and switch["config_facts"]["ip_routing"] is True
    assert {i["name"] for i in switch["interfaces"]} >= {"Vlan10", "Vlan20"}
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    flows = {f["name"]: f for f in report["flows"]}
    assert flows["Web"]["ok"] is True
    # Traffic to the server leaves through Vlan20, so only an outbound list on Vlan20 filters it.
    assert flows["SSH"]["ok"] is (direction == "in")
