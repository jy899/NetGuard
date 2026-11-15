"""Every rule with a configuration cause has a verified remediation: OSPF timers, duplex, trunk mismatch, shadowed
and undefined ACLs, the security hygiene pack, and physical work orders."""
import pytest

from backend.tests.helpers import approve_and_apply

CONFIGS = """hostname R1
enable password cisco123
snmp-server community public RO
ip http server
interface GigabitEthernet0/0
 ip address 10.0.12.1 255.255.255.252
 ip ospf 1 area 0
 ip ospf hello-interval 5
 duplex half
interface GigabitEthernet0/1
 ip address 10.1.0.1 255.255.255.0
 ip ospf 1 area 0
 ip access-group LAN-IN in
interface GigabitEthernet0/2
 ip address 10.9.0.1 255.255.255.0
 ip access-group MISSING out
router ospf 1
ip access-list extended LAN-IN
 10 permit ip 10.1.0.0 0.0.0.255 any
 20 deny tcp 10.1.0.0 0.0.0.255 any eq 23
 30 permit ip any any
line vty 0 4
 transport input telnet ssh
 password cisco
 login
R1#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
R2               Gig 0/0           150             R      IOSv      Gig 0/0
!
hostname R2
interface GigabitEthernet0/0
 ip address 10.0.12.2 255.255.255.252
 ip ospf 1 area 0
 duplex full
interface GigabitEthernet0/1
 ip address 10.2.0.1 255.255.255.0
 ip ospf 1 area 0
router ospf 1
line vty 0 4
 transport input ssh
 access-class 10 in
access-list 10 permit 10.0.0.0 0.255.255.255
R2#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
R1               Gig 0/0           150             R      IOSv      Gig 0/0
!
hostname SW1
vlan 10
vlan 20
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20
SW1#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
SW2              Gig 0/1           150             S      WS-C      Gig 0/1
!
hostname SW2
vlan 10
vlan 20
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 10
SW2#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
SW1              Gig 0/1           150             S      WS-C      Gig 0/1
"""


@pytest.fixture()
def report(client, auth):
    response = client.post("/api/networks/import", headers=auth, json={"name": "Faults", "configs": CONFIGS})
    assert response.status_code == 200, response.text
    nid = response.json()["network_id"]
    return nid, client.get(f"/api/networks/{nid}/health-check", headers=auth).json()


def _fix(rows, rule):
    row = next(r for r in rows if r["rule_id"] == rule)
    assert row["fixes"], (rule, row)
    return row, row["fixes"][0]


@pytest.mark.parametrize("rule, change_type, command", [
    ("OSPF003", "interface_settings", "ip ospf hello-interval"),
    ("PHY004", "interface_settings", " duplex full"),
    ("VLAN003", "trunk_settings", "switchport trunk"),
    ("ACL003", "acl_remove", "ip access-list extended LAN-IN"),
    ("ACL004", "acl_reference", "no ip access-group MISSING out"),
])
def test_configuration_findings_have_verified_fixes(report, rule, change_type, command):
    _, health = report
    _, fix = _fix(health["issues"], rule)
    assert fix["change_type"] == change_type
    assert fix["verification"]["resolves"] and fix["verification"]["verdict"] in ("recommended", "partial"), fix
    assert any(command in line for line in fix["verification"]["commands"]), fix["verification"]["commands"]


@pytest.mark.parametrize("rule, action, command", [
    ("SEC002", "secure_management", "transport input ssh"),
    ("SEC003", "remove_snmp_communities", "no snmp-server community <COMMUNITY-1>"),
    ("SEC004", "secure_passwords", "enable algorithm-type scrypt secret"),
    ("SEC005", "restrict_vty", "access-class NETGUARD-MGMT in"),
])
def test_security_hygiene_advisories_have_verified_hardening(report, rule, action, command):
    _, health = report
    _, fix = _fix(health["advisories"], rule)
    assert fix["parameters"]["action"] == action
    assert fix["verification"]["resolves"], fix["verification"]
    assert not fix["verification"]["new_issues"] and not fix["verification"]["broken_flows"]
    assert any(command in line for line in fix["verification"]["commands"]), fix["verification"]["commands"]


def test_applying_a_generated_fix_clears_the_finding(client, auth, report):
    nid, health = report
    _, fix = _fix(health["issues"], "OSPF003")
    change = client.post("/api/changes", headers=auth, json={k: fix[k] for k in ("device_id", "interface_id",
                                                                                 "change_type", "parameters")}).json()
    assert approve_and_apply(client, auth, change["id"]).status_code == 200
    _, hardening = _fix(health["advisories"], "SEC002")
    change = client.post("/api/changes", headers=auth, json={k: hardening[k] for k in ("device_id", "interface_id",
                                                                                       "change_type", "parameters")}).json()
    assert approve_and_apply(client, auth, change["id"]).status_code == 200
    after = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    assert "OSPF003" not in {i["rule_id"] for i in after["issues"]}
    assert not any(a["rule_id"] == "SEC002" and a["devices"] == ["R1"] for a in after["advisories"])


def test_secret_dependent_hardening_is_not_sent_automatically(client, auth, report):
    from backend.services import cli_generator
    assert cli_generator.automatable(None, "mgmt_hardening", {"action": "secure_passwords"})[0] is False
    assert cli_generator.automatable(None, "physical_remediation", {"action": "clear_errors"})[0] is False
    assert cli_generator.automatable(None, "mgmt_hardening", {"action": "secure_management"})[0] is True


def test_physical_work_orders_are_verified_on_the_model():
    from backend.services import change_detector, fix_engine
    from backend.services.analysis_checks import physical_findings
    from backend.services.forwarding import FlowAnalyzer
    from backend.services.network_model import DeviceM, IfaceM, LinkM, NetworkModel

    def iface(iid, did, name, ip=None, vlan=None, mode=None):
        return IfaceM(iid, did, name, ip, "255.255.255.0" if ip else None, vlan, "up", None, mode, 1000)
    host = DeviceM(1, "PC", "pc", None, {1: iface(1, 1, "eth0", "10.0.0.10")})
    switch = DeviceM(2, "SW", "switch", None, {2: iface(2, 2, "25", vlan=20, mode="access"),
                                                3: iface(3, 2, "1", vlan=20, mode="access")},
                     vendor="HPE Aruba", model="Aruba 2530-24G", vlans={20: "DATA"})
    server = DeviceM(3, "SERVER", "server", None, {4: iface(4, 3, "eth0", "10.0.0.20")})
    model = NetworkModel(1, {1: host, 2: switch, 3: server}, {1: LinkM(1, 1, 1, 2, 2), 2: LinkM(2, 2, 3, 3, 4)}, [])
    finding = next(f for f in physical_findings(model) if f.rule_id == "PHY001")
    options = fix_engine.options_for(model, FlowAnalyzer(model), finding)
    assert {o.parameters["action"] for o in options} == {"replace_media", "move_port"}
    for option in options:
        detected = change_detector.detect(model, option.device_id, option.interface_id, option.change_type, option.parameters)
        candidate = change_detector.apply(model, detected)
        assert not [f for f in physical_findings(candidate) if f.rule_id == "PHY001"], option.label
        assert FlowAnalyzer(candidate).evaluate(1, 3).reachable, option.label
    move = next(o for o in options if o.parameters["action"] == "move_port")
    assert move.parameters["port"] == "2"  # the first free copper port on the Aruba 2530
