"""End to end through the real transports: EVE-NG API import, console collection with Netmiko, rule packs,
approval and laboratory remediation with backup, verification and rollback (test servers on 127.0.0.1)."""
import pytest

from backend.database.session import SessionLocal
from backend.models import ChangeExecution, DeviceConfig
from backend.tests.fixtures.ios_emulator import Device, TelnetEmulator
from backend.tests.fixtures.lab_servers import eve_ng, gns3
from backend.tests.helpers import manager_auth

R1 = """hostname R1
interface Ethernet0/0
 ip address 10.0.10.1 255.255.255.0
interface Ethernet0/1
 ip address 10.0.20.1 255.255.255.0
line vty 0 4
 transport input ssh
 access-class 5 in
access-list 5 permit 10.0.10.0 0.0.0.255
"""
SW1 = """hostname SW1
snmp-server community public RO
vlan 10
 name USERS
vlan 20
 name SERVERS
interface GigabitEthernet0/0
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 20
interface GigabitEthernet0/2
 switchport mode access
 switchport access vlan 20
interface GigabitEthernet0/3
 switchport mode access
 switchport access vlan 20
line vty 0 4
 transport input telnet ssh
"""
VERSION = "Cisco IOS Software, Linux Software (I86BI_LINUX-ADVENTERPRISEK9-M), Version 15.7(3)M3\nR1 uptime is 1 hour\n"


@pytest.fixture()
def lab():
    r1 = Device("R1", R1, {"show version": VERSION})
    sw1 = Device("SW1", SW1, {"show version": VERSION.replace("R1", "SW1").replace("Linux Software", "vios_l2 Software")})
    consoles = {name: TelnetEmulator(dev) for name, dev in (("R1", r1), ("SW1", sw1))}
    definition = {
        "path": "/NetGuard/branch.unl", "name": "Branch",
        "nodes": {
            "1": {"id": 1, "name": "R1", "template": "iol", "type": "iol", "status": 2, "left": 300, "top": 100,
                  "url": f"telnet://127.0.0.1:{consoles['R1'].port}"},
            "2": {"id": 2, "name": "SW1", "template": "viosl2", "type": "qemu", "status": 2, "left": 300, "top": 260,
                  "url": f"telnet://127.0.0.1:{consoles['SW1'].port}"},
            "3": {"id": 3, "name": "PC1", "template": "vpcs", "type": "vpcs", "status": 2, "left": 200, "top": 420},
            "4": {"id": 4, "name": "PC2", "template": "vpcs", "type": "vpcs", "status": 2, "left": 400, "top": 420},
        },
        "interfaces": {"1": [{"name": "e0/0", "network_id": 1}, {"name": "e0/1", "network_id": 4}],
                       "2": [{"name": "Gi0/0", "network_id": 1}, {"name": "Gi0/1", "network_id": 2},
                             {"name": "Gi0/2", "network_id": 3}, {"name": "Gi0/3", "network_id": 4}],
                       "3": [{"name": "eth0", "network_id": 2}], "4": [{"name": "eth0", "network_id": 3}]},
        "networks": {str(i): {"id": i, "name": f"Net{i}", "type": "bridge", "visibility": 0} for i in range(1, 5)},
        "configs": {"1": R1, "2": SW1},
    }
    server = eve_ng(definition)
    yield {"server": server, "r1": r1, "sw1": sw1}
    server.close()
    for console in consoles.values():
        console.close()


def _import(client, auth, lab):
    body = {"provider": "eve-ng", "server": lab["server"].url, "username": "admin", "password": "eve"}
    rejected = client.post("/api/labs/connect", headers=auth, json={**body, "password": "wrong"})
    assert rejected.status_code == 200 and rejected.json()["connected"] is False
    connected = client.post("/api/labs/connect", headers=auth, json=body).json()
    assert connected["connected"] and connected["labs"] == [{"id": "/NetGuard/branch.unl", "name": "branch", "folder": "/NetGuard"}]
    imported = client.post("/api/labs/import", headers=auth, json={**body, "lab_id": "/NetGuard/branch.unl"})
    assert imported.status_code == 201, imported.text
    nid = imported.json()["network_id"]
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    devices = {d["name"]: d for d in topo["devices"]}
    for name, ip, gw in (("PC1", "10.0.10.10", "10.0.10.1"), ("PC2", "10.0.20.10", "10.0.20.1")):
        pc = devices[name]
        eth0 = next(i for i in pc["interfaces"] if i["name"] == "eth0")
        assert client.put(f"/api/interfaces/{eth0['id']}", headers=auth, json={
            "name": "eth0", "ip_address": ip, "subnet_mask": "255.255.255.0", "status": "up"}).status_code == 200
        assert client.put(f"/api/devices/{pc['id']}", headers=auth, json={
            "name": name, "device_type": "pc", "default_gateway": gw}).status_code == 200
    client.post(f"/api/networks/{nid}/intents", headers=auth, json={
        "name": "PC1 to PC2", "source_device_id": devices["PC1"]["id"], "destination_device_id": devices["PC2"]["id"],
        "protocol": "icmp", "expected_action": "allow", "criticality": "critical"})
    return nid, client.get(f"/api/networks/{nid}/topology", headers=auth).json()


def test_eve_ng_import_grades_lab_cables_confirmed_and_reads_startup_configs(client, auth, lab):
    nid, topo = _import(client, auth, lab)
    devices = {d["name"]: d for d in topo["devices"]}
    assert devices["R1"]["device_type"] == "router" and devices["SW1"]["device_type"] == "switch"
    assert all(devices[n]["is_lab"] for n in ("R1", "SW1", "PC1", "PC2"))
    assert {i["name"]: i["ip_address"] for i in devices["R1"]["interfaces"]}["Et0/0"] == "10.0.10.1"
    links = topo["links"]
    assert len(links) == 4 and {l["evidence_grade"] for l in links} == {"Confirmed"}
    assert ("R1", "Et0/0", "SW1", "Gi0/0") in {(l["source_device_name"], l["source_interface_name"],
                                                l["destination_device_name"], l["destination_interface_name"]) for l in links}


def test_console_collection_rule_packs_approval_and_verified_lab_change(client, auth, lab):
    nid, topo = _import(client, auth, lab)
    devices = {d["name"]: d for d in topo["devices"]}
    collected = client.post(f"/api/networks/{nid}/collect", headers=auth, json={
        "device_ids": [devices["R1"]["id"], devices["SW1"]["id"]], "transport": "console"})
    assert collected.status_code == 200, collected.text
    assert all(o["ok"] and o["transport"] == "console" for o in collected.json()["outcomes"]), collected.json()
    with SessionLocal() as db:
        snapshots = db.query(DeviceConfig).filter(DeviceConfig.kind == "collected").all()
        assert len(snapshots) == 2 and all(s.text_enc.startswith("enc2:") and "snmp-server" not in s.text_enc for s in snapshots)
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    issue = next(i for i in report["issues"] if i["rule_id"] == "VLAN001")
    assert issue["pack"] == "layer2" and issue["risk"]["score"] == round(100 * issue["risk"]["S"] * (1 + issue["risk"]["I"] + issue["risk"]["E"]) / 24)
    advisories = {a["rule_id"] for a in report["advisories"]}
    assert {"SEC002", "SEC003"} <= advisories and "SEC005" in advisories  # SW1: telnet, community, no access-class
    fix = next(f for f in issue["fixes"] if f["change_type"] == "access_vlan")
    assert fix["verification"]["verdict"] == "recommended"
    change = client.post("/api/changes", headers=auth, json={k: fix[k] for k in ("device_id", "interface_id", "change_type", "parameters")}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert assessment["recommendation"] != "DO_NOT_DEPLOY" and assessment["risk_factors"]["S"] >= 1
    # Separation of duties: execution needs approval; an engineer cannot approve; the IT Manager can only approve.
    execute = {"confirm": True, "transport": "console"}
    from backend.tests.helpers import group_id
    client.post("/api/accounts", headers=auth, json={"username": "eng-sod", "password": "pw",
                                                     "group_id": group_id(client, auth, "Network Engineers")})
    engineer = {"Authorization": "Bearer " + client.post("/api/auth/login", json={"username": "eng-sod", "password": "pw"}).json()["access_token"]}
    assert client.post(f"/api/changes/{change['id']}/execute", headers=engineer, json=execute).status_code == 409  # no Auto-Fix
    assert client.post(f"/api/changes/{change['id']}/submit", headers=auth).status_code == 200
    assert client.post(f"/api/changes/{change['id']}/approve", headers=auth, json={}).status_code == 403
    manager = manager_auth(client, auth)
    assert client.post(f"/api/networks/{nid}/collect", headers=manager, json={"device_ids": [devices["R1"]["id"]]}).status_code == 403
    assert client.post(f"/api/changes/{change['id']}/execute", headers=manager, json=execute).status_code == 403
    approved = client.post(f"/api/changes/{change['id']}/approve", headers=manager, json={"note": "Lab window"})
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    result = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json=execute)
    assert result.status_code == 200, result.text
    execution = result.json()["execution"]
    assert execution["status"] == "applied" and result.json()["change"]["status"] == "applied"
    assert execution["verification"]["intended_state"] and not execution["verification"]["new_findings"]
    assert "switchport access vlan 10" in lab["sw1"].running().split("interface GigabitEthernet0/1")[1].split("interface")[0]
    after = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    assert "VLAN001" not in {i["rule_id"] for i in after["issues"]}
    with SessionLocal() as db:
        row = db.get(ChangeExecution, execution["id"])
        # The restore point for the automatic undo is always taken; a user backup only when asked for.
        assert db.get(DeviceConfig, row.backup_config_id).kind == "pre-change"
        assert "backup" not in (row.verification or {})
    listed = client.get(f"/api/networks/{nid}/applied-fixes", headers=auth).json()
    assert [(f["id"], f["undo_next"], f["transport"]) for f in listed] == [(change["id"], True, "console")]
    # Undo Fix: the lab device gets its restore point back and the fault returns.
    undone = client.post(f"/api/changes/{change['id']}/undo", headers=auth, json={"transport": "console"})
    assert undone.status_code == 200, undone.text
    assert undone.json()["change"]["status"] == "rolled_back" and undone.json()["execution"]["status"] == "rolled_back"
    assert "switchport access vlan 10" not in lab["sw1"].running().split("interface GigabitEthernet0/1")[1].split("interface")[0]
    back = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    assert "VLAN001" in {i["rule_id"] for i in back["issues"]}
    assert client.post(f"/api/changes/{change['id']}/undo", headers=auth, json={"transport": "console"}).status_code == 409
    assert client.get(f"/api/networks/{nid}/applied-fixes", headers=auth).json() == []


def _approved_vlan_change(client, auth, nid, sw1_id, vlan_id):
    change = client.post("/api/changes", headers=auth, json={"device_id": sw1_id, "change_type": "vlan_database",
                                                             "parameters": {"action": "add", "vlan_id": vlan_id, "name": "GUEST"}}).json()
    client.post(f"/api/changes/{change['id']}/analyze", headers=auth)
    assert client.post(f"/api/changes/{change['id']}/submit", headers=auth).status_code == 200
    assert client.post(f"/api/changes/{change['id']}/approve", headers=manager_auth(client, auth), json={}).status_code == 200
    return change


@pytest.mark.parametrize("failure", ["rewrite", "reject"])
def test_failed_verification_rolls_the_lab_device_back_to_its_backup(client, auth, lab, failure):
    nid, topo = _import(client, auth, lab)
    sw1 = next(d for d in topo["devices"] if d["name"] == "SW1")
    assert client.post(f"/api/networks/{nid}/collect", headers=auth, json={"device_ids": [sw1["id"]], "transport": "console"}).status_code == 200
    before = lab["sw1"].running()
    if failure == "rewrite":
        lab["sw1"].rewrite = {"vlan 40": "vlan 41"}  # the device does something else than asked
    else:
        lab["sw1"].reject = ("vlan 40",)  # the device refuses the command
    change = _approved_vlan_change(client, auth, nid, sw1["id"], 40)
    result = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json={"confirm": True, "transport": "console"})
    assert result.status_code == 200, result.text
    execution = result.json()["execution"]
    assert execution["status"] == "rolled_back", (execution["log"], execution["rollback_commands"], lab["sw1"].running())
    assert result.json()["change"]["status"] == "rolled_back"
    assert execution["verification"]["restored"] is True
    from backend.services import config_diff
    assert config_diff.equivalent(before, lab["sw1"].running())
    if failure == "rewrite":
        assert "no vlan 41" in execution["rollback_commands"]


def test_production_devices_need_the_real_network_permission(client, auth):
    from backend.tests.helpers import group_id

    from backend.models import Network

    network = client.post("/api/networks/demo", headers=auth).json()
    with SessionLocal() as db:  # treat the demo as a real network (practice networks never contact a device)
        db.get(Network, network["id"]).is_simulated = False
        db.commit()
    sw1 = next(d for d in client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()["devices"] if d["name"] == "SW1")
    change = _approved_vlan_change(client, auth, network["id"], sw1["id"], 40)
    client.post("/api/accounts", headers=auth, json={"username": "eng-lab", "password": "pw",
                                                     "group_id": group_id(client, auth, "Network Engineers")})
    engineer = {"Authorization": "Bearer " + client.post("/api/auth/login", json={"username": "eng-lab", "password": "pw"}).json()["access_token"]}
    refused = client.post(f"/api/changes/{change['id']}/execute", headers=engineer, json={"confirm": True})
    assert refused.status_code == 403 and "real-network device" in refused.json()["detail"]


def test_gns3_project_import_uses_its_links_and_consoles(client, auth):
    project = {"project_id": "p-1", "name": "Campus", "status": "closed",
               "nodes": [{"node_id": "n1", "name": "R1", "node_type": "dynamips", "console": 5000, "console_host": "0.0.0.0",
                          "console_type": "telnet", "status": "started", "x": 0, "y": 0,
                          "ports": [{"name": "FastEthernet0/0", "short_name": "f0/0", "adapter_number": 0, "port_number": 0}]},
                         {"node_id": "n2", "name": "Switch1", "node_type": "ethernet_switch", "status": "started", "x": 0, "y": 150,
                          "ports": [{"name": "Ethernet0", "short_name": "e0", "adapter_number": 0, "port_number": 0}]}],
               "links": [{"link_id": "l1", "nodes": [{"node_id": "n1", "adapter_number": 0, "port_number": 0, "label": {"text": "f0/0"}},
                                                     {"node_id": "n2", "adapter_number": 0, "port_number": 0, "label": {"text": "e0"}}]}]}
    server = gns3(project)
    try:
        body = {"provider": "gns3", "server": server.url}
        assert client.post("/api/labs/connect", headers=auth, json=body).json()["labs"][0]["id"] == "p-1"
        nid = client.post("/api/labs/import", headers=auth, json={**body, "lab_id": "p-1"}).json()["network_id"]
        topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
        devices = {d["name"]: d for d in topo["devices"]}
        assert devices["R1"]["access"]["console"] == "telnet://127.0.0.1:5000" and devices["R1"]["is_lab"]
        assert devices["Switch1"]["device_type"] == "switch" and not devices["Switch1"]["is_lab"]  # built-in, unmanaged
        assert [(l["source_interface_name"], l["destination_interface_name"], l["evidence_grade"]) for l in topo["links"]] == [("Fa0/0", "e0", "Confirmed")]
        assert project["status"] == "opened"
    finally:
        server.close()
