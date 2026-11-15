"""Automatic discovery: credential profile matching and the recursive neighbour crawl (router -> switch -> PC)."""
import ipaddress

import pytest

from backend.services.discovery import real_engine, service
from backend.tests.fixtures.ios_emulator import Device, SshEmulator

R1 = """hostname R1
interface GigabitEthernet0/0
 ip address 127.0.0.2 255.0.0.0
"""
SW1 = """hostname SW1
vlan 10
interface GigabitEthernet0/1
 switchport mode trunk
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 10
interface Vlan10
 ip address 127.0.0.3 255.0.0.0
"""


def _cdp(name, address, platform, local, remote):
    return f"""-------------------------
Device ID: {name}
Entry address(es): 
  IP address: {address}
Platform: {platform},  Capabilities: Router Switch IGMP 
Interface: {local},  Port ID (outgoing port): {remote}
Holdtime : 150 sec

Version :
Cisco IOS Software, Version 15.0(2)

advertisement version: 2
Management address(es): 
  IP address: {address}

"""


ARP = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  127.0.0.2               -   aabb.cc00.0100  ARPA   GigabitEthernet0/0
Internet  127.0.0.3               4   aabb.cc00.0200  ARPA   GigabitEthernet0/0
Internet  127.0.0.4               2   aabb.cc00.0300  ARPA   GigabitEthernet0/0
"""
MAC = """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    aabb.cc00.0100    DYNAMIC     Gi0/1
  10    aabb.cc00.0300    DYNAMIC     Fa0/1
Total Mac Addresses for this criterion: 2
"""
VERSION = "Cisco IOS Software, Version 15.9(3)M4\n{0} uptime is 1 week\n"


@pytest.fixture(scope="module")
def lab():
    router = SshEmulator(Device("R1", R1, {
        "show version": VERSION.format("R1"), "show ip arp": ARP,
        "show cdp neighbors detail": _cdp("SW1", "127.0.0.3", "cisco WS-C2960", "GigabitEthernet0/0", "GigabitEthernet0/1")}),
        host="127.0.0.2")
    switch = SshEmulator(Device("SW1", SW1, {
        "show version": VERSION.format("SW1"), "show mac address-table": MAC,
        "show vlan brief": "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n10   USERS                            active    Fa0/1\n",
        "show cdp neighbors detail": _cdp("R1", "127.0.0.2", "Cisco IOSv", "GigabitEthernet0/1", "GigabitEthernet0/0")}),
        host="127.0.0.3")
    yield router, switch
    router.close()
    switch.close()


@pytest.fixture()
def crawl_engine(lab, monkeypatch):
    router, switch = lab
    ports = {router.port: "SSH", switch.port: "SSH"}
    monkeypatch.setattr(service, "engine_factory", lambda target, excluded: real_engine.RealDiscoveryEngine(
        target, excluded, management_ports=ports, host_ports={}, snmp_port=9, timeout=0.4))
    # The loopback lab stands in for private address space.
    monkeypatch.setattr(service, "PRIVATE_NETS", [ipaddress.IPv4Network("127.0.0.0/8")])


def _profile(client, auth, **body):
    response = client.post("/api/credential-profiles", headers=auth, json={"port": 22, "priority": 100, **body})
    assert response.status_code in (200, 201), response.text
    return response.json()


def test_saved_profiles_are_matched_and_neighbours_are_crawled_hop_by_hop(client, auth, crawl_engine):
    _profile(client, auth, name="Wrong SSH", username="netguard", password="not-it", priority=10)
    _profile(client, auth, name="Lab SSH", username="netguard", password="Lab-Pass1", priority=20)
    scan = client.post("/api/discovery/scan", headers=auth, json={
        "target": "127.0.0.2/32", "authorized_scope": True, "auto_credentials": True, "follow_neighbours": True})
    assert scan.status_code == 201, scan.text
    result = scan.json()
    devices = {d["name"]: d for d in result["devices"]}
    assert {"R1", "SW1"} <= set(devices), list(devices)
    assert devices["R1"]["auth"] == "success" and devices["R1"]["auth_profile"] == "Lab SSH"
    assert devices["SW1"]["auth"] == "success"  # reached through R1's CDP table, then read with the same profile
    host = next(d for d in result["devices"] if d["ip"] == "127.0.0.4")  # learned from R1's ARP table
    assert host["type"] not in ("router", "switch")
    assert result["crawl"] and result["crawl"][0]["sources"]["management"] >= 1
    topo = client.get(f"/api/networks/{result['network_id']}/topology", headers=auth).json()
    by_id = {d["id"]: d for d in topo["devices"]}
    pairs = {frozenset({by_id[l["source_device_id"]]["name"], by_id[l["destination_device_id"]]["name"]}): l
             for l in topo["links"]}
    assert pairs[frozenset({"R1", "SW1"})]["evidence_grade"] == "Confirmed"  # both CDP tables agree
    attachment = pairs[frozenset({"SW1", by_id[host["id"]]["name"]})]
    assert attachment["evidence_grade"] == "Inferred"  # one MAC on SW1 Fa0/1
    pc = by_id[host["id"]]
    assert pc["default_gateway"] == "127.0.0.2"  # from the read router interface that holds its subnet


def test_without_follow_the_crawl_stays_in_the_authorised_range(client, auth, crawl_engine):
    _profile(client, auth, name="Lab SSH 2", username="netguard", password="Lab-Pass1", priority=5)
    result = client.post("/api/discovery/scan", headers=auth, json={
        "target": "127.0.0.2/32", "authorized_scope": True, "auto_credentials": True}).json()
    assert [d["ip"] for d in result["devices"]] == ["127.0.0.2"]
    again = client.post(f"/api/discovery/{result['network_id']}/crawl", headers=auth, json={"follow_neighbours": True}).json()
    assert {d["ip"] for d in again["result"]["devices"]} >= {"127.0.0.2", "127.0.0.3", "127.0.0.4"}


def test_local_networks_and_snmpv2c_profiles(client, auth):
    local = client.get("/api/discovery/local-networks", headers=auth).json()
    assert set(local) == {"interfaces", "gateway", "suggested"}
    profile = _profile(client, auth, name="RO community", username="", password="public-ro", method="snmpv2c", port=161)
    assert profile["method"] == "snmpv2c" and profile["username"] == "community"


def test_credentials_entered_once_continue_the_discovery(client, auth, crawl_engine):
    scan = client.post("/api/discovery/scan", headers=auth, json={
        "target": "127.0.0.2/32", "authorized_scope": True, "follow_neighbours": True}).json()
    r1 = next(d for d in scan["devices"] if d["ip"] == "127.0.0.2")
    assert r1["auth"] is None and [r["device_id"] for r in scan["credential_requests"]] == [r1["id"]]
    response = client.post(f"/api/discovery/{scan['network_id']}/authenticate", headers=auth, json={
        "device_ids": [r1["id"]], "method": "ssh", "username": "netguard", "password": "Lab-Pass1"}).json()
    assert response["outcomes"][0]["ok"] and response["crawl"]["read"] >= 1
    after = client.get(f"/api/discovery/{scan['network_id']}", headers=auth).json()
    switch = next(d for d in after["devices"] if d["ip"] == "127.0.0.3")
    assert switch["auth"] == "success" and "entered during this scan" in switch["auth_detail"]
    from backend.database.session import SessionLocal
    from backend.models.credential_profile import CredentialProfile
    with SessionLocal() as db:
        assert db.query(CredentialProfile).count() == 0  # the typed password was not stored
