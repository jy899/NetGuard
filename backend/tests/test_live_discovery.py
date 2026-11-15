"""Live discovery engine against local endpoints: TCP/banner probing, SNMPv3 engine discovery, SSH collection."""
import ipaddress

import pytest
from pysnmp.proto import rfc1902

from backend.collectors import snmpv3
from backend.services.discovery import real_engine, service
from backend.tests.fixtures.ios_emulator import Device, SshEmulator
from backend.tests.fixtures.snmp_agent import SnmpAgent

CONFIG = """hostname CORE1
interface GigabitEthernet0/0
 ip address 127.0.0.1 255.0.0.0
interface GigabitEthernet0/1
 ip address 10.1.12.1 255.255.255.252
 ip ospf hello-interval 5
 duplex half
 ip access-group EDGE in
router ospf 1
 network 10.1.12.0 0.0.0.3 area 0
ip access-list extended EDGE
 10 deny ip any 10.9.0.0 0.0.255.255
 20 permit ip 10.0.0.0 0.255.255.255 any
 30 deny ip 10.1.0.0 0.0.255.255 any
enable password 7 0822455D0A16
line vty 0 4
 transport input ssh
"""


@pytest.fixture(scope="module")
def endpoints():
    ssh = SshEmulator(Device("CORE1", CONFIG, {"show version": "Cisco IOS Software, IOSv Software, Version 15.9(3)M4\nCORE1 uptime is 1 week\n"}))
    agent = SnmpAgent({"1.3.6.1.2.1.1.1.0": rfc1902.OctetString("Cisco IOS Software"),
                       "1.3.6.1.2.1.1.2.0": rfc1902.ObjectName("1.3.6.1.4.1.9.1.1"),
                       "1.3.6.1.2.1.1.5.0": rfc1902.OctetString("CORE1")})
    yield ssh, agent
    ssh.close()
    agent.close()


def _engine(endpoints):
    ssh, agent = endpoints
    return lambda target, excluded: real_engine.RealDiscoveryEngine(
        target, excluded, management_ports={ssh.port: "SSH"}, host_ports={}, snmp_port=agent.port, timeout=0.5)


def test_engine_discovery_packet_round_trip_and_vendor(endpoints):
    _, agent = endpoints
    report = snmpv3.engine_discovery("127.0.0.1", agent.port)
    assert report["engine_id"] == "800000090300500000010000" and report["vendor"] == "Cisco"
    assert snmpv3.parse_engine_report(b"not snmp") is None


def test_probe_finds_the_device_without_credentials(endpoints):
    engine = _engine(endpoints)(ipaddress.IPv4Network("127.0.0.1/32"), [])
    probe = engine.probe()
    techniques = {o["technique"] for o in probe["observations"]}
    assert {"tcp-banner", "snmpv3-engine"} <= techniques
    banner = next(o for o in probe["observations"] if o["technique"] == "tcp-banner")
    assert banner["facts"]["ssh_banner"].startswith("SSH-2.0-Cisco") and banner["facts"]["type"] in ("switch", "router")
    assert all(o["simulated"] is False and o["authenticated"] is False for o in probe["observations"])
    excluded = _engine(endpoints)(ipaddress.IPv4Network("127.0.0.1/32"), ["127.0.0.1/32"])
    assert excluded.addresses() == []  # the workspace exclusion list is never probed


def test_scan_authenticate_and_collect_through_the_api(client, auth, endpoints, monkeypatch):
    monkeypatch.setattr(service, "engine_factory", _engine(endpoints))
    scan = client.post("/api/discovery/scan", headers=auth, json={
        "target": "127.0.0.1/32", "authorized_scope": True, "untrusted": ["203.0.113.0/24"]})
    assert scan.status_code == 201, scan.text
    result = scan.json()
    nid, device = result["network_id"], result["devices"][0]
    assert result["mode"] == "live" and result["report"]["scope"]["untrusted"] == ["203.0.113.0/24"]
    assert device["methods"] == ["ssh", "snmpv3", "snmpv2c"] and result["credential_requests"]
    wrong = client.post(f"/api/discovery/{nid}/authenticate", headers=auth, json={
        "device_ids": [device["id"]], "method": "ssh", "username": "netguard", "password": "nope"}).json()
    assert wrong["outcomes"][0]["ok"] is False and "rejected" in wrong["outcomes"][0]["detail"]
    ok = client.post(f"/api/discovery/{nid}/authenticate", headers=auth, json={
        "device_ids": [device["id"]], "method": "ssh", "username": "netguard", "password": "Lab-Pass1"}).json()
    assert ok["outcomes"][0]["ok"], ok["outcomes"]
    snmp = client.post(f"/api/discovery/{nid}/authenticate", headers=auth, json={
        "device_ids": [device["id"]], "method": "snmpv3", "username": "netguard-ro", "password": "Auth-Pass-123",
        "priv_password": "Priv-Pass-456"}).json()
    assert snmp["outcomes"][0]["ok"], snmp["outcomes"]
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    core = topo["devices"][0]
    assert core["name"] == "CORE1" and core["device_type"] == "router" and core["platform"] == "cisco-ios"
    gi1 = next(i for i in core["interfaces"] if i["name"] == "Gi0/1")
    assert (gi1["ip_address"], gi1["ospf_area"], gi1["ospf_hello"], gi1["duplex"], gi1["acl_in"]) == ("10.1.12.1", 0, 5, "half", "EDGE")
    assert [r["sequence"] for r in core["acl_rules"]] == [10, 20, 30]
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    rules = {i["rule_id"] for i in report["issues"]}
    assert "ACL003" in rules  # entry 30 is shadowed by the earlier permit of 10.0.0.0/8
    assert {"SEC004", "SEC005"} <= {a["rule_id"] for a in report["advisories"]}
    text = client.get(f"/api/discovery/{nid}", headers=auth).text + client.get("/api/history", headers=auth).text
    assert "Lab-Pass1" not in text and "Priv-Pass-456" not in text and "0822455D0A16" not in text
