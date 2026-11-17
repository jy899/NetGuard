"""Config import: Cisco IOS output -> network model, checked against the hand-built demo network."""
import pytest

from backend.core.errors import ValidationFailed
from backend.services.config_import import ifname, interface_range, parse_configs


def test_interface_range_expands_dash_ranges_and_comma_lists():
    assert interface_range("GigabitEthernet1/0/1 - 3 , GigabitEthernet1/0/24") == \
        ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/24"]
    assert interface_range("fa0/1-2,fa0/2") == ["Fa0/1", "Fa0/2"]  # duplicates collapse
    assert interface_range("Vlan10 - 11") == ["Vlan10", "Vlan11"]
    for bad in ("macro UPLINKS", "Gi1/0/9 - 2", "Gi1/0/1 - 9999", "1/0/1 - 4"):
        with pytest.raises(ValueError):
            interface_range(bad)


def test_interface_range_block_applies_every_subcommand_to_each_port():
    devs, warn = parse_configs("""hostname SW1
vlan 10
interface range GigabitEthernet1/0/1 - 12
 switchport mode access
 switchport access vlan 10
 shutdown
interface range Gi1/0/23 - 24
 switchport mode trunk
 switchport trunk native vlan 99
interface Vlan10
 ip address 10.10.10.2 255.255.255.0
""")
    ifs = devs["SW1"].ifs
    access = [ifs[f"Gi1/0/{n}"] for n in range(1, 13)]
    assert all(i.mode == "access" and i.vlan == 10 and i.down for i in access)
    assert all(ifs[f"Gi1/0/{n}"].mode == "trunk" and ifs[f"Gi1/0/{n}"].native == 99 for n in (23, 24))
    assert ifs["Vlan10"].ip == "10.10.10.2" and not ifs["Vlan10"].down  # the range block ended at the next interface
    assert not any(name.lower().startswith("range") for name in ifs) and not warn


def test_unreadable_interface_range_is_reported_not_guessed():
    with pytest.raises(ValidationFailed, match="macros are not modelled"):
        parse_configs("hostname SW1\ninterface range macro UPLINKS\n shutdown\n")
    devs, warn = parse_configs("hostname SW1\ninterface range macro UPLINKS\n shutdown\n", lenient=True)
    assert devs["SW1"].ifs == {} and "macros are not modelled" in warn[0]


def test_ifname_normalises_long_short_and_cdp_forms():
    assert [ifname(x) for x in ("GigabitEthernet0/1.10", "Gig 0/1", "Fa0/2", "FastEthernet0/24", "Vlan1", "Se0/0/0")] \
        == ["Gi0/1.10", "Gi0/1", "Fa0/2", "Fa0/24", "Vlan1", "Se0/0/0"]


def test_parser_reads_acls_routes_ospf_and_cdp():
    devs, warn = parse_configs("""hostname R9
interface GigabitEthernet0/0
 ip address 10.1.1.1 255.255.255.0
 ip access-group EDGE in
!
ip route 0.0.0.0 0.0.0.0 10.1.1.254
ip route 172.16.0.0 255.255.0.0 Serial0/0/0
router ospf 7
 network 10.1.1.0 0.0.0.255 area 3
ip access-list extended EDGE
 remark block web to the server
 10 deny tcp 10.2.0.0 0.0.255.255 host 10.1.1.80 eq www
 20 permit udp any any eq domain
 30 permit ip any any
access-list 5 permit 10.9.9.0 0.0.0.255
R9#show cdp neighbors
Device ID    Local Intrfce   Holdtme    Capability   Platform    Port ID
SW9.lab      Gig 0/0          120            S       2960        Fas 0/24
""")
    r = devs["R9"]
    assert r.routes == [("0.0.0.0/0", "10.1.1.254")]
    assert any("Serial0/0/0" in w for w in warn)
    assert r.acls["EDGE"] == [(10, "deny", "tcp", "10.2.0.0/16", "10.1.1.80/32", 80),
                              (20, "permit", "udp", "any", "any", 53), (30, "permit", "ip", "any", "any", None)]
    assert r.acls["5"] == [(None, "permit", "ip", "10.9.9.0/24", "any", None)]
    assert r.ospf[0][1] == 3
    assert r.cdp == [("Gi0/0", "SW9.lab", "Fa0/24")]


@pytest.fixture()
def imported(client, auth):
    sample = client.get("/api/networks/import/sample", headers=auth).json()
    preview = client.post("/api/networks/import", headers=auth, json={**sample, "dry_run": True}).json()
    assert preview["network_id"] is None
    res = client.post("/api/networks/import", headers=auth, json=sample)
    assert res.status_code == 200, res.text
    return res.json(), preview


def test_sample_import_builds_the_demo_network(client, auth, imported):
    res, preview = imported
    assert preview["summary"] == res["summary"]
    s = res["summary"]
    assert s["by_type"] == {"router": 3, "firewall": 1, "switch": 2, "pc": 2, "server": 2, "internet": 1}
    assert (s["links"], s["flows"], s["acl_rules"], s["routes"]) == (10, 6, 3, 4)
    assert res["warnings"] == []
    topo = client.get(f"/api/networks/{res['network_id']}/topology", headers=auth).json()
    assert topo["network"]["source"] == "config-import" and topo["network"]["metadata_json"]["interface_naming_version"] == 1
    devs = {d["name"]: d for d in topo["devices"]}
    sw1 = {i["name"]: i for i in devs["SW1"]["interfaces"]}
    assert set(sw1) == {"Gi1/0/24", "Gi1/0/1", "Gi1/0/2"}  # unused Gi1/0/3 and the SVI are not modelled
    assert devs["SW1"]["management_ip"] == "192.168.1.11"
    r2 = {i["name"]: i for i in devs["R2"]["interfaces"]}
    assert r2["Gi0/0/1.20"]["vlan_id"] == 20 and r2["Gi0/0/1.20"]["ospf_area"] == 0
    assert "Gi0/1/0" not in {i["name"] for i in devs["R1"]["interfaces"]}  # shut, no IP, no link


def _analyze(client, auth, network_id, device, change_type, **params):
    topo = client.get(f"/api/networks/{network_id}/topology", headers=auth).json()
    dev = next(d for d in topo["devices"] if d["name"] == device)
    ch = client.post("/api/changes", headers=auth, json={"device_id": dev["id"], "change_type": change_type,
                                                         "parameters": params, "reason": "test"}).json()
    return client.post(f"/api/changes/{ch['id']}/analyze", headers=auth).json()


def test_imported_network_gives_the_same_result_as_the_demo(client, auth, imported):
    demo = client.post("/api/networks/demo", headers=auth).json()
    acl = dict(sequence=5, action="deny", protocol="tcp", source="10.20.0.0/24", destination="192.168.30.10/32", port=443)
    a = _analyze(client, auth, imported[0]["network_id"], "R3", "acl_add", **acl)
    b = _analyze(client, auth, demo["id"], "R3", "acl_add", **acl)
    assert (a["risk_level"], a["total_risk_score"]) == (b["risk_level"], b["total_risk_score"]) == ("CRITICAL", 83)
    safe = _analyze(client, auth, imported[0]["network_id"], "SW1", "vlan_database", action="add", vlan_id=40, name="GUEST")
    assert safe["risk_level"] == "LOW"


def test_import_reports_problems_instead_of_failing(client, auth):
    res = client.post("/api/networks/import", headers=auth, json={
        "configs": "hostname RX\ninterface GigabitEthernet0/1.10\n encapsulation dot1Q 10\n ip address 10.0.0.1 255.255.255.0\n"
                   "interface GigabitEthernet0/2\n ip access-group 199 in\n",
        "endpoints": "PC1, laptop, 10.0.0.5/24, 10.0.0.1, SW1 Gi0/1\n", "flows": "x, PC1, RX, tcp, 80, allow, high",
        "dry_run": True}).json()
    text = " ".join(res["warnings"])
    assert "Endpoint line 1" in text and "Flow line 1" in text and "access list 199" in text and "sub-interfaces" in text
    bad = client.post("/api/networks/import", headers=auth, json={"configs": "no hostname here"})
    assert bad.status_code == 422


def test_imported_sample_network_is_healthy(client, auth, imported):
    hc = client.get(f"/api/networks/{imported[0]['network_id']}/health-check", headers=auth).json()
    assert not hc["issues"], hc["issues"]


@pytest.mark.parametrize("entry", [
    "permit tcp any any range 80 90",
    "deny tcp any any gt 1024",
    "permit tcp any eq 12345 any eq 443",
    "permit tcp any any eq madeup",
    "permit tcp any any eq 443 established",
    "permit icmp any any echo",
    "permit tcp any any eq 0",
])
def test_import_rejects_acl_conditions_it_cannot_represent(client, auth, entry):
    payload = {"configs": "hostname R1\ninterface G0/0\n ip address 10.0.0.1 255.255.255.0\n"
               " ip access-group EDGE in\nip access-list extended EDGE\n 10 " + entry,
               "dry_run": True}
    response = client.post("/api/networks/import", headers=auth, json=payload)
    assert response.status_code == 422, response.text
    assert "Configuration import:" in response.json()["detail"]
    assert client.get("/api/networks", headers=auth).json() == []


@pytest.mark.parametrize("setting", [
    "interface G0/0\n ip address 999.0.0.1 255.255.255.0",
    "interface G0/0\n ip address 10.0.0.0 255.255.255.0",
    "interface G0/0\n ip address 10.0.0.1 255.0.255.0",
    "interface G0/0\n switchport access vlan 5000",
    "interface G0/0\n ip ospf 1 area invalid",
    "router ospf 1\n network 10.0.0.0 0.0.0.255 area 999999",
])
def test_invalid_import_settings_return_input_feedback_without_persisting(client, auth, setting):
    response = client.post("/api/networks/import", headers=auth,
                           json={"configs": "hostname R1\n" + setting})
    assert response.status_code == 422, response.text
    assert response.json()["error"] == "validation_error"
    assert client.get("/api/networks", headers=auth).json() == []


def test_import_accepts_supported_dotted_ospf_areas_and_acl_logging():
    devs, warnings = parse_configs("hostname R1\ninterface G0/0\n ip address 10.0.0.1 255.255.255.0\n"
                                  " ip ospf 1 area 0.0.0.1\nip access-list extended EDGE\n"
                                  " 10 permit tcp any host 10.0.0.10 eq https log\n")
    assert not warnings
    assert devs["R1"].ifs["Gi0/0"].area == 1
    assert devs["R1"].acls["EDGE"] == [(10, "permit", "tcp", "any", "10.0.0.10/32", 443)]


def test_import_reports_invalid_endpoint_and_flow_fields(client, auth):
    sample = client.get("/api/networks/import/sample", headers=auth).json()
    payload = {**sample, "dry_run": True,
               "endpoints": sample["endpoints"] + "\nBad-PC, pc, 10.20.0.8/24, invalid, SW1 Gi0/4\n",
               "flows": sample["flows"] + "\nBad port, Finance-PC, ERP, tcp, unknown, allow, high\n"
                        "Bad range, Finance-PC, ERP, tcp, 99999, allow, high\n"}
    response = client.post("/api/networks/import", headers=auth, json=payload)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["summary"]["devices"] == 11 and result["summary"]["flows"] == 6
    text = " ".join(result["warnings"])
    assert "Endpoint Bad-PC skipped" in text and "numeric destination port" in text and "65535" in text


def test_long_ios_description_is_shortened_with_a_warning_not_rejected():
    # IOS accepts 240-character descriptions; NetGuard stores 120 and must still import the device.
    devs, warnings = parse_configs("hostname R9\n!\ninterface GigabitEthernet0/0/0\n description " + "x" * 200
                                   + "\n ip address 10.9.0.1 255.255.255.0\n!\nend\n")
    assert len(devs["R9"].ifs["Gi0/0/0"].description) == 120
    assert any("description shortened" in warning for warning in warnings)
