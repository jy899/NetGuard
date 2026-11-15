"""Hardware naming and supplied sample inventories remain consistent."""
import pytest
from sqlalchemy import text

from backend.services.config_import import parse_configs
from backend.services.interface_naming import canonical_name, platform_for, port_info


@pytest.mark.parametrize("alias, expected", [
    ("GigabitEthernet0/1", "Gi0/1"), ("gi0/1", "Gi0/1"), ("G0/1", "Gi0/1"),
    ("Gig0/1", "Gi0/1"), ("FastEthernet0/1", "Fa0/1"),
    ("TenGigabitEthernet1/1/1", "Te1/1/1"), ("TwentyFiveGigE1/0/1", "Twe1/0/1"),
    ("Ethernet1/1", "Et1/1"), ("Loopback0", "Lo0"), ("Vlan20", "Vlan20"),
    ("Port-channel1", "Po1"), ("Gig 0/0/1.10", "Gi0/0/1.10"),
    ("arbitrary-port", "arbitrary-port"),
])
def test_cisco_canonical_aliases(alias, expected):
    assert canonical_name(alias, "cisco-ios") == expected
    assert canonical_name("  " + alias + "  ", "generic") == alias


def test_platforms_and_catalogue_never_guess_unknown_hardware():
    assert platform_for("Cisco", "ISR 4331", "router") == "cisco-ios"
    assert platform_for("Fortinet", "FortiGate 60F", "firewall") == "fortios"
    assert platform_for("HPE Aruba", "Aruba AP-505", "switch") == "aruba-ap"
    assert platform_for("Microsoft", None, "pc") == "host"
    assert platform_for(None, None, "internet") == "cloud"
    assert platform_for(None, "ISR 4331", "router") == "generic"
    assert port_info("Cisco", "Unknown", "switch", "Gi99/99")["exists"] is None
    assert port_info(None, "ISR 4331", "router", "Gi0/0/0")["exists"] is None
    assert port_info("Cisco", "ISR 4331", "router", "Gi0/0/1.10")["exists"] is True
    assert port_info("Fortinet", "FortiGate 60F", "firewall", "port1")["exists"] is False
    assert port_info("HPE Aruba", "Aruba 2930F-24G-4SFP+", "switch", "25")["media"] == "fibre"
    assert port_info("HPE Aruba", "Aruba 2530-24G", "switch", "30")["exists"] is False


@pytest.mark.parametrize("scenario", ["healthy", "mixed", "vlan", "routing", "interface", "acl", "loop", "missing-link", "ip-conflict"])
def test_new_virtual_sample_ports_exist_and_no_loop_port_collisions(client, auth, scenario):
    created = client.post("/api/networks/samples", headers=auth, json={"scenario": scenario})
    assert created.status_code == 201, created.text
    topo = client.get(f"/api/networks/{created.json()['network_id']}/topology", headers=auth).json()
    for device in topo["devices"]:
        names = [i["name"] for i in device["interfaces"]]
        assert len(names) == len(set(names))
        for iface in device["interfaces"]:
            info = port_info(device["vendor"], device["model"], device["device_type"], iface["name"])
            assert info["exists"] is (None if device["device_type"] == "internet" else True), (device["name"], iface["name"])
    if scenario == "loop":
        sw1 = next(d for d in topo["devices"] if d["name"] == "SW1")
        assert {"Gi1/0/22", "Gi1/0/23", "Gi1/0/24"} <= {i["name"] for i in sw1["interfaces"]}
        assert len(topo["devices"]) == 13








def test_description_create_update_and_additive_upgrade(client, auth, network):
    device = client.post(f"/api/networks/{network['id']}/devices", headers=auth, json={"name": "Host", "device_type": "pc"}).json()
    created = client.post(f"/api/devices/{device['id']}/interfaces", headers=auth, json={"name": "eth0", "description": 'Windows adapter "Ethernet"'})
    assert created.status_code == 201 and created.json()["description"] == 'Windows adapter "Ethernet"'
    iid = created.json()["id"]
    updated = client.put(f"/api/interfaces/{iid}", headers=auth, json={"name": "eth0", "description": "Updated asset label"})
    assert updated.status_code == 200 and updated.json()["description"] == "Updated asset label"
    assert client.put(f"/api/interfaces/{iid}", headers=auth, json={"name": "eth0", "description": "x" * 121}).status_code == 422
    from backend.database.init_db import upgrade_schema
    # A separate SQLite database avoids editing the test model or saved user data.
    from sqlalchemy import create_engine
    import backend.database.init_db as init_module
    from unittest.mock import patch
    legacy = create_engine("sqlite:///:memory:")
    with legacy.begin() as connection:
        connection.execute(text("CREATE TABLE interfaces (id INTEGER PRIMARY KEY, name VARCHAR(64))"))
        connection.execute(text("INSERT INTO interfaces (id, name) VALUES (1, 'G0/1')"))
    with patch.object(init_module, "engine", legacy):
        assert "interfaces.description" in upgrade_schema()
        assert upgrade_schema() == []
    with legacy.connect() as connection:
        assert connection.execute(text("SELECT name, description FROM interfaces")).one() == ("G0/1", None)


def test_config_names_from_running_config_and_cdp_match_one_interface():
    devs, warnings = parse_configs("""hostname R1
interface GigabitEthernet0/0/0
 description Uplink to R2
 ip address 10.0.0.1 255.255.255.252
R1#show cdp neighbors
Device ID Local Intrfce Holdtme Capability Platform Port ID
R2 Gi0/0/0 120 R ISR4331 GigabitEthernet0/0/1
""")
    assert warnings == []
    assert list(devs["R1"].ifs) == ["Gi0/0/0"]
    assert devs["R1"].cdp == [("Gi0/0/0", "R2", "Gi0/0/1")]
    assert devs["R1"].ifs["Gi0/0/0"].description == "Uplink to R2"


