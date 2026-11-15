def _device(client, auth, nid, name, dtype="router", **extra):
    response = client.post(
        f"/api/networks/{nid}/devices", json={"name": name, "device_type": dtype, **extra}, headers=auth
    )
    assert response.status_code == 201, response.text
    return response.json()


def _interface(client, auth, device_id, name, **extra):
    response = client.post(f"/api/devices/{device_id}/interfaces", json={"name": name, **extra}, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def test_device_crud_and_validation(client, auth, network):
    nid = network["id"]
    r1 = _device(client, auth, nid, "R1", vendor="Cisco", model="Generic Router", management_ip="192.168.1.1",
                 x_position=10, y_position=20)
    assert r1["x_position"] == 10 and r1["management_ip"] == "192.168.1.1"

    assert client.post(f"/api/networks/{nid}/devices", json={"name": "r1", "device_type": "router"},
                       headers=auth).status_code == 409
    bad = client.post(f"/api/networks/{nid}/devices",
                      json={"name": "X", "device_type": "toaster", "management_ip": "999.1.1.1"}, headers=auth)
    assert bad.status_code == 422
    assert "device_type" in bad.json()["detail"] and "management_ip" in bad.json()["detail"]

    edited = client.put(f"/api/devices/{r1['id']}",
                        json={"name": "R1-Core", "device_type": "router", "vendor": "Juniper",
                              "model": "MX5", "management_ip": "192.168.1.10"}, headers=auth)
    assert edited.status_code == 200
    assert edited.json()["name"] == "R1-Core"
    assert edited.json()["x_position"] == 10  # position untouched when omitted


def test_interface_crud_and_validation(client, auth, network):
    r1 = _device(client, auth, network["id"], "R1")
    g00 = _interface(client, auth, r1["id"], "G0/0", ip_address="10.0.12.1", subnet_mask="/30", status="up")
    assert g00["subnet_mask"] == "255.255.255.252"

    assert client.post(f"/api/devices/{r1['id']}/interfaces", json={"name": "g0/0"},
                       headers=auth).status_code == 409
    for payload in (
        {"name": "G0/1", "ip_address": "10.0.0.1"},  # missing mask
        {"name": "G0/1", "ip_address": "10.0.0.1", "subnet_mask": "255.0.255.0"},  # non-contiguous
        {"name": "G0/1", "vlan_id": 5000},
        {"name": "G0/1", "status": "broken"},
    ):
        assert client.post(f"/api/devices/{r1['id']}/interfaces", json=payload, headers=auth).status_code == 422

    updated = client.put(f"/api/interfaces/{g00['id']}",
                         json={"name": "G0/0", "ip_address": "10.0.12.5", "subnet_mask": "255.255.255.252",
                               "vlan_id": 10, "status": "down"}, headers=auth)
    assert updated.json()["status"] == "down" and updated.json()["vlan_id"] == 10
    assert client.delete(f"/api/interfaces/{g00['id']}", headers=auth).status_code == 204
    assert client.get(f"/api/devices/{r1['id']}/interfaces", headers=auth).json() == []


def test_link_rules(client, auth, network):
    nid = network["id"]
    r1, r2 = _device(client, auth, nid, "R1"), _device(client, auth, nid, "R2")
    r1_g0 = _interface(client, auth, r1["id"], "G0/0")
    r2_g0 = _interface(client, auth, r2["id"], "G0/0")

    link = client.post(f"/api/networks/{nid}/links", json={
        "source_device_id": r1["id"], "source_interface_id": r1_g0["id"],
        "destination_device_id": r2["id"], "destination_interface_id": r2_g0["id"]}, headers=auth)
    assert link.status_code == 201
    assert link.json()["source_interface_name"] == "G0/0"

    # interface already used
    reused = client.post(f"/api/networks/{nid}/links", json={
        "source_device_id": r1["id"], "source_interface_id": r1_g0["id"], "destination_device_id": r2["id"]},
        headers=auth)
    assert reused.status_code == 409
    # self link
    assert client.post(f"/api/networks/{nid}/links", json={
        "source_device_id": r1["id"], "destination_device_id": r1["id"]}, headers=auth).status_code == 422
    # interface belongs to another device
    assert client.post(f"/api/networks/{nid}/links", json={
        "source_device_id": r1["id"], "source_interface_id": r2_g0["id"],
        "destination_device_id": r2["id"]}, headers=auth).status_code == 422

    # deleting an interface keeps the link but clears the reference
    client.delete(f"/api/interfaces/{r2_g0['id']}", headers=auth)
    links = client.get(f"/api/networks/{nid}/links", headers=auth).json()
    assert len(links) == 1 and links[0]["destination_interface_id"] is None

    # deleting a device removes its links
    client.delete(f"/api/devices/{r2['id']}", headers=auth)
    assert client.get(f"/api/networks/{nid}/links", headers=auth).json() == []


def test_device_from_other_network_rejected(client, auth, network):
    other = client.post("/api/networks", json={"name": "Branch", "network_type": "Branch"}, headers=auth).json()
    r1 = _device(client, auth, network["id"], "R1")
    foreign = _device(client, auth, other["id"], "B1")
    response = client.post(f"/api/networks/{network['id']}/links",
                           json={"source_device_id": r1["id"], "destination_device_id": foreign["id"]}, headers=auth)
    assert response.status_code == 422
    positions = client.put(f"/api/networks/{network['id']}/topology/positions",
                           json={"positions": [{"device_id": foreign["id"], "x": 1, "y": 1}]}, headers=auth)
    assert positions.status_code == 422


def test_save_and_reload_positions(client, auth, network):
    nid = network["id"]
    r1, r2 = _device(client, auth, nid, "R1"), _device(client, auth, nid, "R2")
    saved = client.put(f"/api/networks/{nid}/topology/positions", json={"positions": [
        {"device_id": r1["id"], "x": -123.456, "y": 77.5}, {"device_id": r2["id"], "x": 300, "y": -40}]},
        headers=auth)
    assert saved.json() == {"updated": 2}
    topology = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    positions = {d["name"]: (d["x_position"], d["y_position"]) for d in topology["devices"]}
    assert positions == {"R1": (-123.46, 77.5), "R2": (300.0, -40.0)}


