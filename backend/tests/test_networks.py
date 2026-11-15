def test_network_crud(client, auth, network):
    listed = client.get("/api/networks", headers=auth).json()
    assert [n["name"] for n in listed] == ["HQ Enterprise Network"]
    assert listed[0]["created_by_username"] == "admin"

    updated = client.put(
        f"/api/networks/{network['id']}",
        json={"name": "HQ Network", "description": "Edited", "network_type": "Campus"},
        headers=auth,
    )
    assert updated.status_code == 200
    assert updated.json()["network_type"] == "Campus"

    assert client.delete(f"/api/networks/{network['id']}", headers=auth).status_code == 204
    assert client.get(f"/api/networks/{network['id']}", headers=auth).status_code == 404


def test_network_validation_and_duplicates(client, auth, network):
    blank = client.post("/api/networks", json={"name": "   ", "network_type": "Enterprise"}, headers=auth)
    assert blank.status_code == 422
    bad_type = client.post("/api/networks", json={"name": "X", "network_type": "Mars"}, headers=auth)
    assert bad_type.status_code == 422
    duplicate = client.post(
        "/api/networks", json={"name": "hq enterprise network", "network_type": "Enterprise"}, headers=auth
    )
    assert duplicate.status_code == 409


def test_delete_network_cascades(client, auth, network):
    nid = network["id"]
    r1 = client.post(f"/api/networks/{nid}/devices", json={"name": "R1", "device_type": "router"}, headers=auth).json()
    client.post(f"/api/devices/{r1['id']}/interfaces", json={"name": "G0/0"}, headers=auth)
    assert client.delete(f"/api/networks/{nid}", headers=auth).status_code == 204
    assert client.get(f"/api/devices/{r1['id']}", headers=auth).status_code == 404
    assert client.get("/api/dashboard/summary", headers=auth).json()["interfaces"] == 0


def test_demo_network_and_dashboard(client, auth):
    first = client.post("/api/networks/demo", headers=auth)
    second = client.post("/api/networks/demo", headers=auth)
    assert first.status_code == second.status_code == 201
    assert second.json()["name"] == "HQ Enterprise Network (2)"
    topology = client.get(f"/api/networks/{first.json()['id']}/topology", headers=auth).json()
    names = {d["name"] for d in topology["devices"]}
    assert {"INTERNET", "FW1", "R1", "R2", "R3", "SW1", "SW2", "Finance-PC", "HR-PC", "ERP", "DNS"} == names
    assert len(topology["links"]) == 10

    summary = client.get("/api/dashboard/summary", headers=auth).json()
    assert summary["networks"] == 2
    assert summary["devices"] == 22
    assert summary["pending_changes"] == 0 and summary["high_critical_changes"] == 0
    assert summary["devices_by_type"]["router"] == 6
