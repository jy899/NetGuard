"""Auto-Fix as a group permission, real-network fixing by permission, the issue-to-change link, passwords, and the
Web GUI / Ports permissions."""
from backend.tests.helpers import group_id, manager_auth
from backend.tests.test_live_lab_workflow import _import, lab  # noqa: F401 - the lab fixture is used below


def _account(client, auth, username, group, password="pw"):
    client.post("/api/accounts", headers=auth, json={"username": username, "password": password,
                                                     "group_id": group_id(client, auth, group)})
    token = client.post("/api/auth/login", json={"username": username, "password": password}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _vlan_change(client, headers, sw1_id, vlan_id):
    change = client.post("/api/changes", headers=headers, json={
        "device_id": sw1_id, "change_type": "vlan_database", "parameters": {"action": "add", "vlan_id": vlan_id, "name": "GUEST"}}).json()
    assert client.post(f"/api/changes/{change['id']}/analyze", headers=headers).status_code == 200
    return change


def _group(client, auth, name):
    return next(g for g in client.get("/api/groups", headers=auth).json() if g["name"] == name)


def test_administrators_have_every_permission_including_auto_fix(client, auth):
    admins = _group(client, auth, "Administrators")
    from backend.core.permissions import PERMISSIONS

    assert set(PERMISSIONS) == set(admins["permissions"])  # every permission, Auto-Fix included
    assert "change.auto_fix" not in _group(client, auth, "Network Engineers")["permissions"]
    assert "change.auto_fix" not in _group(client, auth, "IT Managers")["permissions"]
    assert client.get("/api/settings/self-healing", headers=auth).json()["direct_for_me"] is True


def test_without_auto_fix_a_change_needs_approval(client, auth, lab):  # noqa: F811
    engineer = _account(client, auth, "engineer1", "Network Engineers")
    assert client.get("/api/settings/self-healing", headers=engineer).json()["direct_for_me"] is False
    nid, topo = _import(client, auth, lab)
    sw1 = next(d for d in topo["devices"] if d["name"] == "SW1")
    change = _vlan_change(client, engineer, sw1["id"], 41)
    refused = client.post(f"/api/changes/{change['id']}/execute", headers=engineer, json={"confirm": True, "transport": "console"})
    assert refused.status_code == 409 and "approved" in refused.json()["detail"]
    assert client.put("/api/settings/self-healing", headers=engineer, json={"confirm_minutes": 5}).status_code == 403


def test_auto_fix_applies_a_validated_lab_change_in_one_click(client, auth, lab):  # noqa: F811
    nid, topo = _import(client, auth, lab)
    sw1 = next(d for d in topo["devices"] if d["name"] == "SW1")
    assert client.post(f"/api/networks/{nid}/collect", headers=auth, json={"device_ids": [sw1["id"]], "transport": "console"}).status_code == 200
    change = _vlan_change(client, auth, sw1["id"], 40)
    result = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json={"confirm": True, "transport": "console"})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["execution"]["status"] == "applied" and body["change"]["status"] == "applied"
    assert "vlan 40" in lab["sw1"].running()
    history = client.get("/api/history", headers=auth, params={"network_id": nid, "scope": "all"}).json()
    assert any("Auto-Fix by admin" in row["title"] for row in history)


def test_auto_fix_can_be_granted_to_any_group(client, auth, lab):  # noqa: F811
    engineers = _group(client, auth, "Network Engineers")
    granted = engineers["permissions"] + ["change.auto_fix"]
    assert client.put(f"/api/groups/{engineers['id']}", headers=auth, json={
        "name": engineers["name"], "description": engineers["description"], "permissions": granted}).status_code == 200
    try:
        engineer = _account(client, auth, "engineer2", "Network Engineers")
        assert client.get("/api/settings/self-healing", headers=engineer).json()["direct_for_me"] is True
        nid, topo = _import(client, auth, lab)
        sw1 = next(d for d in topo["devices"] if d["name"] == "SW1")
        client.post(f"/api/networks/{nid}/collect", headers=auth, json={"device_ids": [sw1["id"]], "transport": "console"})
        change = _vlan_change(client, engineer, sw1["id"], 42)
        done = client.post(f"/api/changes/{change['id']}/execute", headers=engineer, json={"confirm": True, "transport": "console"})
        assert done.status_code == 200 and done.json()["execution"]["status"] == "applied", done.text
    finally:
        client.put(f"/api/groups/{engineers['id']}", headers=auth, json={
            "name": engineers["name"], "description": engineers["description"], "permissions": engineers["permissions"]})


def test_auto_fix_never_overrides_do_not_deploy(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    r1 = next(d for d in client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()["devices"] if d["name"] == "R1")
    iface = next(i for i in r1["interfaces"] if i.get("ospf_area") not in (None, ""))
    change = client.post("/api/changes", headers=auth, json={"device_id": r1["id"], "interface_id": iface["id"],
                                                             "change_type": "ospf_area", "parameters": {"area": "1"}}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert assessment["recommendation"] == "DO_NOT_DEPLOY"
    refused = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json={"confirm": True})
    assert refused.status_code in (409, 422)
    assert client.get(f"/api/changes/{change['id']}", headers=auth).json()["status"] != "approved"


def test_issue_shows_its_submitted_and_approved_change(client, auth):
    """Approving a fix does not change a device. The analysis now shows the approved change on the issue so the
    submitter can apply it, instead of offering the same fix again (the 'error still there after approval' case)."""
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    issue = next(i for i in report["issues"] if i["fixes"] and i["fixes"][0]["verification"]["verdict"] == "recommended")
    fix = issue["fixes"][0]
    change = client.post("/api/changes", headers=auth, json={k: fix[k] for k in ("device_id", "interface_id", "change_type", "parameters")}).json()
    client.post(f"/api/changes/{change['id']}/analyze", headers=auth)
    assert client.post(f"/api/changes/{change['id']}/submit", headers=auth).status_code == 200
    linked = lambda: next(i for i in client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()["issues"]  # noqa: E731
                          if i["key"] == issue["key"])["fixes"][0].get("change")
    assert linked() == {"id": change["id"], "status": "pending_approval"}
    manager = manager_auth(client, auth)
    assert client.post(f"/api/changes/{change['id']}/approve", headers=manager, json={"note": "ok"}).status_code == 200
    assert linked() == {"id": change["id"], "status": "approved"}


def test_passwords_have_no_rules_and_admin_can_reset_them(client, auth):
    short = _account(client, auth, "shortpw", "IT Managers", password="1")
    assert client.get("/api/auth/me", headers=short).status_code == 200
    assert client.put("/api/auth/password", headers=short, json={"current_password": "1", "new_password": "2"}).status_code == 200
    account = next(a for a in client.get("/api/accounts", headers=auth).json() if a["username"] == "shortpw")
    assert client.put(f"/api/accounts/{account['id']}", headers=auth, json={"password": "reset"}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "shortpw", "password": "reset"}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "shortpw", "password": "2"}).status_code == 401


def test_web_gui_address_and_ports_follow_the_terminal_permission(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    sw1 = next(d for d in client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()["devices"] if d["name"] == "SW1")
    manager = manager_auth(client, auth)  # IT Managers do not have device.terminal
    assert client.post(f"/api/devices/{sw1['id']}/portals/open", headers=manager, json={"address": "127.0.0.1:1"}).status_code == 403
    opened = client.post(f"/api/devices/{sw1['id']}/portals/open", headers=auth, json={"address": "127.0.0.1:1"})
    assert opened.status_code == 200 and opened.json()["url"] == "http://127.0.0.1:1/" and opened.json()["verified"] is False
    portals = client.get(f"/api/devices/{sw1['id']}/portals", headers=auth).json()["portals"]
    assert any(p["url"] == "http://127.0.0.1:1/" and p.get("custom") for p in portals)
    bad = client.post(f"/api/devices/{sw1['id']}/portals/open", headers=auth, json={"address": "javascript:alert(1)"})
    assert bad.status_code == 422
    ports = client.get(f"/api/devices/{sw1['id']}/port-clients", headers=manager)
    assert ports.status_code == 200 and ports.json()["device_id"] == sw1["id"]
