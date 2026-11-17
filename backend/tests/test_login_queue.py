"""Per-device login: every secure method offered with its reason, and an ordered fallback queue of saved profiles."""
from backend.tests.test_smart_discovery import by_name, scan


def _profile(client, auth, name, username, password, priority=100):
    response = client.post("/api/credential-profiles", headers=auth,
                           json={"name": name, "username": username, "password": password, "priority": priority})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_methods_the_scan_did_not_see_are_still_offered_with_the_reason(client, auth):
    result = scan(client, auth)
    gateway = next(r for r in result["available_authentications"] if r["ip"] == "172.16.10.1")
    assert gateway["methods"][-1] == "snmpv2c"            # cleartext community is the last resort
    assert gateway["methods"][:2] == ["ssh", "snmpv3"]
    assert "snmpv3" not in gateway["detected"]
    assert "did not answer" not in gateway["method_notes"]["ssh"]
    assert "No SNMPv3 engine answered" in gateway["method_notes"]["snmpv3"]


def test_fallback_queue_tries_saved_profiles_in_order_until_one_is_accepted(client, auth):
    result = scan(client, auth)
    nid = result["network_id"]
    wrong = _profile(client, auth, "Old admin", "admin", "wrong-password")
    right = _profile(client, auth, "Site admin", "admin", "admin")
    core = by_name(result)["CORE-SW-01"]["id"]
    response = client.post(f"/api/discovery/{nid}/authenticate", headers=auth, json={
        "device_ids": [core], "method": "ssh", "username": "admin", "password": "typo",
        "fallback_profile_ids": [wrong, right], "continue_discovery": False})
    assert response.status_code == 200, response.text
    outcome = response.json()["outcomes"][0]
    assert outcome["ok"] and outcome["profile"] == "Site admin"
    assert "queue order" in outcome["detail"]


def test_queue_only_login_without_typed_credentials(client, auth):
    result = scan(client, auth)
    nid = result["network_id"]
    wrong = _profile(client, auth, "Old admin", "admin", "wrong-password")
    ids = [r["device_id"] for r in result["available_authentications"] if "ssh" in r["detected"]][:2]
    response = client.post(f"/api/discovery/{nid}/authenticate", headers=auth, json={
        "device_ids": ids, "method": "ssh", "fallback_profile_ids": [wrong], "continue_discovery": False})
    assert response.status_code == 200, response.text
    outcomes = response.json()["outcomes"]
    assert not any(o["ok"] for o in outcomes)
    assert all("tried once each, in order: Old admin" in o["detail"] for o in outcomes)
    # Nothing typed and nothing queued is still refused.
    empty = client.post(f"/api/discovery/{nid}/authenticate", headers=auth, json={"device_ids": ids, "method": "ssh"})
    assert empty.status_code == 422


def test_ssh_port_is_passed_to_the_login(client, auth, monkeypatch):
    from backend.services.discovery import service
    seen = {}
    original = service._read_device

    def spy(*args, ssh_port=None, **kwargs):
        seen["port"] = ssh_port
        return original(*args, ssh_port=ssh_port, **kwargs)

    monkeypatch.setattr(service, "_read_device", spy)
    result = scan(client, auth)
    core = by_name(result)["CORE-SW-01"]["id"]
    client.post(f"/api/discovery/{result['network_id']}/authenticate", headers=auth, json={
        "device_ids": [core], "method": "ssh", "username": "admin", "password": "admin", "ssh_port": 2222,
        "continue_discovery": False})
    assert seen["port"] == 2222
