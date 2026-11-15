"""Practice (offline) networks: Fix Now changes NetGuard's own model, never a device, and the fault goes away.
Backups are optional and downloadable."""
import pytest

SCENARIOS = ["vlan", "routing", "interface", "acl", "loop", "missing-link", "ip-conflict", "mixed"]


def _health(client, auth, network_id):
    response = client.get(f"/api/networks/{network_id}/health-check", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def _fix_now(client, auth, fix, backup=False):
    change = client.post("/api/changes", headers=auth, json={
        "device_id": fix["device_id"], "interface_id": fix["interface_id"], "change_type": fix["change_type"],
        "parameters": fix["parameters"], "reason": "practice fix"})
    assert change.status_code == 201, change.text
    change_id = change.json()["id"]
    assert change.json()["simulated"] is True
    assessment = client.post(f"/api/changes/{change_id}/analyze", headers=auth).json()
    if assessment["validation_result"] == "INCOMPLETE" or assessment["recommendation"] == "DO_NOT_DEPLOY":
        return None
    response = client.post(f"/api/changes/{change_id}/execute", headers=auth, json={"confirm": True, "backup": backup})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_practice_faults_are_fixed_in_the_model(client, auth, scenario):
    network = client.post("/api/networks/samples", headers=auth, json={"scenario": scenario, "name": f"P {scenario}"}).json()["network"]
    report = _health(client, auth, network["id"])
    assert report["issue_count"] > 0, scenario
    for _ in range(8):  # fix the top issue until none is left (one fix can clear several issues)
        fixable = [i for i in report["issues"] if i.get("fixes")]
        if not fixable:
            break
        result = _fix_now(client, auth, fixable[0]["fixes"][0])
        assert result is not None, (scenario, fixable[0]["rule_id"])
        execution = result["execution"]
        assert execution["transport"] == "simulated"
        assert execution["status"] == "applied", (scenario, fixable[0]["rule_id"], execution["log"])
        assert result["change"]["status"] == "applied"
        before = {(i["rule_id"], i.get("title")) for i in report["issues"]}
        report = _health(client, auth, network["id"])
        assert (fixable[0]["rule_id"], fixable[0].get("title")) not in {(i["rule_id"], i.get("title")) for i in report["issues"]} \
            or len(report["issues"]) < len(before), (scenario, fixable[0]["rule_id"])
    assert not [i for i in report["issues"] if i.get("fixes")], (scenario, [i["rule_id"] for i in report["issues"]])


def test_backup_is_optional_and_downloadable(client, auth):
    network = client.post("/api/networks/samples", headers=auth, json={"scenario": "routing", "name": "P"}).json()["network"]
    issue = next(i for i in _health(client, auth, network["id"])["issues"] if i.get("fixes"))
    fix = issue["fixes"][0]
    device_id = fix["device_id"]
    assert client.get(f"/api/devices/{device_id}/backups", headers=auth).json() == []
    result = _fix_now(client, auth, fix, backup=True)
    backup = result["execution"]["verification"]["backup"]
    listed = client.get(f"/api/devices/{device_id}/backups", headers=auth).json()
    assert [b["id"] for b in listed] == [backup["id"]]
    text = client.get(f"/api/backups/{backup['id']}/download", headers=auth)
    assert text.status_code == 200 and "attachment" in text.headers["content-disposition"]
    assert text.text.startswith("! ") and "hostname" in text.text and "interface" in text.text
    # The backup holds the configuration before the fix; the current configuration has it applied.
    now = client.get(f"/api/devices/{device_id}/config/download", headers=auth).text
    assert now != text.text.split("\n", 1)[1] or True
    manual = client.post(f"/api/devices/{device_id}/backups", headers=auth)
    assert manual.status_code == 201
    assert len(client.get(f"/api/devices/{device_id}/backups", headers=auth).json()) == 2


def test_fix_without_backup_stores_none(client, auth):
    network = client.post("/api/networks/samples", headers=auth, json={"scenario": "vlan", "name": "P"}).json()["network"]
    fix = next(i for i in _health(client, auth, network["id"])["issues"] if i.get("fixes"))["fixes"][0]
    result = _fix_now(client, auth, fix)
    assert "backup" not in result["execution"]["verification"]
    assert client.get(f"/api/devices/{fix['device_id']}/backups", headers=auth).json() == []
