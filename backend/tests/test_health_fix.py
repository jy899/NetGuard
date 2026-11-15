"""Network Health Check, verified fixes and apply (with approval)."""
from backend.tests.helpers import approve, approve_and_apply  # noqa: E402


def _health(client, auth, network_id):
    response = client.get(f"/api/networks/{network_id}/health-check", headers=auth)
    assert response.status_code == 200
    return response.json()


def _apply(client, auth, fix, reason="test fix"):
    change = client.post("/api/changes", headers=auth, json={
        "device_id": fix["device_id"], "interface_id": fix["interface_id"], "change_type": fix["change_type"],
        "parameters": fix["parameters"], "reason": reason})
    assert change.status_code == 201, change.text
    return approve_and_apply(client, auth, change.json()["id"])


def test_clean_demo_is_healthy(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    report = _health(client, auth, network["id"])
    assert report["status"] == "healthy" and report["issue_count"] == 0
    assert all(f["ok"] for f in report["flows"])
    assert len(report["flows"]) == 6 and any(f["destination"] == "INTERNET" for f in report["flows"])


def test_faulty_demo_issues_are_root_causes_with_verified_fixes(client, auth):
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    report = _health(client, auth, network["id"])
    assert sorted(i["rule_id"] for i in report["issues"]) == ["IP002", "OSPF001", "ROUTE001", "VLAN001"]
    scores = [i["risk"]["score"] for i in report["issues"]]
    assert scores == sorted(scores, reverse=True)  # highest transparent risk score first
    assert all(i["risk"]["score"] == round(100 * i["risk"]["S"] * (1 + i["risk"]["I"] + i["risk"]["E"]) / 24)
               for i in report["issues"])
    for issue in report["issues"]:
        best = issue["fixes"][0]["verification"]
        assert best["verdict"] == "recommended", issue["rule_id"]
        assert best["resolves"] and not best["new_issues"] and not best["broken_flows"]
        # A real template: more than the illustrative header (host fixes are one host-setting line),
        # and never the "no command template" fallback.
        commands = best["commands"]
        assert not any("command template" in line for line in commands), issue["rule_id"]
        if commands[0].startswith("# Illustrative host setting"):
            assert len(commands) == 1, issue["rule_id"]
        else:
            assert len(commands) > 1, issue["rule_id"]
    ospf = next(i for i in report["issues"] if i["rule_id"] == "OSPF001")
    assert ospf["fixes"][0]["label"] == "Set R1 Gi0/0/1 to Area 0"
    assert ospf["fixes"][0]["verification"]["commands"] == [
        "! Generated commands; sent only for an approved change or an Auto-Fix, with backup and automatic undo.", "configure terminal", "interface Gi0/0/1", " ip ospf 1 area 0", "end"]
    route = next(i for i in report["issues"] if i["rule_id"] == "ROUTE001")
    # Only FW1 forwards a default route onwards; R2/R3 would black-hole internet traffic.
    assert [f["label"] for f in route["fixes"]] == ["Use next hop 10.0.1.1 (FW1)", "Remove route 0.0.0.0/0"]


def test_health_check_does_not_modify_network(client, auth):
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    before = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    _health(client, auth, network["id"])
    after = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    assert before["devices"] == after["devices"]
    assert client.get("/api/changes", headers=auth).json() == []


def test_fix_all_one_by_one_reaches_healthy(client, auth):
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    report = _health(client, auth, network["id"])
    for _ in range(10):
        if not report["issues"]:
            break
        issue = report["issues"][0]
        applied = _apply(client, auth, issue["fixes"][0])
        assert applied.status_code == 200, applied.text
        assert applied.json()["change"]["status"] == "applied"
        assert applied.json()["assessment"]["risk_level"] == "LOW"
        report = _health(client, auth, network["id"])
    assert report["status"] == "healthy"
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    r1 = next(d for d in topology["devices"] if d["name"] == "R1")
    assert next(i for i in r1["interfaces"] if i["name"] == "Gi0/0/1")["ospf_area"] == 0
    assert r1["static_routes"][0]["next_hop"] == "10.0.1.1"


def test_apply_refuses_do_not_deploy_and_double_apply(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    r1 = next(d for d in topology["devices"] if d["name"] == "R1")
    g00 = next(i["id"] for i in r1["interfaces"] if i["name"] == "Gi0/0/0")
    risky = {"device_id": r1["id"], "interface_id": g00, "change_type": "ospf_area", "parameters": {"area": 1}}
    refused = _apply(client, auth, risky)
    # A change rated Do not deploy can never be submitted, so it is never approved or applied.
    assert refused.status_code == 409 and "approved" in refused.json()["detail"]
    after = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    r1_after = next(d for d in after["devices"] if d["name"] == "R1")
    assert next(i for i in r1_after["interfaces"] if i["id"] == g00)["ospf_area"] == 0  # unchanged

    safe = {"device_id": next(d["id"] for d in topology["devices"] if d["name"] == "SW1"), "interface_id": None,
            "change_type": "vlan_database", "parameters": {"action": "add", "vlan_id": 40, "name": "GUEST"}}
    ok = _apply(client, auth, safe)
    assert ok.status_code == 200
    again = client.post(f"/api/changes/{ok.json()['change']['id']}/apply", headers=auth, json={"confirm": True})
    assert again.status_code == 409


def test_analysis_includes_device_commands(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    sw1 = next(d for d in topology["devices"] if d["name"] == "SW1")
    port = next(i["id"] for i in sw1["interfaces"] if i["name"] == "Gi1/0/1")
    change = client.post("/api/changes", headers=auth, json={
        "device_id": sw1["id"], "interface_id": port, "change_type": "access_vlan", "parameters": {"vlan_id": 20}}).json()
    result = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert result["change"]["commands"] == ["! Generated commands; sent only for an approved change or an Auto-Fix, with backup and automatic undo.", "configure terminal", "interface Gi1/0/1", " switchport mode access",
                                            " switchport access vlan 20", "end"]


def test_apply_requires_explicit_confirmation(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    sw1 = next(d for d in topology["devices"] if d["name"] == "SW1")
    change = client.post("/api/changes", headers=auth, json={
        "device_id": sw1["id"], "change_type": "vlan_database", "parameters": {"action": "add", "vlan_id": 40}}).json()
    url = f"/api/changes/{change['id']}/apply"
    for body in (None, {}, {"confirm": False}, {"confirm": "true"}, {"confirm": 1}):
        refused = client.post(url, headers=auth, json=body) if body is not None else client.post(url, headers=auth)
        assert refused.status_code == 400, body
        assert refused.json()["error"] == "bad_request" and '{"confirm": true}' in refused.json()["detail"]
    after = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    assert after["devices"] == topology["devices"]  # nothing written without confirmation
    assert client.get(f"/api/changes/{change['id']}", headers=auth).json()["status"] != "applied"
    assert client.post(url, headers=auth, json={"confirm": True}).status_code == 409  # not approved yet
    approve(client, auth, change["id"])
    assert client.post(url, headers=auth, json={"confirm": True}).status_code == 200


def test_ospf_fix_that_moves_area0_side_is_not_recommended(client, auth):
    """Faulty demo: R1 Gi0/0/1 is in Area 1, R3 Gi0/0/0 in Area 0, and R3 Gi0/0/1 stays in Area 0. Moving R3 Gi0/0/0
    to Area 1 would split the backbone on real routers, so only 'R1 Gi0/0/1 to Area 0' is recommended."""
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    ospf = next(i for i in _health(client, auth, network["id"])["issues"] if i["rule_id"] == "OSPF001")
    fixes = {f["label"]: f for f in ospf["fixes"]}
    good, risky = fixes["Set R1 Gi0/0/1 to Area 0"], fixes["Set R3 Gi0/0/0 to Area 1"]
    assert ospf["fixes"][0] is not risky and ospf["recommended_fix"] == 0
    assert good["verification"]["verdict"] == "recommended" and good["verification"]["caution"] is None
    assert risky["verification"]["verdict"] == "partial"
    assert "split the OSPF backbone (Area 0)" in risky["description"] and "review" in risky["description"].lower()
    assert risky["verification"]["caution"]


def test_ospf_fix_rule_when_area0_is_on_the_other_side(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    r3 = next(d for d in topology["devices"] if d["name"] == "R3")
    g00 = next(i for i in r3["interfaces"] if i["name"] == "Gi0/0/0")
    updated = client.put(f"/api/interfaces/{g00['id']}", headers=auth, json={**{k: g00[k] for k in (
        "name", "ip_address", "subnet_mask", "vlan_id", "status", "mode")}, "ospf_area": 2})
    assert updated.status_code == 200, updated.text
    ospf = next(i for i in _health(client, auth, network["id"])["issues"] if i["rule_id"] == "OSPF001")
    verdicts = {f["label"]: f["verification"]["verdict"] for f in ospf["fixes"]}
    assert verdicts == {"Set R3 Gi0/0/0 to Area 0": "recommended", "Set R1 Gi0/0/1 to Area 2": "partial"}
    assert ospf["fixes"][0]["label"] == "Set R3 Gi0/0/0 to Area 0"


def test_route001_fix_keeps_internet_access(client, auth):
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    report = _health(client, auth, network["id"])
    internet = next(f for f in report["flows"] if f["destination"] == "INTERNET")
    assert not internet["ok"] and "invalid next hop" in internet["reason"]
    route = next(i for i in report["issues"] if i["rule_id"] == "ROUTE001")
    assert route["related_flows"] == ["Finance Internet access (HTTPS)"]
    fixes = {f["label"]: f["verification"] for f in route["fixes"]}
    assert fixes["Use next hop 10.0.1.1 (FW1)"]["verdict"] == "recommended"
    assert "Finance-PC → INTERNET" in fixes["Use next hop 10.0.1.1 (FW1)"]["restored_flows"]
    removal = fixes["Remove route 0.0.0.0/0"]
    assert removal["verdict"] != "recommended" and removal["recommendation"] == "DO_NOT_DEPLOY"
    assert [n["rule_id"] for n in removal["new_issues"]] == ["ROUTE002"]
    # The OSPF001 issue is not blamed for the internet flow.
    ospf = next(i for i in report["issues"] if i["rule_id"] == "OSPF001")
    assert ospf["related_flows"] == ["Finance ERP access (HTTPS)"]


def test_fixing_default_route_before_ospf_does_not_hide_the_ospf_cause(client, auth):
    """With R1's default route working again, ERP traffic loops R1 → FW1 → R1 while the R1–R3 adjacency is
    down; the health check still names the OSPF mismatch as the cause, not a new routing issue."""
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    route = next(i for i in _health(client, auth, network["id"])["issues"] if i["rule_id"] == "ROUTE001")
    assert _apply(client, auth, route["fixes"][0]).status_code == 200
    report = _health(client, auth, network["id"])
    assert sorted(i["rule_id"] for i in report["issues"]) == ["IP002", "OSPF001", "VLAN001"]
    erp = next(f for f in report["flows"] if f["name"] == "Finance ERP access (HTTPS)")
    assert erp["reason"] == "OSPF adjacency R1–R3 is down (area mismatch)"
    assert next(f for f in report["flows"] if f["destination"] == "INTERNET")["ok"]
