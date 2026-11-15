"""Common workflow evidence, differential validation and immutable reports."""
from backend.tests.helpers import approve, approve_and_apply  # noqa: E402
import json

from sqlalchemy import select

from backend.database.session import SessionLocal
from backend.models import Device, Interface, Link, Network
from backend.services import history_service


def _scenario(client, auth, scenario):
    response = client.post("/api/networks/scenario", headers=auth, json={"scenario": scenario})
    assert response.status_code == 201, response.text
    return response.json()


def test_analysis_persists_computed_evidence_and_topology(client, auth):
    network = _scenario(client, auth, "vlan")
    before = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    response = client.post(f"/api/networks/{network['id']}/analyze", headers=auth)
    assert response.status_code == 200, response.text
    record = response.json()
    issue = next(i for i in record["snapshot"]["analysis"]["issues"] if i["rule_id"] == "VLAN001")
    assert issue["evidence"] and issue["root_cause"] and issue["corrective_action"] and issue["expected_outcome"]
    assert issue["affected_interfaces"] and issue["affected_link_ids"]
    assert issue["certainty"] == "confirmed"
    assert client.get(f"/api/networks/{network['id']}/topology", headers=auth).json() == before
    assert client.get("/api/history?kind=analysis", headers=auth).json()[0]["id"] == record["id"]


def test_loop_requires_forwarding_cycle_and_supports_protected_redundancy(client, auth):
    network = _scenario(client, auth, "loop")
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    loops = [i for i in report["issues"] if i["rule_id"] == "L2001"]
    confirmed = next(i for i in loops if i["certainty"] == "confirmed")
    assert len(confirmed["link_ids"]) == 3
    assert any("MAC" in e["source"] for e in confirmed["evidence"])
    assert any("counters" in e["source"] for e in confirmed["evidence"])
    with SessionLocal() as db:
        interface = db.scalar(select(Interface).join(Link, Link.source_interface_id == Interface.id)
                              .where(Link.id == confirmed["link_ids"][0]))
        interface.stp_state = "blocking"
        db.commit()
    after = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    assert not any(i["rule_id"] == "L2001" for i in after["issues"])


def test_mac_flaps_alone_do_not_invent_network_loop(client, auth):
    network = _scenario(client, auth, "healthy")
    with SessionLocal() as db:
        row = db.get(Network, network["id"])
        row.metadata_json = {"mac_flaps": [{"device": "SW1", "vlan": 10, "count": 200}]}
        db.commit()
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    assert not any(i["rule_id"] == "L2001" for i in report["issues"])


def test_scenarios_are_computed_from_configuration(client, auth):
    expectations = {"interface": "LINK001", "acl": "ACL001", "ip-conflict": "IP003", "missing-link": "LINK002"}
    for scenario, expected in expectations.items():
        network = _scenario(client, auth, scenario)
        report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
        assert any(i["rule_id"] == expected for i in report["issues"]), (scenario, report)
    network = _scenario(client, auth, "healthy")
    assert client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()["issue_count"] == 0


def test_saved_report_is_immutable_and_export_has_no_secrets(client, auth):
    network = _scenario(client, auth, "vlan")
    saved = client.post(f"/api/networks/{network['id']}/reports", headers=auth, json={"title": "Reviewed sample"}).json()
    with SessionLocal() as db:
        iface = db.scalar(select(Interface).where(Interface.id == saved["snapshot"]["analysis"]["issues"][0]["fixes"][0]["interface_id"]))
        iface.vlan_id = 20
        db.commit()
    report = client.get(f"/api/history/{saved['id']}", headers=auth).json()
    assert report["snapshot"]["analysis"]["issue_count"] > 0
    assert client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()["issue_count"] == 0
    response = client.get(f"/api/history/{saved['id']}/export", headers=auth)
    assert response.status_code == 200 and "attachment" in response.headers["content-disposition"]
    with SessionLocal() as db:
        row = history_service.record(db, None, network["id"], "scan", "Safe scan", {},
                                     {"password": "dont-export", "nested": {"access_token": "dont-export", "status": "ok"}})
        clean = history_service.to_out(row, detail=True).model_dump_json()
        assert "dont-export" not in clean and '"status":"ok"' in clean


def test_dashboard_uses_latest_analysis_per_network(client, auth):
    network = _scenario(client, auth, "vlan")
    first = client.post(f"/api/networks/{network['id']}/analyze", headers=auth).json()
    client.post(f"/api/networks/{network['id']}/analyze", headers=auth)
    summary = client.get("/api/dashboard/summary", headers=auth).json()
    assert summary["detected_issues"] == first["summary"]["issue_count"]
    assert summary["analysis_runs"] == 2 and len(summary["recent_activity"]) == 2


def test_assessment_contains_real_baseline_and_candidate_snapshots(client, auth):
    network = _scenario(client, auth, "vlan")
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    fix = next(i for i in report["issues"] if i["rule_id"] == "VLAN001")["fixes"][0]
    change = client.post("/api/changes", headers=auth, json={k: fix[k] for k in ("device_id", "interface_id", "change_type", "parameters")}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert assessment["baseline_configuration"] != assessment["candidate_configuration"]
    assert assessment["configuration_diff"][0]["current"] != assessment["configuration_diff"][0]["proposed"]
    assert assessment["validation_result"] == "PASS"


def test_unknown_remote_interface_stays_unknown_and_vlan_recommendation_uses_local_evidence(client, auth):
    network = _scenario(client, auth, "healthy")
    with SessionLocal() as db:
        host = db.scalar(select(Device).where(Device.network_id == network["id"], Device.name == "HR-PC"))
        link = db.scalar(select(Link).where(Link.destination_device_id == host.id))
        link.kind, link.confidence, link.destination_interface_id = "mac", 0.65, None
        link.source_interface.vlan_id = 10
        link.evidence_json = json.dumps({"expected_vlan": 20, "evidence": [{"source": "MAC", "detail": "Learned on local port"}]})
        link_id = link.id
        db.commit()
    topology = client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()
    link = next(l for l in topology["links"] if l["id"] == link_id)
    assert link["discovery_status"] == "inferred" and link["destination_interface_name"] is None
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    issue = next(i for i in report["issues"] if i["subject"].startswith("observed-port:"))
    assert issue["certainty"] == "suspected" and issue["confidence"] == 0.65
    assert issue["fixes"][0]["change_type"] == "access_vlan"
    assert "before claiming" in issue["expected_outcome"]


def test_trunk_configuration_comparison_and_edit_preserves_observations(client, auth):
    network = _scenario(client, auth, "loop")
    with SessionLocal() as db:
        link = db.scalar(select(Link).where(Link.network_id == network["id"], Link.kind == "lab").order_by(Link.id.desc()))
        link.destination_interface.native_vlan = 99
        interface_id = link.source_interface_id
        interface = link.source_interface
        payload = {"name": interface.name, "status": interface.status, "mode": interface.mode}
        db.commit()
    response = client.put(f"/api/interfaces/{interface_id}", headers=auth, json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["speed_mbps"] == 1000 and response.json()["stp_state"] == "forwarding"
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    assert any(i["rule_id"] == "VLAN003" for i in report["issues"])
    response = client.put(f"/api/networks/{network['id']}", headers=auth, json={"name": "Renamed sample"})
    assert response.status_code == 200 and response.json()["environment"] == "virtual"


def test_partial_discovery_does_not_claim_failed_or_verified_flows(client, auth):
    network = _scenario(client, auth, "healthy")
    with SessionLocal() as db:
        row = db.get(Network, network["id"])
        row.source, row.environment = "discovery", "real"
        host = db.scalar(select(Device).where(Device.network_id == row.id, Device.name == "HR-PC"))
        link = db.scalar(select(Link).where(Link.destination_device_id == host.id))
        link.destination_interface_id = None
        db.commit()
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    assert report["analysis_complete"] is False
    assert report["unknown_flow_count"] > 0
    assert report["failing_flow_count"] == 0
    assert report["status"] == "incomplete"
    assert any(flow["ok"] is None and flow["status"] == "unknown" for flow in report["flows"])


def test_loop_candidate_validation_uses_changed_model_and_keeps_baseline(client, auth):
    network = _scenario(client, auth, "loop")
    before = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    loop = next(i for i in before["issues"] if i["rule_id"] == "L2001")
    kinds = [f["change_type"] for f in loop["fixes"]]
    assert kinds[0] == "stp_root" and "interface_status" in kinds  # spanning tree first, shutdown as a fallback
    stp = loop["fixes"][0]
    assert stp["verification"]["verdict"] == "recommended", stp["verification"]
    assert any("spanning-tree vlan" in c for c in stp["verification"]["commands"])
    shutdown = next(f for f in loop["fixes"] if f["change_type"] == "interface_status")
    change = client.post("/api/changes", headers=auth, json={k: shutdown[k] for k in ("device_id", "interface_id", "change_type", "parameters")}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert any(i["rule_id"] == "L2001" for i in assessment["resolved_issues"])
    assert not any(i["rule_id"] == "L2001" for i in assessment["findings"])
    # The shutdown still has a model warning; the system must not promise a
    # globally safe correction merely because the cycle has disappeared.
    assert any(i["rule_id"] == "LINK001" for i in assessment["findings"])
    after = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    assert after["issue_count"] == before["issue_count"]


def test_unconfigured_lab_flag_prevents_healthy_claim_for_virtual_layout(client, auth):
    network = _scenario(client, auth, "healthy")
    with SessionLocal() as db:
        row = db.get(Network, network["id"])
        row.metadata_json = {**row.metadata_json, "configuration_incomplete": True}
        db.commit()
    report = client.post(f"/api/networks/{network['id']}/analyze", headers=auth).json()
    analysis = report["snapshot"]["analysis"]
    assert analysis["issue_count"] == 0
    assert analysis["analysis_complete"] is False and analysis["status"] == "incomplete"




def test_incomplete_configuration_guard_blocks_false_pass_and_model_apply(client, auth):
    network = _scenario(client, auth, "vlan")
    report = client.get(f"/api/networks/{network['id']}/health-check", headers=auth).json()
    fix = next(i for i in report["issues"] if i["rule_id"] == "VLAN001")["fixes"][0]
    change = client.post("/api/changes", headers=auth, json={k: fix[k] for k in ("device_id", "interface_id", "change_type", "parameters")}).json()
    ordinary = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert ordinary["validation_result"] == "PASS" and ordinary["recommendation"] == "DEPLOY"
    with SessionLocal() as db:
        row = db.get(Network, network["id"])
        row.metadata_json = {**row.metadata_json, "configuration_incomplete": True}
        db.commit()
    incomplete = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert incomplete["validation_result"] == "INCOMPLETE"
    assert incomplete["recommendation"] == "DO_NOT_DEPLOY"
    assert "configuration evidence is missing" in incomplete["explanation"]
    response = approve_and_apply(client, auth, change["id"])
    assert response.status_code == 409
    with SessionLocal() as db:
        assert db.get(Interface, fix["interface_id"]).vlan_id == 10
