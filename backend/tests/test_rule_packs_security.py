"""Rule packs, transparent risk, configuration rollback diffs, RBAC and local-access controls."""

import pytest

from backend.core import vault
from backend.services import config_diff, risk_engine, rules
from backend.tests.helpers import manager_auth

ROUTERS = """hostname R1
interface GigabitEthernet0/0
 ip address 10.0.12.1 255.255.255.252
 ip ospf 1 area 0
 ip ospf hello-interval 5
 duplex half
interface GigabitEthernet0/1
 ip address 10.1.0.1 255.255.255.0
 ip access-group MISSING in
router ospf 1
!
hostname R2
interface GigabitEthernet0/0
 ip address 10.0.12.2 255.255.255.252
 ip ospf 1 area 0
 duplex full
interface GigabitEthernet0/1
 ip address 10.2.0.1 255.255.255.0
router ospf 1
"""
CDP = """R1#show cdp neighbors
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
R2               Gig 0/0           150             R      IOSv      Gig 0/0
"""


def _import(client, auth, configs):
    res = client.post("/api/networks/import", headers=auth, json={"name": "Packs", "configs": configs})
    assert res.status_code == 200, res.text
    return res.json()["network_id"]


def test_catalogue_has_five_packs_and_a_severity_factor_for_every_rule(client, auth):
    catalogue = client.get("/api/rules", headers=auth).json()
    assert {r["pack"] for r in catalogue} == set(rules.PACKS)
    assert all(1 <= r["severity_factor"] <= 4 for r in catalogue)


def test_ospf_timer_duplex_and_undefined_acl_are_detected(client, auth):
    nid = _import(client, auth, ROUTERS + CDP)
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    link = topo["links"][0]
    assert link["kind"] == "cdp" and link["evidence_grade"] == "Inferred"  # one side reported the neighbour
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    found = {i["rule_id"]: i for i in report["issues"]}
    assert {"OSPF003", "PHY004", "ACL004"} <= set(found)
    assert found["OSPF003"]["pack"] == "layer3" and found["PHY004"]["pack"] == "physical"
    assert "MISSING" in found["ACL004"]["message"]


def test_risk_formula_and_bands():
    assert risk_engine.formula(4, 3, 2) == 100 and risk_engine.formula(1, 0, 0) == 4
    assert [risk_engine.level_for(v) for v in (24, 25, 49, 50, 74, 75)] == ["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL"]
    assert risk_engine.intent_impact([{"status": "broken", "criticality": "critical", "impact_type": "service_flow"}]) == 3
    assert risk_engine.intent_impact([{"status": "broken", "criticality": "critical", "impact_type": "connectivity"}]) == 1


def test_rollback_diff_restores_sections_exactly():
    backup = "hostname SW1\ninterface Gi0/1\n switchport access vlan 20\nvlan 20\n name A\nip route 0.0.0.0 0.0.0.0 10.0.0.1\n"
    after = "hostname SW1\ninterface Gi0/1\n switchport access vlan 30\nvlan 20\n name A\nvlan 30\n"
    commands = config_diff.rollback_commands(backup, after)
    assert commands == ["interface Gi0/1", " no switchport access vlan 30", " switchport access vlan 20", " exit",
                        "ip route 0.0.0.0 0.0.0.0 10.0.0.1", "no vlan 30"]
    assert config_diff.equivalent(backup, "Building configuration...\n" + backup + "end\n")


def test_frrouting_configuration_is_imported(client, auth):
    frr = """frr version 8.4
frr defaults traditional
hostname FRR1
interface eth0
 ip address 10.0.12.1/30
 ip ospf area 0
router ospf
 network 10.9.0.0/24 area 0
ip route 0.0.0.0/0 10.0.12.2
"""
    nid = _import(client, auth, frr)
    device = client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"][0]
    assert device["platform"] == "frr" and device["vendor"] == "FRRouting"
    eth0 = device["interfaces"][0]
    assert (eth0["name"], eth0["ip_address"], eth0["subnet_mask"], eth0["ospf_area"]) == ("eth0", "10.0.12.1", "255.255.255.252", 0)
    assert device["static_routes"][0]["destination"] == "0.0.0.0/0"


def test_it_manager_is_read_and_approve_only(client, auth, network):
    manager = manager_auth(client, auth)
    assert client.get("/api/networks", headers=manager).status_code == 200
    assert client.post("/api/networks", headers=manager, json={"name": "x"}).status_code == 403
    assert client.post("/api/discovery/scan", headers=manager, json={"target": "10.0.0.0/30", "authorized_scope": True}).status_code == 403
    assert client.post(f"/api/networks/{network['id']}/reports", headers=manager, json={"title": "Weekly"}).status_code == 201
    assert client.post("/api/auth/revoke-other-sessions", headers=manager).status_code == 200


def test_change_cannot_be_approved_by_engineer_or_after_reanalysis(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    sw1 = next(d for d in client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()["devices"] if d["name"] == "SW1")
    change = client.post("/api/changes", headers=auth, json={"device_id": sw1["id"], "change_type": "vlan_database",
                                                             "parameters": {"action": "add", "vlan_id": 44}}).json()
    assert client.post(f"/api/changes/{change['id']}/submit", headers=auth).status_code == 422  # not validated yet
    client.post(f"/api/changes/{change['id']}/analyze", headers=auth)
    assert client.post(f"/api/changes/{change['id']}/submit", headers=auth).json()["status"] == "pending_approval"
    assert client.post(f"/api/changes/{change['id']}/approve", headers=auth).status_code == 403
    client.post(f"/api/changes/{change['id']}/analyze", headers=auth)  # re-analysis withdraws the submission
    manager = manager_auth(client, auth)
    assert client.post(f"/api/changes/{change['id']}/approve", headers=manager).status_code == 409
    client.post(f"/api/changes/{change['id']}/submit", headers=auth)
    assert client.post(f"/api/changes/{change['id']}/reject", headers=manager, json={}).status_code == 422  # reason needed
    rejected = client.post(f"/api/changes/{change['id']}/reject", headers=manager, json={"note": "Not in this window"}).json()
    assert rejected["status"] == "rejected" and rejected["approval"]["decided_by"] == "manager"


def test_host_header_is_validated(client):
    assert client.get("/api/health", headers={"Host": "attacker.example"}).status_code == 421
    assert client.get("/api/health", headers={"Host": "127.0.0.1:8001"}).status_code == 200


def test_desktop_gate_blocks_browsers_until_web_access_is_enabled(client, monkeypatch):
    from backend.core import access, config

    settings = config.get_settings()
    monkeypatch.setattr(settings.__class__, "desktop_key", property(lambda self: "launch-key"), raising=False)
    try:
        assert client.get("/api/health").status_code == 403
        opened = client.get("/desktop-session?key=launch-key", follow_redirects=False)
        assert opened.status_code == 303 and "netguard_desktop" in opened.headers["set-cookie"]
        assert client.get("/api/health", cookies={"netguard_desktop": "launch-key"}).status_code == 200
        access.write_app_settings(web_access=True)
        client.cookies.clear()
        assert client.get("/api/health").status_code == 200
    finally:
        access.write_app_settings(web_access=False)


def test_vault_uses_aes_gcm_and_reads_legacy_values():
    sealed = vault.encrypt("s3cret")
    assert sealed.startswith("enc2:") and vault.decrypt(sealed) == "s3cret"
    legacy = vault.LEGACY_PREFIX + vault._legacy_fernet().encrypt(b"old").decode()
    assert vault.decrypt(legacy) == "old" and vault.is_legacy(legacy)
    assert vault.decrypt("enc2:not-valid") is None


@pytest.mark.parametrize("fmt, media", [("json", "application/json"), ("html", "text/html"), ("pdf", "application/pdf")])
def test_reports_export_as_json_html_and_pdf(client, auth, fmt, media):
    network = client.post("/api/networks/demo?faulty=true", headers=auth).json()
    record = client.post(f"/api/networks/{network['id']}/reports", headers=auth, json={"title": "Weekly"}).json()
    response = client.get(f"/api/history/{record['id']}/export?format={fmt}", headers=auth)
    assert response.status_code == 200 and response.headers["content-type"].startswith(media)
    if fmt == "pdf":
        assert response.content.startswith(b"%PDF")
    if fmt == "html":
        assert "Findings (highest risk first)" in response.text and "OSPF001" in response.text
    sw1 = next(d for d in client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()["devices"] if d["name"] == "SW1")
    change = client.post("/api/changes", headers=auth, json={"device_id": sw1["id"], "change_type": "vlan_database",
                                                             "parameters": {"action": "add", "vlan_id": 45}}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    exported = client.get(f"/api/assessments/{assessment['id']}/export?format={fmt}", headers=auth)
    assert exported.status_code == 200 and exported.headers["content-type"].startswith(media)


def test_workspace_scope_feeds_the_exposure_factor(client, auth, network):
    scope = client.put(f"/api/networks/{network['id']}/scope", headers=auth,
                       json={"authorised": ["10.0.0.0/16"], "excluded": ["10.0.0.5"], "untrusted": ["10.0.99.0/24"]})
    assert scope.status_code == 200 and scope.json()["excluded"] == ["10.0.0.5/32"]
    assert client.put(f"/api/networks/{network['id']}/scope", headers=auth, json={"untrusted": ["nope"]}).status_code == 422


def test_saving_an_assessment_keeps_the_approval_state(client, auth):
    network = client.post("/api/networks/demo", headers=auth).json()
    sw1 = next(d for d in client.get(f"/api/networks/{network['id']}/topology", headers=auth).json()["devices"] if d["name"] == "SW1")
    change = client.post("/api/changes", headers=auth, json={"device_id": sw1["id"], "change_type": "vlan_database",
                                                             "parameters": {"action": "add", "vlan_id": 46}}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    client.post(f"/api/changes/{change['id']}/submit", headers=auth)
    manager = manager_auth(client, auth)
    assert client.post(f"/api/changes/{change['id']}/approve", headers=manager, json={}).json()["status"] == "approved"
    assert client.post(f"/api/assessments/{assessment['id']}/save", headers=manager).status_code == 200
    assert client.get(f"/api/changes/{change['id']}", headers=auth).json()["status"] == "approved"
    assert client.post(f"/api/changes/{change['id']}/submit", headers=auth).status_code == 409
    security = client.get("/api/account/settings", headers=auth).json()["security"]
    assert security["vault"] == "AES-256-GCM" and security["web_access"] is False


def test_sample_workspaces_from_an_earlier_version_are_removed_and_live_discovery_is_real(client, monkeypatch):
    from backend.database.init_db import init_db
    from backend.database.session import SessionLocal
    from backend.models import Device, Network
    from backend.services.discovery import service

    with SessionLocal() as db:
        legacy = Network(name="Old sample scan", source="simulated-scan", metadata_json={"method": "smart"})
        db.add(legacy)
        db.flush()
        db.add(Device(network_id=legacy.id, name="FGT-HQ", device_type="firewall", x_position=0, y_position=0))
        db.commit()
    init_db()
    with SessionLocal() as db:
        assert db.query(Network).filter(Network.source == "simulated-scan").count() == 0
        assert db.query(Device).filter(Device.name == "FGT-HQ").count() == 0
    monkeypatch.setattr(service, "engine_factory", service.default_engine)
    live = Network(name="Live", source="discovery", metadata_json={"method": "smart", "target": "127.0.0.1/32"})
    assert service._engine(live).__class__.__name__ == "RealDiscoveryEngine"
