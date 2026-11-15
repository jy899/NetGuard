"""Credential-free discovery with optional authentication (plan criteria 1-10)."""
from backend.tests.helpers import approve, approve_and_apply  # noqa: E402
import json

import pytest
from sqlalchemy import select

from backend.database.session import SessionLocal
from backend.models import AnalysisRecord, CredentialAssignment, Device, Interface, Link, Network
from backend.models.credential_profile import CredentialProfile

SECRET = "Distinctive-Secret-7731"


def scan(client, auth, target="172.16.10.0/24", **extra):
    response = client.post("/api/discovery/scan", headers=auth,
                           json={"target": target, "authorized_scope": True, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def cables(links):
    """Links resting on layer-1/2 evidence (logical "how it is reached" links are drawn but are not cables)."""
    return [l for l in links if l["evidence_grade"] != "Logical"]


def by_name(result):
    return {row["name"]: row for row in result["devices"]}


def authenticate(client, auth, nid, ids, method="ssh", username="admin", password="admin", **extra):
    # These tests read devices one step at a time; the continued crawl has its own test below.
    extra.setdefault("continue_discovery", False)
    response = client.post(f"/api/discovery/{nid}/authenticate", headers=auth,
                           json={"device_ids": ids, "method": method, "username": username, "password": password, **extra})
    assert response.status_code == 200, response.text
    return response.json()


def office_policy(client, auth, result):
    """The office's required flows and approved VLAN plan: organisational input an administrator declares after a
    scan (discovery never invents them)."""
    from backend.tests.fixtures import office_sample
    ids = {row["ip"]: row["id"] for row in result["devices"]}
    for name, src, dst, protocol, port, criticality in office_sample.AUTOMATIC_FLOWS:
        if src in ids and dst in ids:
            created = client.post(f"/api/networks/{result['network_id']}/intents", headers=auth, json={
                "name": name, "source_device_id": ids[src], "destination_device_id": ids[dst], "protocol": protocol,
                "port": port, "expected_action": "allow", "criticality": criticality})
            assert created.status_code == 201, created.text
    with SessionLocal() as db:
        network = db.get(Network, result["network_id"])
        network.metadata_json = {**network.metadata_json, "approved_vlan_plan": {
            "endpoint_data_vlan": 20, "source": "Supplied office VLAN plan (an organisational requirement)"}}
        db.commit()


def health(client, auth, nid):
    response = client.get(f"/api/networks/{nid}/health-check", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def full_read(client, auth, result):
    ids = [r["device_id"] for r in result["credential_requests"] if "ssh" in r["methods"]]
    return authenticate(client, auth, result["network_id"], ids)["result"]


def test_credential_free_scan_identifies_devices_without_inventing_cables(client, auth):
    result = scan(client, auth)
    assert result["network"]["metadata_json"]["method"] == "smart" and result["live_device_contact"] is True
    assert len(result["devices"]) == 12 and cables(result["links"]) == []
    # Every device on the scanned segment is still placed: a Logical link to the subnet's gateway, never a cable.
    assert result["links"] and all(l["kind"] == "segment" and l["evidence_grade"] == "Logical" for l in result["links"])
    counts = result["report"]["counts"]
    assert counts == {"full": 0, "partial": 6, "auth_required": 5, "auth_failed": 0, "unverified": 1, "unreachable": 1}
    assert [r["name"] for r in result["credential_requests"]] == ["CORE-SW-01", "ACC-SW-01", "ACC-SW-02", "172.16.10.1", "AP-LOBBY"]
    firewall = by_name(result)["172.16.10.1"]
    assert firewall["model"] == "FortiGate 60F" and firewall["classification"]["completeness"] == "partial"
    assert by_name(result)["172.16.10.87"]["classification"]["primary"] == "unverified"
    assert result["report"]["unreachable"][0]["ip"] == "172.16.10.25"
    assert [stage["id"] for stage in result["timeline"]] == ["arp", "icmp", "names", "services", "passive-lldp", "snmpv3", "traceroute", "correlate"]
    # Every finding is labelled as simulated sample data.
    assert all(p["simulated"] is False for row in result["devices"] for p in row["provenance"])
    report = health(client, auth, result["network_id"])
    assert report["status"] == "incomplete" and report["issue_count"] == 0
    assert all(flow["status"] == "unknown" for flow in report["flows"])


def test_scan_requires_authorization_and_a_bounded_range(client, auth):
    for body in ({"target": "172.16.10.0/24"}, {"target": "172.16.0.0/21", "authorized_scope": True}):
        response = client.post("/api/discovery/scan", headers=auth, json=body)
        assert response.status_code == 422, response.text


def test_other_targets_translate_every_observation(client, auth):
    result = scan(client, auth, target="10.50.8.0/24")
    assert len(result["devices"]) == 12 and result["report"]["unreachable"][0]["ip"] == "10.50.8.25"
    with SessionLocal() as db:
        observations = db.get(Network, result["network_id"]).metadata_json["observations"]
    assert not any("172.16.10." in json.dumps(o) for o in observations)
    full = full_read(client, auth, result)
    assert full["report"]["connections"] == {"confirmed": 7, "inferred": 4, "logical": 0, "unknown": 0, "unverified_links": 0, "manual": 0}


def test_core_read_alone_confirms_uplinks_and_only_locates_hidden_endpoints(client, auth):
    result = scan(client, auth)
    core = by_name(result)["CORE-SW-01"]["id"]
    after = authenticate(client, auth, result["network_id"], [core])["result"]
    assert after["report"]["connections"]["confirmed"] == 3 and after["report"]["connections"]["inferred"] == 1
    devices = by_name(after)
    assert "FGT-HQ" in devices  # named from CORE-SW-01's LLDP sysName, without reading the firewall
    assert any("CORE-SW-01 port 25 towards ACC-SW-01" in note for note in devices["PC-FIN-01"]["location_notes"])
    assert not any(link["destination_device_name"] == "PC-FIN-01" or link["source_device_name"] == "PC-FIN-01" for link in cables(after["links"]))
    behind = next(l for l in after["links"] if "PC-FIN-01" in (l["source_device_name"], l["destination_device_name"]))
    assert behind["evidence_grade"] == "Logical" and "ACC-SW-01" in (behind["source_device_name"], behind["destination_device_name"])
    acc = next(r for r in after["credential_requests"] if r["name"] == "ACC-SW-01")
    assert any("3 device(s) were located behind this switch (CORE-SW-01 port 25)" in g["text"] for g in acc["gains"])


def test_firewall_and_switch_reads_give_the_evidenced_topology_and_withdraw_the_ap_request(client, auth):
    result = full_read(client, auth, scan(client, auth))
    assert result["report"]["counts"]["full"] == 8 and result["report"]["counts"]["partial"] == 3
    assert result["report"]["connections"] == {"confirmed": 7, "inferred": 4, "logical": 0, "unknown": 0, "unverified_links": 0, "manual": 0}
    assert set(by_name(result)) == {"FGT-HQ", "CORE-SW-01", "ACC-SW-01", "ACC-SW-02", "SRV-FILE-01", "PC-FIN-01", "PC-HR-02",
                                    "PRN-01", "CAM-LOBBY-01", "PHONE-RECEPTION-01", "AP-LOBBY", "172.16.10.87"}
    ap = by_name(result)["AP-LOBBY"]["classification"]
    assert ap["auth"] == "not_needed" and "ACC-SW-02" in ap["note"]
    assert result["credential_requests"] == [] and result["session"]["state"] == "complete"
    inferred = [p for p in result["report"]["port_pairs"] if p["status"] == "inferred"]
    assert all(p["destination_port"] == "Unknown Port" for p in inferred)
    assert {p["destination"] for p in inferred} == {"SRV-FILE-01", "PC-FIN-01", "PC-HR-02", "172.16.10.87"}


def _model(nid):
    with SessionLocal() as db:
        devices = {d.id: d for d in db.scalars(select(Device).where(Device.network_id == nid))}
        ip = {d.id: d.management_ip.rsplit(".", 1)[1] for d in devices.values()}
        ports = {}
        for row in db.scalars(select(Interface).where(Interface.device_id.in_(devices))):
            if devices[row.device_id].device_type == "switch" and row.mode:
                ports[(ip[row.device_id], row.name)] = (row.mode, row.vlan_id, row.allowed_vlans, row.native_vlan, row.stp_state, row.speed_mbps)
        cables = set()
        for link in db.scalars(select(Link).where(Link.network_id == nid)):
            ends = []
            for did, iid in ((link.source_device_id, link.source_interface_id), (link.destination_device_id, link.destination_interface_id)):
                iface = db.get(Interface, iid)
                ends.append((ip[did], iface.name if devices[did].device_type in ("switch", "firewall") and devices[did].name != "AP-LOBBY" else "host"))
            cables.add(frozenset(ends))
        names = {ip[d.id]: d.name for d in devices.values()}
        types = {ip[d.id]: d.device_type for d in devices.values()}
        fw = next(d for d in devices.values() if d.device_type == "firewall")
        lan = db.scalar(select(Interface).where(Interface.device_id == fw.id, Interface.name == "internal1"))
        return names, types, ports, cables, (lan.ip_address, lan.subnet_mask)


def _apply_recommended(client, auth, nid):
    issue = health(client, auth, nid)["issues"][0]
    fix = issue["fixes"][issue["recommended_fix"]]
    change = client.post("/api/changes", headers=auth, json={key: fix[key] for key in ("device_id", "interface_id", "change_type", "parameters")})
    assert approve_and_apply(client, auth, change.json()["id"]).status_code == 200




def test_switches_without_the_firewall_report_one_suspected_vlan_fault(client, auth):
    result = scan(client, auth)
    office_policy(client, auth, result)
    ids = [r["device_id"] for r in result["credential_requests"] if r["type"] == "switch" and "ssh" in r["methods"]]
    authenticate(client, auth, result["network_id"], ids)
    report = health(client, auth, result["network_id"])
    assert [i["rule_id"] for i in report["issues"]] == ["VLAN001"] and report["issues"][0]["certainty"] == "suspected"
    assert report["status"] != "healthy"
    assert any("DHCP leases" in gap["next_step"] and "FGT-HQ" in gap["next_step"] for gap in report["coverage_gaps"])


def test_skip_for_now_leads_to_one_confirmation_and_skip_all_to_none(client, auth):
    result = scan(client, auth)
    nid = result["network_id"]
    while result["credential_requests"]:
        result = client.post(f"/api/discovery/{nid}/skip", headers=auth,
                             json={"device_ids": [result["credential_requests"][0]["device_id"]]}).json()
    assert result["session"]["confirmation"] == "pending" and len(result["confirmation_candidates"]) == 5
    result = client.post(f"/api/discovery/{nid}/confirmation", headers=auth, json={"action": "shown"}).json()
    assert result["session"]["state"] == "complete" and result["confirmation_candidates"] == []
    result = client.post(f"/api/discovery/{nid}/confirmation", headers=auth, json={"action": "continue"}).json()
    assert result["credential_requests"] == [] and result["session"]["state"] == "complete"
    other = scan(client, auth)
    other = client.post(f"/api/discovery/{other["network_id"]}/skip", headers=auth, json={"all": True}).json()
    assert other["session"]["skip_all"] and other["session"]["confirmation"] == "not_needed"
    assert other["credential_requests"] == [] and other["confirmation_candidates"] == []
    # Manual authentication stays possible after the session ends; it is user-initiated, not a prompt.
    core = by_name(other)["CORE-SW-01"]["id"]
    assert authenticate(client, auth, other["network_id"], [core])["outcomes"][0]["ok"]


@pytest.mark.parametrize("reuse,failed", [(False, 1), (True, 4)])
def test_wrong_password_marks_failed_without_collecting_or_retrying(client, auth, reuse, failed):
    result = scan(client, auth)
    request = result["credential_requests"][0]
    ids = [request["device_id"]] + ([c["device_id"] for c in request["reuse_candidates"] if c["preselected"]] if reuse else [])
    outcome = authenticate(client, auth, result["network_id"], ids, password=SECRET)
    assert sum(not o["ok"] for o in outcome["outcomes"]) == failed
    after = outcome["result"]
    assert after["report"]["counts"]["auth_failed"] == failed and cables(after["links"]) == []
    assert by_name(after)["CORE-SW-01"]["classification"]["primary"] == "auth_failed"
    assert "CORE-SW-01" not in [r["name"] for r in after["credential_requests"]]  # not prompted again automatically
    assert SECRET not in json.dumps(outcome)


def test_secrets_are_discarded_unless_remembered_and_never_exposed(client, auth):
    result = scan(client, auth)
    nid = result["network_id"]
    core = by_name(result)["CORE-SW-01"]["id"]
    authenticate(client, auth, nid, [core], password="admin")
    with SessionLocal() as db:
        assert db.scalars(select(CredentialAssignment).where(CredentialAssignment.network_id == nid)).first() is None
        assert db.scalars(select(CredentialProfile)).first() is None
    acc = by_name(result)["ACC-SW-01"]["id"]
    saved = authenticate(client, auth, nid, [acc], method="snmpv3", password="adminadmin", priv_password="adminadmin", remember=True)
    assert saved["profile"]["method"] == "snmpv3" and saved["profile"]["has_priv_password"]
    with SessionLocal() as db:
        profile = db.get(CredentialProfile, saved["profile"]["id"])
        assert profile.password_enc and profile.priv_password_enc and "adminadmin" not in profile.password_enc
    # A name clash gets a numeric suffix instead of failing an authentication that already succeeded.
    again = authenticate(client, auth, nid, [acc], method="snmpv3", password="adminadmin", priv_password="adminadmin", remember=True)
    assert again["profile"]["name"] == saved["profile"]["name"] + " 2"
    # Editing or deleting the profile never touches the smart topology.
    links_before = client.get(f"/api/discovery/{nid}", headers=auth).json()["links"]
    assert client.delete(f"/api/credential-profiles/{saved['profile']['id']}", headers=auth).status_code == 204
    assert client.get(f"/api/discovery/{nid}", headers=auth).json()["links"] == links_before
    # Legacy assignment endpoints refuse smart networks.
    assert client.post("/api/credential-profiles/assign", headers=auth, json={"network_id": nid, "scope": "all", "username": "admin", "password": "admin"}).status_code == 422
    assert client.post("/api/credential-profiles/test", headers=auth, json={"network_id": nid}).status_code == 422
    authenticate(client, auth, nid, [by_name(result)["ACC-SW-02"]["id"]], password=SECRET)
    exposed = [client.get(f"/api/discovery/{nid}", headers=auth).text, client.get("/api/credential-profiles", headers=auth).text,
               client.get(f"/api/networks/{nid}/topology", headers=auth).text, client.get(f"/api/networks/{nid}/health-check", headers=auth).text,
               client.post(f"/api/networks/{nid}/reports", headers=auth).text]
    with SessionLocal() as db:
        exposed += [json.dumps(row.snapshot) + json.dumps(row.summary) for row in db.scalars(select(AnalysisRecord).where(AnalysisRecord.network_id == nid))]
    assert not any(SECRET in text or "adminadmin" in text for text in exposed)


def test_snmpv3_needs_authpriv_passphrases(client, auth):
    result = scan(client, auth)
    core = by_name(result)["CORE-SW-01"]["id"]
    response = client.post(f"/api/discovery/{result['network_id']}/authenticate", headers=auth,
                           json={"device_ids": [core], "method": "snmpv3", "username": "admin", "password": "admin"})
    assert response.status_code == 422


def test_save_without_moving_keeps_auto_layout_and_moved_devices_stay_put(client, auth):
    result = scan(client, auth)
    nid = result["network_id"]
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    positions = [{"device_id": d["id"], "x": d["x_position"], "y": d["y_position"]} for d in topo["devices"]]
    assert client.put(f"/api/networks/{nid}/topology/positions", headers=auth, json={"positions": positions}).status_code == 200
    printer = next(d for d in topo["devices"] if d["name"] == "PRN-01")
    moved = [{**p, "x": 4321, "y": 1234} if p["device_id"] == printer["id"] else p for p in positions]
    client.put(f"/api/networks/{nid}/topology/positions", headers=auth, json={"positions": moved})
    full_read(client, auth, result)
    after = {d["name"]: d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"]}
    assert (after["PRN-01"]["x_position"], after["PRN-01"]["y_position"]) == (4321, 1234)
    before = {d["name"]: d for d in topo["devices"]}
    assert (after["SRV-FILE-01"]["x_position"], after["SRV-FILE-01"]["y_position"]) != (before["SRV-FILE-01"]["x_position"], before["SRV-FILE-01"]["y_position"])
    assert after["FGT-HQ"]["y_position"] < after["CORE-SW-01"]["y_position"] < after["ACC-SW-01"]["y_position"] < after["PC-FIN-01"]["y_position"]


def test_refresh_and_reviewed_corrections_survive(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    _apply_recommended(client, auth, nid)
    assert client.post(f"/api/discovery/{nid}/refresh", headers=auth, json={}).status_code == 200
    assert health(client, auth, nid)["status"] == "healthy"


def test_fusion_never_creates_cables_from_ip_level_or_transit_evidence(client, auth):
    from backend.services.discovery import fusion
    from backend.services.discovery.engine import observation
    result = scan(client, auth)
    nid = result["network_id"]
    devices = by_name(result)
    core, srv, pc = devices["CORE-SW-01"], devices["SRV-FILE-01"], devices["PC-FIN-01"]
    with SessionLocal() as db:
        network = db.get(Network, nid)
        meta = dict(network.metadata_json)
        crafted = list(meta["observations"]) + [
            # Layer-3 and addressing facts only: none of these is cable evidence.
            observation("traceroute", "172.16.10.1", {"gateway": True}, "hop 1"),
            observation("dhcp-leases", "172.16.10.1", {"leases": [{"ip": srv["ip"], "mac": srv["mac"], "mask": "255.255.255.0", "router": "172.16.10.1"}]},
                        "leases", authenticated=True, method="ssh", observed_by="172.16.10.1"),
            # A read switch whose MAC table shows hosts only on a shared port (two MACs) and no LLDP rows.
            observation("mac-table", core["ip"], {"rows": [{"port": "9", "mac": srv["mac"], "vlan": 20},
                                                           {"port": "9", "mac": pc["mac"], "vlan": 20}]},
                        "mac", authenticated=True, method="ssh", observed_by=core["ip"]),
        ]
        network.metadata_json = {**meta, "observations": crafted}
        fusion.fuse(db, network)
        db.commit()
        links = list(db.scalars(select(Link).where(Link.network_id == nid)))
        # Nothing at layer 3 becomes a cable. The two MACs on shared port 9 are attached to that port as Inferred,
        # with the evidence that an unmanaged switch, hub or access point is probably between.
        shared = [l for l in links if l.evidence_grade != "Logical"]
        assert {l.kind for l in shared} == {"mac"} and len(shared) == 2
        assert all(l._observations()["shared_port"] and "unmanaged switch" in l.evidence[0] for l in shared)
        # Add an LLDP uplink on port 25; MACs learned there are transit and must only produce location notes.
        meta = dict(network.metadata_json)
        meta["observations"] = crafted + [
            observation("lldp-table", core["ip"], {"rows": [{"local_port": "25", "chassis_mac": devices["ACC-SW-01"]["mac"],
                                                             "mgmt_ip": devices["ACC-SW-01"]["ip"], "sys_name": "ACC-SW-01",
                                                             "port_id": "25", "sys_descr": None, "model": None, "role": None}]},
                        "lldp", authenticated=True, method="ssh", observed_by=core["ip"]),
            observation("mac-table", core["ip"], {"rows": [{"port": "25", "mac": pc["mac"], "vlan": 20}]},
                        "mac", authenticated=True, method="ssh", observed_by=core["ip"]),
        ]
        network.metadata_json = meta
        fusion.fuse(db, network)
        db.commit()
        links = [l for l in db.scalars(select(Link).where(Link.network_id == nid)) if l.evidence_grade != "Logical"]
        assert ("lldp", {core["id"], devices["ACC-SW-01"]["id"]}) in [(link.kind, {link.source_device_id, link.destination_device_id}) for link in links]
        assert not any(pc["id"] in (l.source_device_id, l.destination_device_id) and l.kind != "mac" for l in links)
        facts = db.get(Network, nid).metadata_json["discovery"][str(pc["id"])]
        assert any("towards ACC-SW-01" in note for note in facts["location_notes"])


def test_failed_profile_save_keeps_the_successful_authentication(client, auth, monkeypatch):
    result = scan(client, auth)
    core = by_name(result)["CORE-SW-01"]["id"]

    def broken(self, value):
        raise RuntimeError("vault unavailable")
    monkeypatch.setattr(CredentialProfile, "password", property(lambda self: None, broken))
    outcome = authenticate(client, auth, result["network_id"], [core], remember=True)
    assert outcome["outcomes"][0]["ok"] and outcome["profile"] is None and "could not be saved" in outcome["profile_note"]
    after = client.get(f"/api/discovery/{result['network_id']}", headers=auth).json()
    assert by_name(after)["CORE-SW-01"]["classification"]["auth"] == "success"
    assert after["report"]["connections"]["confirmed"] == 3


def test_reviewed_endpoint_nic_rename_survives_refresh(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    server = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "SRV-FILE-01")
    nic = next(i for i in server["interfaces"] if i["name"] == "Unknown Port")
    assert client.put(f"/api/interfaces/{nic['id']}", headers=auth, json={"name": "ens192"}).status_code == 200
    assert client.post(f"/api/discovery/{nid}/refresh", headers=auth, json={}).status_code == 200
    server = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "SRV-FILE-01")
    assert [i["name"] for i in server["interfaces"]] == ["ens192"]
    link = next(l for l in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["links"] if l["destination_device_name"] == "SRV-FILE-01")
    assert link["destination_interface_name"] == "ens192"
    report = health(client, auth, nid)
    assert not any(f["status"] == "unknown" for f in report["flows"])


def test_location_notes_never_ask_to_authenticate_an_already_read_switch(client, auth):
    result = scan(client, auth)
    devices = by_name(result)
    after = authenticate(client, auth, result["network_id"], [devices["CORE-SW-01"]["id"], devices["ACC-SW-02"]["id"]])["result"]
    notes = by_name(after)["PC-FIN-01"]["location_notes"]
    assert notes and all("authenticate ACC-SW-01" in note for note in notes)


def test_failed_retry_keeps_an_earlier_successful_read(client, auth):
    result = scan(client, auth)
    core = by_name(result)["CORE-SW-01"]["id"]
    authenticate(client, auth, result["network_id"], [core])
    retry = authenticate(client, auth, result["network_id"], [core], password=SECRET)
    assert not retry["outcomes"][0]["ok"] and "earlier successful read" in retry["outcomes"][0]["detail"]
    after = retry["result"]
    assert by_name(after)["CORE-SW-01"]["classification"]["auth"] == "success" and after["report"]["connections"]["confirmed"] == 3
    with SessionLocal() as db:
        records = list(db.scalars(select(AnalysisRecord).where(AnalysisRecord.network_id == result["network_id"])))
    for record in records:
        exported = client.get(f"/api/history/{record.id}/export", headers=auth)
        assert exported.status_code == 200 and SECRET not in exported.text


def test_firewall_lan_rename_keeps_one_address(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    fw = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "FGT-HQ")
    lan = next(i for i in fw["interfaces"] if i["name"] == "internal1")
    assert client.put(f"/api/interfaces/{lan['id']}", headers=auth, json={"name": "lan"}).status_code == 200
    assert client.post(f"/api/discovery/{nid}/refresh", headers=auth, json={}).status_code == 200
    fw = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "FGT-HQ")
    assert [(i["name"], i["ip_address"]) for i in fw["interfaces"]] == [("lan", "172.16.10.1")]
    assert "IP003" not in {issue["rule_id"] for issue in health(client, auth, nid)["issues"]}


def test_manual_identity_survives_fusion(client, auth):
    result = scan(client, auth)
    nid = result["network_id"]
    unknown = by_name(result)["172.16.10.87"]
    response = client.put(f"/api/devices/{unknown['id']}", headers=auth, json={"name": "GUEST-LAPTOP", "device_type": "pc", "vendor": "Dell", "model": "Latitude 5440"})
    assert response.status_code == 200, response.text
    after = authenticate(client, auth, nid, [by_name(result)["CORE-SW-01"]["id"]])["result"]
    device = by_name(after)["GUEST-LAPTOP"]
    assert device["classification"]["primary"] != "unverified" and device["identity_unknown"] is False


def test_model_edits_refresh_classification_without_resurrecting_links(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    ap_link = next(l for l in cables(result["links"]) if "AP-LOBBY" in (l["source_device_name"], l["destination_device_name"]))
    assert client.delete(f"/api/links/{ap_link['id']}", headers=auth).status_code == 204
    after = client.get(f"/api/discovery/{nid}", headers=auth).json()
    ap = by_name(after)["AP-LOBBY"]["classification"]
    assert ap["auth"] == "required" and "Connection" in ap["missing"]
    assert any(r["name"] == "AP-LOBBY" for r in after["available_authentications"])
    assert not any("AP-LOBBY" in (l["source_device_name"], l["destination_device_name"]) for l in cables(after["links"]))


def test_access_point_console_and_snmpv3_protocols(client, auth):
    result = scan(client, auth)
    nid, ap = result["network_id"], by_name(result)["AP-LOBBY"]["id"]
    wrong = authenticate(client, auth, nid, [ap], method="snmpv3", password="adminadmin", priv_password="adminadmin",
                         snmp_auth_protocol="SHA-512", snmp_priv_protocol="AES-256")
    assert not wrong["outcomes"][0]["ok"]
    saved = authenticate(client, auth, nid, [ap], method="snmpv3", password="adminadmin", priv_password="adminadmin", remember=True)
    assert saved["outcomes"][0]["ok"] and saved["profile"]["snmp_auth_protocol"] == "SHA-256" and saved["profile"]["snmp_priv_protocol"] == "AES-128"


def test_snmpv3_profile_secrets_are_validated_and_never_migrated(client, auth):
    created = client.post("/api/credential-profiles", headers=auth, json={"name": "SSH short", "username": "admin", "password": "admin"})
    assert created.status_code == 201
    pid = created.json()["id"]
    switched = client.put(f"/api/credential-profiles/{pid}", headers=auth,
                          json={"name": "SSH short", "username": "admin", "method": "snmpv3", "priv_password": "privpriv"})
    assert switched.status_code == 422  # the retained 5-character secret is too short for SNMPv3
    snmp = client.post("/api/credential-profiles", headers=auth, json={"name": "SNMP lab", "username": "admin", "password": "labpass123",
                                                                       "method": "snmpv3", "priv_password": "privpriv"})
    assert snmp.status_code == 201
    with SessionLocal() as db:
        assert db.get(CredentialProfile, snmp.json()["id"]).password == "labpass123"
        assert db.get(CredentialProfile, snmp.json()["id"]).password_enc.startswith("enc2:")  # AES-GCM vault



def test_deleted_devices_leave_discovery_coverage(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    ap = by_name(result)["AP-LOBBY"]["id"]
    ap_link = next(l for l in cables(result["links"]) if "AP-LOBBY" in (l["source_device_name"], l["destination_device_name"]))
    client.delete(f"/api/links/{ap_link['id']}", headers=auth)
    assert client.delete(f"/api/devices/{ap}", headers=auth).status_code == 204
    with SessionLocal() as db:
        meta = db.get(Network, nid).metadata_json
    assert str(ap) not in meta["discovery"] and ap not in meta["discovery_can_login"]
    assert meta["configuration_incomplete"] is False


def test_missing_interface_reference_is_a_gap_and_reported_unverified(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    _apply_recommended(client, auth, nid)
    acc2 = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "ACC-SW-02")
    port = next(i for i in acc2["interfaces"] if i["name"] == "3")
    assert client.delete(f"/api/interfaces/{port['id']}", headers=auth).status_code == 204
    report = health(client, auth, nid)
    assert report["status"] != "healthy" and any(g["code"] == "endpoint-port" for g in report["coverage_gaps"])
    after = client.get(f"/api/discovery/{nid}", headers=auth).json()
    assert after["report"]["connections"]["confirmed"] == 6 and after["report"]["connections"]["unverified_links"] == 1
    assert any(p["status"] == "unverified" for p in after["report"]["port_pairs"])


def test_manufacturer_comes_from_the_mac_vendor_and_firewall_needs_both_tables(client, auth):
    result = scan(client, auth)
    devices = by_name(result)
    assert devices["SRV-FILE-01"]["vendor"] == "VMware, Inc" and devices["PC-FIN-01"]["vendor"] == "HP Inc"
    assert devices["CORE-SW-01"]["vendor"] == "HPE Aruba"
    fw = by_name(full_read(client, auth, result))["FGT-HQ"]
    assert fw["classification"]["primary"] == "full"
    assert any(p["technique"] == "arp-table" or "ARP" in p["technique"] for p in fw["provenance"])


def test_reused_interface_ids_never_cross_devices(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    guest = next(d for d in topo["devices"] if d["name"] == "172.16.10.87")
    newest = max((i for d in topo["devices"] for i in d["interfaces"]), key=lambda i: i["id"])
    unknown = next(i for i in guest["interfaces"] if i["name"] == "Unknown Port")
    assert client.delete(f"/api/interfaces/{unknown['id']}", headers=auth).status_code == 204
    fw = next(d for d in topo["devices"] if d["name"] == "FGT-HQ")
    created = client.post(f"/api/devices/{fw['id']}/interfaces", headers=auth, json={"name": "dmz"}).json()
    assert client.post(f"/api/discovery/{nid}/refresh", headers=auth, json={}).status_code == 200
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    owner = {i["id"]: d["id"] for d in topo["devices"] for i in d["interfaces"]}
    for link in topo["links"]:
        for side in ("source", "destination"):
            iid = link[f"{side}_interface_id"]
            assert iid is None or owner[iid] == link[f"{side}_device_id"], (link, created, newest)
    fw = next(d for d in topo["devices"] if d["name"] == "FGT-HQ")
    assert next(i for i in fw["interfaces"] if i["name"] == "dmz")["ip_address"] is None


def test_access_point_needs_a_valid_confirmed_attachment(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    acc2 = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "ACC-SW-02")
    port = next(i for i in acc2["interfaces"] if i["name"] == "3")
    assert client.delete(f"/api/interfaces/{port['id']}", headers=auth).status_code == 204
    ap = by_name(client.get(f"/api/discovery/{nid}", headers=auth).json())["AP-LOBBY"]["classification"]
    assert ap["primary"] != "full" and ap["auth"] == "required" and not ap["note"]


def test_dhcp_addressing_does_not_depend_on_cable_discovery(client, auth):
    result = scan(client, auth)
    office_policy(client, auth, result)
    devices = by_name(result)
    after = authenticate(client, auth, result["network_id"], [devices["CORE-SW-01"]["id"], devices["172.16.10.1"]["id"]])["result"]
    pc = by_name(after)["PC-FIN-01"]["classification"]
    assert "Addressing (mask and gateway)" not in pc["missing"] and "Connection" in pc["missing"]
    report = health(client, auth, result["network_id"])
    assert not any("DHCP leases" in gap["next_step"] for gap in report["coverage_gaps"])
    assert any(gap["code"] == "endpoint-connection" for gap in report["coverage_gaps"])


def test_same_device_id_reuse_never_inherits_the_deleted_port(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    guest = next(d for d in client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"] if d["name"] == "172.16.10.87")
    old = next(i for i in guest["interfaces"] if i["name"] == "Unknown Port")
    assert client.delete(f"/api/interfaces/{old['id']}", headers=auth).status_code == 204
    new = client.post(f"/api/devices/{guest['id']}/interfaces", headers=auth, json={"name": "eth9"}).json()
    assert client.post(f"/api/discovery/{nid}/refresh", headers=auth, json={}).status_code == 200
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    guest = next(d for d in topo["devices"] if d["name"] == "172.16.10.87")
    eth9 = next(i for i in guest["interfaces"] if i["name"] == "eth9")
    assert eth9["id"] == new["id"] and eth9["ip_address"] is None
    link = next(l for l in topo["links"] if l["destination_device_name"] == "172.16.10.87")
    assert link["destination_interface_name"] == "Unknown Port"


def test_interface_less_links_count_as_unconfirmed_connections(client, auth):
    result = scan(client, auth)
    nid = result["network_id"]
    devices = by_name(result)
    created = client.post(f"/api/networks/{nid}/links", headers=auth,
                          json={"source_device_id": devices["CORE-SW-01"]["id"], "destination_device_id": devices["PC-FIN-01"]["id"]})
    assert created.status_code == 201, created.text
    pc = by_name(client.get(f"/api/discovery/{nid}", headers=auth).json())["PC-FIN-01"]["classification"]
    assert "Connection" not in pc["missing"] and "NIC name (port not recorded)" in pc["missing"]


def test_access_point_with_only_an_unconfirmed_attachment_still_needs_confirmation(client, auth):
    result = full_read(client, auth, scan(client, auth))
    nid = result["network_id"]
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    acc2 = next(d for d in topo["devices"] if d["name"] == "ACC-SW-02")
    ap = next(d for d in topo["devices"] if d["name"] == "AP-LOBBY")
    port = next(i for i in acc2["interfaces"] if i["name"] == "3")
    lldp = next(l for l in topo["links"] if "AP-LOBBY" in (l["source_device_name"], l["destination_device_name"]))
    assert client.delete(f"/api/links/{lldp['id']}", headers=auth).status_code == 204
    client.delete(f"/api/interfaces/{port['id']}", headers=auth)
    a = client.post(f"/api/devices/{acc2['id']}/interfaces", headers=auth, json={"name": "4"}).json()
    b_if = next(i for i in ap["interfaces"] if i["name"] == "eth0")
    manual = client.post(f"/api/networks/{nid}/links", headers=auth, json={"source_device_id": acc2["id"], "source_interface_id": a["id"],
                                                                         "destination_device_id": ap["id"], "destination_interface_id": b_if["id"]})
    assert manual.status_code == 201, manual.text
    cls = by_name(client.get(f"/api/discovery/{nid}", headers=auth).json())["AP-LOBBY"]["classification"]
    assert "Confirmed connection" in cls["missing"] and cls["auth"] == "required"
    assert any("LLDP table" in g["text"] for g in cls["gains"])
