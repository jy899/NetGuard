"""EVE-NG-style device interaction: WebSocket CLI terminal (SSH, Telnet console), the production read-only guard,
session recording, web portal detection/fingerprinting and port scans; multi-vendor drivers and parsers."""
import http.server
import json
import threading
import time

import pytest

from backend.collectors import drivers, portals
from backend.services import config_import, terminal_service, vendor_parsers
from backend.tests.fixtures.ios_emulator import Device, SshEmulator, TelnetEmulator

CONFIG = """hostname EDGE1
interface GigabitEthernet0/0
 ip address 127.0.0.1 255.0.0.0
"""


@pytest.fixture(scope="module")
def emulator():
    ssh = SshEmulator(Device("EDGE1", CONFIG, {"show version": "Cisco IOS Software, Version 15.9(3)M4\n"}))
    telnet = TelnetEmulator(Device("LABR1", "hostname LABR1\n", {"show version": "Cisco IOS Software\n"}))
    yield ssh, telnet
    ssh.close()
    telnet.close()


def _device(client, auth, name="EDGE1", ip="127.0.0.1", lab=False, console=None):
    network = client.post("/api/networks", headers=auth, json={"name": f"Terminal {name} {time.time()}"}).json()
    device = client.post(f"/api/networks/{network['id']}/devices", headers=auth,
                         json={"name": name, "device_type": "router", "management_ip": ip}).json()
    if lab or console:
        from backend.database.session import SessionLocal
        from backend.models import Device as DeviceRow

        with SessionLocal() as db:
            row = db.get(DeviceRow, device["id"])
            row.is_lab = lab
            row.access = {"console": console} if console else None
            row.platform = "cisco-ios"
            db.commit()
    return network, device


def _read_until(ws, needle, limit=60):
    seen = ""
    for _ in range(limit):
        message = json.loads(ws.receive_text())
        if message["type"] in ("output", "notice", "ready", "error", "closed"):
            seen += message.get("data") or message.get("message") or ""
        if needle in seen:
            return seen
    raise AssertionError(f"{needle!r} not in {seen!r}")


def test_production_terminal_is_read_only_and_recorded(client, auth, emulator):
    ssh, _ = emulator
    network, device = _device(client, auth)
    session = client.post(f"/api/devices/{device['id']}/terminal", headers=auth, json={
        "transport": "ssh", "port": ssh.port, "username": "netguard", "password": "Lab-Pass1", "mode": "read-only"})
    assert session.status_code == 200, session.text
    body = session.json()
    assert body["mode"] == "read-only" and body["production"] is True and body["ticket"]
    with client.websocket_connect(f"/api/terminal/ws?ticket={body['ticket']}") as ws:
        assert json.loads(ws.receive_text())["type"] == "ready"
        _read_until(ws, "EDGE1#")
        ws.send_text(json.dumps({"type": "input", "data": "show version\r"}))
        assert "Cisco IOS Software" in _read_until(ws, "Cisco IOS Software")
        ws.send_text(json.dumps({"type": "input", "data": "conf t\r"}))
        assert "read-only session on a production device" in _read_until(ws, "read-only session")
        ws.send_text(json.dumps({"type": "input", "data": "\x1b[A"}))  # history recall would bypass the guard
        assert "disabled" in _read_until(ws, "disabled")
    # The ticket is single-use.
    with client.websocket_connect(f"/api/terminal/ws?ticket={body['ticket']}") as ws:
        assert json.loads(ws.receive_text())["type"] == "error"
    for _ in range(50):
        history = client.get(f"/api/history?network_id={network['id']}&kind=terminal", headers=auth)
        rows = [r for r in (history.json() if history.status_code == 200 else []) if r.get("kind") == "terminal"]
        if rows:
            break
        time.sleep(0.1)
    assert rows and rows[0]["summary"]["mode"] == "read-only" and rows[0]["summary"]["blocked"] == 1
    assert "running-config" not in json.dumps(rows[0]["summary"])  # summary only; the transcript is in the snapshot


def test_lab_console_terminal_over_telnet(client, auth, emulator):
    _, telnet = emulator
    _, device = _device(client, auth, name="LABR1", ip=None, lab=True, console=f"telnet://127.0.0.1:{telnet.port}")
    session = client.post(f"/api/devices/{device['id']}/terminal", headers=auth, json={"transport": "auto"}).json()
    assert session["transport"] == "console" and session["mode"] == "full" and session["production"] is False
    with client.websocket_connect(f"/api/terminal/ws?ticket={session['ticket']}") as ws:
        assert json.loads(ws.receive_text())["type"] == "ready"
        ws.send_text(json.dumps({"type": "input", "data": "\r"}))
        _read_until(ws, "LABR1")
        ws.send_text(json.dumps({"type": "input", "data": "show version\r"}))
        assert "Cisco IOS Software" in _read_until(ws, "Cisco IOS Software")


def test_terminal_needs_the_permission_and_credentials(client, auth, emulator):
    from backend.tests.helpers import manager_auth

    _, device = _device(client, auth)
    manager = manager_auth(client, auth)
    assert client.post(f"/api/devices/{device['id']}/terminal", headers=manager, json={}).status_code == 403
    missing = client.post(f"/api/devices/{device['id']}/terminal", headers=auth, json={"transport": "ssh"})
    assert missing.status_code == 422 and "username and password" in missing.text


def test_guard_blocks_configuration_commands_per_platform():
    ios = terminal_service.Guard("cisco-ios", True)
    for typed in ("conf t\r", "configure terminal\r", "write mem\r", "reload\r", "copy run start\r", "show run | redirect flash:x\r"):
        assert ios.feed(typed.encode())[1], typed
        ios.line = ""
    for typed in ("show running-config\r", "show ip interface brief\r", "ping 10.0.0.1\r"):
        assert ios.feed(typed.encode())[1] is None, typed
    forti = drivers.get("fortios")
    assert forti.guard("config system interface") and forti.guard("execute reboot") and not forti.guard("execute ping 1.1.1.1")
    assert drivers.get("huawei-vrp").guard("system-view") and not drivers.get("huawei-vrp").guard("display version")
    assert drivers.get("mikrotik-routeros").guard("/ip address add address=1.1.1.1/24") and \
        not drivers.get("mikrotik-routeros").guard("/ip address print")
    assert drivers.get("pfsense").guard("rm -rf /cf") and not drivers.get("pfsense").guard("cat /cf/conf/config.xml")


def test_host_key_is_pinned_and_a_changed_key_is_refused(client, auth, emulator, tmp_path, monkeypatch):
    ssh, _ = emulator
    monkeypatch.setattr(terminal_service, "_known_hosts_path", lambda: tmp_path / "known_hosts.json")
    (tmp_path / "known_hosts.json").write_text(json.dumps({f"127.0.0.1:{ssh.port}": "ssh-rsa SHA256:not-this-key"}))
    _, device = _device(client, auth)
    ticket = client.post(f"/api/devices/{device['id']}/terminal", headers=auth, json={
        "transport": "ssh", "port": ssh.port, "username": "netguard", "password": "Lab-Pass1"}).json()["ticket"]
    with client.websocket_connect(f"/api/terminal/ws?ticket={ticket}") as ws:
        message = json.loads(ws.receive_text())
        assert message["type"] == "hostkey" and message["known"] == "ssh-rsa SHA256:not-this-key"
    ticket = client.post(f"/api/devices/{device['id']}/terminal", headers=auth, json={
        "transport": "ssh", "port": ssh.port, "username": "netguard", "password": "Lab-Pass1", "accept_new_key": True}).json()["ticket"]
    with client.websocket_connect(f"/api/terminal/ws?ticket={ticket}") as ws:
        assert json.loads(ws.receive_text())["type"] == "ready"
    assert "not-this-key" not in (tmp_path / "known_hosts.json").read_text()


# ------------------------------------------------------------------ web portals
@pytest.fixture()
def web_portal():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", "/login?redir=%2F")
                self.end_headers()
                return
            body = b"<html><head><title>FortiGate - Login</title></head><body><form><input type=password></form></body></html>"
            self.send_response(200)
            self.send_header("Server", "xxxxxxxx-xxxxx")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


def test_portal_detection_follows_redirects_and_fingerprints_the_vendor(web_portal):
    found = portals.detect("127.0.0.1", [web_portal])
    assert len(found) == 1
    site = found[0]
    assert site["vendor"] == "Fortinet" and site["product"] == "FortiGate" and site["login_page"]
    assert site["url"] == f"http://127.0.0.1:{web_portal}/login" and site["title"] == "FortiGate - Login"
    for text, vendor in (("pfSense - Login", "Netgate"), ("UniFi Network", "Ubiquiti"), ("Ruijie Reyee", "Ruijie"),
                         ("TP-LINK Archer C6", "TP-Link"), ("D-LINK DIR-842", "D-Link"), ("FiberHome HG6243C", "FiberHome"),
                         ("ArubaOS AOS-CX", "HPE Aruba"), ("Cisco Systems level_15", "Cisco"), ("RouterOS router", "MikroTik")):
        assert portals.fingerprint(text)[0] == vendor, text


def test_port_scan_job_finds_the_portal_and_stores_it(client, auth, web_portal, monkeypatch):
    from backend.api.routes import terminal as routes

    monkeypatch.setitem(routes._RANGES, "common", lambda: [web_portal, 1])
    _, device = _device(client, auth)
    job = client.post(f"/api/devices/{device['id']}/portals/scan", headers=auth, json={"range": "common"})
    assert job.status_code == 202, job.text
    for _ in range(100):
        row = client.get(f"/api/terminal/jobs/{job.json()['job_id']}", headers=auth).json()
        if row["state"] in ("done", "failed"):
            break
        time.sleep(0.1)
    assert row["state"] == "done" and row["open_ports"] == [web_portal]
    listed = client.get(f"/api/devices/{device['id']}/portals", headers=auth).json()
    assert listed["portals"][0]["product"] == "FortiGate" and listed["last_scan"]["open_ports"] == [web_portal]


# ------------------------------------------------------------------ multi-vendor
FORTIOS = """#config-version=FGT60F-7.2.5
config system global
    set hostname "FGT-HQ"
end
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh http telnet
    next
    edit "lan"
        set ip 192.168.10.1 255.255.255.0
    next
end
config router static
    edit 1
        set gateway 10.0.0.254
        set device "port1"
    next
end
"""


def test_vendor_configurations_become_the_neutral_model():
    devs, warnings = config_import.parse_configs(FORTIOS, lenient=True)
    fgt = devs["FGT-HQ"]
    assert fgt.kind == "firewall" and fgt.platform == "fortios" and fgt.gw == "10.0.0.254"
    assert (fgt.ifs["port1"].ip, fgt.ifs["port1"].mask) == ("10.0.0.1", "255.255.255.0")
    assert fgt.facts["http_server"] and fgt.facts["vty"][0]["transport"] == ["telnet"]
    assert "fortios configuration translated" in warnings[0]
    assert vendor_parsers.detect_format("sysname SW1\ninterface Vlanif10\n") == "huawei"
    assert vendor_parsers.detect_format("set interfaces ethernet eth0 address 10.0.0.1/24\n") == "edgeos"
    assert vendor_parsers.detect_format("/ip address\nadd address=10.0.0.1/24 interface=ether1\n") == "mikrotik"
    assert vendor_parsers.detect_format("hostname R1\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n") is None


def test_fortigate_import_runs_the_rule_packs(client, auth):
    response = client.post("/api/networks/import", headers=auth, json={"name": "FortiGate", "configs": FORTIOS})
    assert response.status_code == 200, response.text
    nid = response.json()["network_id"]
    device = client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"][0]
    assert device["platform"] == "fortios" and device["device_type"] == "firewall" and device["vendor"] == "Fortinet"
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    rows = report["issues"] + report.get("advisories", [])
    sec = [r for r in rows if r["rule_id"] == "SEC002"]
    assert sec and "Telnet management is enabled" in json.dumps(sec), [r["rule_id"] for r in rows]


MIKROTIK = """# 2026-11-18 by RouterOS 7.12
/system identity
set name=MT-Edge
/interface ethernet
set [ find default-name=ether3 ] disabled=yes
/ip address
add address=10.0.0.1/24 interface=ether1
add address=192.168.88.1/24 interface=ether2
/ip route
add dst-address=0.0.0.0/0 gateway=10.0.0.254
/ip service
set telnet disabled=no
set www disabled=no
set ssh disabled=no
"""


def test_mikrotik_export_with_ip_service_section_parses():
    """Every RouterOS export has an /ip service section; it used to crash the parser."""
    dev = vendor_parsers.parse(MIKROTIK)
    assert dev.name == "MT-Edge" and dev.gw == "10.0.0.254"
    assert (dev.ifs["ether1"].ip, dev.ifs["ether1"].mask) == ("10.0.0.1", "255.255.255.0")
    assert dev.ifs["ether3"].down
    assert dev.facts["http_server"] and dev.facts["vty"][0]["transport"] == ["telnet"]


def test_mikrotik_import_runs_the_rule_packs(client, auth):
    response = client.post("/api/networks/import", headers=auth, json={"name": "MikroTik", "configs": MIKROTIK})
    assert response.status_code == 200, response.text
    nid = response.json()["network_id"]
    device = client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"][0]
    assert device["name"] == "MT-Edge" and device["platform"] == "mikrotik-routeros"
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    rows = report["issues"] + report.get("advisories", [])
    assert any(r["rule_id"] == "SEC002" for r in rows), [r["rule_id"] for r in rows]


def test_driver_matrix_and_detection(client, auth):
    matrix = {row["id"]: row for row in client.get("/api/drivers", headers=auth).json()}
    assert {"cisco-ios", "cisco-nxos", "fortios", "pfsense", "aruba-os-switch", "aruba-cx", "edgeos", "unifi", "ruijie-os",
            "tplink-jetstream", "dlink-ds", "huawei-vrp", "mikrotik-routeros", "juniper-junos", "fiberhome"} <= set(matrix)
    assert matrix["fortios"]["self_healing"] and not matrix["pfsense"]["self_healing"] and not matrix["fiberhome"]["ssh"]
    assert drivers.detect("SSH-2.0-ROSSSH") == "mikrotik-routeros" and drivers.detect("SSH-2.0-HUAWEI-1.5") == "huawei-vrp"
    assert drivers.detect(None, "Fortinet", "FortiGate") == "fortios" and drivers.detect("SSH-2.0-OpenSSH_8.9") == "frr"


# ------------------------------------------------------------------ permission-based self-healing on production devices
SW = """hostname SW-PROD
vlan 10
 name USERS
vlan 20
 name SERVERS
interface GigabitEthernet0/0
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 20
"""


@pytest.fixture()
def production_switch(client, auth):
    switch = Device("SW-PROD", SW, {"show version": "Cisco IOS Software, vios_l2 Software, Version 15.2\n"})
    server = SshEmulator(switch)
    imported = client.post("/api/networks/import", headers=auth, json={"name": f"Prod {time.time()}", "configs": SW}).json()
    nid = imported["network_id"]
    device = client.get(f"/api/networks/{nid}/topology", headers=auth).json()["devices"][0]
    assert client.put(f"/api/devices/{device['id']}", headers=auth, json={
        "name": "SW-PROD", "device_type": "switch", "management_ip": "127.0.0.1"}).status_code == 200
    yield {"nid": nid, "device": device, "server": server, "switch": switch}
    server.close()


def _approved_change(client, auth, production_switch, vlan=20):
    from backend.tests.helpers import manager_auth

    device = production_switch["device"]
    gi0 = next(i for i in device["interfaces"] if i["name"] == "Gi0/0")
    change = client.post("/api/changes", headers=auth, json={"device_id": device["id"], "interface_id": gi0["id"],
                                                             "change_type": "access_vlan", "parameters": {"vlan_id": vlan}}).json()
    assessment = client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()
    assert assessment["hybrid"]["score"] >= assessment["hybrid"]["deterministic"]  # AI never lowers the rules score
    assert client.post(f"/api/changes/{change['id']}/submit", headers=auth).status_code == 200
    manager = manager_auth(client, auth)
    assert client.post(f"/api/changes/{change['id']}/approve", headers=manager, json={"note": "window"}).status_code == 200
    return change


def test_real_network_fixing_needs_the_group_permission(client, auth, production_switch):
    from backend.tests.helpers import group_id, manager_auth

    change = _approved_change(client, auth, production_switch)
    body = {"confirm": True, "transport": "ssh", "username": "netguard", "password": "Lab-Pass1",
            "port": production_switch["server"].port}
    client.post("/api/accounts", headers=auth, json={"username": "eng-prod", "password": "pw",
                                                     "group_id": group_id(client, auth, "Network Engineers")})
    engineer = {"Authorization": "Bearer " + client.post("/api/auth/login", json={"username": "eng-prod", "password": "pw"}).json()["access_token"]}
    refused = client.post(f"/api/changes/{change['id']}/execute", headers=engineer, json=body)
    assert refused.status_code == 403 and "real-network" in refused.text
    assert production_switch["switch"].running().count("switchport access vlan 10") == 1  # nothing was sent
    manager = manager_auth(client, auth)
    assert client.put("/api/settings/self-healing", headers=manager, json={"confirm_minutes": 5}).status_code == 403
    assert client.put("/api/settings/self-healing", headers=auth, json={"confirm_minutes": 1}).status_code == 422
    assert client.put("/api/settings/self-healing", headers=auth, json={"confirm_minutes": 5}).json()["confirm_minutes"] == 5


def test_production_change_waits_for_confirmation_then_is_saved(client, auth, production_switch):
    change = _approved_change(client, auth, production_switch)
    body = {"confirm": True, "transport": "ssh", "username": "netguard", "password": "Lab-Pass1",
            "port": production_switch["server"].port}
    result = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json=body)
    assert result.status_code == 200, result.text
    execution = result.json()["execution"]
    assert execution["status"] == "awaiting_confirm" and execution["verification"]["confirm_by"]
    assert result.json()["change"]["self_healing"]["confirm_by"] == execution["verification"]["confirm_by"]
    assert any("switchport access vlan 20" in line for line in production_switch["switch"].lines)
    confirmed = client.post(f"/api/changes/{change['id']}/confirm", headers=auth, json={})
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["execution"]["status"] == "applied" and confirmed.json()["change"]["status"] == "applied"
    history = production_switch["switch"].exec_history
    assert history[0].startswith("reload in ") and "reload cancel" in history and "write memory" in history
    log = " ".join(step["step"] for step in confirmed.json()["execution"]["log"])
    assert "dead-man's switch armed" in log and "Live reachability baseline" in log


def test_unconfirmed_production_change_is_rolled_back(client, auth, production_switch):
    from backend.services import remediation_service

    change = _approved_change(client, auth, production_switch)
    body = {"confirm": True, "transport": "ssh", "username": "netguard", "password": "Lab-Pass1",
            "port": production_switch["server"].port}
    execution = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json=body).json()["execution"]
    assert execution["status"] == "awaiting_confirm"
    remediation_service._expire(execution["id"])  # the confirmation window elapses
    rows = client.get(f"/api/changes/{change['id']}/executions", headers=auth).json()
    assert rows[0]["status"] == "rolled_back" and rows[0]["verification"]["expired"] is True
    assert any(" switchport access vlan 10" == line for line in production_switch["switch"].lines)
    assert client.get(f"/api/changes/{change['id']}", headers=auth).json()["status"] == "rolled_back"


def test_confirmation_after_the_window_expired_is_refused(client, auth, production_switch):
    """The expiry timer, a confirmation and a manual rollback never act on the same change at once."""
    from backend.services import remediation_service

    change = _approved_change(client, auth, production_switch)
    body = {"confirm": True, "transport": "ssh", "username": "netguard", "password": "Lab-Pass1",
            "port": production_switch["server"].port}
    execution = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json=body).json()["execution"]
    with remediation_service._pending_lock:  # the expiry timer has taken the session (rollback in progress)
        state = remediation_service._pending.pop(execution["id"])
    state["timer"].cancel()
    from backend.database.session import SessionLocal
    from backend.models import ChangeExecution
    with SessionLocal() as db:
        row = db.get(ChangeExecution, execution["id"])
        row.verification = {**row.verification, "confirm_by": "2000-01-01T00:00:00"}
        db.commit()
    refused = client.post(f"/api/changes/{change['id']}/confirm", headers=auth, json={})
    assert refused.status_code == 409 and "window has ended" in refused.text
    with remediation_service._pending_lock:
        remediation_service._pending[execution["id"]] = state
    remediation_service._expire(execution["id"])
    assert client.get(f"/api/changes/{change['id']}", headers=auth).json()["status"] == "rolled_back"


def test_restart_during_the_window_with_typed_credentials_is_reported(client, auth, production_switch):
    from backend.services import remediation_service

    change = _approved_change(client, auth, production_switch)
    body = {"confirm": True, "transport": "ssh", "username": "netguard", "password": "Lab-Pass1",
            "port": production_switch["server"].port}
    execution = client.post(f"/api/changes/{change['id']}/execute", headers=auth, json=body).json()["execution"]
    assert execution["verification"]["credential_source"] == {"typed": True}
    with remediation_service._pending_lock:  # the process ended: timers and sessions are gone
        remediation_service._pending.pop(execution["id"])["timer"].cancel()
    assert remediation_service.recover_pending() == 0
    row = client.get(f"/api/changes/{change['id']}/executions", headers=auth).json()[0]
    assert row["status"] == "rollback_failed" and "typed for this session" in row["log"][-1]["step"]
    assert client.get(f"/api/changes/{change['id']}", headers=auth).json()["status"] == "failed"


def test_approver_cannot_execute_a_production_change(client, auth, production_switch):
    from backend.database.session import SessionLocal
    from backend.models import Change, User

    change = _approved_change(client, auth, production_switch)
    # A group that may approve and apply real-network changes, but without Auto-Fix.
    group = client.post("/api/groups", headers=auth, json={"name": "Operators", "permissions": [
        "topology.view", "change.approve", "change.execute", "change.execute_production"]}).json()
    client.post("/api/accounts", headers=auth, json={"username": "ops1", "password": "pw", "group_id": group["id"]})
    ops = {"Authorization": "Bearer " + client.post("/api/auth/login", json={"username": "ops1", "password": "pw"}).json()["access_token"]}
    with SessionLocal() as db:
        row = db.get(Change, change["id"])
        row.decided_by = db.query(User).filter(User.username == "ops1").one().id  # ops1 approved it
        db.commit()
    body = {"confirm": True, "transport": "ssh", "username": "netguard", "password": "Lab-Pass1",
            "port": production_switch["server"].port}
    refused = client.post(f"/api/changes/{change['id']}/execute", headers=ops, json=body)
    assert refused.status_code == 403 and "Separation of duties" in refused.text


def test_multi_vendor_commands_are_generated():
    from types import SimpleNamespace

    from backend.services import cli_generator
    iface = SimpleNamespace(name="GigabitEthernet0/0/1", ip=None, mask=None, vlan=None, mode=None)
    huawei = SimpleNamespace(platform="huawei-vrp", type="switch", vendor="Huawei", model=None, routes=[], interfaces={}, facts={}, acl=[], vlans=[])
    assert cli_generator._huawei(huawei, iface, "access_vlan", {"vlan_id": 20}) == [
        "interface GigabitEthernet0/0/1", " port link-type access", " port default vlan 20", " quit"]
    assert cli_generator.platform_of(huawei) == "huawei-vrp"
    mt = SimpleNamespace(platform="mikrotik-routeros", type="router", vendor="MikroTik", model=None, routes=[])
    assert cli_generator._mikrotik(mt, SimpleNamespace(name="ether2"), "interface_status", {"status": "admin-down"}) == [
        "/interface disable [find name=ether2]"]
    vy = SimpleNamespace(platform="edgeos", type="router", routes=[])
    assert cli_generator._vyos(vy, SimpleNamespace(name="eth1.10"), "ip_address", {"ip_address": "10.0.0.1", "subnet_mask": "255.255.255.0"}) == [
        "delete interfaces ethernet eth1 vif 10 address", "set interfaces ethernet eth1 vif 10 address 10.0.0.1/24"]
    pf = SimpleNamespace(platform="pfsense", type="firewall", vendor="Netgate", model=None)
    assert cli_generator.automatable(pf, "ip_address", {})[0] is False
