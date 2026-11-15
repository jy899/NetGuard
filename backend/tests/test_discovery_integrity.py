"""Discovery shows only evidence from the network: no inherited, sample or guessed devices."""
import socket
import struct
import threading
import time

from backend.collectors import netutil
from backend.database.session import SessionLocal, engine
from backend.models import Device, Network
from backend.services.discovery import real_engine, service


def test_deleted_network_leaves_nothing_for_the_next_network(client, auth):
    """A network deleted while a pooled connection had foreign keys off used to leave its devices behind; SQLite then
    reused the ID and the next network (a discovery) showed the old example devices."""
    old = client.post("/api/networks/samples", headers=auth, json={"scenario": "healthy"}).json()["network_id"]
    with engine.connect() as connection:  # simulate a connection that a migration left with enforcement off
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
    assert client.delete(f"/api/networks/{old}", headers=auth).status_code == 204
    with SessionLocal() as db:
        assert db.query(Device).filter(Device.network_id == old).count() == 0
    new = client.post("/api/networks", headers=auth, json={"name": "Fresh"}).json()
    assert new["id"] != old  # IDs are never reused
    assert client.get(f"/api/networks/{new['id']}/topology", headers=auth).json()["devices"] == []


def test_startup_repairs_devices_a_discovery_inherited(client, auth):
    from backend.database.init_db import init_db
    with SessionLocal() as db:
        ghost_net = Network(name="Deleted earlier")
        db.add(ghost_net)
        db.flush()
        ghost = Device(network_id=ghost_net.id, name="R1", device_type="router", x_position=0, y_position=0)
        db.add(ghost)
        db.flush()
        discovery = Network(name="Discovery · 10.0.0.0/24", source="discovery", metadata_json={"method": "smart"})
        db.add(discovery)
        db.flush()
        real = Device(network_id=discovery.id, name="10.0.0.1", device_type="router", x_position=0, y_position=0)
        db.add(real)
        db.flush()
        ghost.network_id = discovery.id  # what the ID reuse produced in earlier versions
        discovery.metadata_json = {"method": "smart", "discovery": {str(real.id): {"ip": "10.0.0.1"}}}
        db.commit()
        nid = discovery.id
    init_db()
    with SessionLocal() as db:
        assert [d.name for d in db.query(Device).filter(Device.network_id == nid)] == ["10.0.0.1"]


def test_a_fresh_installation_has_no_network(client, auth):
    assert client.get("/api/networks", headers=auth).json() == []
    stats = client.get("/api/dashboard/summary", headers=auth).json()
    assert stats["networks"] == 0 and stats["devices"] == 0


def _nbstat_server(name: bytes, mac: bytes):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def serve():
        data, peer = sock.recvfrom(512)
        tid = data[:2]
        rdata = bytes([2]) + name.ljust(15) + b"\x00" + struct.pack(">H", 0x0400) + \
            b"WORKGROUP".ljust(15) + b"\x00" + struct.pack(">H", 0x8400) + mac + b"\x00" * 40
        answer = tid + struct.pack(">HHHHH", 0x8400, 0, 1, 0, 0) + data[12:12 + 34] + \
            struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata
        sock.sendto(answer, peer)
        sock.close()
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_netbios_node_status_gives_the_computer_name_and_mac():
    port = _nbstat_server(b"FINANCE-PC07", bytes.fromhex("3c52820a1b2c"))
    result = netutil.netbios_status("127.0.0.1", timeout=2, port=port)
    assert result["name"] == "FINANCE-PC07" and result["workgroup"] == "WORKGROUP" and result["mac"] == "3c:52:82:0a:1b:2c"


def test_identity_is_only_claimed_from_evidence():
    identify = real_engine.RealDiscoveryEngine._identify
    assert identify(set(), None, None, None, [], False)[1] == "Unidentified device"
    assert identify(set(), None, None, None, [], False)[2] == "unknown"
    assert identify({445, 135}, None, None, None, [], False)[1].startswith("Windows")
    assert identify({22}, None, None, "SSH-2.0-OpenSSH_9.6", [], False)[2] == "unknown"  # SSH alone names nothing
    assert identify({22}, "Cisco Systems, Inc", None, "SSH-2.0-Cisco-1.25", [], False)[2] == "unknown"  # router or switch?
    assert identify(set(), None, None, None, [], True)[0] == "router"  # this subnet's gateway routes
    assert identify({443}, "Fortinet, Inc.", None, None, [], False)[0] == "firewall"
    kind = real_engine.snmp_kind
    assert kind({"ip_forwarding": 1, "bridge_ports": 0}, False)[0] == "router"
    assert kind({"ip_forwarding": 2, "bridge_ports": 24}, False)[0] == "switch"
    assert kind({"ip_forwarding": 1, "bridge_ports": 48}, False)[1] == "Multilayer switch"
    assert kind({"ip_forwarding": 2, "bridge_ports": 0, "description": "HP LaserJet"}, False)[0] is None


def test_hosts_that_answer_only_arp_are_discovered(monkeypatch):
    monkeypatch.setattr(netutil, "ping_available", lambda: True)
    monkeypatch.setattr(netutil, "ping_ttl", lambda ip, timeout_ms=800: 128 if ip == "10.9.0.5" else None)
    monkeypatch.setattr(netutil, "tcp_open", lambda ip, port, timeout=0.7: False)
    monkeypatch.setattr(netutil, "arp_table", lambda: {"10.9.0.5": "3c:52:82:0a:1b:2c", "10.9.0.9": "00:1b:21:aa:bb:cc",
                                                       "192.168.99.1": "00:00:5e:00:01:01"})
    monkeypatch.setattr(netutil, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(netutil, "netbios_status", lambda ip, timeout=1.0, port=137: None)
    monkeypatch.setattr(netutil, "ssdp_discover", lambda scope, timeout=2.5: {})
    monkeypatch.setattr(netutil, "default_gateway", lambda: None)
    monkeypatch.setattr(netutil, "traceroute", lambda ip, max_hops=12: [])
    monkeypatch.setattr(netutil, "mdns_name", lambda ip, timeout=0.8: None)
    monkeypatch.setattr(real_engine.snmpv3, "engine_discovery", lambda *a, **k: None)
    import ipaddress
    engine = real_engine.RealDiscoveryEngine(ipaddress.IPv4Network("10.9.0.0/28"))
    seen = []
    probe = engine.probe(progress=lambda phase, done, total, found: seen.append(phase))
    subjects = {o["subject"] for o in probe["observations"]}
    assert subjects == {"10.9.0.5", "10.9.0.9"}  # the ARP entry outside the range is ignored
    arp_only = next(o for o in probe["observations"] if o["subject"] == "10.9.0.9" and o["technique"] == "arp")
    assert arp_only["facts"]["arp_only"] and "ARP only" in arp_only["detail"]
    icmp = next(o for o in probe["observations"] if o["technique"] == "icmp")
    assert icmp["facts"]["ttl"] == 128 and "a hint, not an identification" in icmp["detail"]
    assert seen[0] == "sweep" and "services" in seen and seen[-1] == "done"


def test_background_scan_reports_progress_and_the_result(client, auth):
    job = client.post("/api/discovery/jobs", headers=auth, json={"target": "172.16.10.0/24", "authorized_scope": True})
    assert job.status_code == 202, job.text
    job_id = job.json()["id"]
    for _ in range(100):
        status = client.get(f"/api/discovery/jobs/{job_id}", headers=auth).json()
        if status["state"] != "running":
            break
        time.sleep(0.1)
    assert status["state"] == "done", status
    result = client.get(f"/api/discovery/{status['network_id']}", headers=auth).json()
    assert len(result["devices"]) == status["found"] == 12
    assert client.post("/api/discovery/jobs", headers=auth, json={"target": "10.0.0.0/16", "authorized_scope": True}).status_code == 422


def _home_network(monkeypatch, wifi_bssid="36:e4:97:18:6e:66"):
    """A phone hotspot / home router LAN like the one in the field report: the gateway answers ARP and DNS only,
    a TV answers ICMP, this computer is on Wi-Fi."""
    from backend.collectors import portals

    monkeypatch.setattr(netutil, "ping_available", lambda: True)
    monkeypatch.setattr(netutil, "ping_ttl", lambda ip, timeout_ms=800: {"10.154.251.40": 64, "10.154.251.5": 128}.get(ip))
    monkeypatch.setattr(netutil, "tcp_open", lambda ip, port, timeout=0.7: (ip, port) in {("10.154.251.27", 53), ("10.154.251.40", 8443)})
    monkeypatch.setattr(netutil, "arp_ping", lambda ip: {"10.154.251.27": "36:e4:97:18:6e:65", "10.154.251.40": "a4:5e:60:01:02:03"}.get(ip))
    monkeypatch.setattr(netutil, "arp_table", lambda: {"10.154.251.27": "36:e4:97:18:6e:65", "10.154.251.40": "a4:5e:60:01:02:03"})
    monkeypatch.setattr(netutil, "this_computer", lambda scope: {
        "ip": "10.154.251.5", "mask": "255.255.255.0", "interface": "Wi-Fi", "mac": "5c:e4:2a:11:22:33", "hostname": "JY",
        "os": "Windows 11", "speed_mbps": 433, "wireless": True,
        "wifi": {"interface": "Wi-Fi", "ssid": "JY-Phone", "bssid": wifi_bssid, "signal": "92%", "radio": "802.11ac"}})
    monkeypatch.setattr(netutil, "local_networks", lambda max_prefix=22: {"interfaces": [{"network": "10.154.251.0/24"}]})
    monkeypatch.setattr(netutil, "default_gateway", lambda: "10.154.251.27")
    monkeypatch.setattr(netutil, "traceroute", lambda ip, max_hops=12: [])
    monkeypatch.setattr(netutil, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(netutil, "mdns_name", lambda ip, timeout=0.8: "Living-Room-TV" if ip == "10.154.251.40" else None)
    monkeypatch.setattr(netutil, "netbios_status", lambda ip, timeout=1.0, port=137: None)
    monkeypatch.setattr(netutil, "ssdp_discover", lambda scope, timeout=2.5: {})
    monkeypatch.setattr(netutil, "ssh_banner", lambda ip, port=22, timeout=2.0: None)
    monkeypatch.setattr(real_engine.snmpv3, "engine_discovery", lambda *a, **k: None)
    monkeypatch.setattr(portals, "detect", lambda ip, ports, timeout=2.5: [] if ip != "10.154.251.40" else [{
        "port": 8443, "scheme": "https", "url": "https://10.154.251.40:8443/", "status": 200, "title": "UniFi Network",
        "server": None, "vendor": "Ubiquiti", "product": "UniFi", "matched": "unifi", "login_page": True,
        "certificate": {"subject": "UniFi", "issuer": "UniFi", "self_signed": True, "sha256": "ab" * 32}, "self_signed": True}])
    monkeypatch.setattr(service, "engine_factory", service.default_engine)


def test_every_device_is_placed_with_graded_links(client, auth, monkeypatch):
    _home_network(monkeypatch)
    scan = client.post("/api/discovery/scan", headers=auth, json={"target": "10.154.251.0/24", "authorized_scope": True})
    assert scan.status_code == 201, scan.text
    result = scan.json()
    devices = {d["ip"]: d for d in result["devices"]}
    # The scanning computer is part of its own discovery, named from its host name.
    assert set(devices) == {"10.154.251.5", "10.154.251.27", "10.154.251.40"}
    me = devices["10.154.251.5"]
    assert me["name"] == "JY" and me["role"] == "This computer (NetGuard host)"
    tv = devices["10.154.251.40"]
    assert tv["name"] == "Living-Room-TV" and tv["portals"][0]["product"] == "UniFi"
    links = {frozenset({l["source_device_name"], l["destination_device_name"]}): l for l in result["links"]}
    wifi = links[frozenset({"JY", devices["10.154.251.27"]["name"]})]
    # BSSID = gateway MAC + 1: the computer's own adapter reports the association; the AP match is inferred.
    assert wifi["kind"] == "wireless" and wifi["evidence_grade"] == "Inferred" and wifi["media"] == "wireless"
    assert any("SSID 'JY-Phone'" in e for e in wifi["evidence"])
    segment = links[frozenset({"Living-Room-TV", devices["10.154.251.27"]["name"]})]
    assert segment["kind"] == "segment" and segment["evidence_grade"] == "Logical"
    assert result["report"]["connections"]["unknown"] == 0  # nothing floats
    # Logical links are drawn but never used for forwarding verdicts.
    from backend.database.session import SessionLocal
    from backend.services.network_model import load_model
    with SessionLocal() as db:
        model = load_model(db, result["network_id"])
    assert {l.kind for l in model.links.values()} == {"wireless"}


def test_exact_bssid_match_is_a_confirmed_wireless_association(client, auth, monkeypatch):
    _home_network(monkeypatch, wifi_bssid="36:e4:97:18:6e:65")
    result = client.post("/api/discovery/scan", headers=auth, json={"target": "10.154.251.0/24", "authorized_scope": True}).json()
    wifi = next(l for l in result["links"] if l["kind"] == "wireless")
    assert wifi["evidence_grade"] == "Confirmed" and wifi["discovery_status"] == "observed"
