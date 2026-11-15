"""Cross-VLAN subnet discovery, switch port mapping and Web GUI detection (fixes of 13 November 2026)."""
import datetime
import socket
import ssl
import tempfile
import threading
import time

import pytest
from sqlalchemy import select

from backend.collectors import portals
from backend.services.discovery import subnets
from backend.services.discovery.engine import observation

CORE_CONFIG = """hostname CORE-SW1
interface Vlan10
 ip address 10.0.10.2 255.255.255.0
interface Vlan20
 ip address 10.0.20.1 255.255.255.0
interface Vlan30
 ip address 10.0.30.1/24
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
interface GigabitEthernet0/0
 ip address dhcp
ip access-list extended X
 permit ip any 10.0.30.0 0.0.0.255
"""


# ------------------------------------------------------------------ subnets reported by routers and L3 switches
def test_connected_subnets_are_read_from_every_configuration_syntax():
    got = {s["cidr"]: s["interface"] for s in subnets.from_config(CORE_CONFIG)}
    assert got == {"10.0.10.0/24": "Vlan10", "10.0.20.0/24": "Vlan20", "10.0.30.0/24": "Vlan30"}
    forti = 'config system interface\n    edit "lan"\n        set ip 192.168.50.1 255.255.255.0\n    next\n'
    assert subnets.from_config(forti)[0]["cidr"] == "192.168.50.0/24"
    assert subnets.from_config("/ip address\nadd address=172.16.5.1/24 interface=bridge\n")[0]["cidr"] == "172.16.5.0/24"
    junos = "set interfaces vlan unit 40 family inet address 10.0.40.1/24\n"
    assert subnets.from_config(junos)[0]["cidr"] == "10.0.40.0/24"
    rows = subnets.from_addresses([{"ip": "10.0.40.1", "mask": "255.255.255.0", "interface": "Vlan40"}])
    assert rows[0]["cidr"] == "10.0.40.0/24"


def test_sweep_plan_respects_scope_exclusions_and_size():
    obs = [{"authenticated": True, "technique": "connected-subnets", "observed_by": "10.0.10.2",
            "facts": {"subnets": subnets.from_config(CORE_CONFIG)}},
           {"authenticated": True, "technique": "routing-table", "observed_by": "10.0.10.1", "facts": {"routes": [
               {"destination": "10.0.60.0", "mask": "255.255.255.0", "next_hop": "10.0.10.3"},
               {"destination": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.10.254"},
               {"destination": "8.8.8.0", "mask": "255.255.255.0", "next_hop": "10.0.10.254"},
               {"destination": "10.50.0.0", "mask": "255.255.0.0", "next_hop": "10.0.10.3"}]}},
           {"authenticated": False, "technique": "connected-subnets", "observed_by": "x",
            "facts": {"subnets": [{"cidr": "10.9.9.0/24", "source": "interface"}]}}]  # unauthenticated: ignored
    found = subnets.candidates(obs)
    todo, left = subnets.plan(found, ["10.0.10.0/24"], ["10.0.30.0/24"], ["10.0.10.0/24"], follow=True)
    assert [t["cidr"] for t in todo] == ["10.0.20.0/24", "10.0.60.0/24"]
    reasons = {row["cidr"]: row["reason"] for row in left}
    assert reasons["10.0.30.0/24"] == "excluded"
    assert "outside" in reasons["8.8.8.0/24"] and "larger" in reasons["10.50.0.0/16"]
    todo, left = subnets.plan(found, ["10.0.10.0/24"], [], ["10.0.10.0/24"], follow=False)
    assert todo == [] and all("outside" in row["reason"] for row in left)
    todo, _ = subnets.plan(found, ["10.0.10.0/24", "10.0.20.0/24"], [], ["10.0.10.0/24"], follow=False)
    assert [t["cidr"] for t in todo] == ["10.0.20.0/24"]
    assert subnets.split_targets("10.0.10.0/24, 10.0.20.0/24\n10.0.30.0/24") == ["10.0.10.0/24", "10.0.20.0/24", "10.0.30.0/24"]


def test_scan_accepts_several_ranges(client, auth):
    too_many = ", ".join(f"10.0.{i}.0/24" for i in range(9))
    assert client.post("/api/discovery/jobs", headers=auth, json={"target": too_many}).status_code == 422
    assert client.post("/api/discovery/jobs", headers=auth, json={"target": "10.0.0.0/16"}).status_code == 422


# ------------------------------------------------------------------ which switch port leads to which device
def test_port_mapping_uses_router_arp_and_port_macs(client, auth):
    """CORE routes VLAN 10 and 20. SW1 Gi1/0/1 -> SW2 Gi1/0/24 (no LLDP), Gi1/0/5 -> router, Gi1/0/7 -> PC-A in
    VLAN 20 (no local ARP entry). PC-B hangs off SW2 Gi1/0/3 and must not be drawn on SW1's uplink."""
    from backend.database.session import SessionLocal
    from backend.models import Device, Interface, Link, Network
    from backend.services.discovery import classification, fusion, port_clients

    with SessionLocal() as db:
        net = Network(name="ports", network_type="Enterprise", description="", environment="real", source="discovery",
                      is_simulated=False, metadata_json={})
        db.add(net)
        db.flush()
        spec = [("CORE", "10.0.10.2", "switch"), ("SW1", "10.0.10.11", "switch"), ("SW2", "10.0.10.12", "switch"),
                ("RTR", "10.0.10.1", "router"), ("PC-A", "10.0.20.11", "pc"), ("PC-B", "10.0.10.50", "pc")]
        devs, discovery = {}, {}
        for name, ip, kind in spec:
            d = Device(network_id=net.id, name=name, device_type=kind, management_ip=ip, x_position=0, y_position=0)
            db.add(d)
            db.flush()
            devs[name] = d
            discovery[str(d.id)] = {"ip": ip, "position_source": "auto", "type": kind,
                                    "auth": "success" if name in ("CORE", "SW1", "SW2") else None,
                                    "role": {"switch": "Switch", "router": "Router"}.get(kind, "Workstation")}

        def seen(tech, subject, facts):
            return observation(tech, subject, facts)

        def read(tech, ip, facts):
            return observation(tech, ip, facts, authenticated=True, method="ssh", observed_by=ip)

        def port(name, mac):
            return {"port": name, "status": "up", "mac": mac, "speed": 1000}

        obs = [seen("arp", "10.0.10.2", {"mac": "aa:00:00:00:00:02"}), seen("arp", "10.0.10.11", {"mac": "aa:00:00:00:00:11"}),
               seen("arp", "10.0.10.12", {"mac": "aa:00:00:00:00:12"}), seen("arp", "10.0.10.1", {"mac": "aa:00:00:00:00:01"}),
               seen("arp", "10.0.10.50", {"mac": "cc:00:00:00:00:50"}), seen("icmp", "10.0.20.11", {"ttl": 127}),
               read("system-info", "10.0.10.2", {"hostname": "CORE", "type": "switch", "role": "Switch"}),
               read("arp-table", "10.0.10.2", {"entries": [{"ip": "10.0.20.11", "mac": "cc:00:00:00:20:11", "interface": "Vlan20"}]}),
               read("interface-status", "10.0.10.2", {"ports": [], "stp": {}}),
               read("lldp-table", "10.0.10.2", {"rows": []}),
               read("system-info", "10.0.10.11", {"hostname": "SW1", "type": "switch", "role": "Switch"}),
               read("interface-status", "10.0.10.11", {"ports": [port("Gi1/0/1", "bb:11:00:00:00:01"),
                                                                 port("Gi1/0/5", "bb:11:00:00:00:05"),
                                                                 port("Gi1/0/7", "bb:11:00:00:00:07")], "stp": {}}),
               read("lldp-table", "10.0.10.11", {"rows": []}),
               read("mac-table", "10.0.10.11", {"rows": [{"port": "Gi1/0/1", "mac": "bb:12:00:00:00:24", "vlan": 10},
                                                         {"port": "Gi1/0/1", "mac": "cc:00:00:00:00:50", "vlan": 10},
                                                         {"port": "Gi1/0/5", "mac": "aa:00:00:00:00:01", "vlan": 10},
                                                         {"port": "Gi1/0/7", "mac": "cc:00:00:00:20:11", "vlan": 20}]}),
               read("system-info", "10.0.10.12", {"hostname": "SW2", "type": "switch", "role": "Switch"}),
               read("interface-status", "10.0.10.12", {"ports": [port("Gi1/0/24", "bb:12:00:00:00:24"),
                                                                 port("Gi1/0/3", "bb:12:00:00:00:03")], "stp": {}}),
               read("lldp-table", "10.0.10.12", {"rows": []}),
               read("mac-table", "10.0.10.12", {"rows": [{"port": "Gi1/0/24", "mac": "bb:11:00:00:00:01", "vlan": 10},
                                                         {"port": "Gi1/0/3", "mac": "cc:00:00:00:00:50", "vlan": 10}]})]
        net.metadata_json = {"mode": "live", "target": "10.0.10.0/24", "method": "smart",
                             "scope": {"authorised": ["10.0.10.0/24"]}, "observations": obs, "discovery": discovery,
                             "timeline": [], "no_response": []}
        db.flush()
        original = classification.classify
        classification.classify = lambda *a, **k: None
        try:
            fusion.fuse(db, net)
        finally:
            classification.classify = original
        db.commit()
        # Fusion names unidentified devices by their address, so the checks use the original labels by ID.
        names = {devs[label].id: label for label in devs}
        ifname = {i.id: i.name for i in db.scalars(select(Interface))}
        links = set()
        for link in db.scalars(select(Link).where(Link.network_id == net.id)):
            a = (names[link.source_device_id], ifname.get(link.source_interface_id))
            b = (names[link.destination_device_id], ifname.get(link.destination_interface_id))
            links.add(tuple(sorted([a, b], key=lambda x: x[0])))
        assert (("SW1", "Gi1/0/1"), ("SW2", "Gi1/0/24")) in links            # switch-to-switch, both ports
        assert any(("SW1", "Gi1/0/5") in pair and "RTR" in {p[0] for p in pair} for pair in links)
        assert any(("SW1", "Gi1/0/7") in pair and "PC-A" in {p[0] for p in pair} for pair in links)  # other VLAN
        assert any(("SW2", "Gi1/0/3") in pair and "PC-B" in {p[0] for p in pair} for pair in links)
        assert not any(("SW1", "Gi1/0/1") in pair and "PC-B" in {p[0] for p in pair} for pair in links)

        table = port_clients.table(db, devs["SW1"])
        rows = {p["port"]: p for p in table["ports"]}
        assert table["read"] and rows["Gi1/0/1"]["kind"] == "uplink"
        assert rows["Gi1/0/7"]["clients"][0]["ip"] == "10.0.20.11" and rows["Gi1/0/7"]["clients"][0]["device_id"] == devs["PC-A"].id
        assert port_clients.table(db, devs["RTR"])["read"] is False


# ------------------------------------------------------------------ Web GUI on HTTP, HTTPS and custom IP:port
PAGE = b"<html><head><title>Switch Login</title></head><body><input type=\"password\"></body></html>"


@pytest.fixture(scope="module")
def web_servers():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FortiGate")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    folder = tempfile.mkdtemp()
    with open(f"{folder}/c.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(f"{folder}/k.pem", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"{folder}/c.pem", f"{folder}/k.pem")
    sockets = []

    def serve(mode):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        sockets.append(srv)

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    first = conn.recv(1, socket.MSG_PEEK)
                    if mode in ("tls", "nginx") and first == b"\x16":
                        conn = context.wrap_socket(conn, server_side=True)
                    elif mode == "nginx":  # plain HTTP on an HTTPS port: nginx answers 400
                        conn.recv(4096)
                        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Length: 60\r\n\r\n"
                                     b"<html>The plain HTTP request was sent to HTTPS port</html>  ")
                        conn.close()
                        continue
                    elif mode == "tls":
                        conn.close()
                        continue
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Type: text/html\r\n\r\n" + PAGE)
                    if mode == "keepalive":
                        time.sleep(6)  # never closes within the probe timeout
                    conn.close()
                except Exception:  # noqa: BLE001
                    conn.close()
        threading.Thread(target=loop, daemon=True).start()
        return srv.getsockname()[1]

    ports = {mode: serve(mode) for mode in ("http", "nginx", "tls", "keepalive")}
    time.sleep(0.2)
    yield ports
    for srv in sockets:
        srv.close()


def test_portal_detection_handles_https_on_custom_ports_and_keep_alive(web_servers):
    p = web_servers
    r = portals.probe("127.0.0.1", p["http"], 2.0)
    assert r and r["url"] == f"http://127.0.0.1:{p['http']}/" and r["login_page"]
    r = portals.probe("127.0.0.1", p["nginx"], 2.0)  # was recorded as http:// before the fix
    assert r and r["scheme"] == "https" and r["url"] == f"https://127.0.0.1:{p['nginx']}/" and r["vendor"] == "Fortinet"
    assert portals.probe("127.0.0.1", p["tls"], 2.0)["scheme"] == "https"
    started = time.time()
    r = portals.probe("127.0.0.1", p["keepalive"], 2.0)  # was "not a web server" before the fix
    assert r and r["title"] == "Switch Login" and time.time() - started < 5


def test_typed_address_finds_the_right_scheme(web_servers):
    p = web_servers
    assert portals.parse_address("192.168.1.1") == (None, "192.168.1.1", None, "/")
    assert portals.parse_address("192.168.1.1:8443") == (None, "192.168.1.1", 8443, "/")
    assert portals.parse_address("https://sw1.lan:10443/login") == ("https", "sw1.lan", 10443, "/login")
    for bad in ("ftp://x", "10.0.0.1:99999", "a b", "javascript:alert(1)", ""):
        with pytest.raises(ValueError):
            portals.parse_address(bad)
    r = portals.resolve(f"127.0.0.1:{p['nginx']}")
    assert r["verified"] and r["url"] == f"https://127.0.0.1:{p['nginx']}/"
    r = portals.resolve(f"127.0.0.1:{p['http']}/admin")
    assert r["verified"] and r["url"] == f"http://127.0.0.1:{p['http']}/admin"
    assert portals.resolve(f"http://127.0.0.1:{p['tls']}")["scheme"] == "https"  # typed http, device speaks https
    assert portals.resolve("127.0.0.1:8443")["url"] == "https://127.0.0.1:8443/"  # nothing answers: best guess


# ------------------------------------------------------------------ the crawl sweeps other VLANs
def test_crawl_sweeps_the_vlans_a_read_switch_reports(client, auth):
    """A layer 3 switch read in 10.0.10.0/24 reports VLAN 20 (10.0.20.0/24); a quiet PC there only answers ICMP.
    Before the fix the crawl never probed 10.0.20.0/24, so the PC was missing from the map."""
    from backend.database.session import SessionLocal
    from backend.models import Device, Network, User
    from backend.services.discovery import service

    class FakeEngine:
        probed: list[str] = []

        def probe(self, addresses):
            self.probed += list(addresses)
            return {"observations": [observation("icmp", ip, {"ttl": 128}, "Echo reply") for ip in addresses
                                     if ip in ("10.0.20.15", "10.0.30.9")]}

    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "admin").one()
        net = Network(name="vlans", network_type="Enterprise", description="", environment="real", source="discovery",
                      is_simulated=False, metadata_json={})
        db.add(net)
        db.flush()
        core = Device(network_id=net.id, name="CORE", device_type="switch", management_ip="10.0.10.2", x_position=0, y_position=0)
        db.add(core)
        db.flush()
        net.metadata_json = {
            "mode": "live", "target": "10.0.10.0/24", "method": "smart", "timeline": [], "no_response": [],
            "scope": {"authorised": ["10.0.10.0/24"], "excluded": ["10.0.30.0/24"]}, "swept": ["10.0.10.0/24"],
            "discovery": {str(core.id): {"ip": "10.0.10.2", "auth": "success", "type": "switch", "role": "Switch"}},
            "observations": [observation("icmp", "10.0.10.2", {"ttl": 255}),
                             observation("connected-subnets", "10.0.10.2", {"subnets": subnets.from_config(CORE_CONFIG)},
                                         authenticated=True, method="ssh", observed_by="10.0.10.2")]}
        db.commit()
        engine = FakeEngine()
        service.crawl(db, user, net, engine=engine, follow_neighbours=True)
        db.refresh(net)
        meta = net.metadata_json
        assert "10.0.20.15" in engine.probed and not any(ip.startswith("10.0.30.") for ip in engine.probed)
        assert "10.0.20.0/24" in meta["swept"]
        assert {row["cidr"]: row["reason"] for row in meta["subnets_not_scanned"]}["10.0.30.0/24"] == "excluded"
        assert "10.0.20.15" in {facts["ip"] for facts in meta["discovery"].values()}
        result = client.get(f"/api/discovery/{net.id}", headers=auth).json()
        assert "10.0.20.0/24" in result["subnets"]["scanned"]
