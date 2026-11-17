"""Up/down monitoring of discovered devices (no credentials, authorised scope only)."""
from backend.tests.fixtures.sample_engine import SimulatedDiscoveryEngine
from backend.tests.test_smart_discovery import by_name, scan


def test_reachability_marks_each_discovered_device_up_or_down(client, auth, monkeypatch):
    result = scan(client, auth)
    nid = result["network"]["id"] if "network" in result else result["network_id"]
    devices = by_name(client.get(f"/api/discovery/{nid}", headers=auth).json())
    pc = next(row for row in devices.values() if row["type"] == "pc" and row["ip"])
    monkeypatch.setattr(SimulatedDiscoveryEngine, "down", {pc["ip"]})
    response = client.post(f"/api/discovery/{nid}/reachability", headers=auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["down"] == 1 and body["up"] >= 5
    assert body["devices"][str(pc["id"])]["state"] == "down"
    first_change = body["devices"][str(pc["id"])]["since"]
    # Stored for the map, and the "since" time is kept while the state does not change.
    again = client.post(f"/api/discovery/{nid}/reachability", headers=auth).json()
    assert again["devices"][str(pc["id"])]["since"] == first_change
    meta = client.get(f"/api/networks/{nid}", headers=auth).json()["metadata_json"]
    assert meta["reachability"]["down"] == 1
    assert meta["discovery"][str(pc["id"])]["reachability"]["state"] == "down"


def test_reachability_is_only_for_discovered_networks(client, auth):
    net = client.post("/api/networks", headers=auth, json={"name": "Manual"}).json()
    response = client.post(f"/api/discovery/{net['id']}/reachability", headers=auth)
    assert response.status_code in (400, 422)


def test_live_check_falls_back_to_tcp_when_icmp_is_dropped(monkeypatch):
    import ipaddress
    from backend.collectors import netutil
    from backend.services.discovery.real_engine import RealDiscoveryEngine
    monkeypatch.setattr(netutil, "ping", lambda ip, timeout_ms=800: ip == "10.0.0.1")
    monkeypatch.setattr(netutil, "tcp_open", lambda ip, port, timeout=0.7: (ip, port) == ("10.0.0.2", 8443))
    engine = RealDiscoveryEngine(ipaddress.IPv4Network("10.0.0.0/24"))
    result = engine.reachable({"10.0.0.1": [], "10.0.0.2": [443, 8443], "10.0.0.3": []})
    assert result["10.0.0.1"] == {"state": "up", "via": "ICMP echo"}
    assert result["10.0.0.2"] == {"state": "up", "via": "TCP 8443"}
    assert result["10.0.0.3"]["state"] == "down"
