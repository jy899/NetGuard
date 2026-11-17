"""Routed VLAN / segment traversal inside a wider scope the engineer authorised (credential-free, budgeted)."""
import ipaddress

from backend.services.discovery import service
from backend.services.discovery.engine import observation
from backend.services.discovery import subnets

# Segments that exist behind the router: gateway .254 answers; two hosts each.
LIVE = {"10.1.20.0/24": "10.1.20.254", "10.1.30.0/24": "10.1.30.1", "10.1.40.0/24": "10.1.40.254"}
OUTSIDE = "10.2.0.0/24"  # exists, but outside the authorised scope: must never be contacted
contacted: list[str] = []


class FakeEngine:
    simulated = True

    def __init__(self, target, excluded=None):
        self.target = ipaddress.IPv4Network(target)
        contacted.append(str(self.target))

    def _hosts(self):
        net = str(self.target)
        if net in LIVE:
            return [LIVE[net], str(self.target.network_address + 10), str(self.target.network_address + 11)]
        if net == "10.1.10.0/24":
            return ["10.1.10.1", "10.1.10.50"]
        return []

    def probe(self, addresses=None, progress=None):
        obs = [observation("icmp", ip, {"reachable": True}, f"ICMP echo reply from {ip}.", simulated=True) for ip in self._hosts()]
        return {"observations": obs, "timeline": [{"id": "sweep", "label": "Sweep", "detail": "", "count": len(obs)}], "no_response": []}

    def segment_gateways(self, segments):
        for cidr in segments:
            assert ipaddress.IPv4Network(cidr).subnet_of(ipaddress.IPv4Network("10.1.0.0/16"))
        return {cidr: {"gateway": LIVE[cidr], "via": "ICMP echo"} for cidr in segments if cidr in LIVE}

    def local_subnets(self):
        return ["10.1.10.0/24", "192.168.99.0/24"]  # the second is outside the scope: ignored


def _scan(client, auth, **extra):
    return client.post("/api/discovery/scan", headers=auth, json={"target": "10.1.10.0/24", "authorized_scope": True, **extra})


def test_scan_traverses_routed_segments_inside_the_authorised_scope(client, auth, monkeypatch):
    contacted.clear()
    monkeypatch.setattr(service, "engine_factory", FakeEngine)
    response = _scan(client, auth, traverse_scope="10.1.0.0/16")
    assert response.status_code == 201, response.text
    body = response.json()
    ips = {row["ip"] for row in body["devices"]}
    assert {"10.1.20.254", "10.1.30.11", "10.1.40.10"} <= ips and "10.1.10.50" in ips
    meta = client.get(f"/api/networks/{body['network_id']}", headers=auth).json()["metadata_json"]
    segments = meta["segments"]
    assert set(segments["swept"]) == set(LIVE)
    assert segments["probed"] == 255                       # every /24 of the /16 except the one scanned
    assert "10.1.0.0/16" in meta["scope"]["authorised"] and meta["scope"]["traverse"] == "10.1.0.0/16"
    assert OUTSIDE not in contacted and not any(c.startswith("192.168.") for c in contacted)


def test_traversal_scope_is_bounded_and_must_contain_the_range(client, auth, monkeypatch):
    monkeypatch.setattr(service, "engine_factory", FakeEngine)
    assert _scan(client, auth, traverse_scope="10.0.0.0/8").status_code == 422
    assert _scan(client, auth, traverse_scope="10.2.0.0/16").status_code == 422
    assert _scan(client, auth, traverse_scope="not-a-range").status_code == 422


def test_segment_budget_reports_what_was_left_out(monkeypatch):
    rows = [{"cidr": f"10.1.{n}.0/24", "interface": None, "ip": f"10.1.{n}.1", "source": "gateway-probe"} for n in range(1, 30)]
    todo, left = subnets.plan(rows, ["10.1.0.0/16"], [], [], False)
    assert len(todo) == subnets.MAX_SUBNETS
    assert all(r["reason"].startswith("sweep limit") for r in left)
    # Credential-free rows never follow outside the scope, even with follow-neighbours on.
    todo, left = subnets.plan([{"cidr": "172.16.5.0/24", "interface": None, "ip": "172.16.5.1", "source": "gateway-probe"}],
                              ["10.1.0.0/16"], [], [], True)
    assert not todo and left[0]["reason"] == "outside the authorised scope"


def test_excluded_segments_are_never_probed():
    plan = subnets.segments_to_probe("10.1.0.0/22", ["10.1.0.0/24"], ["10.1.2.0/24", "10.1.3.254/32"])
    assert set(plan) == {"10.1.1.0/24", "10.1.3.0/24"}
    assert plan["10.1.3.0/24"] == ["10.1.3.1"]
