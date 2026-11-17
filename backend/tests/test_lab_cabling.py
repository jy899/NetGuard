"""A cable removed from an imported lab is reported; IOL images are routers, not Linux servers."""
import base64

from backend.collectors import packet_tracer
from backend.collectors.labs import _kind
from backend.tests.test_project_import import PT_XML, _post

UNL = """<?xml version="1.0"?><lab name="Edge" id="x"><topology><nodes>
<node id="1" name="ISP1" type="qemu" template="mikrotik" image="mikrotik-7"><interface id="0" name="ether1" type="ethernet" network_id="1"/></node>
<node id="2" name="FW" type="qemu" template="fortinet" image="fortinet-7"><interface id="0" name="port1" type="ethernet" network_id="1"/><interface id="1" name="port2" type="ethernet" network_id="2"/></node>
<node id="3" name="PC-001" type="qemu" template="linux" image="linux-slax"><interface id="0" name="eth0" type="ethernet" network_id="2"/></node>
</nodes><networks><network id="1" type="bridge" name="n1"/><network id="2" type="bridge" name="n2"/></networks></topology></lab>"""


def _health(client, auth, nid):
    return client.get(f"/api/networks/{nid}/health-check", headers=auth).json()


def test_removed_lab_cable_is_not_reported_healthy(client, auth):
    nid = _post(client, auth, [("edge.unl", UNL.encode())]).json()["network_id"]
    assert _health(client, auth, nid)["cabling_count"] == 0
    links = client.get(f"/api/networks/{nid}/topology", headers=auth).json()["links"]
    pc_link = next(l for l in links if "PC-001" in (l["source_device_name"], l["destination_device_name"]))
    assert client.delete(f"/api/links/{pc_link['id']}", headers=auth).status_code == 204
    report = _health(client, auth, nid)
    assert report["status"] == "issues" and report["cabling_count"] == 1
    finding = report["cabling_findings"][0]
    assert finding["severity"] == "HIGH" and "PC-001 now has no connection" in finding["detail"]
    # An intended redesign: accepting the current cabling clears the finding.
    assert client.post(f"/api/networks/{nid}/cabling-baseline", headers=auth).json()["cables"] == 1
    assert _health(client, auth, nid)["cabling_count"] == 0


def test_removed_cable_in_packet_tracer_project_fails_the_flow_and_is_listed(client, auth):
    nid = _post(client, auth, [("branch.pkt", packet_tracer.encode(PT_XML))]).json()["network_id"]
    links = client.get(f"/api/networks/{nid}/topology", headers=auth).json()["links"]
    victim = next(l for l in links if {l["source_device_name"], l["destination_device_name"]} == {"SRV1", "R1"})
    client.delete(f"/api/links/{victim['id']}", headers=auth)
    report = _health(client, auth, nid)
    assert report["status"] == "issues" and report["failing_flow_count"] == 1 and report["cabling_count"] == 1


def test_manual_networks_have_no_cabling_baseline(client, auth):
    net = client.post("/api/networks", headers=auth, json={"name": "Manual"}).json()
    assert _health(client, auth, net["id"])["cabling_count"] == 0
    assert client.post(f"/api/networks/{net['id']}/cabling-baseline", headers=auth).status_code == 422


def test_cisco_iol_and_router_images_are_not_linux_servers():
    assert _kind("iol", "i86bi-linux-l3-adventerprisek9") == "router"
    assert _kind("iol", "i86bi-linux-l2-ipbasek9") == "switch"
    assert _kind("vios", "vios-adventerprisek9") == "router"
    assert _kind("mikrotik", "mikrotik-7.1") == "router"
    assert _kind("linux", "linux-slax", name="PC-001") == "pc"
    assert _kind("linux", "linux-ubuntu-server", name="Web-Server") == "server"
    assert _kind("fortinet", "fortinet-FGT-v7") == "firewall"
    assert _kind("vpcs") == "pc"
