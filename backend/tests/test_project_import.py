"""Topology project import: Packet Tracer, GNS3 and EVE-NG files, configuration bundles and single devices."""
import base64
import io
import json
import zipfile

from backend.collectors import packet_tracer

R1 = """hostname R1
interface GigabitEthernet0/0
 ip address 192.168.10.1 255.255.255.0
interface GigabitEthernet0/1
 ip address 192.168.20.1 255.255.255.0
"""
SW1 = """hostname SW1
vlan 10
interface FastEthernet0/1
 switchport mode access
 switchport access vlan 10
interface FastEthernet0/2
 switchport mode access
 switchport access vlan 10
"""


def _lines(text):
    return "".join(f"<LINE>{line}</LINE>" for line in text.splitlines())


PT_XML = f"""<PACKETTRACER5><VERSION>8.2.1.0118</VERSION><NETWORK><DEVICES>
<DEVICE><ENGINE><TYPE model="2911">Router</TYPE><NAME>R1</NAME><SAVE_REF_ID>save-ref-id:1</SAVE_REF_ID>
 <RUNNINGCONFIG>{_lines(R1)}</RUNNINGCONFIG></ENGINE><WORKSPACE><LOGICAL><X>300</X><Y>100</Y></LOGICAL></WORKSPACE></DEVICE>
<DEVICE><ENGINE><TYPE model="2960-24TT">Switch</TYPE><NAME>SW1</NAME><SAVE_REF_ID>save-ref-id:2</SAVE_REF_ID>
 <RUNNINGCONFIG>{_lines(SW1)}</RUNNINGCONFIG></ENGINE></DEVICE>
<DEVICE><ENGINE><TYPE model="PC-PT">Pc</TYPE><NAME>PC1</NAME><SAVE_REF_ID>save-ref-id:3</SAVE_REF_ID>
 <MODULE><PORT><TYPE>eCopperFastEthernet</TYPE><IP>192.168.10.10</IP><SUBNET>255.255.255.0</SUBNET></PORT></MODULE>
 <GATEWAY>192.168.10.1</GATEWAY></ENGINE></DEVICE>
<DEVICE><ENGINE><TYPE model="Server-PT">Server</TYPE><NAME>SRV1</NAME><SAVE_REF_ID>save-ref-id:4</SAVE_REF_ID>
 <MODULE><PORT><IP>192.168.20.10</IP><SUBNET>255.255.255.0</SUBNET></PORT></MODULE>
 <GATEWAY>192.168.20.1</GATEWAY></ENGINE></DEVICE>
</DEVICES><LINKS>
<LINK><CABLE><FROM>save-ref-id:1</FROM><PORT>GigabitEthernet0/0</PORT><TO>save-ref-id:2</TO><PORT>FastEthernet0/1</PORT></CABLE></LINK>
<LINK><CABLE><FROM>save-ref-id:3</FROM><PORT>FastEthernet0</PORT><TO>save-ref-id:2</TO><PORT>FastEthernet0/2</PORT></CABLE></LINK>
<LINK><CABLE><FROM>save-ref-id:4</FROM><PORT>FastEthernet0</PORT><TO>save-ref-id:1</TO><PORT>GigabitEthernet0/1</PORT></CABLE></LINK>
</LINKS></NETWORK>
<SCENARIOSET><SCENARIO><PDU><SOURCE>PC1</SOURCE><DESTINATION>SRV1</DESTINATION></PDU></SCENARIO></SCENARIOSET>
</PACKETTRACER5>"""


def _post(client, auth, files, name=None):
    body = {"files": [{"name": n, "content": base64.b64encode(d).decode()} for n, d in files]}
    if name:
        body["name"] = name
    return client.post("/api/networks/import-project", headers=auth, json=body)


def _topology(client, auth, nid):
    topo = client.get(f"/api/networks/{nid}/topology", headers=auth).json()
    return topo, {d["name"]: d for d in topo["devices"]}


def test_packet_tracer_project_imports_devices_cables_configs_endpoints_and_scenarios(client, auth):
    response = _post(client, auth, [("branch.pkt", packet_tracer.encode(PT_XML))])
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["kind"] == "packet-tracer" and result["scenario_flows"] == 1
    topo, devices = _topology(client, auth, result["network_id"])
    assert set(devices) == {"R1", "SW1", "PC1", "SRV1"} and len(topo["links"]) == 3
    assert {l["evidence_grade"] for l in topo["links"]} == {"Confirmed"}
    assert devices["SW1"]["device_type"] == "switch" and devices["PC1"]["default_gateway"] == "192.168.10.1"
    assert any(i["ip_address"] == "192.168.10.10" for i in devices["PC1"]["interfaces"])
    assert not any(d["is_lab"] for d in topo["devices"])  # a project file is not a running lab
    report = client.get(f"/api/networks/{result['network_id']}/health-check", headers=auth).json()
    assert report["flows"] and all(f["ok"] for f in report["flows"]), report["flows"]


def test_damaged_packet_tracer_file_is_rejected_with_a_clear_message(client, auth):
    response = _post(client, auth, [("broken.pkt", b"\x00" * 200)])
    assert response.status_code == 422 and "Packet Tracer" in response.json()["detail"]


def test_gns3_portable_project_reads_links_and_node_startup_files(client, auth):
    project = {"name": "Campus", "project_id": "p-1", "topology": {
        "nodes": [{"node_id": "n1", "name": "R1", "node_type": "dynamips", "properties": {"platform": "c7200", "dynamips_id": 1}},
                  {"node_id": "n2", "name": "PC1", "node_type": "vpcs"},
                  {"node_id": "n3", "name": "PC2", "node_type": "vpcs"}],
        "links": [{"nodes": [{"node_id": "n1", "adapter_number": 0, "port_number": 0, "label": {"text": "f0/0"}},
                             {"node_id": "n2", "adapter_number": 0, "port_number": 0}]},
                  {"nodes": [{"node_id": "n1", "adapter_number": 1, "port_number": 0, "label": {"text": "f1/0"}},
                             {"node_id": "n3", "adapter_number": 0, "port_number": 0}]}]}}
    router = "hostname R1\ninterface FastEthernet0/0\n ip address 10.0.1.1 255.255.255.0\ninterface FastEthernet1/0\n ip address 10.0.2.1 255.255.255.0\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("project.gns3", json.dumps(project))
        archive.writestr("project-files/dynamips/n1/configs/i1_startup-config.cfg", router)
        archive.writestr("project-files/vpcs/n2/startup.vpc", "set pcname PC1\nip 10.0.1.10 255.255.255.0 10.0.1.1\n")
        archive.writestr("project-files/vpcs/n3/startup.vpc", "ip 10.0.2.10/24 10.0.2.1\n")
    response = _post(client, auth, [("campus.gns3project", buffer.getvalue())])
    assert response.status_code == 201, response.text
    _, devices = _topology(client, auth, response.json()["network_id"])
    assert {i["name"]: i["ip_address"] for i in devices["R1"]["interfaces"]}["Fa0/0"] == "10.0.1.1"
    assert devices["PC2"]["default_gateway"] == "10.0.2.1"
    assert response.json()["inferred_flows"] == 1  # PC1 <-> PC2 through R1


def test_eve_ng_lab_file_with_base64_configs(client, auth):
    unl = f"""<?xml version="1.0"?><lab name="Edge" id="x">
<topology><nodes>
<node id="1" name="R1" type="iol" template="iol" image="i86bi" left="100" top="100">
 <interface id="0" name="e0/0" type="ethernet" network_id="1"/></node>
<node id="2" name="PC1" type="vpcs" template="vpcs" left="100" top="300">
 <interface id="0" name="eth0" type="ethernet" network_id="1"/></node>
</nodes><networks><network id="1" type="bridge" name="Net1" visibility="0"/></networks></topology>
<objects><configs>
<config id="1">{base64.b64encode(b"hostname R1\ninterface Ethernet0/0\n ip address 10.5.0.1 255.255.255.0\n").decode()}</config>
<config id="2">{base64.b64encode(b"ip 10.5.0.10 255.255.255.0 10.5.0.1").decode()}</config>
</configs></objects></lab>"""
    response = _post(client, auth, [("edge.unl", unl.encode())])
    assert response.status_code == 201, response.text
    topo, devices = _topology(client, auth, response.json()["network_id"])
    assert len(topo["links"]) == 1 and devices["PC1"]["default_gateway"] == "10.5.0.1"
    assert {i["name"]: i["ip_address"] for i in devices["R1"]["interfaces"]}["Et0/0"] == "10.5.0.1"


def test_configuration_bundle_zip_and_single_device_with_neighbour_inference(client, auth):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("configs/R1.cfg", R1)
        archive.writestr("configs/SW1.txt", SW1)
    bundle = _post(client, auth, [("site.zip", buffer.getvalue())])
    assert bundle.status_code == 201, bundle.text
    assert bundle.json()["summary"]["devices"] == 2 and not bundle.json()["single_device"]

    edge = "interface GigabitEthernet0/0\n ip address 10.9.9.1 255.255.255.252\ninterface GigabitEthernet0/1\n ip address 10.1.1.1 255.255.255.0\nip route 0.0.0.0 0.0.0.0 10.9.9.2\n"
    single = _post(client, auth, [("EDGE-RTR.cfg", edge.encode())])
    assert single.status_code == 201, single.text
    result = single.json()
    assert result["single_device"] and len(result["next_steps"]) == 2
    _, devices = _topology(client, auth, result["network_id"])
    assert set(devices) == {"EDGE-RTR"}  # the file name becomes the hostname
    inferred = client.post(f"/api/networks/{result['network_id']}/infer-neighbours", headers=auth).json()
    assert len(inferred["devices"]) == 2 and inferred["links"] == 2
    topo, devices = _topology(client, auth, result["network_id"])
    assert {l["evidence_grade"] for l in topo["links"]} == {"Logical"}
    peer = next(d for name, d in devices.items() if name.startswith("Peer-"))
    assert peer["interfaces"][0]["ip_address"] == "10.9.9.2"
