"""Import a complete topology from project files: Cisco Packet Tracer (.pkt, .pka), GNS3 (.gns3, .gns3project),
EVE-NG (.unl, exported .zip) and bundles of device configurations (.cfg, .txt, .conf, or a .zip of them).

Project files carry the whole lab: devices, cables (graded Confirmed: the lab definition is the cabling record),
startup configurations and endpoint addressing (VPCS, Linux hosts, Packet Tracer PCs). Required traffic flows are
taken from the project where it defines them (Packet Tracer PDU scenarios) and otherwise inferred from the
analysis expectations (every host pair that should communicate: see infer_intents). A single standalone device
configuration is imported as that device; the result says so, and the engineer can add the neighbour configurations
or let NetGuard infer the connected subnets and neighbours (infer_neighbours).
"""
from __future__ import annotations

import base64
import io
import ipaddress as ipa
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import PurePosixPath

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.collectors import labs, packet_tracer
from backend.core.errors import ValidationFailed
from backend.models import Device, Interface, Link, Network, NetworkIntent
from backend.services import config_import, history_service, lab_import_service, network_service
from backend.services.demo_topology import _available_name

CONFIG_EXT = {".cfg", ".txt", ".conf", ".ios", ".config", ".log", ""}
MAX_BYTES = 60 * 1024 * 1024
MAX_FILES = 200


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _ext(name: str) -> str:
    return PurePosixPath(name.lower()).suffix


def decode_files(files: list[dict]) -> list[tuple[str, bytes]]:
    """[{"name", "content" (base64)}] from the browser."""
    out, total = [], 0
    for item in files[:MAX_FILES]:
        try:
            data = base64.b64decode(item.get("content") or "", validate=False)
        except (ValueError, TypeError):
            raise ValidationFailed(f"{item.get('name')}: the file could not be read") from None
        total += len(data)
        if total > MAX_BYTES:
            raise ValidationFailed("The files are larger than 60 MB together")
        out.append((PurePosixPath(str(item.get("name") or "file").replace("\\", "/")).name, data))
    if not out:
        raise ValidationFailed("Choose at least one file to import")
    return out


def _unzip(data: bytes) -> list[tuple[str, bytes]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValidationFailed("The archive is not a valid ZIP file") from None
    entries, total = [], 0
    for info in archive.infolist():
        if info.is_dir() or info.file_size > MAX_BYTES:
            continue
        total += info.file_size
        if total > MAX_BYTES * 2:
            raise ValidationFailed("The archive expands to more than 120 MB")
        entries.append((info.filename.replace("\\", "/"), archive.read(info)))
    return entries


def _text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            text = data.decode(encoding)
            if "\x00" not in text[:2000]:
                return text
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", "replace")


# ------------------------------------------------------------------ detection
def detect(files: list[tuple[str, bytes]]) -> tuple[str, object]:
    """('packet-tracer', bytes) | ('gns3', (project dict, {path: bytes})) | ('eve-ng', xml text) | ('configs', [...])"""
    expanded: list[tuple[str, bytes]] = []
    for name, data in files:
        if _ext(name) in (".zip", ".gns3project", ".gns3p") or data[:4] == b"PK\x03\x04":
            inner = _unzip(data)
            gns3 = next(((n, d) for n, d in inner if n.endswith(".gns3")), None)
            if gns3 is not None:
                return "gns3", (json.loads(_text(gns3[1])), dict(inner))
            expanded += inner
        else:
            expanded.append((name, data))
    for name, data in expanded:
        ext = _ext(name)
        if ext in (".pkt", ".pka"):
            return "packet-tracer", data
        if ext == ".gns3":
            return "gns3", (json.loads(_text(data)), {})
        if ext == ".unl":
            return "eve-ng", _text(data)
        if ext == ".xml":
            head = _text(data[:400]).lstrip()
            if head.startswith("<PACKETTRACER") or "<PACKETTRACER" in head[:200]:
                return "packet-tracer", data
            if "<lab" in head[:300]:
                return "eve-ng", _text(data)
    configs = [(name, _text(data)) for name, data in expanded
               if _ext(name) in CONFIG_EXT and not name.endswith("/") and data.strip()]
    if not configs:
        raise ValidationFailed("No supported file found. Use .pkt/.pka (Packet Tracer), .gns3/.gns3project (GNS3), "
                               ".unl/.zip (EVE-NG) or device configurations (.cfg, .txt, .conf, .zip)")
    return "configs", configs


# ------------------------------------------------------------------ Packet Tracer
def _pt_topology(data: bytes, filename: str) -> tuple[labs.LabTopology, list[tuple[str, str, str]]]:
    try:
        xml = packet_tracer.decode(data)
        project = packet_tracer.parse(xml, PurePosixPath(filename).stem)
    except packet_tracer.PacketTracerError as exc:
        raise ValidationFailed(str(exc)) from None
    nodes, configs = [], {}
    for d in project.devices:
        platform = "cisco-ios" if d.kind in ("router", "switch", "firewall") else None
        nodes.append(labs.LabNode(ref=d.ref, name=d.name, kind=d.kind, template=d.model, console=None,
                                  status="running", bridge=False, platform=platform, x=d.x, y=d.y))
        if d.config and d.kind in ("router", "switch", "firewall"):
            configs[d.ref] = d.config
        elif d.ip:
            configs[d.ref] = f"ip {d.ip} {d.mask or '255.255.255.0'} {d.gateway or ''}".strip()
    links = [labs.LabLink(a, labs._port(ap, "cisco-ios") if ap else None, b, labs._port(bp, "cisco-ios") if bp else None)
             for a, ap, b, bp in project.links]
    return labs.LabTopology("packet-tracer", filename, project.name, nodes, links, configs), project.flows


# ------------------------------------------------------------------ GNS3 files
def _gns3_topology(project: dict, files: dict[str, bytes], filename: str) -> labs.LabTopology:
    topology = project.get("topology") or {}
    nodes, links_raw = topology.get("nodes") or [], topology.get("links") or []
    if not nodes:
        raise ValidationFailed("The GNS3 project has no nodes")
    configs = {}
    for node in nodes:
        node_id = node.get("node_id")
        if not node_id:
            continue
        candidates = [(path, data) for path, data in files.items() if f"/{node_id}/" in f"/{path}"]
        for wanted in ("startup-config.cfg", "startup.vpc", "frr.conf", "config.txt", "interfaces"):
            match = next((d for p, d in candidates if p.endswith(wanted) and "private" not in p), None)
            if match:
                configs[node_id] = _text(match)
                break
    for node in nodes:  # GNS3 keeps VPCS addressing in the node properties of older projects
        script = (node.get("properties") or {}).get("startup_script")
        if script and node.get("node_id") not in configs:
            configs[node["node_id"]] = script
    return labs.gns3_topology(project.get("project_id") or filename, project.get("name") or PurePosixPath(filename).stem,
                              nodes, links_raw, None, configs)


# ------------------------------------------------------------------ EVE-NG files
def _eve_topology(xml: str, filename: str) -> labs.LabTopology:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValidationFailed(f"The EVE-NG lab file could not be read ({exc})") from None
    nodes, membership = {}, {}
    for n in root.iter("node"):
        ref = n.get("id")
        if ref is None:
            continue
        node = labs.LabNode(ref=ref, name=n.get("name") or f"node{ref}",
                            kind=labs._kind(n.get("template"), n.get("image"), n.get("type")), template=n.get("template"),
                            console=None, status="stopped",
                            platform=labs._platform(n.get("template"), n.get("image"), n.get("type")),
                            x=labs._num(n.get("left")), y=labs._num(n.get("top")))
        for iface in n.iter("interface"):
            name = labs._port(iface.get("name"), node.platform)
            if name:
                node.interfaces.append(name)
            if iface.get("network_id") not in (None, "0", ""):
                membership.setdefault(str(iface.get("network_id")), []).append((ref, name))
        nodes[ref] = node
    networks = {n.get("id"): {"type": n.get("type"), "name": n.get("name"), "left": n.get("left"),
                              "top": n.get("top"), "visibility": n.get("visibility")} for n in root.iter("network")}
    links = labs.eve_links(nodes, networks, membership)
    configs = {}
    for cfg in root.iter("config"):
        try:
            text = base64.b64decode(cfg.text or "").decode("utf-8", "replace")
        except ValueError:
            text = cfg.text or ""
        if cfg.get("id") in nodes and text.strip():
            configs[cfg.get("id")] = text
    name = root.get("name") or PurePosixPath(filename).stem
    return labs.LabTopology("eve-ng", filename, name, list(nodes.values()), links, configs)


# ------------------------------------------------------------------ import
def _bundle_text(configs: list[tuple[str, str]]) -> str:
    parts = []
    for name, text in configs:
        if not re.search(r"^hostname\s+\S+", text, re.M) and not re.search(r"^[\w.-]+[#>]", text, re.M):
            text = f"hostname {re.sub(r'[^A-Za-z0-9_.-]', '-', PurePosixPath(name).stem) or 'Device'}\n" + text
        parts.append(text.rstrip() + "\n!")
    return "\n".join(parts)


def import_project(db: Session, user, files: list[tuple[str, bytes]], name: str | None = None) -> dict:
    kind, payload = detect(files)
    filename = files[0][0]
    if kind == "configs":
        result = config_import.import_network(db, user, name or PurePosixPath(filename).stem or "Imported network",
                                              _bundle_text(payload))
        network = network_service.get_network(db, result["network_id"])
        inferred = infer_intents(db, network)
        summary = result["summary"]
        single = summary["devices"] == 1
        return {"network_id": network.id, "kind": "configs", "summary": summary, "warnings": result["warnings"],
                "inferred_flows": inferred, "single_device": single,
                "next_steps": ["Add the configurations of the neighbouring devices to build the connections",
                               "Let NetGuard infer the connected subnets and neighbours from this configuration"]
                if single else []}
    flows: list[tuple[str, str, str]] = []
    if kind == "packet-tracer":
        topology, flows = _pt_topology(payload, filename)
    elif kind == "gns3":
        topology = _gns3_topology(payload[0], payload[1], filename)
    else:
        topology = _eve_topology(payload, filename)
    label = lab_import_service.PROVIDER_LABEL[topology.provider]
    network = Network(
        name=_available_name(db, name or f"{label}: {topology.name}"), network_type="Lab",
        description=f"{label} project '{topology.name}' imported from {filename}.", created_by=user.id,
        environment="virtual", source=topology.provider, is_simulated=False,
        metadata_json={"provider": topology.provider, "project_file": filename, "lab_name": topology.name,
                       "imported_at": _now(), "interface_naming_version": 1, "live_device_contact": False,
                       "scope": {"authorised": [], "excluded": [], "untrusted": []}})
    db.add(network)
    db.flush()
    lab_import_service._sync(db, user, network, topology, lab=False)
    db.flush()
    by_ref = {d.access.get("node"): d for d in db.scalars(select(Device).where(Device.network_id == network.id))
              if d.access}
    explicit = 0
    for src, dst, protocol in flows:
        a, b = by_ref.get(src), by_ref.get(dst)
        if a and b:
            db.add(NetworkIntent(network_id=network.id, name=f"{a.name} → {b.name} (project scenario)",
                                 source_device_id=a.id, destination_device_id=b.id, protocol=protocol,
                                 expected_action="allow", criticality="high"))
            explicit += 1
    db.commit()
    inferred = 0 if explicit else infer_intents(db, network)
    out = network_service.to_out(db, network).model_dump(mode="json")
    history_service.record(db, user, network.id, "connection", f"{label} project imported",
                           {"device_count": out["device_count"], "link_count": out["link_count"], "status": "completed"},
                           {"file": filename, "nodes": len(topology.nodes), "links": len(topology.links),
                            "startup_configs": len(topology.configs), "flows": explicit or inferred})
    return {"network_id": network.id, "kind": topology.provider,
            "summary": {"devices": out["device_count"], "links": out["link_count"],
                        "configurations": len(topology.configs), "flows": explicit + inferred},
            "warnings": (network.metadata_json or {}).get("lab_warnings", []), "inferred_flows": inferred,
            "scenario_flows": explicit, "single_device": False, "next_steps": []}


# ------------------------------------------------------------------ inference
MAX_INFERRED = 60


def infer_intents(db: Session, network: Network) -> int:
    """Required flows from the analysis expectations: every host pair expected to communicate.

    A pair that works, or fails for an addressing, VLAN, link or routing reason, is required; a pair an ACL denies
    is treated as intentional isolation and left out; hosts on a segment without a router are isolated by design.
    Nothing is inferred when the network already has required flows or more than MAX_INFERRED pairs qualify."""
    from backend.services import impact_engine
    from backend.services.forwarding import FlowAnalyzer
    from backend.services.network_model import load_model

    if db.scalar(select(NetworkIntent.id).where(NetworkIntent.network_id == network.id).limit(1)):
        return 0
    model = load_model(db, network.id)
    analyzer = FlowAnalyzer(model)
    flows = [f for f in impact_engine.build_flows(model, analyzer, audit=True)
             if f.kind == "implicit" and f.expected == "allow"]
    if not flows or len(flows) > MAX_INFERRED:
        return 0
    for flow in flows:
        db.add(NetworkIntent(network_id=network.id, name=f"{flow.src_name} ↔ {flow.dst_name} (inferred)",
                             source_device_id=flow.src, destination_device_id=flow.dst, protocol="ip",
                             expected_action="allow", criticality="medium"))
    meta = dict(network.metadata_json or {})
    meta["inferred_intents"] = len(flows)
    network.metadata_json = meta
    db.commit()
    return len(flows)


def infer_neighbours(db: Session, user, network: Network) -> dict:
    """For devices without connection evidence: a stub neighbour per point-to-point subnet and per static-route next
    hop that no device owns, and a LAN segment per routed LAN subnet. Every created item is graded Logical and
    labelled as inferred, so it is never mistaken for a discovered device or cable."""
    devices = list(db.scalars(select(Device).where(Device.network_id == network.id)))
    links = list(db.scalars(select(Link).where(Link.network_id == network.id)))
    owned = {i.ip_address for d in devices for i in d.interfaces if i.ip_address}
    cabled = {iid for l in links for iid in (l.source_interface_id, l.destination_interface_id)}
    created_devices, created_links = [], 0
    taken = {d.name for d in devices}

    def new_device(name, kind, x, y, iface_name, ip, mask, note):
        base, n = name[:60], 1
        while name in taken:
            n += 1
            name = f"{base}-{n}"
        taken.add(name)
        device = Device(network_id=network.id, name=name, device_type=kind, x_position=x, y_position=y,
                        config_facts={"inferred": note})
        db.add(device)
        db.flush()
        iface = Interface(device_id=device.id, name=iface_name, ip_address=ip, subnet_mask=mask, status="up",
                          mode="access" if kind == "switch" else None, vlan_id=1 if kind == "switch" else None)
        db.add(iface)
        db.flush()
        created_devices.append(device.name)
        return device, iface

    def link(a, ia, b, ib, why):
        nonlocal created_links
        db.add(Link(network_id=network.id, source_device_id=a.id, source_interface_id=ia.id, destination_device_id=b.id,
                    destination_interface_id=ib.id, kind="logical", state="up", confidence=0.4,
                    evidence_json=json.dumps({"evidence": [why], "missing": ["Neighbour or cable evidence"],
                                              "origin": "inferred", "status": "logical", "grade": "Logical"})))
        created_links += 1

    for device in devices:
        if device.device_type not in ("router", "firewall", "switch"):
            continue
        for index, iface in enumerate(i for i in device.interfaces if i.ip_address and i.subnet_mask and i.id not in cabled):
            net = ipa.IPv4Interface(f"{iface.ip_address}/{iface.subnet_mask}").network
            x, y = (device.x_position or 0) + 220, (device.y_position or 0) + 160 * index
            if net.prefixlen >= 30:
                peer_ip = next((str(h) for h in (net.hosts() if net.prefixlen < 31 else net) if str(h) != iface.ip_address), None)
                if not peer_ip or peer_ip in owned:
                    continue
                stub, stub_if = new_device(f"Peer-{device.name}-{iface.name.replace('/', '_')}", "router", x, y, "Gi0/0",
                                           peer_ip, iface.subnet_mask, f"point-to-point peer of {device.name} {iface.name}")
                owned.add(peer_ip)
                link(device, iface, stub, stub_if, f"{device.name} {iface.name} is in point-to-point subnet {net}; "
                                                    f"its peer {peer_ip} is not in the imported configurations.")
            elif device.device_type != "switch":
                lan, lan_if = new_device(f"LAN-{net.network_address}_{net.prefixlen}", "switch", x, y, "Gi0/1", None, None,
                                         f"LAN segment {net} behind {device.name} {iface.name}")
                link(device, iface, lan, lan_if, f"{device.name} {iface.name} routes LAN {net}; the switches and hosts "
                                                 "of this LAN are not in the imported configurations.")
        for route in device.static_routes:
            if route.next_hop in owned:
                continue
            local = next((i for i in device.interfaces if i.ip_address and i.subnet_mask and
                          ipa.IPv4Address(route.next_hop) in ipa.IPv4Interface(f"{i.ip_address}/{i.subnet_mask}").network), None)
            if local is None or local.id in cabled:
                continue
            stub, stub_if = new_device(f"NextHop-{route.next_hop}", "router", (device.x_position or 0) - 220,
                                       device.y_position or 0, "Gi0/0", route.next_hop, local.subnet_mask,
                                       f"next hop of {device.name} route {route.destination}")
            owned.add(route.next_hop)
            cabled.add(local.id)
            link(device, local, stub, stub_if, f"{device.name} routes {route.destination} via {route.next_hop}, which no "
                                               "imported device owns.")
    meta = dict(network.metadata_json or {})
    meta["inferred_neighbours"] = {"devices": created_devices, "links": created_links, "at": _now()}
    network.metadata_json = meta
    network_service.touch(network)
    db.commit()
    return {"devices": created_devices, "links": created_links}
