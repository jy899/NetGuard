"""Builds the recommended demo topology from the master brief (section 5.3).

This is sample data only; it is created through the same models as any
user-built network and can be edited or deleted like any other network.

                 INTERNET
                    |
                   FW1
                    |
                    R1
                 /      \\
               R2        R3
               |          |
              SW1        SW2
             /   \\      /   \\
     Finance-PC HR-PC   ERP   DNS

Addressing / configuration supports brief scenarios A-E (section 7.7):
  R1-R2 10.0.12.0/30 and R1-R3 10.0.13.0/30, OSPF area 0
  Finance VLAN 10 10.20.0.0/24 and HR VLAN 20 10.21.0.0/24 on R2 sub-interfaces (router-on-a-stick)
  Server VLAN 30 192.168.30.0/24 behind R3 Gi0/0/1 (ERP .10, DNS .53)
  R1 default route to FW1, advertised into OSPF so R2 and R3 reach the internet through R1 and FW1;
  R2 ACL isolates HR from Finance; R3 ACL protects servers (permit all baseline)
"""
from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.models import AclRule, Device, Interface, Link, Network, NetworkIntent, StaticRoute, User, Vlan

DEMO_NETWORK_NAME = "HQ Enterprise Network"
DEMO_DESCRIPTION = "Demo enterprise network for NetGuard"
FAULTY_DESCRIPTION = "Demo network with injected faults for the NetGuard Health Check"

# name, type, vendor, model, mgmt ip, default gateway, x, y
_DEVICES = [
    ("INTERNET", "internet", None, None, None, None, 0, -540),
    ("FW1", "firewall", "Fortinet", "FortiGate 60F", "192.168.1.254", None, 0, -360),
    ("R1", "router", "Cisco", "ISR 4331", "192.168.1.1", None, 0, -180),
    ("R2", "router", "Cisco", "ISR 4331", "192.168.1.2", None, -260, 0),
    ("R3", "router", "Cisco", "ISR 4331", "192.168.1.3", None, 260, 0),
    ("SW1", "switch", "Cisco", "Catalyst 2960X-24TS-L", "192.168.1.11", None, -260, 180),
    ("SW2", "switch", "Cisco", "Catalyst 2960X-24TS-L", "192.168.1.12", None, 260, 180),
    ("Finance-PC", "pc", "Dell", "OptiPlex 7010", None, "10.20.0.1", -380, 360),
    ("HR-PC", "pc", "Dell", "OptiPlex 7010", None, "10.21.0.1", -140, 360),
    ("ERP", "server", "Dell", "PowerEdge R650", None, "192.168.30.1", 140, 360),
    ("DNS", "server", "Dell", "PowerEdge R350", None, "192.168.30.1", 380, 360),
]

# device, interface, ip, mask, vlan, ospf area, switchport mode
_INTERFACES = [
    ("INTERNET", "isp", "203.0.113.1", "255.255.255.252", None, None, None),
    ("FW1", "wan1", "203.0.113.2", "255.255.255.252", None, None, None),
    ("FW1", "internal1", "10.0.1.1", "255.255.255.252", None, None, None),
    ("R1", "Gi0/0/0", "10.0.12.1", "255.255.255.252", None, 0, None),
    ("R1", "Gi0/0/1", "10.0.13.1", "255.255.255.252", None, 0, None),
    ("R1", "Gi0/0/2", "10.0.1.2", "255.255.255.252", None, None, None),
    ("R2", "Gi0/0/0", "10.0.12.2", "255.255.255.252", None, 0, None),
    ("R2", "Gi0/0/1", None, None, None, None, None),
    ("R2", "Gi0/0/1.10", "10.20.0.1", "255.255.255.0", 10, 0, None),
    ("R2", "Gi0/0/1.20", "10.21.0.1", "255.255.255.0", 20, 0, None),
    ("R3", "Gi0/0/0", "10.0.13.2", "255.255.255.252", None, 0, None),
    ("R3", "Gi0/0/1", "192.168.30.1", "255.255.255.0", None, 0, None),
    ("SW1", "Gi1/0/24", None, None, None, None, "trunk"),
    ("SW1", "Gi1/0/1", None, None, 10, None, "access"),
    ("SW1", "Gi1/0/2", None, None, 20, None, "access"),
    ("SW2", "Gi1/0/24", None, None, 30, None, "access"),
    ("SW2", "Gi1/0/1", None, None, 30, None, "access"),
    ("SW2", "Gi1/0/2", None, None, 30, None, "access"),
    ("Finance-PC", "eth0", "10.20.0.10", "255.255.255.0", None, None, None),
    ("HR-PC", "eth0", "10.21.0.10", "255.255.255.0", None, None, None),
    ("ERP", "eth0", "192.168.30.10", "255.255.255.0", None, None, None),
    ("DNS", "eth0", "192.168.30.53", "255.255.255.0", None, None, None),
]

# (source device, source interface), (destination device, destination interface)
_LINKS = [
    (("INTERNET", "isp"), ("FW1", "wan1")),
    (("FW1", "internal1"), ("R1", "Gi0/0/2")),
    (("R1", "Gi0/0/0"), ("R2", "Gi0/0/0")),
    (("R1", "Gi0/0/1"), ("R3", "Gi0/0/0")),
    (("R2", "Gi0/0/1"), ("SW1", "Gi1/0/24")),
    (("R3", "Gi0/0/1"), ("SW2", "Gi1/0/24")),
    (("SW1", "Gi1/0/1"), ("Finance-PC", "eth0")),
    (("SW1", "Gi1/0/2"), ("HR-PC", "eth0")),
    (("SW2", "Gi1/0/1"), ("ERP", "eth0")),
    (("SW2", "Gi1/0/2"), ("DNS", "eth0")),
]

_VLANS = [("SW1", 10, "FINANCE"), ("SW1", 20, "HR"), ("SW2", 30, "SERVERS")]

_STATIC_ROUTES = [
    ("R1", "0.0.0.0/0", "10.0.1.1"),
    ("FW1", "0.0.0.0/0", "203.0.113.1"),
    ("FW1", "10.0.0.0/8", "10.0.1.2"),
    ("FW1", "192.168.30.0/24", "10.0.1.2"),
]

# device, sequence, action, protocol, source, destination, port
_ACL = [
    ("R2", 10, "deny", "ip", "10.21.0.0/24", "10.20.0.0/24", None),
    ("R2", 100, "permit", "ip", "any", "any", None),
    ("R3", 100, "permit", "ip", "any", "any", None),
]

# name, source, destination, protocol, port, expected action, criticality
_INTENTS = [
    ("Finance ERP access (HTTPS)", "Finance-PC", "ERP", "tcp", 443, "allow", "critical"),
    ("HR ERP access (HTTPS)", "HR-PC", "ERP", "tcp", 443, "allow", "high"),
    ("Finance DNS resolution", "Finance-PC", "DNS", "udp", 53, "allow", "medium"),
    ("HR DNS resolution", "HR-PC", "DNS", "udp", 53, "allow", "medium"),
    ("HR / Finance isolation", "HR-PC", "Finance-PC", "ip", None, "deny", "high"),
    ("Finance Internet access (HTTPS)", "Finance-PC", "INTERNET", "tcp", 443, "allow", "high"),
]


def _available_name(db: Session, base: str) -> str:
    existing = {n.lower() for n in db.scalars(select(Network.name))}
    if base.lower() not in existing:
        return base
    index = 2
    while f"{base} ({index})".lower() in existing:
        index += 1
    return f"{base} ({index})"


# Injected faults for the Health Check demo (faulty=True).
_FAULTS = {
    "ospf_area": ("R1", "Gi0/0/1", 1),            # OSPF001: R1-R3 area mismatch
    "access_vlan": ("SW1", "Gi1/0/2", 10),       # VLAN001: HR-PC port in the Finance VLAN
    "gateway": ("DNS", "192.168.30.254"),      # IP002: DNS gateway not on R3
    "default_route_next_hop": "10.0.99.99",    # ROUTE001: R1 default route unreachable next hop
}


def create_demo_network(db: Session, user: User | None, name: str | None = None, faulty: bool = False) -> Network:
    base_name = name or (f"{DEMO_NETWORK_NAME} (Faulty)" if faulty else DEMO_NETWORK_NAME)
    network = Network(
        name=_available_name(db, base_name),
        description=FAULTY_DESCRIPTION if faulty else DEMO_DESCRIPTION,
        network_type="Enterprise",
        # Built-in sample data: label it as a virtual sample, not a hand-made (manual) model.
        environment="virtual", source="sample", is_simulated=True,
        metadata_json={"interface_naming_version": 1},
        created_by=user.id if user else None,
    )
    db.add(network)
    db.flush()

    devices: dict[str, Device] = {}
    for dev_name, dev_type, vendor, model, mgmt_ip, gateway, x, y in _DEVICES:
        device = Device(
            network_id=network.id, name=dev_name, device_type=dev_type, vendor=vendor, model=model,
            management_ip=mgmt_ip, default_gateway=gateway, x_position=x, y_position=y,
        )
        db.add(device)
        devices[dev_name] = device
    db.flush()

    interfaces: dict[tuple[str, str], Interface] = {}
    for dev_name, if_name, ip, mask, vlan, area, mode in _INTERFACES:
        interface = Interface(
            device_id=devices[dev_name].id, name=if_name, ip_address=ip, subnet_mask=mask,
            vlan_id=vlan, status="up", ospf_area=area, mode=mode, speed_mbps=1000,
            description="Sample first wired NIC" if dev_name in {"Finance-PC", "HR-PC", "ERP", "DNS"} else None,
        )
        db.add(interface)
        interfaces[(dev_name, if_name)] = interface
    db.flush()

    for (src_dev, src_if), (dst_dev, dst_if) in _LINKS:
        for local_dev, local_if, peer_dev, peer_if in (
            (src_dev, src_if, dst_dev, dst_if), (dst_dev, dst_if, src_dev, src_if),
        ):
            iface = interfaces[(local_dev, local_if)]
            if iface.description is None:
                iface.description = f"Link to {peer_dev} {peer_if}"
        db.add(Link(
            network_id=network.id,
            source_device_id=devices[src_dev].id,
            source_interface_id=interfaces[(src_dev, src_if)].id if src_if else None,
            destination_device_id=devices[dst_dev].id,
            destination_interface_id=interfaces[(dst_dev, dst_if)].id if dst_if else None,
        ))
    for dev_name, vlan_id, vlan_name in _VLANS:
        db.add(Vlan(device_id=devices[dev_name].id, vlan_id=vlan_id, name=vlan_name))
    for dev_name, destination, next_hop in _STATIC_ROUTES:
        if faulty and dev_name == "R1" and destination == "0.0.0.0/0":
            next_hop = _FAULTS["default_route_next_hop"]
        db.add(StaticRoute(device_id=devices[dev_name].id, destination=destination, next_hop=next_hop))
    if faulty:
        dev, ifname, area = _FAULTS["ospf_area"]
        interfaces[(dev, ifname)].ospf_area = area
        dev, ifname, vlan = _FAULTS["access_vlan"]
        interfaces[(dev, ifname)].vlan_id = vlan
        dev, gateway = _FAULTS["gateway"]
        devices[dev].default_gateway = gateway
    for dev_name, seq, action, protocol, source, destination, port in _ACL:
        db.add(AclRule(device_id=devices[dev_name].id, sequence=seq, action=action, protocol=protocol,
                       source=source, destination=destination, port=port))
    for intent_name, src, dst, protocol, port, expected, criticality in _INTENTS:
        db.add(NetworkIntent(
            network_id=network.id, name=intent_name, source_device_id=devices[src].id,
            destination_device_id=devices[dst].id, protocol=protocol, port=port,
            expected_action=expected, criticality=criticality,
        ))
    network.updated_at = func.now()
    db.commit()
    db.refresh(network)
    return network


def create_analysis_demo(db: Session, user: User | None, name: str | None = None, scenario: str = "mixed",
                         environment: str = "virtual", source: str = "sample") -> Network:
    """Extended sample uses the existing model and analysis; old demo stays stable."""
    from backend.core.errors import ValidationFailed
    aliases = {"vlan-mismatch": "vlan", "routing-problem": "routing", "interface-shutdown": "interface",
               "firewall": "acl", "network-loop": "loop", "duplicate-ip": "ip-conflict"}
    scenario = aliases.get(scenario, scenario)
    if scenario not in {"healthy", "mixed", "vlan", "routing", "interface", "acl", "loop", "missing-link", "ip-conflict"}:
        raise ValidationFailed("Choose healthy, mixed, vlan, routing, interface, acl, loop, missing-link or ip-conflict")
    network = create_demo_network(db, user, name or f"Example network — {scenario.replace('-', ' ').title()}")
    network.environment, network.source, network.is_simulated = environment, source, True
    devices = {d.name: d for d in db.scalars(select(Device).where(Device.network_id == network.id))}
    interfaces = {(d.name, i.name): i for d in devices.values() for i in d.interfaces}
    meta = {"scenario": scenario, "origin": "example",
            "interface_naming_version": 1, "modeling_assumptions": ["Analysis uses a simplified IPv4 configuration model and sample observations.",
                                     "Risk = 100 x S x (1 + I + E) / 24 ranks risk; it is not a probability of deployment failure."]}
    for iface in interfaces.values():
        iface.speed_mbps = 1000
        if iface.mode == "trunk":
            iface.allowed_vlans, iface.native_vlan = [10, 20, 30], 1
    for link in db.scalars(select(Link).where(Link.network_id == network.id)):
        link.kind, link.confidence, link.speed_mbps = "lab", 1.0, 1000
        link.evidence_json = json.dumps({"origin": "example", "evidence": [{"source": "sample lab definition",
            "detail": "Both device and interface endpoints are explicitly defined in this sample topology."}], "missing": []})
    if scenario in ("vlan", "mixed"):
        interfaces[("SW1", "Gi1/0/2")].vlan_id = 10
    if scenario in ("routing", "mixed"):
        interfaces[("R1", "Gi0/0/1")].ospf_area = 1
    if scenario in ("acl", "mixed"):
        db.add(AclRule(device_id=devices["R3"].id, sequence=5, action="deny", protocol="tcp",
                       source="10.20.0.0/24", destination="192.168.30.10/32", port=443))
    if scenario == "interface":
        interfaces[("R3", "Gi0/0/0")].status = "admin-down"
    if scenario == "ip-conflict":
        interfaces[("DNS", "eth0")].ip_address = "192.168.30.10"
    if scenario == "missing-link":
        link = next(l for l in db.scalars(select(Link).where(Link.network_id == network.id))
                    if {l.source_device_id, l.destination_device_id} == {devices["R3"].id, devices["SW2"].id})
        db.delete(link)
        meta["expected_connections"] = [{"source": "R3", "source_interface": "Gi0/0/1",
                                         "destination": "SW2", "destination_interface": "Gi1/0/24"}]
    if scenario == "loop":
        switches = [devices["SW1"]]
        for index, x in ((3, -530), (4, -530)):
            switch = Device(network_id=network.id, name=f"SW{index}", device_type="switch", vendor="Cisco",
                            model="Catalyst 9200-24T", management_ip=f"192.168.1.{10 + index}",
                            x_position=x, y_position=120 if index == 3 else 380)
            db.add(switch)
            db.flush()
            for vid in (10, 20):
                db.add(Vlan(device_id=switch.id, vlan_id=vid, name=f"VLAN{vid}"))
            switches.append(switch)
        for index, switch in enumerate(switches):
            peer = switches[(index + 1) % len(switches)]
            local = Interface(device_id=switch.id, name="Gi1/0/22", status="up", mode="trunk", speed_mbps=1000,
                              allowed_vlans=[10, 20], native_vlan=1, stp_state="forwarding",
                              description=f"Ring link to {peer.name} Gi1/0/23")
            remote = Interface(device_id=peer.id, name="Gi1/0/23", status="up", mode="trunk", speed_mbps=1000,
                               allowed_vlans=[10, 20], native_vlan=1, stp_state="forwarding",
                               description=f"Ring link to {switch.name} Gi1/0/22")
            db.add_all([local, remote])
            db.flush()
            db.add(Link(network_id=network.id, source_device_id=switch.id, source_interface_id=local.id,
                        destination_device_id=peer.id, destination_interface_id=remote.id, kind="lab", confidence=1.0,
                        speed_mbps=1000, evidence_json=json.dumps({"origin": "example", "evidence": [
                            {"source": "sample LLDP neighbour table", "detail": f"{switch.name} {local.name} ↔ {peer.name} {remote.name}"}]})))
        meta["mac_flaps"] = [{"device": "SW1", "vlan": 10, "mac": "02:00:00:10:00:10",
                              "ports": ["Gi1/0/22", "Gi1/0/23"], "count": 18, "window_seconds": 60}]
        meta["broadcast_samples"] = [{"device": "SW1", "vlan": 10, "pps": 4500, "baseline_pps": 40}]
    network.metadata_json = meta
    db.commit()
    db.refresh(network)
    return network
