"""In-memory network model used by the analysis pipeline.

The database state is loaded once into plain dataclasses (the *baseline*).
A deep copy with the proposed change applied becomes the *candidate*. All
rules and path analysis run on these models, never on ORM objects, so the
analysis is side-effect free. The tables are filled by hand or by the config
import (config_import.py).
"""
from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.models import L3_TYPES, Device, Link, Network, NetworkIntent

HOST_TYPES = ("pc", "server")


@dataclass
class IfaceM:
    id: int
    device_id: int
    name: str
    ip: str | None
    mask: str | None
    vlan: int | None
    status: str
    ospf_area: int | None
    mode: str | None
    speed_mbps: int | None = None
    allowed_vlans: list[int] | None = None
    native_vlan: int | None = None
    stp_state: str | None = None
    description: str | None = None
    duplex: str | None = None
    mtu: int | None = None
    ospf_hello: int | None = None
    ospf_dead: int | None = None
    acl_in: str | None = None
    acl_out: str | None = None
    error_count: int | None = None

    @property
    def up(self) -> bool:
        return self.status == "up"

    @property
    def interface(self) -> ipaddress.IPv4Interface | None:
        if not self.ip or not self.mask:
            return None
        return ipaddress.IPv4Interface(f"{self.ip}/{self.mask}")

    @property
    def network(self) -> ipaddress.IPv4Network | None:
        iface = self.interface
        return iface.network if iface else None

    @property
    def cidr(self) -> str:
        iface = self.interface
        return f"{iface.ip}/{iface.network.prefixlen}" if iface else "no IP"

    @property
    def parent_name(self) -> str | None:
        return self.name.split(".", 1)[0] if "." in self.name else None


@dataclass
class RouteM:
    id: int
    destination: str
    next_hop: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.destination, strict=False)


@dataclass
class AclM:
    id: int
    sequence: int
    action: str
    protocol: str
    source: str
    destination: str
    port: int | None
    acl_name: str | None = None  # None: the device's unnamed rule list, applied to all routed traffic

    def text(self) -> str:
        port = f" eq {self.port}" if self.port else ""
        where = f"{self.acl_name} " if self.acl_name else ""
        return f"{where}{self.sequence} {self.action} {self.protocol} {self.source} {self.destination}{port}"


@dataclass
class DeviceM:
    id: int
    name: str
    type: str
    gateway: str | None
    interfaces: dict[int, IfaceM] = field(default_factory=dict)
    vendor: str | None = None
    vlans: dict[int, str | None] = field(default_factory=dict)
    routes: list[RouteM] = field(default_factory=list)
    acl: list[AclM] = field(default_factory=list)
    model: str | None = None
    facts: dict = field(default_factory=dict)  # hygiene facts from the running configuration
    is_lab: bool = False
    platform: str | None = None
    management_ip: str | None = None

    @property
    def is_l3(self) -> bool:
        return self.type in L3_TYPES

    @property
    def l3_switch(self) -> bool:
        """A multilayer switch: `ip routing` with SVIs (interface VlanX) or routed ports."""
        return self.type == "switch" and bool((self.facts or {}).get("ip_routing"))

    @property
    def is_router(self) -> bool:
        """Forwards IP packets between subnets (router, firewall or multilayer switch)."""
        return self.is_l3 or self.l3_switch

    @property
    def is_host(self) -> bool:
        return self.type in HOST_TYPES

    @property
    def is_switch(self) -> bool:
        return self.type == "switch"

    def iface_by_name(self, name: str) -> IfaceM | None:
        return next((i for i in self.interfaces.values() if i.name == name), None)

    def subinterfaces(self, parent: IfaceM) -> list[IfaceM]:
        return [i for i in self.interfaces.values() if i.parent_name == parent.name]

    def effectively_up(self, iface: IfaceM) -> bool:
        """A sub-interface is only up when its parent is up too."""
        if not iface.up:
            return False
        parent = self.iface_by_name(iface.parent_name) if iface.parent_name else None
        return parent.up if parent else True

    def sorted_acl(self, name: str | None = "*") -> list[AclM]:
        """Entries of one access list (name), the unnamed device-wide list (None) or of every list ("*")."""
        rules = self.acl if name == "*" else [r for r in self.acl if r.acl_name == name]
        return sorted(rules, key=lambda r: ((r.acl_name or ""), r.sequence))

    def acl_lists(self) -> dict[str | None, list[AclM]]:
        lists: dict[str | None, list[AclM]] = {}
        for rule in sorted(self.acl, key=lambda r: r.sequence):
            lists.setdefault(rule.acl_name, []).append(rule)
        return lists

    def svi(self, vlan: int) -> IfaceM | None:
        """The SVI (interface VlanX with an address) of a multilayer switch for `vlan`."""
        if not self.l3_switch:
            return None
        return next((i for i in self.interfaces.values() if i.ip and i.name.lower() in (f"vlan{vlan}", f"vlan {vlan}")), None)


@dataclass
class LinkM:
    id: int
    a_dev: int
    a_if: int | None
    b_dev: int
    b_if: int | None
    kind: str | None = None
    state: str | None = None
    confidence: float | None = None
    evidence: list = field(default_factory=list)
    observation: dict = field(default_factory=dict)

    def other(self, device_id: int) -> tuple[int, int | None]:
        return (self.b_dev, self.b_if) if device_id == self.a_dev else (self.a_dev, self.a_if)

    def local_if(self, device_id: int) -> int | None:
        return self.a_if if device_id == self.a_dev else self.b_if


@dataclass
class IntentM:
    id: int
    name: str
    src: int
    dst: int
    protocol: str
    port: int | None
    expected: str
    criticality: str


@dataclass
class NetworkModel:
    network_id: int
    devices: dict[int, DeviceM]
    links: dict[int, LinkM]
    intents: list[IntentM]
    observations: dict = field(default_factory=dict)

    def copy(self) -> "NetworkModel":
        return copy.deepcopy(self)

    # ------------------------------------------------------------ lookups
    def device(self, device_id: int) -> DeviceM:
        return self.devices[device_id]

    def iface(self, device_id: int, iface_id: int | None) -> IfaceM | None:
        if iface_id is None:
            return None
        return self.devices[device_id].interfaces.get(iface_id)

    def links_of(self, device_id: int) -> list[LinkM]:
        return [l for l in self.links.values() if device_id in (l.a_dev, l.b_dev)]

    def link_for_iface(self, device_id: int, iface: IfaceM) -> LinkM | None:
        """Link attached to an interface (sub-interfaces use their parent's link)."""
        target = iface
        if iface.parent_name:
            target = self.devices[device_id].iface_by_name(iface.parent_name) or iface
        return next((l for l in self.links_of(device_id) if l.local_if(device_id) == target.id), None)

    def link_between(self, a: int, b: int) -> list[LinkM]:
        return [l for l in self.links.values() if {l.a_dev, l.b_dev} == {a, b}]

    def owner_of_ip(self, ip: str) -> list[tuple[DeviceM, IfaceM]]:
        return [(d, i) for d in self.devices.values() for i in d.interfaces.values() if i.ip == ip]

    def label(self, device_id: int, iface: IfaceM | None) -> str:
        name = self.devices[device_id].name
        return f"{name} {iface.name}" if iface else name


def presentation_only(link) -> bool:
    """Logical discovery links (same segment as the gateway, behind an uplink, a traceroute hop, an unseen access
    point) show how a device is reached, not a cable or switch port. They are drawn on the map but excluded from
    forwarding analysis, so no flow verdict ever rests on a path that was not observed."""
    if link.kind not in ("segment", "route", "wireless"):
        return False
    return (link._observations().get("grade") or "Logical") == "Logical"


def load_model(db: Session, network_id: int) -> NetworkModel:
    devices = db.scalars(
        select(Device)
        .where(Device.network_id == network_id)
        .options(
            selectinload(Device.interfaces),
            selectinload(Device.vlans),
            selectinload(Device.static_routes),
            selectinload(Device.acl_rules),
        )
    ).all()
    model_devices: dict[int, DeviceM] = {}
    for d in devices:
        model_devices[d.id] = DeviceM(
            id=d.id,
            name=d.name,
            type=d.device_type,
            gateway=d.default_gateway,
            interfaces={
                i.id: IfaceM(i.id, d.id, i.name, i.ip_address, i.subnet_mask, i.vlan_id, i.status, i.ospf_area, i.mode,
                            i.speed_mbps, i.allowed_vlans, i.native_vlan, i.stp_state, i.description, i.duplex, i.mtu,
                            i.ospf_hello, i.ospf_dead, i.acl_in, i.acl_out, i.error_count)
                for i in d.interfaces
            },
            vlans={v.vlan_id: v.name for v in d.vlans},
            routes=[RouteM(r.id, r.destination, r.next_hop) for r in d.static_routes],
            acl=[AclM(r.id, r.sequence, r.action, r.protocol, r.source, r.destination, r.port, r.acl_name)
                 for r in d.acl_rules],
            vendor=d.vendor,
            model=d.model,
            facts=dict(d.config_facts or {}),
            is_lab=bool(d.is_lab),
            platform=d.platform,
            management_ip=d.management_ip,
        )
    links = {
        l.id: LinkM(l.id, l.source_device_id, l.source_interface_id, l.destination_device_id, l.destination_interface_id,
                   l.kind, l.state, l.confidence, l.evidence, l._observations())
        for l in db.scalars(select(Link).where(Link.network_id == network_id)) if not presentation_only(l)
    }
    intents = [
        IntentM(i.id, i.name, i.source_device_id, i.destination_device_id, i.protocol, i.port, i.expected_action,
                i.criticality)
        for i in db.scalars(select(NetworkIntent).where(NetworkIntent.network_id == network_id).order_by(NetworkIntent.id))
    ]
    network = db.get(Network, network_id)
    return NetworkModel(network_id, model_devices, links, intents, (network.metadata_json or {}) if network else {})
