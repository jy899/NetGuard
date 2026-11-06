"""Per-device discovery completeness, authentication status and the credential advisor.

Completeness and authentication are separate: a device can be partially analyzed *and* need authentication.
Gains are computed from what is already known.
"""
from __future__ import annotations

from collections import defaultdict
from ipaddress import IPv4Address

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models import Device, Interface, Link, Network

CATEGORY_LABELS = {
    "full": "Fully Analyzed", "partial": "Partially Analyzed", "auth_required": "Authentication Required",
    "auth_failed": "Authentication Failed", "unverified": "Unknown or Unverified", "unreachable": "Unreachable",
}
CATEGORY_ORDER = ("full", "partial", "auth_required", "auth_failed", "unverified", "unreachable")


class Context:
    def __init__(self, db: Session, network: Network):
        from backend.services.discovery.fusion import UNKNOWN_PORT, is_access_point, is_infrastructure
        self.network = network
        self.meta = network.metadata_json or {}
        self.discovery = self.meta.get("discovery", {})
        self.devices = {d.id: d for d in db.scalars(select(Device).where(Device.network_id == network.id))
                        if str(d.id) in self.discovery}
        from backend.services.network_model import presentation_only

        # Logical "how it is reached" links (same segment as the gateway, a route hop) are not attachments.
        self.links = [l for l in db.scalars(select(Link).where(Link.network_id == network.id)) if not presentation_only(l)]
        self.ifaces = defaultdict(list)
        for row in db.scalars(select(Interface).where(Interface.device_id.in_(self.devices))):
            self.ifaces[row.device_id].append(row)
        self.iface_by_id = {i.id: i for rows in self.ifaces.values() for i in rows}
        self.neighbours = defaultdict(set)  # recorded attachments (interface references valid or not recorded)
        self.confirmed = set()               # devices with an LLDP attachment whose both ports are present and owned
        self.link_kinds = defaultdict(set)
        self.endpoint_ports = defaultdict(set)
        for link in self.links:
            ends = ((link.source_device_id, link.source_interface_id), (link.destination_device_id, link.destination_interface_id))
            owned = lambda did, iid: iid in self.iface_by_id and self.iface_by_id[iid].device_id == did  # noqa: E731
            if any(iid is not None and not owned(did, iid) for did, iid in ends):
                continue  # dangling or mis-owned reference: no attachment evidence
            both_ports = all(iid is not None for _, iid in ends)
            for me, other, my_if in ((link.source_device_id, link.destination_device_id, link.destination_interface_id),
                                     (link.destination_device_id, link.source_device_id, link.source_interface_id)):
                self.neighbours[me].add(other)
                self.link_kinds[me].add(link.kind)
                if link.kind == "lldp" and both_ports:
                    self.confirmed.add(me)
            for did, iid in ((link.source_device_id, link.source_interface_id), (link.destination_device_id, link.destination_interface_id)):
                if iid in self.iface_by_id:
                    self.endpoint_ports[did].add(self.iface_by_id[iid].name)
        self.reads = defaultdict(set)
        for o in self.meta.get("observations", []):
            if o.get("authenticated"):
                self.reads[o["observed_by"]].add(o["technique"])
        self.sensor_ips = {o["subject"] for o in self.meta.get("observations", []) if o["technique"] == "passive-lldp"}
        self.unknown_port = UNKNOWN_PORT
        self._infra, self._ap = is_infrastructure, is_access_point

    def facts(self, did) -> dict:
        return self.discovery[str(did)]

    def infra(self, dev) -> bool:
        return self._infra(dev, self.facts(dev.id))

    def ap(self, dev) -> bool:
        return self._ap(self.facts(dev.id))

    def addressed(self, dev) -> bool:
        lease = self.facts(dev.id).get("lease")
        return bool(dev.default_gateway) and (bool(lease) or any(i.ip_address and i.subnet_mask for i in self.ifaces[dev.id]))


def _missing(ctx: Context, dev: Device) -> list[str]:
    facts, read = ctx.facts(dev.id), ctx.reads.get(ctx.facts(dev.id)["ip"], set())
    missing = []
    if dev.device_type == "firewall":
        if not dev.model:
            missing.append("Model")
        for technique, label in (("interface-table", "Interface table"), ("routing-table", "Routing table"),
                                 ("dhcp-leases", "DHCP lease table"), ("arp-table", "ARP table")):
            if technique not in read:
                missing.append(label)
        return missing
    if ctx.infra(dev):
        if not dev.model:
            missing.append("Model")
        for technique, label in (("interface-table", "Interface table"), ("vlan-table", "VLAN table"),
                                 ("lldp-table", "Neighbour table (LLDP)"), ("mac-table", "MAC address table")):
            if technique not in read:
                missing.append(label)
        return missing
    if facts.get("identity_unknown"):
        missing.append("Identity")
    if not ctx.neighbours[dev.id]:
        missing.append("Connection")
    elif ctx.ap(dev) and dev.id not in ctx.confirmed:
        missing.append("Confirmed connection")
    elif ctx.endpoint_ports[dev.id] and ctx.endpoint_ports[dev.id] <= {ctx.unknown_port}:
        missing.append("NIC name (connection inferred)")
    elif not ctx.endpoint_ports[dev.id]:
        missing.append("NIC name (port not recorded)")
    if not ctx.addressed(dev):
        missing.append("Addressing (mask and gateway)")
    return missing


def gains(ctx: Context, dev: Device) -> list[dict]:
    """What an authenticated read of this device would add, from known facts only."""
    facts = ctx.facts(dev.id)
    if not facts.get("methods") or facts.get("auth") == "success":
        return []
    read = ctx.reads.get(facts["ip"], set())
    out = []
    unknown = [d for d in ctx.devices.values() if d.id != dev.id and not ctx.neighbours[d.id]]
    if ctx.infra(dev) and dev.device_type == "switch" and "mac-table" not in read:
        behind = [d for d in ctx.devices.values() if any(f"towards {dev.name};" in note for note in ctx.facts(d.id).get("location_notes", []))]
        if behind:
            via = next(note.split(" towards ")[0].removeprefix("Reached through ") for note in ctx.facts(behind[0].id)["location_notes"]
                       if f"towards {dev.name};" in note)
            out.append({"text": f"{len(behind)} device(s) were located behind this switch ({via}); its MAC table can "
                                "identify their exact switch ports.", "important": True})
        if unknown:
            out.append({"text": f"Its LLDP neighbour and MAC tables can identify the switch port of up to {len(unknown)} "
                                "device(s) whose connection is unknown.", "important": True})
        out.append({"text": "Interface, VLAN and trunk configuration used by the path analysis.", "important": True})
    elif dev.device_type == "firewall" and "dhcp-leases" not in read:
        lacking = [d for d in ctx.devices.values() if not ctx.infra(d) and not ctx.addressed(d)]
        if lacking:
            out.append({"text": f"DHCP leases can provide the mask and gateway of {len(lacking)} endpoint(s).", "important": True})
        out.append({"text": "Routing table and LAN interface configuration.", "important": False})
    elif ctx.ap(dev) and dev.id not in ctx.confirmed:
        out.append({"text": "Its LLDP table can confirm the switch port of its uplink.", "important": True})
    return out


def _withdrawn_note(ctx: Context, dev: Device) -> str | None:
    if ctx.ap(dev) and dev.id in ctx.confirmed:
        switch = next((ctx.devices[n].name for n in ctx.neighbours[dev.id] if n in ctx.devices), "a switch")
        return f"Not needed: its connection was confirmed by {switch}'s neighbour table."
    return "Not needed: the remaining details are already known from other devices."


def classify(db: Session, network: Network) -> None:
    current = {d.id for d in db.scalars(select(Device).where(Device.network_id == network.id))}
    meta = dict(network.metadata_json or {})
    # Devices deleted from the model leave the discovery record too (their requests and gains no longer apply).
    discovery = {key: dict(value) for key, value in meta.get("discovery", {}).items() if int(key) in current}
    session = dict(meta.get("discovery_session") or {})
    if session.get("skipped"):
        session["skipped"] = [did for did in session["skipped"] if did in current]
        meta["discovery_session"] = session
    meta["discovery"] = discovery
    network.metadata_json = meta
    ctx = Context(db, network)
    for did, dev in ctx.devices.items():
        facts = discovery[str(did)]
        missing = _missing(ctx, dev)
        device_gains = gains(ctx, dev)
        if facts.get("identity_unknown") or (not ctx.neighbours[did] and facts.get("confidence") == "low"):
            completeness = "unverified"
        else:
            completeness = "partial" if missing else "full"
        if not facts.get("methods"):
            auth = "not_offered"
        elif facts.get("auth") == "success":
            auth = "success"
        elif facts.get("auth") == "failed":
            auth = "failed"
        else:
            auth = "required" if device_gains else "not_needed"
        primary = ("auth_failed" if auth == "failed" else "unverified" if completeness == "unverified"
                   else "auth_required" if auth == "required" else completeness)
        facts["classification"] = {
            "primary": primary, "label": CATEGORY_LABELS[primary], "completeness": completeness, "auth": auth,
            "missing": missing, "gains": device_gains,
            "note": _withdrawn_note(ctx, dev) if auth == "not_needed" else None,
        }
    meta["discovery"] = discovery
    network.metadata_json = meta
    db.flush()


def _ip_key(ip: str):
    return int(IPv4Address(ip))


def requests(db: Session, network: Network) -> list[dict]:
    """Credential requests worth asking for, in priority order (sensor switch, switches, firewalls, access points)."""
    ctx = Context(db, network)
    rows = []
    for did, dev in ctx.devices.items():
        facts = ctx.facts(did)
        cls = facts.get("classification", {})
        if cls.get("auth") not in ("required", "failed") or not cls.get("gains"):
            continue
        ip = facts["ip"]
        rank = (0 if ip in ctx.sensor_ips else 1) if ctx.infra(dev) and dev.device_type == "switch" else 2 if dev.device_type == "firewall" else 3
        rows.append((rank, _ip_key(ip), dev, facts))
    rows.sort(key=lambda r: (r[0], r[1]))
    pending = [(dev, facts) for _, _, dev, facts in rows]
    out = []
    for dev, facts in pending:
        reuse = []
        for other, other_facts in pending:
            shared = [m for m in facts["methods"] if m in other_facts["methods"]]
            if other.id == dev.id or not shared:
                continue
            reuse.append({"device_id": other.id, "name": other.name, "ip": other_facts["ip"], "methods": other_facts["methods"],
                          "preselected": ctx.infra(other) and other.id not in set(network.metadata_json.get("discovery_session", {}).get("skipped", []))})
        out.append({
            "device_id": dev.id, "name": dev.name, "ip": facts["ip"], "type": dev.device_type,
            "model": dev.model, "role": facts.get("role"), "auth": facts["classification"]["auth"],
            "reason": f"{dev.name} answered with secure management services, but credential-free discovery cannot read its "
                      "configuration or neighbour tables.",
            "gains": facts["classification"]["gains"], "important": any(g["important"] for g in facts["classification"]["gains"]),
            "methods": facts["methods"], "not_offered": facts.get("not_offered", []), "reuse_candidates": reuse,
            "last_error": facts.get("auth_detail") if facts.get("auth") == "failed" else None,
        })
    return out
