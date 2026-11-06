"""Change Detector: identifies what a proposed change modifies.

For each supported change type it
  * validates the proposed parameters against the current device state,
  * describes the current and proposed values in human terms,
  * applies the change to a copy of the network model (the candidate).

Supported types: IP/Interface (address, gateway, status, speed/duplex/MTU/OSPF timers), Routing (OSPF area, OSPF
network, static route), ACL (entries, references), VLAN (access VLAN, VLAN database, trunk settings, endpoint
isolation, spanning-tree root), management-plane hardening and physical remediation (a work order whose effect is
verified on the model: replace a cable or transceiver, move a cable to another port, clear an error condition).
BGP/MPLS/NAT are out of scope.
"""
from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from backend.core.errors import ValidationFailed
from backend.models import INTERFACE_STATUSES
from backend.schemas.config import AclRuleCreate
from backend.schemas.validators import validate_cidr, validate_host_address, validate_ipv4, validate_subnet_mask
from backend.services.network_model import AclM, DeviceM, IfaceM, NetworkModel, RouteM

L3 = ("router", "firewall")
ENDPOINTS = ("pc", "server", "internet")
INFRA = ("router", "firewall", "switch")
ROUTING_TYPES = ("static_route", "ospf_area", "ospf_network", "acl_add", "acl_remove")

CHANGE_TYPES: dict[str, dict] = {
    "ip_address": {"category": "ip_interface", "label": "IP Address", "target": "interface",
                   "device_types": L3 + ENDPOINTS + ("switch",)},
    "default_gateway": {"category": "ip_interface", "label": "Default Gateway", "target": "device",
                        "device_types": ("pc", "server")},
    "interface_status": {"category": "ip_interface", "label": "Interface Status", "target": "interface",
                         "device_types": L3 + ENDPOINTS + ("switch",)},
    "ospf_area": {"category": "routing", "label": "OSPF Area", "target": "interface", "device_types": INFRA},
    "ospf_network": {"category": "routing", "label": "OSPF Network", "target": "interface", "device_types": INFRA},
    "static_route": {"category": "routing", "label": "Static Route", "target": "device", "device_types": INFRA},
    "acl_add": {"category": "acl", "label": "Add ACL Rule", "target": "device", "device_types": INFRA},
    "acl_remove": {"category": "acl", "label": "Remove ACL Rule", "target": "device", "device_types": INFRA},
    "acl_reference": {"category": "acl", "label": "ACL Reference", "target": "device", "device_types": INFRA},
    "access_vlan": {"category": "vlan", "label": "Access VLAN", "target": "interface", "device_types": ("switch",)},
    "vlan_database": {"category": "vlan", "label": "VLAN Database", "target": "device", "device_types": ("switch",)},
    "trunk_settings": {"category": "vlan", "label": "Trunk Settings", "target": "interface", "device_types": ("switch",)},
    "isolate_endpoint": {"category": "vlan", "label": "Isolate Endpoint VLAN", "target": "interface",
                         "device_types": ("switch",)},
    "stp_root": {"category": "vlan", "label": "Spanning-Tree Root", "target": "device", "device_types": ("switch",)},
    "interface_settings": {"category": "ip_interface", "label": "Interface Settings", "target": "interface",
                           "device_types": INFRA},
    "mgmt_hardening": {"category": "security", "label": "Management Hardening", "target": "device",
                       "device_types": INFRA},
    "physical_remediation": {"category": "physical", "label": "Physical Remediation", "target": "interface",
                             "device_types": INFRA + ENDPOINTS},
}


@dataclass
class DetectedChange:
    change_type: str
    category: str
    device_id: int
    device_name: str
    interface_id: int | None
    target_name: str | None
    parameters: dict
    current_value: str
    proposed_value: str
    summary: str
    effective: bool  # False when the proposed value equals the current value


def _fail(message: str):
    raise ValidationFailed(message)


def _area(value) -> int:
    try:
        area = int(str(value).lower().replace("area", "").strip())
    except (TypeError, ValueError):
        _fail("OSPF area must be a number, e.g. 0 or 1")
    if not 0 <= area <= 65535:
        _fail("OSPF area must be between 0 and 65535")
    return area


def _ip(value, label: str, required: bool = True) -> str | None:
    try:
        result = validate_ipv4(value)
    except ValueError as exc:
        _fail(f"{label}: {exc}")
    if required and result is None:
        _fail(f"{label} is required")
    return result


def _int_or_none(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _route_text(route: RouteM) -> str:
    return f"{route.destination} via {route.next_hop}"


def _vlan_label(device: DeviceM, vlan: int | None) -> str:
    if vlan is None:
        return "No VLAN"
    name = device.vlans.get(vlan)
    return f"VLAN {vlan}" + (f" ({name})" if name else "")


def detect(model: NetworkModel, device_id: int | None, interface_id: int | None, change_type: str,
           parameters: dict | None) -> DetectedChange:
    """Validate a proposed change against the baseline model and describe it."""
    spec = CHANGE_TYPES.get(change_type)
    if spec is None:
        _fail(f"Unknown change type '{change_type}'")
    if device_id is None or device_id not in model.devices:
        _fail("The target device no longer exists in this network")
    device = model.device(device_id)
    if device.type not in spec["device_types"]:
        _fail(f"{spec['label']} changes are not supported on a {device.type}")
    params = dict(parameters or {})
    iface: IfaceM | None = None
    if spec["target"] == "interface":
        iface = device.interfaces.get(interface_id) if interface_id else None
        if iface is None:
            _fail(f"Select an interface on {device.name} for a {spec['label']} change")
    else:
        interface_id = None
    if change_type in ROUTING_TYPES and device.type == "switch" and not device.is_router:
        _fail(f"{device.name} is a Layer-2 switch (no ip routing); {spec['label']} changes need a router or a "
              "multilayer switch")
    if change_type == "ip_address" and device.type == "switch" and not (device.is_router or iface.name.lower().startswith("vlan")):
        _fail(f"{device.name} {iface.name} is a switch port; only SVIs and routed ports of a multilayer switch have addresses")
    handler = globals()[f"_detect_{change_type}"]
    current, proposed, target, summary, normalised = handler(model, device, iface, params)
    return DetectedChange(
        change_type=change_type, category=spec["category"], device_id=device.id, device_name=device.name,
        interface_id=interface_id, target_name=target, parameters=normalised, current_value=current,
        proposed_value=proposed, summary=summary, effective=current != proposed,
    )


# ----------------------------------------------------------- IP / interface
def _detect_ip_address(model, device, iface, params):
    ip = _ip(params.get("ip_address"), "IP address")
    try:
        mask = validate_subnet_mask(params.get("subnet_mask"))
    except ValueError as exc:
        _fail(f"Subnet mask: {exc}")
    if mask is None:
        _fail("Subnet mask is required")
    try:
        validate_host_address(ip, mask)
    except ValueError as exc:
        _fail(str(exc))
    proposed_iface = IfaceM(0, 0, "", ip, mask, None, "up", None, None)
    if device.is_router:
        # Like IOS: a router cannot have two interfaces in overlapping subnets.
        for other in device.interfaces.values():
            if other.id != iface.id and other.network and other.network.overlaps(proposed_iface.network):
                _fail(f"{proposed_iface.network} overlaps {device.name} {other.name} ({other.cidr})")
    current = iface.cidr if iface.ip else "Not set"
    proposed = proposed_iface.cidr
    summary = (f"The proposed change modifies the IP address of {device.name} {iface.name} "
               f"from {current} to {proposed}.")
    return current, proposed, iface.name, summary, {"ip_address": ip, "subnet_mask": mask}


def _detect_default_gateway(model, device, iface, params):
    gateway = _ip(params.get("gateway"), "Default gateway", required=False)
    current = device.gateway or "None"
    proposed = gateway or "None"
    summary = f"The proposed change modifies the default gateway of {device.name} from {current} to {proposed}."
    return current, proposed, "Default gateway", summary, {"gateway": gateway}


def _detect_interface_status(model, device, iface, params):
    status = str(params.get("status", "")).strip().lower()
    if status not in INTERFACE_STATUSES:
        _fail(f"Interface status must be one of: {', '.join(INTERFACE_STATUSES)}")
    summary = (f"The proposed change sets the status of {device.name} {iface.name} "
               f"from {iface.status} to {status}.")
    return iface.status, status, iface.name, summary, {"status": status}


# ----------------------------------------------------------------- routing
def _ospf_text(area: int | None) -> str:
    return f"Area {area}" if area is not None else "Not in OSPF"


def _detect_ospf_area(model, device, iface, params):
    if not iface.ip:
        _fail(f"{device.name} {iface.name} has no IP address, so it cannot run OSPF")
    area = _area(params.get("area"))
    current, proposed = _ospf_text(iface.ospf_area), _ospf_text(area)
    summary = (f"The proposed change modifies the OSPF area on {device.name} {iface.name} "
               f"from {current} to {proposed}.")
    return current, proposed, iface.name, summary, {"area": area}


def _detect_ospf_network(model, device, iface, params):
    if not iface.ip:
        _fail(f"{device.name} {iface.name} has no IP address to advertise")
    action = str(params.get("action", "")).lower()
    if action not in ("advertise", "remove"):
        _fail("OSPF network action must be 'advertise' or 'remove'")
    area = _area(params.get("area", 0)) if action == "advertise" else None
    network = str(iface.network)
    current = f"{network} advertised in Area {iface.ospf_area}" if iface.ospf_area is not None else f"{network} not advertised"
    proposed = f"{network} advertised in Area {area}" if area is not None else f"{network} not advertised"
    verb = "adds" if action == "advertise" else "removes"
    where = f"to OSPF Area {area}" if action == "advertise" else "from OSPF"
    summary = f"The proposed change {verb} network {network} on {device.name} {iface.name} {where}."
    return current, proposed, iface.name, summary, {"action": action, "area": area}


def _detect_static_route(model, device, iface, params):
    action = str(params.get("action", "")).lower()
    if action not in ("add", "modify", "remove"):
        _fail("Static route action must be add, modify or remove")
    existing = None
    if action in ("modify", "remove"):
        route_id = _int_or_none(params.get("route_id"))
        existing = next((r for r in device.routes if r.id == route_id), None)
        if existing is None:
            _fail(f"Select an existing static route on {device.name}")
    if action == "remove":
        summary = f"The proposed change removes the static route {_route_text(existing)} from {device.name}."
        return _route_text(existing), "Removed", f"Route {existing.destination}", summary, {
            "action": action, "route_id": existing.id}
    try:
        destination = validate_cidr(params.get("destination"), "Destination")
    except ValueError as exc:
        _fail(str(exc))
    next_hop = _ip(params.get("next_hop"), "Next hop")
    clash = next((r for r in device.routes if r.destination == destination and r is not existing), None)
    if clash is not None:
        _fail(f"{device.name} already has a static route to {destination}; modify that route instead")
    proposed = f"{destination} via {next_hop}"
    if action == "add":
        current = f"No static route to {destination}"
        summary = f"The proposed change adds the static route {proposed} on {device.name}."
    else:
        current = _route_text(existing)
        summary = f"The proposed change modifies the static route on {device.name} from {current} to {proposed}."
    normalised = {"action": action, "destination": destination, "next_hop": next_hop}
    if existing:
        normalised["route_id"] = existing.id
    return current, proposed, f"Route {destination}", summary, normalised


# --------------------------------------------------------------------- ACL
def _acl_summary(device: DeviceM, name: str | None = "*") -> str:
    count = len(device.sorted_acl(name))
    where = f"access list {name}" if name not in (None, "*") else "ACL"
    return f"{count} rule(s) in {where}" if count else f"No {where} (all traffic permitted)"


def default_acl_name(device: DeviceM) -> str | None:
    """The list a new entry goes to when none is named: the device's only list, else the unnamed list."""
    names = {r.acl_name for r in device.acl}
    applied = {n for i in device.interfaces.values() for n in (i.acl_in, i.acl_out) if n}
    if len(names) == 1:
        return next(iter(names))
    if not names and len(applied) == 1:
        return next(iter(applied))
    return None


def _detect_acl_add(model, device, iface, params):
    params = dict(params)
    if "acl_name" not in params:
        params["acl_name"] = default_acl_name(device)
    try:
        rule = AclRuleCreate(**{k: params.get(k) for k in ("acl_name", "sequence", "action", "protocol", "source",
                                                          "destination", "port") if params.get(k) is not None})
    except ValidationError as exc:
        _fail("; ".join(str(e["msg"]).removeprefix("Value error, ") for e in exc.errors()))
    if any(r.sequence == rule.sequence and r.acl_name == rule.acl_name for r in device.acl):
        _fail(f"Sequence {rule.sequence} is already used in {'access list ' + rule.acl_name if rule.acl_name else 'the ACL'}"
              f" on {device.name}")
    text = AclM(0, rule.sequence, rule.action, rule.protocol, rule.source, rule.destination, rule.port, rule.acl_name).text()
    summary = f"The proposed change adds ACL rule '{text}' on {device.name}."
    if not device.sorted_acl(rule.acl_name):
        summary += " The list currently has no entries, so its implicit deny becomes active where it is applied."
    return _acl_summary(device, rule.acl_name), text, f"ACL {rule.acl_name or ''} seq {rule.sequence}".replace("  ", " "), \
        summary, rule.model_dump()


def _detect_acl_remove(model, device, iface, params):
    rule_id = _int_or_none(params.get("rule_id"))
    rule = next((r for r in device.acl if r.id == rule_id), None)
    if rule is None:
        _fail(f"Select an existing ACL rule on {device.name}")
    summary = f"The proposed change removes ACL rule '{rule.text()}' from {device.name}."
    return rule.text(), "Removed", f"ACL seq {rule.sequence}", summary, {"rule_id": rule.id}


# -------------------------------------------------------------------- VLAN
def _detect_access_vlan(model, device, iface, params):
    try:
        vlan = int(params.get("vlan_id"))
    except (TypeError, ValueError):
        _fail("VLAN ID must be a number between 1 and 4094")
    if not 1 <= vlan <= 4094:
        _fail("VLAN ID must be between 1 and 4094")
    if (iface.mode or ("access" if iface.vlan else "trunk")) != "access":
        _fail(f"{device.name} {iface.name} is a trunk port; only access ports can be assigned an access VLAN")
    current = _vlan_label(device, iface.vlan)
    proposed = _vlan_label(device, vlan)
    summary = (f"The proposed change moves {device.name} {iface.name} from access {current} "
               f"to access {proposed}.")
    return current, proposed, iface.name, summary, {"vlan_id": vlan}


def _detect_vlan_database(model, device, iface, params):
    action = str(params.get("action", "")).lower()
    if action not in ("add", "remove"):
        _fail("VLAN database action must be add or remove")
    try:
        vlan = int(params.get("vlan_id"))
    except (TypeError, ValueError):
        _fail("VLAN ID must be a number between 1 and 4094")
    if not 1 <= vlan <= 4094:
        _fail("VLAN ID must be between 1 and 4094")
    name = params.get("name")
    if name is not None and not isinstance(name, str):
        _fail("VLAN name must be text")
    name = (name or "").strip() or None
    if name is not None and (len(name) > 32 or not name.isprintable()):
        _fail("VLAN name must be printable text of at most 32 characters")
    if action == "add":
        if vlan in device.vlans:
            _fail(f"VLAN {vlan} already exists on {device.name}")
        summary = f"The proposed change creates VLAN {vlan}{f' ({name})' if name else ''} on {device.name}."
        return f"VLAN {vlan} not defined", f"VLAN {vlan} defined", f"VLAN {vlan}", summary, {
            "action": action, "vlan_id": vlan, "name": name}
    if vlan not in device.vlans:
        _fail(f"VLAN {vlan} does not exist on {device.name}")
    summary = f"The proposed change deletes {_vlan_label(device, vlan)} from {device.name}."
    return f"{_vlan_label(device, vlan)} defined", f"VLAN {vlan} not defined", f"VLAN {vlan}", summary, {
        "action": action, "vlan_id": vlan}


# ------------------------------------------------------ interface settings
_SETTINGS = {"speed": (10, 400000), "mtu": (576, 9216), "ospf_hello": (1, 65535), "ospf_dead": (1, 65535)}


def _settings_text(iface: IfaceM, keys) -> str:
    labels = {"speed": "speed {} Mb/s", "duplex": "{} duplex", "mtu": "MTU {}", "ospf_hello": "OSPF hello {} s",
              "ospf_dead": "OSPF dead {} s"}
    attr = {"speed": "speed_mbps"}
    return ", ".join(labels[k].format(getattr(iface, attr.get(k, k)) if getattr(iface, attr.get(k, k)) is not None
                                      else "default") for k in keys)


def _detect_interface_settings(model, device, iface, params):
    changed = {}
    for key, (low, high) in _SETTINGS.items():
        if params.get(key) is not None:
            value = _int_or_none(params[key])
            if value is None or not low <= value <= high:
                _fail(f"{key.replace('_', ' ')} must be between {low} and {high}")
            changed[key] = value
    if params.get("duplex") is not None:
        duplex = str(params["duplex"]).lower()
        if duplex not in ("full", "half", "auto"):
            _fail("Duplex must be full, half or auto")
        changed["duplex"] = duplex
    if not changed:
        _fail("Choose at least one setting: speed, duplex, MTU, OSPF hello or dead interval")
    if ("ospf_hello" in changed or "ospf_dead" in changed) and iface.ospf_area is None:
        _fail(f"{device.name} {iface.name} does not run OSPF")
    current = _settings_text(iface, changed)
    preview = IfaceM(0, 0, iface.name, None, None, None, "up", None, None, speed_mbps=changed.get("speed", iface.speed_mbps),
                     duplex=changed.get("duplex", iface.duplex), mtu=changed.get("mtu", iface.mtu),
                     ospf_hello=changed.get("ospf_hello", iface.ospf_hello), ospf_dead=changed.get("ospf_dead", iface.ospf_dead))
    proposed = _settings_text(preview, changed)
    summary = f"The proposed change sets {proposed} on {device.name} {iface.name} (currently {current})."
    return current, proposed, iface.name, summary, changed


# ------------------------------------------------------------ trunk settings
def _detect_trunk_settings(model, device, iface, params):
    if (iface.mode or ("access" if iface.vlan else "trunk")) != "trunk":
        _fail(f"{device.name} {iface.name} is not a trunk port")
    changed = {}
    if params.get("native_vlan") is not None:
        native = _int_or_none(params["native_vlan"])
        if native is None or not 1 <= native <= 4094:
            _fail("Native VLAN must be between 1 and 4094")
        changed["native_vlan"] = native
    if params.get("allowed_vlans") is not None:
        allowed = params["allowed_vlans"]
        if allowed == "all":
            changed["allowed_vlans"] = "all"
        else:
            try:
                values = sorted({int(v) for v in allowed})
            except (TypeError, ValueError):
                _fail("Allowed VLANs must be a list of VLAN numbers or 'all'")
            if not values or any(not 1 <= v <= 4094 for v in values):
                _fail("Allowed VLANs must be between 1 and 4094")
            changed["allowed_vlans"] = values
    if not changed:
        _fail("Set the native VLAN or the allowed VLAN list")

    def text(native, allowed):
        shown = "all" if allowed is None or allowed == "all" else ",".join(map(str, allowed))
        return f"native VLAN {native if native is not None else 1}, allowed {shown}"
    current = text(iface.native_vlan, iface.allowed_vlans)
    proposed = text(changed.get("native_vlan", iface.native_vlan), changed.get("allowed_vlans", iface.allowed_vlans))
    summary = f"The proposed change sets trunk {device.name} {iface.name} to {proposed} (currently {current})."
    return current, proposed, iface.name, summary, changed


# ------------------------------------------------------------- ACL reference
def _detect_acl_reference(model, device, iface, params):
    action = str(params.get("action", "")).lower()
    acl, where = str(params.get("acl") or "").strip(), str(params.get("where") or "").strip()
    if action not in ("remove", "define_permit_all") or not acl or not where:
        _fail("ACL reference changes need an action (remove or define_permit_all), the list name and where it is used")
    refs = (device.facts or {}).get("acl_references", [])
    if not any(r.get("acl") == acl and r.get("where") == where for r in refs):
        _fail(f"{device.name} has no reference to access list {acl} on {where}")
    current = f"{where} uses undefined list {acl}" if acl not in {r.acl_name for r in device.acl} else f"{where} uses {acl}"
    if action == "remove":
        proposed = f"{where}: reference to {acl} removed"
        summary = f"The proposed change removes the reference to access list {acl} from {device.name} {where}."
    else:
        proposed = f"{acl} defined with 'permit ip any any'"
        summary = (f"The proposed change defines access list {acl} on {device.name} with a single 'permit ip any any' "
                   f"entry, so {where} keeps its reference and filtering can be tightened later.")
    return current, proposed, where, summary, {"action": action, "acl": acl, "where": where}


# ------------------------------------------------------------ isolation VLAN
def _detect_isolate_endpoint(model, device, iface, params):
    if (iface.mode or ("access" if iface.vlan else "trunk")) != "access":
        _fail(f"{device.name} {iface.name} is not an access port")
    vlan = _int_or_none(params.get("vlan_id"))
    if vlan is None or not 2 <= vlan <= 4094:
        _fail("Isolation VLAN must be between 2 and 4094")
    if vlan == iface.vlan:
        _fail(f"{device.name} {iface.name} is already in VLAN {vlan}")
    name = (str(params.get("name") or "ISOLATED")).strip()[:32]
    current, proposed = _vlan_label(device, iface.vlan), f"VLAN {vlan} ({name})"
    summary = (f"The proposed change moves {device.name} {iface.name} from {current} into the separate VLAN {vlan} "
               f"({name}){' after creating it' if vlan not in device.vlans else ''}, isolating the endpoint at Layer 2.")
    return current, proposed, iface.name, summary, {"vlan_id": vlan, "name": name}


# ----------------------------------------------------------- spanning tree
def _detect_stp_root(model, device, iface, params):
    vlan = _int_or_none(params.get("vlan"))
    priority = _int_or_none(params.get("priority", 4096))
    if vlan is None or not 1 <= vlan <= 4094:
        _fail("VLAN must be between 1 and 4094")
    if vlan not in device.vlans:
        _fail(f"VLAN {vlan} is not defined on {device.name}")
    if priority is None or priority % 4096 or not 0 <= priority <= 61440:
        _fail("Bridge priority must be a multiple of 4096 between 0 and 61440")
    current_priority = ((device.facts or {}).get("stp_priority") or {}).get(str(vlan))
    current = f"priority {current_priority}" if current_priority is not None else "priority 32768 (default)"
    proposed = f"root bridge for VLAN {vlan}, priority {priority}"
    summary = (f"The proposed change enables Rapid PVST+ and makes {device.name} the spanning-tree root for VLAN {vlan} "
               f"(priority {priority}); redundant switch links then block on the side farthest from the root.")
    return current, proposed, f"VLAN {vlan}", summary, {"vlan": vlan, "priority": priority}


# ------------------------------------------------------- management hardening
HARDENING = {
    "secure_management": "Allow only SSH on every VTY line and disable the HTTP server",
    "ssh_only": "Allow only SSH on every VTY line",
    "disable_http": "Disable the cleartext HTTP management server",
    "remove_snmp_communities": "Remove SNMPv1/v2c community strings (use SNMPv3)",
    "restrict_vty": "Restrict VTY access to the management subnet with an access-class",
    "secure_passwords": "Encrypt passwords and use a type 9 (scrypt) enable secret",
    "shutdown_unused": "Shut down unused access ports",
}


def _detect_mgmt_hardening(model, device, iface, params):
    action = str(params.get("action", "")).lower()
    if action not in HARDENING:
        _fail(f"Hardening action must be one of: {', '.join(HARDENING)}")
    facts = device.facts or {}
    normalised = {"action": action}
    if action == "restrict_vty":
        try:
            network = validate_cidr(params.get("permit"), "Management subnet")
        except ValueError as exc:
            _fail(str(exc))
        normalised.update(permit=network, acl=str(params.get("acl") or "NETGUARD-MGMT")[:30])
    if action == "shutdown_unused":
        names = [str(n) for n in params.get("interfaces") or []]
        known = {i.name for i in device.interfaces.values()}
        if not names or any(n not in known for n in names):
            _fail("List the unused interfaces to shut down")
        normalised["interfaces"] = names[:48]
    current = {
        "secure_management": ("ip http server enabled; " if facts.get("http_server") else "") + (", ".join(
            f"line {l['lines']}: {' '.join(l['transport']) if l.get('transport') else 'default transport'}"
            for l in facts.get("vty", []) if l.get("kind") == "vty") or "no VTY lines"),
        "ssh_only": ", ".join(f"line {l['lines']}: {' '.join(l['transport']) if l.get('transport') else 'default transport'}"
                              for l in facts.get("vty", []) if l.get("kind") == "vty") or "no VTY lines",
        "disable_http": "ip http server enabled" if facts.get("http_server") else "HTTP server disabled",
        "remove_snmp_communities": f"{len(facts.get('snmp_communities', []))} community string(s)",
        "restrict_vty": ", ".join(f"line {l['lines']}: {l.get('access_class') or 'no access-class'}"
                                  for l in facts.get("vty", []) if l.get("kind") == "vty") or "no VTY lines",
        "secure_passwords": f"enable {facts.get('enable') or 'not set'}, password encryption "
                            f"{'on' if facts.get('password_encryption') else 'off'}",
        "shutdown_unused": ", ".join(normalised.get("interfaces", [])) + " enabled",
    }[action]
    proposed = HARDENING[action] + (f" ({normalised['permit']})" if action == "restrict_vty" else "")
    summary = f"The proposed change hardens {device.name}: {HARDENING[action].lower()}."
    return current, proposed, HARDENING[action], summary, normalised


# ------------------------------------------------------- physical remediation
PHYSICAL = {
    "replace_media": "Replace the cable or fit matching transceivers at both ends",
    "move_port": "Move the cable to another port",
    "clear_errors": "Replace the cable and clear the error counters",
}


def _detect_physical_remediation(model, device, iface, params):
    action = str(params.get("action", "")).lower()
    if action not in PHYSICAL:
        _fail(f"Physical action must be one of: {', '.join(PHYSICAL)}")
    link = model.link_for_iface(device.id, iface)
    if link is None:
        _fail(f"{device.name} {iface.name} has no cable in the model")
    normalised = {"action": action, "link_id": link.id}
    if action == "move_port":
        port = str(params.get("port") or "").strip()
        if not port or port == iface.name:
            _fail("Choose the port the cable moves to")
        if device.iface_by_name(port) and model.link_for_iface(device.id, device.iface_by_name(port)):
            _fail(f"{device.name} {port} is already cabled")
        normalised["port"] = port
        current, proposed = f"cable on {iface.name}", f"cable on {port}"
    elif action == "replace_media":
        current, proposed = "incompatible cable media", "compatible cable media at both ends"
    else:
        current = f"{iface.error_count or 0} interface errors"
        proposed = "new cable, counters cleared"
    summary = f"Physical work order on {device.name} {iface.name}: {PHYSICAL[action].lower()}" + \
        (f" ({normalised['port']})." if action == "move_port" else ".")
    return current, proposed, iface.name, summary, normalised


# ------------------------------------------------------------------ apply
def apply(model: NetworkModel, change: DetectedChange) -> NetworkModel:
    """Return a candidate copy of the model with the change applied."""
    candidate = model.copy()
    device = candidate.device(change.device_id)
    iface = device.interfaces.get(change.interface_id) if change.interface_id else None
    p = change.parameters
    kind = change.change_type
    if kind == "ip_address":
        iface.ip, iface.mask = p["ip_address"], p["subnet_mask"]
    elif kind == "default_gateway":
        device.gateway = p["gateway"]
    elif kind == "interface_status":
        iface.status = p["status"]
    elif kind == "ospf_area":
        iface.ospf_area = p["area"]
    elif kind == "ospf_network":
        iface.ospf_area = p["area"] if p["action"] == "advertise" else None
    elif kind == "static_route":
        if p["action"] == "remove":
            device.routes = [r for r in device.routes if r.id != p["route_id"]]
        elif p["action"] == "modify":
            route = next(r for r in device.routes if r.id == p["route_id"])
            route.destination, route.next_hop = p["destination"], p["next_hop"]
        else:
            device.routes.append(RouteM(-1, p["destination"], p["next_hop"]))
    elif kind == "acl_add":
        device.acl.append(AclM(-1, p["sequence"], p["action"], p["protocol"], p["source"], p["destination"], p["port"],
                               p.get("acl_name")))
    elif kind == "acl_remove":
        device.acl = [r for r in device.acl if r.id != p["rule_id"]]
    elif kind == "access_vlan":
        iface.vlan, iface.mode = p["vlan_id"], "access"
    elif kind == "vlan_database":
        if p["action"] == "add":
            device.vlans[p["vlan_id"]] = p.get("name")
        else:
            device.vlans.pop(p["vlan_id"], None)
    elif kind == "interface_settings":
        for key, value in p.items():
            setattr(iface, "speed_mbps" if key == "speed" else key, None if value == "auto" and key == "duplex" else value)
    elif kind == "trunk_settings":
        if "native_vlan" in p:
            iface.native_vlan = p["native_vlan"]
        if "allowed_vlans" in p:
            iface.allowed_vlans = None if p["allowed_vlans"] == "all" else list(p["allowed_vlans"])
    elif kind == "acl_reference":
        apply_acl_reference(device, p)
    elif kind == "isolate_endpoint":
        device.vlans.setdefault(p["vlan_id"], p.get("name"))
        iface.vlan, iface.mode = p["vlan_id"], "access"
    elif kind == "stp_root":
        apply_stp_root(candidate, device, p["vlan"], p["priority"])
    elif kind == "mgmt_hardening":
        apply_hardening(device, p)
    elif kind == "physical_remediation":
        apply_physical(candidate, device, iface, p)
    return candidate


def apply_acl_reference(device: DeviceM, p: dict) -> None:
    facts = dict(device.facts or {})
    if p["action"] == "remove":
        facts["acl_references"] = [r for r in facts.get("acl_references", [])
                                   if not (r.get("acl") == p["acl"] and r.get("where") == p["where"])]
        if p["where"].startswith("interface "):
            target = device.iface_by_name(p["where"].removeprefix("interface ").strip())
            if target is not None:
                target.acl_in = None if target.acl_in == p["acl"] else target.acl_in
                target.acl_out = None if target.acl_out == p["acl"] else target.acl_out
        for line in facts.get("vty", []):
            if p["where"] == f"line {line['lines']}" and line.get("access_class") == p["acl"]:
                line["access_class"] = None
    else:
        if not device.sorted_acl(p["acl"]):
            device.acl.append(AclM(-1, 10, "permit", "ip", "any", "any", None, p["acl"]))
        facts["defined_acls"] = sorted(set(facts.get("defined_acls", [])) | {p["acl"]})
    facts["undefined_acls"] = [r for r in facts.get("undefined_acls", [])
                               if not (r.get("acl") == p["acl"] and (p["action"] == "define_permit_all"
                                                                    or r.get("where") == p["where"]))]
    device.facts = facts


def apply_stp_root(model: NetworkModel, root: DeviceM, vlan: int, priority: int) -> None:
    """Spanning tree with `root` as the root bridge: tree links forward, every redundant link blocks one end."""
    from collections import deque
    from backend.services.forwarding import switchport_mode

    depth, parent_link = {root.id: 0}, {}
    queue = deque([root.id])
    trunk_links = []
    while queue:
        sid = queue.popleft()
        for link in model.links_of(sid):
            peer_id, peer_if_id = link.other(sid)
            peer = model.device(peer_id)
            local, remote = model.iface(sid, link.local_if(sid)), model.iface(peer_id, peer_if_id)
            if not (peer.is_switch and local and remote and local.up and remote.up):
                continue
            if switchport_mode(local) != "trunk" or switchport_mode(remote) != "trunk":
                continue
            if any(i.allowed_vlans is not None and vlan not in i.allowed_vlans for i in (local, remote)):
                continue
            if link.id not in {l.id for l in trunk_links}:
                trunk_links.append(link)
            if peer_id not in depth:
                depth[peer_id] = depth[sid] + 1
                parent_link[peer_id] = link.id
                queue.append(peer_id)
    tree = set(parent_link.values())
    for link in trunk_links:
        a_if, b_if = model.iface(link.a_dev, link.a_if), model.iface(link.b_dev, link.b_if)
        if link.id in tree:
            a_if.stp_state = b_if.stp_state = "forwarding"
            continue
        # The designated port is on the bridge closer to the root; the other end blocks.
        a_key, b_key = (depth.get(link.a_dev, 99), link.a_dev), (depth.get(link.b_dev, 99), link.b_dev)
        blocked, designated = (a_if, b_if) if a_key > b_key else (b_if, a_if)
        blocked.stp_state, designated.stp_state = "blocking", "forwarding"
    facts = dict(root.facts or {})
    facts["stp_priority"] = {**(facts.get("stp_priority") or {}), str(vlan): priority}
    facts["stp_mode"] = "rapid-pvst"
    root.facts = facts


def apply_hardening(device: DeviceM, p: dict) -> None:
    facts = dict(device.facts or {})
    vty = [dict(line) for line in facts.get("vty", [])]
    action = p["action"]
    if action == "secure_management":
        facts["http_server"] = False
        action = "ssh_only"
    if action == "ssh_only":
        for line in vty:
            if line.get("kind") == "vty":
                line["transport"] = ["ssh"]
        facts["ssh_version"] = "2"
    elif action == "disable_http":
        facts["http_server"] = False
    elif action == "remove_snmp_communities":
        facts["snmp_communities"] = []
    elif action == "restrict_vty":
        for line in vty:
            if line.get("kind") == "vty":
                line["access_class"] = p["acl"]
        refs = [r for r in facts.get("acl_references", []) if r.get("acl") != p["acl"]]
        facts["acl_references"] = refs + [{"acl": p["acl"], "where": f"line {line['lines']}"} for line in vty
                                          if line.get("kind") == "vty"]
        facts["defined_acls"] = sorted(set(facts.get("defined_acls", [])) | {p["acl"]})
        device.acl = [r for r in device.acl if r.acl_name != p["acl"]] + [
            AclM(-1, 10, "permit", "ip", p["permit"], "any", None, p["acl"])]
    elif action == "secure_passwords":
        facts["enable"] = "secret 9"
        facts["password_encryption"] = True
        facts["local_users"] = [{**u, "storage": "secret 9"} for u in facts.get("local_users", [])]
        for line in vty:
            if line.get("password") in ("cleartext", "type 7"):
                line["password"] = None
                line["login"] = "local"
    elif action == "shutdown_unused":
        for name in p["interfaces"]:
            target = device.iface_by_name(name)
            if target is not None:
                target.status = "admin-down"
    facts["vty"] = vty
    device.facts = facts


def apply_physical(model: NetworkModel, device: DeviceM, iface: IfaceM, p: dict) -> None:
    link = model.links.get(p["link_id"])
    if link is None:
        return
    if p["action"] == "replace_media":
        link.observation = {**(link.observation or {}), "media_override": True}
    elif p["action"] == "clear_errors":
        iface.error_count = 0
        peer_id, peer_if_id = link.other(device.id)
        peer_if = model.iface(peer_id, peer_if_id)
        if peer_if is not None:
            peer_if.error_count = 0
    elif p["action"] == "move_port":
        target = device.iface_by_name(p["port"])
        if target is None:
            new_id = min([0, *[i for d in model.devices.values() for i in d.interfaces]]) - 1
            target = IfaceM(new_id, device.id, p["port"], None, None, None, "up", None, None)
            device.interfaces[new_id] = target
        for attr in ("ip", "mask", "vlan", "mode", "ospf_area", "allowed_vlans", "native_vlan", "duplex", "mtu",
                     "ospf_hello", "ospf_dead", "acl_in", "acl_out", "description"):
            setattr(target, attr, getattr(iface, attr))
        target.status, target.speed_mbps, target.error_count = "up", None, None
        iface.ip = iface.mask = None
        iface.acl_in = iface.acl_out = None
        if link.a_dev == device.id and link.a_if == iface.id:
            link.a_if = target.id
        else:
            link.b_if = target.id


def catalogue() -> list[dict]:
    return [{"id": key, **{k: v for k, v in spec.items()}} for key, spec in CHANGE_TYPES.items()]
