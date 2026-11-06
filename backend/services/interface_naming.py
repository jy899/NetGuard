"""Interface conventions and the sample hardware catalogue; no device probing."""
from __future__ import annotations

import re


def platform_for(vendor, model, device_type, role=None) -> str:
    vendor, model = (vendor or "").lower(), (model or "").lower()
    kind, role = (device_type or "").lower(), (role or "").lower()
    if kind == "internet":
        return "cloud"
    if kind in {"pc", "server", "printer", "camera", "phone", "unknown", "laptop", "host"}:
        return "host"
    if "aruba" in vendor and ("ap-" in model or "access point" in role or kind == "ap"):
        return "aruba-ap"
    if "cisco" in vendor and kind in {"router", "switch", "firewall"}:
        return "cisco-ios"
    if "fortinet" in vendor or "fortigate" in vendor:
        return "fortios"
    if "aruba" in vendor and kind in {"router", "switch"}:
        return "arubaos-switch"
    return "generic"


_CISCO_PREFIXES = (
    ("TwentyFiveGigE", "Twe"), ("TenGigabitEthernet", "Te"),
    ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"),
    ("Port-channel", "Po"), ("Ethernet", "Et"), ("Loopback", "Lo"),
    ("Serial", "Se"), ("Vlan", "Vlan"), ("Gig", "Gi"), ("Ten", "Te"),
    ("Fas", "Fa"), ("Eth", "Et"), ("Ser", "Se"), ("Twe", "Twe"),
    ("Gi", "Gi"), ("Fa", "Fa"), ("Te", "Te"), ("Et", "Et"),
    ("Lo", "Lo"), ("Po", "Po"), ("Se", "Se"), ("Vl", "Vlan"),
    ("G", "Gi"), ("F", "Fa"), ("E", "Et"), ("S", "Se"),
)


def canonical_name(name, platform) -> str:
    value = (name or "").strip()
    if platform != "cisco-ios":
        return value
    compact = re.sub(r"\s+", "", value)
    for prefix, canonical in _CISCO_PREFIXES:
        if re.fullmatch(re.escape(prefix) + r"\d+(?:/\d+)*(?:\.\d+)?", compact, re.I):
            return canonical + compact[len(prefix):]
    return value


def _ports(model: str):
    model = model.lower().strip()
    if model in {"isr 4331", "cisco isr 4331"}:
        # Onboard ports: Gi0/0/0 is an RJ-45/SFP combo, Gi0/0/1 is RJ-45 only and Gi0/0/2 is an SFP-only slot.
        # The samples cable Gi0/0/0 on its RJ-45 side and fit Gi0/0/2 with a 1000BASE-T copper SFP.
        return {"Gi0/0/0": ("copper", 1000, "RJ-45/SFP combo (RJ-45 in use)"),
                "Gi0/0/1": ("copper", 1000, "1000BASE-T copper"),
                "Gi0/0/2": ("copper", 1000, "SFP slot with 1000BASE-T copper SFP")}
    if model in {"catalyst 2960x-24ts-l", "cisco catalyst 2960x-24ts-l"}:
        return {**{f"Gi1/0/{p}": ("copper", 1000, "1000BASE-T copper") for p in range(1, 25)},
                **{f"Gi1/0/{p}": ("fibre", 1000, "SFP fibre") for p in range(25, 29)}}
    if model in {"catalyst 9200-24t", "cisco catalyst 9200-24t"}:
        return {**{f"Gi1/0/{p}": ("copper", 1000, "1000BASE-T copper") for p in range(1, 25)},
                **{f"Gi1/1/{p}": ("fibre", None, "SFP fibre") for p in range(1, 5)}}
    if model in {"fortigate 60f", "fortigate-60f"}:
        # Ten RJ-45 ports: wan1, wan2, dmz, internal1-5 and the FortiLink-capable ports a and b.
        return {p: ("copper", 1000, "1000BASE-T copper")
                for p in ["wan1", "wan2", "dmz", *[f"internal{i}" for i in range(1, 6)], "a", "b"]}
    if model in {"aruba 2930f-24g-4sfp+", "2930f-24g-4sfp+"}:
        return {**{str(p): ("copper", 1000, "1000BASE-T copper") for p in range(1, 25)},
                **{str(p): ("fibre", 10000, "SFP+ fibre (1G/10G)") for p in range(25, 29)}}
    if model in {"aruba 2530-24g", "2530-24g"}:
        return {**{str(p): ("copper", 1000, "1000BASE-T copper") for p in range(1, 25)},
                **{str(p): ("fibre", 1000, "SFP fibre") for p in range(25, 29)}}
    return None


_LOGICAL = re.compile(r"^(?:(?:Po|Port-channel|Vlan|vlan|Lo|Loopback|Tunnel|Tu|Trk|trk|BAGG)\d|ssl\.)")


def port_info(vendor, model, device_type, name) -> dict:
    platform = platform_for(vendor, model, device_type)
    unknown = {"exists": None, "media": None, "max_speed": None, "label": "Unknown port hardware"}
    if platform == "host":
        # Only the sample convention is known; other host NIC names (Fa0, e0, Ethernet)
        # are valid elsewhere, so they stay unknown instead of "absent".
        if (name or "").strip() != "eth0":
            return unknown
        ports = {"eth0": ("copper", None, "Host NIC")}
    elif platform == "aruba-ap" and (model or "").lower() == "aruba ap-505":
        # The sample's device-neutral NIC represents the AP's physical E0 uplink.
        ports = {"eth0": ("copper", 1000, "AP-505 E0 copper uplink")}
    elif platform in {"cisco-ios", "fortios", "arubaos-switch"}:
        ports = _ports(model or "")
    else:
        return unknown
    if ports is None:
        return unknown
    key = canonical_name(name, platform)
    if platform == "cisco-ios":
        key = key.split(".", 1)[0]
    if _LOGICAL.match(key):
        # Aggregates, SVIs, loopbacks and tunnels are configured, not physical ports.
        return unknown
    if key not in ports:
        return {"exists": False, "media": None, "max_speed": None, "label": "Port absent from hardware model"}
    media, speed, label = ports[key]
    return {"exists": True, "media": media, "max_speed": speed, "label": label}
