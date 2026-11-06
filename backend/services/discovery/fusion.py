"""Build the stored topology from discovery observations only (the "no fabrication" contract).

Evidence grades:
- Confirmed: matching LLDP/CDP neighbour entries read from both devices (or an authoritative lab cable definition).
- Inferred: a single-sided LLDP/CDP entry, or one MAC learned on an edge port of a read switch; the endpoint side of
  a MAC attachment is "Unknown Port".
- Logical: two routed interfaces of read devices share a point-to-point subnet, with no layer-2 evidence.
- Unknown: a reachable host without any evidence of the port it is attached to (no link is stored).
MACs on uplink (transit) ports only locate a device behind a switch; they never create a cable. ICMP, DNS, the
gateway hop and DHCP facts never create a cable.
User edits (names, interface settings, positions) are preserved exactly as the legacy refresh does.
"""
from __future__ import annotations

import json
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models import Device, Interface, Link, Network, Vlan
from backend.services.discovery import classification
from backend.services.discovery.engine import METHOD_ORDER, SECURE_METHODS

UNKNOWN_PORT = "Unknown Port"
DISCOVERED_KINDS = ("lldp", "cdp", "mac", "subnet", "stp", "wireless", "segment", "route")
WIRELESS_PORT = __import__("re").compile(r"wlan|wi-?fi|radio|^ath\d|^wl\d|dot11|wireless|ssid|^ra\d|^rai\d", __import__("re").I)
_TECHNIQUE_LABELS = {
    "arp": "ARP", "icmp": "ICMP", "oui": "MAC vendor (OUI)", "dns": "DNS", "netbios": "NetBIOS", "mdns": "mDNS",
    "tcp-banner": "Service scan", "tls-cert": "TLS certificate", "passive-lldp": "Passive LLDP (sensor port)",
    "snmpv3-engine": "SNMPv3 engine discovery", "traceroute": "Traceroute", "system-info": "System information",
    "interface-table": "Interface table", "vlan-table": "VLAN table", "lldp-table": "LLDP neighbour table",
    "mac-table": "MAC address table", "routing-table": "Routing table", "dhcp-leases": "DHCP leases",
    "running-config": "Running configuration", "interface-status": "Interface state and counters",
    "address-table": "IPv4 address table", "arp-table": "ARP table", "syslog": "Syslog messages",
    "upnp": "UPnP (SSDP)", "web-portal": "Web management portal", "local-host": "This computer",
    "wifi-association": "Wi-Fi association", "stp-topology": "Spanning tree (BRIDGE-MIB)",
}


def is_access_point(facts: dict) -> bool:
    return "access point" in str(facts.get("role", "")).lower()


def is_infrastructure(device: Device, facts: dict) -> bool:
    return device.device_type in ("firewall", "router") or (device.device_type == "switch" and not is_access_point(facts))


def detected_methods(device: Device, facts: dict) -> tuple[list[str], list[str]]:
    """Secure management methods supported by observed services; cleartext or out-of-scope options listed separately."""
    services = [str(s) for s in facts.get("open_services", [])]
    infra = device.device_type in ("firewall", "switch", "router")
    methods, not_offered = [], []
    if infra and any(s.upper().startswith("SSH") for s in services):
        methods.append("ssh")
    if infra and facts.get("snmpv3"):
        methods.append("snmpv3")
    if infra:
        methods.append("snmpv2c")  # read-only community string the engineer supplies; never guessed
    for s in services:
        upper = s.upper()
        if upper.startswith("HTTP ") and infra:
            not_offered.append(f"{s} — cleartext web management; credentials are never sent over HTTP")
        if upper.startswith("TELNET"):
            not_offered.append(f"{s} — cleartext; not used")
    if not infra and services:
        not_offered.append("Host sign-in (SSH/WinRM/SMB) — outside NetGuard's discovery scope; its connection "
                           "comes from switch tables")
    if infra:
        not_offered.append("SNMPv1 — not used. SNMPv2c is cleartext: only a read-only community you supply is used, "
                           "and community strings are never guessed")
    return [m for m in METHOD_ORDER if m in methods], not_offered


def fuse(db: Session, network: Network) -> None:
    meta = dict(network.metadata_json or {})
    obs = list(meta.get("observations", []))
    discovery = {key: dict(value) for key, value in meta.get("discovery", {}).items()}
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.network_id == network.id))}
    ip_dev = {discovery[str(did)]["ip"]: dev for did, dev in devices.items() if str(did) in discovery}
    facts_of = lambda dev: discovery[str(dev.id)]  # noqa: E731

    by_subject = defaultdict(list)
    for o in obs:
        by_subject[o["subject"]].append(o)
    mac_ip = {o["facts"]["mac"].lower(): o["subject"] for o in obs if o["technique"] == "arp"}
    reads = defaultdict(dict)
    for o in obs:
        if o["authenticated"]:
            reads[o["observed_by"]][o["technique"]] = o
    leases = {lease["ip"]: lease for o in obs if o["technique"] == "dhcp-leases" for lease in o["facts"]["leases"]}
    lldp_rows = [(o["observed_by"], row, o) for o in obs if o["technique"] == "lldp-table" for row in o["facts"]["rows"]]
    gateway_ips = {o["subject"] for o in obs if o["technique"] == "traceroute"} | {lease["router"] for lease in leases.values()}
    plan_vlan = (meta.get("approved_vlan_plan") or {}).get("endpoint_data_vlan")

    def resolve(row) -> str | None:
        ip = mac_ip.get(str(row.get("chassis_mac", "")).lower())
        if ip in ip_dev:
            return ip
        if row.get("mgmt_ip") in ip_dev:
            return row["mgmt_ip"]
        return next((ip for ip, dev in ip_dev.items() if dev.name == row.get("sys_name")), None)

    # ------------------------------------------------------------ identity
    lldp_about = defaultdict(list)  # neighbour ip -> rows describing it
    for reader, row, _ in lldp_rows:
        target = resolve(row)
        if target:
            lldp_about[target].append((reader, row))
    for ip, dev in ip_dev.items():
        facts = facts_of(dev)
        probe = {o["technique"]: o["facts"] for o in by_subject[ip] if not o["authenticated"]}
        system = reads.get(ip, {}).get("system-info", {}).get("facts", {})
        about = [row for _, row in lldp_about.get(ip, [])]
        banner = probe.get("tcp-banner", {})
        name_sources = [(system.get("hostname"), "authenticated read")]
        name_sources += [(row.get("sys_name"), "LLDP sysName") for row in about]
        name_sources += [(probe.get("local-host", {}).get("hostname"), "this computer")]
        name_sources += [(probe.get(t, {}).get("name"), t.upper() if t != "mdns" else "mDNS") for t in ("dns", "netbios", "mdns")]
        name_sources += [(probe.get("passive-lldp", {}).get("name"), "passive LLDP")]
        name_sources += [(probe.get("upnp", {}).get("friendly_name"), "UPnP friendly name")]
        name, source = next(((n, s) for n, s in name_sources if n), (ip, "IP address"))
        user_named = facts.get("identity_source") == "user supplied" or (facts.get("auto_name") and dev.name != facts["auto_name"])
        taken = {other.name for other in devices.values() if other.id != dev.id}
        if name in taken:
            name, source = dev.name, facts.get("name_source", "IP address")  # never create a duplicate name
        if not user_named and dev.name != name:
            dev.name = name
        if not user_named:
            facts["auto_name"] = name
        facts["name_source"] = "user supplied" if user_named else source
        lldp_role = next((row.get("role") for row in about if row.get("role")), None)
        lldp_model = next((row.get("model") for row in about if row.get("model")), None)
        facts["role"] = system.get("role") or lldp_role or banner.get("role") or facts.get("role") or "Unidentified device"
        upnp = probe.get("upnp", {})
        model = system.get("model") or lldp_model or probe.get("tls-cert", {}).get("model") or \
            probe.get("passive-lldp", {}).get("model") or upnp.get("model")
        if model and not dev.model:
            dev.model = model
        if upnp.get("manufacturer") and not dev.vendor:
            dev.vendor = upnp["manufacturer"][:64]
        identified = bool(system or about)
        user_identity = facts.get("identity_source") == "user supplied"
        if system.get("type") in ("router", "switch", "firewall") and not user_identity:
            dev.device_type = system["type"]
        if system.get("platform"):
            dev.platform = system["platform"]
        facts["ssh_banner"] = banner.get("ssh_banner") or facts.get("ssh_banner")
        facts["ssh_port"] = banner.get("ssh_port") or facts.get("ssh_port")
        facts["vendor_hint"] = banner.get("network_vendor") or facts.get("vendor_hint")
        # Without a service scan answer (a host seen only in a router's ARP table, say) nothing names the device.
        facts["identity_unknown"] = (bool(banner.get("identity_unknown")) or not banner) and not identified and not user_identity
        facts["confidence"] = "high" if identified or user_identity else banner.get("confidence", "low")
        icon = banner.get("icon") or "unknown"
        role = facts["role"].lower()
        for word, value in (("camera", "camera"), ("phone", "phone"), ("printer", "printer"), ("access point", "ap")):
            if word in role:
                icon = value
        facts["icon"] = icon
        facts["display_type"] = "unknown" if facts["identity_unknown"] else dev.device_type
        services = list(banner.get("services", []))
        facts["snmpv3"] = bool(probe.get("snmpv3-engine"))
        if facts["snmpv3"]:
            services.append("SNMPv3 (UDP 161)")
        facts["open_services"] = services
        facts["portals"] = [{k: site.get(k) for k in ("url", "vendor", "product", "title", "login_page", "self_signed")}
                            for site in probe.get("web-portal", {}).get("portals", [])][:8]
        facts["mac"] = probe.get("arp", {}).get("mac")
        facts["methods"], facts["not_offered"] = detected_methods(dev, facts)
        facts["can_login"] = bool(facts["methods"])
        facts["gateway"] = ip in gateway_ips
        provenance = []
        for o in by_subject[ip] + [o for o in obs if o["authenticated"] and o["observed_by"] == ip and o["subject"] == ip and o not in by_subject[ip]]:
            provenance.append({"technique": _TECHNIQUE_LABELS.get(o["technique"], o["technique"]),
                               "access": f"authenticated {SECURE_METHODS.get(o['method'], o['method'])}" if o["authenticated"] else "credential-free",
                               "detail": o["detail"], "simulated": bool(o.get("simulated", False))})
        for reader, row in lldp_about.get(ip, []):
            reader_name = ip_dev[reader].name if reader in ip_dev else reader
            provenance.append({"technique": "LLDP neighbour table", "access": "authenticated read of " + reader_name,
                               "detail": f"{reader_name} port {row['local_port']} reports neighbour {row['sys_name']} "
                                         f"port {row['port_id']} ({row.get('sys_descr') or 'no description'}).", "simulated": False})
        facts["provenance"] = provenance
        facts["evidence"] = [f"{p['access']} — {p['technique']}: {p['detail']}" for p in provenance]

    # ------------------------------------------------------------ interfaces and links
    for link in db.scalars(select(Link).where(Link.network_id == network.id)):
        if link.kind in DISCOVERED_KINDS:
            db.delete(link)
    db.flush()
    existing = {(i.device_id, i.name): i for i in db.scalars(select(Interface).where(Interface.device_id.in_(devices)))}
    by_id = {i.id: i for i in existing.values()}

    def iface(dev: Device, name: str) -> Interface:
        """The interface fusion uses for an observed port name; a reviewed rename keeps its identity."""
        known = facts_of(dev).setdefault("iface_ids", {})
        # Drop mappings to deleted interfaces or to ids reused by another device (SQLite can reuse a deleted id).
        for key in [k for k, rid in known.items() if rid not in by_id or by_id[rid].device_id != dev.id]:
            known.pop(key)
        row = existing.get((dev.id, name))
        if row is None and known.get(name) in by_id:
            row = by_id[known[name]]
        if row is None:
            row = Interface(device_id=dev.id, name=name, status="up")
            db.add(row)
            db.flush()
            existing[(dev.id, name)] = row
            by_id[row.id] = row
        known[name] = row.id
        return row

    def rename(row: Interface, name: str) -> None:
        existing.pop((row.device_id, row.name), None)
        row.name = name
        devices_by_id = {d.id: d for d in devices.values()}
        facts_of(devices_by_id[row.device_id]).setdefault("iface_ids", {})[name] = row.id
        if row.description and row.description.startswith("NIC name not reported"):
            row.description = None
        existing[(row.device_id, name)] = row

    def endpoint_iface(dev: Device, port_id: str | None) -> Interface:
        ip = facts_of(dev)["ip"]
        # The NIC that already holds the endpoint address keeps its identity, including a reviewed rename.
        holder = next((i for (did, _), i in existing.items() if did == dev.id and i.ip_address == ip), None)
        if port_id:
            if (dev.id, port_id) in existing:
                row = existing[(dev.id, port_id)]
            elif holder is not None:
                row = holder
                if row.name == UNKNOWN_PORT:
                    rename(row, port_id)  # a later LLDP row names the NIC that was previously unknown
            elif (dev.id, UNKNOWN_PORT) in existing:
                row = existing[(dev.id, UNKNOWN_PORT)]
                rename(row, port_id)
            else:
                row = iface(dev, port_id)
        else:
            row = holder if holder is not None else iface(dev, UNKNOWN_PORT)
        other = next((i for (did, _), i in existing.items() if did == dev.id and i is not row and i.ip_address == ip), None)
        if not row.ip_address and other is None:
            row.ip_address = ip
        lease = leases.get(ip)
        if lease and row.ip_address == ip and not row.subnet_mask:
            row.subnet_mask = lease["mask"]
        if lease and not dev.default_gateway:
            dev.default_gateway = lease["router"]
        return row

    # Collected running configurations replace the configuration-derived model of the device.
    from backend.services import device_state
    from backend.models import DeviceConfig
    for ip, techniques in reads.items():
        dev = ip_dev.get(ip)
        running = techniques.get("running-config")
        if dev is None or running is None:
            continue
        config = db.get(DeviceConfig, running["facts"].get("config_id")) if running["facts"].get("config_id") else None
        text = config.text if config is not None and config.device_id == dev.id else None
        if text:
            parsed, warn = device_state.parse_one(text, dev.name)
            if parsed is not None:
                applied_warnings = list(warn)
                device_state.apply_config(db, dev, parsed, applied_warnings)
                facts_of(dev)["config_warnings"] = applied_warnings[:20]
                existing.update({(i.device_id, i.name): i for i in db.scalars(select(Interface).where(Interface.device_id == dev.id))})
                by_id.update({i.id: i for i in existing.values()})
        status = techniques.get("interface-status", {}).get("facts", {})
        if status:
            device_state.apply_operational(db, dev, status.get("ports", []), status.get("stp", {}))
        syslog = techniques.get("syslog", {}).get("facts", {}).get("lines")
        if syslog is not None or status:
            device_state.store_telemetry(dev, syslog, status.get("ports") if status else None, "discovery read")
        for address in techniques.get("address-table", {}).get("facts", {}).get("addresses", []):
            if address.get("interface") and address.get("ip"):
                row = iface(dev, address["interface"])
                row.ip_address = row.ip_address or address["ip"]
                row.subnet_mask = row.subnet_mask or address.get("mask")

    # Switch configuration from authenticated reads (seeded only where unset: reviewed edits survive).
    for ip, techniques in reads.items():
        dev = ip_dev.get(ip)
        if dev is None:
            continue
        table = techniques.get("interface-table", {}).get("facts", {})
        for port in table.get("ports", []):
            row = iface(dev, port["port"])
            if row.mode is None:
                row.mode = port["mode"]
                row.vlan_id = port["vlan"] if port["mode"] == "access" else None
            if row.speed_mbps is None:
                row.speed_mbps = port.get("speed")
            if port["mode"] == "trunk" and row.mode == "trunk":
                row.allowed_vlans = row.allowed_vlans if row.allowed_vlans is not None else list(port["allowed_vlans"])
                row.native_vlan = row.native_vlan if row.native_vlan is not None else port["native_vlan"]
                row.stp_state = row.stp_state or port["stp_state"]
        lan = table.get("lan")
        if lan:
            holder = next((i for (did, _), i in existing.items() if did == dev.id and i.ip_address == lan["ip"]), None)
            row = holder if holder is not None and (dev.id, lan["name"]) not in existing else iface(dev, lan["name"])
            facts_of(dev).setdefault("iface_ids", {})[lan["name"]] = row.id
            if not row.ip_address and holder is None:
                row.ip_address, row.subnet_mask = lan["ip"], lan["mask"]
            if row.speed_mbps is None and lan.get("speed"):
                row.speed_mbps = lan["speed"]
        vlans = techniques.get("vlan-table", {}).get("facts", {}).get("vlans", [])
        known = {v.vlan_id for v in db.scalars(select(Vlan).where(Vlan.device_id == dev.id))}
        for vlan_id, vlan_name in vlans:
            if vlan_id not in known:
                db.add(Vlan(device_id=dev.id, vlan_id=vlan_id, name=vlan_name))

    links, linked = [], set()
    uplink_ports, lldp_ports, uplink_neighbour = set(), set(), {}
    seen = set()
    directed = set()
    for reader, row, _ in lldp_rows:
        nb = resolve(row)
        if nb:
            directed.add((reader, row["local_port"], nb, row["port_id"]))
    for reader, row, o in lldp_rows:
        a, nb_ip = ip_dev.get(reader), resolve(row)
        b = ip_dev.get(nb_ip) if nb_ip else None
        if a is None or b is None:
            continue
        key = frozenset({(reader, row["local_port"]), (nb_ip, row["port_id"])})
        if key in seen:
            continue
        seen.add(key)
        a_infra, b_infra = is_infrastructure(a, facts_of(a)), is_infrastructure(b, facts_of(b))
        ia = iface(a, row["local_port"]) if a_infra else endpoint_iface(a, row["local_port"])
        ib = iface(b, row["port_id"]) if b_infra else endpoint_iface(b, row["port_id"])
        for x, ix, y, port in ((a, ia, b, row["port_id"]), (b, ib, a, row["local_port"])):
            if ix.description is None and is_infrastructure(x, facts_of(x)):
                ix.description = f"LLDP neighbour {y.name} port {port}"[:120]
        speeds = [i.speed_mbps for i in (ia, ib) if i.speed_mbps]
        lldp_ports |= {(reader, row["local_port"]), (nb_ip, row["port_id"])}
        if b_infra:
            uplink_ports.add((reader, row["local_port"]))
            uplink_neighbour[(reader, row["local_port"])] = b
        if a_infra:
            uplink_ports.add((nb_ip, row["port_id"]))
            uplink_neighbour[(nb_ip, row["port_id"])] = a
        reader_name = a.name
        protocol = (row.get("protocol") or "lldp").upper()
        both = (nb_ip, row["port_id"], reader, row["local_port"]) in directed
        evidence = [f"Authenticated {SECURE_METHODS.get(o['method'], o['method'])} read of "
                    f"{reader_name}: {protocol} neighbour on port {row['local_port']} is {row['sys_name']} port "
                    f"{row['port_id']}" + (f" (chassis {row['chassis_mac']})." if row.get("chassis_mac") else ".")]
        if both:
            evidence.append(f"{b.name} reports the matching neighbour {reader_name} port {row['local_port']}.")
        # LLDP frames use a reserved link-local multicast address that 802.1D bridges never forward, so an LLDP entry
        # received on a port proves direct adjacency. CDP frames can be flooded through an unmanaged switch, so one
        # CDP entry is an inference until the other end reports the same cable.
        grade = "Confirmed" if both or protocol == "LLDP" else "Inferred"
        links.append(Link(network_id=network.id, source_device_id=a.id, source_interface_id=ia.id,
                          destination_device_id=b.id, destination_interface_id=ib.id, kind="lldp", state="up",
                          confidence=0.97 if grade == "Confirmed" else 0.85, speed_mbps=min(speeds) if speeds else None,
                          evidence_json=json.dumps({
                              "evidence": evidence,
                              "missing": [] if grade == "Confirmed" else [f"A matching {protocol} entry read from {b.name}"],
                              "origin": "discovery", "connectivity": "physical",
                              "status": "confirmed" if grade == "Confirmed" else "inferred", "grade": grade})))
        linked |= {a.id, b.id}

    notes = defaultdict(list)
    behind: dict[int, tuple] = {}  # host id -> (network device it is located behind, evidence)
    for ip, techniques in reads.items():
        sw = ip_dev.get(ip)
        table = techniques.get("mac-table")
        if sw is None or table is None:
            continue
        by_port = defaultdict(list)
        for entry in table["facts"]["rows"]:
            by_port[entry["port"]].append(entry)
        for port, entries in by_port.items():
            if (ip, port) in uplink_ports:
                towards = uplink_neighbour.get((ip, port))
                for entry in entries:
                    host = ip_dev.get(mac_ip.get(entry["mac"].lower(), ""))
                    towards_read = towards is not None and "mac-table" in reads.get(facts_of(towards)["ip"], {})
                    if host is not None and not is_infrastructure(host, facts_of(host)) and towards is not None and not towards_read:
                        notes[host.id].append((sw, port, towards))
                continue
            if (ip, port) in lldp_ports:
                continue
            located = [(entry, ip_dev.get(mac_ip.get(entry["mac"].lower(), ""))) for entry in entries]
            located = [(entry, host) for entry, host in located if host is not None and host.id != sw.id]
            infra_here = {host.id: (entry, host) for entry, host in located if is_infrastructure(host, facts_of(host))}
            hosts_here = [(entry, host) for entry, host in located if not is_infrastructure(host, facts_of(host))]
            wireless = bool(WIRELESS_PORT.search(port))
            if len(infra_here) == 1 and len(entries) > 1:
                # The port leads to one discovered network device without LLDP/CDP: an uplink (inferred from the
                # MAC table); the endpoints learned on it are behind that device.
                entry, nb = next(iter(infra_here.values()))
                if frozenset({sw.id, nb.id}) not in {frozenset({l.source_device_id, l.destination_device_id}) for l in links}:
                    ia = iface(sw, port)
                    links.append(_link(network.id, sw, ia, nb, None, "mac", "Inferred", 0.7, [
                        f"Authenticated {SECURE_METHODS.get(table['method'], table['method'])} read of {sw.name}: "
                        f"the MAC {entry['mac']} of network device {nb.name} is learned on port {port}, together with "
                        f"{len(entries) - 1} other address(es): {port} is an uplink towards {nb.name}."],
                        ["LLDP/CDP on the link, or a MAC table read from " + nb.name], ia.speed_mbps))
                    linked |= {sw.id, nb.id}
                for _, host in hosts_here:
                    behind[host.id] = (nb, f"{sw.name} learned its MAC on {port}, the uplink towards {nb.name}")
                continue
            if infra_here or not hosts_here:
                continue
            ia = iface(sw, port)
            shared = len(entries) > 1
            for entry, host in hosts_here[:64]:
                ib = endpoint_iface(host, None)
                if ib.name == UNKNOWN_PORT and ib.description is None:
                    ib.description = f"NIC name not reported; MAC {entry['mac']} answered ARP"
                if ia.description is None:
                    ia.description = (f"{len(entries)} MAC addresses learned (VLAN {entry['vlan']})" if shared
                                      else f"MAC {entry['mac']} learned (VLAN {entry['vlan']})")
                evidence = [f"Authenticated {SECURE_METHODS.get(table['method'], table['method'])} read of {sw.name}: "
                            f"MAC {entry['mac']} is learned on port {port}"
                            + (f" (VLAN {entry['vlan']})" if entry.get('vlan') else "")
                            + (f", one of {len(entries)} addresses on that port: an unmanaged switch, hub or wireless "
                               "access point is probably between the port and this device." if shared else
                               ", the only address learned there."),
                            f"{host.name} answered ARP with MAC {entry['mac']}; its NIC name is not reported, so the "
                            "endpoint side is shown as Unknown Port."]
                missing = ["Endpoint NIC name (the endpoint does not send LLDP)"] + (
                    ["The intermediate unmanaged device (it has no address or management protocol)"] if shared else
                    ["Reciprocal evidence excluding an intermediate unmanaged device"])
                links.append(Link(network_id=network.id, source_device_id=sw.id, source_interface_id=ia.id,
                                  destination_device_id=host.id, destination_interface_id=ib.id,
                                  kind="wireless" if wireless else "mac", state="up",
                                  confidence=0.65 if shared else 0.8, speed_mbps=ia.speed_mbps, evidence_json=json.dumps({
                                      "evidence": evidence, "missing": missing, "origin": "discovery",
                                      "connectivity": "inferred", "status": "inferred", "grade": "Inferred",
                                      "media": "wireless" if wireless else None, "shared_port": shared,
                                      **({"expected_vlan": plan_vlan} if isinstance(plan_vlan, int) else {})})))
                linked |= {sw.id, host.id}
    # Logical: routed point-to-point subnets between read devices without layer-2 evidence.
    linked_pairs = {frozenset({l.source_device_id, l.destination_device_id}) for l in links}
    by_subnet = defaultdict(list)
    import ipaddress as _ipa
    for ip, techniques in reads.items():
        dev = ip_dev.get(ip)
        if dev is None or "running-config" not in techniques and "address-table" not in techniques:
            continue
        for row in existing.values():
            if row.device_id == dev.id and row.ip_address and row.subnet_mask and row.status != "admin-down":
                try:
                    net = _ipa.IPv4Interface(f"{row.ip_address}/{row.subnet_mask}").network
                except ValueError:
                    continue
                if net.prefixlen >= 29:
                    by_subnet[net].append((dev, row))
    for net, ends in by_subnet.items():
        if len(ends) != 2 or ends[0][0].id == ends[1][0].id:
            continue
        (a, ia), (b, ib) = ends
        if frozenset({a.id, b.id}) in linked_pairs or (a.device_type == "switch" and b.device_type == "switch"):
            continue
        links.append(Link(network_id=network.id, source_device_id=a.id, source_interface_id=ia.id,
                          destination_device_id=b.id, destination_interface_id=ib.id, kind="subnet", state="up",
                          confidence=0.5, evidence_json=json.dumps({
                              "evidence": [f"{a.name} {ia.name} ({ia.ip_address}) and {b.name} {ib.name} ({ib.ip_address}) "
                                           f"share the routed subnet {net}."],
                              "missing": ["Neighbour (LLDP/CDP) or lab evidence of the physical connection"],
                              "origin": "discovery", "connectivity": "logical", "status": "logical", "grade": "Logical"})))
        linked |= {a.id, b.id}
    _inference_tiers(network, devices, ip_dev, facts_of, by_subject, obs, reads, links, linked, behind, notes,
                     gateway_ips, iface, endpoint_iface, existing, mac_ip)
    owned = lambda did, iid: iid is None or iid not in by_id or by_id[iid].device_id == did  # noqa: E731
    for link in links:
        # Defence in depth: never persist a link whose interface belongs to another device.
        if owned(link.source_device_id, link.source_interface_id) and owned(link.destination_device_id, link.destination_interface_id):
            db.add(link)
    db.flush()
    # Lease-derived addressing is a per-device fact (it never creates a cable).
    for ip, dev in ip_dev.items():
        lease = leases.get(ip)
        facts_of(dev)["lease"] = {"mask": lease["mask"], "router": lease["router"]} if lease else None
        if lease and not dev.default_gateway:
            dev.default_gateway = lease["router"]
    # Hosts found through a router's ARP table: the read router interface whose subnet holds the host gives its
    # mask and default gateway (the host itself is never logged in to).
    routed = []
    for row in existing.values():
        owner = devices.get(row.device_id)
        if owner is not None and owner.device_type in ("router", "firewall", "switch") and row.ip_address and row.subnet_mask:
            try:
                routed.append((_ipa.IPv4Interface(f"{row.ip_address}/{row.subnet_mask}").network, row))
            except ValueError:
                continue
    for ip, dev in ip_dev.items():
        if is_infrastructure(dev, facts_of(dev)) or leases.get(ip):
            continue
        address = _ipa.IPv4Address(ip)
        match = max((pair for pair in routed if address in pair[0] and str(address) != pair[1].ip_address),
                    key=lambda pair: pair[0].prefixlen, default=None)
        if match is None or match[0].prefixlen >= 31:
            continue
        net, gw = match
        nic = endpoint_iface(dev, None)
        if nic.ip_address == ip and not nic.subnet_mask:
            nic.subnet_mask = str(net.netmask)
        if not dev.default_gateway:
            dev.default_gateway = gw.ip_address
        facts_of(dev)["addressing"] = f"Subnet {net} and gateway {gw.ip_address} from the read interface of {devices[gw.device_id].name}."

    cabled = {d for l in links if json.loads(l.evidence_json or "{}").get("grade") != "Logical"
              for d in (l.source_device_id, l.destination_device_id)}
    for ip, dev in ip_dev.items():
        facts = facts_of(dev)
        facts["location_notes"] = [] if dev.id in cabled else [
            f"Reached through {sw.name} port {port} towards {towards.name}; exact switch port unknown — "
            f"authenticate {towards.name} to read its MAC table." for sw, port, towards in notes.get(dev.id, [])]
        facts["interfaces_known"] = bool(reads.get(ip, {}).get("interface-table")) or dev.id in cabled
        auth = facts.get("auth")
        facts["auth_status"] = "success" if auth == "success" else "failure" if auth == "failed" else "unassigned"
        facts.setdefault("position_source", "auto")

    _layout(devices, discovery, ip_dev, links, gateway_ips)
    meta["discovery"] = discovery
    network.metadata_json = meta
    db.flush()
    classification.classify(db, network)


def _link(network_id, a, ia, b, ib, kind, grade, confidence, evidence, missing, speed=None, **extra) -> Link:
    connectivity = {"Confirmed": "physical", "Inferred": "inferred", "Logical": "logical"}.get(grade, "unknown")
    return Link(network_id=network_id, source_device_id=a.id, source_interface_id=ia.id if ia is not None else None,
                destination_device_id=b.id, destination_interface_id=ib.id if ib is not None else None, kind=kind,
                state="up", confidence=confidence, speed_mbps=speed, evidence_json=json.dumps({
                    "evidence": evidence, "missing": missing, "origin": "discovery", "connectivity": connectivity,
                    "status": grade.lower(), "grade": grade, **extra}))


def _inference_tiers(network, devices, ip_dev, facts_of, by_subject, obs, reads, links, linked, behind, notes,
                     gateway_ips, iface, endpoint_iface, existing, mac_ip) -> None:
    """Link tiers after LLDP/CDP and MAC tables, strongest evidence first; each tier only links devices that the
    stronger tiers left unconnected, and every link carries its grade and the evidence it rests on.

    1. Spanning tree (BRIDGE-MIB): a port whose designated bridge is another read switch faces that switch.
    2. Wi-Fi association of this computer (its own adapter reports the access point BSSID).
    3. Behind an uplink: a switch learned the host's MAC on the uplink towards another network device.
    4. Same segment: an address of this computer's own subnet (ARP-resolved) reaches the subnet's gateway.
    5. Routed subnet: a host in the subnet of a read router interface (router ARP, lease) is served by it.
    6. Traceroute: consecutive layer-3 hops.
    Tiers 3-6 are Logical: they show how traffic reaches the device, never which cable or switch port it uses.
    """
    import ipaddress as _ipa

    from backend.collectors.netutil import mac_distance

    pairs = {frozenset({l.source_device_id, l.destination_device_id}) for l in links}

    def add(link):
        pairs.add(frozenset({link.source_device_id, link.destination_device_id}))
        links.append(link)
        linked.update({link.source_device_id, link.destination_device_id})

    # 1. spanning tree
    bridges = {}
    for ip, techniques in reads.items():
        stp = techniques.get("stp-topology", {}).get("facts", {})
        if ip in ip_dev and stp.get("bridge_mac"):
            bridges[stp["bridge_mac"].lower()] = ip_dev[ip]
    for ip, techniques in reads.items():
        stp = techniques.get("stp-topology", {}).get("facts", {})
        a = ip_dev.get(ip)
        if a is None or not stp.get("designated"):
            continue
        own = (stp.get("bridge_mac") or "").lower()
        for port, designated in stp["designated"].items():
            b = bridges.get(str(designated).lower())
            if b is None or b.id == a.id or str(designated).lower() == own or frozenset({a.id, b.id}) in pairs:
                continue
            add(_link(network.id, a, iface(a, port), b, None, "stp", "Inferred", 0.75, [
                f"Spanning tree on {a.name} (BRIDGE-MIB): the designated bridge of port {port} is {designated}, the "
                f"bridge address of {b.name}; {port} therefore faces {b.name}."],
                [f"The port of {b.name} (LLDP/CDP, or its spanning-tree port table)"]))

    # 2. this computer's Wi-Fi association
    local = next((o for o in obs if o["technique"] == "local-host"), None)
    local_dev = ip_dev.get(local["subject"]) if local else None
    wifi = next((o for o in obs if o["technique"] == "wifi-association"), None)
    gateway_dev = next((ip_dev[g] for g in gateway_ips if g in ip_dev), None)
    if local_dev is not None and wifi is not None and not any(local_dev.id in p for p in pairs):
        bssid = wifi["facts"].get("bssid")
        candidates = []
        for dev_ip, dev in ip_dev.items():
            if dev.id == local_dev.id:
                continue
            mac = next((o["facts"].get("mac") for o in by_subject.get(dev_ip, []) if o["technique"] == "arp"), None)
            distance = mac_distance(bssid, mac)
            if distance is not None and distance <= 8:
                candidates.append((distance, dev.id != (gateway_dev.id if gateway_dev else None), dev, mac))
        nic = endpoint_iface(local_dev, local["facts"].get("interface"))
        detail = (f"This computer's adapter '{local['facts'].get('interface')}' is associated with SSID "
                  f"'{wifi['facts'].get('ssid') or '?'}', access point radio BSSID {bssid}"
                  + (f" (signal {wifi['facts']['signal']})" if wifi["facts"].get("signal") else "") + ".")
        if candidates:
            distance, _, ap, mac = min(candidates, key=lambda c: (c[0], c[1]))
            grade = "Confirmed" if distance == 0 else "Inferred"
            add(_link(network.id, local_dev, nic, ap, None, "wireless", grade, 0.95 if grade == "Confirmed" else 0.8,
                      [detail, (f"The BSSID is {ap.name}'s own MAC {mac}." if distance == 0 else
                                f"The BSSID differs from {ap.name}'s MAC {mac} only in the last byte (+{distance}), "
                                "the usual offset between an access point's LAN MAC and its radio.")],
                      [] if grade == "Confirmed" else [f"The access point's radio MAC list read from {ap.name}"],
                      media="wireless", ssid=wifi["facts"].get("ssid"), bssid=bssid))
        elif gateway_dev is not None:
            add(_link(network.id, local_dev, nic, gateway_dev, None, "wireless", "Logical", 0.5,
                      [detail, f"No discovered address matches that BSSID, so the access point itself is not shown; "
                               f"this computer reaches its default gateway {gateway_dev.name} through it."],
                      ["The access point's management address (it is a bridge without an address in this range)"],
                      media="wireless", ssid=wifi["facts"].get("ssid"), bssid=bssid))

    # 3. behind an uplink towards another network device
    for host_id, (towards, why) in behind.items():
        host = devices.get(host_id)
        if host is None or any(host_id in p for p in pairs):
            continue
        add(_link(network.id, towards, None, host, endpoint_iface(host, None), "segment", "Logical", 0.45,
                  [f"{why}; the exact port on {towards.name} is not known."],
                  [f"A MAC address table read from {towards.name}"]))
    for host_id, entries in notes.items():
        host = devices.get(host_id)
        if host is None or any(host_id in p for p in pairs) or not entries:
            continue
        sw, port, towards = entries[0]
        add(_link(network.id, towards, None, host, endpoint_iface(host, None), "segment", "Logical", 0.45,
                  [f"{sw.name} learned the host's MAC on {port}, the uplink towards {towards.name}; the exact port on "
                   f"{towards.name} is not known."], [f"A MAC address table read from {towards.name}"]))

    # 4. same segment as this computer: the subnet's gateway serves it
    segment = None
    if local is not None and local["facts"].get("mask"):
        try:
            segment = _ipa.IPv4Interface(f"{local['subject']}/{local['facts']['mask']}").network
        except ValueError:
            segment = None
    if gateway_dev is not None:
        gw_ip = facts_of(gateway_dev)["ip"]
        if segment is None:
            # Without this computer in range, the gateway's own /24 is assumed only for ARP-resolved neighbours.
            segment = _ipa.IPv4Interface(f"{gw_ip}/24").network
        gw_if = next((row for (did, _), row in existing.items() if did == gateway_dev.id and row.ip_address == gw_ip), None)
        for dev_ip, dev in ip_dev.items():
            if dev.id == gateway_dev.id or any(dev.id in p for p in pairs):
                continue
            try:
                inside = _ipa.IPv4Address(dev_ip) in segment
            except ValueError:
                continue
            arp_seen = any(o["technique"] == "arp" for o in by_subject.get(dev_ip, []))
            if not inside or not arp_seen:
                continue
            add(_link(network.id, gateway_dev, gw_if, dev, endpoint_iface(dev, None), "segment", "Logical", 0.4, [
                f"{dev.name} answered ARP on {segment}, the same broadcast domain as this computer, whose default "
                f"gateway is {gateway_dev.name} ({gw_ip}).",
                "The switch or access point between them is not visible without a managed switch read (LLDP or MAC table)."],
                ["Switch port (authenticate the switch or access point to read its MAC table)"]))

    # 5. hosts in the subnet of a read router interface (found in its ARP table or DHCP leases)
    routed = []
    for (did, _), row in existing.items():
        owner = devices.get(did)
        if owner is not None and owner.device_type in ("router", "firewall", "switch") and row.ip_address and row.subnet_mask:
            try:
                routed.append((_ipa.IPv4Interface(f"{row.ip_address}/{row.subnet_mask}").network, row, owner))
            except ValueError:
                continue
    for dev_ip, dev in ip_dev.items():
        if any(dev.id in p for p in pairs):
            continue
        try:
            address = _ipa.IPv4Address(dev_ip)
        except ValueError:
            continue
        match = max((m for m in routed if address in m[0] and m[1].ip_address != dev_ip and m[2].id != dev.id),
                    key=lambda m: m[0].prefixlen, default=None)
        if match is None or match[0].prefixlen >= 31:
            continue
        net, row, owner = match
        add(_link(network.id, owner, row, dev, endpoint_iface(dev, None), "segment", "Logical", 0.45, [
            f"{dev.name} ({dev_ip}) is in {net}, the subnet of {owner.name} {row.name} ({row.ip_address})."],
            ["Switch port (a MAC address table read on that subnet's switch)"]))

    # 6. traceroute: consecutive layer-3 hops present in the discovery
    path = next((o["facts"].get("path") for o in obs if o["technique"] == "traceroute" and o["facts"].get("path")), None)
    if path:
        chain = [ip_dev[h] for h in path if h in ip_dev]
        start = local_dev if local_dev is not None else gateway_dev
        if start is not None and chain and chain[0].id != start.id:
            chain = [start] + chain
        for a, b in zip(chain, chain[1:]):
            if a.id != b.id and frozenset({a.id, b.id}) not in pairs:
                add(_link(network.id, a, None, b, None, "route", "Logical", 0.4,
                          [f"Traceroute: {b.name} is the next layer-3 hop after {a.name}."],
                          ["Layer-2 evidence of the connection (a traceroute hop is not a cable)"]))


def _layout(devices, discovery, ip_dev, links, gateway_ips) -> None:
    """Hierarchy from observed facts; devices placed by the user keep their positions."""
    facts_of = lambda dev: discovery[str(dev.id)]  # noqa: E731
    neighbours = defaultdict(set)
    for link in links:
        neighbours[link.source_device_id].add(link.destination_device_id)
        neighbours[link.destination_device_id].add(link.source_device_id)
    gateway_ids = {dev.id for ip, dev in ip_dev.items() if ip in gateway_ips}

    def level(dev) -> int:
        if dev.id in gateway_ids:
            return 1
        if is_infrastructure(dev, facts_of(dev)) and dev.device_type == "switch":
            switch_nb = [n for n in neighbours[dev.id] if devices[n].device_type == "switch" and not is_access_point(facts_of(devices[n]))]
            return 2 if (neighbours[dev.id] & gateway_ids) or len(switch_nb) >= 2 else 3
        return 4

    levels = {did: level(dev) for did, dev in devices.items() if str(did) in discovery}
    parents = {}
    for link in links:
        a, b = link.source_device_id, link.destination_device_id
        if levels.get(a, 4) < levels.get(b, 4):
            parents.setdefault(b, a)
        elif levels.get(b, 4) < levels.get(a, 4):
            parents.setdefault(a, b)
    children = defaultdict(list)
    for child, parent in parents.items():
        children[parent].append(child)
    linked = {did for did in levels if neighbours[did]}
    movable = {did for did in levels if discovery[str(did)].get("position_source", "auto") == "auto"}
    cursor = [0.0]

    def place(did, depth):
        kids = sorted((c for c in children.get(did, []) if c in linked), key=lambda c: (levels[c], c))
        xs = [place(c, depth + 1) for c in kids]
        if xs:
            x = (min(xs) + max(xs)) / 2
        else:
            x = cursor[0]
            cursor[0] += 190
        if did in movable:
            devices[did].x_position, devices[did].y_position = x, depth * 200
        return x

    roots = sorted((did for did in linked if did not in parents), key=lambda did: (levels[did], did))
    for root in roots:
        place(root, levels[root] - 1 if levels[root] > 1 else 0)
    bottom = max((devices[did].y_position for did in linked), default=-200) + 230
    unlinked = sorted((did for did in levels if did not in linked), key=lambda did: (levels[did], did))
    for index, did in enumerate(unlinked):
        if did in movable:
            devices[did].x_position, devices[did].y_position = (index % 6) * 190, bottom + (index // 6) * 160
        discovery[str(did)]["unknown_row"] = True
    for did in linked:
        discovery[str(did)]["unknown_row"] = False
