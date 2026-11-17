"""Test fixture: a discovery engine that returns the recorded office sample. No packet is sent.

The application always uses RealDiscoveryEngine; the test suite installs this engine through
backend.services.discovery.service.engine_factory to regression-test fusion, classification and the credential
advisor against a known office network.

Each technique returns only what that technique could observe on a real network. Ground-truth cables are never
returned; switch neighbour and MAC tables become available only through an authenticated read.
"""
from __future__ import annotations

import ipaddress

from backend.tests.fixtures import office_sample as sample
from backend.services.discovery.engine import ProbeResult, observation

_ROLE_TYPES = {"firewall": "firewall", "switch": "switch"}


class SimulatedDiscoveryEngine:
    """Recorded-evidence test double (no packet is sent)."""

    def __init__(self, target: ipaddress.IPv4Network, excluded=None):
        self.target = target
        # The sample office is translated onto the first /24 of the target, exactly as the legacy inventory.
        self.base = ipaddress.IPv4Network(f"{target.network_address}/24", strict=False).network_address

    # ------------------------------------------------------------ addresses
    def ip(self, sample_ip: str) -> str:
        return str(self.base + int(sample_ip.rsplit(".", 1)[1]))

    def in_target(self, sample_ip: str) -> bool:
        return ipaddress.IPv4Address(self.ip(sample_ip)) in self.target

    def _recorded_ip(self, ip: str) -> str:
        return "172.16.10." + ip.rsplit(".", 1)[1]

    def _devices(self):
        return [d for d in sample.DEVICES if self.in_target(d["ip"])]

    # ------------------------------------------------------------ up/down monitoring
    down: set[str] = set()  # tests mark addresses as down here

    def reachable(self, targets):
        return {ip: ({"state": "down", "via": "no ICMP or TCP answer"} if ip in self.down else {"state": "up", "via": "ICMP echo"})
                for ip in targets}

    # ------------------------------------------------------------ credential-free
    def probe(self) -> ProbeResult:
        devices = self._devices()
        obs, names, services, engines = [], 0, 0, 0
        for d in devices:
            ip = self.ip(d["ip"])
            obs.append(observation("arp", ip, {"mac": d["mac"]}, f"ARP reply from {ip}: MAC {d['mac']}."))
            obs.append(observation("icmp", ip, {"reachable": True}, f"ICMP echo reply from {ip}."))
            vendor_line = next((e for e in d["evidence"] if e.startswith("MAC vendor")), None)
            manufacturer = vendor_line.split(":", 1)[1].split("(")[0].strip().rstrip(".") if vendor_line else None
            # Network equipment keeps the platform vendor its fingerprint names (needed for its command syntax).
            if d["type"] in ("switch", "firewall"):
                manufacturer = d["vendor"]
            obs.append(observation("oui", ip, {"vendor": manufacturer},
                                   vendor_line or (f"MAC {d['mac']} belongs to {manufacturer}." if manufacturer else
                                                   f"MAC {d['mac']} prefix has no registered vendor (locally administered).")))
            record = sample.NAME_RECORDS.get(d["ip"])
            if record:
                names += 1
                technique, name = record
                label = {"dns": "DNS PTR record", "netbios": "NetBIOS name", "mdns": "mDNS service name"}[technique]
                obs.append(observation(technique, ip, {"name": name}, f"{label} for {ip}: {name}."))
            ports = [p for p in d["ports"] if p != "SNMP"]
            banners = [e for e in d["evidence"] if not e.startswith(("SNMP", "MAC vendor", "DNS name", "NetBIOS"))]
            if ports or banners:
                services += 1
            role = sample.PROBE_ROLES.get(d["ip"], d["role"])
            obs.append(observation("tcp-banner", ip, {
                "services": ports, "role": role, "confidence": d["confidence"], "type": d["type"],
                "os": d["vendor"] if d["type"] not in ("switch", "firewall") else None,
                "icon": d["icon"], "identity_unknown": d["role"] == "Unknown host"},
                f"Service scan of {ip}: " + (", ".join(ports) if ports else "no open TCP service") +
                (". " + "; ".join(banners) + "." if banners else ".")))
            if d["ip"] in sample.CREDENTIAL_FREE_MODELS:
                technique, model = sample.CREDENTIAL_FREE_MODELS[d["ip"]]
                if technique == "tls-cert":
                    obs.append(observation("tls-cert", ip, {"model": model},
                                           f"TLS certificate on {ip} identifies a {model}."))
                elif self.in_target(sample.SENSOR["switch_ip"]) and d["ip"] == sample.SENSOR["switch_ip"]:
                    obs.append(observation("passive-lldp", ip, {"model": model, "name": "CORE-SW-01",
                                                                "sensor_port": sample.SENSOR["port"]},
                                           f"LLDP frame received on the NetGuard sensor port: system CORE-SW-01, port "
                                           f"{sample.SENSOR['port']}, {model}. This describes only the sensor's own cable."))
            if d["ip"] in sample.SNMPV3_ENGINES:
                engines += 1
                obs.append(observation("snmpv3-engine", ip, {"snmpv3": True},
                                       f"SNMPv3 engine discovery answered on {ip} (unauthenticated discovery message; "
                                       "no community string or user tried)."))
        gateway = next((d for d in devices if d["ip"] == "172.16.10.1"), None)
        if gateway:
            obs.append(observation("traceroute", self.ip(gateway["ip"]), {"gateway": True},
                                   f"Traceroute to {sample.INTERNET_TEST_ADDRESS}: hop 1 is {self.ip(gateway['ip'])} "
                                   "(default gateway). A layer-3 hop does not identify a cable."))
        no_response = [{"ip": self.ip(r["ip"]), "name": r["name"],
                        "detail": f"DNS record {r['name']} → {self.ip(r['ip'])} exists, but the address answered no ARP, "
                                  "ICMP or TCP probe."} for r in sample.DNS_ONLY if self.in_target(r["ip"])]
        timeline = [
            {"id": "arp", "label": "ARP sweep", "detail": f"{len(devices)} hosts answered with a MAC address", "count": len(devices)},
            {"id": "icmp", "label": "ICMP echo", "detail": f"{len(devices)} hosts reachable", "count": len(devices)},
            {"id": "names", "label": "Name resolution (DNS, NetBIOS, mDNS)",
             "detail": f"{names} names resolved" + (f"; {len(no_response)} record(s) without a responding host" if no_response else ""),
             "count": names},
            {"id": "services", "label": "Service fingerprinting (TCP banners, TLS certificates)",
             "detail": f"{services} hosts expose identifiable services", "count": services},
            {"id": "passive-lldp", "label": "Passive LLDP on the NetGuard sensor port",
             "detail": "Sensor attached to CORE-SW-01 port 23" if self.in_target(sample.SENSOR["switch_ip"]) else "No LLDP frame received",
             "count": 1 if self.in_target(sample.SENSOR["switch_ip"]) else 0},
            {"id": "snmpv3", "label": "SNMPv3 engine discovery (no community strings tried)",
             "detail": f"{engines} devices support SNMPv3", "count": engines},
            {"id": "traceroute", "label": "Traceroute to an internet test address",
             "detail": f"Default gateway {self.ip('172.16.10.1')}" if gateway else "No gateway hop in this target", "count": 1 if gateway else 0},
            {"id": "correlate", "label": "Correlation and classification",
             "detail": "Devices identified; cables stay unknown until a switch table is read", "count": len(devices)},
        ]
        return ProbeResult(observations=obs, timeline=timeline, no_response=no_response)

    # ------------------------------------------------------------ authentication
    def methods(self, ip: str) -> list[str]:
        return list(sample.AUTH_METHODS.get(self._recorded_ip(ip), []))

    def authenticate(self, ip: str, method: str, username: str, secret: str, priv_secret: str | None = None,
                     protocols: tuple[str, str] = ("SHA-256", "AES-128")) -> bool:
        if method not in self.methods(ip):
            return False
        if method == "snmpv3":
            # The sample devices are configured for SHA-256 / AES-128; other protocols fail as on a real agent.
            ref = sample.SNMPV3_SAMPLE
            return (username.strip() == ref["username"] and secret == ref["auth"] and priv_secret == ref["priv"]
                    and tuple(protocols) == ("SHA-256", "AES-128"))
        return username.strip() == "admin" and secret == "admin"

    # ------------------------------------------------------------ authenticated reads
    def collect(self, ip: str, method: str) -> list[dict]:
        sip = self._recorded_ip(ip)
        d = sample.by_ip(sip)
        label = {"ssh": "SSH", "https-api": "HTTPS API", "snmpv3": "SNMPv3"}[method]
        out = []

        def add(technique, facts, detail, subject=ip):
            out.append(observation(technique, subject, facts, f"Authenticated {label} read of {name}: {detail}",
                                   authenticated=True, method=method, observed_by=ip))

        if d["type"] == "switch" and sip in sample.AUTH_METHODS and sip != "172.16.10.70":
            read = d["read"]
            name = read["hostname"]
            add("system-info", {"hostname": name, "model": d["model"], "version": read["version"],
                                "serial": read["serial"], "role": d["role"]},
                f"{d['model']}, software {read['version']}, serial {read['serial']}.")
            ports = [{"port": port, "mode": mode, "vlan": vlan, "speed": 1000, **(sample.TRUNK if mode == "trunk" else {})}
                     for sw, port, mode, vlan in sample.SWITCH_PORTS if sw == sip]
            add("interface-table", {"ports": ports}, f"{len(ports)} active ports with mode, VLAN and speed.")
            add("vlan-table", {"vlans": [list(v) for v in sample.SWITCH_VLANS]}, "VLAN 20 DATA, VLAN 30 VOICE.")
            add("lldp-table", {"rows": self._lldp_rows(sip)}, f"{len(self._lldp_rows(sip))} LLDP neighbours.")
            rows = [{"port": port, "mac": mac, "vlan": vlan} for port, mac, vlan in sample.mac_tables()[sip]
                    if self._mac_in_target(mac)]
            add("mac-table", {"rows": rows}, f"{len(rows)} learned MAC addresses.")
        elif d["type"] == "firewall":
            fw = sample.FIREWALL_READ
            name = fw["hostname"]
            add("system-info", {"hostname": name, "model": d["model"], "version": d["read"]["version"],
                                "serial": d["read"]["serial"], "role": d["role"]},
                f"{d['model']}, FortiOS {d['read']['version']}.")
            add("interface-table", {"lan": {"name": fw["lan_interface"], "ip": self.ip(fw["lan_ip"]), "mask": fw["lan_mask"], "speed": 1000},
                                    "wan": fw["wan"]},
                f"{fw['lan_interface']} {self.ip(fw['lan_ip'])}/24; {fw['wan']} (WAN facts are kept as evidence only).")
            add("routing-table", {"default_route": fw["default_route"]}, f"default route {fw['default_route']}.")
            leases = []
            for lease_ip in fw["leases"]:
                host = sample.by_ip(lease_ip)
                if self.in_target(lease_ip):
                    leases.append({"ip": self.ip(lease_ip), "mac": host["mac"], "mask": "255.255.255.0",
                                   "router": self.ip(fw["dhcp_router"])})
            arp = [{"ip": self.ip(h["ip"]), "mac": h["mac"]} for h in sample.DEVICES if self.in_target(h["ip"]) and h["ip"] != fw["lan_ip"]]
            add("arp-table", {"entries": arp}, f"{len(arp)} ARP entries on {fw['lan_interface']}.")
            add("dhcp-leases", {"leases": leases},
                f"{len(leases)} DHCP leases in scope {self.ip('172.16.10.0')}/24 with router {self.ip(fw['dhcp_router'])}.")
        elif sip == "172.16.10.70":
            ap = sample.AP_READ
            name = ap["hostname"]
            add("system-info", {"hostname": name, "model": ap["model"], "version": ap["version"], "role": "Wireless access point"},
                f"{ap['model']}, ArubaOS {ap['version']}.")
            add("lldp-table", {"rows": self._lldp_rows(sip)}, "uplink LLDP neighbour.")
        return out

    def _mac_in_target(self, mac: str) -> bool:
        host = next((d for d in sample.DEVICES if d["mac"] == mac), None)
        return host is not None and self.in_target(host["ip"])

    def _lldp_rows(self, reader: str) -> list[dict]:
        rows = []
        for local_ip, port, chassis, mgmt, sys_name, port_id, descr in sample.LLDP_TABLES:
            if local_ip != reader or not self.in_target(mgmt):
                continue
            rows.append({"local_port": port, "chassis_mac": chassis, "mgmt_ip": self.ip(mgmt), "sys_name": sys_name,
                         "port_id": port_id, "sys_descr": descr, "model": sample.LLDP_MODELS.get(descr),
                         "role": sample.LLDP_ROLES.get(descr)})
        return rows
