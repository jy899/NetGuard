"""Supplied office discovery records for the FYP1 simulated network workflow.

Host probes, authorized collector reads and cable inventory are separate sample
evidence sources. SNMP information requires configured collector access; an IP
response alone cannot provide it. Optional interactive device access opens a
read-only sample console. The prototype never sends a network packet.
"""
from __future__ import annotations

SUBNET = "172.16.10.0/24"
DEVICE_PASSWORD = "admin"  # Sample authentication only; never returned in inventory or logs.

# Credential profiles saved in the Account Center of the final system (passwords not shown, stored encrypted).
PROFILES = [
    {"id": 1, "name": "Access switches", "username": "admin", "port": None, "priority": 10},
    {"id": 2, "name": "Core switches", "username": "admin", "port": None, "priority": 20},
    {"id": 3, "name": "Firewalls", "username": "admin", "port": 2222, "priority": 30},
]

# level: 1 firewall or gateway, 2 core, 3 access, 4 end devices (the layout's design order)
DEVICES = [
    {"ip": "172.16.10.1", "found_as": "172.16.10.1", "type": "firewall", "icon": "firewall", "level": 1,
     "vendor": "Fortinet", "model": "FortiGate 60F", "role": "Firewall (default gateway)", "confidence": "high",
     "mac": "70:4c:a5:11:22:33", "ports": ["SSH 2222", "HTTPS 10443"], "web": "https://172.16.10.1:10443",
     "ssh_port": 2222, "login_profile": 3,
     "evidence": ["TLS certificate on HTTPS 10443: FGT60FTK21000001, Fortinet, FortiGate",
                  "Web page on 10443 redirects to /login",
                  "SSH answers on moved port 2222",
                  "MAC vendor: Fortinet, Inc.",
                  "Default gateway of this subnet"],
     "read": {"hostname": "FGT-HQ", "platform": "FortiOS", "version": "v7.2.5 build1517", "serial": "FGT60FTK21000001"},
     "prompt": "FGT-HQ # "},
    {"ip": "172.16.10.2", "found_as": "CORE-SW-01", "type": "switch", "icon": "switch", "level": 2,
     "vendor": "HPE Aruba", "model": "Aruba 2930F-24G-4SFP+", "role": "Layer 3 switch (core)", "confidence": "high",
     "mac": "94:f1:28:aa:00:00", "ports": ["SSH 22", "HTTP 80", "SNMP"], "web": "http://172.16.10.2",
     "ssh_port": 22, "login_profile": 2,
     "evidence": ["SNMP sysObjectID 1.3.6.1.4.1.11.2.3.7.11.181 belongs to HPE",
                  "SNMP sysDescr: Aruba JL253A 2930F-24G-4SFP+ Switch, revision WC.16.10.0010",
                  "SNMP sysServices: bridging and routing (layer 3 switch)",
                  "SNMP sysName: CORE-SW-01", "Web page on HTTP 80: switch management page"],
     "read": {"hostname": "CORE-SW-01", "platform": "ArubaOS-Switch", "version": "WC.16.10.0010", "serial": "SG9ZKMX0AA"},
     "prompt": "CORE-SW-01# "},
    {"ip": "172.16.10.11", "found_as": "ACC-SW-01", "type": "switch", "icon": "switch", "level": 3,
     "vendor": "HPE Aruba", "model": "Aruba 2530-24G", "role": "Switch (access)", "confidence": "high",
     "mac": "94:f1:28:bb:01:00", "ports": ["SSH 22", "HTTP 80", "SNMP"], "web": "http://172.16.10.11",
     "ssh_port": 22, "login_profile": 1,
     "evidence": ["SNMP sysObjectID belongs to HPE", "SNMP sysDescr: Aruba J9776A 2530-24G Switch, revision YA.16.10.0012",
                  "SNMP sysServices: bridging (layer 2 switch)", "SNMP sysName: ACC-SW-01",
                  "Web page on HTTP 80: switch management page"],
     "read": {"hostname": "ACC-SW-01", "platform": "ArubaOS-Switch", "version": "YA.16.10.0012", "serial": "CN83HKW0P1"},
     "prompt": "ACC-SW-01# "},
    {"ip": "172.16.10.12", "found_as": "ACC-SW-02", "type": "switch", "icon": "switch", "level": 3,
     "vendor": "HPE Aruba", "model": "Aruba 2530-24G", "role": "Switch (access)", "confidence": "high",
     "mac": "94:f1:28:bb:02:00", "ports": ["SSH 22", "HTTP 80", "SNMP"], "web": "http://172.16.10.12",
     "ssh_port": 22, "login_profile": 1,
     "evidence": ["SNMP sysObjectID belongs to HPE", "SNMP sysDescr: Aruba J9776A 2530-24G Switch, revision YA.16.10.0012",
                  "SNMP sysServices: bridging (layer 2 switch)", "SNMP sysName: ACC-SW-02",
                  "Web page on HTTP 80: switch management page"],
     "read": {"hostname": "ACC-SW-02", "platform": "ArubaOS-Switch", "version": "YA.16.10.0012", "serial": "CN83HKW0Q7"},
     "prompt": "ACC-SW-02# "},
    {"ip": "172.16.10.20", "found_as": "SRV-FILE-01", "type": "server", "icon": "server", "level": 4,
     "vendor": "Linux", "model": None, "role": "Linux or Unix host", "confidence": "medium",
     "mac": "00:50:56:9a:10:20", "ports": ["SSH 22", "SMB 445"], "web": None, "ssh_port": 22, "login_profile": None,
     "evidence": ["SSH banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "File sharing (SMB) open",
                  "MAC vendor: VMware, Inc. (a virtual machine)", "DNS name: srv-file-01"]},
    {"ip": "172.16.10.31", "found_as": "PC-FIN-01", "type": "pc", "icon": "laptop", "level": 4,
     "vendor": "Microsoft", "model": None, "role": "Windows computer", "confidence": "medium",
     "mac": "3c:52:82:01:31:31", "ports": ["SMB 445", "RDP 3389"], "web": None, "ssh_port": None, "login_profile": None,
     "evidence": ["NetBIOS name PC-FIN-01", "Windows ports open: remote desktop, file sharing", "MAC vendor: HP Inc."]},
    {"ip": "172.16.10.32", "found_as": "PC-HR-02", "type": "pc", "icon": "laptop", "level": 4,
     "vendor": "Microsoft", "model": None, "role": "Windows computer", "confidence": "medium",
     "mac": "3c:52:82:01:32:32", "ports": ["SMB 445"], "web": None, "ssh_port": None, "login_profile": None,
     "evidence": ["NetBIOS name PC-HR-02", "Windows ports open: file sharing", "MAC vendor: HP Inc."]},
    {"ip": "172.16.10.40", "found_as": "PRN-01", "type": "server", "icon": "printer", "level": 4,
     "vendor": "Brother", "model": None, "role": "Printer", "confidence": "medium",
     "mac": "00:80:77:40:40:40", "ports": ["HTTP 80", "IPP 631", "Raw print 9100"], "web": "http://172.16.10.40",
     "ssh_port": None, "login_profile": None,
     "evidence": ["Printer ports open (IPP 631, raw printing 9100)", "Web page title: Printer status",
                  "MAC vendor: Brother Industries"]},
    {"ip": "172.16.10.50", "found_as": "172.16.10.50", "type": "server", "icon": "camera", "level": 4,
     "vendor": "CCTV", "model": None, "role": "Camera or recorder", "confidence": "medium",
     "mac": "c0:56:e3:50:50:50", "ports": ["HTTP 80", "RTSP 554"], "web": "http://172.16.10.50",
     "ssh_port": None, "login_profile": None,
     "evidence": ["Video stream port (RTSP 554) open", "Web page title: Network Camera", "MAC vendor: Hikvision"]},
    {"ip": "172.16.10.60", "found_as": "172.16.10.60", "type": "pc", "icon": "phone", "level": 4,
     "vendor": "VoIP", "model": None, "role": "Phone system", "confidence": "medium",
     "mac": "80:5e:c0:60:60:60", "ports": ["SIP 5060", "HTTP 80"], "web": "http://172.16.10.60",
     "ssh_port": None, "login_profile": None,
     "evidence": ["SIP (5060) open", "Web page title: IP phone settings", "MAC vendor: Yealink Network Technology"]},
    {"ip": "172.16.10.70", "found_as": "AP-LOBBY", "type": "switch", "icon": "ap", "level": 4,
     "vendor": "HPE Aruba", "model": "Aruba AP-505", "role": "Wireless access point", "confidence": "high",
     "mac": "20:4c:03:70:70:70", "ports": ["HTTPS 443", "SNMP"], "web": "https://172.16.10.70",
     "ssh_port": None, "login_profile": None,
     "evidence": ["SNMP sysDescr: ArubaOS (MODEL: 505), Version 8.10.0.6", "SNMP sysName: AP-LOBBY", "Web page on HTTPS 443: access point management page",
                  "MAC vendor: Aruba, a Hewlett Packard Enterprise Company"]},
    {"ip": "172.16.10.87", "found_as": "172.16.10.87", "type": "pc", "icon": "unknown", "level": 4,
     "vendor": None, "model": None, "role": "Unknown host", "confidence": "low",
     "mac": "da:a1:19:87:87:87", "ports": [], "web": None, "ssh_port": None, "login_profile": None,
     "evidence": ["Answered ping only", "Random (locally administered) MAC address, as phones use"]},
]

# What the switches' LLDP tables say once they are read: (device, local port, neighbour, neighbour port)
LLDP = [("CORE-SW-01", "24", "FGT-HQ", "internal1"), ("CORE-SW-01", "25", "ACC-SW-01", "25"),
        ("CORE-SW-01", "26", "ACC-SW-02", "25")]
# MAC address tables: (switch, port, MAC of the host learned there)
MACS = [("CORE-SW-01", "3", "00:50:56:9a:10:20"), ("ACC-SW-01", "5", "3c:52:82:01:31:31"),
        ("ACC-SW-01", "7", "3c:52:82:01:32:32"), ("ACC-SW-01", "12", "00:80:77:40:40:40"),
        ("ACC-SW-02", "3", "20:4c:03:70:70:70"), ("ACC-SW-02", "9", "c0:56:e3:50:50:50"),
        ("ACC-SW-02", "14", "80:5e:c0:60:60:60"), ("ACC-SW-02", "18", "da:a1:19:87:87:87")]

# Separate sample asset records correlate an endpoint MAC with its NIC name.
# This is additional inventory evidence, not a remote port inferred from ping
# or a MAC forwarding table. The unidentified host intentionally has no record.
ENDPOINT_PORTS = {
    "00:50:56:9a:10:20": "eth0",
    "3c:52:82:01:31:31": "eth0",
    "3c:52:82:01:32:32": "eth0",
    "00:80:77:40:40:40": "eth0",
    "c0:56:e3:50:50:50": "eth0",
    "80:5e:c0:60:60:60": "eth0",
    "20:4c:03:70:70:70": "eth0",
}


# Preserve the operating-system or physical adapter label alongside eth0.
ENDPOINT_DESCRIPTIONS = {
    "00:50:56:9a:10:20": 'Ubuntu adapter "ens160" (VMware VM)',
    "3c:52:82:01:31:31": 'Windows adapter "Ethernet"',
    "3c:52:82:01:32:32": 'Windows adapter "Ethernet"',
    "00:80:77:40:40:40": "Printer LAN port",
    "c0:56:e3:50:50:50": "Camera LAN port",
    "80:5e:c0:60:60:60": "IP phone Internet (uplink) port",
    "20:4c:03:70:70:70": "AP-505 uplink port E0",
    "da:a1:19:87:87:87": 'Windows adapter "Ethernet" (sample guest asset record)',
}

# The automatic demonstration includes an explicitly supplied authorized asset
# and patch-cable inventory. These extra records are separate from ping, LLDP
# and MAC learning; legacy discovery modes deliberately do not receive them.
AUTOMATIC_IDENTITIES = {
    "172.16.10.50": ("CAM-LOBBY-01", "Network camera"),
    "172.16.10.60": ("PHONE-RECEPTION-01", "IP phone"),
    "172.16.10.87": ("PC-GUEST-01", "Guest workstation"),
}
AUTOMATIC_ENDPOINT_PORTS = {**ENDPOINT_PORTS, "da:a1:19:87:87:87": "eth0"}
AUTOMATIC_FLOWS = [
    ("Finance file service", "172.16.10.31", "172.16.10.20", "tcp", 445, "high"),
    ("HR file service", "172.16.10.32", "172.16.10.20", "tcp", 445, "high"),
    ("Finance printing", "172.16.10.31", "172.16.10.40", "tcp", 631, "medium"),
    ("HR printing", "172.16.10.32", "172.16.10.40", "tcp", 631, "medium"),
    ("HR camera stream", "172.16.10.32", "172.16.10.50", "tcp", 554, "low"),
    ("Finance phone administration", "172.16.10.31", "172.16.10.60", "tcp", 80, "low"),
]

_ARUBA_SYSTEM = """ Status and Counters - General System Information

  System Name        : {name}
  System Location    : {loc}
  Software revision  : {ver}        Base MAC Addr      : {mac}
  Serial Number      : {serial}
  Up Time            : 41 days              CPU Util (%)       : 3"""


def _aruba_lldp(name: str) -> str:
    rows = [f"  {port:<9} | {nb:<22} {nport}" for dev, port, nb, nport in LLDP if dev == name]
    rows += [f"  {nport:<9} | {dev:<22} {port}" for dev, port, nb, nport in LLDP if nb == name]
    return ("\n LLDP Remote Devices Information\n\n  LocalPort | SysName                PortId\n"
            "  --------- + ---------------------- ------\n" + "\n".join(rows))


def _aruba_macs(name: str) -> str:
    rows = [f"  {mac:<18} {port:<5} {30 if dev == 'ACC-SW-01' and port == '5' else 20}"
            for dev, port, mac in MACS if dev == name]
    rows += [f"  {d['mac']:<18} {p:<5} 20" for dev, p, nb, _ in LLDP if dev == name
             for d in DEVICES if d.get("read", {}).get("hostname") == nb]
    return "\n Status and Counters - Port Address Table\n\n  MAC Address        Port  VLAN\n  ------------------ ----- ----\n" \
        + "\n".join(rows)


def cli_outputs(dev: dict) -> dict[str, str]:
    """Show commands the simulated command line answers for a network device."""
    if dev["ip"] == "172.16.10.70":
        return {
            "show version": f"Aruba Operating System Software.\nArubaOS (MODEL: 505), Version {AP_READ['version']}\n"
                            f"Hostname: {AP_READ['hostname']}",
            "show lldp neighbors": "Interface  Neighbor   Port  Capability\n---------  --------   ----  ----------\n"
                                   "eth0       ACC-SW-02  3     Bridge",
        }
    r = dev.get("read") or {}
    name = r.get("hostname", dev["ip"])
    if dev["vendor"] == "Fortinet":
        return {
            "get system status": f"Version: FortiGate-60F {r['version'].replace(' build', ',build')},230606 (GA.F)\n"
                                 f"Serial-Number: {r['serial']}\nHostname: {name}\nOperation Mode: NAT\n"
                                 "Current virtual domain: root\nCurrent HA mode: standalone",
            "get system interface physical": "== [onboard]\n\t==[wan1]\n\t\tmode: static\n\t\tip: 203.0.113.2 "
                                             "255.255.255.252\n\t\tstatus: up\n\t==[internal1]\n\t\tmode: static\n"
                                             "\t\tip: 172.16.10.1 255.255.255.0\n\t\tstatus: up",
            "get router info routing-table all": "S*      0.0.0.0/0 [10/0] via 203.0.113.1, wan1\n"
                                                 "C       172.16.10.0/24 is directly connected, internal1\n"
                                                 "C       203.0.113.0/30 is directly connected, wan1",
            "show system interface": "config system interface\n    edit \"internal1\"\n        set ip 172.16.10.1 "
                                     "255.255.255.0\n        set allowaccess ping https ssh snmp\n    next\nend",
        }
    if dev["vendor"] == "HPE Aruba":
        loc = "Server room" if dev["level"] == 2 else "Floor 1" if name.endswith("01") else "Floor 2"
        return {
            "show system": _ARUBA_SYSTEM.format(name=name, loc=loc, ver=r["version"], mac=dev["mac"].replace(":", "")[:6]
                                                + "-" + dev["mac"].replace(":", "")[6:], serial=r["serial"]),
            "show version": f"Image stamp:    /ws/swbuildm/rel_onboard/code/build\n                {r['version']}\n"
                            "Boot Image:     Primary",
            "show lldp info remote-device": _aruba_lldp(name),
            "show mac-address": _aruba_macs(name),
            "show interfaces brief": "\n  Port   Type      | Alert     Enabled Status Mode\n  ------ --------- + --------- "
                                     "------- ------ ----\n  1-24   100/1000T | No        Yes     Up     1000FDx\n"
                                     + ("  25-26  SFP+      | No        Yes     Up     1000FDx\n"
                                        "  27-28  SFP+      | No        Yes     Down   -" if dev['level'] == 2 else
                                        "  25     1000SX    | No        Yes     Up     1000FDx\n"
                                        "  26-28  SFP       | No        Yes     Down   Not present"),
            "show vlans": "\n Status and Counters - VLAN Information\n\n  VLAN ID Name             Status\n"
                          "  ------- ---------------- ------\n  1       DEFAULT_VLAN     Port-based\n"
                          "  20      DATA             Port-based\n  30      VOICE            Port-based",
        }
    return {}


def by_ip(ip: str) -> dict | None:
    return next((d for d in DEVICES if d["ip"] == ip), None)


# ---------------------------------------------------------------------------
# Ground truth for the credential-free ("smart") discovery workflow.
# The simulated discovery engine derives what each technique could observe from
# these records; fusion never reads them directly.
# ---------------------------------------------------------------------------

# The NetGuard sensor is plugged into CORE-SW-01 port 23 (it is not a model device).
SENSOR = {"switch_ip": "172.16.10.2", "port": "23", "ip": "172.16.10.250"}

# Names answered without credentials: DNS PTR, NetBIOS and mDNS. 172.16.10.1 has no record.
NAME_RECORDS = {
    "172.16.10.2": ("dns", "CORE-SW-01"), "172.16.10.11": ("dns", "ACC-SW-01"), "172.16.10.12": ("dns", "ACC-SW-02"),
    "172.16.10.20": ("dns", "SRV-FILE-01"), "172.16.10.31": ("netbios", "PC-FIN-01"),
    "172.16.10.32": ("netbios", "PC-HR-02"), "172.16.10.40": ("mdns", "PRN-01"), "172.16.10.70": ("dns", "AP-LOBBY"),
}
# A DNS record whose host answers nothing: the report's "Unreachable" example.
DNS_ONLY = [{"ip": "172.16.10.25", "name": "NAS-BACKUP-01"}]

# Identity facts visible without credentials (TLS certificate, passive LLDP on the sensor port).
CREDENTIAL_FREE_MODELS = {"172.16.10.1": ("tls-cert", "FortiGate 60F"), "172.16.10.2": ("passive-lldp", "Aruba 2930F-24G-4SFP+")}
# Devices answering SNMPv3 engine discovery (no community string or user is sent).
SNMPV3_ENGINES = {"172.16.10.2", "172.16.10.11", "172.16.10.12", "172.16.10.70"}
# Credential-free role hints (fingerprints); refined by authenticated reads.
PROBE_ROLES = {"172.16.10.2": "Network switch", "172.16.10.11": "Network switch", "172.16.10.12": "Network switch"}
INTERNET_TEST_ADDRESS = "198.51.100.10"

# Secure management methods offered per device (from detected services). Endpoints are out of scope (D4).
AUTH_METHODS = {
    "172.16.10.1": ["ssh", "https-api"], "172.16.10.2": ["ssh", "snmpv3"], "172.16.10.11": ["ssh", "snmpv3"],
    "172.16.10.12": ["ssh", "snmpv3"], "172.16.10.70": ["https-api", "snmpv3"],
}
SNMPV3_SAMPLE = {"username": "admin", "auth": "adminadmin", "priv": "adminadmin"}

# LLDP neighbour tables, as read from each device:
# (reader ip, local port, neighbour chassis MAC, neighbour mgmt ip, sysName, PortID, sysDescr)
LLDP_TABLES = [
    ("172.16.10.2", "24", "70:4c:a5:11:22:33", "172.16.10.1", "FGT-HQ", "internal1", "FortiGate-60F v7.2.5"),
    ("172.16.10.2", "25", "94:f1:28:bb:01:00", "172.16.10.11", "ACC-SW-01", "25", "Aruba J9776A 2530-24G Switch"),
    ("172.16.10.2", "26", "94:f1:28:bb:02:00", "172.16.10.12", "ACC-SW-02", "25", "Aruba J9776A 2530-24G Switch"),
    ("172.16.10.11", "25", "94:f1:28:aa:00:00", "172.16.10.2", "CORE-SW-01", "25", "Aruba JL253A 2930F-24G-4SFP+ Switch"),
    ("172.16.10.11", "12", "00:80:77:40:40:40", "172.16.10.40", "PRN-01", "eth0", "Brother network printer"),
    ("172.16.10.12", "25", "94:f1:28:aa:00:00", "172.16.10.2", "CORE-SW-01", "26", "Aruba JL253A 2930F-24G-4SFP+ Switch"),
    ("172.16.10.12", "3", "20:4c:03:70:70:70", "172.16.10.70", "AP-LOBBY", "eth0", "ArubaOS (MODEL: 505), Version 8.10.0.6"),
    ("172.16.10.12", "9", "c0:56:e3:50:50:50", "172.16.10.50", "CAM-LOBBY-01", "eth0", "Hikvision network camera"),
    ("172.16.10.12", "14", "80:5e:c0:60:60:60", "172.16.10.60", "PHONE-RECEPTION-01", "eth0", "Yealink IP phone"),
    ("172.16.10.70", "eth0", "94:f1:28:bb:02:00", "172.16.10.12", "ACC-SW-02", "3", "Aruba J9776A 2530-24G Switch"),
]
# Role refinements an LLDP sysDescr supports.
LLDP_ROLES = {"Hikvision network camera": "Network camera", "Yealink IP phone": "IP phone",
              "Brother network printer": "Printer", "ArubaOS (MODEL: 505), Version 8.10.0.6": "Wireless access point"}
LLDP_MODELS = {"ArubaOS (MODEL: 505), Version 8.10.0.6": "Aruba AP-505", "FortiGate-60F v7.2.5": "FortiGate 60F",
               "Aruba J9776A 2530-24G Switch": "Aruba 2530-24G", "Aruba JL253A 2930F-24G-4SFP+ Switch": "Aruba 2930F-24G-4SFP+"}

# Switch port configuration (ground truth; returned by an authenticated switch read).
# (switch ip, port, mode, access vlan)
SWITCH_PORTS = [
    ("172.16.10.2", "3", "access", 20), ("172.16.10.2", "24", "access", 20), ("172.16.10.2", "25", "trunk", None),
    ("172.16.10.2", "26", "trunk", None),
    ("172.16.10.11", "5", "access", 30), ("172.16.10.11", "7", "access", 20), ("172.16.10.11", "12", "access", 20),
    ("172.16.10.11", "25", "trunk", None),
    ("172.16.10.12", "3", "access", 20), ("172.16.10.12", "9", "access", 20), ("172.16.10.12", "14", "access", 20),
    ("172.16.10.12", "18", "access", 20), ("172.16.10.12", "25", "trunk", None),
]
TRUNK = {"allowed_vlans": [20, 30], "native_vlan": 20, "stp_state": "forwarding"}
SWITCH_VLANS = [(20, "DATA"), (30, "VOICE")]


def mac_tables() -> dict[str, list[tuple[str, str, int]]]:
    """MAC address tables per switch ip: (port, mac, vlan), including MACs learned on uplinks (transit)."""
    by_ip = {d["ip"]: d for d in DEVICES}
    edge = {"172.16.10.2": [("3", "172.16.10.20")],
            "172.16.10.11": [("5", "172.16.10.31"), ("7", "172.16.10.32"), ("12", "172.16.10.40")],
            "172.16.10.12": [("3", "172.16.10.70"), ("9", "172.16.10.50"), ("14", "172.16.10.60"), ("18", "172.16.10.87")]}
    # What lies behind each uplink port (devices reached through it).
    behind = {("172.16.10.2", "24"): ["172.16.10.1"],
              ("172.16.10.2", "25"): ["172.16.10.11"] + [ip for _, ip in edge["172.16.10.11"]],
              ("172.16.10.2", "26"): ["172.16.10.12"] + [ip for _, ip in edge["172.16.10.12"]]}
    for access in ("172.16.10.11", "172.16.10.12"):
        other = "172.16.10.12" if access == "172.16.10.11" else "172.16.10.11"
        behind[(access, "25")] = ["172.16.10.1", "172.16.10.2", "172.16.10.20", other] + [ip for _, ip in edge[other]]
    vlan = {(sw, port): v for sw, port, mode, v in SWITCH_PORTS if mode == "access"}
    tables = {}
    for switch in edge:
        rows = [(port, by_ip[ip]["mac"], vlan[(switch, port)]) for port, ip in edge[switch]]
        rows += [(port, by_ip[ip]["mac"], 20) for (sw, port), ips in behind.items() if sw == switch for ip in ips]
        tables[switch] = rows
    return tables


# Firewall read: LAN interface, WAN facts (evidence only), routing, DHCP leases (mask/gateway source).
FIREWALL_READ = {
    "hostname": "FGT-HQ", "lan_interface": "internal1", "lan_ip": "172.16.10.1", "lan_mask": "255.255.255.0",
    "wan": "wan1 203.0.113.2/30", "default_route": "0.0.0.0/0 via 203.0.113.1 (wan1)",
    "dhcp_scope": "172.16.10.0/24", "dhcp_router": "172.16.10.1",
    "leases": ["172.16.10.20", "172.16.10.31", "172.16.10.32", "172.16.10.40", "172.16.10.50", "172.16.10.60",
               "172.16.10.70", "172.16.10.87"],
}
AP_READ = {"hostname": "AP-LOBBY", "model": "Aruba AP-505", "version": "8.10.0.6"}
