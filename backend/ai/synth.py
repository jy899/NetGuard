"""Seeded generators for NetGuard's synthetic training data.

* campus(): a random enterprise campus as real Cisco IOS configurations (routers in OSPF area 0, Layer-2 access
  switches or multilayer switches with SVIs, VLANs, access lists), the `show cdp neighbors` output of every
  infrastructure device, an endpoint list and required flows. It is imported through NetGuard's own configuration
  importer, so the training topologies go through exactly the parser and model the product uses.
* LINK_FAULTS / inject_link_fault(): cross-device misconfigurations applied to one link of a parsed model, with
  benign variation (default values written out or omitted, descriptions) so a classifier must learn which
  differences matter.
* syslog(): Cisco IOS-format syslog messages for fault categories, with randomised fields.

Nothing here is presented as field data: every record carries its generator and seed.
"""
from __future__ import annotations

import ipaddress
import random

GENERATOR_VERSION = 1


# ------------------------------------------------------------------ topologies
def campus(seed: int) -> dict:
    rng = random.Random(seed)
    routers = [f"R{i}" for i in range(1, rng.choice((2, 2, 3, 3, 4)) + 1)]
    configs: dict[str, list[str]] = {r: [f"hostname {r}", "ip cef"] for r in routers}
    cdp: dict[str, list[tuple[str, str, str]]] = {r: [] for r in routers}
    ospf: dict[str, list[str]] = {r: [] for r in routers}
    endpoints, flows, hosts = [], [], []
    subnet_of: dict[str, tuple[str, str]] = {}  # vlan label -> (network, gateway)

    # Core: a chain, closed into a ring for redundancy on some campuses.
    core = [(routers[i], routers[i + 1]) for i in range(len(routers) - 1)]
    if len(routers) >= 3 and rng.random() < 0.6:
        core.append((routers[-1], routers[0]))
    port = {r: 0 for r in routers}
    for n, (a, b) in enumerate(core):
        net = ipaddress.IPv4Network(f"10.255.{n}.0/30")
        ia, ib = f"GigabitEthernet0/{port[a]}", f"GigabitEthernet0/{port[b]}"
        port[a] += 1
        port[b] += 1
        for dev, iface, ip in ((a, ia, net[1]), (b, ib, net[2])):
            configs[dev] += [f"interface {iface}", f" description core link", f" ip address {ip} 255.255.255.252"]
            if rng.random() < 0.3:
                configs[dev] += [" ip ospf hello-interval 10"]  # written-out default
            ospf[dev].append(f" network {net.network_address} 0.0.0.3 area 0")
        cdp[a].append((ia, b, ib))
        cdp[b].append((ib, a, ia))

    switch_n = 0
    vlan_base = 10
    server_site = rng.choice(routers)
    server_planned = False
    lan = iter(range(1, 250))
    for r in routers:
        sites = rng.choice((1, 1, 2))
        for _ in range(sites):
            switch_n += 1
            layer3 = rng.random() < 0.35
            sw = f"{'MLS' if layer3 else 'SW'}{switch_n}"
            vlans = [vlan_base + 10 * k for k in range(rng.choice((1, 2, 2, 3)))]
            vlan_base += 10 * len(vlans) + 10
            if r == server_site and not any(h[1] == "server" for h in hosts) and not server_planned:
                vlans.append(900 + switch_n)
                server_planned = True
            configs[sw] = [f"hostname {sw}"]
            cdp[sw] = []
            for v in vlans:
                configs[sw] += [f"vlan {v}", f" name {'SERVERS' if v >= 900 else 'USERS'}-{v}"]
            if layer3:
                uplink = ipaddress.IPv4Network(f"10.254.{switch_n}.0/30")
                ri = f"GigabitEthernet0/{port[r]}"
                port[r] += 1
                configs[r] += [f"interface {ri}", f" description to {sw}", f" ip address {uplink[1]} 255.255.255.252"]
                ospf[r].append(f" network {uplink.network_address} 0.0.0.3 area 0")
                configs[sw] += ["ip routing", "interface GigabitEthernet1/0/24", " no switchport",
                                f" ip address {uplink[2]} 255.255.255.252"]
                cdp[r].append((ri, sw, "GigabitEthernet1/0/24"))
                cdp[sw].append(("GigabitEthernet1/0/24", r, ri))
                sw_ospf = [f" network {uplink.network_address} 0.0.0.3 area 0"]
                for k, v in enumerate(vlans):
                    net = ipaddress.IPv4Network(f"172.16.{next(lan)}.0/24")
                    configs[sw] += [f"interface Vlan{v}", f" ip address {net[1]} {net.netmask}"]
                    sw_ospf.append(f" network {net.network_address} 0.0.0.255 area 0")
                    subnet_of[f"{sw}:{v}"] = (str(net), str(net[1]))
                configs[sw] += ["router ospf 1"] + sw_ospf
            else:
                for k, v in enumerate(vlans):
                    net = ipaddress.IPv4Network(f"192.168.{next(lan)}.0/24")
                    ri, si = f"GigabitEthernet0/{port[r]}", f"GigabitEthernet0/{k + 1}"
                    port[r] += 1
                    configs[r] += [f"interface {ri}", f" description LAN {sw} VLAN {v}", f" ip address {net[1]} {net.netmask}"]
                    ospf[r].append(f" network {net.network_address} 0.0.0.255 area 0")
                    configs[sw] += [f"interface {si}", " switchport mode access", f" switchport access vlan {v}"]
                    cdp[r].append((ri, sw, si))
                    cdp[sw].append((si, r, ri))
                    subnet_of[f"{sw}:{v}"] = (str(net), str(net[1]))
            # Some Layer-2 sites add an access switch behind the first one, on an 802.1Q trunk.
            edge = [sw]
            if not layer3 and rng.random() < 0.5:
                swb = f"{sw}B"
                edge.append(swb)
                allowed = ",".join(str(v) for v in vlans)
                native = rng.choice((1, 1, 99))
                configs[swb] = [f"hostname {swb}"] + [x for v in vlans for x in (f"vlan {v}", f" name SITE-{v}")]
                cdp[swb] = []
                for dev, local in ((sw, "GigabitEthernet0/24"), (swb, "GigabitEthernet0/1")):
                    configs[dev] += [f"interface {local}", " switchport trunk encapsulation dot1q", " switchport mode trunk",
                                     f" switchport trunk allowed vlan {allowed}"] + \
                                    ([f" switchport trunk native vlan {native}"] if native != 1 else [])
                cdp[sw].append(("GigabitEthernet0/24", swb, "GigabitEthernet0/1"))
                cdp[swb].append(("GigabitEthernet0/1", sw, "GigabitEthernet0/24"))
            access = {dev: (2 if dev.endswith("B") else 1) for dev in edge}
            for v in vlans:
                net, gateway = subnet_of[f"{sw}:{v}"]
                network = ipaddress.IPv4Network(net)
                kind = "server" if v >= 900 else "pc"
                for h in range(rng.choice((1, 2, 2, 3)) if kind == "pc" else rng.choice((1, 2))):
                    name = f"{'SRV' if kind == 'server' else 'PC'}{len([x for x in hosts if x[1] == kind]) + 1}"
                    ip = network[10 + h + (40 if kind == "server" else 0)]
                    target = rng.choice(edge)
                    sport = f"FastEthernet0/{access[target]}" if not layer3 else f"GigabitEthernet1/0/{access[target]}"
                    access[target] += 1
                    configs[target] += [f"interface {sport}", " switchport mode access", f" switchport access vlan {v}"]
                    if rng.random() < 0.4:
                        configs[target] += [" spanning-tree portfast"]
                    endpoints.append(f"{name}, {kind}, {ip}/{network.prefixlen}, {gateway}, {target} {sport}")
                    hosts.append((name, kind, str(ip), sw, v))
    for r in routers:
        if ospf[r]:
            configs[r] += ["router ospf 1"] + ospf[r]

    servers = [h for h in hosts if h[1] == "server"]
    pcs = [h for h in hosts if h[1] == "pc"]
    # Access lists: an edge filter that isolates one user VLAN from a server service.
    if servers and len(pcs) >= 2 and rng.random() < 0.6:
        victim = rng.choice(pcs)
        target = rng.choice(servers)
        router = next(r for r in routers if any(f"LAN {victim[3]} VLAN {victim[4]}" in line for line in configs[r])) \
            if any(any(f"LAN {victim[3]} VLAN {victim[4]}" in line for line in configs[r]) for r in routers) else None
        if router:
            net = ipaddress.IPv4Network(next(v[0] for k, v in subnet_of.items() if k == f"{victim[3]}:{victim[4]}"))
            iface = next(line.split()[1] for i, line in enumerate(configs[router]) if line.startswith("interface ")
                         and i + 1 < len(configs[router]) and f"LAN {victim[3]} VLAN {victim[4]}" in configs[router][i + 1])
            configs[router] += ["ip access-list extended USER_EDGE",
                                f" 10 deny tcp {net.network_address} {net.hostmask} host {target[2]} eq 22",
                                " 20 permit ip any any"]
            at = configs[router].index(f"interface {iface}")
            configs[router].insert(at + 1, " ip access-group USER_EDGE in")
            flows.append(f"{victim[0]} SSH blocked, {victim[0]}, {target[0]}, tcp, 22, deny, high")
    for pc in rng.sample(pcs, min(len(pcs), rng.randint(2, 5))):
        for srv in rng.sample(servers, min(len(servers), 1)):
            port_no, crit = rng.choice(((443, "critical"), (80, "high"), (53, "high"), (445, "medium")))
            flows.append(f"{pc[0]} to {srv[0]} {port_no}, {pc[0]}, {srv[0]}, tcp, {port_no}, allow, {crit}")
    text = []
    for dev, lines in configs.items():
        text += lines + ["!"]
        if cdp.get(dev):
            text += [f"{dev}#show cdp neighbors", "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID"]
            text += [f"{nbr}  {_short(loc)}  150  R S I  CISCO  {_short(rem)}" for loc, nbr, rem in cdp[dev]]
            text += ["!"]
    return {"seed": seed, "configs": "\n".join(text), "endpoints": "\n".join(endpoints), "flows": "\n".join(dict.fromkeys(flows)),
            "devices": len(configs) + len(hosts), "hosts": len(hosts)}


def _short(name: str) -> str:
    for long, short in (("GigabitEthernet", "Gig "), ("FastEthernet", "Fas ")):
        if name.startswith(long):
            return short + name[len(long):]
    return name


# ------------------------------------------------------------------ cross-device link faults
LINK_FAULTS = ("clean", "duplex_mismatch", "speed_mismatch", "native_vlan_mismatch", "trunk_vlan_pruned",
               "trunk_mode_mismatch", "mtu_mismatch", "ospf_timer_mismatch", "ospf_area_mismatch", "subnet_mismatch",
               "access_vlan_mismatch", "physical_errors")
FAULT_LABELS = {
    "clean": "No cross-device misconfiguration",
    "duplex_mismatch": "Duplex mismatch", "speed_mismatch": "Speed mismatch",
    "native_vlan_mismatch": "Native VLAN mismatch", "trunk_vlan_pruned": "VLAN pruned from a trunk",
    "trunk_mode_mismatch": "Trunk on one side, access on the other", "mtu_mismatch": "MTU mismatch",
    "ospf_timer_mismatch": "OSPF hello/dead timer mismatch", "ospf_area_mismatch": "OSPF area mismatch",
    "subnet_mismatch": "Addresses in different subnets", "access_vlan_mismatch": "Different access VLANs on a cable",
    "physical_errors": "Physical-layer errors (cable, optic or port)",
}


def applicable(fault: str, a, b) -> bool:
    routed = bool(a.ip and b.ip)
    trunk = a.mode == "trunk" and b.mode == "trunk"
    access = a.mode == "access" and b.mode == "access"
    return {"clean": True, "duplex_mismatch": True, "speed_mismatch": True, "physical_errors": True,
            "native_vlan_mismatch": trunk, "trunk_vlan_pruned": trunk, "trunk_mode_mismatch": trunk or access,
            "mtu_mismatch": True, "ospf_timer_mismatch": routed and a.ospf_area is not None,
            "ospf_area_mismatch": routed and a.ospf_area is not None, "subnet_mismatch": routed,
            "access_vlan_mismatch": access}[fault]


def benign_noise(rng: random.Random, a, b) -> None:
    """Variation that does not break anything: defaults written on one side only, matching settings."""
    if rng.random() < 0.3:
        a.mtu = 1500 if rng.random() < 0.5 else None
    if rng.random() < 0.3:
        side = rng.choice((a, b))
        side.speed_mbps = side.speed_mbps or 1000
    if rng.random() < 0.25:
        a.duplex = b.duplex = rng.choice(("full", None))
    if rng.random() < 0.2 and a.ospf_area is not None:
        a.ospf_hello = 10  # the default, written out
    if rng.random() < 0.2:
        a.error_count = rng.choice((0, 1, 2))
    if rng.random() < 0.15 and a.mode == "trunk" and b.mode == "trunk":
        a.native_vlan = b.native_vlan = rng.choice((1, 99))


def inject_link_fault(rng: random.Random, fault: str, a, b) -> None:
    side, other = (a, b) if rng.random() < 0.5 else (b, a)
    if fault == "duplex_mismatch":
        side.duplex, other.duplex = "half", rng.choice(("full", None))
        if rng.random() < 0.6:
            side.error_count = rng.randint(30, 4000)
    elif fault == "speed_mismatch":
        side.speed_mbps, other.speed_mbps = 100, rng.choice((1000, 10000))
    elif fault == "native_vlan_mismatch":
        side.native_vlan, other.native_vlan = rng.choice((99, 100, 999)), 1
    elif fault == "trunk_vlan_pruned":
        allowed = list(other.allowed_vlans or [10, 20, 30])
        drop = rng.choice(allowed) if allowed else 10
        side.allowed_vlans = [v for v in allowed if v != drop] or [1]
        other.allowed_vlans = allowed
    elif fault == "trunk_mode_mismatch":
        side.mode, other.mode = "trunk", "access"
        other.vlan = other.vlan or 10
    elif fault == "mtu_mismatch":
        side.mtu, other.mtu = rng.choice((1400, 9000, 9216)), 1500
    elif fault == "ospf_timer_mismatch":
        side.ospf_hello, side.ospf_dead = rng.choice(((5, 20), (1, 4), (30, 120))), None
        if isinstance(side.ospf_hello, tuple):
            side.ospf_hello, side.ospf_dead = side.ospf_hello
        other.ospf_hello, other.ospf_dead = rng.choice(((10, 40), (None, None)))
    elif fault == "ospf_area_mismatch":
        side.ospf_area = rng.choice((1, 2, 10))
        other.ospf_area = 0
    elif fault == "subnet_mismatch":
        net = ipaddress.IPv4Network(f"10.{rng.randint(100, 199)}.{rng.randint(0, 255)}.0/30")
        side.ip, side.mask = str(net[1]), "255.255.255.252"
    elif fault == "access_vlan_mismatch":
        side.vlan, other.vlan = (other.vlan or 10) + 10 * rng.randint(1, 5), other.vlan or 10
    elif fault == "physical_errors":
        side.error_count = rng.randint(200, 50000)
        if rng.random() < 0.3:
            side.status = rng.choice(("down", "up"))


# ------------------------------------------------------------------ syslog
SYSLOG_CATEGORIES = {
    "normal": "Routine operation",
    "link_flap": "Interface or link flapping",
    "duplex_mismatch": "Duplex mismatch reported by a neighbour",
    "l2_loop": "Layer-2 loop or MAC address flapping",
    "ip_conflict": "Duplicate IP address",
    "routing_adjacency": "Routing adjacency lost or unstable",
    "security_auth": "Authentication failures or access violations",
    "resource": "CPU, memory or hardware resource problem",
    "config_change": "Configuration changed",
    "stp_change": "Spanning-tree topology change or inconsistency",
}

_IF = ("GigabitEthernet0/{a}", "GigabitEthernet1/0/{b}", "FastEthernet0/{b}", "TenGigabitEthernet1/1/{c}")


def _iface(rng):
    return rng.choice(_IF).format(a=rng.randint(0, 3), b=rng.randint(1, 48), c=rng.randint(1, 4))


def _ip(rng):
    return f"{rng.choice((10, 172, 192))}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _mac(rng):
    raw = "".join(rng.choice("0123456789abcdef") for _ in range(12))
    return f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"


def syslog(rng: random.Random, category: str) -> str:
    i, ip, mac, vlan = _iface(rng), _ip(rng), _mac(rng), rng.choice((1, 10, 20, 30, 99, 100))
    user = rng.choice(("admin", "netops", "cisco", "root", "backup"))
    host = rng.choice(("SW1", "SW2", "R1", "R2", "CORE1", "DIST2", "MLS3"))
    templates = {
        "normal": [
            f"%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host {ip} port 514 started - CLI initiated",
            f"%SSH-5-SSH2_SESSION: SSH2 Session request from {ip} (tty = 0) using crypto cipher 'aes256-ctr', hmac 'hmac-sha2-256' Succeeded",
            f"%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: {user}] [Source: {ip}] [localport: 22]",
            "%NTP-6-PEERREACH: Peer 10.0.0.1 is reachable",
            f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {i}, changed state to up",
            f"%DHCPD-6-ADDRESS_ASSIGN: Interface Vlan{vlan} assigned DHCP address {ip}, mask 255.255.255.0",
            "%SYS-6-CLOCKUPDATE: System clock has been updated from NTP",
        ],
        "link_flap": [
            f"%LINK-3-UPDOWN: Interface {i}, changed state to down",
            f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {i}, changed state to down",
            f"%PM-4-ERR_DISABLE: link-flap error detected on {i}, putting {i} in err-disable state",
            f"%LINK-3-UPDOWN: Interface {i}, changed state to up",
            f"%PM-4-ERR_RECOVER: Attempting to recover from link-flap err-disable state on {i}",
        ],
        "duplex_mismatch": [
            f"%CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on {i} (not full duplex), with {host} {_iface(rng)} (full duplex).",
            f"%CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on {i} (not half duplex), with {host} {_iface(rng)} (half duplex).",
        ],
        "l2_loop": [
            f"%SW_MATM-4-MACFLAP_NOTIF: Host {mac} in vlan {vlan} is flapping between port {_iface(rng)} and port {_iface(rng)}",
            f"%SW_MATM-4-MACFLAP_NOTIF: Host {mac} in vlan {vlan} is flapping between port {i} and port {_iface(rng)}",
            f"%PM-4-ERR_DISABLE: bpduguard error detected on {i}, putting {i} in err-disable state",
            f"%STORM_CONTROL-3-FILTERED: A packet storm was detected on {i}. A packet filter action has been applied on the interface.",
        ],
        "ip_conflict": [
            f"%IP-4-DUPADDR: Duplicate address {ip} on Vlan{vlan}, sourced by {mac}",
            f"%IP-4-DUPADDR: Duplicate address {ip} on {i}, sourced by {mac}",
            f"%ARP-4-DUPADDR: Duplicate IP address {ip} detected, sourced by {mac}",
        ],
        "routing_adjacency": [
            f"%OSPF-5-ADJCHG: Process 1, Nbr {ip} on {i} from FULL to DOWN, Neighbor Down: Dead timer expired",
            f"%OSPF-5-ADJCHG: Process 1, Nbr {ip} on {i} from LOADING to FULL, Loading Done",
            f"%OSPF-4-ERRRCV: Received invalid packet: mismatched hello parameters from {ip}, {i}",
            f"%OSPF-4-ERRRCV: Received invalid packet: mismatch area ID, from backbone area must be virtual-link but not found from {ip}, {i}",
            f"%BGP-5-ADJCHANGE: neighbor {ip} Down BGP Notification sent",
            f"%DUAL-5-NBRCHANGE: EIGRP-IPv4 100: Neighbor {ip} ({i}) is down: holding time expired",
        ],
        "security_auth": [
            f"%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: {user}] [Source: {ip}] [localport: 22] [Reason: Login Authentication Failed]",
            f"%SSH-5-SSH2_USERAUTH: User '{user}' authentication for SSH2 Session from {ip} (tty = 0) using crypto cipher 'aes128-ctr', hmac 'hmac-sha1' Failed",
            f"%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address {mac} on port {i}.",
            f"%SEC-6-IPACCESSLOGP: list EDGE denied tcp {ip}({rng.randint(1024, 65535)}) -> {_ip(rng)}(22), {rng.randint(1, 50)} packets",
            f"%SNMP-3-AUTHFAIL: Authentication failure for SNMP req from host {ip}",
            f"%SEC_LOGIN-1-QUIET_MODE_ON: Still timeleft for watching failures is 107 secs, [user: {user}] [Source: {ip}] [localport: 22]",
        ],
        "resource": [
            f"%SYS-2-MALLOCFAIL: Memory allocation of {rng.randint(1000, 90000)} bytes failed from 0x{rng.randint(1 << 20, 1 << 28):x}, alignment 0",
            f"%SYS-1-CPURISINGTHRESHOLD: Threshold: Total CPU Utilization(Total/Intr): {rng.randint(85, 99)}%/{rng.randint(1, 40)}%, Top 3 processes",
            f"%PLATFORM_ENV-1-FAN: Faulty fan{rng.randint(1, 4)} detected",
            "%PLATFORM_ENV-1-TEMP: Temperature exceeded the threshold",
            f"%TCAM-4-FULL: TCAM resources exhausted, entries for {i} are processed in software",
        ],
        "config_change": [
            f"%SYS-5-CONFIG_I: Configured from console by {user} on vty0 ({ip})",
            f"%PARSER-5-CFGLOG_LOGGEDCMD: User:{user}  logged command:interface {i}",
            f"%PARSER-5-CFGLOG_LOGGEDCMD: User:{user}  logged command:no ip access-list extended EDGE",
            "%SYS-5-RESTART: System restarted --",
        ],
        "stp_change": [
            f"%SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port {i} on VLAN{vlan:04d}.",
            f"%SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocking port {i} on VLAN{vlan:04d}.",
            f"%SPANTREE-7-RECV_1Q_NON_TRUNK: Received 802.1Q BPDU on non trunk {i} VLAN{vlan}.",
            f"%SPANTREE-2-BLOCK_PVID_LOCAL: Blocking {i} on VLAN{vlan:04d}. Inconsistent local vlan.",
            f"%SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan {vlan}",
            f"%SPANTREE-5-ROOTCHANGE: Root Changed for vlan {vlan}: New Root Port is {i}. New Root Mac Address is {mac}",
        ],
    }
    message = rng.choice(templates[category])
    seq = rng.randint(1, 99999)
    stamp = f"{rng.choice(('Jan', 'Mar', 'Jun', 'Sep', 'Nov'))} {rng.randint(1, 28):2d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
    return f"{seq:06d}: {host}: *{stamp}.{rng.randint(0, 999):03d}: {message}" if rng.random() < 0.5 else f"*{stamp}: {message}"
