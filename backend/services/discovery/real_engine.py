"""Live discovery engine: credential-free probes of the authorised range, then optional authenticated reads.

probe() sends ICMP echo, TCP connection attempts to management ports, banner and certificate reads, reverse DNS
lookups and the unauthenticated SNMPv3 engine-discovery message, and reads the computer's own ARP cache. It never
sends a credential or community string. authenticate() tries one user-supplied credential once (SSH or SNMPv3
authPriv) and, when it succeeds, performs the read-only collection that collect() returns as observations.
"""
from __future__ import annotations

import ipaddress
import time

from backend.collectors import cli, netutil, snmpv3
from backend.services.discovery.engine import ProbeResult, observation

NETWORK_VENDORS = ("cisco", "juniper", "aruba", "hewlett", "hpe", "fortinet", "mikrotik", "ubiquiti", "arista",
                   "huawei", "extreme", "netgear", "tp-link", "palo alto", "h3c", "dell", "brocade", "ruckus", "zyxel")
FIREWALL_VENDORS = ("fortinet", "fortigate", "palo alto", "checkpoint", "sonicwall", "watchguard", "pfsense", "opnsense",
                    "sophos", "netgate", "deciso")
NETWORK_VENDORS += ("ruijie", "reyee", "d-link", "fiberhome", "zte", "omada", "unifi", "edgeos", "routeros",
                    "netgear", "meraki", "juniper")
CAMERA_VENDORS = ("hikvision", "dahua", "axis communications", "uniview")
NON_HTTP_PORTS = {22, 23, 53, 135, 139, 445, 3389, 554, 5060, 830, 9100, 631, 5900}


def on_link_target(target, nets) -> bool:
    return any(target.overlaps(net) for net in nets)


def _obs(*args, **kwargs):
    return observation(*args, simulated=False, **kwargs)


def snmp_kind(system: dict, has_bridge_table: bool) -> tuple[str | None, str, str]:
    """Device class from standard MIB facts: ipForwarding (IP-MIB), the bridge port count (BRIDGE-MIB) and the
    sysServices layer bits. Returns (type or None, role, the evidence used). None means not a router, switch or
    firewall by this evidence (a printer or server with an SNMP agent, for example)."""
    descr = (system.get("description") or "").lower()
    services = system.get("services") or 0
    forwards = system.get("ip_forwarding") == 1 or bool(services & 0x04)
    bridges = (system.get("bridge_ports") or 0) > 0 or has_bridge_table or bool(services & 0x02)
    if any(v in descr for v in FIREWALL_VENDORS + ("firewall", "asa", "fortios", "pan-os")):
        return "firewall", "Firewall", "the system description names a firewall platform"
    if forwards and bridges:
        return "switch", "Multilayer switch", "it forwards IP (ipForwarding) and bridges (BRIDGE-MIB ports)"
    if bridges:
        return "switch", "Switch", "it bridges (BRIDGE-MIB ports) and does not forward IP"
    if forwards:
        return "router", "Router", "it forwards IP (ipForwarding) and has no bridge ports"
    return None, "SNMP-managed host", "it neither forwards IP nor bridges"


class RealDiscoveryEngine:
    simulated = False

    def __init__(self, target: ipaddress.IPv4Network, excluded: list[str] | None = None,
                 management_ports: dict[int, str] | None = None, host_ports: dict[int, str] | None = None,
                 snmp_port: int = 161, timeout: float = 0.7):
        self.target = target
        self.excluded = [ipaddress.ip_network(e, strict=False) for e in (excluded or [])]
        self.management_ports = management_ports or netutil.MANAGEMENT_PORTS
        # Custom port maps (laboratory emulators, tests) are probed exactly; the default scan adds web portals.
        self.web_ports = {} if management_ports else netutil.WEB_PORTS
        self.host_ports = netutil.HOST_PORTS if host_ports is None else host_ports
        self.snmp_port, self.timeout = snmp_port, timeout
        self._facts: dict[str, dict] = {}
        self._reads: dict[tuple[str, str], object] = {}
        self.last_error: str | None = None

    # ------------------------------------------------------------ addresses
    def addresses(self) -> list[str]:
        hosts = [self.target.network_address] if self.target.prefixlen == 32 else list(self.target.hosts())
        return [str(h) for h in hosts if not any(h in net for net in self.excluded)]

    # ------------------------------------------------------------ credential-free
    def probe(self, addresses: list[str] | None = None, progress=None) -> ProbeResult:
        """Probe the authorised range, or the given addresses (neighbours learned from devices already read).

        progress(phase, done, total, found) is called as the scan advances (for the live progress display)."""
        import threading

        from backend.collectors import portals

        started = time.monotonic()
        addresses = self.addresses() if addresses is None else [
            a for a in addresses if not any(ipaddress.IPv4Address(a) in net for net in self.excluded)]
        report = progress or (lambda *_: None)
        use_ping = netutil.ping_available()
        method = netutil.ping_method()
        sweep = [p for p in netutil.SWEEP_PORTS if p in self.management_ports or p in self.web_ports] \
            or list(self.management_ports)[:2]
        local = netutil.this_computer(self.target)
        on_link = self._on_link_networks()
        done = [0]
        lock = threading.Lock()

        def first_pass(ip):
            ttl = netutil.ping_ttl(ip) if use_ping else None
            open_ports = [] if ttl is not None and ip == (local or {}).get("ip") else \
                [p for p in sweep if netutil.tcp_open(ip, p, self.timeout)]
            # An explicit ARP request finds on-link hosts that drop ICMP and every TCP port (Windows SendARP).
            mac = netutil.arp_ping(ip) if ttl is None and not open_ports and self._is_on_link(ip, on_link) else None
            with lock:
                done[0] += 1
                if done[0] % 8 == 0 or done[0] == len(addresses):
                    report("sweep", done[0], len(addresses), None)
            return ip, ttl, open_ports, mac
        alive, arp_direct = {}, {}
        for ip, ttl, open_ports, mac in netutil.parallel(first_pass, addresses, workers=netutil.sweep_workers()):
            if ttl is not None or open_ports:
                alive[ip] = {"icmp": ttl is not None, "ttl": ttl, "ports": set(open_ports), "arp_only": False}
            elif mac:
                alive[ip] = {"icmp": False, "ttl": None, "ports": set(), "arp_only": True}
            if mac:
                arp_direct[ip] = mac
        # The sweep made this computer resolve every address on its own segment: a host that drops ICMP and TCP
        # still answers ARP, so a complete ARP entry is evidence that it exists.
        arp = {**netutil.arp_table(), **arp_direct}
        wanted = set(addresses)
        for ip in arp:
            if ip in wanted and ip not in alive:
                alive[ip] = {"icmp": False, "ttl": None, "ports": set(), "arp_only": True}
        # This computer: its own address never appears in its own ARP cache.
        if local and local["ip"] in wanted:
            row = alive.setdefault(local["ip"], {"icmp": False, "ttl": None, "ports": set(), "arp_only": False})
            row["arp_only"] = False
            if local.get("mac"):
                arp[local["ip"]] = local["mac"]
        report("services", 0, len(alive), len(alive))
        rest = {**self.management_ports, **self.web_ports, **self.host_ports}
        done[0] = 0

        def second_pass(ip):
            ports = {p for p in rest if p not in alive[ip]["ports"] and netutil.tcp_open(ip, p, self.timeout)}
            engine = snmpv3.engine_discovery(ip, self.snmp_port, timeout=1.0, retries=0)
            name = netutil.reverse_dns(ip)
            nbstat = netutil.netbios_status(ip, timeout=0.8)
            mdns = netutil.mdns_name(ip, timeout=0.6)
            with lock:
                done[0] += 1
                report("services", done[0], len(alive), len(alive))
            return ip, ports, engine, name, nbstat, mdns
        engines, names, netbios, mdns_names = {}, {}, {}, {}
        for ip, ports, engine, name, nbstat, mdns in netutil.parallel(second_pass, alive, workers=64):
            alive[ip]["ports"] |= ports
            if ports or engine:
                alive[ip]["arp_only"] = False  # it answered a service probe after all
            if engine:
                engines[ip] = engine
            if name:
                names[ip] = name
            if nbstat:
                netbios[ip] = nbstat
            if mdns:
                mdns_names[ip] = mdns
        # SNMPv3 agents that answer neither ICMP, TCP nor ARP are still devices (routed segments).
        if len(addresses) <= 256:
            silent = [ip for ip in addresses if ip not in alive]
            for ip, engine in zip(silent, netutil.parallel(lambda a: snmpv3.engine_discovery(a, self.snmp_port, 0.6, 0), silent)):
                if engine:
                    alive[ip] = {"icmp": False, "ttl": None, "ports": set(), "arp_only": False}
                    engines[ip] = engine
        report("identify", 0, len(alive), len(alive))
        upnp = netutil.ssdp_discover(self.target) if self.target.num_addresses > 1 else {}
        for ip, row in upnp.items():
            if ip in alive and row.get("location"):
                row["description"] = netutil.upnp_description(row["location"], self.target)
        not_web = {p for p, label in {**self.management_ports, **self.host_ports}.items()
                   if label in ("SSH", "Telnet", "NETCONF")} | NON_HTTP_PORTS
        web = {ip: portals.detect(ip, [p for p in info["ports"] if p not in not_web])
               for ip, info in alive.items() if info["ports"] - not_web}
        arp = {**arp, **netutil.arp_table(), **arp_direct}
        if local and local.get("mac"):
            arp[local["ip"]] = local["mac"]
        gateway = netutil.default_gateway()
        # Routed scans: the router hops between this computer and the range (layer-3 path, never a cable).
        hops = []
        if not self.target.is_loopback and not on_link_target(self.target, on_link) and alive:
            first = sorted(alive, key=lambda a: int(ipaddress.IPv4Address(a)))[0]
            hops = [h for h in netutil.traceroute(first, 10)]
        obs, banner_count = [], 0
        for ip in sorted(alive, key=lambda a: int(ipaddress.IPv4Address(a))):
            info = alive[ip]
            is_local = bool(local and ip == local["ip"])
            mac = arp.get(ip) or (netbios.get(ip) or {}).get("mac")
            if mac:
                source = ("this computer's adapter" if is_local else "ARP request (SendARP)" if ip in arp_direct
                          else "ARP cache" if arp.get(ip) else "NetBIOS node status")
                obs.append(_obs("arp", ip, {"mac": mac, "arp_only": info["arp_only"]},
                                f"{source}: {ip} is at MAC {mac}" + (" (the host answered ARP only; ICMP and TCP were "
                                                                     "not answered)." if info["arp_only"] else ".")))
            if is_local:
                wifi = local.get("wifi")
                obs.append(_obs("local-host", ip, {
                    "hostname": local.get("hostname"), "os": local.get("os"), "interface": local.get("interface"),
                    "mask": local.get("mask"), "wireless": local.get("wireless"), "speed_mbps": local.get("speed_mbps")},
                    f"This computer (running NetGuard): {local.get('hostname') or ip}, {local.get('os')}, adapter "
                    f"'{local.get('interface')}'" + (" (wireless)" if local.get("wireless") else "") + "."))
                if wifi and wifi.get("bssid"):
                    obs.append(_obs("wifi-association", ip, dict(wifi),
                                    f"This computer's Wi-Fi adapter '{wifi.get('interface')}' is associated with SSID "
                                    f"'{wifi.get('ssid') or '?'}' through access point radio BSSID {wifi['bssid']}"
                                    + (f", signal {wifi['signal']}" if wifi.get("signal") else "")
                                    + (f", {wifi['radio']}" if wifi.get("radio") else "")
                                    + (f", channel {wifi['channel']}" if wifi.get("channel") else "") + "."))
            if info["icmp"]:
                hint = netutil.ttl_hint(info["ttl"])
                obs.append(_obs("icmp", ip, {"reachable": True, "ttl": info["ttl"]},
                                f"ICMP echo reply from {ip}, TTL {info['ttl']}" + (f" — {hint}; a hint, not an identification." if hint else ".")))
            vendor = netutil.oui_vendor(mac)
            engine = engines.get(ip)
            if mac:
                obs.append(_obs("oui", ip, {"vendor": vendor}, f"MAC {mac} is registered to {vendor}." if vendor else
                                f"MAC {mac} has no registered vendor (locally administered or unlisted)."))
            if ip in names:
                obs.append(_obs("dns", ip, {"name": names[ip].split(".")[0]}, f"DNS PTR record for {ip}: {names[ip]}."))
            if ip in mdns_names:
                obs.append(_obs("mdns", ip, {"name": mdns_names[ip]}, f"mDNS (Bonjour) name of {ip}: {mdns_names[ip]}.local."))
            nb = netbios.get(ip)
            if nb:
                obs.append(_obs("netbios", ip, {"name": nb["name"], "workgroup": nb.get("workgroup")},
                                f"NetBIOS node status from {ip}: computer {nb['name']}" +
                                (f", workgroup/domain {nb['workgroup']}" if nb.get("workgroup") else "") + "."))
            up = upnp.get(ip)
            if up:
                desc = up.get("description") or {}
                product = " ".join(x for x in (desc.get("manufacturer"), desc.get("modelName")) if x)
                obs.append(_obs("upnp", ip, {"server": up.get("server"), "types": up.get("types", []),
                                             "friendly_name": desc.get("friendlyName"), "manufacturer": desc.get("manufacturer"),
                                             "model": desc.get("modelName")},
                                f"UPnP (SSDP) answer from {ip}: " + "; ".join(x for x in (
                                    f"server '{up['server']}'" if up.get("server") else None,
                                    f"'{desc['friendlyName']}'" if desc.get("friendlyName") else None,
                                    product or None,
                                    ", ".join(t.split(":")[-2] for t in up.get("types", [])[:4]) or None) if x) + "."))
            services, banners = [], []
            labels = {**self.management_ports, **self.web_ports, **self.host_ports}
            for port in sorted(info["ports"]):
                services.append(f"{labels.get(port, f'TCP {port}')} (TCP {port})")
            ssh_port = next((p for p in sorted(info["ports"]) if self.management_ports.get(p) == "SSH"), None)
            ssh = netutil.ssh_banner(ip, ssh_port) if ssh_port else None
            if ssh:
                banners.append(f"SSH banner {ssh}")
            sites = web.get(ip) or []
            for site in sites:
                banners.append(" ".join(x for x in (f"{site['scheme'].upper()} {site['port']}",
                                                     f"server '{site['server']}'" if site.get("server") else None,
                                                     f"title '{site['title']}'" if site.get("title") else None,
                                                     f"{site['vendor']} {site['product']}" if site.get("vendor") else None) if x))
            if sites:
                obs.append(_obs("web-portal", ip, {"portals": sites},
                                f"Web management on {ip}: " + "; ".join(
                                    f"{s['url']}" + (f" ({s['vendor']} {s['product']})" if s.get("vendor") else "")
                                    + (" login page" if s.get("login_page") else "") for s in sites[:6]) + "."))
            cert = next(((s.get("certificate") or {}) for s in sites if s.get("certificate")), None)
            if cert and (cert.get("subject") or cert.get("issuer")):
                obs.append(_obs("tls-cert", ip, {"subject": cert.get("subject"), "issuer": cert.get("issuer"),
                                                 "sha256": cert.get("sha256")},
                                f"TLS certificate on {ip}: subject {cert.get('subject')}, issuer {cert.get('issuer')}"
                                + (" (self-signed)" if cert.get("self_signed") else "") + "."))
            if up:
                banners.append(" ".join(str(x) for x in (up.get("server"), *(up.get("types") or [])[:3],
                                                         (up.get("description") or {}).get("manufacturer"),
                                                         (up.get("description") or {}).get("modelName")) if x))
            if is_local:
                kind, role, icon, confidence = "pc", "This computer (NetGuard host)", "pc", "high"
            else:
                kind, role, icon, confidence = self._identify(info["ports"], vendor, engine, ssh, banners, ip == gateway,
                                                              netbios=ip in netbios, ttl=info["ttl"])
            if services or banners:
                banner_count += 1
            portal_vendor = next((s["vendor"] for s in sites if s.get("vendor")), None)
            self._facts[ip] = {"ports": sorted(info["ports"]), "ssh": ssh,
                               "vendor": (engine or {}).get("vendor") or portal_vendor or vendor,
                               "portal_product": next((s["product"] for s in sites if s.get("product")), None),
                               "type": kind, "ssh_port": ssh_port, "snmpv3": engine is not None,
                               "telnet": 23 in info["ports"]}
            obs.append(_obs("tcp-banner", ip, {
                "services": services, "role": role, "confidence": confidence, "type": kind, "os": None, "icon": icon,
                "identity_unknown": icon == "unknown", "ssh_banner": ssh, "ssh_port": ssh_port,
                "network_vendor": (engine or {}).get("vendor") or portal_vendor or vendor},
                f"Service scan of {ip}: " + (", ".join(services) if services else "no open TCP service") +
                (". " + "; ".join(b for b in banners if b) + "." if any(banners) else ".")))
            if engine:
                obs.append(_obs("snmpv3-engine", ip, {"snmpv3": True, "engine_id": engine["engine_id"],
                                                      "vendor": engine.get("vendor"), "enterprise": engine.get("enterprise")},
                                f"SNMPv3 engine discovery answered on {ip}: engine ID {engine['engine_id']}"
                                + (f" (enterprise {engine['enterprise']}, {engine['vendor']})" if engine.get("vendor") else "")
                                + "; no community string or user was tried."))
        if gateway and gateway in alive:
            obs.append(_obs("traceroute", gateway, {"gateway": True},
                            f"{gateway} is this computer's default gateway (first layer-3 hop). A layer-3 hop does not identify a cable."))
        for number, hop in enumerate(hops, 1):
            if hop and hop in alive and hop != gateway:
                obs.append(_obs("traceroute", hop, {"gateway": False, "hop": number, "path": hops},
                                f"Traceroute hop {number} towards the range is {hop} (a router on the layer-3 path)."))
        elapsed = round(time.monotonic() - started, 1)
        arp_only = sum(1 for i in alive.values() if i["arp_only"])
        portals_found = sum(len(v) for v in web.values())
        timeline = [
            {"id": "icmp", "label": "ICMP echo, TCP and ARP sweep", "count": len(alive) - arp_only,
             "detail": f"{len(alive) - arp_only} of {len(addresses)} address(es) answered ICMP or TCP ({method})"
                       + ("" if use_ping else "; ping unavailable, TCP only")},
            {"id": "arp", "label": "ARP", "count": sum(1 for ip in alive if ip in arp),
             "detail": f"{sum(1 for ip in alive if ip in arp)} MAC address(es) learned on this segment"
                       + (f"; {arp_only} host(s) answered ARP only" if arp_only else "")},
            {"id": "names", "label": "DNS, NetBIOS and mDNS names", "count": len(set(names) | set(netbios) | set(mdns_names)),
             "detail": f"{len(names)} DNS name(s), {len(netbios)} NetBIOS name(s), {len(mdns_names)} mDNS name(s)"},
            {"id": "services", "label": "Services, banners, web portals, certificates and UPnP", "count": banner_count,
             "detail": f"{banner_count} host(s) expose identifiable services; {portals_found} web portal(s); {len(upnp)} UPnP answer(s)"},
            {"id": "snmpv3", "label": "SNMPv3 engine discovery", "count": len(engines),
             "detail": f"{len(engines)} device(s) answered with an SNMPv3 engine ID"},
            {"id": "wireless", "label": "This computer and its Wi-Fi association", "count": 1 if local else 0,
             "detail": (f"{local.get('hostname') or local['ip']} on '{local.get('interface')}'"
                        + (f", associated with BSSID {local['wifi']['bssid']} (SSID '{local['wifi'].get('ssid')}')"
                           if local.get("wifi") else "")) if local else "This computer has no address in the range"},
            {"id": "correlate", "label": "Correlation", "count": len(alive), "detail": f"Completed in {elapsed} s"},
        ]
        report("done", len(alive), len(alive), len(alive))
        return ProbeResult(observations=obs, timeline=timeline, no_response=[])

    @staticmethod
    def _on_link_networks() -> list:
        nets = []
        for row in netutil.local_networks(max_prefix=8)["interfaces"]:
            try:
                nets.append(ipaddress.IPv4Network(row["network"]))
            except (ValueError, KeyError):
                continue
        return nets

    @staticmethod
    def _is_on_link(ip: str, nets) -> bool:
        address = ipaddress.IPv4Address(ip)
        return any(address in net for net in nets)

    @staticmethod
    def _identify(ports, vendor, engine, ssh, banners, is_gateway, netbios=False, ttl=None):
        """(type, role, icon, confidence) from credential-free evidence only.

        A device is given a specific role only when the evidence names it (a vendor, a service that only one class
        of device offers, the gateway role); otherwise it stays an unidentified device with its evidence listed."""
        text = " ".join([vendor or "", (engine or {}).get("vendor") or "", ssh or "", *[b for b in banners if b]]).lower()
        network_vendor = any(v in text for v in NETWORK_VENDORS)
        managed = bool(ports & {22, 23, 830}) or bool(ssh) or engine is not None
        from backend.collectors import portals

        product = portals.fingerprint(text)[1]
        if any(v in text for v in FIREWALL_VENDORS):
            return "firewall", f"Firewall ({product or 'vendor identified'})", "firewall", "medium"
        if "internetgatewaydevice" in text or "wanipconnection" in text:
            return "router", "Internet gateway router (UPnP IGD)" + (f" — {product}" if product else ""), "router", "medium"
        if is_gateway:
            return "router", "Default gateway (routes this subnet)" + (f" — {product}" if product else ""), "router", "medium"
        if any(v in text for v in CAMERA_VENDORS):
            return "pc", f"IP camera / recorder ({product or 'vendor identified'})", "camera", "medium"
        if managed and (network_vendor or engine is not None) and not ports & {135, 445, 3389}:
            return "switch", "Network device (router or switch — sign in to confirm)" + (f" — {product}" if product else ""), \
                "unknown", "low"
        if network_vendor and product and not ports & {135, 445, 3389}:
            return "switch", f"Network device with {product} web management (router, switch or access point — "\
                             "sign in to confirm)", "unknown", "low"
        if "accesspoint" in text or "wlanaccesspoint" in text:
            return "pc", "Wireless access point (UPnP)", "ap", "medium"
        if ports & {9100, 631} or "printer" in text:
            return "pc", "Printer", "printer", "medium"
        if ports & {3389, 445, 135} or netbios:
            return "pc", "Windows/SMB host" + (" (NetBIOS)" if netbios else ""), "pc", "medium"
        if 554 in ports or "camera" in text or "nvt" in text:
            return "pc", "IP camera (RTSP)", "camera", "low"
        if 5060 in ports:
            return "pc", "IP phone (SIP)", "phone", "low"
        if "mediarenderer" in text or "mediaserver" in text:
            return "pc", "Media device (UPnP)", "unknown", "low"
        if 22 in ports or ssh:
            return "server", "Host with SSH (identity unconfirmed)", "unknown", "low"
        if ports & {80, 443, 8443}:
            return "server", "Host with a web service (identity unconfirmed)", "unknown", "low"
        return "pc", "Unidentified device", "unknown", "low"

    # ------------------------------------------------------------ authentication
    def methods(self, ip: str) -> list[str]:
        facts = self._facts.get(ip, {})
        methods = ["ssh"] if facts.get("ssh_port") else []
        if facts.get("snmpv3"):
            methods.append("snmpv3")
        if facts.get("type") in ("router", "switch", "firewall"):
            methods.append("snmpv2c")  # only with a saved read-only community string
        return methods

    def platform(self, ip: str, hint: dict | None = None) -> str:
        facts = {**(hint or {}), **self._facts.get(ip, {})}
        return cli.detect_platform(facts.get("ssh"), facts.get("vendor"), facts.get("portal_product"))

    def authenticate(self, ip: str, method: str, username: str, secret: str, priv_secret: str | None = None,
                     protocols: tuple[str, str] = ("SHA-256", "AES-128"), hint: dict | None = None) -> bool:
        self.last_error = None
        try:
            if method == "ssh":
                target = cli.Target(ip, int((hint or {}).get("ssh_port", 22)), "ssh", self.platform(ip, hint), username,
                                    secret, (hint or {}).get("enable_secret"))
                self._reads[(ip, method)] = cli.collect(target)
                return True
            if method == "snmpv3":
                self._reads[(ip, method)] = snmpv3.collect(ip, username, secret, priv_secret or "", protocols,
                                                           port=self.snmp_port)
                return True
            if method == "snmpv2c":
                self._reads[(ip, method)] = snmpv3.collect_v2c(ip, secret, port=self.snmp_port)
                return True
        except cli.AuthFailed as exc:
            self.last_error = str(exc)
            return False
        except (cli.CliError, snmpv3.SnmpError) as exc:
            self.last_error = str(exc)
            return False
        self.last_error = "Unsupported authentication method."
        return False

    # ------------------------------------------------------------ authenticated reads
    def collect(self, ip: str, method: str) -> list[dict]:
        data = self._reads.pop((ip, method), None)
        if data is None:
            return []
        label = {"ssh": "SSH", "snmpv3": "SNMPv3", "snmpv2c": "SNMPv2c"}[method]

        def add(technique, facts, detail):
            out.append(_obs(technique, ip, facts, f"Authenticated {label} read of {name}: {detail}",
                            authenticated=True, method=method, observed_by=ip))
        out: list[dict] = []
        if method == "ssh":
            c: cli.Collection = data
            name = c.system.get("hostname") or ip
            kind = cli.device_type(c)
            add("system-info", {"hostname": c.system.get("hostname"), "model": c.system.get("model"),
                                "version": c.system.get("version"), "serial": c.system.get("serial"),
                                "role": "Switch" if kind == "switch" else "Router", "type": kind,
                                "platform": c.platform},
                f"{c.system.get('model') or 'model not reported'}, software {c.system.get('version') or 'unknown'}.")
            add("running-config", {"text": c.running_config, "platform": c.platform},
                f"running configuration ({len(c.running_config.splitlines())} lines) collected.")
            add("interface-status", {"ports": c.ports, "stp": c.stp}, f"{len(c.ports)} interfaces with state and counters.")
            if kind == "switch":
                add("vlan-table", {"vlans": c.vlans}, f"{len(c.vlans)} VLANs.")
                add("mac-table", {"rows": c.macs}, f"{len(c.macs)} learned MAC addresses.")
            add("lldp-table", {"rows": c.neighbours}, f"{len(c.neighbours)} LLDP/CDP neighbours.")
            if c.logs:
                add("syslog", {"lines": c.logs}, f"{len(c.logs)} recent syslog messages.")
            if c.arp:
                add("arp-table", {"entries": c.arp}, f"{len(c.arp)} ARP entries.")
            return out
        snmp = data
        system = snmp["system"]
        name = system.get("hostname") or ip
        kind, role, basis = snmp_kind(system, bool(snmp["macs"]))
        add("system-info", {"hostname": system.get("hostname"), "model": None, "version": None, "serial": None,
                            "role": role, "type": kind, "description": system.get("description")},
            f"sysDescr '{(system.get('description') or '')[:80]}'; {basis}.")
        add("interface-status", {"ports": snmp["ports"], "stp": snmp.get("stp", {})},
            f"{len(snmp['ports'])} interfaces (IF-MIB)" + (f", spanning-tree state of {len(snmp['stp'])} ports." if snmp.get("stp") else "."))
        add("address-table", {"addresses": snmp["addresses"]}, f"{len(snmp['addresses'])} IPv4 addresses (IP-MIB).")
        add("lldp-table", {"rows": snmp["neighbours"]}, f"{len(snmp['neighbours'])} LLDP/CDP neighbours.")
        if snmp["macs"]:
            vlans = sorted({m["vlan"] for m in snmp["macs"] if m.get("vlan")})
            add("mac-table", {"rows": snmp["macs"]}, f"{len(snmp['macs'])} learned MAC addresses (BRIDGE-MIB"
                + (f", per-VLAN for VLAN {', '.join(map(str, vlans[:12]))}" if vlans else "") + ").")
        if snmp.get("arp"):
            add("arp-table", {"entries": snmp["arp"]}, f"{len(snmp['arp'])} ARP entries (IP-MIB).")
        if snmp.get("routes"):
            add("routing-table", {"routes": snmp["routes"]}, f"{len(snmp['routes'])} routes (IP-FORWARD-MIB).")
        if system.get("bridge_mac") or snmp.get("stp_designated"):
            add("stp-topology", {"bridge_mac": system.get("bridge_mac"), "designated": snmp.get("stp_designated", {})},
                f"bridge address {system.get('bridge_mac') or 'not reported'}; designated bridge of "
                f"{len(snmp.get('stp_designated', {}))} port(s) (BRIDGE-MIB spanning tree).")
        return out
