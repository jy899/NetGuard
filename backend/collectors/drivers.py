"""Multi-vendor driver matrix: how NetGuard reads, configures, saves and safely reverts each platform.

Each driver names the Netmiko device type for SSH and Telnet, the read-only commands used for collection (and the
prefixes a read-only command may start with), the configuration parser, whether NetGuard may push configuration
(approved self-healing), how a change is persisted once confirmed, the device-side revert timer where the platform
has one (the dead-man's switch), the error patterns that mean a command was rejected, and the commands a read-only
terminal session blocks on production devices.

Platforms: Cisco IOS/IOS-XE, NX-OS and ASA; Fortinet FortiOS; Netgate pfSense and OPNsense; HPE Aruba
ArubaOS-Switch (ProCurve) and AOS-CX; Ubiquiti EdgeOS/VyOS, EdgeSwitch and UniFi; Ruijie RGOS/Reyee; TP-Link
JetStream/Omada; D-Link DES/DGS; Huawei VRP; MikroTik RouterOS; Juniper Junos; FiberHome ONT/routers (web and
SNMP only); FRRouting/Linux.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Driver:
    id: str
    label: str
    vendor: str
    netmiko_ssh: str | None
    netmiko_telnet: str | None
    commands: dict[str, str]
    parser: str                       # ios | frr | fortios | pfsense | edgeos | junos | procurve | huawei | mikrotik | dlink | none
    readonly_prefixes: tuple[str, ...]
    structured: str | None = None     # ntc-templates platform for TextFSM parsing of show output
    enable: bool = False              # needs privileged EXEC (enable secret)
    configurable: bool = True         # approved changes may be pushed
    commit: bool = False              # candidate configuration needs a commit (VyOS/EdgeOS, Junos)
    save: tuple[str, ...] = ()        # persist the running configuration once the change is confirmed
    revert: str | None = None         # device-side dead-man's switch: ios-reload | junos-commit-confirmed | fortios-revert
    error: str = r"% ?(Invalid|Incomplete|Ambiguous|Unknown)"
    blocked: str = r"^$"              # read-only terminal guard (production devices)
    comment: str = "!"
    detect: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    def netmiko(self, transport: str) -> str | None:
        return self.netmiko_telnet if transport == "telnet" else self.netmiko_ssh

    def is_read_only(self, command: str) -> bool:
        return command.strip().lower().startswith(self.readonly_prefixes)

    def guard(self, line: str) -> bool:
        """True when a typed line must be blocked in a read-only terminal session."""
        return bool(re.search(self.blocked, line.strip(), re.I)) if line.strip() else False


_IOS_BLOCK = (r"^(conf(i(g(u(r(e)?)?)?)?)?|copy|wr(i(t(e)?)?)?|reload|erase|del(ete)?|format|squeeze|archive|boot|"
              r"license|crypto|clear|debug|undebug|test|tclsh|request|install|upgrade|rename|mkdir|rmdir|send|"
              r"verify\s+/md5\s+.*\s+>|.*\|\s*(redirect|tee|append))\b")
_IOS = dict(
    version="show version", running="show running-config", interfaces="show interfaces",
    lldp="show lldp neighbors detail", cdp="show cdp neighbors detail", mac="show mac address-table",
    vlan="show vlan brief", arp="show ip arp", stp="show spanning-tree", logging="show logging",
)
_SHELL_BLOCK = (r"(^|[;&|]\s*)(rm|mv|dd|mkfs|reboot|halt|poweroff|shutdown|init|kill|killall|pfctl|configctl|"
                r"ifconfig\s+\S+\s+(up|down|inet|delete)|route\s+(add|delete|change|flush)|ip\s+(link|addr|route)\s+"
                r"(set|add|del|flush)|sysctl\s+-w|sed\s+-i|tee|chmod|chown|passwd|pkg|apt|yum|opkg|vi|nano|"
                r"php|pfSsh\.php|configure|vtysh\s+-c\s+.?conf)\b|>")

DRIVERS: dict[str, Driver] = {d.id: d for d in (
    Driver("cisco-ios", "Cisco IOS / IOS-XE", "Cisco", "cisco_ios", "cisco_ios_telnet", _IOS, "ios",
           ("show ",), "cisco_ios", enable=True, save=("write memory",), revert="ios-reload", blocked=_IOS_BLOCK,
           detect=("cisco ios", "ios-xe", "ios software", "cisco-1.", "cisco_ios")),
    Driver("cisco-nxos", "Cisco NX-OS", "Cisco", "cisco_nxos", None,
           {**_IOS, "interfaces": "show interface", "logging": "show logging last 200"}, "ios", ("show ",),
           "cisco_nxos", save=("copy running-config startup-config",), blocked=_IOS_BLOCK, detect=("nx-os", "nexus")),
    Driver("cisco-asa", "Cisco ASA", "Cisco", "cisco_asa", None,
           dict(version="show version", running="show running-config", interfaces="show interface",
                arp="show arp", routes="show route", logging="show logging"),
           "ios", ("show ",), "cisco_asa", enable=True, save=("write memory",), blocked=_IOS_BLOCK,
           detect=("adaptive security", "cisco asa", " asa ")),
    Driver("fortios", "Fortinet FortiOS (FortiGate)", "Fortinet", "fortinet", None,
           dict(version="get system status", running="show", interfaces="get system interface physical",
                lldp="diagnose lldprx neighbor summary", arp="get system arp",
                routes="get router info routing-table all", logging="execute log display"),
           "fortios", ("get ", "show", "diagnose lldprx", "execute log display", "diagnose sys"),
           save=("execute cfg save",), revert="fortios-revert", error=r"Command fail|entry not found|parse error|-61|-651",
           blocked=r"^(config|set|unset|edit|delete|purge|rename|move|clone|append|select|unselect|abort|end|next|"
                   r"exec(ute)?\s+(?!ping|traceroute|telnet\s|ssh\s|log\s+display))\b",
           comment="#", detect=("fortinet", "fortigate", "fortios", "fortiswitch", "fortiap")),
    Driver("pfsense", "Netgate pfSense", "Netgate", "linux", None,
           dict(version="cat /etc/version", running="cat /cf/conf/config.xml", interfaces="ifconfig -a",
                arp="arp -an", routes="netstat -rn -f inet"),
           "pfsense", ("cat /etc/version", "cat /cf/conf/config.xml", "ifconfig", "arp ", "netstat "),
           configurable=False, blocked=_SHELL_BLOCK, comment="#", detect=("pfsense", "netgate"),
           notes=("Use an account with shell access (or root, menu option 8). Configuration changes are made through "
                  "the web GUI; NetGuard reads config.xml.",)),
    Driver("opnsense", "Deciso OPNsense", "Deciso", "linux", None,
           dict(version="opnsense-version", running="cat /conf/config.xml", interfaces="ifconfig -a",
                arp="arp -an", routes="netstat -rn -f inet"),
           "pfsense", ("opnsense-version", "cat /conf/config.xml", "ifconfig", "arp ", "netstat "),
           configurable=False, blocked=_SHELL_BLOCK, comment="#", detect=("opnsense", "deciso")),
    Driver("aruba-os-switch", "HPE Aruba ArubaOS-Switch (ProCurve)", "HPE Aruba", "aruba_osswitch", "hp_procurve_telnet",
           dict(version="show version", running="show running-config", interfaces="show interfaces brief",
                lldp="show lldp info remote-device detail", mac="show mac-address", vlan="show vlans",
                arp="show arp", stp="show spanning-tree", logging="show logging -r"),
           "procurve", ("show ",), "hp_procurve", save=("write memory",), error=r"Invalid input|Ambiguous input",
           blocked=_IOS_BLOCK, detect=("procurve", "arubaos-switch", "aruba switch", "hp j", "hpe ", "hewlett")),
    Driver("aruba-cx", "HPE Aruba AOS-CX", "HPE Aruba", "aruba_aoscx", None,
           dict(version="show version", running="show running-config", interfaces="show interface",
                lldp="show lldp neighbor-info detail", mac="show mac-address-table", vlan="show vlan",
                arp="show arp", stp="show spanning-tree", logging="show logging -r"),
           "ios", ("show ",), "aruba_aoscx", save=("write memory",), error=r"Invalid input|% Command incomplete",
           blocked=_IOS_BLOCK, detect=("aos-cx", "arubaos-cx", "aruba-cx")),
    Driver("edgeos", "Ubiquiti EdgeOS / VyOS", "Ubiquiti", "vyos", None,
           dict(version="show version", running="show configuration commands", interfaces="show interfaces",
                lldp="show lldp neighbors detail", arp="show arp", routes="show ip route"),
           "edgeos", ("show ",), "vyos", commit=True, save=("save",), error=r"Invalid command|Set failed|Commit failed",
           blocked=r"^(configure|set|delete|commit|save|load|merge|discard|rollback|reboot|poweroff|add|sudo|run\s+(?!show))\b",
           comment="#", detect=("edgeos", "edgerouter", "vyos", "vyatta")),
    Driver("edgeswitch", "Ubiquiti EdgeSwitch", "Ubiquiti", "ubiquiti_edgeswitch", None,
           dict(version="show version", running="show running-config", interfaces="show interfaces status all",
                lldp="show lldp remote-device all", mac="show mac-addr-table", vlan="show vlan brief", arp="show arp"),
           "ios", ("show ",), "ubiquiti_edgeswitch", enable=True, save=("write memory",), blocked=_IOS_BLOCK,
           detect=("edgeswitch", "edgemax")),
    Driver("unifi", "Ubiquiti UniFi (AP / switch shell)", "Ubiquiti", "linux", None,
           dict(version="info", running="cat /tmp/system.cfg", interfaces="ifconfig", arp="cat /proc/net/arp"),
           "none", ("info", "cat /tmp/system.cfg", "ifconfig", "cat /proc/net/arp", "mca-cli-op info"),
           configurable=False, blocked=_SHELL_BLOCK, comment="#", detect=("unifi", "ubnt", "ubiquiti", "u7", "uap"),
           notes=("UniFi devices are configured by their controller; NetGuard reads them and opens the controller GUI.",)),
    Driver("ruijie-os", "Ruijie RGOS / Reyee", "Ruijie", "ruijie_os", "ruijie_os_telnet",
           dict(version="show version", running="show running-config", interfaces="show interfaces",
                lldp="show lldp neighbors detail", mac="show mac-address-table", vlan="show vlan", arp="show arp",
                stp="show spanning-tree", logging="show logging"),
           "ios", ("show ",), "ruijie_os", enable=True, save=("write",), blocked=_IOS_BLOCK,
           detect=("ruijie", "reyee", "rgos", "rg-")),
    Driver("tplink-jetstream", "TP-Link JetStream / Omada switch", "TP-Link", "tplink_jetstream", "tplink_jetstream_telnet",
           dict(version="show system-info", running="show running-config", interfaces="show interface status",
                lldp="show lldp neighbor-information", mac="show mac address-table all", vlan="show vlan", arp="show arp"),
           "ios", ("show ",), None, enable=True, save=("copy running-config startup-config",), error=r"Error:|Bad command",
           blocked=_IOS_BLOCK, detect=("tp-link", "tplink", "jetstream", "omada")),
    Driver("dlink-ds", "D-Link DES/DGS (managed switch)", "D-Link", "dlink_ds", "dlink_ds_telnet",
           dict(version="show switch", running="show config current_config", interfaces="show ports",
                lldp="show lldp remote_ports", mac="show fdb", vlan="show vlan", arp="show arpentry"),
           "dlink", ("show ",), None, save=("save",), error=r"Fail!|Invalid|Available commands",
           blocked=r"^(config|create|delete|enable|disable|save|reboot|reset|download|upload|clear)\b",
           comment="#", detect=("d-link", "dlink", "des-", "dgs-", "dlink corp")),
    Driver("huawei-vrp", "Huawei VRP", "Huawei", "huawei", "huawei_telnet",
           dict(version="display version", running="display current-configuration", interfaces="display interface brief",
                lldp="display lldp neighbor", mac="display mac-address", vlan="display vlan", arp="display arp",
                routes="display ip routing-table", logging="display logbuffer"),
           "huawei", ("display ",), "huawei", save=("save",), error=r"Error:|Unrecognized command|Wrong parameter",
           blocked=r"^(system-view|sys|save|reboot|reset|delete|format|undo|quit|return|interface|copy|move)\b",
           comment="#", detect=("huawei", "vrp", "huawei-")),
    Driver("mikrotik-routeros", "MikroTik RouterOS", "MikroTik", "mikrotik_routeros", None,
           {"version": "/system resource print", "running": "/export terse", "interfaces": "/interface print detail without-paging",
            "lldp": "/ip neighbor print detail without-paging", "mac": "/interface bridge host print without-paging",
            "arp": "/ip arp print without-paging", "routes": "/ip route print without-paging"},
           "mikrotik", ("/system resource print", "/export", "/interface print", "/ip neighbor print",
                        "/interface bridge host print", "/ip arp print", "/ip route print"), None,
           error=r"failure:|bad command|syntax error|expected end of command",
           blocked=r"(^|\s)(add|set|remove|disable|enable|reset|reboot|shutdown|import|unset|move|edit|/system\s+(reboot|reset))\b",
           comment="#", detect=("mikrotik", "routeros", "rosssh")),
    Driver("juniper-junos", "Juniper Junos", "Juniper", "juniper_junos", "juniper_junos_telnet",
           dict(version="show version", running="show configuration | display set", interfaces="show interfaces terse",
                lldp="show lldp neighbors", mac="show ethernet-switching table", arp="show arp no-resolve",
                routes="show route"),
           "junos", ("show ",), "juniper_junos", commit=True, revert="junos-commit-confirmed",
           error=r"error:|syntax error|unknown command",
           blocked=r"^(configure|edit|set|delete|commit|rollback|load|request|restart|clear|start)\b",
           comment="#", detect=("juniper", "junos")),
    Driver("fiberhome", "FiberHome ONT / router", "FiberHome", None, None, {}, "none", (), configurable=False,
           comment="#", detect=("fiberhome", "fiber home", "hg6", "an5506"),
           notes=("FiberHome ONTs and home routers are managed through their web GUI (and TR-069); the CLI, where "
                  "present, is vendor-restricted. NetGuard opens the GUI and reads SNMP when enabled.",)),
    Driver("frr", "FRRouting / Linux", "FRRouting", "linux", "generic_telnet",
           {"version": 'vtysh -c "show version"', "running": 'vtysh -c "show running-config"',
            "interfaces": 'vtysh -c "show interface"', "lldp": "lldpcli -f keyvalue show neighbors",
            "arp": "ip -4 neigh show"},
           "frr", ('vtysh -c "show', "lldpcli ", "ip -4 neigh"), blocked=_SHELL_BLOCK, comment="!",
           error=r"^\s*(% ?(Invalid|Incomplete|Ambiguous|Unknown)|bash: .*not found|command not found)",
           detect=("openssh", "linux", "frr", "net-snmp", "dropbear")),
)}


def get(platform: str | None) -> Driver:
    return DRIVERS.get(platform or "", DRIVERS["cisco-ios"])


def detect(*texts: str | None) -> str:
    """Platform id from banners, vendor names, portal products or sysDescr text (first specific match wins)."""
    text = " ".join(t for t in texts if t).lower()
    order = ("cisco-nxos", "cisco-asa", "aruba-cx", "edgeswitch", "unifi", "edgeos", "fortios", "pfsense", "opnsense",
             "aruba-os-switch", "ruijie-os", "tplink-jetstream", "dlink-ds", "huawei-vrp", "mikrotik-routeros",
             "juniper-junos", "fiberhome", "cisco-ios")
    for pid in order:
        if any(word in text for word in DRIVERS[pid].detect):
            return pid
    if "cisco" in text:
        return "cisco-ios"
    if any(word in text for word in DRIVERS["frr"].detect):
        return "frr"
    return "cisco-ios"


def matrix() -> list[dict]:
    """The capability matrix shown in Settings and the device panel."""
    return [{"id": d.id, "label": d.label, "vendor": d.vendor, "ssh": bool(d.netmiko_ssh), "telnet": bool(d.netmiko_telnet),
             "collection": bool(d.commands), "parser": d.parser, "self_healing": d.configurable and bool(d.netmiko_ssh),
             "device_revert_timer": d.revert, "save": list(d.save), "notes": list(d.notes)} for d in DRIVERS.values()]
