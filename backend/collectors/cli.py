"""Read-only CLI collection over SSH (Netmiko) or a laboratory console, and configuration changes on lab devices.

Supported platforms: Cisco IOS and IOS-XE (Netmiko "cisco_ios") and FRRouting on Linux (Netmiko "linux", vtysh).
collect() sends only the show commands listed in COMMANDS; configuration is changed only by apply_config(), which
the remediation service calls for an approved change on a laboratory device.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from backend.services.interface_naming import canonical_name

log = logging.getLogger("netguard.cli")

from backend.collectors import drivers

COMMANDS = {pid: dict(d.commands) for pid, d in drivers.DRIVERS.items() if d.commands}
NETMIKO_TYPES = {(pid, transport): d.netmiko(transport) for pid, d in drivers.DRIVERS.items()
                 for transport in ("ssh", "telnet") if d.netmiko(transport)}
_ERROR = re.compile(r"^\s*(% ?(Invalid|Incomplete|Ambiguous|Unknown)|bash: .*not found|command not found)", re.I | re.M)


class CliError(Exception):
    pass


class AuthFailed(CliError):
    pass


@dataclass
class Target:
    host: str
    port: int = 22
    transport: str = "ssh"  # ssh | telnet (laboratory console)
    platform: str = "cisco-ios"
    username: str = ""
    password: str = ""
    secret: str | None = None
    timeout: int = 12


@dataclass
class Collection:
    platform: str
    outputs: dict[str, str] = field(default_factory=dict)
    system: dict = field(default_factory=dict)
    ports: list[dict] = field(default_factory=list)
    neighbours: list[dict] = field(default_factory=list)
    macs: list[dict] = field(default_factory=list)
    vlans: list[list] = field(default_factory=list)
    arp: list[dict] = field(default_factory=list)
    stp: dict[str, str] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)  # recent syslog messages (show logging)
    running_config: str = ""
    warnings: list[str] = field(default_factory=list)


def _connect(target: Target):
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    driver = drivers.get(target.platform)
    device_type = NETMIKO_TYPES.get((driver.id, target.transport))
    if device_type is None:
        raise CliError(f"{driver.label} has no {target.transport.upper()} CLI driver; use its web GUI or SNMP.")
    params = dict(device_type=device_type, host=target.host, port=target.port, username=target.username or "",
                  password=target.password or "", conn_timeout=target.timeout, auth_timeout=target.timeout,
                  banner_timeout=target.timeout, fast_cli=False, global_delay_factor=1)
    if target.secret:
        params["secret"] = target.secret
    try:
        conn = ConnectHandler(**params)
    except NetmikoAuthenticationException:
        raise AuthFailed("The device rejected the supplied credentials.") from None
    except NetmikoTimeoutException:
        raise CliError(f"No {target.transport.upper()} response from {target.host}:{target.port}.") from None
    except Exception as exc:  # noqa: BLE001 - every transport problem becomes one readable message
        text = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        if "uthentication" in text:
            raise AuthFailed("The device rejected the supplied credentials.") from None
        raise CliError(f"Could not open a {target.transport.upper()} session to {target.host}:{target.port}: {text[:160]}") from None
    if driver.enable:
        try:
            if not conn.check_enable_mode():
                if not target.secret:
                    conn.disconnect()
                    raise CliError("The session is not in privileged EXEC mode; enter an enable secret.")
                conn.enable()
        except CliError:
            raise
        except Exception:  # noqa: BLE001
            conn.disconnect()
            raise CliError("Privileged EXEC mode could not be entered with the supplied secret.") from None
    return conn


def detect_platform(banner: str | None, vendor: str | None, *more: str | None) -> str:
    """Driver id from the SSH banner, the vendor (OUI, SNMP enterprise, web portal) and any other text."""
    return drivers.detect(banner, vendor, *more)


def test_login(target: Target) -> bool:
    conn = _connect(target)
    conn.disconnect()
    return True


def _show(conn, command: str, warnings: list[str], platform: str = "cisco-ios") -> str:
    assert drivers.get(platform).is_read_only(command), command  # collection sends read-only commands only
    try:
        out = conn.send_command(command, read_timeout=40, strip_prompt=True, strip_command=True)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"'{command}' failed: {str(exc).splitlines()[0][:120] if str(exc) else 'timeout'}")
        return ""
    if _ERROR.search(out or ""):
        return ""  # command not supported on this platform (for example show vlan on a router)
    return out or ""


def collect(target: Target) -> Collection:
    conn = _connect(target)
    result = Collection(platform=target.platform)
    try:
        for key, command in COMMANDS[target.platform].items():
            result.outputs[key] = _show(conn, command, result.warnings, target.platform)
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001
            pass
    if not result.outputs.get("running"):
        raise CliError("The device returned no running configuration (check the account's privilege level).")
    parse(result)
    return result


# ------------------------------------------------------------------ parsing
def _structured(raw: str, command: str, platform: str = "cisco_ios") -> list[dict]:
    if not raw.strip():
        return []
    try:
        from netmiko.utilities import get_structured_data

        data = get_structured_data(raw, platform=platform, command=command)
    except Exception:  # noqa: BLE001
        return []
    return data if isinstance(data, list) else []


def _name(raw: str, platform: str) -> str:
    raw = (raw or "").strip()
    return canonical_name(raw, "cisco-ios") if platform == "cisco-ios" and raw else raw


def _mac(value: str | None) -> str | None:
    from backend.collectors.netutil import normalize_mac

    return normalize_mac(value)


def _speed(text: str | None) -> int | None:
    if not text:
        return None
    m = re.search(r"(\d+)\s*(Mb|Gb|Kb)", text, re.I)
    if not m:
        return None
    value, unit = int(m.group(1)), m.group(2).lower()
    return value * 1000 if unit == "gb" else value // 1000 if unit == "kb" else value


SYSLOG_LINE = re.compile(r"%[A-Z0-9_]+-\d-[A-Z0-9_]+")


def parse(result: Collection) -> None:
    out, p = result.outputs, result.platform
    result.running_config = out.get("running", "")
    result.logs = [line.strip() for line in out.get("logging", "").splitlines() if SYSLOG_LINE.search(line)][-200:]
    if p == "frr":
        _parse_frr(result)
        return
    driver = drivers.get(p)
    if driver.parser != "ios":
        _parse_vendor(result, driver)
        return
    commands = COMMANDS[p]
    templ = driver.structured or "cisco_ios"

    def structured(raw, command):  # TextFSM templates of this platform, then the IOS ones
        if templ == "cisco_ios":
            return _structured(raw, command)
        return _structured(raw, commands.get(_KEYS.get(command, ""), command), templ) or (
            _structured(raw, command, "cisco_ios") if templ != "cisco_ios" else [])
    version = structured(out.get("version", ""), "show version")
    if version:
        v = version[0]
        hardware = v.get("hardware") or []
        serial = v.get("serial") or []
        result.system = {"hostname": v.get("hostname"), "version": v.get("version"),
                         "model": hardware[0] if hardware else None, "serial": serial[0] if serial else None,
                         "image": v.get("software_image") or v.get("running_image")}
    host = re.search(r"^hostname (\S+)", result.running_config, re.M)
    if host:
        result.system["hostname"] = result.system.get("hostname") or host.group(1)
    for row in structured(out.get("interfaces", ""), "show interfaces"):
        name = _name(row.get("interface", ""), p)
        link, proto = (row.get("link_status") or "").lower(), (row.get("protocol_status") or "").lower()
        status = "admin-down" if "administratively" in link else "up" if link == "up" and proto.startswith("up") else "down"
        errors = None
        try:
            errors = int(row.get("input_errors") or 0) + int(row.get("output_errors") or 0)
        except ValueError:
            pass
        duplex = (row.get("duplex") or "").lower()
        result.ports.append({"port": name, "status": status, "speed": _speed(row.get("speed")) or _speed(row.get("bandwidth")),
                             "duplex": "full" if duplex.startswith(("full", "a-full")) else "half" if "half" in duplex else None,
                             "mtu": int(row["mtu"]) if str(row.get("mtu", "")).isdigit() else None, "errors": errors,
                             "mac": _mac(row.get("mac_address")), "description": row.get("description") or None})
    for row in structured(out.get("lldp", ""), "show lldp neighbors detail"):
        result.neighbours.append({
            "protocol": "lldp", "local_port": _name(row.get("local_interface", ""), p),
            "sys_name": (row.get("neighbor_name") or "").split(".")[0] or None,
            "port_id": _name(row.get("neighbor_port_id") or row.get("neighbor_interface") or "", p),
            "chassis_mac": _mac(row.get("chassis_id")), "mgmt_ip": row.get("mgmt_address") or None,
            "sys_descr": (row.get("neighbor_description") or "")[:200]})
    for row in structured(out.get("cdp", ""), "show cdp neighbors detail"):
        mgmt = row.get("mgmt_address")
        result.neighbours.append({
            "protocol": "cdp", "local_port": _name(row.get("local_interface", ""), p),
            "sys_name": (row.get("neighbor_name") or "").split(".")[0] or None,
            "port_id": _name(row.get("neighbor_interface", ""), p), "chassis_mac": None,
            "mgmt_ip": mgmt if isinstance(mgmt, str) else (mgmt[0] if mgmt else None),
            "sys_descr": (row.get("platform") or "")[:200]})
    for row in structured(out.get("mac", ""), "show mac address-table"):
        ports = row.get("destination_port") or []
        ports = ports if isinstance(ports, list) else [ports]
        mac = _mac(row.get("destination_address"))
        if mac and len(ports) == 1 and (row.get("type") or "").upper() != "STATIC" and not ports[0].upper().startswith("CPU"):
            vlan = row.get("vlan_id") or row.get("vlan")
            result.macs.append({"port": _name(ports[0], p), "mac": mac, "vlan": int(vlan) if str(vlan).isdigit() else None})
    for row in structured(out.get("vlan", ""), "show vlan"):
        if str(row.get("vlan_id", "")).isdigit() and int(row["vlan_id"]) < 1002:
            result.vlans.append([int(row["vlan_id"]), row.get("vlan_name")])
    for row in structured(out.get("arp", ""), "show ip arp"):
        mac = _mac(row.get("mac_address"))
        if mac:
            result.arp.append({"ip": row.get("ip_address"), "mac": mac, "interface": _name(row.get("interface", ""), p)})
    for row in structured(out.get("stp", ""), "show spanning-tree"):
        state = (row.get("status") or "").upper()
        name = _name(row.get("interface", ""), p)
        if name:
            result.stp[name] = "blocking" if state.startswith(("BLK", "BKN")) else "forwarding" if state.startswith("FWD") else state.lower()


_KEYS = {"show version": "version", "show interfaces": "interfaces", "show lldp neighbors detail": "lldp",
         "show cdp neighbors detail": "cdp", "show mac address-table": "mac", "show vlan": "vlan", "show ip arp": "arp",
         "show spanning-tree": "stp"}
_IP_MAC = re.compile(r"(\d+\.\d+\.\d+\.\d+)\D{1,40}?([0-9a-f]{2}([:-])[0-9a-f]{2}(\3[0-9a-f]{2}){4}|[0-9a-f]{4}[.-][0-9a-f]{4}[.-][0-9a-f]{4})", re.I)


def _parse_vendor(result: Collection, driver) -> None:
    """Non-IOS platforms: the configuration parser gives hostname and interfaces; ARP rows are read generically
    (an IPv4 address followed by a MAC on one line, which every platform's ARP output has)."""
    from backend.services import vendor_parsers

    dev = vendor_parsers.parse(result.running_config, driver.parser)
    if dev is not None:
        result.system = {"hostname": dev.name, "version": None, "model": driver.label, "serial": None}
        for iface in dev.ifs.values():
            result.ports.append({"port": iface.name, "status": "admin-down" if iface.down else "up", "speed": iface.speed,
                                 "duplex": iface.duplex, "mtu": iface.mtu, "errors": None, "mac": None,
                                 "description": iface.description})
        result.vlans = [[vid, name] for vid, name in sorted(dev.vlans.items())]
    version = result.outputs.get("version", "")
    m = re.search(r"(?:Version|version)[:\s]+v?([\w.()-]+)", version)
    if m:
        result.system["version"] = m.group(1)
    for line in result.outputs.get("arp", "").splitlines():
        hit = _IP_MAC.search(line)
        if hit:
            mac = _mac(hit.group(2))
            if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                result.arp.append({"ip": hit.group(1), "mac": mac, "interface": None})


def _parse_frr(result: Collection) -> None:
    out = result.outputs
    host = re.search(r"^hostname (\S+)", result.running_config, re.M)
    version = re.search(r"FRRouting (\S+)", out.get("version", ""))
    result.system = {"hostname": host.group(1) if host else None, "version": version.group(1) if version else None,
                     "model": "FRRouting", "serial": None}
    for block in re.split(r"(?m)^Interface ", out.get("interfaces", "")):
        m = re.match(r"(\S+) is (\w+), line protocol is (\w+)", block)
        if not m:
            continue
        name, admin, proto = m.groups()
        mtu = re.search(r"mtu (\d+)", block)
        mac = re.search(r"HWaddr: ([0-9a-f:]{17})", block, re.I)
        errors = re.findall(r"(\d+) (?:input|output) errors", block)
        result.ports.append({"port": name, "status": "admin-down" if admin == "down" else "up" if proto == "up" else "down",
                             "speed": None, "duplex": None, "mtu": int(mtu.group(1)) if mtu else None,
                             "errors": sum(int(x) for x in errors) if errors else None, "mac": _mac(mac.group(1)) if mac else None})
    rows: dict[str, dict] = {}
    for line in out.get("lldp", "").splitlines():
        m = re.match(r"lldp\.([^.]+)\.(.+?)=(.*)$", line.strip())
        if m:
            rows.setdefault(m.group(1), {})[m.group(2)] = m.group(3)
    for local, row in rows.items():
        result.neighbours.append({
            "protocol": "lldp", "local_port": local, "sys_name": row.get("chassis.name"),
            "port_id": row.get("port.ifname") or row.get("port.descr"), "chassis_mac": _mac(row.get("chassis.mac")),
            "mgmt_ip": row.get("chassis.mgmt-ip"), "sys_descr": (row.get("chassis.descr") or "")[:200]})
    for line in out.get("arp", "").splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+) dev (\S+) lladdr (\S+)", line)
        if m:
            result.arp.append({"ip": m.group(1), "mac": _mac(m.group(3)), "interface": m.group(2)})


def device_type(collection: Collection) -> str:
    """Router, firewall or switch from the collected evidence (switchports and a VLAN table mean a switch)."""
    if collection.platform == "frr":
        return "router"
    driver = drivers.get(collection.platform)
    if driver.id in ("fortios", "pfsense", "opnsense", "cisco-asa"):
        return "firewall"
    if driver.parser != "ios":
        from backend.services import vendor_parsers

        dev = vendor_parsers.parse(collection.running_config, driver.parser)
        return dev.kind if dev is not None and dev.kind in ("router", "switch", "firewall") else "router"
    switchports = len(re.findall(r"^\s+switchport (mode|access|trunk)", collection.running_config, re.M))
    # A multilayer switch is still a switch: NetGuard models its SVI routing as not analysed (import warning).
    return "switch" if (collection.vlans or switchports) else "router"


# ------------------------------------------------------------------ laboratory changes
def running_config(target: Target) -> str:
    conn = _connect(target)
    try:
        return _show(conn, COMMANDS[target.platform]["running"], [], target.platform)
    finally:
        conn.disconnect()


def _close(conn) -> None:
    try:
        conn.disconnect()
    except Exception:  # noqa: BLE001
        pass


def apply_config(target: Target, commands: list[str]) -> str:
    """Enter the commands in configuration mode (commit where the platform needs it). Raises CliError when the
    device rejects a command."""
    driver = drivers.get(target.platform)
    if not driver.configurable or not driver.netmiko_ssh:
        raise CliError(f"NetGuard does not push configuration to {driver.label}; apply the approved change in its "
                       "management interface and record the deployment.")
    conn = _connect(target)
    error = re.compile(driver.error, re.I | re.M)
    try:
        output = conn.send_config_set(commands, read_timeout=60, error_pattern=driver.error)
        if driver.commit:
            output += conn.commit() or ""
            if driver.id == "edgeos":
                output += conn.exit_config_mode() or ""
    except Exception as exc:  # noqa: BLE001
        raise CliError(f"The device rejected the change: {str(exc).splitlines()[0][:200] if str(exc) else 'error'}") from None
    finally:
        _close(conn)
    if error.search(output or "") or _ERROR.search(output or ""):
        hit = error.search(output or "") or _ERROR.search(output or "")
        raise CliError("The device rejected a command: " + hit.group(0).strip())
    return output


def save_config(target: Target) -> str:
    """Persist the running configuration (after a confirmed change)."""
    driver = drivers.get(target.platform)
    if not driver.save:
        return ""
    conn = _connect(target)
    try:
        out = ""
        for command in driver.save:
            out += conn.send_command_timing(command, read_timeout=60) or ""
            if re.search(r"\[confirm\]|\[y/n\]|\(y/n\)|Destination filename|Are you sure", out, re.I):
                out += conn.send_command_timing("y" if re.search(r"y/n", out, re.I) else "\n", read_timeout=60) or ""
        return out
    except Exception as exc:  # noqa: BLE001
        raise CliError(f"Saving the configuration failed: {str(exc).splitlines()[0][:160] if str(exc) else 'error'}") from None
    finally:
        _close(conn)


def startup_matches_running(target: Target) -> bool | None:
    """Cisco IOS only: whether the startup configuration equals the running one (a reload timer is safe only
    when it would restore the pre-change configuration and nothing else). None when not determinable."""
    if drivers.get(target.platform).revert != "ios-reload":
        return None
    from backend.services import config_diff

    conn = _connect(target)
    try:
        running = _show(conn, "show running-config", [], target.platform)
        startup = _show(conn, "show startup-config", [], target.platform)
    finally:
        _close(conn)
    if not running or not startup:
        return None
    header = re.compile(r"^(Using \d+ out of \d+ bytes.*|Building configuration.*|Current configuration.*|"
                        r"! Last configuration change.*|! NVRAM config last updated.*)$", re.M)
    return config_diff.equivalent(header.sub("", running), header.sub("", startup))


def arm_revert(target: Target, minutes: int) -> str | None:
    """Arm the platform's own dead-man's switch so the device restores the pre-change configuration by itself if
    NetGuard loses it (the change cuts the management path). Returns the mechanism used, or None."""
    driver = drivers.get(target.platform)
    if driver.revert == "ios-reload":
        conn = _connect(target)
        try:
            out = conn.send_command_timing(f"reload in {int(minutes)}", read_timeout=30) or ""
            if re.search(r"save\?|modified", out, re.I):
                out += conn.send_command_timing("no", read_timeout=30) or ""
            if re.search(r"confirm", out, re.I):
                out += conn.send_command_timing("\n", read_timeout=30) or ""
        finally:
            _close(conn)
        if _ERROR.search(out or ""):
            return None
        return f"reload in {int(minutes)} (restores the saved startup configuration)"
    if driver.revert == "fortios-revert":
        apply_config(target, ["config system global", "set cfg-save revert", f"set cfg-revert-timeout {int(minutes) * 60}", "end"])
        return f"cfg-save revert, timeout {int(minutes) * 60} s"
    return None


def cancel_revert(target: Target) -> None:
    driver = drivers.get(target.platform)
    if driver.revert == "ios-reload":
        conn = _connect(target)
        try:
            conn.send_command_timing("reload cancel", read_timeout=30)
        finally:
            _close(conn)
    elif driver.revert == "fortios-revert":
        conn = _connect(target)
        try:
            conn.send_command_timing("execute cfg save", read_timeout=30)
            conn.send_config_set(["config system global", "set cfg-save automatic", "end"], read_timeout=30)
        finally:
            _close(conn)
