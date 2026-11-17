"""Smart discovery workflow: credential-free scan, automatic credential matching, recursive neighbour crawl,
optional manual authentication, skip handling, one confirmation, report.

Secrets supplied for authentication are used inside the request and discarded unless the user explicitly asks to
remember them, in which case they are stored as an encrypted, method-specific credential profile. Secrets never
appear in responses, history records or reports.

Automatic credential matching tries only the engineer's own saved profiles (SSH, SNMPv3 authPriv, SNMPv2c read-only),
in profile priority order, once each per device, and stops at the first success; nothing is guessed or retried.
The recursive crawl follows management addresses from LLDP/CDP tables, ARP entries and route next hops of devices it
has read. It stays inside the authorised range unless the engineer allows following neighbours into private
(RFC 1918) address space; excluded ranges are never contacted.
"""
from __future__ import annotations

import copy
import ipaddress
import re
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.errors import ValidationFailed
from backend.models import Device, Network
from backend.models.credential_profile import CredentialProfile
from backend.services import credential_service
from backend.services.demo_topology import _available_name
from backend.services.discovery import classification, fusion, subnets
from backend.services.discovery.engine import SECURE_METHODS, observation
from backend.services.discovery.real_engine import RealDiscoveryEngine

MAX_PREFIX = 22
MAX_CRAWL_DEPTH = 3
MAX_CRAWL_ADDRESSES = 1024
MAX_EXTRA_RANGES = 7  # further ranges (VLANs) typed with the first one
PRIVATE_NETS = [ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SESSION_DEFAULT = {"version": 1, "state": "prompting", "skipped": [], "skip_all": False,
                   "confirmation": "not_needed", "closed_reason": None}


DISCOVERY_SOURCES = ("discovery",)


def is_smart(network: Network) -> bool:
    return network.source in DISCOVERY_SOURCES and (network.metadata_json or {}).get("method") == "smart"


def default_engine(target: ipaddress.IPv4Network, excluded: list[str]):
    return RealDiscoveryEngine(target, excluded)


# The test suite installs a recorded-evidence engine here; the application always uses live discovery.
engine_factory = default_engine


def _engine(network: Network):
    scope = (network.metadata_json or {}).get("scope", {})
    return engine_factory(ipaddress.IPv4Network(network.metadata_json["target"], strict=False), scope.get("excluded", []))


def parse_scope(values: list[str] | None, label: str) -> list[str]:
    out = []
    for value in values or []:
        value = value.strip()
        if not value:
            continue
        try:
            out.append(str(ipaddress.IPv4Network(value, strict=False)))
        except ValueError:
            raise ValidationFailed(f"{label}: '{value}' is not an IPv4 address or subnet.") from None
    return out


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def scan(db: Session, user, network_range: ipaddress.IPv4Network, name: str | None, authorized: bool,
         excluded: list[str] | None = None, untrusted: list[str] | None = None, auto_credentials: bool = False,
         follow_neighbours: bool = False, max_depth: int = MAX_CRAWL_DEPTH, progress=None,
         extra_ranges: list[ipaddress.IPv4Network] | None = None,
         traverse_scope: ipaddress.IPv4Network | None = None) -> Network:
    if not authorized:
        raise ValidationFailed("Confirm that you are authorized to scan this address range before starting discovery.")
    if network_range.prefixlen < MAX_PREFIX:
        raise ValidationFailed(f"Limit discovery to an authorized range of at most a /{MAX_PREFIX} (1,024 addresses).")
    if network_range.is_multicast or network_range.is_unspecified or network_range.is_loopback and network_range.prefixlen < 24:
        raise ValidationFailed("Choose a unicast IPv4 range to discover.")
    excluded = parse_scope(excluded, "Excluded addresses")
    untrusted = parse_scope(untrusted, "Untrusted segments")
    if traverse_scope is not None:
        if traverse_scope.prefixlen < subnets.TRAVERSE_MIN_PREFIX:
            raise ValidationFailed(f"Limit the routed scope to traverse to at most a /{subnets.TRAVERSE_MIN_PREFIX} (65,536 addresses).")
        if not network_range.subnet_of(traverse_scope):
            raise ValidationFailed(f"The routed scope {traverse_scope} must contain the range being scanned ({network_range}).")
    engine = engine_factory(network_range, excluded)
    report = progress or (lambda *_: None)
    try:
        probe = engine.probe(progress=report)
    except TypeError:  # engines without progress reporting
        probe = engine.probe()
    # Further ranges the engineer authorised (other VLANs): swept the same way, off-link (ICMP and TCP, no ARP).
    extra_ranges = [n for n in (extra_ranges or []) if n != network_range]
    for extra in extra_ranges:
        more = engine_factory(extra, excluded).probe()
        probe["observations"] = list(probe["observations"]) + list(more["observations"])
        probe["no_response"] = list(probe["no_response"]) + list(more["no_response"])
        probe["timeline"] = list(probe["timeline"]) + [
            {**row, "id": f"{row['id']}-{extra}", "label": f"{row['label']} ({extra})"} for row in more["timeline"]]
    ranges = [str(network_range)] + [str(n) for n in extra_ranges]
    segments = None
    if traverse_scope is not None:
        segments, swept_more = _traverse(engine, traverse_scope, ranges, excluded, probe, report)
        ranges_swept = ranges + swept_more
    else:
        ranges_swept = list(ranges)
    meta = {
        "mode": "live", "live_device_contact": True, "target": str(network_range),
        "method": "smart", "discovery_schema_version": 3, "interface_naming_version": 1,
        "scope": {"authorised": ranges + ([str(traverse_scope)] if traverse_scope is not None else []),
                  "excluded": excluded, "untrusted": untrusted, "follow_neighbours": bool(follow_neighbours),
                  "traverse": str(traverse_scope) if traverse_scope is not None else None},
        "swept": ranges_swept,
        **({"segments": segments} if segments is not None else {}),
        "authorization": {"confirmed": True, "by": user.username, "at": _now(), "range": str(network_range)},
        "observations": probe["observations"], "timeline": probe["timeline"], "no_response": probe["no_response"],
        "discovery": {}, "discovery_can_login": [], "discovery_session": dict(SESSION_DEFAULT),
        "limitations": ["Hosts in another VLAN are found only when that subnet is scanned: add it to the range, or "
                        "let NetGuard read the router or layer 3 switch and follow the subnets it reports.",
                        "ICMP, DNS, the gateway hop and DHCP facts never establish a cable.",
                        "Switch neighbour and MAC tables require an authenticated read.",
                        "ARP (MAC) evidence is available only for addresses on this computer's own subnet."],
        "modeling_assumptions": [
            "Credential-free discovery identifies devices and services; cables stay unknown until a neighbour or MAC table is read.",
            "A MAC learned on a switch edge port is an inferred attachment; the endpoint NIC stays Unknown Port.",
            "Required and prohibited traffic intents are declared by the administrator."],
    }
    network = Network(
        name=_available_name(db, name or f"Discovery · {network_range}"), network_type="Enterprise",
        description=f"Network discovery of {', '.join(ranges)}.", created_by=user.id, environment="real",
        source="discovery", is_simulated=False, metadata_json=meta)
    db.add(network)
    db.flush()
    discovery = _add_devices(db, network, {}, probe["observations"])
    network.metadata_json = {**network.metadata_json, "discovery": discovery}
    db.flush()
    fusion.fuse(db, network)
    _sync_login_ids(network)
    db.commit()
    if auto_credentials:
        report("credentials", 0, 0, len(discovery))
        crawl(db, user, network, engine, follow_neighbours=follow_neighbours, max_depth=max_depth, progress=report)
    return network


def _traverse(engine, scope: ipaddress.IPv4Network, ranges: list[str], excluded: list[str], probe: dict, report) -> tuple[dict, list[str]]:
    """Routed segments inside the wider scope the engineer authorised: find the /24s whose usual gateway address
    answers (and this computer's own subnets), then sweep them within the crawl budget. Never leaves the scope."""
    to_probe = subnets.segments_to_probe(str(scope), ranges, excluded)
    finder = getattr(engine, "segment_gateways", None)
    report("segments", 0, len(to_probe), 0)
    answered = finder(to_probe) if finder and to_probe else {}
    rows = [{"cidr": cidr, "interface": None, "ip": hit["gateway"], "source": "gateway-probe", "via": hit["via"]}
            for cidr, hit in sorted(answered.items(), key=lambda kv: ipaddress.IPv4Network(kv[0]))]
    local = getattr(engine, "local_subnets", None)
    for cidr in (local() if local else []):
        net = ipaddress.IPv4Network(cidr, strict=False)
        if net.subnet_of(scope) and str(net) not in ranges and not any(r["cidr"] == str(net) for r in rows):
            rows.insert(0, {"cidr": str(net), "interface": "this computer", "ip": None, "source": "local", "via": "local interface"})
    for row in rows:
        if row["source"] == "gateway-probe":
            probe["observations"] = list(probe["observations"]) + [observation(
                "segment-gateway", row["ip"], {"segment": {k: row[k] for k in ("cidr", "interface", "ip", "source")}},
                f"{row['ip']} answered ({row['via']}): routed segment {row['cidr']} exists inside the authorised scope {scope}.",
                simulated=bool(getattr(engine, "simulated", False)))]
    sweep, left = subnets.plan(rows, [str(scope)], excluded, ranges, False)
    swept = []
    for row in sweep:
        report("segments", len(swept) + 1, len(sweep), 0)
        try:
            more = engine_factory(ipaddress.IPv4Network(row["cidr"]), excluded).probe()
        except Exception as exc:  # noqa: BLE001 — one unreachable segment must not abort the scan
            left.append({**row, "reason": f"sweep failed: {exc}"})
            continue
        swept.append(row["cidr"])
        probe["observations"] = list(probe["observations"]) + list(more["observations"])
        probe["no_response"] = list(probe["no_response"]) + list(more["no_response"])
        hosts = {o["subject"] for o in more["observations"]}
        probe["timeline"] = list(probe["timeline"]) + [{
            "id": f"segment-{row['cidr']}", "label": f"Routed segment {row['cidr']}", "count": len(hosts),
            "detail": (f"Gateway {row['ip']} answered ({row['via']})" if row["ip"] else "This computer is attached to it")
                      + "; swept with ICMP and TCP (no ARP across a router)."}]
    summary = {"scope": str(scope), "probed": len(to_probe), "gateways_checked": sum(len(v) for v in to_probe.values()),
               "answered": rows, "swept": swept, "left_out": left,
               "note": None if finder else "This discovery engine cannot probe segment gateways."}
    return summary, swept


def _add_devices(db: Session, network: Network, discovery: dict, observations: list[dict]) -> dict:
    """One device per newly observed subject (ARP, ICMP, service scan or SNMP engine answer)."""
    discovery = dict(discovery)
    known = {facts["ip"] for facts in discovery.values()}
    subjects = list(dict.fromkeys(o["subject"] for o in observations
                                  if o["technique"] in ("arp", "icmp", "tcp-banner", "snmpv3-engine")))
    for subject in subjects:
        if subject in known:
            continue
        banner = next((x["facts"] for x in observations if x["subject"] == subject and x["technique"] == "tcp-banner"), {})
        vendor = next((x["facts"].get("vendor") for x in observations if x["subject"] == subject and x["technique"] == "oui"), None)
        device = Device(network_id=network.id, name=subject, device_type=banner.get("type", "pc"), vendor=vendor,
                        management_ip=subject, x_position=0, y_position=0)
        db.add(device)
        db.flush()
        discovery[str(device.id)] = {"ip": subject, "position_source": "auto", "auth": None}
        known.add(subject)
    return discovery


# ------------------------------------------------------------ automatic credentials and recursive crawl
def _profiles(db: Session, user) -> list[CredentialProfile]:
    return list(db.scalars(select(CredentialProfile).where(CredentialProfile.created_by == user.id)
                           .order_by(CredentialProfile.priority, CredentialProfile.name)))


class ScanCredential:
    """A credential the engineer typed during this scan: kept in memory for the scan only, never stored."""

    def __init__(self, method, username, secret, priv=None, protocols=("SHA-256", "AES-128"), name="entered credentials",
                 port=None):
        self.id, self.method, self.username, self.password, self.priv_password = f"scan:{id(self)}", method, username, secret, priv
        self.snmp_auth_protocol, self.snmp_priv_protocol = protocols
        self.name, self.port = name, port


def auto_authenticate(db: Session, user, network: Network, engine=None, only: set[int] | None = None,
                      extra: list | None = None) -> list[dict]:
    """Try the engineer's credentials on devices not yet read: credentials entered in this scan first, then saved
    profiles in priority order; once each per device, first success wins."""
    profiles = list(extra or []) + _profiles(db, user)
    if not profiles:
        return []
    engine = engine or _engine(network)
    meta = dict(network.metadata_json)
    meta["discovery"] = {key: dict(value) for key, value in meta["discovery"].items()}
    observations = list(meta.get("observations", []))
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.network_id == network.id))}
    outcomes = []
    for did, facts in meta["discovery"].items():
        if only is not None and int(did) not in only or facts.get("auth") == "success" or not facts.get("methods"):
            continue
        tried = set(facts.get("auto_tried", []))
        attempts = []
        for profile in profiles:
            method = profile.method or "ssh"
            if method not in facts["methods"] or profile.id in tried:
                continue
            if not isinstance(profile, ScanCredential):
                tried.add(profile.id)
            protocols = (profile.snmp_auth_protocol or "SHA-256", profile.snmp_priv_protocol or "AES-128")
            ok, detail, observations = _read_device(db, user, engine, devices, meta, observations, int(did), method,
                                                    profile.username, profile.password or "", profile.priv_password,
                                                    protocols, ssh_port=profile.port if method == "ssh" else None)
            attempts.append(f"{profile.name} ({SECURE_METHODS[method]})")
            if ok:
                facts["auth_profile"] = profile.name
                facts["auth_detail"] = (f"{detail} Read with the credentials entered during this scan." if isinstance(profile, ScanCredential)
                                        else f"{detail} Matched automatically with the saved profile '{profile.name}'.")
                outcomes.append({"device_id": int(did), "name": devices[int(did)].name, "ok": True,
                                 "profile": profile.name, "method": method})
                break
        else:
            if attempts:
                facts.update(auth="failed", auth_at=_now(), auth_detail=(
                    "Credentials tried automatically, once each: " + ", ".join(attempts) +
                    ". None was accepted; NetGuard does not retry. Supply credentials for this device or skip it."))
                outcomes.append({"device_id": int(did), "name": devices[int(did)].name, "ok": False,
                                 "profile": None, "method": None})
        facts["auto_tried"] = sorted(t for t in tried if isinstance(t, int))
    meta["observations"] = observations
    network.metadata_json = meta
    db.flush()
    fusion.fuse(db, network)
    _sync_login_ids(network)
    db.commit()
    return outcomes


def _in_scope(ip: str, meta: dict, follow: bool) -> bool:
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if address.is_loopback and not meta["target"].startswith("127."):
        return False
    if address.is_multicast or address.is_unspecified or address.is_link_local or address.is_reserved:
        return False
    scope = meta.get("scope", {})
    if any(address in ipaddress.IPv4Network(n) for n in scope.get("excluded", [])):
        return False
    if any(address in ipaddress.IPv4Network(n) for n in scope.get("authorised", [])):
        return True
    return follow and any(address in net for net in PRIVATE_NETS)


_TCP_PORT = re.compile(r"TCP (\d+)")
MONITOR_LIMIT = 1024


def reachability(db: Session, network: Network) -> dict:
    """Up/down check of every discovered device with an address inside the authorised scope (no credentials used).

    Unmanaged endpoints (PCs, laptops) are only monitored this way; infrastructure is also checked here so a
    switch or firewall that stops answering is visible on the map."""
    meta = copy.deepcopy(network.metadata_json or {})
    follow = meta.get("scope", {}).get("follow_neighbours", False)
    info = meta.setdefault("discovery", {})
    targets: dict[str, list[int]] = {}
    owners: dict[str, list[str]] = {}
    skipped = 0
    for device in db.scalars(select(Device).where(Device.network_id == network.id).order_by(Device.id)):
        facts = info.setdefault(str(device.id), {})
        ip = device.management_ip
        if not ip or not _in_scope(ip, meta, follow) or len(targets) >= MONITOR_LIMIT:
            facts["reachability"] = {"state": "not-checked", "via": "no address inside the authorised scope" if ip else "no address"}
            skipped += 1
            continue
        ports = [int(m) for m in _TCP_PORT.findall(" ".join(map(str, facts.get("open_services", []))))]
        targets.setdefault(ip, sorted(set(ports), key=lambda p: (p not in (443, 22, 80), p)))
        owners.setdefault(ip, []).append(str(device.id))
    engine = _engine(network)
    check = getattr(engine, "reachable", None)
    answers = check(targets) if check and targets else {}
    stamp = _now()
    up = down = 0
    for ip, ids in owners.items():
        answer = answers.get(ip, {"state": "unknown", "via": "not checked by this engine"})
        up += answer["state"] == "up"
        down += answer["state"] == "down"
        for did in ids:
            previous = info[did].get("reachability", {})
            row = {**answer, "checked": stamp}
            row["since"] = previous.get("since") if previous.get("state") == answer["state"] else stamp
            info[did]["reachability"] = row
    meta["reachability"] = {"checked": stamp, "up": up, "down": down, "not_checked": skipped}
    network.metadata_json = meta
    db.commit()
    return {"checked": stamp, "up": up, "down": down, "not_checked": skipped,
            "devices": {did: info[did]["reachability"] for did in info if "reachability" in info[did]}}


def neighbour_addresses(db: Session, network: Network, follow: bool) -> dict[str, list[str]]:
    """Addresses learned from devices already read, grouped by source: management, arp, next-hop."""
    meta = network.metadata_json or {}
    known = {facts["ip"] for facts in meta.get("discovery", {}).values()}
    device_ids = [d for d in db.scalars(select(Device.id).where(Device.network_id == network.id))]
    from backend.models import Interface
    own = {ip for ip in db.scalars(select(Interface.ip_address).where(Interface.device_id.in_(device_ids))) if ip}
    found: dict[str, list[str]] = {"management": [], "arp": [], "next-hop": []}
    for o in meta.get("observations", []):
        if not o["authenticated"]:
            continue
        facts = o["facts"]
        if o["technique"] == "lldp-table":
            found["management"] += [row.get("mgmt_ip") for row in facts.get("rows", [])]
        elif o["technique"] == "arp-table":
            found["arp"] += [row.get("ip") for row in facts.get("entries", [])]
        elif o["technique"] == "routing-table":
            found["next-hop"] += [row.get("next_hop") for row in facts.get("routes", [])]
    return {key: [ip for ip in dict.fromkeys(values) if ip and ip not in known and ip not in own and _in_scope(ip, meta, follow)]
            for key, values in found.items()}


def crawl(db: Session, user, network: Network, engine=None, follow_neighbours: bool = False,
          max_depth: int = MAX_CRAWL_DEPTH, extra: list | None = None, progress=None) -> dict:
    """Read devices with the engineer's credentials, then probe and read the neighbours they report, hop by hop."""
    engine = engine or _engine(network)
    report = progress or (lambda *_: None)
    summary = {"rounds": [], "added": 0, "read": 0}
    budget = MAX_CRAWL_ADDRESSES
    outcomes = auto_authenticate(db, user, network, engine, extra=extra)
    summary["read"] += sum(o["ok"] for o in outcomes)
    for depth in range(1, max(0, min(max_depth, MAX_CRAWL_DEPTH)) + 1):
        candidates = neighbour_addresses(db, network, follow_neighbours)
        probe_list = list(dict.fromkeys(candidates["management"] + candidates["next-hop"] + candidates["arp"]))[:budget]
        # Other VLANs: every subnet a read router or layer 3 switch is attached to, or routes to, is swept too.
        meta = dict(network.metadata_json)
        scope = meta.get("scope", {})
        swept = list(meta.get("swept") or scope.get("authorised", []))
        sweep, left_out = subnets.plan(subnets.candidates(meta.get("observations", [])), scope.get("authorised", []),
                                       scope.get("excluded", []), swept, follow_neighbours)
        known = {facts["ip"] for facts in meta.get("discovery", {}).values()}
        sweep_list = [ip for row in sweep for ip in subnets.hosts(row["cidr"]) if ip not in known and ip not in probe_list]
        if not probe_list and not sweep:
            if left_out:
                meta["subnets_not_scanned"] = left_out
                network.metadata_json = meta
                db.commit()
            break
        budget -= len(probe_list)
        report("subnets" if sweep else "neighbours", depth, max_depth, len(probe_list) + len(sweep_list))
        result = engine.probe(probe_list + sweep_list)
        meta = dict(network.metadata_json)
        meta["swept"] = swept + [row["cidr"] for row in sweep]
        meta["subnets_not_scanned"] = left_out
        if sweep:
            meta["timeline"] = list(meta.get("timeline", [])) + [
                {"id": f"subnet-{row['cidr']}", "label": f"Other subnet {row['cidr']}",
                 "count": sum(1 for ip in subnets.hosts(row["cidr"]) if ip in {o["subject"] for o in result["observations"]}),
                 "detail": f"Reported by {row.get('reported_by')}"
                           + (f" on {row['interface']}" if row.get("interface") else " as a routed destination")
                           + "; swept with ICMP and TCP (no ARP across a router)."} for row in sweep]
        observations = list(meta.get("observations", [])) + list(result["observations"])
        answered = {o["subject"] for o in result["observations"]}
        # A host listed in a read router's ARP table exists even when it answers no probe (host firewalls).
        for o in meta.get("observations", []):
            if o["authenticated"] and o["technique"] == "arp-table":
                reader = o["observed_by"]
                for row in o["facts"].get("entries", []):
                    if row.get("ip") in candidates["arp"] and row.get("mac") and row["ip"] not in answered:
                        observations.append(observation("arp", row["ip"], {"mac": row["mac"]},
                                                        f"ARP entry on {reader}: {row['ip']} is at {row['mac']}"
                                                        + (f" ({row['interface']})." if row.get("interface") else "."),
                                                        observed_by=reader, simulated=False))
                        answered.add(row["ip"])
                    elif row.get("ip") in answered and row.get("mac") and not any(
                            x["technique"] == "arp" and x["subject"] == row["ip"] for x in observations):
                        observations.append(observation("arp", row["ip"], {"mac": row["mac"]},
                                                        f"ARP entry on {reader}: {row['ip']} is at {row['mac']}.",
                                                        observed_by=reader, simulated=False))
        before = len(meta.get("discovery", {}))
        meta["observations"] = observations
        meta["discovery"] = _add_devices(db, network, meta.get("discovery", {}), observations)
        added = len(meta["discovery"]) - before
        meta.setdefault("crawl", []).append({"depth": depth, "probed": len(probe_list) + len(sweep_list),
                                             "answered": len(answered), "added": added,
                                             "subnets": [row["cidr"] for row in sweep],
                                             "sources": {**{k: len(v) for k, v in candidates.items()},
                                                         "subnet-sweep": len(sweep_list)}})
        network.metadata_json = meta
        db.flush()
        fusion.fuse(db, network)
        _sync_login_ids(network)
        db.commit()
        outcomes = auto_authenticate(db, user, network, engine, extra=extra)
        summary["read"] += sum(o["ok"] for o in outcomes)
        summary["added"] += added
        summary["rounds"].append(meta["crawl"][-1])
        if not added and not any(o["ok"] for o in outcomes) or budget <= 0:
            break
    _history(db, user, network, "Automatic discovery crawl", {
        "rounds": len(summary["rounds"]), "devices_added": summary["added"], "devices_read": summary["read"]})
    return summary


def _sync_login_ids(network: Network) -> None:
    meta = dict(network.metadata_json)
    meta["discovery_can_login"] = sorted(int(did) for did, facts in meta["discovery"].items() if facts.get("methods"))
    meta["configuration_incomplete"] = any(r["important"] for r in _important_unread(meta))
    network.metadata_json = meta


def _important_unread(meta: dict) -> list[dict]:
    rows = []
    for did, facts in meta.get("discovery", {}).items():
        cls = facts.get("classification", {})
        if cls.get("auth") in ("required", "failed") and any(g["important"] for g in cls.get("gains", [])):
            rows.append({"device_id": int(did), "important": True})
    return rows


def refresh(db: Session, network: Network) -> None:
    fusion.fuse(db, network)
    _sync_login_ids(network)
    db.commit()


# ------------------------------------------------------------ session
def evaluate(db: Session, network: Network) -> dict:
    """Prompt queue and confirmation state, derived from the stored session and current requests."""
    meta = network.metadata_json or {}
    session = {**SESSION_DEFAULT, **meta.get("discovery_session", {})}
    available = classification.requests(db, network)
    skipped = set(session["skipped"])
    queue, candidates = [], []
    if session["state"] == "prompting" and not session["skip_all"]:
        queue = [r for r in available if r["device_id"] not in skipped and r["auth"] != "failed"]
        if not queue:
            candidates = [r for r in available if r["important"] and (r["device_id"] in skipped or r["auth"] == "failed")]
            if candidates and session["confirmation"] != "shown":
                session["confirmation"] = "pending"
            else:
                # Nothing left to ask, or the one consolidated confirmation was already shown.
                session["state"], session["closed_reason"] = "complete", session["closed_reason"] or "all_answered"
    elif session["skip_all"]:
        session["state"] = "complete"
    return {"session": session, "queue": queue, "confirmation_candidates": candidates if session["confirmation"] == "pending" else [],
            "available": available}


def _save_session(db: Session, network: Network, session: dict) -> None:
    network.metadata_json = {**network.metadata_json, "discovery_session": session}
    db.commit()


def _persist_evaluation(db: Session, network: Network) -> None:
    state = evaluate(db, network)
    _save_session(db, network, state["session"])


def skip(db: Session, user, network: Network, device_ids: list[int], skip_all: bool) -> None:
    session = {**SESSION_DEFAULT, **(network.metadata_json or {}).get("discovery_session", {})}
    known = {int(did) for did in network.metadata_json.get("discovery", {})}
    if any(did not in known for did in device_ids):
        raise ValidationFailed("A selected device does not belong to this discovery.")
    session["skipped"] = sorted(set(session["skipped"]) | set(device_ids))
    if skip_all:
        session.update(skip_all=True, state="complete", closed_reason="skip_all")
    _save_session(db, network, session)
    _persist_evaluation(db, network)
    _history(db, user, network, "Credential requests skipped" if skip_all else "Credential request skipped",
             {"devices": len(device_ids), "skip_all": skip_all})


def confirmation(db: Session, user, network: Network, action: str) -> None:
    session = {**SESSION_DEFAULT, **(network.metadata_json or {}).get("discovery_session", {})}
    if action == "shown":
        session["confirmation"] = "shown"
    elif action == "continue":
        session.update(state="complete", closed_reason=session.get("closed_reason") or "continue_without_credentials",
                       confirmation="shown" if session["confirmation"] in ("pending", "shown") else session["confirmation"])
    else:
        raise ValidationFailed("Unknown confirmation action.")
    _save_session(db, network, session)


# ------------------------------------------------------------ authentication
def authenticate(db: Session, user, network: Network, data: dict) -> dict:
    method = data["method"]
    if method not in SECURE_METHODS:
        raise ValidationFailed("Choose SSH, SNMPv3 or a read-only SNMPv2c community.")
    discovery = network.metadata_json.get("discovery", {})
    ids = list(dict.fromkeys(data["device_ids"]))
    if not ids:
        raise ValidationFailed("Select at least one device to authenticate.")
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.network_id == network.id))}
    for did in ids:
        facts = discovery.get(str(did))
        if did not in devices or facts is None:
            raise ValidationFailed("A selected device does not belong to this discovery.")
        if method not in facts.get("methods", []) and method not in facts.get("login_methods", []):
            raise ValidationFailed(f"{devices[did].name} does not offer {SECURE_METHODS[method]}.")
    profile = credential_service.profile_for(db, user, data["profile_id"]) if data.get("profile_id") else None
    # Bulk fallback queue: saved profiles tried in the given order on each device the entered credentials did not open.
    fallback = [credential_service.profile_for(db, user, pid) for pid in dict.fromkeys(data.get("fallback_profile_ids") or [])]
    queue_only = profile is None and not (data.get("password") or "") and bool(fallback)
    if profile is not None:
        if (profile.method or "ssh") != method:
            raise ValidationFailed(f"The saved profile '{profile.name}' is for {SECURE_METHODS.get(profile.method or 'ssh')}.")
        username, secret, priv = profile.username, profile.password or "", profile.priv_password
        protocols = (profile.snmp_auth_protocol or "SHA-256", profile.snmp_priv_protocol or "AES-128")
    else:
        username, secret, priv = (data.get("username") or "").strip(), data.get("password") or "", data.get("priv_password") or None
        protocols = (data.get("snmp_auth_protocol") or "SHA-256", data.get("snmp_priv_protocol") or "AES-128")
        if method == "snmpv2c":
            username = username or "community"
        if (not username or not secret) and not queue_only:
            raise ValidationFailed("Enter a username and password, choose a saved profile, or tick saved profiles to try in order.")
    if method == "snmpv2c" and not secret and not queue_only:
        raise ValidationFailed("Enter the read-only SNMPv2c community string.")
    if method == "snmpv3" and not queue_only and (len(secret) < 8 or not priv or len(priv) < 8):
        raise ValidationFailed("SNMPv3 authPriv needs authentication and privacy passphrases of at least 8 characters.")
    if method == "snmpv3" and (protocols[0] not in ("SHA-256", "SHA-512") or protocols[1] not in ("AES-128", "AES-256")):
        raise ValidationFailed("Choose SHA-256 or SHA-512 authentication and AES-128 or AES-256 privacy.")
    engine = _engine(network)
    meta = dict(network.metadata_json)
    meta["discovery"] = {key: dict(value) for key, value in meta["discovery"].items()}
    observations = list(meta.get("observations", []))
    outcomes = []
    ssh_port = data.get("ssh_port") or (profile.port if profile is not None else None)
    for did in ids:
        if queue_only:
            ok, detail = False, "No credentials entered; trying the saved profiles in order."
        else:
            ok, detail, observations = _read_device(db, user, engine, devices, meta, observations, did, method, username,
                                                    secret, priv, protocols, ssh_port=ssh_port if method == "ssh" else None)
        used = None
        if not ok and fallback:
            offered = set(meta["discovery"][str(did)].get("login_methods") or meta["discovery"][str(did)].get("methods", []))
            tried = []
            for candidate in fallback:
                cmethod = candidate.method or "ssh"
                if cmethod not in offered:
                    continue
                tried.append(candidate.name)
                cprot = (candidate.snmp_auth_protocol or "SHA-256", candidate.snmp_priv_protocol or "AES-128")
                ok, cdetail, observations = _read_device(db, user, engine, devices, meta, observations, did, cmethod,
                                                         candidate.username, candidate.password or "", candidate.priv_password,
                                                         cprot, ssh_port=candidate.port if cmethod == "ssh" else None)
                if ok:
                    used = candidate
                    detail = f"{cdetail} Opened with the saved profile '{candidate.name}' ({SECURE_METHODS[cmethod]}), tried in queue order."
                    meta["discovery"][str(did)]["auth_profile"] = candidate.name
                    break
            if not ok and tried:
                detail = f"{detail} Saved profiles tried once each, in order: {', '.join(tried)}. None was accepted."
        outcomes.append({"device_id": did, "name": devices[did].name, "ok": ok, "detail": detail,
                         "profile": used.name if used is not None else None})
    meta["observations"] = observations
    network.metadata_json = meta
    db.flush()
    fusion.fuse(db, network)
    _sync_login_ids(network)
    db.commit()  # the outcome and collected data are kept even if saving a profile fails below
    saved_profile, profile_note = None, None
    if data.get("remember") and profile is None and not queue_only and any(o["ok"] and not o.get("profile") for o in outcomes):
        saved_profile, profile_note = _remember(db, user, method, username, secret, priv,
                                                data.get("profile_name"), devices[ids[0]].name, protocols)
    crawled = None
    if data.get("continue_discovery", True) and not queue_only and any(o["ok"] and not o.get("profile") for o in outcomes):
        # Continue discovery from what the read revealed (neighbours, ARP, routes), with the same credentials.
        follow = (network.metadata_json or {}).get("scope", {}).get("follow_neighbours", False)
        credential = ScanCredential(method, username, secret, priv, protocols,
                                    name=profile.name if profile is not None else "entered credentials",
                                    port=ssh_port)
        crawled = crawl(db, user, network, engine, follow_neighbours=follow, extra=[credential])
    _persist_evaluation(db, network)
    _history(db, user, network, "Device authentication", {
        "method": SECURE_METHODS[method], "succeeded": sum(o["ok"] for o in outcomes),
        "failed": sum(not o["ok"] for o in outcomes), "remembered": saved_profile is not None},
        {"devices": [{"name": o["name"], "ok": o["ok"]} for o in outcomes]})
    return {"outcomes": outcomes, "profile": saved_profile, "profile_note": profile_note, "crawl": crawled}


def _static_routes(text: str) -> list[dict]:
    routes = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[:2] == ["ip", "route"] and parts[2][0].isdigit():
            hop = next((p for p in parts[4:] if p[0].isdigit()), None)
            if hop:
                routes.append({"destination": parts[2], "mask": parts[3], "next_hop": hop})
    return routes


def _read_device(db, user, engine, devices, meta, observations, did, method, username, secret, priv, protocols,
                 ssh_port: int | None = None):
    """Authenticate one device once and keep its read-only observations. Returns (ok, detail, observations)."""
    facts = meta["discovery"][str(did)]
    prefix = ""
    hint = {"ssh": facts.get("ssh_banner"), "vendor": facts.get("vendor_hint") or devices[did].vendor,
            "ssh_port": facts.get("ssh_port") or ssh_port or 22}
    try:
        ok = engine.authenticate(facts["ip"], method, username, secret, priv, protocols, hint=hint)
    except TypeError:  # engines without platform hints
        ok = engine.authenticate(facts["ip"], method, username, secret, priv, protocols)
    reason = getattr(engine, "last_error", None)
    label = SECURE_METHODS[method]
    if ok:
        facts.update(auth="success", auth_method=method, auth_at=_now(),
                     auth_detail=f"{prefix}{label} authentication succeeded; read-only tables collected."
                                 + (" SNMPv2c is cleartext on the wire; prefer SNMPv3 authPriv." if method == "snmpv2c" else ""))
        observations = [o for o in observations if not (o["authenticated"] and o["observed_by"] == facts["ip"])]
        for o in engine.collect(facts["ip"], method):
            if o["technique"] == "running-config" and "text" in o["facts"]:
                from backend.services import device_state
                text = o["facts"].pop("text")
                config = device_state.store_config(db, devices[did], text, method, "collected", user)
                o["facts"].update(config_id=config.id, sha256=config.sha256)
                attached = subnets.from_config(text)
                if attached:
                    observations.append(observation("connected-subnets", facts["ip"], {"subnets": attached},
                                                    f"{len(attached)} subnet(s) on the device's own interfaces: "
                                                    + ", ".join(s["cidr"] for s in attached[:8]) + ".",
                                                    authenticated=True, method=method, observed_by=facts["ip"],
                                                    simulated=False))
                routes = _static_routes(text)
                if routes:
                    observations.append(observation("routing-table", facts["ip"], {"routes": routes},
                                                    f"{len(routes)} static route(s) in the collected configuration.",
                                                    authenticated=True, method=method, observed_by=facts["ip"],
                                                    simulated=False))
            observations.append(o)
        return True, facts["auth_detail"], observations
    if facts.get("auth") == "success":
        # Keep the earlier successful read; record only that this attempt was rejected.
        return False, (f"{prefix}{label} authentication was rejected" + (f" ({reason})" if reason else "")
                       + "; the earlier successful read and its data are kept."), observations
    facts.update(auth="failed", auth_method=method, auth_at=_now(),
                 auth_detail=f"{prefix}{label} authentication failed" + (f": {reason}" if reason else "")
                             + ". No data was collected; NetGuard does not retry automatically.")
    return False, facts["auth_detail"], observations


def _remember(db, user, method, username, secret, priv, name, device_name, protocols=("SHA-256", "AES-128")):
    base = (name or f"{device_name} {SECURE_METHODS[method].split(' ')[0]}").strip()[:60]
    candidate, n = base, 2
    while db.scalar(select(CredentialProfile).where(CredentialProfile.created_by == user.id,
                                                    func.lower(CredentialProfile.name) == candidate.lower())):
        candidate, n = f"{base} {n}", n + 1
    try:
        row = CredentialProfile(created_by=user.id, name=candidate, username=username, port=22, priority=100,
                                method=method, notes="Saved from discovery authentication")
        row.password = secret
        if method == "snmpv3":
            row.priv_password = priv
            row.snmp_auth_protocol, row.snmp_priv_protocol = protocols
        if method == "snmpv2c":
            row.port = 161
        db.add(row)
        db.commit()
        return credential_service.profile_out(db, row), None
    except Exception:  # noqa: BLE001 - authentication already succeeded; report the storage problem only
        db.rollback()
        return None, "Authentication succeeded, but the credentials could not be saved as a profile."


def _history(db, user, network, title, summary, snapshot=None):
    from backend.services import history_service
    history_service.record(db, user, network.id, "discovery", title, {**summary, "status": "completed"}, snapshot or {})


# ------------------------------------------------------------ result payload
def extend_result(db: Session, network: Network, result: dict) -> dict:
    state = evaluate(db, network)
    discovery = (network.metadata_json or {}).get("discovery", {})
    for row in result["devices"]:
        facts = discovery.get(str(row["id"]), {})
        row["classification"] = facts.get("classification")
        row["methods"] = facts.get("methods", [])
        row["not_offered"] = facts.get("not_offered", [])
        row["location_notes"] = facts.get("location_notes", [])
        row["provenance"] = facts.get("provenance", [])
    links = result["links"]
    linked = {did for link in links for did in (link["source_device_id"], link["destination_device_id"])}
    counts = {key: 0 for key in classification.CATEGORY_ORDER}
    for row in result["devices"]:
        counts[(row["classification"] or {}).get("primary", "partial")] += 1
    no_response = (network.metadata_json or {}).get("no_response", [])
    counts["unreachable"] = len(no_response)
    result.update({
        "credential_requests": state["queue"], "available_authentications": state["available"],
        "confirmation_candidates": state["confirmation_candidates"], "session": state["session"],
        "timeline": (network.metadata_json or {}).get("timeline", []),
        "subnets": {"scanned": (network.metadata_json or {}).get("swept", []),
                    "not_scanned": (network.metadata_json or {}).get("subnets_not_scanned", [])},
        "report": {
            "counts": counts, "labels": classification.CATEGORY_LABELS,
            "connections": {"confirmed": sum(link["discovery_status"] == "observed" for link in links),
                            "inferred": sum(link["discovery_status"] == "inferred" for link in links),
                            "logical": sum(link["discovery_status"] == "logical" for link in links),
                            "unknown": sum(1 for row in result["devices"] if row["id"] not in linked),
                            "unverified_links": sum(link["discovery_status"] == "unknown" for link in links),
                            "manual": sum(link["discovery_status"] == "manual" for link in links)},
            "unreachable": no_response,
            "port_pairs": [{"link_id": link["id"], "source": link["source_device_name"],
                            "source_port": link["source_interface_name"] or fusion.UNKNOWN_PORT,
                            "destination": link["destination_device_name"],
                            "destination_port": link["destination_interface_name"] or fusion.UNKNOWN_PORT,
                            "status": {"observed": "confirmed", "inferred": "inferred", "manual": "manual", "logical": "logical"}.get(
                                link["discovery_status"], "unverified")} for link in links],
            "authorization": (network.metadata_json or {}).get("authorization"),
            "scope": (network.metadata_json or {}).get("scope"),
            "simulated": bool(network.is_simulated),
        },
    })
    grades = {"Confirmed": 0, "Inferred": 0, "Logical": 0}
    for link in links:
        if link.get("evidence_grade") in grades:
            grades[link["evidence_grade"]] += 1
    result["report"]["grades"] = {**grades, "Unknown": result["report"]["connections"]["unknown"]}
    result["summary"]["confirmed_links"] = result["report"]["connections"]["confirmed"]
    return result
