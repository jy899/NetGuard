"""Physical checks and advisories from stored evidence; no device contact."""
from collections import defaultdict
import re

from backend.services.forwarding import _vlan_fabric, switchport_mode
from backend.services.interface_naming import canonical_name, platform_for
from backend.services.physical_layer import link_ports, media_problem
from backend.services.rules import RULES


def physical_findings(model):
    from backend.services.validation_engine import Finding

    findings = []
    for link in model.links.values():
        ends = link_ports(model, link)
        evidence = [{"source": "hardware catalogue and stored interface record",
                     "detail": f"{dev.name} {iface.name}: {dev.model}, {info['label']}; recorded speed {iface.speed_mbps or 'unknown'} Mb/s."}
                    for dev, iface, info in ends if iface and info]
        if problem := media_problem(model, link):
            a, b = ends
            recommendation = (f"Use a {a[2]['media']} port on {b[0].name} compatible with {a[0].name} {a[1].name}, "
                              "or fit supported transceivers with matching media at both ends.")
            findings.append(Finding("PHY001", f"link:{link.id}", problem["reason"] + ".",
                [dev.id for dev, _, _ in ends], [link.id],
                {"symptom": f"The physical connection between {a[0].name} and {b[0].name} cannot become operational.",
                 "evidence": evidence, "recommendation": recommendation,
                 "expected_outcome": "Both ports use compatible media; traffic can use this link after remaining faults are corrected."}))
        for dev, iface, info in ends:
            if iface and info["exists"] is False:
                findings.append(Finding("PHY002", f"interface:{dev.id}:{iface.id}",
                    f"{dev.name} interface {iface.name} is not present on {dev.model}.", [dev.id], [link.id],
                    {"symptom": f"The cable inventory identifies a port unavailable on {dev.name}'s recorded hardware.",
                     "evidence": evidence, "recommendation": f"Verify {dev.name}'s model and select an existing compatible port on {dev.model}."}))
        if all(iface and info["exists"] is True and iface.speed_mbps for _, iface, info in ends):
            a, b = ends
            if a[1].speed_mbps != b[1].speed_mbps:
                findings.append(Finding("PHY003", f"link:{link.id}",
                    f"{a[0].name} {a[1].name} is recorded at {a[1].speed_mbps} Mb/s while {b[0].name} {b[1].name} is {b[1].speed_mbps} Mb/s.",
                    [a[0].id, b[0].id], [link.id],
                    {"symptom": "The two ends of this link report different operating speeds.", "evidence": evidence}))
        known = [(dev, iface) for dev, iface, _ in ends if iface is not None]
        duplex = {iface.duplex for _, iface in known if iface.duplex in ("full", "half")}
        if len(known) == 2 and len(duplex) == 2:
            (da, ia), (db_, ib) = known
            findings.append(Finding("PHY004", f"link:{link.id}",
                f"{da.name} {ia.name} is {ia.duplex} duplex while {db_.name} {ib.name} is {ib.duplex} duplex.",
                [da.id, db_.id], [link.id],
                {"symptom": "The link drops frames and runs far below its speed.",
                 "evidence": [{"source": "interface duplex (configuration or show interfaces)",
                               "detail": f"{da.name} {ia.name}: {ia.duplex}; {db_.name} {ib.name}: {ib.duplex}."}]}))
        for dev, iface in known:
            if iface.error_count is not None and iface.error_count >= ERROR_THRESHOLD:
                findings.append(Finding("PHY005", f"errors:{dev.id}:{iface.id}",
                    f"{dev.name} {iface.name} reported {iface.error_count} input/output errors in the last collection.",
                    [dev.id], [link.id],
                    {"symptom": "Frames on this link are being corrupted or dropped.", "errors": iface.error_count,
                     "confidence": 0.7, "certainty": "suspected",
                     "evidence": [{"source": "interface counters (show interfaces / IF-MIB)",
                                   "detail": f"{dev.name} {iface.name}: {iface.error_count} errors."}]}))
    return findings


ERROR_THRESHOLD = 10  # input + output errors since the counters were last cleared


def _advisory(rule_id, subject, devices, evidence, recommendation=None):
    rule = RULES[rule_id]
    reference = {"SEC001": "Network segmentation (NIST SP 800-41 / CIS Control 12)",
                 "SEC002": "NSA Network Infrastructure Security Guide (2022): secure management protocols",
                 "SEC003": "NSA Network Infrastructure Security Guide (2022): SNMP",
                 "SEC004": "NSA Network Infrastructure Security Guide (2022): passwords",
                 "SEC005": "NSA Network Infrastructure Security Guide (2022): remote administration",
                 "SEC006": "NSA Network Infrastructure Security Guide (2022): disable unused ports",
                 "NAME001": "NetGuard interface naming standard"}[rule_id]
    return {"id": f"{rule_id}|{subject}", "rule_id": rule_id, "title": rule.name, "name": rule.name,
            "category": "advisory", "severity": rule.severity, "evidence": evidence,
            "affected_devices": [dev.name for dev in devices], "devices": [dev.name for dev in devices],
            "device_ids": [dev.id for dev in devices], "recommendation": recommendation or rule.recommendation,
            "reference": reference, "standard": reference}


def hygiene_advisories(model) -> list[dict]:
    """Security hygiene pack: checks on the collected or imported running configuration (never on secrets)."""
    rows = []
    for dev in model.devices.values():
        facts = dev.facts or {}
        if not facts or dev.type not in ("router", "switch", "firewall"):
            continue
        source = "running configuration"
        vty = [line for line in facts.get("vty", []) if line.get("kind") == "vty"]
        telnet = [line["lines"] for line in vty if line.get("transport") and
                  any(t in ("telnet", "all") for t in line["transport"])]
        unset = [line["lines"] for line in vty if line.get("transport") is None and dev.platform != "frr"]
        exposed = []
        ios_like = dev.platform in (None, "cisco-ios", "cisco-iosxe", "cisco-nxos", "ruijie-os", "frr")
        if telnet:
            exposed.append(f"line {', '.join(telnet)}: transport input allows Telnet" if ios_like
                           else f"{', '.join(telnet)}: Telnet management is enabled")
        if unset:
            exposed.append(f"line {', '.join(unset)}: no transport input (older IOS defaults allow Telnet)")
        if facts.get("http_server"):
            exposed.append("ip http server is enabled (cleartext HTTP management)" if ios_like
                           else "cleartext HTTP management is enabled")
        if exposed:
            rows.append(_advisory("SEC002", str(dev.id), [dev], [{"source": source, "detail": f"{dev.name}: {e}."} for e in exposed],
                                  f"On {dev.name}: 'transport input ssh' on every VTY line and 'no ip http server'." if ios_like
                                  else f"On {dev.name}: allow only SSH and HTTPS management (remove Telnet and HTTP)."))
        communities = facts.get("snmp_communities", [])
        if communities:
            rw = sum(c.get("mode") == "RW" for c in communities)
            open_ = sum(not c.get("restricted") for c in communities)
            rows.append(_advisory("SEC003", str(dev.id), [dev], [{"source": source, "detail":
                f"{dev.name}: {len(communities)} SNMP community string(s) configured"
                + (f", {rw} with write access" if rw else "") + (f", {open_} without an ACL" if open_ else "") + "."}]))
        weak = []
        enable = facts.get("enable")
        if enable in ("password 0", "password 7"):
            weak.append(f"enable {enable.replace('password', 'password type')}")
        elif enable == "secret 5":
            weak.append("enable secret type 5 (MD5)")
        for user in facts.get("local_users", []):
            if user.get("storage") in ("password 0", "password 7", "secret 5"):
                weak.append(f"username {user['user']} uses {user['storage'].replace('password', 'password type').replace('secret', 'secret type')}")
        for line in facts.get("vty", []):
            if line.get("password") in ("cleartext", "type 7"):
                weak.append(f"line {line['lines']} password is {line['password']}")
        if weak:
            rows.append(_advisory("SEC004", str(dev.id), [dev], [{"source": source, "detail": f"{dev.name}: {w}."} for w in weak]))
        open_vty = [line["lines"] for line in vty if not line.get("access_class") and line.get("login") != "none"
                    and line.get("transport") != ["none"]]
        if open_vty and dev.platform != "frr":
            rows.append(_advisory("SEC005", str(dev.id), [dev], [{"source": source, "detail":
                f"{dev.name}: line {', '.join(open_vty)} has no access-class."}]))
        if dev.is_switch:
            linked = {model.links[lid].local_if(dev.id) for lid in model.links if dev.id in (model.links[lid].a_dev, model.links[lid].b_dev)}
            unused = [iface.name for iface in dev.interfaces.values()
                      if (iface.mode == "access" or (iface.mode is None and iface.vlan)) and iface.status == "down"
                      and iface.id not in linked]
            if unused:
                rows.append(_advisory("SEC006", str(dev.id), [dev], [{"source": "interface state (show interfaces / IF-MIB)",
                    "detail": f"{dev.name}: {', '.join(sorted(unused)[:12])}{' ...' if len(unused) > 12 else ''} "
                              "administratively up without a link."}],
                    f"Shut down {', '.join(sorted(unused)[:6])} on {dev.name} and move them to an unused VLAN."))
    return rows


def _segment(model, dev, nic):
    """(switch, VLAN) where an endpoint attaches, using the forwarding engine's eligibility rules."""
    if not nic.up:
        return None
    for link in model.links_of(dev.id):
        peer_id, peer_if = link.other(dev.id)
        switch, port = model.device(peer_id), model.iface(peer_id, peer_if)
        if (link.local_if(dev.id) == nic.id and switch.is_switch and port and port.up and switchport_mode(port) == "access"
                and port.vlan is not None and port.vlan in switch.vlans and not media_problem(model, link)
                and port.stp_state not in ("blocking", "discarding", "disabled")):
            return switch, port.vlan
    return None


def advisories(model):
    from backend.services.interface_naming import port_info

    rows = []
    for dev in model.devices.values():
        if platform_for(dev.vendor, dev.model, dev.type) != "cisco-ios":
            continue
        for iface in dev.interfaces.values():
            canonical = canonical_name(iface.name, "cisco-ios")
            # Suggest the canonical name unless catalogued hardware proves it absent (PHY002 reports that port).
            if canonical != iface.name.strip() and port_info(dev.vendor, dev.model, dev.type, canonical)["exists"] is not False:
                rows.append(_advisory("NAME001", f"{dev.id}:{iface.id}", [dev],
                    [{"source": "stored interface name", "detail": f"{dev.name}: {iface.name}; canonical spelling {canonical}."}],
                    f"Use {canonical} for {dev.name} {iface.name}; review references before renaming a saved interface."))
    rows.extend(hygiene_advisories(model))
    discovery = model.observations.get("discovery", {})
    segments = defaultdict(list)
    roles = {}
    for dev in model.devices.values():
        facts = discovery.get(str(dev.id), {})
        # A user-supplied identity supersedes the scan's role, as in Device.role.
        role = "" if facts.get("identity_source") == "user supplied" else str(facts.get("role", "")).lower()
        # SEC002 needs infrastructure plus service evidence; a discovered role is optional.
        infrastructure = dev.type in ("router", "switch", "firewall") or "access point" in role
        if infrastructure and not dev.facts:  # configuration facts, when collected, decide SEC002 (hygiene_advisories)
            services = facts.get("open_services", facts.get("ports", []))
            observed = list(services) + list(facts.get("evidence", []))
            exposed = [str(item) for item in observed if
                       re.search(r"\b(?:http\s*(?:\(|:|port\s*)?\s*80|telnet\s*(?:\(|:|port\s*)?\s*23)\b", str(item), re.I)]
            if exposed:
                rows.append(_advisory("SEC002", str(dev.id), [dev],
                    [{"source": "stored discovery service evidence", "detail": item} for item in exposed]))
        # Untrusted devices need a discovered role; internal assets are known from their stored type.
        untrusted = bool(role) and any(word in role for word in ("guest", "camera", "phone", "unknown host", "access point"))
        # Sensitive: servers (not printers) and staff workstations (not kiosk/reception/public-use PCs).
        staff_pc = dev.type == "pc" and not any(word in role for word in ("kiosk", "reception", "public", "shared"))
        sensitive = not untrusted and (dev.type == "server" and "printer" not in role or staff_pc)
        if not (untrusted or sensitive):
            continue
        roles[dev.id] = role or f"{dev.type} (stored device type)"
        joined = set()
        for nic in (iface for iface in dev.interfaces.values() if iface.network):
            attached = _segment(model, dev, nic)
            if attached:
                # One broadcast domain = the switches that forward this VLAN to each other (same rules as forwarding).
                switch, vlan = attached
                key = (vlan, str(nic.network), min(_vlan_fabric(model, switch, vlan)))
                if key not in joined:
                    joined.add(key)
                    segments[key].append((dev, untrusted, sensitive))
    denied = {(intent.src, intent.dst) for intent in model.intents
              if intent.expected == "deny" and intent.protocol == "ip" and intent.port is None}
    for (vlan, subnet, _fabric_id), members in segments.items():
        pairs = [(untrusted, sensitive) for untrusted, is_untrusted, _ in members if is_untrusted
                 for sensitive, _, is_sensitive in members if is_sensitive
                 and (untrusted.id, sensitive.id) not in denied]
        if pairs:
            affected = {dev.id: dev for pair in pairs for dev in pair}
            evidence = [{"source": "stored access VLAN, endpoint subnet and discovery roles",
                         "detail": f"VLAN {vlan if vlan is not None else 'unknown'}, subnet {subnet}: " +
                                   ", ".join(f"{dev.name} ({roles[dev.id]})" for dev in affected.values()) + "."},
                        {"source": "NetGuard isolation intents", "detail": "No deny intent covers these untrusted/sensitive device pairs."}]
            rows.append(_advisory("SEC001", f"{vlan}:{subnet}:{_fabric_id}", list(affected.values()), evidence))
    return sorted(rows, key=lambda row: (row["rule_id"], row["id"]))


def _unevaluated(model, starts, dst, skip):
    """Shortest continuation from `starts` towards dst through devices not yet evaluated."""
    queue = [(node, [] if node in skip else [node]) for node in starts]
    visited = set(starts) | set(skip)
    while queue:
        node, path = queue.pop(0)
        if node == dst:
            return [n for n in path if n != dst]
        for link in model.links_of(node):
            peer, _ = link.other(node)
            if peer not in visited:
                visited.add(peer)
                queue.append((peer, path + [peer]))
    return []


def coverage_notes(model, flows, which="baseline"):
    """Report the unevaluated continuation of failed required paths, without inferring faults."""
    groups = {}

    def group(key):
        return groups.setdefault(key, {"flows": set(), "devices": set(), "evaluated": set()})

    for flow in flows:
        result = getattr(flow, which)
        if flow.kind == "gateway" or flow.expected != "allow" or result.reachable or result.fail_device is None or flow.dst is None:
            continue
        detail = getattr(result, "detail", None) or {}
        # A return-leg failure means the forward path was already evaluated end to end.
        if detail.get("direction") == "return":
            continue
        start = result.fail_device
        if start == flow.dst:
            continue
        if result.code == "acl_deny" and start in result.path:
            # Forwarding succeeded end to end (routes are computed before ACLs); only the
            # policy checks after the blocking device were not reached.
            continuation = [node for node in result.path[result.path.index(start) + 1:] if node != flow.dst]
            if continuation:
                entry = group(("acl", start))
                entry["flows"].add(flow.key)  # names need not be unique
                entry["devices"].update(continuation)
            continue
        if start == flow.src:
            # Source attachment failure: its access switch was checked (that is the evidence),
            # so the unevaluated part starts after it.
            continuation = _unevaluated(model, [start], flow.dst, {start})[1:]
            if continuation:
                entry = group(("source", start))
                entry["flows"].add(flow.key)  # names need not be unique
                entry["devices"].update(continuation)
            continue
        # Routers that forwarded the traffic were evaluated, even when the cause is reported elsewhere.
        evaluated = set(result.path) | set(detail.get("traversed", []))
        link = model.links.get(result.fail_link) if result.fail_link is not None else None
        ends = [node for node in (link.a_dev, link.b_dev) if node not in evaluated] if link else []
        # Without a failing link the note says the flow stops at `start`, so the continuation begins after it
        # (otherwise "stop at R1 ... beyond that point (FW1, R1)" would list the stopping device itself).
        continuation = _unevaluated(model, ends or [start], flow.dst,
                                    evaluated | {flow.src} | (set() if ends else {start}))
        if continuation:
            context = tuple(sorted(evaluated))  # opposite directions evaluate different routers
            entry = group(("link", link.id, context) if link else ("device", start, context))
            entry["flows"].add(flow.key)  # names need not be unique
            entry["devices"].update(continuation)
            entry["evaluated"].update(evaluated)
    names = lambda ids: ", ".join(sorted(model.device(node).name for node in ids))
    notes = []
    for (kind, ref, *_), entry in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2:])):
        count = f"{len(entry['flows'])} required flow(s)"
        tail = "Additional faults may be masked; re-run analysis after correcting this fault."
        if kind == "acl":
            notes.append(f"{count} stop at {model.device(ref).name}; forwarding was evaluated end to end, but policy checks "
                         f"at devices beyond that point ({names(entry['devices'])}) were not evaluated. {tail}")
        elif kind == "source":
            notes.append(f"{count} cannot leave {model.device(ref).name}'s access segment; forwarding and policy checks "
                         f"at devices beyond that point ({names(entry['devices'])}) were not evaluated. {tail}")
        else:
            where = (f"the {model.device(model.links[ref].a_dev).name}–{model.device(model.links[ref].b_dev).name} link"
                     if kind == "link" else model.device(ref).name)
            done = (f" Forwarding through {names(entry['evaluated'])} was evaluated; policy checks on those devices were not reached."
                    if entry["evaluated"] else "")
            notes.append(f"{count} stop at {where}; forwarding and policy checks at devices beyond that point "
                         f"({names(entry['devices'])}) were not evaluated.{done} {tail}")
    return notes
