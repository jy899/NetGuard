"""Other subnets (VLANs) that a scan can reach: found on devices already read, then swept like the first range.

ARP and LLDP/CDP stop at a router, so a scan of one subnet never sees hosts in another VLAN on its own. NetGuard
therefore asks the routers and layer 3 switches it has read which subnets they are attached to (interface
addresses in the collected configuration, the SNMP IPv4 address table and routed destinations) and sweeps each of
those subnets too. A subnet is swept only when it lies inside the authorised scope, or when the engineer allowed
following neighbours into private (RFC 1918) address space; excluded ranges are never contacted.
"""
from __future__ import annotations

import ipaddress
import re

MIN_PREFIX = 22          # a discovered subnet larger than a /22 is reported, not swept
TRAVERSE_MIN_PREFIX = 16  # the widest routed scope an engineer may authorise for segment traversal
GATEWAY_HOSTS = (1, 254)  # where a segment's router address usually sits (.1 or .254 of a /24)
MAX_SUBNETS = 16         # per crawl
MAX_ADDRESSES = 4096     # per crawl
PRIVATE_NETS = [ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

_INTERFACE = re.compile(r"^\s*(?:interface|edit|set interfaces)\s+\"?([^\"\s]+(?:\s?\d[\w/.:-]*)?)\"?", re.I)
_ADDRESS = re.compile(
    r"^\s*(?:ip(?:v4)? address|ip addr|set ip|(?:add\s+)?address(?:=|\s)|set interfaces\s.*?family inet address)"
    r"\s*(\d{1,3}(?:\.\d{1,3}){3})"
    r"(?:/(\d{1,2})|\s+(\d{1,3}(?:\.\d{1,3}){3}))", re.I)


def _network(ip: str, mask) -> ipaddress.IPv4Network | None:
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    except (ValueError, TypeError):
        return None
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified or net.prefixlen > 30:
        return None
    return net


def from_config(text: str) -> list[dict]:
    """Subnets of the interface addresses in a collected configuration (IOS-like, FRR, NX-OS, Huawei, FortiOS,
    RouterOS and Junos address syntax)."""
    found, current = {}, None
    for line in (text or "").splitlines():
        head = _INTERFACE.match(line)
        if head and not line.lstrip().lower().startswith(("ip ", "set ip")):
            current = head.group(1)
        m = _ADDRESS.match(line)
        if not m:
            continue
        net = _network(m.group(1), m.group(2) or m.group(3))
        if net is not None:
            found.setdefault(str(net), {"cidr": str(net), "interface": current, "ip": m.group(1), "source": "interface"})
    return list(found.values())


def from_addresses(addresses: list[dict]) -> list[dict]:
    """Subnets of an SNMP IPv4 address table (IP-MIB ipAdEntAddr / ipAdEntNetMask)."""
    found = {}
    for row in addresses or []:
        net = _network(row.get("ip"), row.get("mask")) if row.get("mask") else None
        if net is not None:
            found.setdefault(str(net), {"cidr": str(net), "interface": row.get("interface"), "ip": row.get("ip"),
                                        "source": "interface"})
    return list(found.values())


def from_routes(routes: list[dict]) -> list[dict]:
    """Routed destinations (static or learned): subnets behind another router."""
    found = {}
    for row in routes or []:
        net = _network(row.get("destination"), row.get("mask")) if row.get("mask") else None
        if net is not None and net.prefixlen >= 8:
            found.setdefault(str(net), {"cidr": str(net), "interface": None, "ip": row.get("next_hop"), "source": "route"})
    return list(found.values())


def candidates(observations: list[dict]) -> list[dict]:
    """Every subnet reported by an authenticated read, with the device that reported it."""
    out, seen = [], set()
    for o in observations:
        if o.get("technique") == "segment-gateway":
            # Credential-free: a gateway address of this /24 answered inside the authorised traversal scope.
            row = (o.get("facts") or {}).get("segment")
            if row and row["cidr"] not in seen:
                seen.add(row["cidr"])
                out.append({**row, "reported_by": o.get("subject")})
            continue
        if not o.get("authenticated"):
            continue
        facts = o.get("facts") or {}
        rows = (facts.get("subnets", []) if o["technique"] == "connected-subnets" else
                from_addresses(facts.get("addresses")) if o["technique"] == "address-table" else
                from_routes(facts.get("routes")) if o["technique"] == "routing-table" else [])
        for row in rows:
            if row["cidr"] not in seen:
                seen.add(row["cidr"])
                out.append({**row, "reported_by": o.get("observed_by")})
    return out


def plan(found: list[dict], authorised: list[str], excluded: list[str], swept: list[str], follow: bool,
         max_subnets: int = MAX_SUBNETS, max_addresses: int = MAX_ADDRESSES) -> tuple[list[dict], list[dict]]:
    """(subnets to sweep now, subnets left out with the reason). Directly attached subnets come first."""
    allow = [ipaddress.IPv4Network(n, strict=False) for n in authorised]
    deny = [ipaddress.ip_network(n, strict=False) for n in excluded]
    done = [ipaddress.IPv4Network(n, strict=False) for n in swept]
    todo, left, budget = [], [], max_addresses
    for row in sorted(found, key=lambda r: (r["source"] != "interface", r["cidr"])):
        net = ipaddress.IPv4Network(row["cidr"])
        if any(net.subnet_of(d) for d in done) or any(net == ipaddress.IPv4Network(t["cidr"]) for t in todo):
            continue
        inside = any(net.subnet_of(a) for a in allow)
        if row.get("source") in ("gateway-probe", "local") and not inside:
            left.append({**row, "reason": "outside the authorised scope"})  # credential-free rows never follow out
        elif any(net.subnet_of(d) for d in deny if d.version == 4):
            left.append({**row, "reason": "excluded"})
        elif not inside and not (follow and any(net.subnet_of(p) for p in PRIVATE_NETS)):
            left.append({**row, "reason": "outside the authorised scope"})
        elif net.prefixlen < MIN_PREFIX:
            left.append({**row, "reason": f"larger than a /{MIN_PREFIX}; scan it as its own range"})
        elif len(todo) >= max_subnets or net.num_addresses > budget:
            left.append({**row, "reason": "sweep limit reached; run the crawl again"})
        else:
            budget -= net.num_addresses
            todo.append(row)
    return todo, left


def segments_to_probe(scope: str, swept: list[str], excluded: list[str], limit: int = 256) -> dict[str, list[str]]:
    """Each /24 of a wider authorised scope that was not swept yet, with its usual gateway addresses (.1 and .254)."""
    wide = ipaddress.IPv4Network(scope, strict=False)
    done = [ipaddress.IPv4Network(n, strict=False) for n in swept]
    deny = [ipaddress.ip_network(n, strict=False) for n in excluded]
    out = {}
    blocks = [wide] if wide.prefixlen >= 24 else wide.subnets(new_prefix=24)
    for net in blocks:
        if len(out) >= limit:
            break
        if any(net.overlaps(d) for d in done) or any(net.subnet_of(d) for d in deny if d.version == 4):
            continue
        gateways = [str(net.network_address + n) for n in GATEWAY_HOSTS if n < net.num_addresses - 1]
        gateways = [ip for ip in gateways if not any(ipaddress.IPv4Address(ip) in d for d in deny if d.version == 4)]
        if gateways:
            out[str(net)] = gateways
    return out


def hosts(cidr: str) -> list[str]:
    return [str(h) for h in ipaddress.IPv4Network(cidr).hosts()]


def split_targets(text: str | None) -> list[str]:
    """'10.0.10.0/24, 10.0.20.0/24' or one range per line -> the individual ranges, in order."""
    return [part for part in re.split(r"[,;\s]+", (text or "").strip()) if part]
