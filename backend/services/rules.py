"""Validation rule catalogue (brief section 6.3 / 6.4).

Each rule is data: ID, name, condition, severity, impact type, recommendation
and its heuristic risk weights for the four 25-point dimensions (brief 7.2).
Weights are prototype heuristics, to be calibrated in the Final evaluation.
"""
from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_FLOOR = {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 80}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str  # base severity
    escalates: bool  # "Medium/High": escalates to HIGH when a required flow breaks
    condition: str
    impact_type: str
    recommendation: str
    consequence: str
    weights: tuple[int, int, int, int]  # configuration, connectivity, protocol, service

    @property
    def severity_label(self) -> str:
        return "MEDIUM/HIGH" if self.escalates else self.severity

    @property
    def issue_code(self) -> str:
        return self.name.upper().replace(" ", "_").replace("-", "_")


RULES: dict[str, Rule] = {r.id: r for r in [
    Rule("OSPF001", "OSPF Area Mismatch", "routing", "HIGH", False,
         "Connected OSPF interfaces use different areas",
         "routing_adjacency", "Verify and align the OSPF area configuration",
         "This creates an OSPF area mismatch and may prevent {a_dev} and {b_dev} from forming an OSPF adjacency.",
         (18, 20, 25, 15)),
    Rule("OSPF002", "Missing OSPF Configuration", "routing", "MEDIUM", True,
         "OSPF is enabled on only one side of a routed link, or a destination network is not advertised into OSPF",
         "routing_adjacency", "Enable OSPF consistently on both sides and advertise all required networks",
         "Without matching OSPF configuration the routers cannot exchange routes for this network.",
         (15, 18, 20, 12)),
    Rule("ACL001", "Required Flow Denied", "acl", "CRITICAL", False,
         "A required flow (allow intent) is denied by an ACL on its path",
         "service_flow", "Permit the required flow before any broader deny, or narrow the deny rule",
         "The required business service is denied by policy.",
         (15, 25, 22, 25)),
    Rule("ACL002", "Unexpected Permissive Rule", "acl", "HIGH", False,
         "A permit rule allows traffic that must stay isolated, or a permit-any rule shadows existing deny rules",
         "security_policy", "Restrict the permit rule or place it after the deny rules it overrides",
         "This weakens the intended isolation and security policy.",
         (15, 10, 22, 18)),
    Rule("IP001", "Subnet Mismatch", "ip_interface", "HIGH", False,
         "Directly connected interfaces, or a host and its gateway interface, are in different subnets",
         "connectivity", "Correct the IP address or mask so both ends are in the same subnet",
         "Devices in different subnets cannot communicate directly over this connection.",
         (20, 20, 10, 15)),
    Rule("IP002", "Gateway Mismatch", "ip_interface", "HIGH", False,
         "A host default gateway is outside its subnet or not configured on any router serving its segment",
         "gateway_reachability", "Align the host default gateway with the router interface serving its VLAN",
         "The host can no longer reach its default gateway or any other network.",
         (20, 20, 8, 15)),
    Rule("IP003", "Duplicate IP", "ip_interface", "HIGH", False,
         "The same IP address is configured on more than one interface",
         "address_conflict", "Assign a unique IP address to each interface",
         "Duplicate addresses cause ARP conflicts and unpredictable forwarding.",
         (22, 18, 8, 15)),
    Rule("VLAN001", "Access VLAN Mismatch", "vlan", "MEDIUM", True,
         "A host is placed in an access VLAN that does not match its IP subnet",
         "l2_segmentation", "Assign the port to the VLAN that matches the host subnet",
         "The host is moved into the wrong broadcast domain and loses its default gateway.",
         (15, 18, 12, 15)),
    Rule("VLAN002", "VLAN Unavailable", "vlan", "HIGH", False,
         "An access port uses a VLAN that is not defined on the switch",
         "l2_segmentation", "Create the VLAN on the switch (and trunks) before assigning ports to it",
         "Traffic on this port cannot be forwarded until the VLAN exists.",
         (18, 20, 12, 15)),
    Rule("ROUTE001", "Invalid Next Hop", "routing", "HIGH", False,
         "A static route next hop is not in a connected subnet or not owned by a directly connected neighbour",
         "routing_path", "Use the IP address of a directly connected neighbour as the next hop",
         "Traffic matching this route cannot be forwarded.",
         (18, 20, 15, 12)),
    Rule("ROUTE002", "Missing Destination Route", "routing", "HIGH", False,
         "A router on a required path has no route to the destination network",
         "routing_path", "Add a static route or advertise the destination network in OSPF",
         "Traffic to this destination is dropped at that router.",
         (15, 22, 15, 15)),
    Rule("LINK001", "Active Link Disabled", "ip_interface", "MEDIUM", True,
         "An interface carrying a topology link is shut down (NetGuard extension rule)",
         "connectivity", "Confirm an alternative path exists or schedule the shutdown in a maintenance window",
         "Traffic that used this link is interrupted unless an alternative path exists.",
         (10, 22, 10, 15)),
    Rule("L2001", "Forwarding Loop", "vlan", "HIGH", False,
         "A VLAN has a cycle of explicitly forwarding switch ports without a blocking STP port",
         "l2_loop", "Verify the redundant cable and enable STP; isolate one redundant link after review",
         "A forwarding cycle can recirculate broadcast frames and destabilise MAC learning.", (15, 22, 20, 15)),
    Rule("VLAN003", "Trunk VLAN Mismatch", "vlan", "HIGH", False,
         "Connected trunk ports have conflicting native VLANs or allowed VLAN lists",
         "l2_segmentation", "Align both trunk ends with the approved VLAN design",
         "The trunk can drop a VLAN or place untagged traffic in the wrong broadcast domain.", (15, 20, 15, 15)),
    Rule("LINK002", "Expected Connection Missing", "ip_interface", "HIGH", False,
         "An approved expected connection is absent from the observed topology",
         "connectivity", "Check both interfaces and the expected cable; confirm with LLDP or a physical inspection",
         "The intended path cannot be confirmed from the available connection evidence.", (10, 20, 8, 12)),
    Rule("PHY001", "Cable Media Mismatch", "ip_interface", "HIGH", False,
         "A cable joins known copper and fibre ports", "connectivity",
         "Use ports with compatible media or an appropriate supported transceiver",
         "The physical link cannot come up with the recorded media.", (15, 22, 0, 15)),
    Rule("PHY002", "Interface Not Present on Hardware Model", "ip_interface", "MEDIUM", False,
         "A linked interface does not exist on its catalogued model", "connectivity",
         "Confirm the model and connect a valid hardware port",
         "The recorded connection cannot be verified against this hardware.", (12, 12, 0, 5)),
    Rule("PHY003", "Link Speed Mismatch", "ip_interface", "MEDIUM", False,
         "Both linked interfaces have different recorded speeds", "connectivity",
         "Confirm negotiation and configure compatible speeds at both ends",
         "The configured port speeds differ and need review.", (10, 12, 0, 5)),
    Rule("OSPF003", "OSPF Timer or MTU Mismatch", "routing", "HIGH", False,
         "Connected OSPF interfaces use different hello/dead intervals or different MTUs",
         "routing_adjacency", "Use the same hello and dead intervals and the same MTU on both OSPF interfaces",
         "The routers never form a full OSPF adjacency, so routes over this link are not exchanged.",
         (16, 20, 25, 15)),
    Rule("ACL003", "Shadowed ACL Rule", "acl", "MEDIUM", False,
         "An ACL entry can never match because an earlier entry with the opposite action covers all of its traffic",
         "security_policy", "Reorder or remove the shadowed entry so the intended action takes effect",
         "The shadowed entry has no effect; the earlier entry decides this traffic.", (12, 8, 15, 10)),
    Rule("ACL004", "Undefined ACL Reference", "acl", "HIGH", False,
         "An interface access-group or line access-class refers to an ACL that is not defined",
         "security_policy", "Define the ACL before applying it, or remove the reference",
         "Cisco IOS permits all traffic through a reference to an undefined ACL, so the intended filter is absent.",
         (15, 10, 18, 15)),
    Rule("PHY004", "Duplex Mismatch", "ip_interface", "MEDIUM", False,
         "Both linked interfaces report different duplex settings", "connectivity",
         "Set both ends to auto-negotiation, or to the same speed and full duplex",
         "A duplex mismatch causes late collisions, errors and very poor throughput.", (10, 15, 0, 10)),
    Rule("PHY005", "Interface Errors", "ip_interface", "MEDIUM", False,
         "An interface carrying a link reports input or output errors in the last collection", "connectivity",
         "Check the cable, transceiver and duplex setting; clear the counters and monitor again",
         "Errors indicate a physical or duplex problem that drops traffic.", (8, 12, 0, 8)),
    Rule("SEC003", "SNMPv1/v2c Community Configured", "advisory", "MEDIUM", False,
         "An SNMP community string is configured (cleartext, no per-user authentication)", "security_hygiene",
         "Remove SNMPv1/v2c communities and use SNMPv3 with authPriv; restrict any remaining community with an ACL",
         "Community strings are sent in cleartext and grant access to anyone who captures them.", (0, 0, 0, 0)),
    Rule("SEC004", "Weak Password Storage", "advisory", "MEDIUM", False,
         "An enable, user or line password is stored in cleartext, type 7 or type 5 (MD5)", "security_hygiene",
         "Use 'enable algorithm-type scrypt secret' and 'username ... algorithm-type scrypt secret' (type 9 or 8)",
         "Type 7 passwords are reversible and type 5 hashes are weak against offline cracking.", (0, 0, 0, 0)),
    Rule("SEC005", "Unrestricted VTY Access", "advisory", "MEDIUM", False,
         "A VTY line has no access-class restricting management sources", "security_hygiene",
         "Apply an access-class that permits only the management network on every VTY line",
         "Any host that reaches the device can attempt to log in to its management lines.", (0, 0, 0, 0)),
    Rule("SEC006", "Unused Access Port Enabled", "advisory", "LOW", False,
         "A switch access port is administratively up but has no link", "security_hygiene",
         "Shut down unused access ports and place them in an unused VLAN",
         "An enabled unused port lets anyone with physical access join the network.", (0, 0, 0, 0)),
    Rule("NAME001", "Non-standard Interface Name", "advisory", "LOW", False,
         "A Cisco interface uses a recognised non-canonical alias", "hygiene",
         "Use the canonical Cisco abbreviated interface name",
         "Consistent names make configuration and neighbour evidence easier to compare.", (0, 0, 0, 0)),
    Rule("SEC001", "Untrusted Devices Share a Segment with Sensitive Assets", "advisory", "MEDIUM", False,
         "Untrusted and sensitive discovered roles share a segment without an isolation intent", "security_hygiene",
         "Separate guest, camera, phone, unknown and AP devices from sensitive assets with reviewed VLANs and isolation policy",
         "The stored segment has no documented isolation intent between these assets.", (0, 0, 0, 0)),
    Rule("SEC002", "Cleartext Management Service Exposed", "advisory", "MEDIUM", False,
         "Telnet or HTTP management is enabled in the configuration or seen by discovery", "security_hygiene",
         "Disable HTTP and Telnet management; use HTTPS and SSH only",
         "Management traffic may use an unencrypted service.", (0, 0, 0, 0)),
]}

CATEGORY_LABELS = {
    "ip_interface": "IP / Interface",
    "routing": "Routing",
    "acl": "ACL",
    "vlan": "VLAN",
    "security": "Security hardening",
    "physical": "Physical",
    "advisory": "Security & hygiene advisories",
}

# The five rule packs of the proposal. Every rule belongs to exactly one pack.
PACKS = {"physical": "Physical", "layer2": "Layer 2", "layer3": "Layer 3", "acl": "ACL and policy",
         "security": "Security hygiene (NSA guidance)"}
_PACK_OF = {
    "LINK001": "physical", "LINK002": "physical", "PHY001": "physical", "PHY002": "physical", "PHY003": "physical",
    "PHY004": "physical", "PHY005": "physical",
    "VLAN001": "layer2", "VLAN002": "layer2", "VLAN003": "layer2", "L2001": "layer2",
    "IP001": "layer3", "IP002": "layer3", "IP003": "layer3", "OSPF001": "layer3", "OSPF002": "layer3",
    "OSPF003": "layer3", "ROUTE001": "layer3", "ROUTE002": "layer3",
    "ACL001": "acl", "ACL002": "acl", "ACL003": "acl", "ACL004": "acl",
}


def pack_of(rule_id: str) -> str:
    return _PACK_OF.get(rule_id, "security")


# Severity factor S of the risk formula (1 = Low ... 4 = Critical).
SEVERITY_FACTOR = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def catalogue() -> list[dict]:
    return [
        {
            "id": r.id, "name": r.name, "category": r.category, "category_label": CATEGORY_LABELS[r.category],
            "severity": r.severity_label, "condition": r.condition, "impact_type": r.impact_type,
            "recommendation": r.recommendation, "pack": pack_of(r.id), "pack_label": PACKS[pack_of(r.id)],
            "severity_factor": SEVERITY_FACTOR[r.severity],
            "weights": dict(zip(("configuration", "connectivity", "protocol", "service"), r.weights)),
        }
        for r in RULES.values()
    ]
