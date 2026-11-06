"""Recommendation Engine: deploy decision and suggested actions (brief 7.6)."""
from __future__ import annotations

from backend.services.rules import RULES

# What to review, per rule (brief 7.6: "Review the OSPF area configuration before ...").
REVIEW_SUBJECT = {
    "OSPF001": "OSPF area configuration", "OSPF002": "OSPF configuration", "ACL001": "ACL change",
    "ACL002": "ACL change", "IP001": "IP addressing", "IP002": "default gateway configuration",
    "IP003": "IP addressing", "VLAN001": "VLAN assignment", "VLAN002": "VLAN configuration",
    "ROUTE001": "static route", "ROUTE002": "routing for the affected destinations", "LINK001": "interface shutdown",
    "OSPF003": "OSPF timers and MTU", "ACL003": "ACL entry order", "ACL004": "ACL references",
    "PHY004": "duplex settings", "PHY005": "physical link",
}

LABELS = {"DEPLOY": "Deploy", "DEPLOY_WITH_CAUTION": "Deploy with caution", "DO_NOT_DEPLOY": "Do not deploy"}

DECISIONS = {
    "LOW": ("DEPLOY", "Deploy"),
    "MEDIUM": ("DEPLOY_WITH_CAUTION", "Deploy with caution"),
    "HIGH": ("DO_NOT_DEPLOY", "Do not deploy"),
    "CRITICAL": ("DO_NOT_DEPLOY", "Do not deploy"),
}


def _actions_for(finding, change) -> list[str]:
    d = finding.detail
    rid = finding.rule_id
    if rid == "OSPF001":
        changed_a = change.device_name == d["a_dev"] and change.target_name == d["a_if"]
        new_area, other_area = (d["a_area"], d["b_area"]) if changed_a else (d["b_area"], d["a_area"])
        return [f"Keep both interfaces in Area {other_area}, or",
                f"Update both {d['a_dev']} and {d['b_dev']} consistently if migration to Area {new_area} is intended."]
    if rid == "OSPF002":
        if "network" in d:
            return [f"Advertise {d['network']} into OSPF on {d['router']} {d['interface']}, or add static routes to it."]
        return [f"Enable OSPF on both {d['a_dev']} {d['a_if']} and {d['b_dev']} {d['b_if']} in the same area, "
                f"or remove OSPF from both and route statically."]
    if rid == "ACL001":
        if d.get("rule"):
            return [f"Add a permit rule for {d['flow']} before '{d['rule']}' on {d['device']}, or narrow the deny rule."]
        return [f"Add an explicit permit for required traffic on {d['device']}; an ACL ends with an implicit deny."]
    if rid == "ACL002":
        if "flow" in d:
            target = f" on {d['device']}" if d.get("device") else ""
            return [f"Restrict the permit rule{target} so that '{d['flow']}' stays isolated."]
        return [f"Move '{d['rule']}' on {d['device']} after the deny rules, or replace it with specific permits."]
    if rid == "IP001":
        if finding.subject.startswith("overlap:"):
            return [f"Re-address {d['device']} {d['interface']} so it does not overlap the subnet of {d['destination']}."]
        if "host_cidr" in d:
            return [f"Re-address {d['router']} {d['interface']} or the host so both are in the same subnet "
                    f"({d['host_cidr']} vs {d['router_cidr']})."]
        return [f"Use addresses in the same subnet on both ends ({d['a_cidr']} vs {d['b_cidr']})."]
    if rid == "IP002":
        if d.get("reason") == "missing":
            return [f"Set the default gateway of the host to {d['router_cidr'].split('/')[0]} "
                    f"({d['router']} {d['interface']})."]
        if d.get("owner") and not d.get("router_cidr"):
            vlan = f"VLAN {d['vlan']}" if d.get("vlan") else "the host's segment"
            return [f"Make sure {vlan} reaches {d['owner']}: check the switch ports and trunks between the host "
                    f"and that interface."]
        if d.get("router_cidr"):
            gateway_ip = d["router_cidr"].split("/")[0]
            return [f"Keep {d['gateway']} on {d['router']} {d['interface']}, or update the hosts' default gateway "
                    f"to {gateway_ip}."]
        return [f"Set a default gateway inside {d['host_cidr']} that a router in the segment owns."]
    if rid == "IP003":
        return [f"Assign a unique address: {d['ip']} is already in use."]
    if rid == "VLAN001":
        return [f"Keep {d['switch']} {d['port']} in VLAN {d['expected_vlan']}, or re-address the host for VLAN {d['vlan']}."]
    if rid == "VLAN002":
        return [f"Create VLAN {d['vlan']} on {d['switch']} (and on its trunks) before assigning {d['port']} to it."]
    if rid == "ROUTE001":
        return [f"Use a directly connected neighbour's address as the next hop for {d['destination']} on {d['device']}."]
    if rid == "ROUTE002":
        if d.get("loop"):
            return [f"Correct the routes on {d['device']} so traffic for {d['destination']} does not loop ({d['loop']})."]
        return [f"Add a route to {d['destination']} on {d['device']}, or advertise the destination network in OSPF."]
    if rid == "OSPF003":
        if d.get("kind") == "mtu_mismatch":
            return [f"Set the same MTU on {d['a_dev']} {d['a_if']} and {d['b_dev']} {d['b_if']} ({d.get('a_mtu')} vs {d.get('b_mtu')})."]
        return [f"Use the same OSPF hello/dead intervals on {d['a_dev']} {d['a_if']} ({d.get('a_hello')}/{d.get('a_dead')} s) "
                f"and {d['b_dev']} {d['b_if']} ({d.get('b_hello')}/{d.get('b_dead')} s)."]
    if rid == "ACL003":
        return [f"On {d['device']}, move '{d['rule']}' before '{d['earlier']}', or remove it if it is not needed."]
    if rid == "ACL004":
        return [f"Define ACL {d['acl']} on {d['device']} or remove the reference on {d['where']}."]
    if rid == "LINK001":
        return [f"Confirm an alternative path exists before shutting {d['device']} {d['interface']}, "
                f"or schedule the change in a maintenance window."]
    return [RULES[rid].recommendation]


def recommend(level: str, findings: list, change, primary, impacts: list[dict] | None = None,
              unexplained: list[str] | None = None) -> dict:
    code, label = DECISIONS[level]
    statuses = {i["status"] for i in impacts or []}
    actions: list[str] = []
    for finding in findings:
        for action in _actions_for(finding, change):
            if action not in actions:
                actions.append(action)
    if unexplained:
        actions.append(f"Investigate why these flows break: {', '.join(unexplained)}.")
    if findings:
        summary = f"Review the {REVIEW_SUBJECT.get(primary.rule_id, 'configuration')} before implementing this change."
        actions.append("Re-run the NetGuard analysis after correcting the change.")
    elif unexplained:
        summary = "Required traffic would break. Do not deploy until the affected flows are understood."
        actions.append("Re-run the NetGuard analysis after correcting the change.")
    elif level == "LOW" and "rerouted" in statuses:
        summary = ("No validation rule failed. Some flows keep working over a different path; "
                   "the change can proceed with a check of the new paths.")
        actions = ["Proceed through the normal change-approval process.",
                   "Verify the rerouted flows after deployment and keep a rollback point."]
    elif level == "LOW":
        summary = "No validation rule failed and no evaluated flow is affected. The change can proceed."
        actions = ["Proceed through the normal change-approval process.",
                   "Keep the current configuration as a rollback point and verify after deployment."]
    else:
        summary = "No rule failed, but traffic behaviour changes. Verify the new behaviour before deployment."
        actions = ["Review the affected paths listed below.", "Deploy in a maintenance window with a rollback plan."]
    return {"recommendation": code, "label": label, "summary": summary, "actions": actions}
