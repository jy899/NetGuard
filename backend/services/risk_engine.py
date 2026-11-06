"""Transparent, rule-based risk scoring (proposal section 5.1).

    Score = 100 x S x (1 + I + E) / 24

S  severity of the finding, 1 (Low) to 4 (Critical), from the rule catalogue (escalating rules become High when
   they break a required flow).
I  intent impact, 0 to 3: 0 no declared or implicit flow affected; 1 implicit flows or low/medium intents;
   2 a high-criticality intent; 3 a critical intent, or a prohibited flow that becomes permitted.
E  exposure to untrusted segments, 0 to 2: 0 internal only; 1 a security-boundary device (firewall, internet edge),
   an ACL/policy finding or a broken flow to or from an untrusted endpoint; 2 the finding sits in an untrusted
   segment (internet, or a workspace subnet marked untrusted), or a prohibited flow from one becomes permitted.

Bands: Low < 25, Medium 25 to < 50, High 50 to < 75, Critical >= 75. A change is scored by its worst new finding.
The verdict is Do not deploy for a High or Critical score, any new High or Critical finding or any newly broken
flow; Deploy with caution for a Medium score, a new Medium or Low finding, rerouted flows or Low evidence
confidence; otherwise Deploy. It carries an evidence-confidence rating (High, Medium, Low).
The weights are fixed and documented; no trained machine-learning model is involved.
"""
from __future__ import annotations

import ipaddress

from backend.services.rules import RULES, SEVERITY_FACTOR, SEVERITY_ORDER

DIMENSIONS = ("configuration", "connectivity", "protocol", "service")  # legacy assessment columns (kept at 0)
CRITICALITY_IMPACT = {"low": 1, "medium": 1, "high": 2, "critical": 3}


def formula(s: int, i: int, e: int) -> int:
    return round(100 * s * (1 + i + e) / 24)


def level_for(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _broken(impacts: list[dict]) -> list[dict]:
    return [i for i in impacts if i["status"] in ("broken", "violation")]


def relate(findings: list, impacts: list[dict], device_id_by_name: dict[str, int]) -> None:
    """Attach the flows each finding breaks (by failure link/device or explicit relation)."""
    for finding in findings:
        related = set(finding.related_flows)
        for impact in _broken(impacts):
            fail_dev = device_id_by_name.get(impact["failure_device"]) if impact["failure_device"] else None
            if impact["failure_link_id"] and impact["failure_link_id"] in finding.link_ids:
                related.add(impact["service"])
            elif finding.subject.startswith("link:"):
                continue  # a finding about one link only breaks flows that fail on that link
            elif fail_dev is not None and fail_dev in finding.device_ids and finding.rule_id not in ("ACL001", "ACL002"):
                related.add(impact["service"])
        finding.related_flows = sorted(related)


def _untrusted_networks(model) -> list[ipaddress.IPv4Network]:
    scope = (model.observations or {}).get("scope", {}) if model is not None else {}
    nets = []
    for value in scope.get("untrusted", []) or []:
        try:
            nets.append(ipaddress.IPv4Network(value, strict=False))
        except ValueError:
            continue
    return nets


def _device_untrusted(model, device_id: int, nets) -> bool:
    dev = model.devices.get(device_id) if model is not None else None
    if dev is None:
        return False
    if dev.type == "internet":
        return True
    for iface in dev.interfaces.values():
        if iface.ip and any(ipaddress.IPv4Address(iface.ip) in net for net in nets):
            return True
    return False


def _edge(model, device_id: int) -> bool:
    dev = model.devices.get(device_id) if model is not None else None
    if dev is None:
        return False
    if dev.type == "firewall":
        return True
    return any(model.devices.get(link.other(device_id)[0]) is not None and
               model.devices[link.other(device_id)[0]].type == "internet" for link in model.links_of(device_id))


def intent_impact(flows: list[dict]) -> int:
    value = 0
    for flow in flows:
        if flow["status"] == "violation":
            value = max(value, 3 if (flow.get("criticality") or "medium") in ("high", "critical") else 2)
        elif flow["status"] == "broken":
            value = max(value, CRITICALITY_IMPACT.get(flow.get("criticality") or "", 1)
                        if flow.get("impact_type") == "service_flow" else 1)
    return value


def exposure(model, device_ids: list[int], flows: list[dict], rule_id: str | None, name_to_id: dict[str, int]) -> int:
    """2: the finding sits in an untrusted segment, or lets an untrusted endpoint reach a prohibited destination.
    1: a security-boundary device or ACL/policy finding, or a broken flow to or from an untrusted endpoint.
    0: internal only."""
    nets = _untrusted_networks(model)
    if any(_device_untrusted(model, did, nets) for did in device_ids):
        return 2
    for flow in flows:
        ends = [name_to_id.get(flow.get("source_device")), name_to_id.get(flow.get("destination_device"))]
        if flow["status"] == "violation" and any(did is not None and _device_untrusted(model, did, nets) for did in ends):
            return 2
    if any(_edge(model, did) for did in device_ids) or (rule_id and RULES[rule_id].category == "acl"):
        return 1
    for flow in flows:
        ends = [name_to_id.get(flow.get("source_device")), name_to_id.get(flow.get("destination_device"))]
        if any(did is not None and _device_untrusted(model, did, nets) for did in ends):
            return 1
    return 0


def score_finding(finding, impacts: list[dict], model, name_to_id: dict[str, int]) -> dict:
    rule = RULES[finding.rule_id]
    related = [i for i in _broken(impacts) if i["service"] in set(finding.related_flows)]
    finding.severity = "HIGH" if (rule.escalates and related) else rule.severity
    s = SEVERITY_FACTOR[finding.severity]
    i = intent_impact(related)
    e = exposure(model, finding.device_ids, related, finding.rule_id, name_to_id)
    value = formula(s, i, e)
    finding.detail["risk"] = {"S": s, "I": i, "E": e, "score": value, "level": level_for(value)}
    return finding.detail["risk"]


def score(findings: list, impacts: list[dict], effective: bool, model=None) -> dict:
    name_to_id = {d.name: d.id for d in model.devices.values()} if model is not None else {}
    worst = {"S": 0, "I": 0, "E": 0, "score": 0}
    top_severity = "LOW"
    for finding in findings:
        result = score_finding(finding, impacts, model, name_to_id)
        if result["score"] > worst["score"]:
            worst = dict(result)
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[top_severity]:
            top_severity = finding.severity
    # Safety net: a broken required flow that no rule explains still counts as a High-severity problem.
    explained = {name for f in findings for name in f.related_flows}
    unexplained = [i for i in _broken(impacts) if i["service"] not in explained]
    if unexplained:
        s, i = SEVERITY_FACTOR["HIGH"], intent_impact(unexplained)
        e = exposure(model, [], unexplained, None, name_to_id)
        if formula(s, i, e) > worst["score"]:
            worst = {"S": s, "I": i, "E": e, "score": formula(s, i, e)}
        if SEVERITY_ORDER[top_severity] < SEVERITY_ORDER["HIGH"]:
            top_severity = "HIGH"
    if not findings and not unexplained and effective:
        worst = {"S": 1, "I": 0, "E": 0, "score": formula(1, 0, 0)}  # the residual risk of any change
    total = min(worst["score"], 100)
    return {"dimensions": dict.fromkeys(DIMENSIONS, 0), "total": total, "level": level_for(total),
            "top_severity": top_severity, "unexplained": [i["service"] for i in unexplained],
            "factors": {"S": worst["S"], "I": worst["I"], "E": worst["E"]},
            "formula": f"100 x {worst['S']} x (1 + {worst['I']} + {worst['E']}) / 24 = {total}"}


def evidence_confidence(model, device_ids: set[int], link_ids: set[int], incomplete: bool) -> str:
    """High: configuration evidence for every involved device and Confirmed/Manual links. Medium: some links are
    only Inferred or Logical. Low: configuration evidence is missing for an involved device."""
    if incomplete:
        return "LOW"
    for did in device_ids:
        dev = model.devices.get(did)
        if dev is not None and dev.type in ("router", "switch", "firewall") and not dev.interfaces:
            return "LOW"
    discovery = (model.observations or {}).get("discovery", {})
    for did in device_ids:
        facts = discovery.get(str(did))
        dev = model.devices.get(did)
        if facts and dev is not None and dev.type in ("router", "switch") and facts.get("auth") != "success" and not dev.facts:
            return "LOW"
    grades = set()
    for lid in link_ids:
        link = model.links.get(lid)
        if link is None:
            continue
        grade = (link.observation or {}).get("grade")
        if grade is None:
            grade = "Inferred" if link.kind in ("mac", "inferred") else "Logical" if link.kind in ("subnet", "logical") else "Confirmed"
        grades.add(grade)
    return "MEDIUM" if grades & {"Inferred", "Logical", "Unknown"} else "HIGH"


def verdict(level: str, findings: list, impacts: list[dict], unexplained: list[str], confidence: str) -> str:
    breaks_traffic = any(i["status"] in ("broken", "violation") for i in impacts)
    severe = any((f.severity or RULES[f.rule_id].severity) in ("HIGH", "CRITICAL") for f in findings)
    if level in ("HIGH", "CRITICAL") or unexplained or severe or (findings and breaks_traffic):
        return "DO_NOT_DEPLOY"
    statuses = {i["status"] for i in impacts}
    if level == "MEDIUM" or findings or "rerouted" in statuses or confidence == "LOW":
        return "DEPLOY_WITH_CAUTION"
    return "DEPLOY"


def primary_finding(findings: list):
    if not findings:
        return None
    return max(findings, key=lambda f: ((f.detail.get("risk") or {}).get("score", 0),
                                        SEVERITY_ORDER[f.severity or RULES[f.rule_id].severity]))


def hybrid(risk: dict, ai: dict | None) -> dict:
    """Hybrid risk: the deterministic score blended with the AI harm probability. The model can raise the score
    (changes like this one often break things the simulation does not model) but never lowers it below the
    deterministic score: a rule violation or a broken simulated flow is never talked down by a prediction."""
    deterministic = int(risk.get("total") or 0)
    if not ai or not ai.get("available"):
        return {"score": deterministic, "level": level_for(deterministic), "deterministic": deterministic,
                "ai_probability": None, "basis": "rules and simulation only (no AI forecast)"}
    p = float(ai.get("harm_probability") or 0.0)
    blended = round(0.65 * deterministic + 0.35 * p * 100)
    score = max(deterministic, min(blended, 100))
    raised = score > deterministic
    return {"score": score, "level": level_for(score), "deterministic": deterministic, "ai_probability": round(p, 3),
            "basis": (f"0.65 x rules {deterministic} + 0.35 x AI {p:.0%}, floored at the rules score" +
                      (" — the AI forecast raised the risk" if raised else "")),
            "second_review": bool(p >= 0.66 and ai.get("agreement") == "model_higher")}
