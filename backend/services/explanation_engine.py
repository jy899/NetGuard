"""Explanation Engine: deterministic, template-based explanations (brief 7.5).

No LLM is used. The output is a short sequence of paragraphs:
what changed -> what NetGuard found -> what it affects -> the conclusion.
"""
from __future__ import annotations

from backend.services.rules import RULES


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def explain(change, findings: list, existing: list, resolved: list, impacts: list[dict], risk: dict,
            decision: dict, checks: list[dict], revealed: list | None = None) -> str:
    paragraphs = [change.summary]
    if not change.effective:
        paragraphs.append("The proposed value is identical to the current configuration, so the change "
                          "introduces no configuration difference.")

    for finding in findings:
        rule = RULES[finding.rule_id]
        try:
            consequence = rule.consequence.format(**finding.detail)
        except (KeyError, IndexError):
            consequence = rule.consequence.split("{")[0].strip() or rule.recommendation
        paragraphs.append(f"[{rule.id} {rule.name}] {finding.message} {consequence}")

    broken = [i for i in impacts if i["status"] == "broken" and i["kind"] != "gateway"]
    violations = [i for i in impacts if i["status"] == "violation"]
    gateways = [i for i in impacts if i["status"] == "broken" and i["kind"] == "gateway"]
    rerouted = [i for i in impacts if i["status"] == "rerouted"]
    restored = [i for i in impacts if i["status"] == "restored" and i["expected"] != "deny"]
    isolated = [i for i in impacts if i["status"] == "restored" and i["expected"] == "deny"]
    evaluated = len([i for i in impacts if i["kind"] != "gateway"])

    impact_sentences = []
    if broken:
        labels = [f"{i['source_device']} → {i['destination_device']} ({i['protocol_label']})" for i in broken]
        impact_sentences.append(f"As a result, {len(broken)} of {evaluated} evaluated flows would fail: {_join(labels)}.")
    if gateways:
        impact_sentences.append(f"{_join([i['source_device'] for i in gateways])} would lose reachability to "
                                f"{'its' if len(gateways) == 1 else 'their'} default gateway.")
    if violations:
        impact_sentences.append("Isolation would be broken for: "
                                f"{_join([i['service'] for i in violations])}.")
    if rerouted:
        impact_sentences.append(f"{len(rerouted)} flow(s) keep working over a different path.")
    if restored:
        impact_sentences.append(f"{len(restored)} flow(s) that fail today would start working.")
    if isolated:
        impact_sentences.append("Required isolation would be restored for: "
                                f"{_join([i['service'] for i in isolated])}.")
    if risk.get("unexplained"):
        impact_sentences.append("No validation rule identifies the cause of every failure, so the broken flows "
                                "themselves set the risk.")
    if impact_sentences:
        paragraphs.append(" ".join(impact_sentences))
    else:
        paragraphs.append(f"All {evaluated} evaluated flows and every host's gateway reachability keep their "
                          f"current behaviour.")

    if not findings:
        passed = len([c for c in checks if c["status"] == "passed"])
        paragraphs.append(f"All {len(checks)} validation rules were evaluated: {passed} passed and none failed "
                          f"because of this change.")
    if resolved:
        paragraphs.append("The change also resolves an existing issue: "
                          f"{_join([RULES[f.rule_id].name for f in resolved])}.")
    if revealed:
        paragraphs.append("The affected flows already failed before this change; with the change they get further and "
                          "now stop at a second, pre-existing problem: "
                          f"{_join([f'{f.rule_id} {RULES[f.rule_id].name}' for f in revealed])}. "
                          "It is not caused by this change and is listed as a warning.")
    if existing:
        paragraphs.append(f"{len(existing)} pre-existing issue(s) were found in the current network; they are "
                          f"not caused by this change and are listed as warnings.")

    factors = risk.get("factors")
    formula = (f" Score = 100 x S x (1 + I + E) / 24 with S={factors['S']}, I={factors['I']}, E={factors['E']}."
               if factors else "")
    confidence = f" Evidence confidence: {risk['confidence'].title()}." if risk.get("confidence") else ""
    paragraphs.append(f"Overall risk is {risk['level']} ({risk['total']}/100).{formula}{confidence} "
                      f"Recommendation: {decision['label'].upper()}.")
    return "\n\n".join(paragraphs)
