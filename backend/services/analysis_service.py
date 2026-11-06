"""Runs the analysis pipeline for a proposed change (brief 7.1) and stores the result.

Proposed Change -> Change Detector -> Validation Engine -> Topology/Dependency
Analysis -> Impact Engine -> Risk Engine -> Explanation Engine ->
Recommendation Engine -> Analysis Result
"""
from __future__ import annotations

import time
from dataclasses import asdict
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.core.errors import NotFoundError
from backend.models import Assessment, Change, Impact, Network, User
from backend.schemas.change import AssessmentOut, ImpactOut
from backend.services import (
    change_detector,
    cli_generator,
    explanation_engine,
    impact_engine,
    recommendation_engine,
    risk_engine,
    validation_engine,
)
from backend.services.forwarding import FlowAnalyzer
from backend.services.network_model import load_model
from backend.services.rules import CATEGORY_LABELS, RULES, SEVERITY_ORDER
from backend.services.analysis_checks import advisories, coverage_notes


def run_pipeline(db: Session, change: Change, audit: bool = False) -> dict:
    """Pure analysis (no persistence). Returns everything needed for an assessment.

    audit=True uses health-check flow expectations (impact_engine.build_flows), so a fix is
    verified against the same issues the health check reported.
    """
    started = time.perf_counter()
    baseline = load_model(db, change.network_id)
    detected = change_detector.detect(baseline, change.device_id, change.interface_id, change.change_type,
                                      change.parameters)
    candidate = change_detector.apply(baseline, detected)

    base_analyzer = FlowAnalyzer(baseline)
    cand_analyzer = FlowAnalyzer(candidate, baseline=base_analyzer)
    flows = impact_engine.build_flows(baseline, base_analyzer, audit=audit)
    impact_engine.evaluate_candidate(flows, cand_analyzer)

    base_findings = validation_engine.run(baseline, base_analyzer, flows, "baseline")
    cand_findings = validation_engine.run(candidate, cand_analyzer, flows, "candidate")
    new, existing, resolved = validation_engine.diff(base_findings, cand_findings)

    # Fix verification passes a lightweight change without relationships, so load by id.
    network = db.get(Network, change.network_id)
    evidence_incomplete = bool(network and (network.metadata_json or {}).get("configuration_incomplete"))
    impacts = impact_engine.compare(flows, baseline, candidate, evidence_incomplete)
    risk_engine.relate(new, impacts, {d.name: d.id for d in candidate.devices.values()})
    # A finding on a flow that already failed, and now fails further along its path, is not
    # caused by the change: it was hidden behind the problem the change fixes.
    progressed = impact_engine.progressed_flows(flows)
    revealed = [f for f in new if f.related_flows and set(f.related_flows) <= progressed]
    new = [f for f in new if f not in revealed]
    risk = risk_engine.score(new, impacts, detected.effective, candidate)
    new.sort(key=lambda f: (-(f.detail.get("risk") or {}).get("score", 0), -SEVERITY_ORDER[f.severity], f.rule_id))
    primary = risk_engine.primary_finding(new)
    validation_complete = not bool(baseline.observations.get("configuration_incomplete"))
    involved = {change.device_id} | {did for i in impacts if i["status"] != "unchanged" for did in i.get("path_device_ids", [])}
    involved_links = {lid for i in impacts if i["status"] != "unchanged" for lid in i.get("path_link_ids", [])}
    confidence = risk_engine.evidence_confidence(candidate, {d for d in involved if d}, involved_links,
                                                 not validation_complete)
    risk["confidence"] = confidence
    decision = recommendation_engine.recommend(risk["level"], new, detected, primary, impacts, risk["unexplained"])
    code = risk_engine.verdict(risk["level"], new, impacts, risk["unexplained"], confidence)
    decision["recommendation"], decision["label"] = code, recommendation_engine.LABELS[code]
    if code == "DEPLOY_WITH_CAUTION" and risk["level"] == "LOW" and not new:
        decision["summary"] = ("No validation rule failed" + (", but part of the path evidence is only inferred; verify "
                               "the affected paths after the change." if confidence != "HIGH" else
                               "; some flows use a different path. Verify the new paths after the change."))
    if not validation_complete:
        decision = {"recommendation": "DO_NOT_DEPLOY", "label": "Validation incomplete",
                    "summary": "The lab contains a topology layout without a complete configuration baseline. A deployment decision cannot be validated.",
                    "actions": ["Collect or import the device configuration baseline and required service flows.",
                                "Re-run validation after completing the configuration evidence."]}
    ai = {"available": False}
    if not audit:  # fix verification (audit) runs many pipelines; the forecast is for proposed changes
        try:
            from backend.services import ai_engine
            ai = ai_engine.change_insight(baseline, ai_engine.forecast_flows(baseline, base_analyzer, change.network_id),
                                          detected, impacts, new)
        except Exception:  # noqa: BLE001 - the advisory model must never block the deterministic analysis
            ai = {"available": False}
    decision["hybrid"] = risk_engine.hybrid(risk, ai)
    checks = validation_engine.build_checks(new, existing + revealed)
    summary = impact_engine.summarise(impacts, new, baseline)
    explanation = explanation_engine.explain(detected, new, existing, resolved, impacts, risk, decision, checks,
                                             revealed)
    if not validation_complete:
        explanation += "\n\nValidation is incomplete: configuration evidence is missing. No deployment or stored-model apply is approved by this assessment."
    if ai.get("available") and ai.get("summary"):
        explanation += "\n\nAI forecast (advisory): " + ai["summary"]
    return {
        "detected": detected, "risk": risk, "decision": decision, "checks": checks, "impacts": impacts,
        "summary": summary, "explanation": explanation, "primary": primary,
        "validation_complete": validation_complete,
        "advisories": advisories(candidate), "coverage_notes": coverage_notes(candidate, flows, "candidate"),
        "evidence_scope": _evidence_scope(network),
        "findings": [f.to_dict(candidate) for f in new],
        "existing": [f.to_dict(candidate) for f in existing] + [{**f.to_dict(candidate), "revealed": True}
                                                                for f in revealed],
        "revealed": [f.to_dict(candidate) for f in revealed],
        "resolved": [f.to_dict(baseline) for f in resolved],
        "commands": cli_generator.commands_for(baseline, detected),
        "baseline_configuration": {str(d.id): asdict(d) for d in baseline.devices.values()},
        "candidate_configuration": {str(d.id): asdict(d) for d in candidate.devices.values()},
        "configuration_diff": [{"device": detected.device_name, "target": detected.target_name,
                                "current": detected.current_value, "proposed": detected.proposed_value}],
        "ai": ai,
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
    }


def _evidence_scope(network) -> str:
    if network is None:
        return "Stored network model."
    source = {"discovery": "live discovery and collected configurations", "eve-ng": "the EVE-NG lab definition and collected configurations",
              "gns3": "the GNS3 lab definition and collected configurations", "config-import": "imported device configurations",
              "packet-tracer": "the Packet Tracer project", "sample": "the example network"}.get(network.source, "the stored network model")
    return f"Analysis of a copy of the network model built from {source}; nothing is sent to a device."


def analyze_change(db: Session, change: Change, user: User | None) -> Assessment:
    result = run_pipeline(db, change)
    detected, risk, decision, summary = result["detected"], result["risk"], result["decision"], result["summary"]

    change.current_value = detected.current_value
    change.proposed_value = detected.proposed_value
    change.target_name = detected.target_name
    if change.status not in ("applied", "rolled_back", "failed"):  # executed changes keep their status
        change.status = "analyzed"  # re-analysis withdraws a pending or given approval
        change.approved_assessment_id = None

    dims = risk["dimensions"]
    assessment = Assessment(
        change_id=change.id,
        configuration_score=dims["configuration"], connectivity_score=dims["connectivity"],
        protocol_score=dims["protocol"], service_score=dims["service"],
        total_risk_score=risk["total"], risk_level=risk["level"],
        risk_severity=risk["factors"]["S"], risk_impact=risk["factors"]["I"], risk_exposure=risk["factors"]["E"],
        evidence_confidence=risk["confidence"],
        recommendation=decision["recommendation"],
        validation_result="INCOMPLETE" if not result["validation_complete"] else "FAIL" if result["findings"] else "PASS",
        primary_issue=RULES[result["primary"].rule_id].issue_code if result["primary"] else None,
        change_snapshot={
            "device": detected.device_name, "target": detected.target_name,
            "category": detected.category, "category_label": CATEGORY_LABELS[detected.category],
            "change_type": detected.change_type,
            "change_type_label": change_detector.CHANGE_TYPES[detected.change_type]["label"],
            "current_value": detected.current_value, "proposed_value": detected.proposed_value,
            "reason": change.reason, "summary": detected.summary, "effective": detected.effective,
            "commands": result["commands"],
        },
        explanation=result["explanation"], findings=result["findings"], checks=result["checks"],
        actions=decision["actions"], affected_devices=summary["affected_devices"],
        affected_links=summary["affected_link_ids"],
        details={
            "advisories": result["advisories"], "coverage_notes": result["coverage_notes"],
            "evidence_scope": result["evidence_scope"],
            # One entry per impact, in the order Impact rows are created (flow names need not be unique).
            "flow_results": [{key: impact[key] for key in ("expected", "result", "reason")} for impact in result["impacts"]],
            "baseline_configuration": result["baseline_configuration"],
            "candidate_configuration": result["candidate_configuration"],
            "configuration_diff": result["configuration_diff"],
            "recommendation_label": decision["label"], "recommendation_summary": decision["summary"],
            "affected_paths": summary["affected_paths"], "affected_device_ids": summary["affected_device_ids"],
            "existing_issues": result["existing"], "resolved_issues": result["resolved"],
            "counts": {k: summary[k] for k in ("affected_count", "broken_count", "evaluated_count")},
            "ai": {k: v for k, v in (result.get("ai") or {}).items() if k != "features"},
            "hybrid": decision.get("hybrid"),
        },
        analysis_ms=result["elapsed_ms"],
        created_by=user.id if user else None,
    )
    for impact in result["impacts"]:
        assessment.impacts.append(Impact(**{k: impact[k] for k in (
            "service", "source_device", "destination_device", "protocol", "port", "criticality", "impact_type",
            "status", "affected", "baseline_status", "candidate_status", "explanation", "path", "path_device_ids",
            "path_link_ids", "failure_link_id", "failure_device")}))
    db.add(assessment)
    try:
        from backend.services import ai_engine
        ai_engine.record_forecast(db, change, result.get("ai") or {})
    except Exception:  # noqa: BLE001
        pass
    db.commit()
    db.refresh(assessment)
    return assessment


def get_assessment(db: Session, assessment_id: int) -> Assessment:
    assessment = db.scalar(
        select(Assessment).where(Assessment.id == assessment_id)
        .options(selectinload(Assessment.impacts), selectinload(Assessment.change))
    )
    if assessment is None:
        raise NotFoundError(f"Assessment {assessment_id} not found")
    return assessment


def save_assessment(db: Session, assessment_id: int) -> Assessment:
    assessment = get_assessment(db, assessment_id)
    assessment.saved = True
    assessment.saved_at = datetime.now(timezone.utc).replace(tzinfo=None)
    if assessment.change.status in ("draft", "analyzed"):  # saving never alters an approval or execution state
        assessment.change.status = "saved"
    db.commit()
    db.refresh(assessment)
    return assessment


def list_assessments(db: Session, network_id: int | None = None, saved: bool | None = None,
                     change_id: int | None = None, limit: int = 200) -> list[Assessment]:
    query = select(Assessment).join(Change).options(selectinload(Assessment.change).selectinload(Change.network))
    if network_id is not None:
        query = query.where(Change.network_id == network_id)
    if saved is not None:
        query = query.where(Assessment.saved == saved)
    if change_id is not None:
        query = query.where(Assessment.change_id == change_id)
    return list(db.scalars(query.order_by(Assessment.id.desc()).limit(limit)))


def _impact_kind(impact: Impact) -> str:
    if impact.impact_type == "gateway_reachability":
        return "gateway"
    return "intent" if impact.impact_type == "service_flow" else "implicit"


def to_out(assessment: Assessment) -> AssessmentOut:
    change = assessment.change
    details = assessment.details or {}
    impacts = []
    stored_results = details.get("flow_results", [])
    for position, impact in enumerate(assessment.impacts):
        # Lists are aligned with impact order; dicts keyed by flow name come from earlier saved records.
        flow_result = (stored_results[position] if isinstance(stored_results, list) and position < len(stored_results)
                       else stored_results.get(impact.service, {}) if isinstance(stored_results, dict) else {})
        kind = _impact_kind(impact)
        proto = (impact.protocol or "ip").upper() + (f"/{impact.port}" if impact.port else "")
        impacts.append(ImpactOut(
            **flow_result,
            service=impact.service, kind=kind, source_device=impact.source_device,
            destination_device=impact.destination_device, protocol=impact.protocol, port=impact.port,
            protocol_label="gateway" if kind == "gateway" else proto, criticality=impact.criticality,
            impact_type=impact.impact_type, status=impact.status, affected=impact.affected,
            baseline_status=impact.baseline_status, candidate_status=impact.candidate_status,
            explanation=impact.explanation, path=impact.path, path_device_ids=impact.path_device_ids,
            path_link_ids=impact.path_link_ids, failure_link_id=impact.failure_link_id,
            failure_device=impact.failure_device,
        ))
    return AssessmentOut(
        id=assessment.id, change_id=assessment.change_id, network_id=change.network_id,
        network_name=change.network.name if change.network else None,
        change={**(assessment.change_snapshot or {}), "id": change.id, "status": change.status},
        scores={"configuration": assessment.configuration_score, "connectivity": assessment.connectivity_score,
                "protocol": assessment.protocol_score, "service": assessment.service_score},
        risk_factors={"S": assessment.risk_severity, "I": assessment.risk_impact, "E": assessment.risk_exposure}
        if assessment.risk_severity is not None else None,
        evidence_confidence=assessment.evidence_confidence,
        risk_score=assessment.total_risk_score, total_risk_score=assessment.total_risk_score,
        risk_level=assessment.risk_level, issue=assessment.primary_issue,
        recommendation=assessment.recommendation,
        recommendation_label=details.get("recommendation_label", assessment.recommendation),
        recommendation_summary=details.get("recommendation_summary", ""),
        validation_result=assessment.validation_result, explanation=assessment.explanation,
        findings=assessment.findings, checks=assessment.checks, actions=assessment.actions,
        advisories=details.get("advisories", []), coverage_notes=details.get("coverage_notes", []),
        evidence_scope=details.get("evidence_scope", "Stored network model."),
        affected_devices=assessment.affected_devices,
        affected_device_ids=details.get("affected_device_ids", []),
        affected_links=assessment.affected_links,
        affected_paths=details.get("affected_paths", []),
        existing_issues=details.get("existing_issues", []), resolved_issues=details.get("resolved_issues", []),
        baseline_configuration=details.get("baseline_configuration", {}),
        candidate_configuration=details.get("candidate_configuration", {}),
        configuration_diff=details.get("configuration_diff", []),
        counts=details.get("counts", {}), impacts=impacts, saved=assessment.saved, saved_at=assessment.saved_at,
        created_at=assessment.created_at,
        created_by_username=assessment.creator.username if assessment.creator else None,
        analysis_ms=assessment.analysis_ms, ai=details.get("ai") or {}, hybrid=details.get("hybrid") or {},
    )
