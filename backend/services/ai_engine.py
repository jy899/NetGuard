"""NetGuard AI: advisory machine-learning components on top of the deterministic analysis.

1. Change Risk & Blast-Radius Predictor - the probability that a proposed change breaks connectivity or introduces
   a high-severity problem, and how many endpoints and flows it is expected to affect, with the factors behind it.
2. Cross-Device Anomaly & Misconfiguration Classifier - link-pair configuration faults (both ends of a cable
   compared), devices that deviate from their peers, interface error outliers and syslog fault categories.
3. Root-Cause Analyzer - ranks the validation findings of a network as causes of its failing flows.
4. Remediation Ranker - the probability that a candidate fix is a true root-cause repair (it returns the network
   to its state before the fault, rather than working around it), used to order fixes within each safety verdict.

The models are trained on synthetic, simulation-labelled data (backend/ai) and on this installation's executed
laboratory changes when retrained. They never decide: verdicts, approval and execution stay deterministic, and
every output is labelled advisory. When the model files are missing the features degrade to empty results.
"""
from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path

from backend.ai import features as F
from backend.ai.ml import GradientBoostedTrees, MultinomialNB, RobustBaseline
from backend.ai.synth import FAULT_LABELS, SYSLOG_CATEGORIES
from backend.core.config import PROJECT_ROOT

MODEL_DIR = PROJECT_ROOT / "data" / "models"
DATASET_DIR = PROJECT_ROOT / "data" / "datasets"
ADVISORY = "Advisory machine-learning estimate; the deterministic analysis and the approval decision are unchanged."


# ------------------------------------------------------------------ loading
@lru_cache(maxsize=1)
def _models() -> dict:
    out = {}
    if not MODEL_DIR.exists():
        return out
    for path in MODEL_DIR.glob("*.json"):
        if path.name == "manifest.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        kind = data.get("type")
        if kind == "gbt":
            out[path.stem] = GradientBoostedTrees.from_dict(data)
        elif kind == "nb":
            out[path.stem] = MultinomialNB.from_dict(data)
        elif kind == "peer":
            out[path.stem] = {role: RobustBaseline.from_dict(v) for role, v in data["roles"].items()}
    return out


def reload() -> None:
    _models.cache_clear()
    _manifest.cache_clear()


@lru_cache(maxsize=1)
def _manifest() -> dict:
    try:
        return json.loads((MODEL_DIR / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def version() -> int:
    return int(_manifest().get("model_version") or 0)


def available() -> bool:
    return "change_risk" in _models()


def status(db=None) -> dict:
    manifest = _manifest()
    out = {"available": available(), "model_version": version(), "models": sorted(_models()),
           "trained_at": manifest.get("trained_at"), "metrics": manifest.get("metrics", {}),
           "evaluation": manifest.get("evaluation"), "dataset": manifest.get("dataset", {}),
           "advisory": ADVISORY}
    if db is not None:
        from sqlalchemy import func, select
        from backend.models import ChangeOutcome
        out["local_outcomes"] = {
            "forecasts": db.scalar(select(func.count(ChangeOutcome.id))) or 0,
            "executed": db.scalar(select(func.count(ChangeOutcome.id)).where(ChangeOutcome.actual_harmful.is_not(None))) or 0}
    return out


# ------------------------------------------------------------------ 1. change risk and blast radius
FACTOR_TEXT = {
    "dev_path_share": lambda v, c: f"{c['device']} lies on {v:.0%} of the evaluated flow paths",
    "iface_path_share": lambda v, c: f"{c['target'] or 'the interface'} carries {v:.0%} of the evaluated flow paths",
    "iface_link_is_bridge": lambda v, c: "the link is the only path between two parts of the network" if v
    else "an alternative path exists around this link",
    "dev_is_cut_vertex": lambda v, c: f"{c['device']} is a single point of failure" if v
    else f"the network stays connected without {c['device']}",
    "dev_critical_paths": lambda v, c: f"{int(v)} critical or high-priority flows cross {c['device']}",
    "iface_down_proposed": lambda v, c: "the change shuts an interface down" if v else "no interface is shut down",
    "iface_to_infra": lambda v, c: "the interface is an infrastructure uplink" if v else "the interface is not an uplink",
    "iface_to_host": lambda v, c: "the interface connects an end host" if v else "the interface does not face a host",
    "acl_deny": lambda v, c: "the rule denies traffic" if v else "the rule permits traffic",
    "acl_breadth": lambda v, c: "the rule matches a broad address range" if v >= 0.6 else "the rule is narrowly scoped",
    "acl_position": lambda v, c: f"the rule is evaluated before {v:.0%} of the existing entries",
    "acl_any_protocol": lambda v, c: "the rule matches every IP protocol" if v else "the rule matches one protocol",
    "net_redundancy": lambda v, c: f"{v:.0%} of the infrastructure devices have more than one uplink",
    "dev_infra_degree": lambda v, c: f"{c['device']} connects to {int(v)} infrastructure neighbour(s)",
    "route_default": lambda v, c: "the route is a default route" if v else "the route is specific",
    "ospf_leaves_backbone": lambda v, c: "the interface leaves OSPF area 0" if v else "the backbone area is unchanged",
    "effective": lambda v, c: "the change modifies the current configuration" if v else "the proposed value equals the current one",
    "vlan_hosts_on_port": lambda v, c: f"{int(v)} port(s) on {c['device']} share this VLAN",
    "evidence_inferred_share": lambda v, c: f"{v:.0%} of the connections are inferred rather than confirmed",
    "dev_l2_switch": lambda v, c: f"{c['device']} is a Layer-2 switch" if v else f"{c['device']} is not a Layer-2 switch",
    "dev_router": lambda v, c: f"{c['device']} routes between subnets" if v else f"{c['device']} is not a router",
    "dev_host": lambda v, c: f"{c['device']} is an end host" if v else f"{c['device']} is infrastructure",
}


def _factor_text(name: str, value: float, ctx: dict) -> str:
    if name.startswith("type:"):
        return f"{name[5:].replace('_', ' ')} changes" + (" (this change type)" if value else "")
    if name.startswith("category:"):
        return f"{name[9:].replace('_', ' / ')} category"
    fn = FACTOR_TEXT.get(name)
    return fn(value, ctx) if fn else name.replace("_", " ")


def _band(p: float) -> str:
    return "high" if p >= 0.66 else "medium" if p >= 0.33 else "low"


def forecast_flows(baseline, analyzer, seed: int = 0):
    """The flow sample the models were trained with: required flows plus up to 90 host pairs."""
    import random
    from backend.ai.datasets import _flows
    return _flows(baseline, analyzer, random.Random(seed))


def change_insight(baseline, flows, detected, impacts: list[dict] | None = None, findings: list | None = None) -> dict:
    """Forecast for one proposed change, from the baseline model and its baseline flow paths only."""
    models = _models()
    model = models.get("change_risk")
    if model is None:
        return {"available": False}
    ctx = F.topology_context(baseline, flows)
    x = F.change_features(baseline, ctx, detected)
    vec = F.vector(x)
    p = model.predict(vec)
    endpoints = max(math.expm1(models["blast_endpoints"].predict(vec)), 0.0) if "blast_endpoints" in models else None
    flow_count = max(math.expm1(models["blast_flows"].predict(vec)), 0.0) if "blast_flows" in models else None
    names = {"device": detected.device_name, "target": detected.target_name}
    contributions = sorted(model.contributions(vec).items(), key=lambda kv: -abs(kv[1]))
    factors = []
    for name, weight in contributions:
        if abs(weight) < 0.05 or (name.startswith(("type:", "category:")) and not x.get(name)):
            continue
        factors.append({"feature": name, "text": _factor_text(name, x.get(name, 0.0), names),
                        "direction": "raises" if weight > 0 else "lowers", "weight": round(weight, 3)})
        if len(factors) == 5:
            break
    out = {"available": True, "model_version": version(), "harm_probability": round(p, 3), "band": _band(p),
           "expected_endpoints": round(endpoints, 1) if endpoints is not None else None,
           "expected_flows": round(flow_count, 1) if flow_count is not None else None,
           "factors": factors, "features": vec, "advisory": ADVISORY}
    if impacts is not None:
        broken = [i for i in impacts if i["status"] in ("broken", "violation")]
        severe = any(getattr(f, "severity", "") in ("HIGH", "CRITICAL") for f in (findings or []))
        simulated = bool(broken) or severe
        out["simulated_harmful"] = simulated
        out["simulated_endpoints"] = len({n for i in broken for n in (i["source_device"], i["destination_device"])})
        out["agreement"] = ("agrees" if simulated == (p >= 0.5) else
                            "model_higher" if p >= 0.5 else "model_lower")
    out["summary"] = _change_summary(out, detected)
    return out


def _change_summary(out: dict, detected) -> str:
    p = out["harm_probability"]
    text = (f"The model estimates a {p:.0%} chance ({out['band']}) that changing {detected.target_name or detected.device_name} "
            f"on {detected.device_name} breaks connectivity or introduces a high-severity problem")
    if out.get("expected_endpoints") is not None and p >= 0.33:
        text += f", affecting about {out['expected_endpoints']:.0f} endpoint(s)"
    text += "."
    raising = [f["text"] for f in out["factors"] if f["direction"] == "raises"][:2]
    lowering = [f["text"] for f in out["factors"] if f["direction"] == "lowers"][:2]
    if raising:
        text += " It rises because " + " and ".join(raising) + "."
    if lowering:
        text += " It falls because " + " and ".join(lowering) + "."
    agreement = out.get("agreement")
    if agreement == "agrees":
        text += " The simulation of this network agrees."
    elif agreement == "model_higher":
        text += (" The simulation found no broken flow: changes like this one often cause problems outside the "
                 "modelled flows, so verify the paths after the change.")
    elif agreement == "model_lower":
        text += " The simulation of this network shows a problem; follow the simulation."
    return text


# ------------------------------------------------------------------ 2. anomalies and misconfigurations
def link_anomalies(model, threshold: float = 0.6) -> list[dict]:
    classifier = _models().get("link_faults")
    if classifier is None:
        return []
    out = []
    for link in model.links.values():
        tokens = F.link_tokens(model, link)
        if not tokens:
            continue
        probs = classifier.predict_proba(tokens)
        label, p = max(probs.items(), key=lambda kv: kv[1])
        if label == "clean" or p < threshold:
            continue
        a, b = model.devices[link.a_dev], model.devices[link.b_dev]
        ia, ib = model.iface(a.id, link.a_if), model.iface(b.id, link.b_if)
        evidence = classifier.evidence(tokens, label)
        out.append({"kind": "link", "link_id": link.id, "device_ids": [a.id, b.id], "label": label,
                    "title": FAULT_LABELS.get(label, label), "probability": round(p, 3),
                    "where": f"{a.name} {ia.name if ia else '?'} ↔ {b.name} {ib.name if ib else '?'}",
                    "evidence": [_token_text(t) for t in evidence],
                    "summary": f"{FAULT_LABELS.get(label, label)} likely on {a.name} {ia.name if ia else ''} ↔ "
                               f"{b.name} {ib.name if ib else ''} ({p:.0%})" + (": " + "; ".join(_token_text(t) for t in evidence[:2]) if evidence else "") + "."})
    return sorted(out, key=lambda r: -r["probability"])


def _token_text(token: str) -> str:
    key, _, value = token.partition(":")
    words = {"duplex": "duplex", "speed": "speed", "mtu": "MTU", "mtu-raw": "MTU values", "native": "native VLAN",
             "allowed": "allowed VLANs", "access-vlan": "access VLAN", "subnet": "subnet", "ospf-area": "OSPF area",
             "ospf-hello": "OSPF hello", "ospf-dead": "OSPF dead interval", "errors": "interface errors",
             "mode": "switchport modes", "status": "status", "types": "device types"}
    if token == "half-duplex-side":
        return "one side runs half duplex"
    return f"{words.get(key, key)}: {value.replace('|', ' / ')}"


PEER_LABELS = {
    "interfaces": "interfaces", "up_share": "share of interfaces up", "acl_rules": "access-list entries",
    "acl_lists": "access lists", "vlans": "VLANs", "routes": "static routes", "trunk_ports": "trunk ports",
    "access_ports": "access ports", "routed_ports": "routed interfaces", "errors": "interface errors",
    "half_duplex": "half-duplex ports", "mtu_nonstandard": "ports with a non-standard MTU",
    "ospf_ifaces": "OSPF interfaces", "hello_values": "distinct OSPF hello timers",
}
# Metrics whose deviation suggests a problem (others, such as the number of interfaces, describe size only).
PEER_SIGNAL = ("errors", "half_duplex", "mtu_nonstandard", "hello_values", "up_share")


def peer_anomalies(model, z_threshold: float = 3.5) -> list[dict]:
    baselines = _models().get("peer_baselines", {})
    groups = defaultdict(list)
    for device in model.devices.values():
        if not device.is_host:
            groups[F.role_of(device)].append(device)
    out = []
    for role, devices in groups.items():
        rows = {d.id: F.device_metrics(d) for d in devices}
        local = RobustBaseline().fit(list(rows.values())) if len(devices) >= 5 else None
        reference = local or baselines.get(role)
        if reference is None:
            continue
        for device in devices:
            for metric in PEER_SIGNAL:
                value = rows[device.id][metric]
                z = reference.z(metric, value)
                if z is None:
                    continue
                if metric == "up_share":
                    z = -z  # fewer interfaces up than peers is the concerning direction
                if z >= z_threshold and (metric != "errors" or value >= 20):
                    med = reference.stats[metric][0]
                    out.append({"kind": "peer", "device_ids": [device.id], "metric": metric, "z": round(z, 1),
                                "value": round(value, 2), "peer_median": round(med, 2),
                                "compared_with": f"{len(devices)} {role} peers in this network" if local else
                                f"{role} profiles learned from the training topologies",
                                "title": f"{device.name}: unusual {PEER_LABELS[metric]}",
                                "summary": f"{device.name} has {value:g} {PEER_LABELS[metric]} where similar {role}s "
                                           f"have about {med:g} (robust z = {z:.1f})."})
    return sorted(out, key=lambda r: -r["z"])


def syslog_insights(devices_telemetry: dict[int, tuple[str, dict]], limit: int = 200) -> list[dict]:
    classifier = _models().get("syslog")
    if classifier is None:
        return []
    out = []
    for device_id, (name, telemetry) in devices_telemetry.items():
        lines = (telemetry or {}).get("syslog") or []
        if not lines:
            continue
        counts, examples = Counter(), {}
        for line in lines[-limit:]:
            probs = classifier.predict_proba(F.syslog_tokens(line))
            label, p = max(probs.items(), key=lambda kv: kv[1])
            if label != "normal" and p >= 0.6:
                counts[label] += 1
                examples.setdefault(label, line[-160:])
        for label, n in counts.most_common():
            out.append({"kind": "syslog", "device_ids": [device_id], "label": label,
                        "title": f"{name}: {SYSLOG_CATEGORIES.get(label, label).lower()}", "count": n,
                        "example": examples[label],
                        "summary": f"{n} recent syslog message(s) on {name} classified as "
                                   f"{SYSLOG_CATEGORIES.get(label, label).lower()}."})
    return out


def classify_syslog(lines: list[str]) -> list[dict]:
    classifier = _models().get("syslog")
    if classifier is None:
        return []
    rows = []
    for line in lines[:500]:
        probs = classifier.predict_proba(F.syslog_tokens(line))
        label, p = max(probs.items(), key=lambda kv: kv[1])
        rows.append({"line": line, "label": label, "category": SYSLOG_CATEGORIES.get(label, label),
                     "probability": round(p, 3), "evidence": classifier.evidence(F.syslog_tokens(line), label, 3)})
    return rows


# ------------------------------------------------------------------ 3. root cause and 4. remediation ranking
def root_causes(model, flows, findings: list, limit: int = 5) -> list[dict]:
    ranker = _models().get("root_cause")
    failing = [f for f in flows if f.baseline is not None and f.expected and f.kind != "gateway"
               and f.baseline.reachable != (f.expected == "allow")]
    if ranker is None or not failing or not findings:
        return []
    ctx = F.topology_context(model, flows)
    scored = []
    for finding in findings:
        x = F.rca_features(model, ctx, finding, failing, findings)
        scored.append((ranker.predict(F.vector(x, F.RCA_FEATURES)), finding, x))
    scored.sort(key=lambda s: -s[0])
    total = sum(s[0] for s in scored) or 1.0
    out = []
    for p, finding, x in scored[:limit]:
        names = ", ".join(model.devices[d].name for d in finding.device_ids if d in model.devices)
        reasons = []
        if x["on_first_break"]:
            reasons.append("it is where failing flows first stop")
        if x["explains_flows"]:
            n = int(x["explains_flows"])
            reasons.append(f"it explains {n} of {max(n, len(failing))} failing flow(s)")
        elif x["on_broken_path"]:
            reasons.append("it lies on the path of failing flows")
        if not reasons:
            reasons.append("it is not on the path of any failing flow")
        out.append({"rule_id": finding.rule_id, "subject": finding.subject, "message": finding.message,
                    "device_ids": finding.device_ids, "probability": round(p, 3), "share": round(p / total, 3),
                    "summary": f"{finding.rule_id} on {names or finding.subject} ({p:.0%}): " + "; ".join(reasons) + "."})
    return out


def fix_vector(model, ctx: dict, finding: dict, fix: dict, failing_count: int) -> list[float]:
    """The ranker's features from a health-check fix and its verification (mirrors datasets.fix_features)."""
    from backend.ai.datasets import FIX_FEATURES
    from backend.services.change_detector import CHANGE_TYPES
    v = fix.get("verification") or {}
    device = model.devices.get(fix.get("device_id"))
    category = CHANGE_TYPES.get(fix.get("change_type"), {}).get("category")
    x = {
        "resolves_target": float(bool(v.get("resolves"))), "also_resolves": float(len(v.get("also_resolves") or [])),
        "new_issues": float(len(v.get("new_issues") or [])), "broken_flows": float(len(v.get("broken_flows") or [])),
        "restored_flows": float(len(v.get("restored_flows") or [])),
        "restored_share": min(len(v.get("restored_flows") or []) / max(len(finding.get("related_flows") or []), 1), 1.0),
        "risk_total": float(v.get("risk_score") or 0), "same_device": float(fix.get("device_id") in finding.get("device_ids", [])),
        "same_interface": 0.0, "on_first_break": float(fix.get("device_id") in ctx.get("fail_devices", set())),
        "caution": float(bool(fix.get("caution"))), "work_order": float(fix.get("change_type") == "physical_remediation"),
        "params_count": float(len([p for p in (fix.get("parameters") or {}).values() if p not in (None, "", [])])),
        "fix_routing": float(category == "routing"), "fix_acl": float(category == "acl"), "fix_vlan": float(category == "vlan"),
        "fix_interface": float(category == "ip_interface"), "fix_physical": float(category == "physical"),
        "fix_security": float(category == "security"),
        "dev_path_share": ctx["dev_load"].get(fix.get("device_id"), 0) / ctx["total"],
        "dev_router": float(bool(device and device.is_router)), "dev_switch": float(bool(device and device.is_switch)),
        "dev_host": float(bool(device and device.is_host)),
    }
    return [x[k] for k in FIX_FEATURES]


VERDICT_ORDER = {"recommended": 0, "partial": 1, "unsafe": 2}


def rank_fixes(model, flows, issues: list[dict]) -> None:
    """Adds fix['ai'] and orders fixes: deterministic safety verdict first, repair probability second."""
    ranker = _models().get("fix_ranker")
    if ranker is None:
        return
    ctx = F.topology_context(model, flows)
    failing = sum(1 for f in flows if f.baseline is not None and f.expected and f.kind != "gateway"
                  and f.baseline.reachable != (f.expected == "allow"))
    for issue in issues:
        for fix in issue.get("fixes", []):
            vec = fix_vector(model, ctx, issue, fix, failing)
            p = ranker.predict(vec)
            contributions = sorted(ranker.contributions(vec).items(), key=lambda kv: -abs(kv[1]))[:3]
            fix["ai"] = {"repair_probability": round(p, 3), "band": _band(p),
                         "reason": _fix_reason(fix, p, contributions)}
        issue["fixes"].sort(key=lambda f: (VERDICT_ORDER.get((f.get("verification") or {}).get("verdict"), 9),
                                           -(f.get("ai") or {}).get("repair_probability", 0),
                                           -len((f.get("verification") or {}).get("also_resolves", []))))


FIX_REASON = {
    "same_device": ("it changes the device where the problem is", "it changes a different device than the one at fault"),
    "resolves_target": ("verification shows it resolves the issue", "verification does not show the issue resolved"),
    "restored_share": ("it restores the failing flows", "it restores few of the failing flows"),
    "restored_flows": ("it restores the failing flows", "it restores few of the failing flows"),
    "on_first_break": ("it acts where the failing flows first stop", None),
    "new_issues": ("it introduces no new issue", "it introduces new issues"),
    "caution": ("it needs no design review", "it needs a design review"),
    "fix_routing": ("it is a routing correction", "it is not a routing correction"),
    "also_resolves": ("it also resolves related issues", "it resolves only this issue"),
}


def _fix_reason(fix: dict, p: float, contributions) -> str:
    parts = []
    for name, weight in contributions:
        texts = FIX_REASON.get(name)
        if texts:
            good, bad = texts
            text = good if weight > 0 else bad
            if text:
                parts.append(text)
    head = ("Likely a root-cause repair" if p >= 0.66 else "Possibly a workaround rather than a repair" if p < 0.33
            else "May repair the root cause")
    return f"{head} ({p:.0%})" + (": " + ", ".join(dict.fromkeys(parts)) + "." if parts else ".")


# ------------------------------------------------------------------ network insight
def network_insights(model, flows, findings: list, issues: list[dict], telemetry: dict | None = None) -> dict:
    if not _models():
        return {"available": False, "advisory": ADVISORY}
    causes = root_causes(model, flows, findings)
    anomalies = link_anomalies(model) + peer_anomalies(model) + syslog_insights(telemetry or {})
    # Anomalies that no validation rule already reports are the new information.
    reported = {d for f in findings for d in f.device_ids}
    for row in anomalies:
        row["also_reported_by_rules"] = bool(set(row.get("device_ids", [])) & reported)
    summary = []
    if causes:
        summary.append("Most likely root cause: " + causes[0]["summary"])
    fresh = [a for a in anomalies if not a["also_reported_by_rules"]]
    if fresh:
        summary.append(f"{len(fresh)} anomal{'y' if len(fresh) == 1 else 'ies'} not reported by any validation rule: "
                       + "; ".join(a["title"] for a in fresh[:3]) + ".")
    elif anomalies:
        summary.append(f"{len(anomalies)} anomal{'y' if len(anomalies) == 1 else 'ies'}, all on devices that "
                       "validation rules already report.")
    if not causes and not anomalies:
        summary.append("No anomaly or likely root cause found by the models.")
    ranked = [{"issue": i["rule_id"], "subject": i.get("subject"), "fix": f["label"], **f["ai"]}
              for i in issues for f in i.get("fixes", [])[:1] if f.get("ai")]
    return {"available": True, "model_version": version(), "root_causes": causes, "anomalies": anomalies[:30],
            "ranked_fixes": ranked, "summary": " ".join(summary), "advisory": ADVISORY}


# ------------------------------------------------------------------ outcomes (DB)
def record_forecast(db, change, insight: dict) -> None:
    from sqlalchemy import select
    from backend.models import ChangeOutcome
    if not insight.get("available"):
        return
    row = db.scalar(select(ChangeOutcome).where(ChangeOutcome.change_id == change.id))
    if row is None:
        row = ChangeOutcome(change_id=change.id, network_id=change.network_id, change_type=change.change_type)
        db.add(row)
    row.change_type, row.features, row.model_version = change.change_type, insight["features"], insight["model_version"]
    row.predicted_harm, row.predicted_endpoints = insight["harm_probability"], insight.get("expected_endpoints")
    if "simulated_harmful" in insight:
        row.simulated_harmful = int(insight["simulated_harmful"])
        row.simulated_endpoints = insight.get("simulated_endpoints")


def record_execution(db, change, verification: dict, success: bool) -> None:
    from datetime import datetime, timezone
    from sqlalchemy import select
    from backend.models import ChangeOutcome
    row = db.scalar(select(ChangeOutcome).where(ChangeOutcome.change_id == change.id))
    if row is None:
        return
    broken = list(verification.get("broken_flows") or [])
    row.actual_harmful = int(bool(broken or verification.get("new_findings")))
    row.actual = {"success": success, "broken_flows": len(broken), "new_findings": len(verification.get("new_findings") or []),
                  "intended_state": verification.get("intended_state"), "restored": verification.get("restored")}
    row.executed_at = datetime.now(timezone.utc).replace(tzinfo=None)


def local_training_rows(db) -> list[dict]:
    from sqlalchemy import select
    from backend.models import ChangeOutcome
    rows = []
    for row in db.scalars(select(ChangeOutcome).where(ChangeOutcome.actual_harmful.is_not(None))):
        if len(row.features or []) != len(F.CHANGE_FEATURES):
            continue  # recorded by a model with other features
        # Only the harm label is observed on a device; blast-radius targets stay simulation-labelled.
        rows.append({"x": row.features, "harmful": row.actual_harmful, "change_type": row.change_type})
    return rows


def retrain(db, include_local: bool = True) -> dict:
    """Retrain from the bundled datasets plus this installation's executed changes."""
    from backend.ai import train
    if not (DATASET_DIR / "change_outcomes.jsonl").exists():
        from backend.core.errors import ValidationFailed
        raise ValidationFailed("The training datasets are not installed (data/datasets).")
    manifest = train.train(DATASET_DIR, MODEL_DIR, local_training_rows(db) if include_local else [], log=lambda *_: None)
    reload()
    return manifest
