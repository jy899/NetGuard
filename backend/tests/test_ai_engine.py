"""Advisory AI: learning algorithms, features, shipped models and their integration in analysis and health check."""
import json
import random
from copy import deepcopy

import pytest

from backend.ai import features as F
from backend.ai import synth
from backend.ai.ml import GradientBoostedTrees, MultinomialNB, RobustBaseline, auc
from backend.services import ai_engine
from backend.tests.helpers import manager_auth


# ------------------------------------------------------------------ algorithms
def test_gradient_boosting_learns_an_interaction_and_explains_it():
    rng = random.Random(3)
    X = [[rng.random(), rng.random(), rng.random()] for _ in range(600)]
    y = [float((a > 0.5) != (b > 0.5)) for a, b, _ in X]  # XOR: needs depth-2 trees
    model = GradientBoostedTrees(["a", "b", "noise"], "binary", rounds=60, depth=3).fit(X[:500], y[:500])
    probs = [model.predict(x) for x in X[500:]]
    assert auc(probs, [int(v) for v in y[500:]]) > 0.95
    x = X[0]
    parts = model.contributions(x)
    assert abs(sum(parts.values()) - (model.raw(x) - model.expected())) < 1e-6  # contributions decompose the score
    assert model.importance()["a"] > model.importance().get("noise", 0)
    again = GradientBoostedTrees.from_dict(json.loads(json.dumps(model.to_dict())))
    assert abs(again.predict(x) - model.predict(x)) < 1e-6


def test_regression_naive_bayes_and_robust_baseline():
    X = [[float(i)] for i in range(200)]
    reg = GradientBoostedTrees(["x"], "regression", rounds=80).fit(X, [2.0 * i for i in range(200)])
    assert abs(reg.predict([100.0]) - 200) < 25
    nb = MultinomialNB().fit([["duplex", "half"], ["mtu", "diff"], ["duplex", "half", "errors"]], ["d", "m", "d"])
    assert max(nb.predict_proba(["half"]).items(), key=lambda kv: kv[1])[0] == "d"
    assert nb.evidence(["half", "mtu"], "d") == ["half"]
    base = RobustBaseline().fit([{"errors": v} for v in (0, 1, 0, 2, 1, 0)])
    assert base.z("errors", 500) > 50 and abs(base.z("errors", 1)) < 2


# ------------------------------------------------------------------ features and generators
def test_link_tokens_reflect_cross_device_differences():
    from backend.services.network_model import DeviceM, IfaceM, LinkM, NetworkModel
    a = IfaceM(1, 1, "Gi0/1", "10.0.0.1", "255.255.255.252", None, "up", 0, None, duplex="half", error_count=900)
    b = IfaceM(2, 2, "Gi0/1", "10.0.0.2", "255.255.255.252", None, "up", 1, None, duplex="full")
    model = NetworkModel(1, {1: DeviceM(1, "R1", "router", None, {1: a}), 2: DeviceM(2, "R2", "router", None, {2: b})},
                         {9: LinkM(9, 1, 1, 2, 2)}, [])
    tokens = F.link_tokens(model, model.links[9])
    assert "duplex:full|half" in tokens and "ospf-area:backbone-vs-other" in tokens and "errors:high" in tokens
    assert "subnet:same" in tokens


def test_synthetic_campus_is_a_valid_healthy_network(client, auth):
    campus = synth.campus(7)
    response = client.post("/api/networks/import", headers=auth, json={
        "name": "Campus 7", "configs": campus["configs"], "endpoints": campus["endpoints"], "flows": campus["flows"]})
    assert response.status_code in (200, 201), response.text
    report = client.get(f"/api/networks/{response.json()['network_id']}/health-check", headers=auth).json()
    assert report["status"] == "healthy", [i["message"] for i in report["issues"]]
    line = synth.syslog(random.Random(1), "l2_loop")
    assert "%" in line and F.syslog_tokens(line)


# ------------------------------------------------------------------ shipped models and integration
@pytest.fixture()
def example(client, auth):
    def make(scenario):
        network = client.post("/api/networks/samples", headers=auth, json={"scenario": scenario}).json()
        topo = client.get(f"/api/networks/{network['network_id']}/topology", headers=auth).json()
        return network["network_id"], {d["name"]: d for d in topo["devices"]}
    return make


def test_models_are_bundled_with_metrics():
    status = ai_engine.status()
    assert status["available"] and {"change_risk", "blast_endpoints", "root_cause", "fix_ranker", "link_faults",
                                    "syslog", "peer_baselines"} <= set(status["models"])
    metrics = status["metrics"]
    assert metrics["change_risk"]["auc"] > 0.85 and metrics["syslog"]["macro_f1"] > 0.8
    assert metrics["change_risk"]["brier"] < metrics["change_risk"]["brier_base_rate"]  # better than the base rate


def test_change_forecast_is_attached_to_the_assessment_and_recorded(client, auth, example):
    nid, devices = example("healthy")
    r1 = devices["R1"]
    uplink = next(i for i in r1["interfaces"] if i["ip_address"])

    def analyze(device, change_type, interface=None, **parameters):
        change = client.post("/api/changes", headers=auth, json={"device_id": device["id"], "change_type": change_type,
                                                                 "interface_id": interface, "parameters": parameters}).json()
        return client.post(f"/api/changes/{change['id']}/analyze", headers=auth).json()

    risky = analyze(r1, "interface_status", uplink["id"], status="admin-down")
    safe = analyze(devices["SW1"], "vlan_database", action="add", vlan_id=40, name="GUEST")
    assert risky["ai"]["available"] and risky["ai"]["harm_probability"] > safe["ai"]["harm_probability"]
    assert risky["ai"]["factors"] and risky["ai"]["summary"].startswith("The model estimates")
    assert "features" not in risky["ai"]  # the stored assessment keeps the explanation, not the raw vector
    assert risky["ai"]["agreement"] in ("agrees", "model_higher", "model_lower")
    assert risky["recommendation"] != "DEPLOY"  # the deterministic decision is unchanged by the model
    from backend.database.session import SessionLocal
    from backend.models import ChangeOutcome
    with SessionLocal() as db:
        rows = db.query(ChangeOutcome).all()
        assert len(rows) == 2 and all(len(r.features) == len(F.CHANGE_FEATURES) for r in rows)


def test_health_check_ranks_root_causes_and_fixes(client, auth, example):
    nid, _ = example("routing")
    report = client.get(f"/api/networks/{nid}/health-check", headers=auth).json()
    ai = report["ai"]
    assert ai["available"] and ai["root_causes"][0]["rule_id"] == "OSPF001"
    fixes = next(i for i in report["issues"] if i["rule_id"] == "OSPF001")["fixes"]
    assert all("repair_probability" in f["ai"] for f in fixes)
    verdicts = [f["verification"]["verdict"] for f in fixes]
    assert verdicts == sorted(verdicts, key=lambda v: ai_engine.VERDICT_ORDER[v])  # safety order is kept
    assert fixes[0]["ai"]["repair_probability"] >= 0.5
    insight = client.get(f"/api/ai/networks/{nid}/insights", headers=auth).json()
    assert insight["root_causes"] and insight["fixes"]


def test_link_misconfiguration_is_classified(client, auth, example):
    nid, devices = example("healthy")
    from backend.database.session import SessionLocal
    from backend.services.network_model import load_model
    with SessionLocal() as db:
        model = load_model(db, nid)
    link = next(l for l in model.links.values()
                if model.iface(l.a_dev, l.a_if) and model.iface(l.b_dev, l.b_if)
                and model.iface(l.a_dev, l.a_if).ip and model.iface(l.b_dev, l.b_if).ip)
    broken = deepcopy(model)
    a = broken.iface(link.a_dev, link.a_if)
    b = broken.iface(link.b_dev, link.b_if)
    a.duplex, b.duplex, a.error_count = "half", "full", 3000
    found = ai_engine.link_anomalies(broken)
    assert found and found[0]["label"] == "duplex_mismatch" and found[0]["link_id"] == link.id
    assert not [x for x in ai_engine.link_anomalies(model) if x["link_id"] == link.id]


def test_syslog_classification_and_permissions(client, auth):
    lines = ["%SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.4455 in vlan 10 is flapping between port Gi1/0/1 and port Gi1/0/2",
             "%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Dead timer expired",
             "%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 10.1.1.9] [localport: 22] [Reason: Login Authentication Failed]"]
    rows = client.post("/api/ai/syslog/classify", headers=auth, json={"lines": lines}).json()["rows"]
    assert [r["label"] for r in rows] == ["l2_loop", "routing_adjacency", "security_auth"]
    manager = manager_auth(client, auth)
    assert client.post("/api/ai/retrain", headers=manager, json={}).status_code == 403  # administrators only
    assert client.get("/api/ai/status", headers=manager).json()["available"]


def test_executed_outcomes_become_training_rows(client, auth, example, tmp_path):
    from backend.ai import train
    from backend.database.session import SessionLocal
    from backend.models import Change, ChangeOutcome
    nid, devices = example("healthy")
    change = client.post("/api/changes", headers=auth, json={"device_id": devices["SW1"]["id"], "change_type": "vlan_database",
                                                             "parameters": {"action": "add", "vlan_id": 41, "name": "X"}}).json()
    client.post(f"/api/changes/{change['id']}/analyze", headers=auth)
    with SessionLocal() as db:
        ai_engine.record_execution(db, db.get(Change, change["id"]), {"broken_flows": [], "new_findings": [],
                                                                      "intended_state": True}, True)
        db.commit()
        rows = ai_engine.local_training_rows(db)
        assert len(rows) == 1 and rows[0]["harmful"] == 0
        assert db.query(ChangeOutcome).one().actual["success"] is True
    # A tiny training run writes loadable models with held-out metrics.
    data = tmp_path / "ds"
    data.mkdir()
    rng = random.Random(0)
    with (data / "change_outcomes.jsonl").open("w") as handle:
        for i in range(120):
            x = [rng.random() for _ in F.CHANGE_FEATURES]
            handle.write(json.dumps({"source": f"s{i % 12}", "x": x, "harmful": int(x[0] > 0.5),
                                     "blast_flows": int(x[1] * 5), "blast_endpoints": int(x[2] * 3)}) + "\n")
    manifest = train.train(data, tmp_path / "models", rows, log=lambda *_: None)
    assert manifest["local_outcomes"] == 1 and (tmp_path / "models" / "change_risk.json").exists()
