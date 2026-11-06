"""Trains NetGuard's advisory models from data/datasets/*.jsonl and writes data/models/*.json plus metrics.

Evaluation holds out whole topologies (grouped by `source`), so the reported metrics describe networks the models
have never seen. Local outcomes recorded by this installation (executed laboratory changes) are added to the
change-risk training set when "include executed changes" is chosen.

Run from Settings → AI Models → Retrain.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from collections import Counter
from pathlib import Path

from backend.ai import datasets as D
from backend.ai import features as F
from backend.ai.ml import GradientBoostedTrees, MultinomialNB, RobustBaseline, auc, brier, classification_report

MODEL_VERSION = 1


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _held_out(source: str) -> bool:
    return int(hashlib.sha1(source.encode()).hexdigest(), 16) % 5 == 0


def _split(rows):
    train = [r for r in rows if not _held_out(r["source"])]
    test = [r for r in rows if _held_out(r["source"])]
    return train, test


def _binary(name, rows, features, label, rounds=90, depth=3, min_leaf=10):
    train, test = _split(rows)
    model = GradientBoostedTrees(list(features), "binary", rounds=rounds, depth=depth, min_leaf=min_leaf)
    model.fit([r["x"] for r in train], [float(r[label]) for r in train])
    probs = [model.predict(r["x"]) for r in test]
    labels = [int(r[label]) for r in test]
    base_rate = sum(r[label] for r in train) / max(len(train), 1)
    metrics = {"train_rows": len(train), "test_rows": len(test), "positive_rate": round(base_rate, 3),
               "auc": _r(auc(probs, labels)), "brier": _r(brier(probs, labels)),
               "brier_base_rate": _r(brier([base_rate] * len(labels), labels)),
               "accuracy": _r(sum((p >= 0.5) == bool(l) for p, l in zip(probs, labels)) / max(len(labels), 1))}
    # Refit on everything for the shipped model.
    final = GradientBoostedTrees(list(features), "binary", rounds=rounds, depth=depth, min_leaf=min_leaf)
    final.fit([r["x"] for r in rows], [float(r[label]) for r in rows])
    return final, metrics


def _regression(rows, features, target, rounds=90):
    train, test = _split(rows)
    model = GradientBoostedTrees(list(features), "regression", rounds=rounds, depth=3, min_leaf=10)
    model.fit([r["x"] for r in train], [F.log1p(r[target]) for r in train])
    pred = [max(math.expm1(model.predict(r["x"])), 0.0) for r in test]
    true = [r[target] for r in test]
    mean = sum(r[target] for r in train) / max(len(train), 1)
    metrics = {"train_rows": len(train), "test_rows": len(test),
               "mae": _r(sum(abs(p - t) for p, t in zip(pred, true)) / max(len(true), 1)),
               "mae_mean_baseline": _r(sum(abs(mean - t) for t in true) / max(len(true), 1)),
               "spearman": _r(_spearman(pred, true))}
    final = GradientBoostedTrees(list(features), "regression", rounds=rounds, depth=3, min_leaf=10)
    final.fit([r["x"] for r in rows], [F.log1p(r[target]) for r in rows])
    return final, metrics


def _nb(rows, tokens_of):
    train, test = _split(rows) if "source" in rows[0] else _random_split(rows)
    model = MultinomialNB(0.5).fit([tokens_of(r) for r in train], [r["label"] for r in train])
    pred = [max(model.predict_proba(tokens_of(r)).items(), key=lambda p: p[1])[0] for r in test]
    report = classification_report(pred, [r["label"] for r in test])
    majority = Counter(r["label"] for r in train).most_common(1)[0][0]
    report["majority_baseline_accuracy"] = _r(sum(r["label"] == majority for r in test) / max(len(test), 1))
    report.update(train_rows=len(train), test_rows=len(test))
    final = MultinomialNB(0.5).fit([tokens_of(r) for r in rows], [r["label"] for r in rows])
    return final, report


def _random_split(rows):
    train = [r for i, r in enumerate(rows) if i % 5]
    test = [r for i, r in enumerate(rows) if not i % 5]
    return train, test


def _spearman(a, b):
    if len(a) < 3:
        return None
    ra, rb = _ranks(a), _ranks(b)
    ma, mb = sum(ra) / len(ra), sum(rb) / len(rb)
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = math.sqrt(sum((x - ma) ** 2 for x in ra))
    vb = math.sqrt(sum((y - mb) ** 2 for y in rb))
    return cov / (va * vb) if va and vb else None


def _ranks(values):
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2
        i = j + 1
    return ranks


def _r(value):
    return None if value is None else round(value, 4)


def train(dataset_dir: Path, model_dir: Path, local_outcomes: list[dict] | None = None, log=print) -> dict:
    started = time.time()
    model_dir.mkdir(parents=True, exist_ok=True)
    data = {name: _rows(dataset_dir / f"{name}.jsonl") for name in
            ("change_outcomes", "root_cause", "fix_outcomes", "link_faults", "syslog", "device_profiles")}
    changes = data["change_outcomes"] + [dict(r, source=f"local:{i}") for i, r in enumerate(local_outcomes or [])]
    metrics, models = {}, {}
    if changes:
        models["change_risk"], metrics["change_risk"] = _binary("change_risk", changes, F.CHANGE_FEATURES, "harmful")
        log(f"change risk {metrics['change_risk']}")
        blast = [r for r in changes if "blast_endpoints" in r]
        models["blast_endpoints"], metrics["blast_endpoints"] = _regression(blast, F.CHANGE_FEATURES, "blast_endpoints")
        models["blast_flows"], metrics["blast_flows"] = _regression(blast, F.CHANGE_FEATURES, "blast_flows")
        log(f"blast radius {metrics['blast_endpoints']}")
    if data["root_cause"]:
        models["root_cause"], metrics["root_cause"] = _binary("root_cause", data["root_cause"], F.RCA_FEATURES, "cause",
                                                              rounds=70, min_leaf=6)
        metrics["root_cause"]["top1_accuracy"] = _top1(data["root_cause"], models["root_cause"])
        log(f"root cause {metrics['root_cause']}")
    if data["fix_outcomes"]:
        models["fix_ranker"], metrics["fix_ranker"] = _binary("fix_ranker", data["fix_outcomes"], D.FIX_FEATURES, "restores",
                                                              rounds=70, min_leaf=6)
        log(f"fix ranker {metrics['fix_ranker']}")
    if data["link_faults"]:
        models["link_faults"], metrics["link_faults"] = _nb(data["link_faults"], lambda r: r["tokens"])
        log(f"link faults accuracy {metrics['link_faults']['accuracy']} macro-F1 {metrics['link_faults']['macro_f1']}")
    if data["syslog"]:
        models["syslog"], metrics["syslog"] = _nb(data["syslog"], lambda r: F.syslog_tokens(r["line"]))
        log(f"syslog accuracy {metrics['syslog']['accuracy']} macro-F1 {metrics['syslog']['macro_f1']}")
    peer = {}
    for role in sorted({r["role"] for r in data["device_profiles"]}):
        rows = [r["m"] for r in data["device_profiles"] if r["role"] == role]
        peer[role] = RobustBaseline().fit(rows).to_dict()
    manifest_in = json.loads((dataset_dir / "manifest.json").read_text()) if (dataset_dir / "manifest.json").exists() else {}
    for name, model in models.items():
        (model_dir / f"{name}.json").write_text(json.dumps(model.to_dict(), separators=(",", ":")), encoding="utf-8")
    (model_dir / "peer_baselines.json").write_text(json.dumps({"type": "peer", "roles": peer}), encoding="utf-8")
    manifest = {"model_version": MODEL_VERSION, "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "trained_seconds": round(time.time() - started, 1), "dataset": manifest_in,
                "local_outcomes": len(local_outcomes or []), "metrics": metrics,
                "models": sorted(list(models) + ["peer_baselines"]),
                "evaluation": "Held-out topologies (one in five sources by hash), never seen in training; shipped "
                              "models are then refitted on all rows."}
    (model_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _top1(rows, model) -> float | None:
    """Share of held-out faulted networks whose highest-scored finding is a true cause."""
    groups: dict[str, list] = {}
    for r in rows:
        if _held_out(r["source"]):
            groups.setdefault(r.get("case", r["source"]), []).append(r)
    hits = total = 0
    for members in groups.values():
        if not any(m["cause"] for m in members):
            continue
        best = max(members, key=lambda m: model.predict(m["x"]))
        hits += best["cause"]
        total += 1
    return round(hits / total, 3) if total else None

