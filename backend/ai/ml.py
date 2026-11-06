"""Small, dependency-free learning algorithms used by NetGuard's advisory AI.

* GradientBoostedTrees: histogram-based gradient boosting of shallow regression trees (squared loss for
  regression, logistic loss for binary classification). Each prediction can be decomposed into per-feature
  contributions (the path-attribution method of Saabas), which the explanations quote.
* MultinomialNB: multinomial naive Bayes with Laplace smoothing for token streams (configuration lines, syslog).
* RobustBaseline: median / MAD statistics for peer-group outlier scores.

Everything serialises to plain JSON so trained models ship as files and load without pickle.
"""
from __future__ import annotations

import math
import random
from collections import Counter, defaultdict


def sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


# ------------------------------------------------------------------ gradient boosting
class GradientBoostedTrees:
    def __init__(self, features: list[str], objective: str = "binary", rounds: int = 80, depth: int = 3,
                 learning_rate: float = 0.15, min_leaf: int = 8, bins: int = 24, l2: float = 1.0,
                 subsample: float = 0.85, seed: int = 7):
        assert objective in ("binary", "regression")
        self.features, self.objective = list(features), objective
        self.rounds, self.depth, self.lr, self.min_leaf = rounds, depth, learning_rate, min_leaf
        self.bins, self.l2, self.subsample, self.seed = bins, l2, subsample, seed
        self.base = 0.0
        self.trees: list[dict] = []
        self.thresholds: list[list[float]] = []
        self.gain: list[float] = [0.0] * len(self.features)

    # -------------------------------------------------------------- training
    def _binning(self, X: list[list[float]]) -> list[list[int]]:
        self.thresholds = []
        for j in range(len(self.features)):
            values = sorted({row[j] for row in X})
            if len(values) <= self.bins:
                cuts = [(values[i] + values[i + 1]) / 2 for i in range(len(values) - 1)]
            else:
                column = sorted(row[j] for row in X)
                cuts = sorted({column[int(len(column) * q / self.bins)] for q in range(1, self.bins)})
            self.thresholds.append(cuts)
        return [[_bin(row[j], self.thresholds[j]) for j in range(len(self.features))] for row in X]

    def fit(self, X: list[list[float]], y: list[float]) -> "GradientBoostedTrees":
        n = len(X)
        rng = random.Random(self.seed)
        B = self._binning(X)
        if self.objective == "binary":
            p = min(max(sum(y) / n, 1e-4), 1 - 1e-4)
            self.base = math.log(p / (1 - p))
        else:
            self.base = sum(y) / n
        raw = [self.base] * n
        for _ in range(self.rounds):
            if self.objective == "binary":
                prob = [sigmoid(r) for r in raw]
                grad = [prob[i] - y[i] for i in range(n)]
                hess = [max(prob[i] * (1 - prob[i]), 1e-6) for i in range(n)]
            else:
                grad = [raw[i] - y[i] for i in range(n)]
                hess = [1.0] * n
            rows = [i for i in range(n) if rng.random() < self.subsample] or list(range(n))
            tree = self._grow(B, grad, hess, rows, 0)
            self.trees.append(tree)
            for i in range(n):
                raw[i] += self.lr * _leaf(tree, B[i])
        total = sum(self.gain) or 1.0
        self.gain = [g / total for g in self.gain]
        return self

    def _grow(self, B, grad, hess, rows, depth) -> dict:
        G, H = sum(grad[i] for i in rows), sum(hess[i] for i in rows)
        node = {"v": -G / (H + self.l2)}
        if depth >= self.depth or len(rows) < 2 * self.min_leaf:
            return node
        parent = G * G / (H + self.l2)
        best = (0.0, None, None)
        for j in range(len(self.features)):
            k = len(self.thresholds[j]) + 1
            if k < 2:
                continue
            gs, hs, cs = [0.0] * k, [0.0] * k, [0] * k
            for i in rows:
                b = B[i][j]
                gs[b] += grad[i]
                hs[b] += hess[i]
                cs[b] += 1
            gl = hl = 0.0
            cl = 0
            for b in range(k - 1):
                gl += gs[b]
                hl += hs[b]
                cl += cs[b]
                if cl < self.min_leaf or len(rows) - cl < self.min_leaf:
                    continue
                gr, hr = G - gl, H - hl
                gain = gl * gl / (hl + self.l2) + gr * gr / (hr + self.l2) - parent
                if gain > best[0]:
                    best = (gain, j, b)
        gain, j, b = best
        if j is None or gain <= 1e-9:
            return node
        self.gain[j] += gain
        left = [i for i in rows if B[i][j] <= b]
        right = [i for i in rows if B[i][j] > b]
        node.update(f=j, t=self.thresholds[j][b], b=b, l=self._grow(B, grad, hess, left, depth + 1),
                    r=self._grow(B, grad, hess, right, depth + 1))
        return node

    # -------------------------------------------------------------- inference
    def raw(self, x: list[float]) -> float:
        return self.base + self.lr * sum(_value(tree, x) for tree in self.trees)

    def predict(self, x: list[float]) -> float:
        r = self.raw(x)
        return sigmoid(r) if self.objective == "binary" else r

    def expected(self) -> float:
        """The raw score before any split: the reference the contributions are measured from."""
        return self.base + self.lr * sum(tree["v"] for tree in self.trees)

    def contributions(self, x: list[float]) -> dict[str, float]:
        """Per-feature contribution to the raw score (log-odds for binary models); they sum to raw - expected()."""
        out = [0.0] * len(self.features)
        for tree in self.trees:
            node = tree
            while "f" in node:
                child = node["l"] if x[node["f"]] <= node["t"] else node["r"]
                out[node["f"]] += self.lr * (child["v"] - node["v"])
                node = child
        return {self.features[j]: out[j] for j in range(len(out)) if abs(out[j]) > 1e-9}

    def importance(self) -> dict[str, float]:
        return {f: round(g, 4) for f, g in sorted(zip(self.features, self.gain), key=lambda p: -p[1]) if g > 0}

    # -------------------------------------------------------------- persistence
    def to_dict(self) -> dict:
        def strip(node):
            if "f" not in node:
                return {"v": round(node["v"], 6)}
            return {"v": round(node["v"], 6), "f": node["f"], "t": node["t"], "l": strip(node["l"]), "r": strip(node["r"])}
        return {"type": "gbt", "objective": self.objective, "features": self.features, "base": self.base, "lr": self.lr,
                "trees": [strip(t) for t in self.trees], "importance": self.importance(),
                "params": {"rounds": self.rounds, "depth": self.depth, "min_leaf": self.min_leaf, "bins": self.bins}}

    @classmethod
    def from_dict(cls, data: dict) -> "GradientBoostedTrees":
        model = cls(data["features"], data["objective"], learning_rate=data["lr"])
        model.base, model.trees = data["base"], data["trees"]
        imp = data.get("importance", {})
        model.gain = [imp.get(f, 0.0) for f in model.features]
        return model


def _bin(value: float, cuts: list[float]) -> int:
    lo, hi = 0, len(cuts)
    while lo < hi:
        mid = (lo + hi) // 2
        if value <= cuts[mid]:
            hi = mid
        else:
            lo = mid + 1
    return lo


def _leaf(tree: dict, binned: list[int]) -> float:
    node = tree
    while "f" in node:
        node = node["l"] if binned[node["f"]] <= node["b"] else node["r"]
    return node["v"]


def _value(tree: dict, x: list[float]) -> float:
    node = tree
    while "f" in node:
        node = node["l"] if x[node["f"]] <= node["t"] else node["r"]
    return node["v"]


# ------------------------------------------------------------------ naive Bayes
class MultinomialNB:
    def __init__(self, alpha: float = 0.5):
        self.alpha = alpha
        self.classes: list[str] = []
        self.prior: dict[str, float] = {}
        self.loglik: dict[str, dict[str, float]] = {}
        self.unseen: dict[str, float] = {}

    def fit(self, docs: list[list[str]], labels: list[str]) -> "MultinomialNB":
        counts: dict[str, Counter] = defaultdict(Counter)
        per_class = Counter(labels)
        for tokens, label in zip(docs, labels):
            counts[label].update(tokens)
        vocab = {t for c in counts.values() for t in c}
        V = len(vocab) or 1
        self.classes = sorted(per_class)
        total = sum(per_class.values())
        self.prior = {c: math.log(per_class[c] / total) for c in self.classes}
        for c in self.classes:
            denom = sum(counts[c].values()) + self.alpha * V
            self.loglik[c] = {t: math.log((counts[c][t] + self.alpha) / denom) for t in counts[c]}
            self.unseen[c] = math.log(self.alpha / denom)
        self.vocab = vocab
        return self

    def scores(self, tokens: list[str]) -> dict[str, float]:
        known = [t for t in tokens if t in self.vocab]
        out = {}
        for c in self.classes:
            ll, miss = self.loglik[c], self.unseen[c]
            out[c] = self.prior[c] + sum(ll.get(t, miss) for t in known)
        return out

    def predict_proba(self, tokens: list[str]) -> dict[str, float]:
        scores = self.scores(tokens)
        top = max(scores.values())
        exp = {c: math.exp(s - top) for c, s in scores.items()}
        z = sum(exp.values())
        return {c: v / z for c, v in exp.items()}

    def evidence(self, tokens: list[str], label: str, limit: int = 4) -> list[str]:
        """Tokens that most favour `label` over the other classes (for explanations)."""
        others = [c for c in self.classes if c != label]
        if not others:
            return []
        weights = {}
        for t in set(tokens):
            if t not in self.vocab:
                continue
            mine = self.loglik[label].get(t, self.unseen[label])
            rest = max(self.loglik[c].get(t, self.unseen[c]) for c in others)
            weights[t] = mine - rest
        return [t for t, w in sorted(weights.items(), key=lambda p: -p[1]) if w > 0.5][:limit]

    def to_dict(self, max_tokens: int = 4000) -> dict:
        # Keep the most informative tokens so model files stay small.
        keep = set()
        for c in self.classes:
            ranked = sorted(self.loglik[c].items(), key=lambda p: -p[1])[: max_tokens // max(len(self.classes), 1)]
            keep.update(t for t, _ in ranked)
        return {"type": "nb", "alpha": self.alpha, "classes": self.classes, "prior": self.prior, "unseen": self.unseen,
                "loglik": {c: {t: round(v, 5) for t, v in self.loglik[c].items() if t in keep} for c in self.classes}}

    @classmethod
    def from_dict(cls, data: dict) -> "MultinomialNB":
        model = cls(data["alpha"])
        model.classes, model.prior, model.unseen, model.loglik = data["classes"], data["prior"], data["unseen"], data["loglik"]
        model.vocab = {t for c in model.loglik.values() for t in c}
        return model


# ------------------------------------------------------------------ robust statistics
class RobustBaseline:
    """Median and scaled MAD per metric; z = (x - median) / (1.4826 * MAD)."""

    def __init__(self, stats: dict[str, tuple[float, float]] | None = None):
        self.stats = dict(stats or {})

    def fit(self, rows: list[dict[str, float]]) -> "RobustBaseline":
        keys = {k for row in rows for k in row}
        for k in keys:
            values = sorted(row[k] for row in rows if k in row)
            med = _median(values)
            mad = _median(sorted(abs(v - med) for v in values))
            self.stats[k] = (med, max(1.4826 * mad, _floor(values)))
        return self

    def z(self, key: str, value: float) -> float | None:
        if key not in self.stats:
            return None
        med, scale = self.stats[key]
        return (value - med) / scale if scale else 0.0

    def to_dict(self) -> dict:
        return {"type": "robust", "stats": {k: [round(m, 4), round(s, 4)] for k, (m, s) in self.stats.items()}}

    @classmethod
    def from_dict(cls, data: dict) -> "RobustBaseline":
        return cls({k: (v[0], v[1]) for k, v in data["stats"].items()})


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    n = len(values)
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def _floor(values: list[float]) -> float:
    """A minimum scale so a constant metric does not make every deviation infinite."""
    spread = (max(values) - min(values)) if values else 0.0
    return max(spread * 0.05, 0.5)


# ------------------------------------------------------------------ evaluation
def split(n: int, test_fraction: float = 0.2, seed: int = 11) -> tuple[list[int], list[int]]:
    idx = list(range(n))
    random.Random(seed).shuffle(idx)
    cut = int(n * (1 - test_fraction))
    return idx[:cut], idx[cut:]


def auc(scores: list[float], labels: list[int]) -> float | None:
    pos = [s for s, l in zip(scores, labels) if l]
    neg = [s for s, l in zip(scores, labels) if not l]
    if not pos or not neg:
        return None
    ranked = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    rank_sum, i = 0.0, 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg = (i + j + 1) / 2
        rank_sum += avg * sum(1 for k in range(i, j) if ranked[k][1])
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def classification_report(pred: list[str], true: list[str]) -> dict:
    classes = sorted(set(true) | set(pred))
    f1s, per = [], {}
    for c in classes:
        tp = sum(1 for p, t in zip(pred, true) if p == c and t == c)
        fp = sum(1 for p, t in zip(pred, true) if p == c and t != c)
        fn = sum(1 for p, t in zip(pred, true) if p != c and t == c)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per[c] = {"precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
                  "support": sum(1 for t in true if t == c)}
        if per[c]["support"]:
            f1s.append(f1)
    accuracy = sum(1 for p, t in zip(pred, true) if p == t) / len(true) if true else 0.0
    return {"accuracy": round(accuracy, 3), "macro_f1": round(sum(f1s) / len(f1s), 3) if f1s else 0.0, "classes": per}


def brier(probs: list[float], labels: list[int]) -> float:
    return sum((p - l) ** 2 for p, l in zip(probs, labels)) / len(labels) if labels else 0.0
