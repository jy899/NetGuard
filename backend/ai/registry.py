"""Model versions for NetGuard AI: every training run is kept as a numbered release, only a release that scores at
least as well as the active one is put into use (champion / challenger), and any release can be restored.

Layout (inside data/models):
    *.json + manifest.json      the active release, loaded by backend.services.ai_engine
    versions/<n>/               every release, including rejected candidates (for the record)
    versions/index.json         release list: number, date, trigger, data used, quality, status
"""
from __future__ import annotations

import json
import shutil
import tempfile
import threading
import time
from pathlib import Path

# Quality keys compared between releases (higher is better) and the tolerance for noise between two trainings.
QUALITY_KEYS = {"change_risk": "auc", "root_cause": "auc", "fix_ranker": "auc", "link_faults": "macro_f1",
                "syslog": "macro_f1"}
TOLERANCE = 0.005
_lock = threading.Lock()


def _versions(model_dir: Path) -> Path:
    return model_dir / "versions"


def _model_files(folder: Path) -> list[Path]:
    return [p for p in folder.glob("*.json")]


def quality(manifest: dict) -> dict:
    metrics = manifest.get("metrics") or {}
    return {name: (metrics.get(name) or {}).get(key) for name, key in QUALITY_KEYS.items()
            if (metrics.get(name) or {}).get(key) is not None}


def read_index(model_dir: Path) -> list[dict]:
    path = _versions(model_dir) / "index.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def _write_index(model_dir: Path, rows: list[dict]) -> None:
    folder = _versions(model_dir)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "index.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")


def ensure_index(model_dir: Path) -> list[dict]:
    """The first time, record the installed models as release 1 ("Shipped")."""
    rows = read_index(model_dir)
    if rows or not (model_dir / "manifest.json").exists():
        return rows
    manifest = json.loads((model_dir / "manifest.json").read_text(encoding="utf-8"))
    target = _versions(model_dir) / "1"
    target.mkdir(parents=True, exist_ok=True)
    for path in _model_files(model_dir):
        shutil.copy2(path, target / path.name)
    rows = [{"release": 1, "trained_at": manifest.get("trained_at"), "trigger": "shipped",
             "local_outcomes": manifest.get("local_outcomes", 0), "quality": quality(manifest), "status": "active",
             "note": "Installed with NetGuard"}]
    _write_index(model_dir, rows)
    return rows


def active(model_dir: Path) -> dict | None:
    return next((row for row in ensure_index(model_dir) if row["status"] == "active"), None)


def compare(candidate: dict, current: dict | None) -> tuple[bool, str]:
    """A candidate is accepted when no quality score drops by more than the tolerance."""
    if not current:
        return True, "First trained release"
    worse = [f"{name} {candidate.get(name, 0):.3f} < {value:.3f}" for name, value in current.get("quality", {}).items()
             if candidate.get(name) is not None and candidate[name] < value - TOLERANCE]
    if worse:
        return False, "Scored lower than the active release: " + ", ".join(worse)
    better = [name for name, value in current.get("quality", {}).items()
              if candidate.get(name) is not None and candidate[name] > value + TOLERANCE]
    return True, ("Better: " + ", ".join(better)) if better else "As good as the active release"


def train_release(model_dir: Path, train_fn, trigger: str) -> dict:
    """Train into a scratch folder, keep it as a new release, and activate it only if it passes the comparison.
    ``train_fn(folder)`` trains and returns the manifest. Returns the index row of the new release."""
    if not _lock.acquire(blocking=False):
        raise RuntimeError("NetGuard AI is already training.")
    try:
        rows = ensure_index(model_dir)
        current = next((row for row in rows if row["status"] == "active"), None)
        with tempfile.TemporaryDirectory() as scratch:
            manifest = train_fn(Path(scratch))
            number = max((row["release"] for row in rows), default=0) + 1
            target = _versions(model_dir) / str(number)
            target.mkdir(parents=True, exist_ok=True)
            for path in _model_files(Path(scratch)):
                shutil.copy2(path, target / path.name)
        scores = quality(manifest)
        accepted, note = compare(scores, current)
        row = {"release": number, "trained_at": manifest.get("trained_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "trigger": trigger, "local_outcomes": manifest.get("local_outcomes", 0), "quality": scores,
               "status": "active" if accepted else "rejected", "note": note}
        if accepted:
            _install(model_dir, target)
            for other in rows:
                if other["status"] == "active":
                    other["status"] = "previous"
        rows.append(row)
        _write_index(model_dir, rows)
        return row
    finally:
        _lock.release()


def restore(model_dir: Path, release: int) -> dict:
    """Put an earlier (or rejected) release back into use."""
    with _lock:
        rows = ensure_index(model_dir)
        row = next((r for r in rows if r["release"] == release), None)
        source = _versions(model_dir) / str(release)
        if row is None or not (source / "manifest.json").exists():
            raise LookupError(f"Release {release} is not stored.")
        _install(model_dir, source)
        for other in rows:
            if other["status"] == "active":
                other["status"] = "previous"
        row["status"] = "active"
        row["note"] = f"Restored {time.strftime('%Y-%m-%d %H:%M', time.localtime())}"
        _write_index(model_dir, rows)
        return row


def _install(model_dir: Path, source: Path) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    for path in _model_files(model_dir):
        path.unlink()
    for path in _model_files(source):
        shutil.copy2(path, model_dir / path.name)


def busy() -> bool:
    return _lock.locked()
