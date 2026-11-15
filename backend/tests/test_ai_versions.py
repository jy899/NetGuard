"""NetGuard AI releases: every training is kept, a weaker release is not put into use, any release can be restored,
and only administrators can retrain, restore or change automatic learning."""
import json
import shutil

import pytest

from backend.ai import registry
from backend.services import ai_engine


@pytest.fixture()
def model_copy(tmp_path, monkeypatch):
    """A private copy of the shipped models, so the tests never touch data/models."""
    target = tmp_path / "models"
    target.mkdir()
    for path in ai_engine.MODEL_DIR.glob("*.json"):
        shutil.copy2(path, target / path.name)
    monkeypatch.setattr(ai_engine, "MODEL_DIR", target)
    ai_engine.reload()
    yield target
    ai_engine.reload()


def _fake_trainer(scores: dict, local: int = 0):
    """Writes one small model file and a manifest with the given quality scores, instead of a 30 s training run."""
    def train_fn(folder):
        manifest = {"model_version": 1, "trained_at": "2026-11-14T00:00:00Z", "local_outcomes": local,
                    "metrics": {name: {key: scores.get(name, 0.99)} for name, key in registry.QUALITY_KEYS.items()}}
        (folder / "manifest.json").write_text(json.dumps(manifest))
        (folder / "marker.json").write_text(json.dumps({"scores": scores}))
        return manifest
    return train_fn


def test_releases_are_kept_and_only_better_or_equal_ones_are_used(model_copy):
    shipped = registry.ensure_index(model_copy)
    assert shipped[0]["release"] == 1 and shipped[0]["status"] == "active" and shipped[0]["trigger"] == "shipped"
    base = shipped[0]["quality"]["change_risk"]

    equal = registry.train_release(model_copy, _fake_trainer({"change_risk": base, "root_cause": 1, "fix_ranker": 1,
                                                              "link_faults": 1, "syslog": 1}, local=12), "auto")
    assert equal["release"] == 2 and equal["status"] == "active" and equal["local_outcomes"] == 12
    assert (model_copy / "marker.json").exists()  # release 2 is installed

    worse = registry.train_release(model_copy, _fake_trainer({"change_risk": base - 0.2}), "manual")
    assert worse["release"] == 3 and worse["status"] == "rejected" and "Scored lower" in worse["note"]
    assert registry.active(model_copy)["release"] == 2  # the weaker release is stored but not used
    assert (model_copy / "versions" / "3" / "manifest.json").exists()

    restored = registry.restore(model_copy, 1)
    assert restored["status"] == "active" and registry.active(model_copy)["release"] == 1
    assert not (model_copy / "marker.json").exists()  # release 1 files are back
    statuses = {row["release"]: row["status"] for row in registry.read_index(model_copy)}
    assert statuses == {1: "active", 2: "previous", 3: "rejected"}


def test_ai_status_lists_releases_and_learning(client, auth, model_copy):
    status = client.get("/api/ai/status", headers=auth).json()
    assert status["release"] == 1 and status["releases"][0]["status"] == "active"
    assert status["learning"] == {"auto": True, "after": 10} and status["new_outcomes"] == 0
    assert client.put("/api/ai/learning", headers=auth, json={"auto": False, "after": 25}).json() == {"auto": False, "after": 25}
    assert client.put("/api/ai/learning", headers=auth, json={"after": 0}).status_code == 422
    client.put("/api/ai/learning", headers=auth, json={"auto": True, "after": 10})


def test_only_administrators_change_the_ai(client, auth, model_copy):
    from backend.tests.helpers import manager_auth

    manager = manager_auth(client, auth)
    assert client.get("/api/ai/status", headers=manager).status_code == 200
    assert client.post("/api/ai/retrain", headers=manager, json={}).status_code == 403
    assert client.post("/api/ai/releases/1/restore", headers=manager).status_code == 403
    assert client.put("/api/ai/learning", headers=manager, json={"auto": False}).status_code == 403
    assert client.post("/api/ai/releases/99/restore", headers=auth).status_code == 404
