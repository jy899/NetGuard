"""Test fixtures: every test runs against a fresh temporary SQLite database."""
import os
import tempfile
from pathlib import Path

import pytest

_TMP_DIR = tempfile.mkdtemp(prefix="netguard-tests-")
os.environ["NETGUARD_DATABASE_URL"] = f"sqlite:///{Path(_TMP_DIR, 'test.db').as_posix()}"
os.environ.setdefault("NETGUARD_SECRET_KEY", "test-secret-key")
os.environ["NETGUARD_VAULT_KEY_FILE"] = str(Path(_TMP_DIR, "vault.key"))
os.environ["NETGUARD_SETTINGS_FILE"] = str(Path(_TMP_DIR, "settings.json"))
os.environ["NETGUARD_DEFAULT_USER"] = "admin"
os.environ["NETGUARD_DEFAULT_PASSWORD"] = "admin"
os.environ["NETGUARD_AI_AUTO"] = "0"  # tests never retrain the shipped models in the background

from fastapi.testclient import TestClient  # noqa: E402

from backend.core.login_throttle import login_throttle  # noqa: E402
from backend.database.session import Base, engine  # noqa: E402
from backend.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def sample_discovery_engine(monkeypatch):
    """Discovery tests run against the recorded office sample unless a test installs another engine."""
    from backend.services.discovery import service
    from backend.tests.fixtures.sample_engine import SimulatedDiscoveryEngine

    monkeypatch.setattr(service, "engine_factory", lambda target, excluded: SimulatedDiscoveryEngine(target, excluded))


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    login_throttle.reset()
    with TestClient(app) as test_client:  # lifespan creates tables + default user
        yield test_client


@pytest.fixture()
def auth(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture()
def network(client, auth):
    response = client.post(
        "/api/networks",
        json={"name": "HQ Enterprise Network", "description": "Demo", "network_type": "Enterprise"},
        headers=auth,
    )
    assert response.status_code == 201
    return response.json()
