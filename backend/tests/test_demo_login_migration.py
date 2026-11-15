"""The requested demo login must not reset unrelated or subsequently changed accounts."""
import pytest
from sqlalchemy import func, select

from backend.core.config import Settings
from backend.core.errors import AuthenticationError
from backend.core.security import hash_password, verify_password
from backend.database.session import SessionLocal
from backend.models import Network, User
from backend.services import auth_service


def _legacy(db, password="netguard123", role="Network Engineer"):
    for user in db.scalars(select(User)):
        db.delete(user)
    db.commit()
    legacy = User(username="engineer", role=role, password_hash=hash_password(password))
    custom = User(username="lecturer", role="Network Engineer",
                  password_hash=hash_password("custom-password-1"))
    db.add_all([legacy, custom])
    db.flush()
    network = Network(name="Preserved learning network", network_type="Lab", created_by=legacy.id)
    db.add(network)
    db.commit()
    return legacy, custom, network


def _settings(**kwargs):
    return Settings(default_username="admin", default_password="admin", secret_key="test-secret-key", **kwargs)


def test_fresh_install_has_only_the_requested_demo_login(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "engineer", "password": "netguard123"}).status_code == 401
    with SessionLocal() as db:
        assert list(db.scalars(select(User.username))) == ["admin"]


def test_legacy_demo_migrates_once_preserving_ownership_and_other_accounts(client):
    with SessionLocal() as db:
        legacy, custom, network = _legacy(db)
        original_id, network_id, custom_hash = legacy.id, network.id, custom.password_hash
        old_token = auth_service.issue_token(legacy, _settings())

        migrated = auth_service.ensure_default_user(db, _settings())
        assert migrated.id == original_id and migrated.username == "admin"
        assert verify_password("admin", migrated.password_hash)
        assert migrated.token_version == 1
        with pytest.raises(AuthenticationError):
            auth_service.user_from_token(db, old_token, _settings())
        assert db.get(Network, network_id).created_by == original_id
        assert db.scalar(select(func.count(Network.id))) == 1
        assert db.scalar(select(func.count(User.id))) == 2
        assert db.get(User, custom.id).password_hash == custom_hash
        assert auth_service.authenticate(db, "lecturer", "custom-password-1").id == custom.id

        auth_service.change_password(db, migrated, "admin", "later-password-1")
        changed_hash = migrated.password_hash
        again = auth_service.ensure_default_user(db, _settings())
        assert again.id == original_id and again.password_hash == changed_hash
        assert auth_service.authenticate(db, "admin", "later-password-1").id == original_id
        with pytest.raises(AuthenticationError):
            auth_service.authenticate(db, "admin", "admin")


def test_modified_legacy_password_is_not_reset(client):
    with SessionLocal() as db:
        legacy, _, network = _legacy(db, password="changed-legacy-password")
        original_hash = legacy.password_hash
        result = auth_service.ensure_default_user(db, _settings())
        assert result.id == legacy.id and result.username == "engineer"
        assert result.password_hash == original_hash
        assert db.scalar(select(User).where(User.username == "admin")) is None
        assert db.get(Network, network.id).created_by == legacy.id


def test_existing_admin_is_not_overwritten_by_legacy_migration(client):
    with SessionLocal() as db:
        legacy, _, network = _legacy(db)
        admin = User(username="admin", role="Network Engineer",
                     password_hash=hash_password("existing-admin-password"))
        db.add(admin)
        db.commit()
        original_hash = admin.password_hash
        result = auth_service.ensure_default_user(db, _settings())
        assert result.id == admin.id and result.password_hash == original_hash
        assert legacy.username == "engineer" and db.get(Network, network.id).created_by == legacy.id


@pytest.mark.parametrize("field,value", [("role", "Lecturer")])
def test_same_named_custom_account_is_not_treated_as_legacy_seed(client, field, value):
    with SessionLocal() as db:
        legacy, _, _ = _legacy(db, **{field: value})
        original_hash = legacy.password_hash
        auth_service.ensure_default_user(db, _settings())
        assert legacy.username == "engineer" and legacy.password_hash == original_hash


def test_explicit_custom_default_settings_do_not_trigger_demo_migration(client):
    with SessionLocal() as db:
        legacy, _, _ = _legacy(db)
        settings = Settings(default_username="custom-demo", default_password="custom-demo-password",
                            secret_key="test-secret-key")
        auth_service.ensure_default_user(db, settings)
        assert legacy.username == "engineer" and verify_password("netguard123", legacy.password_hash)
