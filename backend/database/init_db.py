"""Database initialisation.

Usage (from the project root):
    python -m backend.database.init_db           # create tables + default user
    python -m backend.database.init_db --reset   # drop everything first (destructive)
"""
from __future__ import annotations

import argparse

from sqlalchemy import inspect, text

from backend import models  # noqa: F401  (registers tables)
from backend.core.config import get_settings
from backend.database.session import Base, SessionLocal, engine
from backend.services import auth_service


# Columns added after Phase 1. create_all() does not alter existing tables, so a
# pre-existing SQLite database gets these columns added in place automatically.
_ADDED_COLUMNS = {
    "devices": {"default_gateway": "VARCHAR(45)", "is_lab": "BOOLEAN NOT NULL DEFAULT 0", "platform": "VARCHAR(16)",
                "config_facts": "JSON", "access": "JSON", "telemetry": "JSON"},
    "interfaces": {"description": "VARCHAR(120)", "ospf_area": "INTEGER", "mode": "VARCHAR(10)", "speed_mbps": "INTEGER",
                   "allowed_vlans": "JSON", "native_vlan": "INTEGER", "stp_state": "VARCHAR(16)",
                   "duplex": "VARCHAR(8)", "mtu": "INTEGER", "ospf_hello": "INTEGER", "ospf_dead": "INTEGER",
                   "acl_in": "VARCHAR(64)", "acl_out": "VARCHAR(64)", "error_count": "INTEGER"},
    "changes": {"submitted_by": "INTEGER", "submitted_at": "DATETIME", "decided_by": "INTEGER", "decided_at": "DATETIME",
                "decision_note": "VARCHAR(300)", "approved_assessment_id": "INTEGER"},
    "assessments": {"risk_severity": "INTEGER", "risk_impact": "INTEGER", "risk_exposure": "INTEGER",
                    "evidence_confidence": "VARCHAR(10)"},
    "users": {"token_version": "INTEGER NOT NULL DEFAULT 0", "is_active": "BOOLEAN NOT NULL DEFAULT 1",
              "group_id": "INTEGER REFERENCES user_groups(id)"},
    "networks": {"environment": "VARCHAR(16) NOT NULL DEFAULT 'manual'", "source": "VARCHAR(24) NOT NULL DEFAULT 'manual'",
                 "is_simulated": "BOOLEAN NOT NULL DEFAULT 1", "metadata_json": "JSON NOT NULL DEFAULT '{}'"},
    "links": {"kind": "VARCHAR(16)", "state": "VARCHAR(16)", "confidence": "FLOAT", "evidence_json": "TEXT",
              "speed_mbps": "INTEGER"},
    "credential_profiles": {"method": "VARCHAR(16) NOT NULL DEFAULT 'ssh'", "snmp_auth_protocol": "VARCHAR(16)",
                            "snmp_priv_protocol": "VARCHAR(16)", "priv_password_enc": "TEXT"},
}


def _rebuild_table(name: str, model) -> None:
    """Recreate a SQLite table from its current model (dropped columns, new constraints), keeping the rows.

    Foreign-key enforcement is switched off on a dedicated connection outside any transaction (SQLite ignores the
    pragma inside one) and the pool is discarded afterwards, so no connection with enforcement off is reused."""
    from sqlalchemy.schema import CreateTable

    inspector = inspect(engine)
    old = [c["name"] for c in inspector.get_columns(name)]
    shared = [c.name for c in model.__table__.columns if c.name in old]
    create = str(CreateTable(model.__table__).compile(engine)).replace(f"CREATE TABLE {name}", f"CREATE TABLE {name}_rebuild", 1)
    raw = engine.raw_connection()
    try:
        cursor = raw.cursor()
        raw.commit()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute(f"DROP TABLE IF EXISTS {name}_rebuild")
        cursor.execute(create)
        cursor.execute(f"INSERT INTO {name}_rebuild ({', '.join(shared)}) SELECT {', '.join(shared)} FROM {name}")
        cursor.execute(f"DROP TABLE {name}")
        cursor.execute(f"ALTER TABLE {name}_rebuild RENAME TO {name}")
        for index in model.__table__.indexes:
            columns = ", ".join(c.name for c in index.columns)
            unique = "UNIQUE " if index.unique else ""
            cursor.execute(f"CREATE {unique}INDEX IF NOT EXISTS {index.name} ON {name} ({columns})")
        raw.commit()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    finally:
        raw.close()
    engine.dispose()


# Child tables and the column that ties each row to its parent (deleted parents leave nothing behind).
_ORPHAN_RULES = (
    ("devices", "network_id", "networks"), ("links", "network_id", "networks"),
    ("network_intents", "network_id", "networks"), ("changes", "network_id", "networks"),
    ("labs", "network_id", "networks"), ("credential_assignments", "network_id", "networks"),
    ("ai_insights", "network_id", "networks"), ("change_outcomes", "network_id", "networks"),
    ("interfaces", "device_id", "devices"), ("vlans", "device_id", "devices"), ("static_routes", "device_id", "devices"),
    ("acl_rules", "device_id", "devices"), ("device_configs", "device_id", "devices"),
    ("links", "source_device_id", "devices"), ("links", "destination_device_id", "devices"),
    ("network_intents", "source_device_id", "devices"), ("network_intents", "destination_device_id", "devices"),
    ("assessments", "change_id", "changes"), ("change_executions", "change_id", "changes"),
    ("impacts", "assessment_id", "assessments"),
)


def purge_orphans() -> dict[str, int]:
    """Delete rows whose parent no longer exists.

    Earlier versions could delete a network while foreign-key enforcement was off, leaving its devices, links and
    flows behind; SQLite then reused the network ID and the next network showed those old devices. Repeated until
    nothing changes, because removing a device can orphan its interfaces and links."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    removed: dict[str, int] = {}
    with engine.begin() as connection:
        for _ in range(4):
            changed = 0
            for table, column, parent in _ORPHAN_RULES:
                if table not in tables or parent not in tables or column not in {c["name"] for c in inspector.get_columns(table)}:
                    continue
                count = connection.execute(text(
                    f"DELETE FROM {table} WHERE {column} IS NOT NULL AND {column} NOT IN (SELECT id FROM {parent})")).rowcount
                if count:
                    removed[table] = removed.get(table, 0) + count
                    changed += count
            if not changed:
                break
    return removed


def remove_adopted_rows(db) -> int:
    """Remove devices a discovery workspace inherited from a deleted network that had the same ID.

    A discovery workspace's own devices are created by its scan, so a device whose ID is lower than the first one
    the scan created existed before the workspace did: it belongs to the deleted network, not to this scan."""
    from backend.models import Device, Network

    removed = 0
    for network in db.query(Network).filter(Network.source == "discovery"):
        own = [int(key) for key in ((network.metadata_json or {}).get("discovery") or {})]
        if not own:
            continue
        first = min(own)
        for device in db.query(Device).filter(Device.network_id == network.id, Device.id < first):
            db.delete(device)
            removed += 1
    if removed:
        db.commit()
    return removed


def remove_legacy_samples(db) -> int:
    """Delete sample discovery workspaces created by earlier versions (recorded office data, not a real network)."""
    from backend.models import Network

    rows = db.query(Network).filter(Network.source == "simulated-scan").all()
    for row in rows:
        db.delete(row)
    if rows:
        db.commit()
    return len(rows)


def rebuild_changed_tables() -> list[str]:
    """Accounts no longer have an email address; ACL entries belong to named access lists."""
    from backend.models import AclRule, User

    inspector = inspect(engine)
    rebuilt = []
    if inspector.has_table("users") and "email" in {c["name"] for c in inspector.get_columns("users")}:
        _rebuild_table("users", User)
        rebuilt.append("users")
    if inspector.has_table("acl_rules") and "acl_name" not in {c["name"] for c in inspector.get_columns("acl_rules")}:
        _rebuild_table("acl_rules", AclRule)
        rebuilt.append("acl_rules")
    return rebuilt


def upgrade_schema() -> list[str]:
    inspector = inspect(engine)
    added = []
    with engine.begin() as connection:
        for table, columns in _ADDED_COLUMNS.items():
            if not inspector.has_table(table):
                continue
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                    added.append(f"{table}.{name}")
    return added


def reencrypt_legacy(db) -> int:
    """Move secrets written by earlier versions (key derived from the token secret) to the vault key."""
    from backend.core import vault
    from backend.models import CredentialAssignment, CredentialProfile, SavedLogin

    changed = 0
    for model, fields in ((CredentialProfile, ("password_enc", "priv_password_enc")),
                          (CredentialAssignment, ("password_enc",)), (SavedLogin, ("password_enc",))):
        for row in db.query(model):
            for name in fields:
                value = getattr(row, name)
                if vault.is_legacy(value):
                    plain = vault.decrypt(value)
                    if plain is not None:
                        setattr(row, name, vault.encrypt(plain))
                        changed += 1
    # Lab-server logins were only kept by earlier versions; NetGuard no longer stores them, so remove them.
    removed = db.query(SavedLogin).delete()
    if changed or removed:
        db.commit()
    return changed


def correct_model_flags(db) -> None:
    """Earlier versions marked every network as simulated; a hand-built or imported model is not."""
    from backend.models import Network

    changed = db.query(Network).filter(Network.source.in_(("manual", "config-import")), Network.is_simulated.is_(True)) \
        .update({Network.is_simulated: False}, synchronize_session=False)
    if changed:
        db.commit()


def init_db(reset: bool = False) -> None:
    """Create or upgrade the schema. A new database holds the default account only: no network is created."""
    if reset:
        Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    upgrade_schema()
    rebuild_changed_tables()
    purge_orphans()
    settings = get_settings()
    with SessionLocal() as db:
        from backend.services import account_service
        account_service.ensure_groups(db)
        user = auth_service.ensure_default_user(db, settings)
        account_service.ensure_groups(db)
        reencrypt_legacy(db)
        correct_model_flags(db)
        if remove_legacy_samples(db) + remove_adopted_rows(db):
            purge_orphans()


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialise the NetGuard database")
    parser.add_argument("--reset", action="store_true", help="drop all tables first (deletes all data)")
    args = parser.parse_args()
    init_db(reset=args.reset)
    settings = get_settings()
    print(f"Database ready: {settings.database_url}")
    print(f"Default login: {settings.default_username} / (change it after the first sign-in)")


if __name__ == "__main__":
    main()
