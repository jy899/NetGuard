"""User-owned, encrypted device credential profiles and per-device credential assignments.

Only this service decrypts assignment secrets. Public responses and history snapshots
contain metadata and outcomes, never passwords or encrypted values.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from backend.models import Device, Network, SavedLogin
from backend.models.credential_profile import CredentialAssignment, CredentialProfile


def can_manage(user, network: Network) -> bool:
    """Owner, administrator, or a record without an owner (created before ownership was stored)."""
    from backend.services.account_service import is_admin
    return network.created_by in (None, user.id) or is_admin(user)


def network_for(db: Session, user, network_id: int, manage: bool = False) -> Network:
    """Networks are a shared workspace: every signed-in user can read them (as in the topology view).

    Actions that change a discovery session or use device credentials (manage=True) are limited to the
    network's owner and administrators. Credential assignments themselves stay private to each user.
    """
    row = db.get(Network, network_id)
    if row is None:
        raise NotFoundError("Network not found")
    if manage and not can_manage(user, row):
        raise ForbiddenError("Only the network's owner or an administrator can change this discovery.")
    return row


def profile_for(db: Session, user, profile_id: int) -> CredentialProfile:
    row = db.get(CredentialProfile, profile_id)
    if row is None or row.created_by != user.id:
        raise NotFoundError("Credential profile not found")
    return row


def profile_out(db: Session, row: CredentialProfile) -> dict:
    used = db.scalar(select(func.count(CredentialAssignment.id)).where(CredentialAssignment.profile_id == row.id)) or 0
    return {"id": row.id, "name": row.name, "username": row.username, "port": row.port,
            "priority": row.priority, "notes": row.notes, "has_password": bool(row.password_enc),
            "method": row.method or "ssh", "snmp_auth_protocol": row.snmp_auth_protocol,
            "snmp_priv_protocol": row.snmp_priv_protocol, "has_priv_password": bool(row.priv_password_enc),
            "updated_at": row.updated_at, "used_by": used}


def list_profiles(db: Session, user) -> list[dict]:
    rows = db.scalars(select(CredentialProfile).where(CredentialProfile.created_by == user.id)
                      .order_by(CredentialProfile.priority, CredentialProfile.name))
    return [profile_out(db, row) for row in rows]


def save_profile(db: Session, user, data: dict, profile_id: int | None = None) -> dict:
    name, username = data["name"].strip(), data["username"].strip()
    if (data.get("method") or "ssh") == "snmpv2c":
        username = username or "community"  # an SNMPv2c profile holds only the read-only community string
    if not name or not username:
        raise ValidationFailed("Enter a profile name and device username.")
    duplicate = db.scalar(select(CredentialProfile).where(CredentialProfile.created_by == user.id,
                          func.lower(CredentialProfile.name) == name.lower()))
    if duplicate is not None and duplicate.id != profile_id:
        raise ConflictError("A credential profile with this name already exists.")
    row = profile_for(db, user, profile_id) if profile_id else CredentialProfile(created_by=user.id)
    if not data.get("password") and not profile_id:
        raise ValidationFailed("Enter the device password for the new profile.")
    method = data.get("method") or "ssh"
    if method == "snmpv3":
        auth_secret = data.get("password") or (row.password if row.password_enc else "")
        priv_secret = data.get("priv_password") or (row.priv_password if row.priv_password_enc else "")
        if not priv_secret:
            raise ValidationFailed("Enter the SNMPv3 privacy passphrase (authPriv is required).")
        if len(auth_secret or "") < 8 or len(priv_secret) < 8:
            raise ValidationFailed("SNMPv3 authentication and privacy passphrases need at least 8 characters.")
    row.name, row.username, row.method = name, username, method
    row.port, row.priority, row.notes = data["port"], data["priority"], data.get("notes") or None
    row.snmp_auth_protocol = data.get("snmp_auth_protocol") or ("SHA-256" if method == "snmpv3" else None)
    row.snmp_priv_protocol = data.get("snmp_priv_protocol") or ("AES-128" if method == "snmpv3" else None)
    if data.get("password"):
        row.password = data["password"]
    if method != "snmpv3":
        row.priv_password_enc = None
    elif data.get("priv_password"):
        row.priv_password = data["priv_password"]
    db.add(row)
    affected_networks = set()
    if profile_id:
        for assignment in db.scalars(select(CredentialAssignment).where(CredentialAssignment.profile_id == profile_id)):
            assignment.auth_status, assignment.detail, assignment.tested_at = "untested", "Profile changed; test again.", None
            affected_networks.add(assignment.network_id)
    db.commit()
    db.refresh(row)
    for network_id in affected_networks:
        _refresh_discovery(db, user, network_id)
    return profile_out(db, row)


def delete_profile(db: Session, user, profile_id: int) -> None:
    row = profile_for(db, user, profile_id)
    affected_networks = set()
    for assignment in db.scalars(select(CredentialAssignment).where(CredentialAssignment.profile_id == profile_id)):
        assignment.profile_id = None
        assignment.auth_status, assignment.detail, assignment.tested_at = "untested", "Profile removed; assign credentials again.", None
        affected_networks.add(assignment.network_id)
    db.delete(row)
    db.commit()
    for network_id in affected_networks:
        _refresh_discovery(db, user, network_id)


def assignment_out(db: Session, row: CredentialAssignment) -> dict:
    device = db.get(Device, row.device_id)
    profile = db.get(CredentialProfile, row.profile_id) if row.profile_id else None
    return {"id": row.id, "network_id": row.network_id, "device_id": row.device_id,
            "device_name": device.name if device else "Removed device", "ip": device.management_ip if device else None,
            "scope": row.scope, "profile_id": row.profile_id, "profile_name": profile.name if profile else None,
            "username": profile.username if profile else row.username, "auth_status": row.auth_status,
            "has_password": bool(profile.password_enc if profile else row.password_enc),
            "detail": row.detail, "tested_at": row.tested_at}


def list_assignments(db: Session, user, network_id: int) -> list[dict]:
    network_for(db, user, network_id)
    return [assignment_out(db, row) for row in db.scalars(select(CredentialAssignment)
            .where(CredentialAssignment.user_id == user.id, CredentialAssignment.network_id == network_id)
            .order_by(CredentialAssignment.device_id))]


def _reject_smart(network: Network) -> None:
    if (network.metadata_json or {}).get("method") == "smart":
        raise ValidationFailed("Use the discovery authentication dialog for this network; credentials are not assigned here.")


def assign(db: Session, user, data: dict) -> dict:
    _reject_smart(network_for(db, user, data["network_id"], manage=True))
    devices = list(db.scalars(select(Device).where(Device.network_id == data["network_id"])))
    network = db.get(Network, data["network_id"])
    discovered_ids = (network.metadata_json or {}).get("discovery_can_login")
    eligible = {device.id: device for device in devices if device.device_type in ("router", "switch", "firewall")
                and (discovered_ids is None or device.id in discovered_ids)}
    ids = list(eligible) if data["scope"] == "all" else list(dict.fromkeys(data["device_ids"]))
    if not ids or any(device_id not in eligible for device_id in ids):
        raise ValidationFailed("Select network devices from this network.")
    if data["scope"] == "individual" and len(ids) != 1:
        raise ValidationFailed("Individual credentials apply to one device at a time.")
    profile = profile_for(db, user, data["profile_id"]) if data.get("profile_id") else None
    if profile is not None and (profile.method or "ssh") != "ssh":
        raise ValidationFailed("Device Access for this discovery uses SSH; choose an SSH credential profile.")
    if profile is None and (not data.get("username", "").strip() or not data.get("password")):
        raise ValidationFailed("Choose a saved profile or enter a device username and password.")
    for device_id in ids:
        row = db.scalar(select(CredentialAssignment).where(CredentialAssignment.user_id == user.id,
                        CredentialAssignment.device_id == device_id))
        row = row or CredentialAssignment(user_id=user.id, network_id=data["network_id"], device_id=device_id)
        row.scope, row.profile_id = data["scope"], profile.id if profile else None
        row.username = None if profile else data["username"].strip()
        row.password = None if profile else data["password"]
        row.auth_status, row.detail, row.tested_at = "untested", "Credentials assigned; authentication has not been tested.", None
        db.add(row)
    db.commit()
    _refresh_discovery(db, user, data["network_id"])
    return {"assignments": list_assignments(db, user, data["network_id"])}


def remove_assignment(db: Session, user, assignment_id: int) -> None:
    row = db.get(CredentialAssignment, assignment_id)
    if row is None or row.user_id != user.id:
        raise NotFoundError("Credential assignment not found")
    network_id = row.network_id
    db.delete(row)
    db.commit()
    _refresh_discovery(db, user, network_id)


def _refresh_discovery(db: Session, user, network_id: int) -> None:
    """Assignments do not change the topology; kept as a hook for callers of the earlier workflow."""
    return None


def test_assignments(db: Session, user, network_id: int, device_ids: list[int]) -> dict:
    network = network_for(db, user, network_id, manage=True)
    _reject_smart(network)
    rows = list(db.scalars(select(CredentialAssignment).where(CredentialAssignment.user_id == user.id,
                           CredentialAssignment.network_id == network_id)))
    if device_ids:
        known = {device.id for device in db.scalars(select(Device).where(Device.network_id == network_id))}
        if any(device_id not in known for device_id in device_ids):
            raise ValidationFailed("A selected device does not belong to this network.")
        rows = [row for row in rows if row.device_id in device_ids]
    if not rows:
        raise ValidationFailed("Assign credentials before testing authentication.")
    from backend.collectors import cli
    from backend.services import collection_service
    for row in rows:
        profile = profile_for(db, user, row.profile_id) if row.profile_id else None
        username, password = (profile.username, profile.password) if profile else (row.username, row.password)
        device = db.get(Device, row.device_id)
        try:
            target = collection_service.target_for(device, "ssh", username or "", password or "", None,
                                                   (profile.port if profile else 22) or 22)
            cli.test_login(target)
            row.auth_status, row.detail = "success", "SSH sign-in succeeded (read-only test; no command was run)."
        except cli.AuthFailed:
            row.auth_status, row.detail = "failure", "The device rejected the credentials."
        except (cli.CliError, ValidationFailed) as exc:
            row.auth_status, row.detail = "failure", (getattr(exc, "detail", None) or str(exc))[:200]
        row.tested_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    _refresh_discovery(db, user, network_id)
    assignments = list_assignments(db, user, network_id)
    return {"assignments": assignments, "success": sum(row["auth_status"] == "success" for row in assignments),
            "failure": sum(row["auth_status"] == "failure" for row in assignments)}
