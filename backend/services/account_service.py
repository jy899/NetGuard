"""User accounts and user groups (administered by accounts with the users.manage permission)."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.errors import ConflictError, NotFoundError, ValidationFailed
from backend.core.permissions import BUILTIN_GROUPS, GROUP_ADMIN, LEGACY_ROLE_GROUP, PERMISSIONS, USERS, has, require
from backend.core.security import hash_password
from backend.models.user import User, UserGroup


def is_admin(user: User) -> bool:
    return has(user, USERS)


def require_admin(user: User):
    require(user, USERS)


# ------------------------------------------------------------------ groups
def ensure_groups(db: Session) -> None:
    """Create the built-in groups and place accounts from earlier versions (fixed roles) in them."""
    groups = {g.name: g for g in db.scalars(select(UserGroup))}
    for name, (description, permissions) in BUILTIN_GROUPS.items():
        if name not in groups:
            groups[name] = UserGroup(name=name, description=description, permissions=list(permissions), builtin=True)
            db.add(groups[name])
    db.flush()
    from backend.core import access
    from backend.core.permissions import ADDED_PERMISSIONS

    granted = set(access.read_app_settings().get("granted_permissions", []))
    pending = [p for p in ADDED_PERMISSIONS if p not in granted]
    if pending:
        for name, (_, defaults) in BUILTIN_GROUPS.items():
            group = groups.get(name)
            if group is not None:
                group.permissions = list(dict.fromkeys(list(group.permissions or []) + [p for p in pending if p in defaults]))
        try:
            access.write_app_settings(granted_permissions=sorted(granted | set(pending)))
        except OSError:
            pass
    for user in db.scalars(select(User).where(User.group_id.is_(None))):
        group = groups.get(LEGACY_ROLE_GROUP.get(user.role, user.role)) or groups[
            GROUP_ADMIN if user.username == "admin" else "Network Engineers"]
        user.group_id, user.role = group.id, group.name
    db.commit()


def group_out(db: Session, group: UserGroup) -> dict:
    members = db.scalar(select(func.count()).select_from(User).where(User.group_id == group.id)) or 0
    return {"id": group.id, "name": group.name, "description": group.description, "builtin": group.builtin,
            "permissions": [p for p in PERMISSIONS if p in (group.permissions or [])], "members": members}


def list_groups(db: Session) -> list[UserGroup]:
    return list(db.scalars(select(UserGroup).order_by(UserGroup.builtin.desc(), UserGroup.id)))


def _group(db: Session, group_id: int) -> UserGroup:
    group = db.get(UserGroup, group_id)
    if group is None:
        raise NotFoundError('User group not found')
    return group


def _unique_group(db: Session, name: str, except_id: int | None = None) -> None:
    query = select(UserGroup).where(func.lower(UserGroup.name) == name.lower())
    if except_id is not None:
        query = query.where(UserGroup.id != except_id)
    if db.scalar(query) is not None:
        raise ConflictError('A user group with that name already exists')


def create_group(db: Session, user: User, payload) -> UserGroup:
    require_admin(user)
    _unique_group(db, payload.name)
    group = UserGroup(name=payload.name, description=payload.description, permissions=payload.permissions)
    db.add(group)
    db.commit()
    return group


def update_group(db: Session, user: User, group_id: int, payload) -> UserGroup:
    require_admin(user)
    group = _group(db, group_id)
    _unique_group(db, payload.name, except_id=group.id)
    if group.builtin and payload.name != group.name:
        raise ValidationFailed('Built-in groups keep their name; create a new group for a different name')
    if group.id == user.group_id and USERS not in payload.permissions and user.username != "admin":
        raise ValidationFailed('Your own group must keep the permission to manage users and groups')
    if group.name == GROUP_ADMIN and USERS not in payload.permissions:
        raise ValidationFailed('The Administrators group must keep the permission to manage users and groups')
    group.name, group.description, group.permissions = payload.name, payload.description, list(payload.permissions)
    for member in group.members:
        member.role = group.name
    db.commit()
    return group


def delete_group(db: Session, user: User, group_id: int) -> None:
    require_admin(user)
    group = _group(db, group_id)
    if group.builtin:
        raise ValidationFailed('Built-in groups cannot be deleted')
    if group.members:
        raise ValidationFailed('Move the accounts in this group to another group first')
    db.delete(group)
    db.commit()


# ------------------------------------------------------------------ accounts
def list_accounts(db: Session, user: User):
    require_admin(user)
    return list(db.scalars(select(User).order_by(User.id)))


def _unique(db, username):
    # Case-insensitive: "Admin" next to "admin" would only confuse sign-in.
    if db.scalar(select(User).where(func.lower(User.username) == username.lower())) is not None:
        raise ConflictError('That username is already used')


def create_account(db, user, payload):
    require_admin(user)
    _unique(db, payload.username)
    group = _group(db, payload.group_id)
    account = User(username=payload.username, group_id=group.id, role=group.name,
                   password_hash=hash_password(payload.password), is_active=True)
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


def _account(db, account_id):
    account = db.get(User, account_id)
    if account is None:
        raise NotFoundError('Account not found')
    return account


def update_account(db, user, account_id, payload):
    require_admin(user)
    account = _account(db, account_id)
    if payload.is_active is False and (account.id == user.id or account.username == 'admin'):
        raise ValidationFailed('The current account and built-in admin cannot be disabled')
    if payload.group_id is not None and payload.group_id != account.group_id:
        if account.id == user.id:
            raise ValidationFailed('Use another administrator to change your own user group')
        group = _group(db, payload.group_id)
        account.group_id, account.role = group.id, group.name
    if payload.is_active is not None and account.is_active != payload.is_active:
        account.is_active = payload.is_active
        account.token_version += 1
    db.commit()
    db.refresh(account)
    return account


def delete_account(db, user, account_id):
    require_admin(user)
    account = _account(db, account_id)
    if account.id == user.id or account.username == 'admin':
        raise ValidationFailed('The current account and built-in admin cannot be deleted')
    db.delete(account)
    db.commit()
