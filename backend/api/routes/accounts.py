from fastapi import APIRouter, Response

from backend.api.deps import AppSettings, CurrentUser, DbSession
from backend.core import vault
from backend.core.access import web_access_enabled
from backend.core.login_throttle import login_throttle
from backend.core.permissions import PERMISSIONS
from backend.schemas.account import AccountCreate, AccountUpdate, GroupIn
from backend.schemas.auth import UserOut
from backend.services import account_service, auth_service

router = APIRouter(tags=['accounts'])


def _device_changes() -> str:
    from backend.services.remediation_service import self_healing_settings

    policy = self_healing_settings()
    return ("Approved changes to laboratory devices; production devices with permission-based self-healing "
            f"(confirmation window {policy['confirm_minutes']} min, hybrid risk limit {policy['max_hybrid_level']})"
            if policy["enabled"] else "Approved changes to laboratory devices only (production self-healing is off)")


@router.get('/account/settings')
def settings(user: CurrentUser, configuration: AppSettings):
    return {'profile': UserOut.model_validate(user), 'is_admin': account_service.is_admin(user),
            'security': {'password_min_length': 8, 'token_expire_minutes': configuration.token_expire_minutes,
                         'login_throttling': True, 'failed_login_limit': login_throttle.max_failures,
                         'encrypted_device_credentials': True, 'vault': 'AES-256-GCM',
                         'key_protection': vault.protection(), 'web_access': web_access_enabled(),
                         'device_changes': _device_changes()}}


@router.get('/permissions')
def permission_catalogue(_: CurrentUser):
    return [{"id": key, "label": label} for key, label in PERMISSIONS.items()]


@router.get('/groups')
def groups(db: DbSession, user: CurrentUser):
    account_service.require_admin(user)
    return [account_service.group_out(db, g) for g in account_service.list_groups(db)]


@router.post('/groups', status_code=201)
def create_group(body: GroupIn, db: DbSession, user: CurrentUser):
    return account_service.group_out(db, account_service.create_group(db, user, body))


@router.put('/groups/{group_id}')
def update_group(group_id: int, body: GroupIn, db: DbSession, user: CurrentUser):
    return account_service.group_out(db, account_service.update_group(db, user, group_id, body))


@router.delete('/groups/{group_id}', status_code=204)
def delete_group(group_id: int, db: DbSession, user: CurrentUser):
    account_service.delete_group(db, user, group_id)
    return Response(status_code=204)


@router.post('/auth/revoke-other-sessions')
def revoke_sessions(db: DbSession, user: CurrentUser, configuration: AppSettings):
    auth_service.revoke_tokens(db, user)
    return {'access_token': auth_service.issue_token(user, configuration), 'token_type': 'bearer',
            'expires_in': configuration.token_expire_minutes * 60, 'user': UserOut.model_validate(user)}


@router.get('/accounts', response_model=list[UserOut])
def accounts(db: DbSession, user: CurrentUser):
    return account_service.list_accounts(db, user)


@router.post('/accounts', response_model=UserOut, status_code=201)
def create(body: AccountCreate, db: DbSession, user: CurrentUser):
    return account_service.create_account(db, user, body)


@router.put('/accounts/{account_id}', response_model=UserOut)
def update(account_id: int, body: AccountUpdate, db: DbSession, user: CurrentUser):
    return account_service.update_account(db, user, account_id, body)


@router.delete('/accounts/{account_id}', status_code=204)
def delete(account_id: int, db: DbSession, user: CurrentUser):
    account_service.delete_account(db, user, account_id)
    return Response(status_code=204)
