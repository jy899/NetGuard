"""User groups and granular permissions.

Every account belongs to one user group; a group grants a set of permissions. Administrators create, edit and
delete groups and choose their permissions. Three groups are built in (their permissions can be edited, the groups
cannot be deleted):

* Administrators: every permission.
* Network Engineers: build, import, discover, collect, analyse, propose and execute approved laboratory changes.
* IT Managers: read everything, run analyses and save reports, approve or reject changes.

Separation of duties does not depend on the groups alone: a change can never be approved by the account that
submitted it. The built-in ``admin`` account always keeps every permission, so the system cannot be locked out.
"""
from __future__ import annotations

import re

from fastapi import Request

from backend.core.errors import ForbiddenError

VIEW = "topology.view"
EDIT = "network.edit"
IMPORT_EXPORT = "network.import_export"
DISCOVERY = "discovery.run"
ANALYSIS = "analysis.run"
PROPOSE = "change.propose"
APPROVE = "change.approve"
EXECUTE = "change.execute"
CREDENTIALS = "credentials.manage"
USERS = "users.manage"
TERMINAL = "device.terminal"
TERMINAL_CONFIG = "device.terminal_config"
PRODUCTION = "change.execute_production"

PERMISSIONS: dict[str, str] = {
    VIEW: "View networks, topologies, analyses and reports",
    EDIT: "Create and edit networks, devices, links and traffic intents",
    IMPORT_EXPORT: "Import topology projects and configurations; export reports",
    DISCOVERY: "Run network discovery, lab import and configuration collection",
    ANALYSIS: "Run network analysis and save reports",
    PROPOSE: "Propose, validate and submit configuration changes",
    APPROVE: "Approve or reject submitted changes",
    EXECUTE: "Execute approved changes on laboratory devices and record deployments",
    CREDENTIALS: "Manage shared device credential profiles",
    USERS: "Manage user accounts and user groups",
    TERMINAL: "Open device CLI terminals (SSH, Telnet, lab console) and web management portals",
    TERMINAL_CONFIG: "Enter configuration commands in a terminal on a production (real-network) device",
    PRODUCTION: "Execute approved changes on production (real-network) devices (permission-based self-healing)",
}

GROUP_ADMIN, GROUP_ENGINEER, GROUP_MANAGER = "Administrators", "Network Engineers", "IT Managers"
BUILTIN_GROUPS: dict[str, tuple[str, list[str]]] = {
    GROUP_ADMIN: ("Full access, including accounts and groups", list(PERMISSIONS)),
    GROUP_ENGINEER: ("Builds, discovers, analyses and changes networks", [
        VIEW, EDIT, IMPORT_EXPORT, DISCOVERY, ANALYSIS, PROPOSE, EXECUTE, CREDENTIALS, TERMINAL]),
    GROUP_MANAGER: ("Reviews analyses and approves or rejects changes", [VIEW, ANALYSIS, APPROVE, IMPORT_EXPORT]),
}
# Permissions added after a database was created are granted once to the built-in groups whose defaults include them.
ADDED_PERMISSIONS = (TERMINAL, TERMINAL_CONFIG, PRODUCTION)
# Earlier versions stored a fixed role per account.
LEGACY_ROLE_GROUP = {"Administrator": GROUP_ADMIN, "Network Engineer": GROUP_ENGINEER, "IT Manager": GROUP_MANAGER}


def permissions_of(user) -> set[str]:
    if user is None:
        return set()
    if user.username == "admin":
        return set(PERMISSIONS)
    group = getattr(user, "group", None)
    if group is not None:
        return {p for p in (group.permissions or []) if p in PERMISSIONS}
    return set(BUILTIN_GROUPS.get(LEGACY_ROLE_GROUP.get(user.role or "", ""), ("", []))[1])


def has(user, permission: str) -> bool:
    return permission in permissions_of(user)


def require(user, permission: str) -> None:
    if not has(user, permission):
        raise ForbiddenError(f"Your user group does not have the permission: {PERMISSIONS[permission]}.")


def is_admin(user) -> bool:
    return has(user, USERS)


def can_modify(user) -> bool:
    return has(user, PROPOSE)


def can_approve(user) -> bool:
    return has(user, APPROVE)


def require_modify(user) -> None:
    require(user, PROPOSE)


# Write requests and the permission each needs (first match wins; anything else needs network.edit).
_WRITE_RULES: list[tuple[re.Pattern, str | None]] = [(re.compile(p), perm) for p, perm in (
    (r"^/api/auth/", None),
    (r"^/api/(accounts|groups)(/|$)", USERS),
    (r"^/api/credential-profiles(/|$)", CREDENTIALS),
    (r"^/api/changes/\d+/(approve|reject)$", APPROVE),
    (r"^/api/changes/\d+/(execute|apply|confirm|rollback)$", EXECUTE),
    (r"^/api/devices/\d+/(terminal|portals/scan)$", TERMINAL),
    (r"^/api/terminal/", TERMINAL),
    (r"^/api/settings/self-healing$", USERS),
    (r"^/api/changes(/|$)", PROPOSE),
    (r"^/api/assessments/\d+/save$", ANALYSIS),
    (r"^/api/networks/\d+/(analyze|reports)$", ANALYSIS),
    (r"^/api/networks/(import|import-project|samples|scenario|demo)$", IMPORT_EXPORT),
    (r"^/api/(discovery|labs)(/|$)", DISCOVERY),
    (r"^/api/networks/\d+/collect$", DISCOVERY),
    (r"^/api/ai/retrain$", USERS),
    (r"^/api/ai/", ANALYSIS),
)]
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def required_permission(method: str, path: str) -> str | None:
    if method not in _WRITE_METHODS:
        return None if path.startswith(("/api/auth/", "/api/account/", "/api/health")) else VIEW
    for pattern, permission in _WRITE_RULES:
        if pattern.match(path):
            return permission
    return EDIT


def write_allowed(user, request: Request) -> bool:
    permission = required_permission(request.method, request.url.path)
    return permission is None or has(user, permission)
