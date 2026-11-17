"""Approved, verified self-healing on laboratory devices, and permission-based self-healing on production devices.

Only a change that an IT Manager approved is applied to a device. Laboratory devices follow steps 1-5. A production
(real-network) device additionally needs, before anything is sent:
* the administrator setting "permission-based self-healing" switched on (it is off by default);
* the executing account's group to hold change.execute_production;
* separation of duties across three accounts' roles: the approver is neither the submitter nor the executor;
* a platform driver that NetGuard may configure, and a hybrid (rules + AI) risk level within the configured limit;
and then runs with a dead-man's switch: the platform's own revert timer where one exists (Cisco IOS "reload in"
with an unchanged startup configuration, FortiOS cfg-save revert), a live reachability baseline re-checked after
the change, and a confirmation window: a change that is not confirmed in time is rolled back automatically, and
only a confirmed change is saved to the startup configuration.

Laboratory steps:

1. re-validate the change on a fresh copy of the model (the approval is void if the verdict worsened);
2. back up the running configuration (stored encrypted, with its SHA-256);
3. send the generated commands in configuration mode;
4. collect the running configuration again, update the model and verify that the intended state is present,
   that no new rule violation appeared and that no previously working required flow broke;
5. on any failure, restore every changed configuration section from the backup and verify the restoration.

Every step is recorded in a ChangeExecution row and the history.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.collectors import cli
from backend.core.errors import ConflictError, ForbiddenError, ValidationFailed
from backend.core.permissions import EXECUTE, PRODUCTION, has
from backend.models import ChangeExecution, Device, Network
from backend.models.credential_profile import CredentialAssignment
from backend.services import (analysis_service, change_detector, cli_generator, collection_service, config_diff,
                              credential_service, device_state, history_service, impact_engine, model_snapshot,
                              validation_engine)
from backend.services.forwarding import FlowAnalyzer
from backend.services.network_model import load_model

RISK_ORDER = {"DEPLOY": 0, "DEPLOY_WITH_CAUTION": 1, "DO_NOT_DEPLOY": 2}
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
# Who may fix what is decided by group permissions (change.execute, change.execute_production, change.auto_fix);
# these settings only tune the safeguards.
SELF_HEALING_DEFAULTS = {"confirm_minutes": 5, "device_timer": True, "max_hybrid_level": "HIGH",
                         "reachability_check": True}
_pending: dict[int, dict] = {}   # execution id -> in-memory session state (target, backup, timer) until confirmed
_pending_lock = __import__("threading").Lock()


def self_healing_settings() -> dict:
    from backend.core import access

    stored = access.read_app_settings().get("self_healing") or {}
    return {**SELF_HEALING_DEFAULTS, **{k: v for k, v in stored.items() if k in SELF_HEALING_DEFAULTS}}


def update_self_healing(user, values: dict) -> dict:
    from backend.core import access
    from backend.core.permissions import USERS

    if not has(user, USERS):
        raise ForbiddenError("Only an administrator can change the self-healing policy.")
    current = self_healing_settings()
    if "confirm_minutes" in values:
        minutes = int(values["confirm_minutes"])
        if not 2 <= minutes <= 60:
            raise ValidationFailed("The confirmation window must be between 2 and 60 minutes.")
        current["confirm_minutes"] = minutes
    if "device_timer" in values:
        current["device_timer"] = bool(values["device_timer"])
    if "reachability_check" in values:
        current["reachability_check"] = bool(values["reachability_check"])
    if "max_hybrid_level" in values:
        if values["max_hybrid_level"] not in LEVELS:
            raise ValidationFailed("Choose LOW, MEDIUM, HIGH or CRITICAL.")
        current["max_hybrid_level"] = values["max_hybrid_level"]
    access.write_app_settings(self_healing=current)
    return current


def admin_direct(user) -> bool:
    """Auto-Fix: the account's group has change.auto_fix (administrators always do). It removes the wait for a
    second person (approval and separation of duties); backup, verification, the risk limit, the revert timer, the
    confirmation window and automatic rollback all still apply, and "Do not deploy" is never overridden."""
    from backend.core.permissions import AUTO_FIX

    return has(user, AUTO_FIX)


def _authorize_production(db, user, change, device, check) -> None:
    from backend.collectors import drivers

    settings = self_healing_settings()
    direct = admin_direct(user)
    if not has(user, PRODUCTION) and not direct:
        raise ForbiddenError(f"{device.name} is a real-network device. Your user group needs the permission "
                             "\"Apply approved changes to real-network devices\" (Settings > Groups), or apply the "
                             "commands manually and record the change as deployed.")
    if not direct:
        if change.decided_by is not None and change.decided_by == user.id:
            raise ForbiddenError("Separation of duties: the account that approved this change cannot also execute it.")
        if change.submitted_by is not None and change.decided_by == change.submitted_by:
            raise ForbiddenError("Separation of duties: the change was approved by its own submitter.")
    platform = device.platform if device.platform in drivers.DRIVERS else drivers.detect(device.vendor, device.model)
    driver = drivers.get(platform)
    if not driver.configurable or not driver.netmiko_ssh:
        raise ValidationFailed(f"NetGuard does not push configuration to {driver.label}; apply the approved change in "
                               "its management interface and record the deployment.")
    hybrid = (check.get("decision") or {}).get("hybrid") or {}
    level = hybrid.get("level")
    if level and LEVELS.index(level) > LEVELS.index(settings["max_hybrid_level"]):
        raise ConflictError(f"The hybrid (rules + AI) risk of this change is {level}, above the self-healing limit "
                            f"{settings['max_hybrid_level']}. Apply it manually in a maintenance window.")


def _reachability_targets(db, network_id: int, device) -> list[str]:
    """Addresses whose reachability from NetGuard is compared before and after a production change: the changed
    device, every device with a management address and the endpoints of required flows (at most 48)."""
    from backend.models import NetworkIntent

    addresses = [device.management_ip] if device.management_ip else []
    for row in db.scalars(select(Device).where(Device.network_id == network_id, Device.management_ip.is_not(None))):
        addresses.append(row.management_ip)
    for intent in db.scalars(select(NetworkIntent).where(NetworkIntent.network_id == network_id)):
        for did in (intent.source_device_id, intent.destination_device_id):
            row = db.get(Device, did) if did else None
            if row is not None and row.management_ip:
                addresses.append(row.management_ip)
    return list(dict.fromkeys(a for a in addresses if a))[:48]


def _reachable(addresses: list[str]) -> dict[str, bool]:
    from backend.collectors import netutil

    def check(ip):
        return ip, bool(netutil.ping(ip, 700) or any(netutil.tcp_open(ip, port, 0.7) for port in (22, 443, 80)))
    return dict(netutil.parallel(check, addresses, 32))


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _credentials(db: Session, user, device: Device, data: dict) -> tuple[str, str, str | None, int]:
    if data.get("profile_id"):
        profile = credential_service.profile_for(db, user, data["profile_id"])
        return profile.username, profile.password or "", data.get("secret") or None, profile.port or 22
    if data.get("username") and data.get("password"):
        return data["username"].strip(), data["password"], data.get("secret") or None, int(data.get("port") or 22)
    row = db.scalar(select(CredentialAssignment).where(CredentialAssignment.user_id == user.id,
                                                       CredentialAssignment.device_id == device.id))
    if row is not None:
        profile = credential_service.profile_for(db, user, row.profile_id) if row.profile_id else None
        username, password = (profile.username, profile.password) if profile else (row.username, row.password)
        return username or "", password or "", data.get("secret") or None, (profile.port if profile else 22) or 22
    return "", "", data.get("secret") or None, 22


def _target(db: Session, user, device: Device, data: dict) -> cli.Target:
    username, password, secret, port = _credentials(db, user, device, data)
    transport = data.get("transport") or "auto"
    if transport == "auto":
        transport = "ssh" if username and password and device.management_ip else "console"
    return collection_service.target_for(device, transport, username, password, secret, port)


def _state(model, device_id: int, iface_id: int | None, kind: str):
    dev = model.devices.get(device_id)
    if dev is None:
        return None
    iface = dev.interfaces.get(iface_id) if iface_id else None
    if kind == "ip_address":
        return (iface.ip, iface.mask) if iface else None
    if kind == "interface_status":
        return (iface.status == "admin-down") if iface else None
    if kind in ("ospf_area", "ospf_network"):
        return iface.ospf_area if iface else None
    if kind == "access_vlan":
        return (iface.vlan, iface.mode or "access") if iface else None
    if kind == "static_route":
        return sorted((str(r.network), r.next_hop) for r in dev.routes)
    if kind in ("acl_add", "acl_remove"):
        return sorted((r.acl_name or "", r.sequence, r.action, r.protocol, r.source, r.destination, r.port or 0)
                      for r in dev.acl)
    if kind == "vlan_database":
        return sorted(dev.vlans)
    if kind == "interface_settings":
        return (iface.speed_mbps, iface.duplex, iface.mtu, iface.ospf_hello, iface.ospf_dead) if iface else None
    if kind == "trunk_settings":
        return (iface.native_vlan or 1, tuple(iface.allowed_vlans) if iface.allowed_vlans is not None else "all") \
            if iface else None
    if kind == "isolate_endpoint":
        return (iface.vlan, iface.vlan in dev.vlans) if iface else None
    if kind == "acl_reference":
        facts = dev.facts or {}
        return (sorted((r["acl"], r["where"]) for r in facts.get("undefined_acls", [])),
                sorted((r["acl"], r["where"]) for r in facts.get("acl_references", [])))
    if kind == "stp_root":
        return (dev.facts or {}).get("stp_priority")
    if kind == "mgmt_hardening":
        facts = dev.facts or {}
        return ([(l.get("lines"), tuple(l.get("transport") or ()), l.get("access_class")) for l in facts.get("vty", [])],
                facts.get("http_server"), sorted(i.name for i in dev.interfaces.values() if i.status == "admin-down"))
    return None


def _assess(model):
    analyzer = FlowAnalyzer(model)
    flows = impact_engine.build_flows(model, analyzer, audit=True)
    findings = validation_engine.run(model, analyzer, flows, "baseline")
    working = {f.key for f in flows if f.expected and f.baseline.reachable == (f.expected == "allow")}
    return set(findings), working, {f.key: f.name for f in flows}


def _clean(commands: list[str]) -> list[str]:
    """The configuration lines to send: comments, mode wrappers and save commands are handled by the driver."""
    wrappers = {"configure terminal", "end", "configure", "system-view", "return", "write memory", "save", "commit"}
    return [c for c in commands if c.strip() and not c.lstrip().startswith(("!", "#")) and c.strip() not in wrappers]


def device_config_text(db: Session, device: Device, model=None) -> tuple[str, str]:
    """The configuration NetGuard holds for a device: the latest stored one, or one written from the model."""
    stored = device_state.latest_config(db, device.id, ("collected", "post-change", "startup"))
    if stored is not None and (stored.text or "").strip():
        return stored.text, "stored"
    from backend.services import config_render

    model = model or load_model(db, device.network_id)
    dev = model.devices.get(device.id)
    return (config_render.render(dev) if dev else f"hostname {device.name}\n"), "model"


def backup_device(db: Session, user, device: Device, model=None, source: str = "netguard"):
    """Optional backup before a fix: a copy of the configuration NetGuard holds, downloadable later."""
    text, origin = device_config_text(db, device, model)
    row = device_state.store_config(db, device, text, f"{source}-{origin}", "backup", user)
    return row, origin


def execute(db: Session, user, change, data: dict) -> ChangeExecution:
    direct = admin_direct(user)
    if not has(user, EXECUTE) and not direct:
        raise ForbiddenError("Your user group may not apply changes (permission: change.execute).")
    if change.status != "approved" and not direct:
        raise ConflictError("Only an approved change can be executed. Submit it for IT Manager approval first.")
    device = db.get(Device, change.device_id) if change.device_id else None
    if device is None:
        raise ValidationFailed("The target device no longer exists.")
    network = db.get(Network, change.network_id)
    pre = load_model(db, change.network_id)
    detected = change_detector.detect(pre, change.device_id, change.interface_id, change.change_type, change.parameters)
    simulated = bool(network and network.is_simulated)
    allowed, why = cli_generator.automatable(pre.device(change.device_id), change.change_type, change.parameters)
    if not allowed and not simulated:
        raise ValidationFailed(f"This change cannot be applied automatically: {why}.")
    try:
        commands = _clean(cli_generator.commands_for(pre, detected))
    except Exception:  # noqa: BLE001 - a practice network is changed in the model even without a template
        if not simulated:
            raise
        commands = []
    if not commands and not simulated:
        raise ValidationFailed("NetGuard has no command template for this change on this platform; apply it manually.")
    if change.status != "approved":
        # Auto-Fix: approved only once the change is known to be executable, so a refused fix
        # leaves no approval behind.
        from backend.services import approval_service

        approval_service.admin_approve(db, change, user)
    # 1. re-validation on a fresh model copy
    check = analysis_service.run_pipeline(db, change)
    approved = next((a for a in change.assessments if a.id == change.approved_assessment_id), None)
    verdict = check["decision"]["recommendation"]
    if verdict == "DO_NOT_DEPLOY" or (approved and RISK_ORDER[verdict] > RISK_ORDER.get(approved.recommendation, 0)):
        change.status = "analyzed"
        change.approved_assessment_id = None
        db.commit()
        raise ConflictError(f"The network changed since approval: the change is now rated {check['decision']['label']}. "
                            "Validate and submit it again.")
    want_backup = bool(data.get("backup"))
    if simulated:
        return _execute_simulated(db, user, change, device, network, pre, detected, commands, want_backup, check)
    production = not device.is_lab
    if production:
        _authorize_production(db, user, change, device, check)
    expected_model = change_detector.apply(pre, detected)
    expected = _state(expected_model, change.device_id, change.interface_id, change.change_type)
    pre_findings, pre_working, flow_names = _assess(pre)
    target = _target(db, user, device, data)
    execution = ChangeExecution(change_id=change.id, device_id=device.id, device_name=device.name,
                                transport="console" if target.transport == "telnet" else "ssh", status="failed",
                                commands=commands, rollback_commands=[], verification={}, log=[], executed_by=user.id)
    # How the credentials were obtained (never the secret): a saved profile or assignment can be used again to
    # roll the change back if NetGuard restarts during the confirmation window; typed credentials cannot.
    credential_source = {"profile_id": data["profile_id"]} if data.get("profile_id") else \
        {"assignment": True} if not (data.get("username") and data.get("password")) else {"typed": True}
    db.add(execution)
    log = []

    def note(text):
        log.append({"at": _now().isoformat(timespec="seconds"), "step": text})

    # 2. optional backup of the configuration NetGuard holds (the user's choice)
    user_backup = None
    if want_backup:
        user_backup, origin = backup_device(db, user, device, pre)
        note(f"Backup saved: the configuration NetGuard holds for {device.name}"
             f"{' (written from the model)' if origin == 'model' else ''}. Download it any time.")
    # 3. connect and keep a restore point, so the automatic undo can put the device back
    try:
        backup_text = cli.running_config(target)
    except cli.CliError as exc:
        note(f"Could not connect to {device.name}: {exc}. Nothing was changed.")
        execution.log, execution.finished_at = log, _now()
        execution.verification = {"backup": _backup_ref(user_backup)} if user_backup else {}
        db.commit()
        where = f"{target.host}:{target.port}" if getattr(target, "host", None) else device.name
        raise ValidationFailed(f"NetGuard could not connect to {device.name} ({where}): {exc}. Nothing was changed. "
                               "Check the address, the login and that SSH or the console is enabled.") from None
    if not backup_text.strip():
        note("The device returned an empty configuration. Nothing was changed.")
        execution.log, execution.finished_at = log, _now()
        db.commit()
        raise ValidationFailed(f"{device.name} returned an empty configuration; nothing was changed.")
    backup = device_state.store_config(db, device, backup_text, execution.transport, "pre-change", user)
    execution.backup_config_id = backup.id
    note(f"Connected; restore point taken for the automatic undo (SHA-256 {backup.sha256[:16]}…).")
    settings = self_healing_settings()
    baseline, armed = {}, None
    if production:
        if settings["reachability_check"]:
            targets = _reachability_targets(db, change.network_id, device)
            baseline = _reachable(targets)
            note(f"Live reachability baseline: {sum(baseline.values())} of {len(baseline)} address(es) answer from NetGuard.")
        if settings["device_timer"]:
            try:
                from backend.collectors import drivers as _drivers

                same = cli.startup_matches_running(target)
                if _drivers.get(target.platform).revert == "ios-reload" and same is not True:
                    note("Device revert timer not armed: the startup configuration " + (
                        "differs from the running one, so a reload would also discard earlier unsaved changes."
                        if same is False else "could not be compared with the running one.")
                        + " NetGuard's confirmation window still applies.")
                else:
                    armed = cli.arm_revert(target, settings["confirm_minutes"] + 2)
                    if armed:
                        note(f"Device-side dead-man's switch armed: {armed}.")
            except cli.CliError as exc:
                note(f"Device revert timer could not be armed ({exc}); NetGuard's confirmation window still applies.")
    # 3. apply
    before_model = model_snapshot.take(db, change.network_id)
    applied_ok, error = True, None
    try:
        cli.apply_config(target, commands)
        note(f"{len(commands)} configuration command(s) sent.")
    except cli.CliError as exc:
        applied_ok, error = False, str(exc)
        note(f"Applying the change failed: {exc}")
    # 4. verify
    verification = {"intended_state": False, "new_findings": [], "broken_flows": [], "error": error}
    if user_backup is not None:
        verification["backup"] = _backup_ref(user_backup)
    post_text = None
    try:
        post_text = cli.running_config(target)
    except cli.CliError as exc:
        note(f"Post-change configuration could not be read: {exc}")
    if post_text:
        post_cfg = device_state.store_config(db, device, post_text, execution.transport, "post-change", user)
        dev, warnings = device_state.parse_one(post_text, device.name)
        if dev is not None:
            device_state.apply_config(db, device, dev, warnings)
        db.flush()
        post = load_model(db, change.network_id)
        actual = _state(post, change.device_id, change.interface_id, change.change_type)
        post_findings, post_working, names = _assess(post)
        new, revealed = _split_revealed(sorted(f"{rule}|{subject}" for rule, subject in post_findings - pre_findings), check)
        verification.update(
            intended_state=actual == expected, revealed=revealed,
            new_findings=new,
            broken_flows=sorted(names.get(k, k) for k in pre_working - post_working),
            post_sha256=post_cfg.sha256)
        note("Post-change configuration collected and analysed: intended state "
             + ("present" if verification["intended_state"] else "NOT present") +
             f", {len(verification['new_findings'])} new finding(s), {len(verification['broken_flows'])} newly broken flow(s).")
    if production and baseline and applied_ok:
        after = _reachable(list(baseline))
        lost = sorted(ip for ip, ok in baseline.items() if ok and not after.get(ip))
        verification["lost_reachability"] = lost
        note("Live reachability after the change: " + (f"{len(lost)} address(es) no longer answer: {', '.join(lost[:8])}."
                                                         if lost else "every address that answered before still answers."))
    success = applied_ok and post_text is not None and verification["intended_state"] and \
        not verification["new_findings"] and not verification["broken_flows"] and not verification.get("lost_reachability")
    if success and production:
        execution.status = "awaiting_confirm"
        change.status = "awaiting_confirm"
        deadline = _now() + __import__("datetime").timedelta(minutes=settings["confirm_minutes"])
        verification["confirm_by"] = deadline.isoformat(timespec="seconds")
        verification["device_timer"] = armed
        verification["credential_source"] = credential_source
        note(f"Verification passed. Confirm the change by {verification['confirm_by']} UTC, or it is rolled back "
             "automatically" + (" (and the device reverts itself if NetGuard cannot reach it)." if armed else "."))
    elif success:
        execution.status = "applied"
        change.status = "applied"
        note("Verification passed; the change is kept. Undo it any time with Undo Fix on the toolbar.")
    if success:
        verification["undo"] = model_snapshot.changed(before_model, model_snapshot.take(db, change.network_id))
    else:
        # 5. rollback from the backup
        current = post_text
        if current is None:
            try:
                current = cli.running_config(target)
            except cli.CliError:
                current = None
        rollback = config_diff.rollback_commands(backup_text, current) if current else []
        execution.rollback_commands = rollback
        restored = False
        if current is not None and not rollback:
            restored = True  # the device configuration never changed
            note("The configuration is unchanged; no rollback was needed.")
        elif rollback:
            try:
                cli.apply_config(target, rollback)
                note(f"Rollback: {len(rollback)} command(s) sent to restore the backed-up sections.")
                after = cli.running_config(target)
                restored = config_diff.equivalent(backup_text, after)
                device_state.store_config(db, device, after, execution.transport, "post-change", user)
                dev, warnings = device_state.parse_one(after, device.name)
                if dev is not None:
                    device_state.apply_config(db, device, dev, warnings)
                note("Restoration verified: the configuration matches the backup." if restored else
                     "Restoration check failed: " + ", ".join(config_diff.changed_sections(backup_text, after)[:5]))
            except cli.CliError as exc:
                note(f"Rollback failed: {exc}")
        else:
            note("The device could not be read after the change; restore it manually from the stored backup.")
        verification["restored"] = restored
        execution.status = "rolled_back" if restored else "rollback_failed"
        change.status = "rolled_back" if restored else "failed"
        if armed and restored:
            try:
                cli.cancel_revert(target)
                note("Device revert timer cancelled (the configuration is already restored).")
            except cli.CliError as exc:
                note(f"The device revert timer could not be cancelled ({exc}); the device will reload to its saved configuration.")
    execution.verification, execution.log, execution.finished_at = verification, log, _now()
    try:
        from backend.services import ai_engine
        ai_engine.record_execution(db, change, verification, success)  # a real outcome for retraining
        ai_engine.schedule_auto_retrain()
    except Exception:  # noqa: BLE001 - learning from the outcome never blocks recording the execution
        logging.getLogger("netguard.ai").warning("The outcome of change %s was not recorded for AI learning.",
                                                 change.id, exc_info=True)
    meta = dict(network.metadata_json or {})
    meta["last_remediation"] = {"change_id": change.id, "status": execution.status, "at": _now().isoformat(timespec="seconds")}
    network.metadata_json = meta
    db.commit()
    if execution.status == "awaiting_confirm":
        _schedule(execution.id, change.id, user.id, target, backup_text, armed, settings["confirm_minutes"])
    history_service.record(db, user, change.network_id, "remediation",
                           f"{'Production' if production else 'Laboratory'} change {execution.status.replace('_', ' ')}: {device.name}",
                           {"change_id": change.id, "status": execution.status, "transport": execution.transport},
                           {"commands": commands, "rollback_commands": execution.rollback_commands,
                            "verification": verification, "log": log, "backup_sha256": backup.sha256})
    db.refresh(execution)
    return execution


def _backup_ref(row) -> dict:
    return {"id": row.id, "sha256": row.sha256, "at": _now().isoformat(timespec="seconds")}


def _split_revealed(new_keys: list[str], check: dict) -> tuple[list[str], list[str]]:
    """Problems that were hidden behind the fixed fault (predicted by the analysis as "revealed") are not caused by
    the change: report them, but do not undo the fix for them."""
    revealed = {r.get("key") for r in (check or {}).get("revealed", [])}
    return [k for k in new_keys if k not in revealed], [k for k in new_keys if k in revealed]


def _execute_simulated(db: Session, user, change, device, network, pre, detected, commands, want_backup,
                       check) -> ChangeExecution:
    """Practice (offline) network: no device exists, so the fix is applied to NetGuard's own model of it, checked
    the same way (intended state, no new finding, no newly broken flow) and undone if the check fails."""
    from backend.services import apply_service

    execution = ChangeExecution(change_id=change.id, device_id=device.id, device_name=device.name, transport="simulated",
                                status="failed", commands=commands, rollback_commands=[], verification={}, log=[],
                                executed_by=user.id)
    db.add(execution)
    log = []

    def note(text):
        log.append({"at": _now().isoformat(timespec="seconds"), "step": text})

    verification = {"intended_state": False, "new_findings": [], "broken_flows": [], "error": None, "simulated": True}
    if want_backup:
        row, origin = backup_device(db, user, device, pre)
        verification["backup"] = _backup_ref(row)
        note(f"Backup saved: the configuration of {device.name} before the fix. Download it any time.")
    expected = _state(change_detector.apply(pre, detected), change.device_id, change.interface_id, change.change_type)
    pre_findings, pre_working, _ = _assess(pre)
    db.flush()
    before_model = model_snapshot.take(db, change.network_id)
    savepoint = db.begin_nested()
    try:
        apply_service._mutate(db, change)
        db.flush()
        db.expire_all()
        post = load_model(db, change.network_id)
        actual = _state(post, change.device_id, change.interface_id, change.change_type)
        post_findings, post_working, names = _assess(post)
        new, revealed = _split_revealed(sorted(f"{rule}|{subject}" for rule, subject in post_findings - pre_findings), check)
        verification.update(intended_state=actual == expected, new_findings=new, revealed=revealed,
                            broken_flows=sorted(names.get(k, k) for k in pre_working - post_working))
        note(f"Practice network: the fix was applied to NetGuard's model of {device.name}"
             + (f" ({len(commands)} command(s) shown for reference)." if commands else "."))
        note("Checked: intended state " + ("present" if verification["intended_state"] else "NOT present")
             + f", {len(verification['new_findings'])} new problem(s), {len(verification['broken_flows'])} newly broken flow(s).")
        if revealed:
            note(f"{len(revealed)} problem(s) that the fixed fault was hiding are now visible: {', '.join(k.split('|')[0] for k in revealed)}. "
                 "Run Analyze again to fix them.")
    except Exception as exc:  # noqa: BLE001
        verification["error"] = str(exc)
        note(f"Applying the fix to the model failed: {exc}")
    success = verification["intended_state"] and not verification["new_findings"] and not verification["broken_flows"] \
        and not verification["error"]
    if success:
        verification["undo"] = model_snapshot.changed(before_model, model_snapshot.take(db, change.network_id))
        savepoint.commit()
        note("The fix is kept. Undo it any time with Undo Fix on the toolbar.")
    else:
        savepoint.rollback()
        note("The check failed, so the fix was undone; the network is as it was before.")
    db.expire_all()
    execution = db.get(ChangeExecution, execution.id)
    change = db.get(type(change), change.id)
    execution.status = "applied" if success else "rolled_back"
    change.status = "applied" if success else "rolled_back"
    verification["restored"] = not success
    execution.verification, execution.log, execution.finished_at = verification, log, _now()
    network = db.get(Network, change.network_id)
    meta = dict(network.metadata_json or {})
    meta["last_remediation"] = {"change_id": change.id, "status": execution.status, "at": _now().isoformat(timespec="seconds")}
    network.metadata_json = meta
    from backend.services import network_service
    network_service.touch(network)
    db.commit()
    history_service.record(db, user, change.network_id, "remediation",
                           f"Practice fix {execution.status.replace('_', ' ')}: {device.name}",
                           {"change_id": change.id, "status": execution.status, "transport": "simulated"},
                           {"commands": commands, "verification": verification, "log": log})
    db.refresh(execution)
    return execution


# ------------------------------------------------------------------ confirmation window (dead-man's switch)
def _schedule(execution_id, change_id, user_id, target, backup_text, armed, minutes) -> None:
    import threading

    timer = threading.Timer(minutes * 60, _expire, args=(execution_id,))
    timer.daemon = True
    with _pending_lock:
        _pending[execution_id] = {"target": target, "backup": backup_text, "armed": armed, "timer": timer,
                                  "change_id": change_id, "user_id": user_id}
    timer.start()


def _restore(target, backup_text: str) -> tuple[bool, list[str], str | None, str]:
    """Restore the backed-up sections; (restored, rollback commands, configuration after, message)."""
    try:
        current = cli.running_config(target)
    except cli.CliError as exc:
        return False, [], None, f"The device could not be read for the rollback: {exc}"
    rollback = config_diff.rollback_commands(backup_text, current)
    if not rollback:
        return True, [], current, "The configuration already matches the backup."
    try:
        cli.apply_config(target, rollback)
        after = cli.running_config(target)
    except cli.CliError as exc:
        return False, rollback, None, f"Rollback failed: {exc}"
    restored = config_diff.equivalent(backup_text, after)
    return restored, rollback, after, ("Restoration verified: the configuration matches the backup." if restored else
                                       "Restoration check failed: " + ", ".join(config_diff.changed_sections(backup_text, after)[:5]))


def _finish(db, execution: ChangeExecution, change, outcome: str, steps: list[str], extra: dict | None = None) -> None:
    log = list(execution.log or [])
    for text in steps:
        log.append({"at": _now().isoformat(timespec="seconds"), "step": text})
    execution.log = log
    execution.verification = {**(execution.verification or {}), **(extra or {})}
    execution.status = outcome
    change.status = {"applied": "applied", "rolled_back": "rolled_back"}.get(outcome, "failed")
    execution.finished_at = _now()
    db.commit()


def _expire(execution_id: int) -> None:
    from backend.database.session import SessionLocal
    from backend.models import Change, User

    with _pending_lock:
        state = _pending.pop(execution_id, None)
    if state is None:
        return
    with SessionLocal() as db:
        execution = db.get(ChangeExecution, execution_id)
        change = db.get(Change, state["change_id"])
        if execution is None or change is None or execution.status != "awaiting_confirm":
            return
        restored, rollback, after, message = _restore(state["target"], state["backup"])
        steps = ["The change was not confirmed within the confirmation window: automatic rollback.", message]
        if restored and state["armed"]:
            try:
                cli.cancel_revert(state["target"])
                steps.append("Device revert timer cancelled.")
            except cli.CliError:
                steps.append("The device revert timer was left to run (NetGuard could not cancel it).")
        elif not restored and state["armed"]:
            steps.append("NetGuard could not restore the device; its own revert timer restores the saved configuration.")
        execution.rollback_commands = rollback
        _finish(db, execution, change, "rolled_back" if restored else "rollback_failed", steps, {"restored": restored,
                                                                                                "expired": True})
        user = db.get(User, state["user_id"])
        history_service.record(db, user, change.network_id, "remediation",
                               f"Production change rolled back (not confirmed): {execution.device_name}",
                               {"change_id": change.id, "status": execution.status},
                               {"log": execution.log, "rollback_commands": rollback})


def _awaiting(db, change) -> ChangeExecution:
    row = db.scalar(select(ChangeExecution).where(ChangeExecution.change_id == change.id)
                    .order_by(ChangeExecution.id.desc()).limit(1))
    if row is None or row.status != "awaiting_confirm" or change.status != "awaiting_confirm":
        raise ConflictError("This change is not waiting for confirmation.")
    return row


def _deadline_passed(execution) -> bool:
    confirm_by = (execution.verification or {}).get("confirm_by")
    try:
        return bool(confirm_by) and datetime.fromisoformat(confirm_by) <= _now()
    except ValueError:
        return False


def _claim(db, user, change, execution, data: dict) -> dict:
    """Take the confirmation-window state for this execution, exclusively: the expiry timer, a confirmation and a
    manual rollback can never act on the same change at the same time."""
    with _pending_lock:
        state = _pending.pop(execution.id, None)
    if state is not None:
        return state
    if _deadline_passed(execution):
        raise ConflictError("The confirmation window has ended; the change is being rolled back.")
    # NetGuard restarted during the window: the engineer supplies the credentials again (or a saved profile).
    device = db.get(Device, change.device_id)
    from backend.models import DeviceConfig

    backup = db.get(DeviceConfig, execution.backup_config_id) if execution.backup_config_id else None
    source = (execution.verification or {}).get("credential_source") or {}
    creds = {**({"profile_id": source["profile_id"]} if source.get("profile_id") else {}), **data, "transport": "ssh"}
    return {"target": _target(db, user, device, creds), "backup": backup.text if backup else "",
            "armed": (execution.verification or {}).get("device_timer"), "timer": None,
            "change_id": change.id, "user_id": user.id}


def _release(execution_id: int, state: dict) -> None:
    with _pending_lock:
        _pending.setdefault(execution_id, state)


def recover_pending() -> int:
    """At start-up: production changes left waiting for confirmation by a previous NetGuard process. Their timers
    and sessions were lost with the process, so each is re-armed (when the remaining window allows it and the
    credentials came from a saved profile or assignment) or, once the window has passed, rolled back."""
    from backend.database.session import SessionLocal
    from backend.models import Change, User

    count = 0
    with SessionLocal() as db:
        rows = db.scalars(select(ChangeExecution).where(ChangeExecution.status == "awaiting_confirm")).all()
        for execution in rows:
            change = db.get(Change, execution.change_id)
            user = db.get(User, execution.executed_by) if execution.executed_by else None
            device = db.get(Device, execution.device_id) if execution.device_id else None
            if change is None or user is None or device is None:
                if change is not None:
                    _finish(db, execution, change, "rollback_failed", [
                        "NetGuard restarted during the confirmation window and the device or account no longer "
                        "exists: check the device and restore it from the stored backup if needed."], {"restored": False})
                continue
            source = (execution.verification or {}).get("credential_source") or {}
            from backend.models import DeviceConfig

            backup = db.get(DeviceConfig, execution.backup_config_id) if execution.backup_config_id else None
            if source.get("typed") or backup is None:
                _finish(db, execution, change, "rollback_failed", [
                    "NetGuard restarted during the confirmation window; the credentials were typed for this session "
                    "only, so NetGuard cannot roll the change back itself. "
                    + ("The device's own revert timer restores its saved configuration. " if
                       (execution.verification or {}).get("device_timer") else "")
                    + "Verify the device and restore it from the stored backup if needed."], {"restored": False,
                                                                                              "expired": True})
                continue
            try:
                target = _target(db, user, device, {"profile_id": source.get("profile_id"), "transport": "ssh"})
            except Exception:  # noqa: BLE001 - the profile was deleted or is not shared any more
                _finish(db, execution, change, "rollback_failed", [
                    "NetGuard restarted during the confirmation window and the saved credentials are no longer "
                    "available: verify the device and restore it from the stored backup if needed."], {"restored": False})
                continue
            remaining = 0.0
            confirm_by = (execution.verification or {}).get("confirm_by")
            try:
                remaining = (datetime.fromisoformat(confirm_by) - _now()).total_seconds() if confirm_by else 0.0
            except ValueError:
                remaining = 0.0
            _schedule(execution.id, change.id, user.id, target, backup.text,
                      (execution.verification or {}).get("device_timer"), max(remaining, 1.0) / 60)
            count += 1
    return count


def confirm(db: Session, user, change, data: dict) -> ChangeExecution:
    """Keep a verified production change: cancel the revert timers and save the configuration."""
    if not has(user, EXECUTE):
        raise ForbiddenError("Only an engineer who may execute changes can confirm one.")
    execution = _awaiting(db, change)
    state = _claim(db, user, change, execution, data)
    steps = []
    try:
        if state.get("armed"):
            cli.cancel_revert(state["target"])
            steps.append("Device revert timer cancelled.")
        out = cli.save_config(state["target"])
        steps.append("Configuration saved to the startup configuration." if out is not None else "Nothing to save.")
    except cli.CliError as exc:
        _release(execution.id, state)  # the confirmation window keeps running and still rolls back on expiry
        raise ValidationFailed(f"The change could not be confirmed: {exc}. The confirmation window is still running.") from None
    if state.get("timer") is not None:
        state["timer"].cancel()
    steps.append(f"Confirmed by {user.username}; the change is kept.")
    _finish(db, execution, change, "applied", steps, {"confirmed_by": user.username})
    history_service.record(db, user, change.network_id, "remediation", f"Production change confirmed: {execution.device_name}",
                           {"change_id": change.id, "status": "applied"}, {"log": execution.log})
    db.refresh(execution)
    return execution


def rollback_now(db: Session, user, change, data: dict) -> ChangeExecution:
    """Roll back a production change during its confirmation window."""
    if not has(user, EXECUTE):
        raise ForbiddenError("Only an engineer who may execute changes can roll one back.")
    execution = _awaiting(db, change)
    state = _claim(db, user, change, execution, data)
    if state.get("timer") is not None:
        state["timer"].cancel()
    restored, rollback, _, message = _restore(state["target"], state["backup"])
    steps = [f"Rollback requested by {user.username}.", message]
    if restored and state.get("armed"):
        try:
            cli.cancel_revert(state["target"])
            steps.append("Device revert timer cancelled.")
        except cli.CliError:
            steps.append("The device revert timer could not be cancelled; the device will reload to its saved configuration.")
    execution.rollback_commands = rollback
    _finish(db, execution, change, "rolled_back" if restored else "rollback_failed", steps, {"restored": restored})
    history_service.record(db, user, change.network_id, "remediation", f"Production change rolled back: {execution.device_name}",
                           {"change_id": change.id, "status": execution.status}, {"log": execution.log, "rollback_commands": rollback})
    db.refresh(execution)
    return execution


def undo(db: Session, user, change, data: dict) -> ChangeExecution:
    """Undo an applied fix. Practice network: its devices are put back in NetGuard's model. Lab or real device: the
    restore point taken before the fix is put back on the device, then the model is updated from the device."""
    from backend.models import Change, DeviceConfig

    if change.status != "applied":
        raise ConflictError("Only an applied fix can be undone.")
    execution = db.scalar(select(ChangeExecution).where(ChangeExecution.change_id == change.id,
                                                       ChangeExecution.status == "applied")
                          .order_by(ChangeExecution.id.desc()))
    if execution is None:
        raise ConflictError("This change was recorded as deployed outside NetGuard; undo it on the device, then "
                            "collect the configuration again.")
    if not (has(user, EXECUTE) or admin_direct(user)):
        raise ForbiddenError("Your user group may not apply or undo fixes.")
    newer = db.scalar(select(ChangeExecution).join(Change, Change.id == ChangeExecution.change_id)
                      .where(Change.network_id == change.network_id, ChangeExecution.id > execution.id,
                             ChangeExecution.status == "applied").order_by(ChangeExecution.id.desc()))
    if newer is not None:
        raise ConflictError(f"A newer fix on this network is still applied ({newer.device_name}, change #{newer.change_id}). "
                            "Undo fixes from the newest to the oldest.")
    snapshot = (execution.verification or {}).get("undo")
    device = db.get(Device, change.device_id)
    log = list(execution.log or [])

    def note(text):
        log.append({"at": _now().isoformat(timespec="seconds"), "step": text})

    note(f"Undo requested by {user.username}.")
    if execution.transport == "simulated":
        if snapshot is None:
            raise ConflictError("This fix was applied by an earlier NetGuard version that kept no undo record. "
                                "Use Start again on the practice network instead.")
        names = model_snapshot.restore(db, snapshot)
        note(f"Practice network: {', '.join(names) or device.name} put back as before the fix.")
    else:
        if device is None:
            raise ConflictError("The device no longer exists.")
        production = not device.is_lab
        if production and not (has(user, PRODUCTION) or admin_direct(user)):
            raise ForbiddenError("Undoing a fix on a real-network device needs the real-network permission.")
        backup = db.get(DeviceConfig, execution.backup_config_id) if execution.backup_config_id else None
        if backup is None or not (backup.text or "").strip():
            raise ConflictError("No restore point is stored for this fix; undo it on the device by hand.")
        target = _target(db, user, device, data)
        restored, rollback, after, message = _restore(target, backup.text)
        note(message)
        if not restored:
            execution.log = log
            db.commit()
            raise ValidationFailed(f"The fix could not be undone: {message}")
        if production:
            try:
                cli.save_config(target)
                note("Configuration saved to the startup configuration.")
            except cli.CliError as exc:
                note(f"The configuration could not be saved ({exc}); save it on the device.")
        if after:
            device_state.store_config(db, device, after, execution.transport, "post-change", user)
            dev, warnings = device_state.parse_one(after, device.name)
            if dev is not None:
                device_state.apply_config(db, device, dev, warnings)
        execution.rollback_commands = rollback
    note("The fix is undone.")
    execution = db.get(ChangeExecution, execution.id)
    change = db.get(type(change), change.id)
    execution.status = "rolled_back"
    change.status = "rolled_back"
    execution.log = log
    execution.verification = {**(execution.verification or {}), "undone_by": user.username,
                              "undone_at": _now().isoformat(timespec="seconds")}
    network = db.get(Network, change.network_id)
    meta = dict(network.metadata_json or {})
    meta["last_remediation"] = {"change_id": change.id, "status": "undone", "at": _now().isoformat(timespec="seconds")}
    network.metadata_json = meta
    from backend.services import network_service
    network_service.touch(network)
    db.commit()
    history_service.record(db, user, change.network_id, "remediation", f"Fix undone: {execution.device_name}",
                           {"change_id": change.id, "status": "undone", "transport": execution.transport},
                           {"log": log, "rollback_commands": execution.rollback_commands})
    db.refresh(execution)
    return execution


def applied_fixes(db: Session, network_id: int) -> list[dict]:
    """Fixes still applied on a network, newest first, in the order Undo takes them. Only the newest fix applied by
    NetGuard can be undone next; a change recorded as deployed outside NetGuard has no undo record."""
    from backend.models import Change, User
    from backend.services import change_service

    changes = db.scalars(select(Change).where(Change.network_id == network_id, Change.status == "applied")).all()
    rows = []
    for change in changes:
        execution = db.scalar(select(ChangeExecution).where(ChangeExecution.change_id == change.id,
                                                           ChangeExecution.status == "applied")
                              .order_by(ChangeExecution.id.desc()))
        rows.append((change, execution))
    rows.sort(key=lambda r: ((r[1].finished_at or r[1].started_at) if r[1] else r[0].updated_at,
                             r[1].id if r[1] else 0), reverse=True)
    newest = max((e.id for _, e in rows if e is not None), default=None)
    out = []
    for change, execution in rows:
        item = change_service.to_out(db, change).model_dump(mode="json")
        if execution is None:
            item.update(applied_at=item["updated_at"], applied_by=None, transport="recorded", can_undo=False,
                        undo_next=False, undo_note="Recorded as deployed outside NetGuard; undo it on the device.")
        else:
            undo_record = (execution.transport == "simulated" and (execution.verification or {}).get("undo") is not None) \
                or (execution.transport != "simulated" and execution.backup_config_id is not None)
            user = db.get(User, execution.executed_by) if execution.executed_by else None
            item.update(applied_at=(execution.finished_at or execution.started_at).isoformat(),
                        applied_by=user.username if user else None, transport=execution.transport,
                        can_undo=bool(undo_record), undo_next=execution.id == newest and bool(undo_record),
                        undo_note=None if undo_record else "No undo record was kept for this fix.")
        out.append(item)
    return out


def execution_out(row: ChangeExecution) -> dict:
    return {"id": row.id, "change_id": row.change_id, "device_name": row.device_name, "transport": row.transport,
            "status": row.status, "commands": row.commands, "rollback_commands": row.rollback_commands,
            "verification": row.verification, "log": row.log, "started_at": row.started_at,
            "finished_at": row.finished_at}
