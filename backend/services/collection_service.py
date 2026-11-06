"""Read-only configuration collection from devices of a workspace.

Laboratory devices are read through their lab console (EVE-NG/GNS3 telnet console, normally without a login) or
over SSH; other devices only over SSH with user-supplied read-only credentials. Collection never enters
configuration mode. The collected running configuration replaces the configuration-derived model of the device.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.collectors import cli
from backend.core.errors import ValidationFailed
from backend.models import Device, Network
from backend.services import credential_service, device_state, history_service


def _now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def console_target(device: Device) -> tuple[str, int] | None:
    url = (device.access or {}).get("console")
    if not url or not str(url).startswith("telnet://"):
        return None
    parts = urlsplit(url)
    return (parts.hostname, parts.port or 23) if parts.hostname else None


def target_for(device: Device, transport: str, username: str = "", password: str = "", secret: str | None = None,
               port: int = 22) -> cli.Target:
    from backend.collectors import drivers

    platform = device.platform if device.platform in drivers.DRIVERS else (device.access or {}).get("platform")
    platform = "cisco-ios" if platform == "cisco-iosxe" else platform
    if platform not in drivers.DRIVERS:
        platform = drivers.detect(device.vendor, device.model)
    if transport == "console":
        console = console_target(device)
        if console is None or not device.is_lab:
            raise ValidationFailed(f"{device.name} has no laboratory console.")
        host, cport = console
        return cli.Target(host, cport, "telnet", platform, username, password, secret or password or None)
    if not device.management_ip:
        raise ValidationFailed(f"{device.name} has no management IP address for SSH.")
    if not username or not password:
        raise ValidationFailed("Enter the SSH username and password, or choose a saved profile.")
    return cli.Target(device.management_ip, port, "ssh", platform, username, password, secret)


def collect(db: Session, user, network: Network, device_ids: list[int], transport: str = "auto",
            username: str = "", password: str = "", secret: str | None = None, profile_id: int | None = None,
            port: int = 22) -> dict:
    if profile_id:
        profile = credential_service.profile_for(db, user, profile_id)
        if (profile.method or "ssh") != "ssh":
            raise ValidationFailed("Configuration collection uses an SSH credential profile.")
        username, password, port = profile.username, profile.password or "", profile.port or 22
    devices = [d for d in db.scalars(select(Device).where(Device.network_id == network.id, Device.id.in_(device_ids)))]
    if not devices:
        raise ValidationFailed("Select at least one device of this workspace.")
    outcomes = []
    for device in devices:
        mode = transport
        if mode == "auto":
            mode = "ssh" if (username and password and device.management_ip) else "console" if console_target(device) else "ssh"
        try:
            target = target_for(device, mode, username, password, secret, port)
            result = cli.collect(target)
        except (ValidationFailed, cli.CliError) as exc:
            outcomes.append({"device_id": device.id, "name": device.name, "ok": False, "transport": mode,
                             "detail": getattr(exc, "detail", None) or str(exc)})
            continue
        warnings = list(result.warnings)
        if device.device_type in ("router", "switch"):
            device.device_type = cli.device_type(result)
        system = result.system
        device.model = (system.get("model") or device.model or "")[:64] or None
        from backend.collectors import drivers

        device.vendor = device.vendor or drivers.get(result.platform).vendor
        dev, warn = device_state.parse_one(result.running_config, system.get("hostname") or device.name)
        warnings += warn
        snapshot = device_state.store_config(db, device, result.running_config, "lab-console" if mode == "console" else "ssh",
                                             "collected", user)
        summary = {}
        if dev is not None:
            summary = device_state.apply_config(db, device, dev, warnings)
        device_state.apply_operational(db, device, result.ports, result.stp)
        device_state.store_telemetry(device, result.logs, result.ports, _now())
        facts = dict(device.config_facts or {})
        facts["software"] = {"version": system.get("version"), "serial": system.get("serial"), "image": system.get("image")}
        facts["collected_at"], facts["collected_via"] = _now(), mode
        facts["neighbours"] = result.neighbours[:64]
        device.config_facts = facts
        outcomes.append({"device_id": device.id, "name": device.name, "ok": True, "transport": mode,
                         "sha256": snapshot.sha256, "summary": summary, "warnings": warnings[:20],
                         "detail": f"Read-only {'console' if mode == 'console' else 'SSH'} collection completed."})
    meta = dict(network.metadata_json or {})
    meta.pop("configuration_incomplete", None) if all(o["ok"] for o in outcomes) else None
    meta["last_collection"] = {"at": _now(), "devices": len(outcomes), "succeeded": sum(o["ok"] for o in outcomes)}
    network.metadata_json = meta
    db.commit()
    history_service.record(db, user, network.id, "collection", "Configuration collection",
                           {"succeeded": sum(o["ok"] for o in outcomes), "failed": sum(not o["ok"] for o in outcomes),
                            "status": "completed"},
                           {"devices": [{k: o[k] for k in ("name", "ok", "transport", "detail")} for o in outcomes]})
    return {"outcomes": outcomes}
