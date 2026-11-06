"""Discovery API facade: scan, report payload, authentication, skip and confirmation."""
from __future__ import annotations

import ipaddress

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.errors import ValidationFailed
from backend.models import Device, Link
from backend.services import credential_service, history_service, link_service, network_service
from backend.services.discovery import service as smart


def _target(target: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(target.strip(), strict=False)
    except ValueError:
        raise ValidationFailed("Enter a valid IPv4 address or subnet, such as 172.16.10.0/24.") from None


def local_networks() -> dict:
    from backend.collectors import netutil
    return netutil.local_networks(smart.MAX_PREFIX)


def _resolve_target(target: str | None) -> ipaddress.IPv4Network:
    if not (target or "").strip():
        target = local_networks().get("suggested")
        if not target:
            raise ValidationFailed("No active IPv4 interface was found on this computer. Enter the range to discover.")
    return _target(target)


def scan(db: Session, user, target: str | None = None, name: str | None = None, authorized_scope: bool = False,
         excluded: list[str] | None = None, untrusted: list[str] | None = None, auto_credentials: bool = False,
         follow_neighbours: bool = False, max_depth: int = smart.MAX_CRAWL_DEPTH, progress=None) -> dict:
    network_range = _resolve_target(target)
    network = smart.scan(db, user, network_range, name, authorized_scope, excluded, untrusted,
                         auto_credentials=auto_credentials, follow_neighbours=follow_neighbours, max_depth=max_depth,
                         progress=progress)
    out = result(db, user, network.id)
    history_service.record(db, user, network.id, "scan", "Network discovery completed",
                           {"device_count": len(out["devices"]), "link_count": len(out["links"]), "status": "completed"},
                           {"target": str(network_range), "scope": out["report"].get("scope"),
                            "devices": [{k: v for k, v in row.items() if k not in ("provenance", "evidence")}
                                        for row in out["devices"]],
                            "report": out["report"]})
    return out


def result(db: Session, user, network_id: int) -> dict:
    network = credential_service.network_for(db, user, network_id)
    if not smart.is_smart(network):
        raise ValidationFailed("This network was not created by discovery.")
    info = (network.metadata_json or {}).get("discovery", {})
    rows = []
    for device in db.scalars(select(Device).where(Device.network_id == network_id).order_by(Device.id)):
        facts = info.get(str(device.id), {})
        rows.append({"id": device.id, "name": device.name, "ip": device.management_ip,
                     "type": "unknown" if facts.get("identity_unknown") else device.device_type,
                     "vendor": device.vendor, "model": device.model, **facts})
    links = [link_service.to_out(link).model_dump(mode="json") for link in
             db.scalars(select(Link).where(Link.network_id == network_id))]
    out = {"network_id": network.id, "network": network_service.to_out(db, network).model_dump(mode="json"),
           "devices": rows, "links": links, "assignments": credential_service.list_assignments(db, user, network.id),
           "mode": (network.metadata_json or {}).get("mode", "live"),
           "crawl": (network.metadata_json or {}).get("crawl", []),
           "live_device_contact": bool((network.metadata_json or {}).get("live_device_contact", True)),
           "summary": {"found": len(rows), "authenticated": sum(row.get("auth_status") == "success" for row in rows),
                       "observed_links": sum(link.get("discovery_status") == "observed" for link in links),
                       "inferred_links": sum(link.get("discovery_status") == "inferred" for link in links)}}
    return smart.extend_result(db, network, out)


def _network(db, user, network_id):
    network = credential_service.network_for(db, user, network_id, manage=True)
    if not smart.is_smart(network):
        raise ValidationFailed("This network was not created by discovery.")
    return network


def crawl(db: Session, user, network_id: int, follow_neighbours: bool | None = None,
          max_depth: int = smart.MAX_CRAWL_DEPTH) -> dict:
    """Try saved profiles on unread devices and follow their neighbours (for example after adding a profile)."""
    network = _network(db, user, network_id)
    follow = (network.metadata_json or {}).get("scope", {}).get("follow_neighbours", False) if follow_neighbours is None else follow_neighbours
    if follow_neighbours is not None:
        meta = dict(network.metadata_json)
        meta["scope"] = {**meta.get("scope", {}), "follow_neighbours": bool(follow_neighbours)}
        network.metadata_json = meta
        db.commit()
    summary = smart.crawl(db, user, network, follow_neighbours=follow, max_depth=max_depth)
    return {"crawl": summary, "result": result(db, user, network_id)}


def refresh(db: Session, user, network_id: int) -> dict:
    smart.refresh(db, _network(db, user, network_id))
    return result(db, user, network_id)


def authenticate(db: Session, user, network_id: int, data: dict) -> dict:
    outcome = smart.authenticate(db, user, _network(db, user, network_id), data)
    return {**outcome, "result": result(db, user, network_id)}


def skip(db: Session, user, network_id: int, device_ids: list[int], skip_all: bool) -> dict:
    smart.skip(db, user, _network(db, user, network_id), device_ids, skip_all)
    return result(db, user, network_id)


def confirmation(db: Session, user, network_id: int, action: str) -> dict:
    smart.confirmation(db, user, _network(db, user, network_id), action)
    return result(db, user, network_id)


# ------------------------------------------------------------ background scans (live progress)
import threading as _threading
import time as _time
import uuid as _uuid

_JOBS: dict[str, dict] = {}
_JOBS_LOCK = _threading.Lock()
PHASES = {"sweep": "Finding live hosts (ICMP, TCP, ARP)", "services": "Identifying services, names and SNMP agents",
          "identify": "Reading UPnP, banners and certificates", "done": "Correlating evidence",
          "credentials": "Reading devices with your credentials", "neighbours": "Following neighbours"}


def start_scan(db: Session, user, **params) -> dict:
    """Validate and start a scan in the background; poll job_status() for progress and the result."""
    network_range = _resolve_target(params.get("target"))
    if not params.get("authorized_scope"):
        raise ValidationFailed("Confirm that you are authorized to scan this address range before starting discovery.")
    if network_range.prefixlen < smart.MAX_PREFIX:
        raise ValidationFailed(f"Limit discovery to an authorized range of at most a /{smart.MAX_PREFIX} (1,024 addresses).")
    smart.parse_scope(params.get("excluded"), "Excluded addresses")
    smart.parse_scope(params.get("untrusted"), "Untrusted segments")
    job_id = _uuid.uuid4().hex
    total = network_range.num_addresses - (2 if network_range.prefixlen < 31 else 0)
    job = {"id": job_id, "user_id": user.id, "state": "running", "phase": "sweep", "phase_label": PHASES["sweep"],
           "done": 0, "total": max(total, 1), "found": 0, "network_id": None, "error": None,
           "target": str(network_range), "started": _time.time()}
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    params = {**params, "target": str(network_range)}

    def progress(phase, done, total_, found):
        with _JOBS_LOCK:
            job.update(phase=phase, phase_label=PHASES.get(phase, phase))
            if phase == "sweep":
                job.update(done=done, total=max(total_, 1))
            if found is not None:
                job["found"] = found

    def run():
        from backend.database.session import SessionLocal
        from backend.models import User
        with SessionLocal() as session:
            try:
                owner = session.get(User, job["user_id"])
                out = scan(session, owner, progress=progress, **params)
                with _JOBS_LOCK:
                    job.update(state="done", network_id=out["network_id"], found=len(out["devices"]),
                               done=job["total"], phase="complete", phase_label="Discovery complete")
            except Exception as exc:  # noqa: BLE001 - reported to the user through the job status
                session.rollback()
                with _JOBS_LOCK:
                    job.update(state="failed", error=str(exc) or exc.__class__.__name__)
    _threading.Thread(target=run, name=f"netguard-scan-{job_id[:8]}", daemon=True).start()
    return job_status(user, job_id)


def job_status(user, job_id: str) -> dict:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None or job["user_id"] != user.id:
            raise ValidationFailed("This discovery job is not known (it may have ended when NetGuard restarted).")
        out = {k: v for k, v in job.items() if k != "user_id"}
    out["elapsed"] = round(_time.time() - out.pop("started"), 1)
    return out
