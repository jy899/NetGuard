"""Device terminals (WebSocket CLI), web management portals and the multi-vendor driver matrix."""
from __future__ import annotations

import asyncio
import json
import secrets
import threading
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from backend.api.deps import CurrentUser, DbSession
from backend.collectors import drivers, netutil, portals
from backend.core.errors import NotFoundError, ValidationFailed
from backend.models import Device, Network
from backend.services import terminal_service

router = APIRouter(tags=["terminal"])


class TerminalIn(BaseModel):
    transport: str = "auto"       # auto | ssh | telnet | console
    port: int | None = None
    username: str | None = None
    password: str | None = None
    profile_id: int | None = None
    mode: str | None = None       # read-only to force the guard
    accept_new_key: bool = False


def _device(db, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise NotFoundError("Device not found")
    return device


@router.get("/drivers")
def driver_matrix(_: CurrentUser):
    return drivers.matrix()


@router.post("/devices/{device_id}/terminal")
def open_terminal(device_id: int, payload: TerminalIn, db: DbSession, user: CurrentUser):
    return terminal_service.prepare(db, user, _device(db, device_id), payload.model_dump())


@router.websocket("/terminal/ws")
async def terminal_socket(websocket: WebSocket):
    ticket = terminal_service.redeem(websocket.query_params.get("ticket", ""))
    await websocket.accept()
    if ticket is None:
        await websocket.send_text(json.dumps({"type": "error", "message": "The terminal ticket is invalid or expired."}))
        await websocket.close(code=4401)
        return
    cols = int(websocket.query_params.get("cols") or 120)
    rows = int(websocket.query_params.get("rows") or 32)
    loop = asyncio.get_running_loop()
    try:
        channel = await asyncio.to_thread(terminal_service.open_channel, ticket, cols, rows)
    except terminal_service.HostKeyChanged as exc:
        await websocket.send_text(json.dumps({"type": "hostkey", "known": exc.known, "offered": exc.offered,
                                              "message": str(exc) + " Reopen with 'Accept the new host key' only if "
                                                                    "you know why the key changed."}))
        await websocket.close(code=4403)
        return
    except Exception as exc:  # noqa: BLE001 - every connection problem is shown in the terminal
        await websocket.send_text(json.dumps({"type": "error", "message": getattr(exc, "detail", None) or str(exc)}))
        await websocket.close(code=4400)
        return
    guard = terminal_service.Guard(ticket.platform, ticket.guarded)
    started, transcript, last = time.monotonic(), [], [time.monotonic()]
    stop = threading.Event()
    queue: asyncio.Queue = asyncio.Queue()

    def push(item) -> bool:
        try:
            loop.call_soon_threadsafe(queue.put_nowait, item)
            return True
        except RuntimeError:  # the socket's event loop has already finished
            return False

    def reader():
        while not stop.is_set():
            try:
                data = channel.recv()
            except Exception:  # noqa: BLE001 - EOF, socket errors and transport teardown all end the session
                push(None)
                return
            if data and not push(data):
                return
    threading.Thread(target=reader, daemon=True, name=f"terminal-{ticket.device_id}").start()
    await websocket.send_text(json.dumps({"type": "ready", "mode": "read-only" if ticket.guarded else "full",
                                          "host_key": getattr(channel, "fingerprint", None),
                                          "platform": drivers.get(ticket.platform).label}))

    async def pump_out():
        while True:
            data = await queue.get()
            if data is None:
                await websocket.send_text(json.dumps({"type": "closed", "message": "The device closed the session."}))
                return "device closed"
            text = data.decode("utf-8", "replace")
            if sum(len(t) for t in transcript) < terminal_service.TRANSCRIPT_LIMIT:
                transcript.append(text)
            await websocket.send_text(json.dumps({"type": "output", "data": text}))

    async def pump_in():
        while True:
            message = json.loads(await websocket.receive_text())
            last[0] = time.monotonic()
            if message.get("type") == "resize":
                channel.resize(int(message.get("cols", 120)), int(message.get("rows", 32)))
            elif message.get("type") == "input":
                data, notice = guard.feed(str(message.get("data", "")).encode("utf-8"))
                if data:
                    await asyncio.to_thread(channel.send, data)
                if notice:
                    await websocket.send_text(json.dumps({"type": "notice", "message": notice}))

    async def idle():
        while True:
            await asyncio.sleep(30)
            if time.monotonic() - last[0] > terminal_service.IDLE_TIMEOUT:
                await websocket.send_text(json.dumps({"type": "closed", "message": "Closed after 30 minutes without input."}))
                return "idle timeout"
    reason = "closed by the user"
    tasks = [asyncio.create_task(pump_out()), asyncio.create_task(pump_in()), asyncio.create_task(idle())]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            try:
                reason = task.result() or reason
            except (WebSocketDisconnect, RuntimeError):
                reason = "closed by the user"
            except Exception:  # noqa: BLE001
                reason = "connection error"
        for task in pending:
            task.cancel()
    finally:
        # Synchronous on purpose: the teardown must complete even when the socket task is being cancelled.
        stop.set()
        channel.close()
        terminal_service.record(ticket, started, guard, "".join(transcript), reason, getattr(channel, "fingerprint", None))
        try:
            await websocket.close()
        except (RuntimeError, asyncio.CancelledError, WebSocketDisconnect, OSError):
            pass  # the browser already closed the socket
        except Exception:  # noqa: BLE001 - uvicorn's ClientDisconnected and similar transport teardown errors
            pass


# ------------------------------------------------------------------ web management portals
def _discovery_facts(db, device: Device) -> tuple[dict, list[dict]]:
    network = db.get(Network, device.network_id)
    meta = (network.metadata_json or {}) if network else {}
    ip = device.management_ip
    sites = []
    for o in meta.get("observations", []):
        if o.get("subject") == ip and o.get("technique") == "web-portal":
            sites = list(o["facts"].get("portals", []))
    scanned = (meta.get("portal_scans") or {}).get(str(device.id), {})
    known = {s["url"] for s in sites}
    sites += [s for s in scanned.get("portals", []) if s["url"] not in known]
    return scanned, sites


@router.get("/devices/{device_id}/portals")
def device_portals(device_id: int, db: DbSession, _: CurrentUser):
    device = _device(db, device_id)
    scanned, sites = _discovery_facts(db, device)
    lab_console = (device.access or {}).get("console") if device.is_lab else None
    return {"device_id": device.id, "ip": device.management_ip, "portals": sites, "lab_console": lab_console,
            "last_scan": {k: scanned.get(k) for k in ("at", "range", "open_ports", "by")} if scanned else None,
            "suggested": [] if sites or not device.management_ip else [
                {"url": f"https://{device.management_ip}/", "verified": False},
                {"url": f"http://{device.management_ip}/", "verified": False}]}


class PortScanIn(BaseModel):
    range: str = "common"   # common | well-known | all


_jobs: dict[str, dict] = {}
_RANGES = {"common": lambda: sorted({*netutil.MANAGEMENT_PORTS, *netutil.WEB_PORTS, *netutil.HOST_PORTS, 161, 2000,
                                    5000, 5001, 8291, 8728, 8729, 9000, 9090, 10000}),
           "well-known": lambda: sorted(set(range(1, 1025)) | {*netutil.WEB_PORTS, 1433, 1521, 1723, 1883, 2000, 3306,
                                                              3389, 5000, 5001, 5060, 5432, 5900, 6379, 8000, 8008,
                                                              8081, 8291, 8443, 8728, 8888, 9000, 9090, 9100, 9443,
                                                              10000, 10443}),
           "all": lambda: list(range(1, 65536))}


@router.post("/devices/{device_id}/portals/scan", status_code=202)
def scan_portals(device_id: int, payload: PortScanIn, db: DbSession, user: CurrentUser):
    device = _device(db, device_id)
    if not device.management_ip:
        raise ValidationFailed(f"{device.name} has no IP address to scan.")
    if payload.range not in _RANGES:
        raise ValidationFailed("Choose the common, well-known or all-ports range.")
    network = db.get(Network, device.network_id)
    scope = ((network.metadata_json or {}).get("scope") or {}) if network else {}
    if device.management_ip in {e.split("/")[0] for e in scope.get("excluded", [])}:
        raise ValidationFailed(f"{device.management_ip} is excluded from discovery in this workspace.")
    job_id = secrets.token_hex(8)
    ports = _RANGES[payload.range]()
    _jobs[job_id] = {"id": job_id, "state": "running", "done": 0, "total": len(ports), "open_ports": [], "portals": [],
                     "device_id": device.id, "error": None}
    ip, device_pk, username = device.management_ip, device.id, user.username

    def run():
        job = _jobs[job_id]
        try:
            job["open_ports"] = netutil.port_scan(ip, ports, timeout=0.6 if len(ports) < 2000 else 0.4,
                                                  progress=lambda d, t: job.update(done=d))
            job["done"] = job["total"]
            job["state"] = "identifying"
            job["portals"] = portals.detect(ip, [p for p in job["open_ports"] if p not in (22, 23, 53, 135, 139, 445)])
            from backend.database.session import SessionLocal

            with SessionLocal() as session:
                dev = session.get(Device, device_pk)
                net = session.get(Network, dev.network_id) if dev else None
                if net is not None:
                    meta = dict(net.metadata_json or {})
                    scans = dict(meta.get("portal_scans") or {})
                    scans[str(device_pk)] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "range": payload.range,
                                             "open_ports": job["open_ports"], "portals": job["portals"], "by": username}
                    meta["portal_scans"] = scans
                    net.metadata_json = meta
                    session.commit()
            job["state"] = "done"
        except Exception as exc:  # noqa: BLE001
            job.update(state="failed", error=str(exc)[:200])
    threading.Thread(target=run, daemon=True, name=f"portscan-{device_id}").start()
    return {"job_id": job_id, "total": len(ports)}


@router.get("/terminal/jobs/{job_id}")
def portal_job(job_id: str, _: CurrentUser):
    job = _jobs.get(job_id)
    if job is None:
        raise NotFoundError("Scan job not found")
    return job
