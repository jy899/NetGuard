"""Test-only SNMPv3 agent (pysnmp command responder) serving a fixed set of OIDs on 127.0.0.1.

It answers the unauthenticated engine-discovery exchange like any SNMPv3 agent and authenticated GET/GETNEXT for
one authPriv user, which exercises NetGuard's real SNMPv3 code paths.
"""
from __future__ import annotations

import asyncio
import socket
import threading

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1902
from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Instrum:
    def __init__(self, values: dict[tuple, object]):
        self.values = dict(sorted(values.items()))
        self.keys = list(self.values)

    def read_variables(self, *var_binds, **context):
        return [(name, self.values.get(tuple(name), NoSuchInstance())) for name, _ in var_binds]

    def read_next_variables(self, *var_binds, **context):
        out = []
        for name, _ in var_binds:
            name = tuple(name)
            nxt = next((k for k in self.keys if k > name), None)
            out.append((rfc1902.ObjectName(nxt), self.values[nxt]) if nxt else (rfc1902.ObjectName(name), EndOfMibView()))
        return out

    def write_variables(self, *var_binds, **context):
        raise NotImplementedError


def oid(text: str) -> tuple:
    return tuple(int(x) for x in text.split("."))


class SnmpAgent:
    def __init__(self, values: dict[str, object], user="netguard-ro", auth="Auth-Pass-123", priv="Priv-Pass-456",
                 engine_id: bytes = bytes.fromhex("800000090300500000010000")):
        self.port = _free_udp_port()
        self.values = {oid(k): v for k, v in values.items()}
        self.user, self.auth, self.priv, self.engine_id = user, auth, priv, engine_id
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.ready.wait(10)

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop
        snmp = engine.SnmpEngine(rfc1902.OctetString(self.engine_id))
        config.add_transport(snmp, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", self.port)))
        config.add_v3_user(snmp, self.user, config.USM_AUTH_HMAC192_SHA256, self.auth,
                           config.USM_PRIV_CFB128_AES, self.priv)
        config.add_vacm_user(snmp, 3, self.user, "authPriv", (1,), (1,))
        ctx = context.SnmpContext(snmp)
        ctx.unregister_context_name(b"")
        ctx.register_context_name(b"", _Instrum(self.values))
        cmdrsp.GetCommandResponder(snmp, ctx)
        cmdrsp.NextCommandResponder(snmp, ctx)
        cmdrsp.BulkCommandResponder(snmp, ctx)
        snmp.transport_dispatcher.job_started(1)
        self.snmp = snmp
        self.ready.set()
        try:
            snmp.open_dispatcher()
        except Exception:  # noqa: BLE001 - stopped
            pass

    def close(self):
        try:
            self.snmp.transport_dispatcher.job_finished(1)
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:  # noqa: BLE001
            pass
