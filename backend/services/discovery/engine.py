"""The discovery engine contract (implemented by RealDiscoveryEngine; the test suite uses a sample-data engine).

Observations are plain dicts so they can be stored in the network metadata:
    {"technique": str, "subject": ip, "facts": dict, "authenticated": bool, "method": str | None,
     "observed_by": ip | None, "detail": str, "simulated": bool}
"""
from __future__ import annotations

from typing import Protocol

SECURE_METHODS = {
    "ssh": "SSH",
    "https-api": "HTTPS / API",
    "snmpv3": "SNMPv3 (authPriv)",
    "snmpv2c": "SNMPv2c (read-only community)",
}
METHOD_ORDER = ("ssh", "https-api", "snmpv3", "snmpv2c")
# SNMPv2c sends its community string in cleartext: it is used only with a read-only community the engineer saved.
CLEARTEXT_METHODS = ("snmpv2c",)


class ProbeResult(dict):
    """{"observations": [...], "timeline": [...], "no_response": [...]}"""


class DiscoveryEngine(Protocol):
    simulated: bool

    def probe(self) -> ProbeResult:
        """Credential-free discovery of the authorized target."""

    def authenticate(self, ip: str, method: str, username: str, secret: str, priv_secret: str | None = None,
                     protocols: tuple[str, str] = ("SHA-256", "AES-128")) -> bool:
        """Try one user-supplied credential once. Never called with guessed or default values."""

    def collect(self, ip: str, method: str) -> list[dict]:
        """Read-only collection after a successful authentication."""


def observation(technique: str, subject: str, facts: dict | None = None, detail: str = "", *, authenticated: bool = False,
                method: str | None = None, observed_by: str | None = None, simulated: bool = False) -> dict:
    return {"technique": technique, "subject": subject, "facts": facts or {}, "authenticated": authenticated,
            "method": method, "observed_by": observed_by, "detail": detail, "simulated": simulated}
