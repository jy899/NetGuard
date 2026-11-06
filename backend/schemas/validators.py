"""Reusable field validators shared by the Pydantic schemas."""
from __future__ import annotations

import ipaddress


def clean_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        # Change parameters arrive as free JSON; a number, list or object is invalid input, not a server error.
        raise ValueError("must be text")
    value = value.strip()
    return value or None


def clean_required_text(value: str, field_label: str) -> str:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field_label} must be text")
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{field_label} is required")
    return value


def validate_ipv4(value: str | None) -> str | None:
    value = clean_optional_text(value)
    if value is None:
        return None
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        raise ValueError(f"'{value}' is not a valid IPv4 address") from None


def validate_subnet_mask(value: str | None) -> str | None:
    """Interface subnet mask: dotted-decimal (255.255.255.0) or prefix form (/24 or 24), /1 to /32.

    A wildcard (inverse) mask such as 0.0.0.255 is rejected instead of being read as /24, and /0 is
    rejected because no interface address can use the whole IPv4 space.
    """
    value = clean_optional_text(value)
    if value is None:
        return None
    prefix_text = value.lstrip("/")
    if prefix_text.isdigit():
        prefix = int(prefix_text)
        if not 1 <= prefix <= 32:
            raise ValueError("Prefix length must be between 1 and 32")
        return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{value}")
    except (ipaddress.NetmaskValueError, ValueError):
        raise ValueError(f"'{value}' is not a valid subnet mask") from None
    if str(network.netmask) != value:
        # ipaddress silently accepts host (wildcard) masks; an interface needs a contiguous netmask.
        raise ValueError(f"'{value}' looks like a wildcard mask; enter the subnet mask {network.netmask} instead")
    if network.prefixlen == 0:
        raise ValueError("Subnet mask 0.0.0.0 (/0) cannot be used on an interface")
    return value


def validate_cidr(value: str | None, field_label: str = "Network") -> str:
    """Normalise '10.20.0.0/24' (host bits are cleared). Required."""
    value = clean_optional_text(value)
    if value is None:
        raise ValueError(f"{field_label} is required")
    try:
        return str(ipaddress.IPv4Network(value, strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        raise ValueError(f"'{value}' is not a valid IPv4 network (use a.b.c.d/nn)") from None


def validate_acl_address(value: str | None) -> str:
    """ACL source/destination: 'any', a host IP, 'host a.b.c.d' or a CIDR network."""
    value = (clean_optional_text(value) or "any").lower()
    if value == "any":
        return "any"
    if value.startswith("host "):
        value = value[5:].strip()
    if "/" not in value:
        value = f"{value}/32"
    return validate_cidr(value, "Address")


def validate_port(value: int | None, protocol: str) -> int | None:
    if value is None:
        return None
    if protocol not in ("tcp", "udp"):
        raise ValueError("A port can only be set for TCP or UDP")
    if not 1 <= value <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return value


def validate_host_address(ip: str | None, mask: str | None) -> None:
    """An interface address must not be the subnet's network or broadcast address (except /31 and /32)."""
    if not ip or not mask:
        return
    iface = ipaddress.IPv4Interface(f"{ip}/{mask}")
    network = iface.network
    if network.prefixlen >= 31:
        return
    if iface.ip == network.network_address:
        raise ValueError(f"{ip} is the network address of {network}; use a host address")
    if iface.ip == network.broadcast_address:
        raise ValueError(f"{ip} is the broadcast address of {network}; use a host address")
