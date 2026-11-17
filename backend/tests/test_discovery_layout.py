"""Discovered maps wrap endpoints into rows instead of one long line."""
from types import SimpleNamespace

from backend.services.discovery.fusion import _layout


def _dev(did, kind, ip):
    return SimpleNamespace(id=did, device_type=kind, management_ip=ip, x_position=0.0, y_position=0.0)


def _link(a, b):
    return SimpleNamespace(source_device_id=a, destination_device_id=b)


def test_thirty_two_endpoints_under_a_firewall_wrap_into_a_grid():
    devices = {1: _dev(1, "firewall", "10.1.40.254")}
    links = []
    for n in range(2, 34):
        devices[n] = _dev(n, "pc", f"10.1.40.{n}")
        links.append(_link(1, n))
    discovery = {str(d): {} for d in devices}
    _layout(devices, discovery, {d.management_ip: d for d in devices.values()}, links, {"10.1.40.254"})
    xs = [d.x_position for d in devices.values()]
    rows = {d.y_position for i, d in devices.items() if i != 1}
    assert max(xs) - min(xs) <= 10 * 190          # at most ten columns wide
    assert len(rows) >= 3                          # wrapped into several rows
    assert all(devices[1].y_position < y for y in rows)
    assert len({(d.x_position, d.y_position) for d in devices.values()}) == len(devices)  # no overlaps


def test_switch_branches_sit_below_the_gateway_endpoints():
    devices = {1: _dev(1, "firewall", "10.0.0.1"), 2: _dev(2, "switch", "10.0.0.2")}
    links = [_link(1, 2)]
    for n in range(3, 23):
        devices[n] = _dev(n, "pc", f"10.0.0.{n}")
        links.append(_link(2 if n % 2 else 1, n))
    discovery = {str(d): {} for d in devices}
    _layout(devices, discovery, {d.management_ip: d for d in devices.values()}, links, {"10.0.0.1"})
    gateway_leaves = [devices[n].y_position for n in range(3, 23) if n % 2 == 0]
    assert devices[2].y_position > max(gateway_leaves)
    switch_leaves = [devices[n].y_position for n in range(3, 23) if n % 2]
    assert min(switch_leaves) > devices[2].y_position
