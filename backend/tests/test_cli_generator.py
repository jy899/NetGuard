"""Illustrative command templates must match the stored device platform."""
from backend.services.change_detector import detect
from backend.services.cli_generator import HEADER, commands_for

# IOS and ArubaOS-Switch comments start with "!"; a "#" line would be rejected as a command.
IOS_HEADER = "!" + HEADER[1:]
from backend.services.network_model import DeviceM, IfaceM, NetworkModel


def _model(vendor, device_type, name, ip=None, mask=None):
    iface = IfaceM(11, 1, name, ip, mask, 30, "up", None, "access")
    device = DeviceM(1, "TARGET", device_type, None, {11: iface}, vendor=vendor)
    return NetworkModel(1, {1: device}, {}, [])


def test_aruba_access_vlan_commands_are_native():
    model = _model("HPE Aruba", "switch", "5")
    change = detect(model, 1, 11, "access_vlan", {"vlan_id": 20})
    assert commands_for(model, change) == [IOS_HEADER, "configure", "vlan 20", "untagged 5", "exit", "write memory"]


def test_fortios_static_route_commands_use_connected_egress():
    model = _model("Fortinet", "firewall", "wan1", "203.0.113.2", "255.255.255.252")
    change = detect(model, 1, None, "static_route", {
        "action": "add", "destination": "0.0.0.0/0", "next_hop": "203.0.113.1"})
    assert commands_for(model, change) == [
        HEADER, "config router static", "edit 0", "set dst 0.0.0.0 0.0.0.0",
        "set gateway 203.0.113.1", 'set device "wan1"', "next", "end"]


def test_cisco_access_vlan_commands_use_canonical_interface_name():
    model = _model("Cisco", "switch", "GigabitEthernet1/0/1")
    change = detect(model, 1, 11, "access_vlan", {"vlan_id": 20})
    assert commands_for(model, change) == [
        IOS_HEADER, "configure terminal", "interface Gi1/0/1", " switchport mode access",
        " switchport access vlan 20", "end"]


def test_unsupported_platform_does_not_receive_cisco_commands():
    model = _model("Juniper", "switch", "ge-0/0/1")
    change = detect(model, 1, 11, "access_vlan", {"vlan_id": 20})
    assert commands_for(model, change) == [
        HEADER, "# No generic command template for this change; apply manually"]


def test_fortios_route_without_known_egress_requires_manual_action():
    model = _model("Fortinet", "firewall", "internal1", "10.0.0.1", "255.255.255.0")
    change = detect(model, 1, None, "static_route", {
        "action": "add", "destination": "0.0.0.0/0", "next_hop": "203.0.113.1"})
    assert commands_for(model, change) == [
        HEADER, "# No fortios command template for this change; apply manually"]


def test_vendorless_router_gets_manual_action_not_guessed_ios():
    # No stored vendor is no platform evidence: never emit configuration syntax for a guessed platform.
    model = _model(None, "router", "Gi0/0", "10.0.0.1", "255.255.255.0")
    change = detect(model, 1, 11, "interface_status", {"status": "down"})
    assert commands_for(model, change) == [HEADER, "# No generic command template for this change; apply manually"]


def test_cisco_firewall_from_config_import_uses_ios_syntax():
    model = _model("Cisco", "firewall", "GigabitEthernet0/0/1", "10.0.1.1", "255.255.255.252")
    change = detect(model, 1, 11, "interface_status", {"status": "down"})
    assert commands_for(model, change)[1:] == ["configure terminal", "interface Gi0/0/1", " shutdown", "end"]
