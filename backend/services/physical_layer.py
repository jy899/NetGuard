"""Hardware facts used by validation and stored-model forwarding."""
from backend.services.interface_naming import port_info


def link_ports(model, link):
    ends = []
    for did, iid in ((link.a_dev, link.a_if), (link.b_dev, link.b_if)):
        device, iface = model.device(did), model.iface(did, iid)
        info = port_info(device.vendor, device.model, device.type, iface.name) if iface else None
        ends.append((device, iface, info))
    return ends


def media_problem(model, link):
    if (getattr(link, "observation", None) or {}).get("media_override"):
        return None  # verified what-if: compatible cable or transceivers fitted
    ends = link_ports(model, link)
    if not all(iface and info and info["exists"] is True and info["media"] for _, iface, info in ends):
        return None
    if ends[0][2]["media"] == ends[1][2]["media"]:
        return None
    a, b = ends
    reason = (f"{a[0].name} {a[1].name} ({a[2]['label']}) and "
              f"{b[0].name} {b[1].name} ({b[2]['label']}) use incompatible cable media")
    return {"device": a[0].name, "interface": a[1].name, "link_id": link.id, "reason": reason}
