// In-memory model of the open network, filled from GET /networks/{id}/topology.
// Cytoscape renders from this store; the store never holds unsaved positions.

export const store = {
  network: null,
  devices: new Map(), // id -> device (with interfaces[])
  links: new Map(), // id -> link
  intents: [], // required flows
};

export function loadTopology(topology) {
  store.network = topology.network;
  store.devices = new Map(topology.devices.map((d) => [d.id, d]));
  store.links = new Map(topology.links.map((l) => [l.id, l]));
  store.intents = topology.intents || [];
}

export function clearTopology() {
  store.network = null;
  store.devices = new Map();
  store.links = new Map();
  store.intents = [];
}

export function sortedDevices() {
  return [...store.devices.values()].sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
}

export function findInterface(interfaceId) {
  if (!interfaceId) return null;
  for (const device of store.devices.values()) {
    const match = device.interfaces.find((i) => i.id === interfaceId);
    if (match) return match;
  }
  return null;
}

export function linksForDevice(deviceId) {
  return [...store.links.values()].filter(
    (l) => l.source_device_id === deviceId || l.destination_device_id === deviceId
  );
}

export function usedInterfaceIds() {
  const used = new Set();
  for (const link of store.links.values()) {
    if (link.source_interface_id) used.add(link.source_interface_id);
    if (link.destination_interface_id) used.add(link.destination_interface_id);
  }
  return used;
}

/** Map interface id -> "Neighbour Gx/x" label for the interface tables. */
export function interfaceNeighbours(deviceId) {
  const result = new Map();
  for (const link of linksForDevice(deviceId)) {
    const isSource = link.source_device_id === deviceId;
    const localIf = isSource ? link.source_interface_id : link.destination_interface_id;
    if (!localIf) continue;
    const peerName = isSource ? link.destination_device_name : link.source_device_name;
    const peerIf = isSource ? link.destination_interface_name : link.source_interface_name;
    result.set(localIf, `${peerName}${peerIf ? " " + peerIf : ""}`);
  }
  return result;
}
