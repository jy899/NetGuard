// Cytoscape.js setup: styling, element mapping, store synchronisation and
// analysis highlighting. Nodes = devices, edges = links. Affected paths are
// shown by adding status classes to nodes/edges (brief 9.4).
/* global cytoscape */

import { deviceIconFor } from "../device-types.js";

export const nodeId = (deviceId) => `d${deviceId}`;
export const edgeId = (linkId) => `l${linkId}`;

const STYLE = [
  {
    selector: "node",
    style: {
      shape: "round-rectangle",
      width: 54,
      height: 54,
      "background-color": "#ffffff",
      "border-width": 1,
      "border-color": "#cbd3de",
      "background-image": "data(icon)",
      "background-fit": "none",
      "background-width": "76%",
      "background-height": "76%",
      label: "data(displayLabel)",
      "text-wrap": "wrap",
      "text-max-width": 150,
      "text-valign": "bottom",
      "text-halign": "center",
      "text-margin-y": 7,
      "font-family": "Segoe UI, system-ui, sans-serif",
      "font-size": 12,
      "font-weight": 600,
      color: "#1b2533",
      "text-background-color": "#f7f9fc",
      "text-background-opacity": 0.92,
      "text-background-padding": "2px",
      "text-background-shape": "round-rectangle",
      "overlay-opacity": 0,
    },
  },
  { selector: "node:active", style: { "overlay-opacity": 0.06, "overlay-color": "#1f5fbf" } },
  {
    selector: "node:selected",
    style: { "border-width": 3, "border-color": "#1f5fbf", "background-color": "#e8f0fc", color: "#1f5fbf" },
  },
  {
    selector: "node.ng-connect-source",
    style: { "border-width": 3, "border-color": "#1f5fbf", "border-style": "dashed", "background-color": "#e8f0fc" },
  },
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#8492a6",
      "curve-style": "bezier",
      "source-label": "data(sourceLabel)",
      "target-label": "data(targetLabel)",
      "source-text-offset": "data(labelOffset)",
      "target-text-offset": "data(labelOffset)",
      "font-family": "Segoe UI, system-ui, sans-serif",
      "font-size": 10,
      color: "#4b5668",
      "text-background-color": "#ffffff",
      "text-background-opacity": 0.9,
      "text-background-padding": "1.5px",
      "overlay-opacity": 0,
    },
  },
  { selector: 'edge[media = "fibre"]', style: { "line-color": "#0e9bb0" } }, // aqua, like OM3/OM4 fibre jackets
  { selector: "edge:selected", style: { width: 3.5, "line-color": "#1f5fbf", color: "#1f5fbf" } },
  // Line pattern encodes evidence (solid confirmed, long dash inferred, dotted unknown); colour encodes state.
  { selector: 'edge[discoveryStatus = "inferred"]', style: { "line-style": "dashed", "line-dash-pattern": [10, 6], "line-color": "#7a5cc4" } },
  { selector: 'edge[discoveryStatus = "unknown"]', style: { "line-style": "dotted", "line-color": "#a0aabb" } },
  { selector: 'edge[kind = "logical"]', style: { "line-style": "dotted", "line-color": "#5379a0" } },
  { selector: 'edge[discoveryStatus = "logical"]', style: { "line-style": "dotted", "line-color": "#5379a0" } },
  { selector: 'edge[media = "wireless"]', style: { "line-style": "dashed", "line-dash-pattern": [3, 4], "line-color": "#1f9d8a", width: 2.2 } },
  { selector: 'edge[linkState = "down"]', style: { "line-color": "#c62f2f" } },
  { selector: 'edge[linkState = "blocked"]', style: { "line-color": "#c08a1d" } },
  // Discovery completeness / authentication on nodes (smart discoveries only).
  { selector: 'node[discoveryState = "full"]', style: { "border-width": 2, "border-style": "solid", "border-color": "#3f8f63" } },
  { selector: 'node[discoveryState = "partial"]', style: { "border-width": 2, "border-style": "dashed", "border-color": "#7d8798" } },
  { selector: 'node[discoveryState = "auth_required"]', style: { "border-width": 2.5, "border-style": "dashed", "border-color": "#c08a1d" } },
  { selector: 'node[discoveryState = "auth_failed"]', style: { "border-width": 2.5, "border-style": "solid", "border-color": "#c62f2f" } },
  { selector: 'node[discoveryState = "unverified"]', style: { "border-width": 2, "border-style": "dotted", "border-color": "#98a2b3" } },

  // ---- analysis highlighting (risk colour passed in as data(riskColor))
  { selector: ".ng-dim", style: { opacity: 0.32 } },
  {
    selector: "node.ng-on-path",
    style: { opacity: 1, "border-width": 2, "border-color": "data(riskColor)" },
  },
  {
    selector: "node.ng-affected",
    style: {
      opacity: 1, "border-width": 3, "border-color": "data(riskColor)", "background-color": "#fff6ef",
      color: "data(riskColor)", "underlay-color": "data(riskColor)", "underlay-opacity": 0.12, "underlay-padding": 7,
    },
  },
  {
    selector: "node.ng-changed",
    style: { "border-style": "double", "border-width": 5 },
  },
  {
    selector: "edge.ng-on-path",
    style: { opacity: 1, width: 4, "line-color": "data(riskColor)", color: "#1b2533" },
  },
  {
    selector: "edge.ng-fail",
    style: {
      opacity: 1, width: 6, "line-color": "#c62f2f",
      label: "data(failLabel)", "font-size": 11, "font-weight": 700, color: "#9e1f1f",
      "text-background-color": "#fff", "text-background-opacity": 1, "text-background-padding": "3px",
      "text-border-color": "#c62f2f", "text-border-width": 1, "text-border-opacity": 1,
      "text-background-shape": "round-rectangle",
    },
  },
  { selector: "edge.ng-focus", style: { width: 6, "z-index": 10 } },
];

const NODE_SIZE = 54;

/**
 * Interface labels sit near each end of a link. On short links a fixed
 * offset makes the two labels cross, so the offset scales with link length.
 */
function updateLabelOffsets(edges) {
  edges.forEach((edge) => {
    const a = edge.source().position();
    const b = edge.target().position();
    const visible = Math.max(0, Math.hypot(a.x - b.x, a.y - b.y) - NODE_SIZE);
    edge.data("labelOffset", Math.round(Math.min(40, Math.max(10, visible * 0.3))));
  });
}

export function createGraph(container) {
  const cy = cytoscape({
    container,
    style: STYLE,
    elements: [],
    minZoom: 0.2,
    maxZoom: 3,
    boxSelectionEnabled: false,
    selectionType: "single",
  });
  cy.on("position", "node", (event) => updateLabelOffsets(event.target.connectedEdges()));
  cy.on("add", "edge", (event) => updateLabelOffsets(event.target));
  return cy;
}

export const UNKNOWN_PORT = "Unknown Port";
const STATE_TAGS = { auth_required: "Auth required", auth_failed: "Auth failed", unverified: "Unverified" };

function nodeData(device, network = null) {
  const facts = network?.metadata_json?.method === "smart" ? network.metadata_json.discovery?.[String(device.id)] : null;
  const state = facts?.classification?.primary || "";
  const tags = [STATE_TAGS[state], facts?.unknown_row ? "Connection unknown" : null].filter(Boolean);
  const base = device.management_ip && device.name !== device.management_ip ? `${device.name}\n${device.management_ip}` : device.name;
  return {
    id: nodeId(device.id),
    deviceId: device.id,
    label: device.name,
    discoveryState: state,
    displayLabel: tags.length ? `${base}\n${tags.join(" · ")}` : base,
    type: device.device_type,
    role: device.role || device.device_type,
    icon: deviceIconFor(device),
  };
}

function edgeData(link) {
  const kind = ['segment', 'route', 'logical', 'tunnel', 'vpn'].includes(link.kind) ? 'logical' : link.kind || "physical";
  // A logical link (same segment, routed subnet, traceroute hop) or the access-point side of a Wi-Fi association
  // has no port by definition: no "Unknown Port" label clutters it.
  const portless = kind === "logical" || kind === "wireless";
  const label = (name) => (name && name !== UNKNOWN_PORT ? name : portless ? "" : UNKNOWN_PORT);
  return {
    id: edgeId(link.id),
    linkId: link.id,
    source: nodeId(link.source_device_id),
    target: nodeId(link.destination_device_id),
    sourceLabel: label(link.source_interface_name),
    targetLabel: label(link.destination_interface_name),
    kind,
    linkState: link.state || "unknown",
    discoveryStatus: link.discovery_status || "manual",
    media: link.media || (link.source_port_info?.media === link.destination_port_info?.media ? link.source_port_info?.media : null) || "unknown",
    labelOffset: 24,
  };
}

/**
 * Bring the graph in line with the store.
 * Existing nodes keep their on-canvas position (unsaved moves are preserved)
 * unless resetPositions is true.
 */
export function syncGraph(cy, store, { resetPositions = false } = {}) {
  cy.batch(() => {
    const deviceIds = new Set([...store.devices.keys()].map(nodeId));
    const linkIds = new Set([...store.links.keys()].map(edgeId));
    cy.edges().filter((e) => !linkIds.has(e.id())).remove();
    cy.nodes().filter((n) => !deviceIds.has(n.id())).remove();

    for (const device of store.devices.values()) {
      const existing = cy.getElementById(nodeId(device.id));
      const position = { x: device.x_position, y: device.y_position };
      if (existing.nonempty()) {
        existing.data(nodeData(device, store.network));
        if (resetPositions) existing.position(position);
      } else {
        cy.add({ group: "nodes", data: nodeData(device, store.network), position });
      }
    }
    for (const link of store.links.values()) {
      const existing = cy.getElementById(edgeId(link.id));
      if (existing.nonempty()) existing.data({ ...edgeData(link), labelOffset: existing.data("labelOffset") });
      else cy.add({ group: "edges", data: edgeData(link) });
    }
  });
  updateLabelOffsets(cy.edges());
}

export function collectPositions(cy) {
  return cy.nodes().map((node) => ({
    device_id: node.data("deviceId"),
    x: Math.round(node.position("x") * 100) / 100,
    y: Math.round(node.position("y") * 100) / 100,
  }));
}

/** A free spot near the centre of the current viewport for a new device. */
export function freePosition(cy) {
  const extent = cy.extent();
  let x = (extent.x1 + extent.x2) / 2;
  let y = (extent.y1 + extent.y2) / 2;
  const occupied = (px, py) => cy.nodes().some((n) => Math.hypot(n.position("x") - px, n.position("y") - py) < 70);
  for (let i = 0; i < 40 && occupied(x, y); i += 1) {
    x += 80;
    if (i % 5 === 4) {
      x -= 400;
      y += 90;
    }
  }
  return { x: Math.round(x), y: Math.round(y) };
}

export function fitGraph(cy) {
  if (cy.nodes().empty()) {
    cy.reset();
    return;
  }
  cy.fit(cy.elements(), 28);
  if (cy.zoom() > 1.3) {
    cy.zoom(1.3);
    cy.center();
  }
}

/**
 * Highlight an assessment on the canvas.
 * @param {object} view  {color, affectedDeviceIds, changedDeviceId, pathDeviceIds, pathLinkIds, failLinks: Map(linkId -> label)}
 */
export function applyHighlight(cy, view) {
  clearHighlight(cy);
  const pathDevices = new Set(view.pathDeviceIds.map(nodeId));
  const pathLinks = new Set(view.pathLinkIds.map(edgeId));
  const affected = new Set(view.affectedDeviceIds.map(nodeId));
  const failing = new Map([...view.failLinks].map(([id, label]) => [edgeId(id), label]));
  const anything = pathDevices.size || affected.size || failing.size;
  cy.batch(() => {
    cy.elements().data("riskColor", view.color);
    cy.nodes().forEach((node) => {
      const id = node.id();
      if (affected.has(id)) node.addClass("ng-affected");
      else if (pathDevices.has(id)) node.addClass("ng-on-path");
      else if (anything) node.addClass("ng-dim");
      if (view.changedDeviceId && id === nodeId(view.changedDeviceId)) node.addClass("ng-changed");
    });
    cy.edges().forEach((edge) => {
      const id = edge.id();
      if (failing.has(id)) edge.addClass("ng-fail").data("failLabel", failing.get(id));
      else if (pathLinks.has(id)) edge.addClass("ng-on-path");
      else if (anything) edge.addClass("ng-dim");
    });
  });
}

export function focusPath(cy, linkIds) {
  cy.edges().removeClass("ng-focus");
  linkIds.forEach((id) => cy.getElementById(edgeId(id)).addClass("ng-focus"));
}

export function clearHighlight(cy) {
  cy.elements().removeClass("ng-dim ng-on-path ng-affected ng-changed ng-fail ng-focus");
}

export function autoArrange(cy, network = null) {
  if (network?.environment === "real" || network?.source === "discovery") {
    arrangeDiscovered(cy);
    updateLabelOffsets(cy.edges());
    return;
  }
  const roots = cy.nodes('[type = "internet"]');
  const fallback = cy.nodes().sort((a, b) => b.degree() - a.degree()).first();
  cy.layout({
    name: "breadthfirst",
    directed: false,
    roots: roots.nonempty() ? roots : fallback,
    spacingFactor: 1.15,
    padding: 60,
    animate: false,
  }).run();
  updateLabelOffsets(cy.edges());
}

/** Keep each endpoint beneath the infrastructure device carrying its cable. */
function arrangeDiscovered(cy) {
  const infrastructure = cy.nodes().filter(node => ["router", "firewall", "switch", "internet"].includes(node.data("role") || node.data("type")));
  if (!infrastructure.length) return;
  const root = infrastructure.filter(node => ["firewall", "router"].includes(node.data("type"))).first();
  const start = root.length ? root : infrastructure.sort((a, b) => b.degree() - a.degree()).first();
  const depth = new Map([[start.id(), 0]]);
  const queue = [start];
  for (let index = 0; index < queue.length; index += 1) {
    queue[index].neighborhood("node").filter(node => infrastructure.contains(node)).forEach(node => {
      if (depth.has(node.id())) return;
      depth.set(node.id(), depth.get(queue[index].id()) + 1);
      queue.push(node);
    });
  }
  const endpoints = cy.nodes().difference(infrastructure);
  const children = new Map(infrastructure.map(node => [node.id(), []]));
  endpoints.forEach(node => {
    const parent = node.neighborhood("node").filter(peer => infrastructure.contains(peer)).first();
    if (parent.length) children.get(parent.id()).push(node);
  });
  const rows = new Map();
  infrastructure.forEach(node => {
    const level = depth.get(node.id()) ?? 0;
    if (!rows.has(level)) rows.set(level, []);
    rows.get(level).push(node);
  });
  let endpointX = 0;
  cy.batch(() => {
    [...rows].sort(([a], [b]) => b - a).forEach(([level, nodes]) => {
      nodes.sort((a, b) => a.data("label").localeCompare(b.data("label")));
      nodes.forEach(node => {
        const leaves = children.get(node.id()).sort((a, b) => a.data("label").localeCompare(b.data("label")));
        const downstream = node.neighborhood("node").filter(peer => (depth.get(peer.id()) ?? -1) > level);
        let x;
        if (leaves.length) {
          leaves.forEach((leaf, index) => leaf.position({ x: endpointX + index * 155, y: level * 200 + 200 }));
          x = endpointX + (leaves.length - 1) * 155 / 2;
          endpointX += Math.max(1, leaves.length) * 155 + 130;
        } else if (downstream.length) x = downstream.reduce((sum, peer) => sum + peer.position("x"), 0) / downstream.length;
        else { x = endpointX; endpointX += 220; }
        // Endpoints on a core branch occupy their own horizontal interval.
        if (leaves.length && downstream.length) x = (x + downstream.reduce((sum, peer) => sum + peer.position("x"), 0) / downstream.length) / 2;
        node.position({ x, y: level * 200 });
      });
    });
    endpoints.filter(node => !node.neighborhood("node").some(peer => infrastructure.contains(peer))).forEach((node, index) => node.position({ x: endpointX + index * 155, y: 540 }));
  });
}
