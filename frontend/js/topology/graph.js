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
      "control-point-step-size": 70, // parallel cables bow apart so their port labels do not overlap
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
  {
    selector: "edge.ng-bus",
    style: { "curve-style": "taxi", "taxi-direction": "downward", "taxi-turn": 70, "taxi-turn-min-distance": 4, width: 1.4 },
  },
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
  // Up/down monitoring: a device that stopped answering is faded with a red dashed frame (not colour alone: the label says "Down").
  { selector: 'node[reach = "down"]', style: { "border-width": 2, "border-style": "dashed", "border-color": "#c62828", "background-opacity": 0.75, "background-image-opacity": 0.45, color: "#a51d1d" } },

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
  cy.on("dragfree", "node", () => markBusEdges(cy));
  cy.on("add", "edge", (event) => updateLabelOffsets(event.target));
  return cy;
}

export const UNKNOWN_PORT = "Unknown Port";
const STATE_TAGS = { auth_required: "Auth required", auth_failed: "Auth failed", unverified: "Unverified" };

function nodeData(device, network = null) {
  const facts = network?.metadata_json?.method === "smart" ? network.metadata_json.discovery?.[String(device.id)] : null;
  const state = facts?.classification?.primary || "";
  const reach = facts?.reachability?.state || "";
  const tags = [reach === "down" ? "Down" : null, STATE_TAGS[state], facts?.unknown_row ? "Connection unknown" : null].filter(Boolean);
  const base = device.management_ip && device.name !== device.management_ip ? `${device.name}\n${device.management_ip}` : device.name;
  return {
    id: nodeId(device.id),
    deviceId: device.id,
    label: device.name,
    discoveryState: state,
    reach,
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
  markBusEdges(cy);
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
  cy.fit(cy.elements(), 56);  // clears the legend and zoom controls drawn over the canvas corners
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
  // Discovered networks, and any map where one device carries many endpoints, use the hierarchical grid:
  // a long row of endpoints would otherwise stretch far off-screen.
  if (network?.environment === "real" || network?.source === "discovery" || largestFanOut(cy) > 8) {
    arrangeHierarchy(cy);
    markBusEdges(cy);
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
  markBusEdges(cy);
  updateLabelOffsets(cy.edges());
}

const INFRA_TYPES = new Set(["router", "firewall", "switch", "internet"]);
const CELL_W = 150;       // grid column width
const CELL_H = 125;       // grid row height
const LEVEL_GAP = 170;    // a device to the first row beneath it
const SIBLING_GAP = 90;   // between neighbouring subtrees

const isInfra = (node) => INFRA_TYPES.has(node.data("role") || node.data("type"));
const byLabel = (a, b) => String(a.data("label") || "").localeCompare(String(b.data("label") || ""), undefined, { numeric: true });

function largestFanOut(cy) {
  return cy.nodes().filter(isInfra).reduce((most, node) => Math.max(most, node.neighborhood("node").filter((n) => !isInfra(n)).length), 0);
}

/** Columns for a block of endpoints: one row up to 6, then a block about twice as wide as it is tall (at most 10). */
function gridColumns(count) {
  if (count <= 6) return Math.max(count, 1);
  return Math.min(10, Math.ceil(Math.sqrt(count * 2.4)));
}

function placeGrid(nodes, left, top) {
  const cols = gridColumns(nodes.length);
  nodes.forEach((node, index) => node.position({ x: left + (index % cols) * CELL_W + CELL_W / 2, y: top + Math.floor(index / cols) * CELL_H }));
}

/**
 * Hierarchical grid: infrastructure forms a tree (internet, firewall, router, then switches); each endpoint sits in a
 * compact grid under the device it is linked to (a switch first), wrapped into rows instead of one long line.
 */
function arrangeHierarchy(cy) {
  const infrastructure = cy.nodes().filter(isInfra);
  if (!infrastructure.length) {
    cy.batch(() => placeGrid(cy.nodes().sort(byLabel), 0, 0));
    return;
  }
  const rank = (node) => ({ internet: 0, firewall: 1, router: 2, switch: 3 })[node.data("type")] ?? 4;
  const ordered = infrastructure.sort((a, b) => rank(a) - rank(b) || b.degree() - a.degree() || byLabel(a, b));
  const kids = new Map(infrastructure.map((node) => [node.id(), []]));
  const roots = [];
  const seen = new Set();
  ordered.forEach((start) => {
    if (seen.has(start.id())) return;
    roots.push(start);
    seen.add(start.id());
    const queue = [start];
    for (let index = 0; index < queue.length; index += 1) {
      queue[index].neighborhood("node").filter(isInfra).sort(byLabel).forEach((peer) => {
        if (seen.has(peer.id())) return;
        seen.add(peer.id());
        kids.get(queue[index].id()).push(peer);
        queue.push(peer);
      });
    }
  });
  const leaves = new Map(infrastructure.map((node) => [node.id(), []]));
  const orphans = [];
  cy.nodes().filter((node) => !isInfra(node)).sort(byLabel).forEach((node) => {
    const peers = node.neighborhood("node").filter(isInfra);
    if (peers.empty()) { orphans.push(node); return; }
    const host = peers.sort((a, b) => (a.data("type") === "switch" ? 0 : 1) - (b.data("type") === "switch" ? 0 : 1) || byLabel(a, b)).first();
    leaves.get(host.id()).push(node);
  });
  const size = new Map();
  const childrenWidth = (node) => kids.get(node.id()).reduce((sum, kid) => sum + size.get(kid.id()).width, 0)
    + SIBLING_GAP * Math.max(0, kids.get(node.id()).length - 1);
  const measure = (node) => {
    kids.get(node.id()).forEach(measure);
    const count = leaves.get(node.id()).length;
    const cols = count ? gridColumns(count) : 0;
    const rows = count ? Math.ceil(count / cols) : 0;
    size.set(node.id(), { cols, rows, width: Math.max(cols * CELL_W, childrenWidth(node), CELL_W) });
  };
  const place = (node, left, top) => {
    const { cols, rows, width } = size.get(node.id());
    node.position({ x: left + width / 2, y: top });
    const list = leaves.get(node.id());
    list.forEach((leaf, index) => {
      const row = Math.floor(index / cols);
      const inRow = Math.min(cols, list.length - row * cols);
      const rowLeft = left + width / 2 - (inRow * CELL_W) / 2;
      leaf.position({ x: rowLeft + (index % cols) * CELL_W + CELL_W / 2, y: top + LEVEL_GAP + row * CELL_H });
    });
    const childTop = top + LEVEL_GAP + (rows ? (rows - 1) * CELL_H + LEVEL_GAP : 0);
    let childLeft = left + (width - childrenWidth(node)) / 2;
    kids.get(node.id()).forEach((kid) => {
      place(kid, childLeft, childTop);
      childLeft += size.get(kid.id()).width + SIBLING_GAP;
    });
  };
  cy.batch(() => {
    let left = 0;
    roots.forEach((root) => {
      measure(root);
      place(root, left, 0);
      left += size.get(root.id()).width + SIBLING_GAP * 2;
    });
    if (orphans.length) placeGrid(orphans, left, 0);
  });
}

/** Logical links from a device down to an endpoint are drawn as a bus (down, across, down), not a fan of diagonals. */
function markBusEdges(cy) {
  cy.edges('[kind = "logical"]').forEach((edge) => {
    const below = edge.target().position("y") - edge.source().position("y") > 60;
    edge.toggleClass("ng-bus", below && isInfra(edge.source()) && !isInfra(edge.target()));
  });
}
