// Right-hand Device / Analysis panel. Pure render functions returning HTML;
// the page controller binds actions through data-action attributes.

import { deviceIcon, deviceLabel, iconKey } from "../device-types.js";
import { environmentLabel, expectedActionBadge, flowResultBadge } from "../evidence-view.js";
import { flowLabel } from "../risk.js";
import { escapeHtml, formatDate, formatIp } from "../ui.js";
import { findInterface, interfaceNeighbours, linksForDevice, store } from "./store.js";
import { isSmartDiscovery as isDiscoveredNetwork } from "../discovery/discovery-flow.js";

const L3 = ["router", "firewall"];
const HOSTS = ["pc", "server"];

function returnBanner(analysis) {
  if (!analysis) return "";
  return `<div class="ng-return-banner"><span><i class="bi bi-shield-exclamation me-1"></i>Analysis of change #${analysis.change.id} is open.</span>
    <button class="btn btn-sm btn-primary" data-action="show-analysis">Back to analysis</button></div>`;
}

export function renderNoNetwork() {
  return `
    <div class="ng-panel-section">
      <div class="ng-panel-title">Network</div>
      <p class="text-muted-ng mb-0">No network is open. Create or select a network to start building its topology.</p>
    </div>`;
}

function intentRows(health) {
  if (!store.intents.length) {
    return `<p class="small text-muted-ng mb-2">None defined. NetGuard will protect all host-to-host connectivity that works today.</p>`;
  }
  return `<ul class="ng-conn-list mb-2">${store.intents
    .map((i) => {
      const src = store.devices.get(i.source_device_id)?.name || "?";
      const dst = store.devices.get(i.destination_device_id)?.name || "?";
      // Match by intent id; tuple matching only for older results without ids, and only if unambiguous.
      const tupleMatches = (health?.flows || []).filter(flow => flow.intent_id == null && flow.source === src && flow.destination === dst
        && flow.protocol === i.protocol && flow.port === i.port && flow.expected === i.expected_action);
      const result = health?.flows?.find(flow => flow.intent_id === i.id) || (tupleMatches.length === 1 ? tupleMatches[0] : undefined);
      // Before Analyze Network runs there is no result; show "Not analyzed" rather than a misleading UNKNOWN.
      const badge = health ? flowResultBadge(result?.ok) : '<span class="ng-flow-result unknown" title="Run Analyze Network to test this flow">NOT ANALYZED</span>';
      const action = `<span class="d-flex flex-column align-items-end gap-1">${badge}${expectedActionBadge(i.expected_action)}</span>`;
      return `<li><span><strong>${escapeHtml(src)}</strong> → <strong>${escapeHtml(dst)}</strong>
        <span class="mono text-muted-ng">${escapeHtml(flowLabel(i.protocol, i.port))}</span>
        <div class="small text-muted-ng">${escapeHtml(i.name)} · ${escapeHtml(i.criticality)}</div>${result?.ok === false && result.reason ? `<div class="small text-danger">${escapeHtml(result.reason)}</div>` : ""}</span>${action}</li>`;
    })
    .join("")}</ul>`;
}

export function renderOverview(analysis, health = null) {
  const network = store.network;
  const devices = [...store.devices.values()];
  const interfaceCount = devices.reduce((sum, d) => sum + d.interfaces.length, 0);
  const counts = {};
  devices.forEach((d) => { const role = d.role || iconKey(d); counts[role] = (counts[role] || 0) + 1; });
  const typeRows = Object.keys(counts)
    .map(
      (t) => `<li><span><img src="${deviceIcon(t)}" width="18" height="18" alt="" class="me-2">${escapeHtml(deviceLabel(t))}</span>
        <strong>${counts[t]}</strong></li>`
    )
    .join("");

  return `${returnBanner(analysis)}
    <div class="ng-panel-section">
      <div class="ng-panel-title">Network</div>
      <h3 class="h5 fw-bold mb-1">${escapeHtml(network.name)}</h3>
      <div class="mb-2"><span class="ng-type-badge ng-environment-badge">${escapeHtml(environmentLabel(network))}</span></div>
      <p class="text-muted-ng small mb-3">${escapeHtml(network.description || "No description")}</p>
      <dl class="ng-kv">
        <dt>Devices</dt><dd data-overview="devices">${devices.length}</dd>
        <dt>Interfaces</dt><dd>${interfaceCount}</dd>
        <dt>Links</dt><dd data-overview="links">${store.links.size}</dd>
        <dt>Last updated</dt><dd>${formatDate(network.updated_at)}</dd>
      </dl>
    </div>
    <div class="ng-panel-section">
      <div class="ng-panel-title">Required Flows <span>${store.intents.length}</span></div>
      ${intentRows(health)}
      <button class="btn btn-sm btn-outline-primary" data-action="manage-intents"><i class="bi bi-signpost-split me-1"></i>Manage Required Flows</button>
    </div>
    ${typeRows ? `<div class="ng-panel-section"><div class="ng-panel-title">Inventory</div><ul class="ng-conn-list">${typeRows}</ul></div>` : ""}
    <div class="ng-panel-section">
      <div class="ng-panel-title">Network Actions</div>
      <div class="d-flex gap-2 flex-wrap">
        ${isDiscoveredNetwork(network) ? '<button class="btn btn-sm btn-primary" data-action="device-access"><i class="bi bi-key me-1"></i>Device Access</button>' : ''}
        <button class="btn btn-sm btn-success" data-action="rerun-health">Analyze Network</button>
        <button class="btn btn-sm btn-outline-primary" data-action="show-connections">Connections</button>
        <button class="btn btn-sm btn-outline-primary" data-action="save-network-report">Save Report</button>
        <a class="btn btn-sm btn-outline-primary" href="/changes?network=${network.id}">Validation &amp; Changes</a>
      </div>
      <dl class="ng-kv mt-3 mb-0"><dt>Environment</dt><dd>${escapeHtml(network.environment || 'manual')}</dd>
        <dt>Source</dt><dd>${escapeHtml(network.source || 'manual')}</dd>
        <dt>Data</dt><dd>${network.is_simulated ? 'Offline example' : 'Collected or imported configuration'}</dd></dl>
    </div>`;
}

function ospfSummary(device) {
  const areas = new Map();
  device.interfaces.filter((i) => i.ospf_area !== null && i.ospf_area !== undefined).forEach((i) => {
    if (!areas.has(i.ospf_area)) areas.set(i.ospf_area, []);
    areas.get(i.ospf_area).push(i.name);
  });
  if (!areas.size) return "Not configured";
  return [...areas].map(([area, names]) => `Area ${area} (${names.join(", ")})`).join("; ");
}

function routingSection(device) {
  const routes = device.static_routes.length
    ? `<ul class="ng-kv-compact mono">${device.static_routes.map((r) => `<li>${escapeHtml(r.destination)} via ${escapeHtml(r.next_hop)}</li>`).join("")}</ul>`
    : `<p class="small text-muted-ng mb-0">No static routes.</p>`;
  const acl = device.acl_rules.length
    ? `<ul class="ng-kv-compact mono">${device.acl_rules
        .map((r) => `<li>${r.sequence} ${escapeHtml(r.action)} ${escapeHtml(r.protocol)} ${escapeHtml(r.source)} ${escapeHtml(r.destination)}${r.port ? ` eq ${r.port}` : ""}</li>`)
        .join("")}<li class="text-muted-ng">implicit deny</li></ul>`
    : `<p class="small text-muted-ng mb-0">No ACL — all routed traffic is permitted.</p>`;
  return `
    <div class="ng-panel-section">
      <div class="ng-panel-title">Routing</div>
      <dl class="ng-kv mb-2"><dt>OSPF</dt><dd data-panel="ospf">${escapeHtml(ospfSummary(device))}</dd></dl>
      <div class="small fw-semibold mb-1">Static routes</div>${routes}
    </div>
    <div class="ng-panel-section"><div class="ng-panel-title">ACL <span>${device.acl_rules.length}</span></div>${acl}</div>`;
}

function vlanSection(device) {
  const list = device.vlans.length
    ? device.vlans.map((v) => `<span class="ng-badge-plain me-1 mb-1">VLAN ${v.vlan_id}${v.name ? ` ${escapeHtml(v.name)}` : ""}</span>`).join("")
    : `<span class="small text-muted-ng">No VLANs defined.</span>`;
  return `<div class="ng-panel-section"><div class="ng-panel-title">VLANs <span>${device.vlans.length}</span></div>${list}</div>`;
}

const DISCOVERY_AUTH = { not_offered: "Not offered", not_needed: "Not needed", required: "Would add detail", success: "Authenticated", failed: "Failed" };
const DISCOVERY_METHODS = { ssh: "SSH", "https-api": "HTTPS / API", snmpv3: "SNMPv3", snmpv2c: "SNMPv2c" };

function discoverySection(device, facts) {
  const cls = facts.classification || {};
  const provenance = facts.provenance || [];
  return `<div class="ng-panel-section" data-panel="discovery">
    <div class="ng-panel-title">Discovery</div>
    <dl class="ng-kv">
      <dt>Status</dt><dd data-panel="discovery-status">${escapeHtml(cls.label || '—')}</dd>
      <dt>Authentication</dt><dd data-panel="discovery-auth" class="${cls.auth === 'success' ? 'text-success' : cls.auth === 'failed' ? 'text-danger' : 'text-muted-ng'}">${escapeHtml(DISCOVERY_AUTH[cls.auth] || '—')}${(facts.methods || []).length ? ` · ${escapeHtml(facts.methods.map((m) => DISCOVERY_METHODS[m] || m).join(', '))}` : ''}</dd>
      <dt>Missing</dt><dd>${(cls.missing || []).length ? escapeHtml(cls.missing.join(', ')) : 'Nothing within the supported scope'}</dd>
    </dl>
    ${(facts.location_notes || []).map((note) => `<p class="small mb-1"><i class="bi bi-geo-alt me-1"></i>${escapeHtml(note)}</p>`).join('')}
    ${cls.note ? `<p class="small text-muted-ng mb-1">${escapeHtml(cls.note)}</p>` : ''}
    <details class="small"><summary>Evidence (${provenance.length})</summary><ul class="ps-3 mb-0">${provenance.map((p) => `<li><span class="badge ${p.access === 'credential-free' ? 'text-bg-light border' : 'text-bg-primary'}">${escapeHtml(p.access)}</span> <strong>${escapeHtml(p.technique)}</strong>: ${escapeHtml(p.detail)}</li>`).join('')}</ul></details>
  </div>`;
}

export function renderDevice(device, analysis) {
  const discovery = store.network?.metadata_json?.discovery?.[String(device.id)];
  const smart = store.network?.metadata_json?.method === 'smart' && !!discovery;
  const neighbours = interfaceNeighbours(device.id);
  const isSwitch = device.device_type === "switch";
  const isL3 = L3.includes(device.device_type);
  const interfaces = device.interfaces.length
    ? `<table class="ng-panel-table">
        <thead><tr><th>Interface</th><th>${isSwitch ? "Mode" : "IP Address"}</th><th>${isL3 ? "OSPF" : "VLAN"}</th><th>Status</th></tr></thead>
        <tbody>${device.interfaces
          .map((i) => {
            const mode = i.mode || (i.vlan_id ? "access" : "trunk");
            const second = isSwitch ? `${mode}` : escapeHtml(formatIp(i.ip_address, i.subnet_mask));
            const third = isL3
              ? (i.ospf_area !== null && i.ospf_area !== undefined ? `Area ${i.ospf_area}` : "—") + (i.vlan_id ? `<div class="small text-muted-ng">dot1q ${i.vlan_id}</div>` : "")
              : i.vlan_id ?? "—";
            return `<tr>
              <td class="fw-semibold">${escapeHtml(i.name)}${i.description ? `<div class="small text-muted-ng fw-normal">${escapeHtml(i.description)}</div>` : ""}${
                neighbours.has(i.id)
                  ? `<div class="small text-muted-ng fw-normal"><i class="bi bi-link-45deg"></i>${escapeHtml(neighbours.get(i.id))}</div>`
                  : ""
              }</td>
              <td class="${isSwitch ? "" : "mono"}">${second}</td>
              <td>${third}</td>
              <td><span class="ng-status ${escapeHtml(i.status)}">${escapeHtml(i.status.replace("-", " "))}</span></td>
            </tr>`;
          })
          .join("")}</tbody>
      </table>`
    : `<p class="small text-muted-ng mb-0">No interfaces defined.</p>`;

  const links = linksForDevice(device.id);
  const connections = links.length
    ? `<ul class="ng-conn-list">${links
        .map((l) => {
          const isSource = l.source_device_id === device.id;
          const local = isSource ? l.source_interface_name : l.destination_interface_name;
          const peerId = isSource ? l.destination_device_id : l.source_device_id;
          const peer = isSource ? l.destination_device_name : l.source_device_name;
          const peerIf = isSource ? l.destination_interface_name : l.source_interface_name;
          return `<li>
            <span><span class="mono">${escapeHtml(local || "—")}</span>
              <i class="bi bi-arrow-left-right mx-1 text-muted-ng"></i>
              <a href="#" data-action="select-device" data-device-id="${peerId}">${escapeHtml(peer)}</a>
              <span class="mono text-muted-ng">${escapeHtml(peerIf || "")}</span></span>
            <button class="btn btn-sm btn-link p-0" data-action="select-link" data-link-id="${l.id}" title="View link">View</button>
          </li>`;
        })
        .join("")}</ul>`
    : `<p class="small text-muted-ng mb-0">${isDiscoveredNetwork(store.network) ? 'No connection evidence is available for this device. Its physical cabling is unknown.' : 'No connections are present in the stored model.'}</p>`;

  const hostRow = HOSTS.includes(device.device_type)
    ? `<dt>Default Gateway</dt><dd class="mono" data-panel="gateway">${escapeHtml(device.default_gateway || "—")}</dd>`
    : "";

  return `${returnBanner(analysis)}
    <div class="ng-panel-section">
      <div class="ng-panel-title">Selected Device</div>
      <div class="ng-device-head mb-3">
        <img src="${deviceIcon(iconKey(device))}" alt="">
        <div>
          <h3 data-panel="device-name">${escapeHtml(device.name)}</h3>
          <span class="ng-type-badge">${escapeHtml(deviceLabel(device.role || iconKey(device)))}</span>
        </div>
      </div>
      <dl class="ng-kv">
        <dt>Type</dt><dd>${escapeHtml(deviceLabel(device.device_type))}</dd>
        <dt>Vendor</dt><dd data-panel="vendor">${escapeHtml(device.vendor || "—")}</dd>
        <dt>Model</dt><dd data-panel="model">${escapeHtml(device.model || "—")}</dd>
        <dt>Management IP</dt><dd class="mono" data-panel="management-ip">${escapeHtml(device.management_ip || "—")}</dd>
        ${discovery && !smart ? `<dt>Authentication</dt><dd class="${discovery.auth_status === 'success' ? 'text-success' : discovery.auth_status === 'failure' ? 'text-danger' : 'text-muted-ng'}">${escapeHtml(discovery.can_login ? discovery.auth_status : 'Not required')}</dd>` : ''}
        ${hostRow}
      </dl>
    </div>
    ${smart ? discoverySection(device, discovery) : ''}
    <div class="ng-panel-section">
      <div class="ng-panel-actions">
        ${device.management_ip || device.access?.console ? `<button class="btn btn-sm btn-dark" data-action="open-cli" data-device-id="${device.id}" title="Interactive terminal (double-click the device)"><i class="bi bi-terminal me-1"></i>Open CLI</button>
        <button class="btn btn-sm btn-outline-dark" data-action="open-gui" data-device-id="${device.id}" title="Detected web management portals"><i class="bi bi-window me-1"></i>Web GUI</button>` : ''}
        ${smart && ['required', 'failed'].includes(discovery.classification?.auth) ? `<button class="btn btn-sm btn-primary full" data-action="discovery-auth" data-device-id="${device.id}"><i class="bi bi-shield-lock me-1"></i>Authenticate this device</button>` : ''}
        <button class="btn btn-sm btn-primary full" data-action="propose-change" ${device.device_type === 'unknown' ? 'disabled title="Identify the device and collect configuration first"' : ''}><i class="bi bi-lightning-charge me-1"></i>Propose Change</button>
        <button class="btn btn-sm btn-outline-primary" data-action="edit-device"><i class="bi bi-pencil me-1"></i>Edit Device</button>
        <button class="btn btn-sm btn-outline-primary" data-action="manage-interfaces"><i class="bi bi-sliders me-1"></i>Configuration</button>
        <button class="btn btn-sm btn-outline-primary full" data-action="show-connections" data-device-id="${device.id}"><i class="bi bi-ethernet me-1"></i>View Connections</button>
        <button class="btn btn-sm btn-outline-secondary" data-action="connect-from"><i class="bi bi-share me-1"></i>Connect To…</button>
        <button class="btn btn-sm btn-outline-danger" data-action="delete-device"><i class="bi bi-trash me-1"></i>Delete Device</button>
      </div>
      ${device.device_type === 'unknown' ? `<p class="small text-muted-ng mt-2 mb-0">Identity is unknown. Use Edit Device to enter known details, or <a href="/networks?environment=real">start automatic discovery</a>.</p>` : ''}
    </div>
    <div class="ng-panel-section">
      <div class="ng-panel-title">Interfaces <span>${device.interfaces.length}</span></div>
      ${interfaces}
    </div>
    ${isL3 ? routingSection(device) : ""}
    ${isSwitch ? vlanSection(device) : ""}
    <div class="ng-panel-section">
      <div class="ng-panel-title">Connections <span>${links.length}</span></div>
      ${connections}
    </div>`;
}

function endpoint(deviceId, interfaceId, portInfo) {
  const device = store.devices.get(deviceId);
  const iface = findInterface(interfaceId);
  return `
    <div class="ng-link-endpoint">
      <img src="${deviceIcon(iconKey(device))}" alt="">
      <div class="dev"><a href="#" data-action="select-device" data-device-id="${deviceId}">${escapeHtml(device?.name)}</a></div>
      <div class="mono small text-muted-ng">${escapeHtml(device?.management_ip || 'Management IP unknown')}</div>
      <div class="mono small fw-semibold">${escapeHtml(iface?.name || "Unknown interface")}</div>
      ${iface?.description ? `<div class="small text-muted-ng">${escapeHtml(iface.description)}</div>` : ""}
      ${portInfo?.label ? `<div class="small">${escapeHtml(portInfo.label)}</div>` : ""}
      <div class="mono small text-muted-ng">${iface?.ip_address ? escapeHtml(formatIp(iface.ip_address, iface.subnet_mask)) : ''}</div>
      ${iface ? `<dl class="ng-kv small mt-2 mb-0"><dt>Status</dt><dd>${escapeHtml(iface.status)}</dd>
        <dt>Mode</dt><dd>${escapeHtml(iface.mode || 'routed / unknown')}</dd>
        <dt>Access VLAN</dt><dd>${iface.vlan_id ?? 'Not set'}</dd>
        <dt>Trunk VLANs</dt><dd>${escapeHtml(iface.allowed_vlans?.join(', ') || 'Unknown')}</dd>
        <dt>Native VLAN</dt><dd>${iface.native_vlan ?? 'Unknown'}</dd>
        <dt>Speed</dt><dd>${iface.speed_mbps ? `${iface.speed_mbps} Mbps` : 'Unknown'}</dd>
        <dt>STP</dt><dd>${escapeHtml(iface.stp_state || 'Unknown / not applicable')}</dd></dl>` : ''}
    </div>`;
}

const GRADE_CLASS = { Confirmed: "ng-risk-low", Inferred: "ng-risk-medium", Logical: "ng-risk-neutral", Unknown: "ng-risk-high", Manual: "ng-risk-neutral" };
function gradeBadge(link) {
  const grade = link.evidence_grade || "Manual";
  return `<span class="ng-badge-risk ${GRADE_CLASS[grade] || "ng-risk-neutral"}">${escapeHtml(grade)}</span>`;
}

export function renderLink(link, analysis) {
  const evidence = link.evidence || [];
  const kind = ['segment', 'logical', 'tunnel', 'vpn'].includes(link.kind) ? 'Logical connectivity' : link.discovery_status === 'inferred' ? 'Inferred attachment' : 'Physical / modeled connection';
  return `${returnBanner(analysis)}
    <div class="ng-panel-section">
      <div class="ng-panel-title">Selected Link</div>
      <div class="ng-link-endpoints mb-3">
        ${endpoint(link.source_device_id, link.source_interface_id, link.source_port_info)}
        <i class="bi bi-arrow-left-right text-muted-ng"></i>
        ${endpoint(link.destination_device_id, link.destination_interface_id, link.destination_port_info)}
      </div>
      <dl class="ng-kv"><dt>Connection</dt><dd>${kind}</dd><dt>Evidence source</dt><dd>${escapeHtml(link.kind || 'manual')}</dd>
        <dt>Link status</dt><dd>${escapeHtml(link.state || 'unknown')}</dd>
        <dt>Evidence grade</dt><dd data-link="discovery">${gradeBadge(link)}</dd>
        <dt>Confidence</dt><dd>${link.confidence == null ? 'Unknown' : `${Math.round(link.confidence * 100)}%`}</dd>
        <dt>Link speed</dt><dd>${link.speed_mbps ? `${link.speed_mbps} Mbps` : 'Unknown'}</dd></dl>
      <div class="ng-panel-title">Discovery evidence</div>
      ${evidence.length ? `<ul class="small ps-3">${evidence.map(item => `<li><strong>${escapeHtml(typeof item === 'object' ? item.source || 'Observation' : 'Observation')}</strong>: ${escapeHtml(typeof item === 'object' ? item.detail || item.observation || item.description || '' : item)}</li>`).join('')}</ul>` : '<p class="small text-muted-ng">No discovery evidence. This connection was entered in the stored model.</p>'}
      ${(link.missing || []).length ? `<p class="small text-warning-emphasis">Not established: ${escapeHtml(link.missing.join('; '))}</p>` : ''}
      ${link.discovery_status === 'inferred' || !link.source_interface_id || !link.destination_interface_id ? '<p class="small text-muted-ng">An inferred attachment does not establish an exact physical cable or an unknown peer port.</p>' : ''}
      <button class="btn btn-sm btn-outline-danger w-100" data-action="delete-link"><i class="bi bi-trash me-1"></i>Delete Link</button>
    </div>`;
}

export function renderConnections(deviceId = null) {
  const links = [...store.links.values()].filter(link => !deviceId || link.source_device_id === deviceId || link.destination_device_id === deviceId);
  const device = store.devices.get(deviceId);
  const unmapped = [...store.devices.values()].filter(item => ![...store.links.values()].some(link => link.source_device_id === item.id || link.destination_device_id === item.id));
  const discovered = isDiscoveredNetwork(store.network);
  return `<div class="ng-panel-section"><div class="ng-panel-title">Connections
      <button class="btn btn-sm btn-link p-0" data-action="close-connections" aria-label="Close connections"><i class="bi bi-x-lg"></i></button></div>
    <h3 class="h6">${escapeHtml(device?.name || store.network.name)}</h3>
    <p class="small text-muted-ng">Solid: confirmed or modeled. Dashed: inferred or down. Dotted: logical or unknown. Select a connection to inspect both ports and its evidence.</p>
    ${discovered ? `<div class="border rounded p-3 mb-3"><p class="small mb-2">${!links.length ? 'The scan found devices, but no neighbour evidence has been collected yet. Authenticating a switch or router reads its LLDP/CDP and MAC tables; an IP response never establishes a cable.' : 'Confirmed: both ends report the neighbour. Inferred: one end or a MAC table reports it. Logical: a shared routed subnet with no cable evidence. Unknown: no supporting evidence.'}</p><button class="btn btn-sm btn-primary" data-action="device-access"${deviceId ? ` data-device-id="${deviceId}"` : ''}><i class="bi bi-key me-1"></i>Device Access</button></div>` : ''}
    <ul class="ng-conn-list">${links.map(link => `<li><div class="min-w-0">
      <button type="button" class="btn btn-sm btn-link text-start p-0" data-action="select-link" data-link-id="${link.id}">
        <strong>${escapeHtml(link.source_device_name)} <span class="mono">${escapeHtml(link.source_interface_name || 'Unknown Port')}</span></strong><br>
        ↔ ${escapeHtml(link.destination_device_name)} <span class="mono">${escapeHtml(link.destination_interface_name || 'Unknown Port')}</span></button>
      <div class="small text-muted-ng">${escapeHtml(link.kind || 'physical')} · ${escapeHtml(link.state || 'unknown')} · ${escapeHtml(link.evidence_grade || link.discovery_status || 'Manual')}${link.speed_mbps ? ` · ${link.speed_mbps} Mbps` : ''}</div>
    </div></li>`).join('') || '<li>No mapped connections.</li>'}</ul>
    ${!deviceId && unmapped.length ? `<h3 class="h6 mt-3">Mapping unknown</h3><ul class="small ps-3">${unmapped.map(item => `<li>${escapeHtml(item.name)}${item.name === item.management_ip ? '' : ` · ${escapeHtml(item.management_ip || 'No IP')}`} — no connection evidence</li>`).join('')}</ul>` : ''}
  </div>`;
}
