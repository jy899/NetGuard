// Topology Workspace controller: loads a network, wires the toolbar,
// canvas interactions, side panel, dialogs and change analysis together.

import { api } from "../api.js";
import { DEVICE_TYPES, deviceIcon } from "../device-types.js";
import { initShell, setPageTitle } from "../layout.js";
import { renderAnalysisPanel } from "../analysis-view.js";
import { fixableIssues, renderHealthPanel } from "../health-view.js";
import { RISK_COLORS } from "../risk.js";
import { confirmDialog, escapeHtml, toast, withBusy } from "../ui.js";
import { createChangeForm } from "../topology/change-form.js";
import { createDialogs } from "../topology/dialogs.js";
import { createWorkflow } from "../topology/workflow.js";
import {
  applyHighlight,
  autoArrange,
  clearHighlight,
  collectPositions,
  createGraph,
  edgeId,
  fitGraph,
  focusPath,
  freePosition,
  nodeId,
  syncGraph,
} from "../topology/graph.js";
import { renderConnections, renderDevice, renderLink, renderNoNetwork, renderOverview } from "../topology/panel.js";
import { clearTopology, linksForDevice, loadTopology, store } from "../topology/store.js";
import { environmentLabel } from "../evidence-view.js";
import { isSmartDiscovery, openAuthentication, renderReport } from "../discovery/discovery-flow.js";
import { openPortals, openTerminal } from "../topology/console.js";

const LAST_NETWORK_KEY = "netguard.lastNetwork";

const ui = {
  networkSelect: document.getElementById("network-select"),
  panel: document.getElementById("side-panel"),
  saveState: document.getElementById("save-state"),
  connectBtn: document.getElementById("btn-connect"),
  connectBanner: document.getElementById("connect-banner"),
  connectBannerText: document.getElementById("connect-banner-text"),
  canvasEmpty: document.getElementById("canvas-empty"),
  legend: document.getElementById("analysis-legend"),
};

const state = {
  cy: null,
  dialogs: null,
  selection: null, // { kind: "device" | "link", id }
  dirty: false,
  connect: { active: false, sourceId: null },
  changeForm: null,
  analysis: null, // { change, assessment } currently shown
  showAnalysis: false, // panel shows the analysis (true) or device/link details (false)
  health: null, // latest health check report
  showHealth: false,
  showConnections: false,
  connectionDeviceId: null,
  skipped: new Set(), // issue keys the engineer chose to skip (this session)
  workflow: null,
  user: null,
};

const isDiscoveredNetwork = (network) => isSmartDiscovery(network);

function openDetailsPanel() {
  document.dispatchEvent(new CustomEvent("netguard:panel-open"));
}

function closeDetailsPanel() {
  document.dispatchEvent(new CustomEvent("netguard:panel-close"));
}

async function fitWorkspaceAfterLayout() {
  // The discovery banner and wrapped toolbar change the canvas height. Fit only
  // after their final layout, using the actual container bounds. Panel dragging
  // still calls resize alone and preserves the engineer's current zoom.
  await new Promise((resolve) => requestAnimationFrame(resolve));
  state.cy.resize();
  fitGraph(state.cy);
}

function updateDiscoveryStatus() {
  const network = store.network;
  document.getElementById("environment-badge").textContent = environmentLabel(network || {});
  const button = document.getElementById("btn-device-access");
  const banner = document.getElementById("discovery-status");
  const discovered = isDiscoveredNetwork(network);
  button?.classList.toggle("d-none", !discovered);
  const collectable = !network?.is_simulated && [...store.devices.values()].some((d) => ["router", "switch", "firewall"].includes(d.device_type) && (d.access?.console || d.management_ip));
  document.getElementById("btn-collect")?.classList.toggle("d-none", !collectable);
  if (!banner) return;
  banner.classList.toggle("d-none", !discovered);
  if (discovered) renderSmartBanner(banner, network);
}

function renderSmartBanner(banner, network) {
  const facts = Object.values(network.metadata_json?.discovery || {});
  const links = [...store.links.values()];
  const grade = (name) => links.filter((link) => link.evidence_grade === name).length;
  const confirmed = grade("Confirmed");
  const inferred = grade("Inferred");
  const logical = grade("Logical");
  const unknown = facts.filter((item) => item.unknown_row).length;
  const authenticated = facts.filter((item) => item.auth === "success").length;
  const failed = facts.filter((item) => item.auth === "failed").length;
  const required = facts.filter((item) => item.classification?.auth === "required").length;
  const session = network.metadata_json?.discovery_session || {};
  const summary = `Credential-free discovery · Devices ${store.devices.size} · Connections ${confirmed} confirmed / ${inferred} inferred / ${logical} logical / ${unknown} unknown · Authenticated ${authenticated}${failed ? ` · ${failed} failed` : ""}`;
  const detail = session.state === "prompting" && required
    ? `${required} credential request(s) pending · review them in the Discovery Report. Every request is optional.`
    : !links.length ? "Devices are identified, but no connection is verified yet. Authenticating a switch or router reads its LLDP/CDP and MAC tables; an IP response never establishes a cable."
    : required ? `${required} device(s) could add detail after authentication. Dashed lines are inferred (one-sided neighbour or MAC table); solid lines are confirmed by both ends.`
    : "All available evidence is collected. Solid lines are confirmed by LLDP/CDP from both ends; dashed lines are inferred; dotted lines are logical (shared routed subnet).";
  banner.innerHTML = `<div class="d-flex justify-content-between align-items-center gap-2 flex-wrap w-100"><div class="min-w-0"><div class="small fw-semibold" id="discovery-stage-summary">${escapeHtml(summary)}</div><div class="small text-muted-ng" id="discovery-stage-detail">${escapeHtml(detail)}</div></div><div class="d-flex gap-2 flex-wrap"><button type="button" class="btn btn-sm btn-primary" data-discovery-report>Discovery Report</button><button type="button" class="btn btn-sm btn-light border" data-discovery-connections>Connections</button></div></div>`;
}

let reportModal = null;
async function openDiscoveryReport() {
  if (!reportModal) {
    const wrapper = document.createElement("div");
    wrapper.innerHTML = `<div class="modal" id="discovery-report-modal" tabindex="-1" aria-labelledby="discovery-report-title" aria-hidden="true"><div class="modal-dialog modal-xl modal-dialog-scrollable"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="discovery-report-title">Discovery Report</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div><div class="modal-body" id="discovery-report-body"></div></div></div></div>`;
    document.body.appendChild(wrapper.firstElementChild);
    reportModal = document.getElementById("discovery-report-modal");
    reportModal.addEventListener("click", async (event) => {
      if (event.target.closest("[data-report-open]")) { event.preventDefault(); bootstrap.Modal.getOrCreateInstance(reportModal).hide(); }
      const details = event.target.closest("[data-device-details]");
      if (details) {
        bootstrap.Modal.getOrCreateInstance(reportModal).hide();
        selectDevice(Number(details.dataset.deviceDetails));
      }
      if (event.target.closest("[data-report-authenticate]")) {
        bootstrap.Modal.getOrCreateInstance(reportModal).hide();
        await authenticateDevices();
      }
    });
  }
  const result = await api.get(`/discovery/${store.network.id}`);
  document.getElementById("discovery-report-body").innerHTML = renderReport(result);
  bootstrap.Modal.getOrCreateInstance(reportModal).show();
}

async function afterDiscoveryChange() {
  // Collected evidence invalidates the old diagnosis/validation display.
  // Saved reports and assessments remain available in history.
  state.analysis = null;
  state.health = null;
  state.showAnalysis = false;
  state.showHealth = false;
  const url = new URL(window.location.href);
  url.searchParams.delete("change");
  history.replaceState(null, "", url);
  state.skipped.clear();
  state.selection = null;
  clearHighlight(state.cy);
  ui.legend.classList.add("d-none");
  await refresh({ resetPositions: true });
  if (!document.querySelector(".modal.show")) await fitWorkspaceAfterLayout();
}

async function authenticateDevices(deviceIds = null) {
  try {
    const result = await api.get(`/discovery/${store.network.id}`);
    const outcome = await openAuthentication(store.network.id, result, { deviceIds, manageProfiles: !deviceIds });
    // New evidence re-lays out the map; a rejected attempt only refreshes statuses and keeps the current layout;
    // closing without any attempt (or only removing a saved profile) changes nothing.
    if (outcome.changed) await afterDiscoveryChange();
    else if (outcome.attempted) await refresh();
  } catch (error) { toast(error.message, "error"); }
}

async function openDeviceAccess(deviceId = null) {
  if (!isDiscoveredNetwork(store.network)) return;
  await authenticateDevices(deviceId ? [deviceId] : null);
}

function setupDiscoveryAccess() {
  const banner = document.createElement("div");
  banner.id = "discovery-status";
  banner.className = "ng-return-banner d-none px-3 py-2";
  banner.setAttribute("role", "status");
  banner.setAttribute("aria-live", "polite");
  document.querySelector(".ng-canvas-wrap").before(banner);
  banner.addEventListener("click", (event) => {
    if (event.target.closest("[data-discovery-access]")) openDeviceAccess();
    if (event.target.closest("[data-discovery-report]")) openDiscoveryReport();
    if (event.target.closest("[data-discovery-connections]")) showConnections();
  });
  state.workflow = createWorkflow({
    onChanged: async (change, { collected = false, executed = false } = {}) => {
      if (collected) { await afterDiscoveryChange(); return; }
      if (executed) await refresh();
      if (change && state.analysis?.change.id === change.id) {
        state.analysis.change = change;
        if (executed) {
          try {
            const [latest] = await api.get(`/assessments?change_id=${change.id}&limit=1`);
            if (latest) state.analysis.assessment = latest;
          } catch { /* keep the shown assessment */ }
        }
        renderPanel();
      }
    },
  });
  document.getElementById("btn-device-access")?.addEventListener("click", () => openDeviceAccess());
  document.getElementById("btn-collect")?.addEventListener("click", () => state.workflow.collect(store.network, [...store.devices.values()]));
}

// ------------------------------------------------------------ state helpers
function setDirty(dirty) {
  state.dirty = dirty;
  ui.saveState.textContent = dirty ? "Unsaved layout" : "Saved";
  ui.saveState.classList.toggle("dirty", dirty);
}

function setNetworkControlsEnabled(enabled) {
  document.querySelectorAll("[data-requires-network]").forEach((el) => (el.disabled = !enabled));
  document.querySelectorAll(".ng-palette-item").forEach((el) => (el.disabled = !enabled));
}

function updateCanvasEmpty() {
  if (!store.network) {
    ui.canvasEmpty.innerHTML = `
      <div><i class="bi bi-hdd-network fs-2 text-muted"></i>
        <h4 class="h6 mt-2">No network selected</h4>
        <p class="small text-muted mb-3">Create a network first, then build its topology here.</p>
        <a class="btn btn-sm btn-primary" href="/networks?create=1"><i class="bi bi-plus-lg me-1"></i>Create Network</a></div>`;
    ui.canvasEmpty.classList.remove("d-none");
  } else if (store.devices.size === 0) {
    ui.canvasEmpty.innerHTML = `
      <div><i class="bi bi-diagram-3 fs-2 text-muted"></i>
        <h4 class="h6 mt-2">This topology is empty</h4>
        <p class="small text-muted mb-3">Add routers, switches, firewalls, PCs, servers or an Internet cloud from the palette above.</p>
        <button class="btn btn-sm btn-primary" data-empty-add><i class="bi bi-plus-lg me-1"></i>Add First Device</button></div>`;
    ui.canvasEmpty.classList.remove("d-none");
    ui.canvasEmpty.querySelector("[data-empty-add]").addEventListener("click", () => state.dialogs.device.openCreate());
  } else {
    ui.canvasEmpty.classList.add("d-none");
  }
}

// ---------------------------------------------------------------- selection
function renderPanel() {
  if (!store.network) {
    ui.panel.innerHTML = renderNoNetwork();
    return;
  }
  if (state.analysis && state.showAnalysis) {
    ui.panel.innerHTML = renderAnalysisPanel(state.analysis.assessment, state.analysis.change, state.user);
    return;
  }
  if (state.health && state.showHealth) {
    ui.panel.innerHTML = renderHealthPanel(state.health, state.skipped, store.network);
    return;
  }
  if (state.showConnections) {
    ui.panel.innerHTML = renderConnections(state.connectionDeviceId);
    return;
  }
  const analysis = state.analysis?.assessment;
  const healthBanner = !analysis && state.health
    ? `<div class="ng-return-banner"><span><i class="bi bi-heart-pulse me-1"></i>Network analysis</span>
        <button class="btn btn-sm btn-primary" data-action="show-health">Back to analysis</button></div>`
    : "";
  const { selection } = state;
  if (selection?.kind === "device" && store.devices.has(selection.id)) {
    ui.panel.innerHTML = healthBanner + renderDevice(store.devices.get(selection.id), analysis);
  } else if (selection?.kind === "link" && store.links.has(selection.id)) {
    ui.panel.innerHTML = healthBanner + renderLink(store.links.get(selection.id), analysis);
  } else {
    state.selection = null;
    ui.panel.innerHTML = healthBanner + renderOverview(analysis, state.health);
  }
}

// ----------------------------------------------------------------- analysis
function highlightAssessment(assessment) {
  const affectedImpacts = assessment.impacts.filter((i) => i.status === "broken" || i.status === "violation");
  const pathDeviceIds = new Set();
  const pathLinkIds = new Set();
  affectedImpacts.forEach((i) => {
    i.path_device_ids.forEach((d) => pathDeviceIds.add(d));
    i.path_link_ids.forEach((l) => pathLinkIds.add(l));
  });
  const failLinks = new Map();
  assessment.findings.forEach((f) => f.link_ids.forEach((id) => failLinks.set(id, `✕ ${f.name}`)));
  affectedImpacts.forEach((i) => {
    if (i.failure_link_id && !failLinks.has(i.failure_link_id)) failLinks.set(i.failure_link_id, "✕");
  });
  const color = RISK_COLORS[assessment.risk_level] || RISK_COLORS.HIGH;
  applyHighlight(state.cy, {
    color,
    affectedDeviceIds: assessment.affected_device_ids,
    changedDeviceId: state.analysis?.change.device_id,
    pathDeviceIds: [...pathDeviceIds],
    pathLinkIds: [...pathLinkIds],
    failLinks,
  });
  document.getElementById("legend-path").style.borderColor = color;
  document.getElementById("legend-path-label").textContent = "Affected path";
  ui.legend.classList.toggle("d-none", !(pathLinkIds.size || failLinks.size || assessment.affected_device_ids.length));
}

function showAnalysis(change, assessment) {
  openDetailsPanel();
  state.analysis = { change, assessment };
  state.showAnalysis = true;
  state.showHealth = false;
  state.showConnections = false;
  state.selection = null;
  state.cy.elements().unselect();
  const url = new URL(window.location.href);
  url.searchParams.set("change", change.id);
  history.replaceState(null, "", url);
  highlightAssessment(assessment);
  renderPanel();
  ui.panel.scrollTop = 0;
}

function closeAnalysis() {
  state.analysis = null;
  state.showAnalysis = false;
  clearHighlight(state.cy);
  ui.legend.classList.add("d-none");
  const url = new URL(window.location.href);
  url.searchParams.delete("change");
  history.replaceState(null, "", url);
  if (state.health) {
    showHealth();
    return;
  }
  renderPanel();
  closeDetailsPanel();
}

// ------------------------------------------------------------ health check
const SEVERITY_COLORS = { CRITICAL: RISK_COLORS.CRITICAL, HIGH: RISK_COLORS.HIGH, MEDIUM: RISK_COLORS.MEDIUM };

function highlightHealth(report) {
  const deviceIds = new Set();
  const failLinks = new Map();
  const issues = report.issues.filter((issue) => !state.skipped.has(issue.key));
  issues.forEach((issue) => {
    issue.device_ids.forEach((id) => deviceIds.add(id));
    issue.link_ids.forEach((id) => failLinks.set(id, `✕ ${issue.rule_id}`));
  });
  const worst = ["CRITICAL", "HIGH", "MEDIUM"].find((level) => issues.some((i) => i.severity === level)) || "HIGH";
  applyHighlight(state.cy, {
    color: SEVERITY_COLORS[worst],
    affectedDeviceIds: [...deviceIds],
    changedDeviceId: null,
    pathDeviceIds: [],
    pathLinkIds: [],
    failLinks,
  });
  document.getElementById("legend-path").style.borderColor = SEVERITY_COLORS[worst];
  document.getElementById("legend-path-label").textContent = "Device with an issue";
  ui.legend.classList.toggle("d-none", !issues.length);
}

function showHealth() {
  if (!state.health) return;
  openDetailsPanel();
  state.showHealth = true;
  state.showAnalysis = false;
  state.showConnections = false;
  state.selection = null;
  state.cy.elements().unselect();
  highlightHealth(state.health);
  renderPanel();
  ui.panel.scrollTop = 0;
}

function closeHealth() {
  state.health = null;
  state.skipped = new Set();
  state.showHealth = false;
  clearHighlight(state.cy);
  ui.legend.classList.add("d-none");
  renderPanel();
  closeDetailsPanel();
}

async function runHealthCheck(button) {
  const run = async () => {
    try {
      state.analysis = null;
      const record = await api.post(`/networks/${store.network.id}/analyze`);
      state.health = { ...record.snapshot.analysis, record_id: record.id, network_id: store.network.id };
      showHealth();
    } catch (error) {
      toast(error.message, "error");
    }
  };
  if (button) await withBusy(button, run);
  else await run();
}

function showConnections(deviceId = null) {
  openDetailsPanel();
  state.showAnalysis = false;
  state.showHealth = false;
  state.showConnections = true;
  state.connectionDeviceId = deviceId;
  renderPanel();
  ui.panel.scrollTop = 0;
}

async function saveNetworkReport(button) {
  await withBusy(button, async () => {
    try {
      const record = await api.post(`/networks/${store.network.id}/reports`, { title: `${store.network.name} — Network Analysis` });
      window.location.assign(`/reports?record=${record.id}`);
    } catch (error) {
      toast(error.message, "error");
    }
  });
}

function issueOf(kind, index) {
  const item = kind === "advisory" ? state.health.advisories[index] : state.health.issues[index];
  return { ...item, name: item.name || item.title };
}

async function reviewFix(issueIndex, fixIndex, button, kind = "issue") {
  const issue = issueOf(kind, issueIndex);
  const fix = issue.fixes[fixIndex];
  await withBusy(button, async () => {
    try {
      const change = await api.post("/changes", {
        device_id: fix.device_id,
        interface_id: fix.interface_id,
        change_type: fix.change_type,
        parameters: fix.parameters,
        reason: `Health check fix for ${issue.rule_id} ${issue.name}: ${fix.label}`,
      });
      const assessment = await api.post(`/changes/${change.id}/analyze`);
      showAnalysis(change, assessment);
    } catch (error) {
      toast(error.message, "error");
    }
  });
}

function fixPreview(fix) {
  const v = fix.verification;
  return `<div class="mb-2"><strong>${escapeHtml(v.device)}</strong>${v.target ? ` · <span class="mono">${escapeHtml(v.target)}</span>` : ""}:
    <span class="mono text-muted">${escapeHtml(v.current_value)}</span> → <span class="mono fw-semibold">${escapeHtml(v.proposed_value)}</span>
    <div class="small text-success">${escapeHtml(v.risk_level)} risk · ${v.new_issues.length || v.broken_flows.length ? "additional modeled issues or broken flows" : "no additional modeled issues or broken required flows"}</div></div>`;
}

async function createAndSubmitFix(issue, fix) {
  const change = await api.post("/changes", {
    device_id: fix.device_id,
    interface_id: fix.interface_id,
    change_type: fix.change_type,
    parameters: fix.parameters,
    reason: `Health check fix for ${issue.rule_id} ${issue.name}: ${fix.label}`,
  });
  const assessment = await api.post(`/changes/${change.id}/analyze`);
  if (assessment.validation_result === "INCOMPLETE" || assessment.recommendation === "DO_NOT_DEPLOY") {
    return { change, assessment, submitted: false };
  }
  return { change: await api.post(`/changes/${change.id}/submit`), assessment, submitted: true };
}

/** Validate one fix on a model copy and submit it for IT Manager approval (asks first). */
async function applyFix(issueIndex, fixIndex, button, kind = "issue") {
  const issue = issueOf(kind, issueIndex);
  const fix = issue.fixes[fixIndex];
  const commands = fix.verification.commands || [];
  const ok = await confirmDialog({
    title: `Submit fix for ${issue.rule_id} for approval`,
    message: `<p class="mb-2">${escapeHtml(fix.label)}</p>${fixPreview(fix)}
      ${commands.length ? `<p class="small mb-1">Commands for review:</p><pre class="ng-cli">${commands.map(escapeHtml).join("\n")}</pre>` : ""}
      <p class="small text-muted mb-0">NetGuard records the change, validates it on a copy of the model and sends it to an IT Manager. Nothing is sent to a device until the change is approved and executed.</p>`,
    confirmLabel: "Submit for Approval",
  });
  if (!ok) return;
  await withBusy(button, async () => {
    try {
      const { change, assessment, submitted } = await createAndSubmitFix(issue, fix);
      toast(submitted ? `Submitted for approval: ${fix.label}` : "Validation blocked submission; review the assessment.", submitted ? "success" : "warning");
      showAnalysis(change, assessment);
    } catch (error) {
      toast(error.message, "error");
    }
  });
}

/** Validate and submit every recommended fix for approval, one change per fix. */
async function fixAll(button) {
  const planned = fixableIssues(state.health, state.skipped).map(({ issue }) => ({ issue, fix: issue.fixes[0] }));
  if (!planned.length) return;
  const allCommands = planned.flatMap(({ fix }) => fix.verification.commands || []);
  const ok = await confirmDialog({
    title: `Submit ${planned.length} fix${planned.length > 1 ? "es" : ""} for approval?`,
    message: `<p class="small">NetGuard validates each fix on a copy of the model and submits it to an IT Manager as a separate change. No device is contacted:</p>
      <ol class="ps-3">${planned.map(({ issue, fix }) => `<li><span class="mono small">${escapeHtml(issue.rule_id)}</span> ${escapeHtml(fix.label)}
        ${fixPreview(fix)}</li>`).join("")}</ol>
      ${allCommands.length ? `<details><summary class="small">Commands for review</summary><pre class="ng-cli mt-1">${allCommands.map(escapeHtml).join("\n")}</pre></details>` : ""}`,
    confirmLabel: `Submit ${planned.length} for Approval`,
  });
  if (!ok) return;
  await withBusy(button, async () => {
    let submitted = 0;
    const blocked = [];
    for (const { issue, fix } of planned) {
      try {
        const result = await createAndSubmitFix(issue, fix);
        if (result.submitted) submitted += 1;
        else blocked.push(issue.rule_id);
      } catch (error) {
        toast(`${issue.rule_id}: ${error.message}`, "error");
        break;
      }
    }
    toast(`Submitted ${submitted} change(s) for approval${blocked.length ? `; ${blocked.length} blocked by validation (${blocked.join(", ")})` : ""}. Track them under Changes.`, blocked.length ? "warning" : "success", 6000);
  });
}

/** An approved change on a non-laboratory device is deployed outside NetGuard; this records it in the model. */
async function applyChange(button) {
  const { change, assessment } = state.analysis;
  const commands = assessment.change.commands || [];
  const ok = await confirmDialog({
    title: "Record approved change as deployed",
    message: `<p>Confirm that this approved change was deployed on the device:
      <strong>${escapeHtml(assessment.change.device)}</strong> · ${escapeHtml(assessment.change.change_type_label)}
      <span class="mono">${escapeHtml(assessment.change.current_value)} → ${escapeHtml(assessment.change.proposed_value)}</span>.</p>
      ${commands.length ? `<p class="small mb-1">Approved commands:</p>
        <pre class="ng-cli">${commands.map(escapeHtml).join("\n")}</pre>` : ""}
      <p class="small text-muted mb-0">NetGuard sends commands only to laboratory devices. For this device it re-validates the change and updates the stored model; collect the configuration afterwards to confirm it.</p>`,
    confirmLabel: "Record as Deployed",
  });
  if (!ok) return;
  await withBusy(button, async () => {
    try {
      const result = await api.post(`/changes/${change.id}/apply`, { confirm: true });
      await refresh();
      toast(`Recorded: ${assessment.change.device} ${assessment.change.change_type_label}`, "success");
      showAnalysis(result.change, result.assessment);
    } catch (error) {
      toast(error.message, "error");
      try {
        const [latest] = await api.get(`/assessments?change_id=${change.id}&limit=1`);
        if (latest) showAnalysis(await api.get(`/changes/${change.id}`), latest);
      } catch {
        /* keep current view */
      }
    }
  });
}

async function copyCommands(button) {
  const pre = ui.panel.querySelector(`pre[data-commands="${CSS.escape(button.dataset.commandsId)}"]`);
  try {
    await navigator.clipboard.writeText(pre.textContent);
    toast("Commands copied", "success");
  } catch {
    toast("Copy failed — select the text manually", "warning");
  }
}

async function reanalyze(button) {
  const { change } = state.analysis;
  await withBusy(button, async () => {
    try {
      const assessment = await api.post(`/changes/${change.id}/analyze`);
      const updated = await api.get(`/changes/${change.id}`);
      showAnalysis(updated, assessment);
      toast(`Re-analysed: ${assessment.risk_level} risk (${assessment.total_risk_score}/100)`, "info");
    } catch (error) {
      toast(error.message, "error");
    }
  });
}

async function saveAssessment(button) {
  await withBusy(button, async () => {
    try {
      const assessment = await api.post(`/assessments/${state.analysis.assessment.id}/save`);
      state.analysis.assessment = assessment;
      if (["draft", "analyzed"].includes(state.analysis.change.status)) state.analysis.change.status = "saved";
      renderPanel();
      toast("Assessment saved to history", "success");
    } catch (error) {
      toast(error.message, "error");
    }
  });
}

async function openChangeFromUrl(changeId) {
  try {
    const change = await api.get(`/changes/${changeId}`);
    if (change.network_id !== store.network.id) return;
    const [latest] = await api.get(`/assessments?change_id=${change.id}&limit=1`);
    if (latest) showAnalysis(change, latest);
    else if (store.devices.has(change.device_id)) state.changeForm.openModify(change);
  } catch (error) {
    toast(error.message, "error");
  }
}

function select(selection) {
  state.selection = selection;
  const { cy } = state;
  cy.elements().unselect();
  if (selection) {
    const id = selection.kind === "device" ? nodeId(selection.id) : edgeId(selection.id);
    cy.getElementById(id).select();
  }
  renderPanel();
}

const selectDevice = (id) => {
  openDetailsPanel();
  state.showAnalysis = false;
  state.showHealth = false;
  state.showConnections = false;
  select({ kind: "device", id });
};
const selectLink = (id) => {
  openDetailsPanel();
  state.showAnalysis = false;
  state.showHealth = false;
  state.showConnections = false;
  select({ kind: "link", id });
};

// ------------------------------------------------------------- data loading
async function refresh({ resetPositions = false } = {}) {
  const topology = await api.get(`/networks/${store.network.id}/topology`);
  loadTopology(topology);
  syncGraph(state.cy, store, { resetPositions });
  updateCanvasEmpty();
  updateDiscoveryStatus();
  renderPanel();
}

/** After a model edit, earlier analysis results describe a model that no longer exists. */
async function refreshAfterEdit() {
  if (state.health || state.analysis) {
    state.health = null;
    state.analysis = null;
    state.showHealth = false;
    state.showAnalysis = false;
    state.skipped = new Set();
    clearHighlight(state.cy);
    ui.legend.classList.add("d-none");
  }
  // A reload must not reopen an assessment of the previous model.
  const url = new URL(window.location.href);
  if (url.searchParams.has("change")) {
    url.searchParams.delete("change");
    history.replaceState(null, "", url);
  }
  await refresh();
}

async function openNetwork(networkId) {
  try {
    const topology = await api.get(`/networks/${networkId}/topology`);
    loadTopology(topology);
  } catch (error) {
    toast(error.message, "error");
    return false;
  }
  localStorage.setItem(LAST_NETWORK_KEY, String(networkId));
  const url = new URL(window.location.href);
  url.searchParams.set("network", networkId);
  url.searchParams.delete("change");
  history.replaceState(null, "", url);
  ui.networkSelect.value = String(networkId);
  setPageTitle("Network Topology Workspace", store.network.name);

  state.cy.elements().remove();
  state.analysis = null;
  state.showAnalysis = false;
  state.health = null;
  state.showHealth = false;
  state.showConnections = false;
  state.connectionDeviceId = null;
  state.skipped = new Set();
  ui.legend.classList.add("d-none");
  syncGraph(state.cy, store, { resetPositions: true });
  setDirty(false);
  cancelConnect();
  state.selection = null;
  setNetworkControlsEnabled(true);
  updateCanvasEmpty();
  updateDiscoveryStatus();
  renderPanel();
  await fitWorkspaceAfterLayout();
  return true;
}

async function loadNetworkList() {
  const networks = await api.get("/networks");
  ui.networkSelect.innerHTML = networks.length
    ? networks.map((n) => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join("")
    : `<option value="">No networks</option>`;
  ui.networkSelect.disabled = networks.length === 0;
  return networks;
}

// ------------------------------------------------------------------ actions
async function saveTopology(button) {
  await withBusy(button, async () => {
    try {
      const result = await api.put(`/networks/${store.network.id}/topology/positions`, {
        positions: collectPositions(state.cy),
      });
      setDirty(false);
      toast(`Topology saved (${result.updated} device positions)`, "success");
      await refresh();
    } catch (error) {
      toast(error.message, "error");
    }
  });
}

async function reloadTopology() {
  if (state.dirty) {
    const ok = await confirmDialog({
      title: "Discard unsaved layout?",
      message: "<p class='mb-0'>Reloading restores device positions from the database. Unsaved moves will be lost.</p>",
      confirmLabel: "Reload",
    });
    if (!ok) return;
  }
  try {
    await refresh({ resetPositions: true });
    setDirty(false);
    toast("Topology reloaded from database", "info");
  } catch (error) {
    toast(error.message, "error");
  }
}

async function deleteDevice(device) {
  const linkCount = linksForDevice(device.id).length;
  const ok = await confirmDialog({
    title: "Delete device",
    message: `<p>Delete <strong>${escapeHtml(device.name)}</strong>?</p>
      <p class="small text-muted mb-0">This also removes its ${device.interfaces.length} interface(s) and ${linkCount} link(s).</p>`,
    confirmLabel: "Delete Device",
    danger: true,
  });
  if (!ok) return;
  try {
    await api.del(`/devices/${device.id}`);
    toast(`Device ${device.name} deleted`, "success");
    state.selection = null;
    await refreshAfterEdit();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function deleteLink(link) {
  const describe = (dev, iface) => `${dev}${iface ? " " + iface : ""}`;
  const ok = await confirmDialog({
    title: "Delete link",
    message: `<p class="mb-0">Remove the link <strong>${escapeHtml(describe(link.source_device_name, link.source_interface_name))}</strong>
      ↔ <strong>${escapeHtml(describe(link.destination_device_name, link.destination_interface_name))}</strong>?</p>`,
    confirmLabel: "Delete Link",
    danger: true,
  });
  if (!ok) return;
  try {
    await api.del(`/links/${link.id}`);
    toast("Link deleted", "success");
    state.selection = null;
    await refreshAfterEdit();
  } catch (error) {
    toast(error.message, "error");
  }
}

function deleteSelection() {
  const { selection } = state;
  if (selection?.kind === "device") deleteDevice(store.devices.get(selection.id));
  if (selection?.kind === "link") deleteLink(store.links.get(selection.id));
}

// ------------------------------------------------------------- connect mode
function startConnect(sourceId = null) {
  if (store.devices.size < 2) {
    toast("Add at least two devices before connecting them.", "warning");
    return;
  }
  state.connect = { active: true, sourceId: null };
  ui.connectBtn.classList.replace("btn-outline-secondary", "btn-secondary");
  ui.connectBtn.setAttribute("aria-pressed", "true");
  ui.connectBanner.classList.remove("d-none");
  if (sourceId) setConnectSource(sourceId);
  else ui.connectBannerText.textContent = "Connect mode: click the source device";
}

function setConnectSource(deviceId) {
  state.cy.nodes().removeClass("ng-connect-source");
  state.connect.sourceId = deviceId;
  state.cy.getElementById(nodeId(deviceId)).addClass("ng-connect-source");
  ui.connectBannerText.textContent = `Source: ${store.devices.get(deviceId).name} — now click the destination device`;
}

function cancelConnect() {
  state.connect = { active: false, sourceId: null };
  state.cy?.nodes().removeClass("ng-connect-source");
  ui.connectBtn.classList.replace("btn-secondary", "btn-outline-secondary");
  ui.connectBtn.setAttribute("aria-pressed", "false");
  ui.connectBanner.classList.add("d-none");
}

function handleConnectTap(deviceId) {
  if (!state.connect.sourceId) {
    setConnectSource(deviceId);
    return;
  }
  if (deviceId === state.connect.sourceId) {
    toast("Choose a different device as the destination.", "warning");
    return;
  }
  const sourceId = state.connect.sourceId;
  cancelConnect();
  state.dialogs.link.open({ sourceId, destinationId: deviceId });
}

// ------------------------------------------------------------------- wiring
function bindCanvas() {
  const { cy } = state;
  cy.on("tap", "node", (event) => {
    const deviceId = event.target.data("deviceId");
    if (state.connect.active) {
      state.lastConnectTap = Date.now();
      handleConnectTap(deviceId);
      // keep the selection highlight consistent with the panel
      setTimeout(() => select(state.selection), 0);
      return;
    }
    selectDevice(deviceId);
  });
  cy.on("tap", "edge", (event) => {
    if (state.connect.active) return;
    selectLink(event.target.data("linkId"));
  });
  // EVE-NG style: double-click a device to open its console/CLI.
  cy.on("dbltap", "node", (event) => {
    // Not while connecting devices (two quick taps on two nodes) or while a dialog is open.
    if (state.connect.active || Date.now() - (state.lastConnectTap || 0) < 800 || document.querySelector(".modal.show")) return;
    const device = store.devices.get(event.target.data("deviceId"));
    if (device && (device.management_ip || device.access?.console)) openTerminal(device);
  });
  cy.on("tap", (event) => {
    if (event.target !== cy) return;
    if (state.analysis && !state.showAnalysis) state.showAnalysis = true;
    else if (!state.analysis && state.health && !state.showHealth) state.showHealth = true;
    select(null);
  });
  cy.on("dragfree", "node", () => setDirty(true));
}

function bindToolbar() {
  ui.networkSelect.addEventListener("change", async () => {
    const target = Number(ui.networkSelect.value);
    if (state.dirty) {
      const ok = await confirmDialog({
        title: "Discard unsaved layout?",
        message: "<p class='mb-0'>You have unsaved device positions in this network. Switch anyway?</p>",
        confirmLabel: "Switch Network",
      });
      if (!ok) {
        ui.networkSelect.value = String(store.network.id);
        return;
      }
    }
    openNetwork(target);
  });

  document.getElementById("btn-add-device").addEventListener("click", () => state.dialogs.device.openCreate());
  document.getElementById("btn-add-link").addEventListener("click", () =>
    state.dialogs.link.open({ sourceId: state.selection?.kind === "device" ? state.selection.id : null })
  );
  ui.connectBtn.addEventListener("click", () => (state.connect.active ? cancelConnect() : startConnect()));
  document.getElementById("btn-connect-cancel").addEventListener("click", cancelConnect);
  document.getElementById("btn-save").addEventListener("click", (e) => saveTopology(e.currentTarget));
  document.getElementById("btn-reload").addEventListener("click", reloadTopology);
  document.getElementById("btn-health").addEventListener("click", (e) => runHealthCheck(e.currentTarget));
  document.getElementById("btn-connections").addEventListener("click", () => showConnections());
  document.getElementById("btn-report").addEventListener("click", (e) => saveNetworkReport(e.currentTarget));
  document.getElementById("btn-layout").addEventListener("click", () => {
    if (state.cy.nodes().empty()) return;
    autoArrange(state.cy, store.network);
    setDirty(true);
    toast("Devices auto-arranged. Save Topology to keep this layout.", "info");
  });
  document.getElementById("btn-fit").addEventListener("click", () => fitGraph(state.cy));
  document.getElementById("btn-zoom-in").addEventListener("click", () =>
    state.cy.zoom({ level: state.cy.zoom() * 1.2, renderedPosition: centre() })
  );
  document.getElementById("btn-zoom-out").addEventListener("click", () =>
    state.cy.zoom({ level: state.cy.zoom() / 1.2, renderedPosition: centre() })
  );

  const palette = document.getElementById("palette");
  palette.insertAdjacentHTML(
    "beforeend",
    Object.entries(DEVICE_TYPES)
      .map(
        ([type, meta]) =>
          `<button type="button" class="ng-palette-item" data-device-type="${type}" title="Add ${meta.label}">
            <img src="${deviceIcon(type)}" alt="">${meta.short || meta.label}</button>`
      )
      .join("")
  );
  palette.addEventListener("click", (event) => {
    const item = event.target.closest("[data-device-type]");
    if (item) state.dialogs.device.openCreate(item.dataset.deviceType);
  });
}

function centre() {
  const container = state.cy.container();
  return { x: container.clientWidth / 2, y: container.clientHeight / 2 };
}

function bindPanel() {
  ui.panel.addEventListener("click", (event) => {
    const flow = event.target.closest("[data-impact-index]");
    if (flow && state.analysis) {
      const impact = state.analysis.assessment.impacts[Number(flow.dataset.impactIndex)];
      ui.panel.querySelectorAll(".ng-flow.active").forEach((el) => el.classList.remove("active"));
      flow.classList.add("active");
      focusPath(state.cy, impact.path_link_ids);
      return;
    }
    const target = event.target.closest("[data-action]");
    if (!target) return;
    event.preventDefault();
    const device = state.selection?.kind === "device" ? store.devices.get(state.selection.id) : null;
    const link = state.selection?.kind === "link" ? store.links.get(state.selection.id) : null;
    switch (target.dataset.action) {
      case "edit-device":
        state.dialogs.device.openEdit(device);
        break;
      case "manage-interfaces":
        state.dialogs.config.open(device.id);
        break;
      case "propose-change":
        state.changeForm.open(device);
        break;
      case "manage-intents":
        state.dialogs.intents.open();
        break;
      case "show-analysis":
        state.showAnalysis = true;
        select(null);
        break;
      case "close-analysis":
        closeAnalysis();
        break;
      case "modify-change":
        if (!state.changeForm.openModify(state.analysis.change)) {
          toast("The device of this change no longer exists.", "warning");
        }
        break;
      case "reanalyze":
        reanalyze(target);
        break;
      case "save-assessment":
        saveAssessment(target);
        break;
      case "apply-change":
        applyChange(target);
        break;
      case "submit-change":
        state.workflow.submit(state.analysis.change, target);
        break;
      case "approve-change":
      case "reject-change":
        state.workflow.decide(state.analysis.change, state.analysis.assessment, target.dataset.action === "approve-change");
        break;
      case "execute-change":
        state.workflow.execute(state.analysis.change, state.analysis.assessment);
        break;
      case "show-executions":
        state.workflow.showExecutions(state.analysis.change);
        break;
      case "confirm-change":
      case "rollback-change":
        state.workflow.confirm(state.analysis.change, target.dataset.action === "confirm-change", target);
        break;
      case "copy-commands":
        copyCommands(target);
        break;
      case "show-health":
        showHealth();
        break;
      case "close-health":
        closeHealth();
        break;
      case "rerun-health":
        runHealthCheck(target);
        break;
      case "show-connections":
        showConnections(Number(target.dataset.deviceId) || null);
        break;
      case "device-access":
        openDeviceAccess(Number(target.dataset.deviceId) || null);
        break;
      case "open-cli":
        openTerminal(device || store.devices.get(Number(target.dataset.deviceId)));
        break;
      case "open-gui":
        openPortals(device || store.devices.get(Number(target.dataset.deviceId)));
        break;
      case "discovery-auth":
        authenticateDevices([Number(target.dataset.deviceId)]);
        break;
      case "discovery-report":
        openDiscoveryReport();
        break;
      case "close-connections":
        state.showConnections = false;
        renderPanel();
        closeDetailsPanel();
        break;
      case "save-network-report":
        saveNetworkReport(target);
        break;
      case "apply-fix":
        applyFix(Number(target.dataset.issueIndex), Number(target.dataset.fixIndex), target, target.dataset.kind);
        break;
      case "fix-all":
        fixAll(target);
        break;
      case "skip-issue":
        state.skipped.add(state.health.issues[Number(target.dataset.issueIndex)].key);
        highlightHealth(state.health);
        renderPanel();
        break;
      case "unskip-all":
        state.skipped = new Set();
        highlightHealth(state.health);
        renderPanel();
        break;
      case "review-fix":
        reviewFix(Number(target.dataset.issueIndex), Number(target.dataset.fixIndex), target, target.dataset.kind);
        break;
      case "focus-issue": {
        const issue = state.health.issues[Number(target.dataset.issueIndex)];
        ui.panel.querySelectorAll(".ng-issue.active").forEach((el) => el.classList.remove("active"));
        target.closest(".ng-issue").classList.add("active");
        highlightHealth({ ...state.health, issues: [issue] });
        focusPath(state.cy, issue.link_ids);
        state.cy.nodes().unselect();
        issue.device_ids.forEach((id) => state.cy.getElementById(nodeId(id)).select());
        break;
      }
      case "connect-from":
        state.dialogs.link.open({ sourceId: device.id });
        break;
      case "delete-device":
        deleteDevice(device);
        break;
      case "delete-link":
        deleteLink(link);
        break;
      case "select-device":
        selectDevice(Number(target.dataset.deviceId));
        break;
      case "select-link":
        selectLink(Number(target.dataset.linkId));
        break;
      default:
        break;
    }
  });
}

function bindKeyboard() {
  document.addEventListener("keydown", (event) => {
    if (document.querySelector(".modal.show")) return;
    const tag = event.target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || event.target.isContentEditable) return;
    if (event.key === "Escape") {
      if (state.connect.active) cancelConnect();
      else if (state.analysis && state.showAnalysis) closeAnalysis();
      else if (state.health && state.showHealth) closeHealth();
      else if (state.showConnections) { state.showConnections = false; renderPanel(); closeDetailsPanel(); }
      else select(null);
    } else if ((event.key === "Delete" || event.key === "Backspace") && state.selection && !state.showAnalysis && !state.showHealth) {
      event.preventDefault();
      deleteSelection();
    }
  });
  window.addEventListener("beforeunload", (event) => {
    if (state.dirty) {
      event.preventDefault();
      event.returnValue = "";
    }
  });
}

async function main() {
  state.user = await initShell({ active: "topology", title: "Network Topology Workspace", subtitle: "" });
  state.cy = createGraph(document.getElementById("cy"));
  // Read-only handle for debugging in the browser console and for the E2E test script.
  window.netguardWorkspace = { cy: state.cy, store };
  state.dialogs = createDialogs({
    refresh: () => refreshAfterEdit(),
    freePosition: () => freePosition(state.cy),
    selectDevice,
    selectLink,
  });
  state.changeForm = createChangeForm({
    onAnalyzed: (change, assessment) => {
      showAnalysis(change, assessment);
    },
  });
  bindCanvas();
  bindToolbar();
  bindPanel();
  bindKeyboard();
  setupDiscoveryAccess();
  let resizeFrame = 0;
  document.addEventListener("netguard:layout-changed", () => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(() => {
      const canvas = document.getElementById("cy");
      if (state.cy && (Math.abs(state.cy.width() - canvas.clientWidth) >= 1 || Math.abs(state.cy.height() - canvas.clientHeight) >= 1)) state.cy.resize();
    });
  });

  let networks = [];
  try {
    networks = await loadNetworkList();
  } catch (error) {
    toast(error.message, "error");
  }
  if (!networks.length) {
    clearTopology();
    setNetworkControlsEnabled(false);
    setPageTitle("Network Topology Workspace", "No network selected");
    updateCanvasEmpty();
    renderPanel();
    return;
  }

  const requested = Number(new URLSearchParams(window.location.search).get("network"));
  const remembered = Number(localStorage.getItem(LAST_NETWORK_KEY));
  const ids = networks.map((n) => n.id);
  const target = [requested, remembered].find((id) => ids.includes(id)) ?? ids[0];
  if (requested && !ids.includes(requested)) toast(`Network ${requested} was not found.`, "warning");
  const requestedChange = Number(new URLSearchParams(window.location.search).get("change"));
  const opened = await openNetwork(target);
  if (opened && requestedChange) await openChangeFromUrl(requestedChange);
  const requestedDevice = Number(new URLSearchParams(window.location.search).get("device"));
  if (opened && !requestedChange && store.devices.has(requestedDevice)) selectDevice(requestedDevice);
  const query = new URL(window.location.href);
  const initialDiscovery = query.searchParams.has("discovery");
  if (opened && query.searchParams.get("discovery") === "authenticate" && isDiscoveredNetwork(store.network)) {
    await openDeviceAccess();
  }
  if (query.searchParams.has("discovery")) {
    query.searchParams.delete("discovery");
    history.replaceState(null, "", query);
  }
  if (opened && initialDiscovery && !requestedChange && !requestedDevice && isDiscoveredNetwork(store.network)
      && !document.querySelector(".modal.show") && store.links.size) {
    showConnections();
    await fitWorkspaceAfterLayout();
  }
}

main();
