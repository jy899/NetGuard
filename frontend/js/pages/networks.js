import { api } from "../api.js";
import { initShell } from "../layout.js";
import { confirmDialog, escapeHtml, fillForm, formatDate, readForm, showFormError, toast, withBusy } from "../ui.js";
import { environmentLabel } from "../evidence-view.js";
import { load as loadDiscovery, setupScanner } from "../discovery/scanner.js";

const state = { networks: [], editingId: null, provider: null, connection: null, scan: null };
const $ = (id) => document.getElementById(id);
const form = document.getElementById("network-form");
const modalEl = document.getElementById("network-modal");
let modal;

function renderList() {
  const container = document.getElementById("network-list");
  if (!state.networks.length) {
    container.innerHTML = `
      <div class="ng-empty">
        <i class="bi bi-hdd-network"></i>
        <h4>No networks yet</h4>
        <p>Import an EVE-NG or GNS3 lab, discover an authorised range or import device configurations to get started.</p>
      </div>`;
    return;
  }
  const rows = state.networks
    .map(
      (n) => `
      <tr data-network-id="${n.id}">
        <td>
          <a href="/topology?network=${n.id}" class="fw-semibold text-decoration-none">${escapeHtml(n.name)}</a>
          <div class="small text-muted-ng text-truncate" style="max-width:360px">${escapeHtml(n.description || "—")}</div>
        </td>
        <td><span class="ng-type-badge ng-environment-badge">${escapeHtml(environmentLabel(n))}</span></td>
        <td>${n.device_count}</td>
        <td>${n.link_count}</td>
        <td class="text-muted-ng">${escapeHtml(n.created_by_username || "—")}</td>
        <td class="text-muted-ng">${formatDate(n.updated_at)}</td>
        <td class="actions">
          <a class="btn btn-sm btn-primary" href="/topology?network=${n.id}" data-action="open"><i class="bi bi-diagram-3 me-1"></i>Open Topology</a>
          ${n.source === "discovery" ? '<button class="btn btn-sm btn-light border" data-action="discovery">Discovery</button>' : ""}
          <button class="btn btn-sm btn-light border" data-action="edit" title="Edit network" aria-label="Edit ${escapeHtml(n.name)}"><i class="bi bi-pencil"></i></button>
          <button class="btn btn-sm btn-light border text-danger" data-action="delete" title="Delete network" aria-label="Delete ${escapeHtml(n.name)}"><i class="bi bi-trash"></i></button>
        </td>
      </tr>`
    )
    .join("");
  container.innerHTML = `
    <div class="table-responsive">
      <table class="table ng-table">
        <thead><tr><th>Name</th><th>Environment</th><th>Devices</th><th>Links</th><th>Created by</th><th>Last updated</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

async function loadNetworks() {
  state.networks = await api.get("/networks");
  $("network-count").textContent = state.networks.length;
  renderList();
  renderVirtualProjects();
}

function renderVirtualProjects() {
  const current = $("virtual-project").value;
  const projects = state.networks.filter((network) => network.environment === "virtual");
  $("virtual-project").innerHTML = '<option value="new">Import a new laboratory</option>' + projects.map((network) =>
    `<option value="${network.id}">${escapeHtml(network.name)} · ${escapeHtml({ "eve-ng": "EVE-NG", gns3: "GNS3", sample: "example" }[network.source] || network.source)}</option>`).join("");
  if (projects.some((network) => String(network.id) === current)) $("virtual-project").value = current;
  selectVirtualProject();
}

function selectVirtualProject() {
  const network = state.networks.find((item) => String(item.id) === $("virtual-project").value);
  $("virtual-open").disabled = !network;
  $("virtual-new-options").classList.toggle("d-none", !!network);
  if (network) $("provider-box").classList.add("d-none");
  $("virtual-project-summary").textContent = network ? `${network.device_count} devices · ${network.link_count} links · ${network.metadata_json?.server ? `from ${network.metadata_json.server}` : "saved model"}. Opening preserves your topology, analysis and reviewed corrections.` : "Select a saved laboratory workspace or import a lab from an EVE-NG or GNS3 server below.";
}

function existingProviderProject(labId) {
  return state.networks.find((network) => network.environment === "virtual" && network.source === state.connection?.provider &&
    network.metadata_json?.server === state.connection.server && network.metadata_json?.lab_id === labId);
}

function selectProviderProject() {
  const id = $("provider-project").value;
  const existing = existingProviderProject(id);
  $("provider-project-note").textContent = existing ? "This lab is already imported. Open the saved workspace to keep your changes, or import it again as a new workspace." : "NetGuard imports the nodes, cables and startup configurations of this lab.";
  $("provider-project-open").textContent = existing ? "Open Saved Workspace" : "Import Lab";
  $("provider-project-reimport").classList.toggle("d-none", !existing);
}

function openModal(network = null) {
  state.editingId = network?.id ?? null;
  document.getElementById("network-modal-title").textContent = network ? "Edit Network" : "New Network";
  fillForm(form, network || { network_type: "Enterprise" });
  showFormError(form, "");
  modal.show();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = readForm(form);
  if (!data.name) {
    showFormError(form, "Network name is required.");
    return;
  }
  await withBusy(document.getElementById("network-submit"), async () => {
    try {
      if (state.editingId) {
        await api.put(`/networks/${state.editingId}`, data);
        toast("Network updated", "success");
      } else {
        const created = await api.post("/networks", data);
        toast(`Network "${created.name}" created`, "success");
      }
      modal.hide();
      await loadNetworks();
      showTab("saved");
    } catch (error) {
      showFormError(form, error.message);
    }
  });
});

async function deleteNetwork(network) {
  const ok = await confirmDialog({
    title: "Delete network",
    message: `<p>Delete <strong>${escapeHtml(network.name)}</strong>?</p>
      <p class="mb-0 text-muted small">This permanently removes ${network.device_count} device(s), their interfaces and
      ${network.link_count} link(s).</p>`,
    confirmLabel: "Delete Network",
    danger: true,
  });
  if (!ok) return;
  try {
    await api.del(`/networks/${network.id}`);
    if (localStorage.getItem("netguard.lastNetwork") === String(network.id)) {
      localStorage.removeItem("netguard.lastNetwork");
    }
    toast("Network deleted", "success");
    await loadNetworks();
  } catch (error) {
    toast(error.message, "error");
  }
}

document.getElementById("network-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const id = Number(button.closest("tr").dataset.networkId);
  const network = state.networks.find((n) => n.id === id);
  if (button.dataset.action === "edit") openModal(network);
  if (button.dataset.action === "delete") deleteNetwork(network);
  if (button.dataset.action === "discovery") loadScan(id);
});

const imp = {
  form: document.getElementById("import-form"),
  el: document.getElementById("import-modal"),
  preview: document.getElementById("imp-preview"),
};

function importPayload(dryRun) {
  const data = readForm(imp.form);
  return { name: data.name || "Imported network", configs: data.configs || "", endpoints: data.endpoints || "",
    flows: data.flows || "", dry_run: dryRun };
}

function showPreview(res) {
  const s = res.summary;
  const names = { router: "router", firewall: "firewall", switch: "switch", pc: "PC", server: "server", internet: "internet" };
  const types = Object.entries(s.by_type).filter(([, n]) => n)
    .map(([t, n]) => `${n} ${names[t]}${n > 1 ? (t === "switch" ? "es" : "s") : ""}`).join(", ");
  const warn = res.warnings.length
    ? `<div class="alert alert-warning small mt-2 mb-0"><strong>${res.warnings.length} note(s):</strong><ul class="mb-0 ps-3">
        ${res.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul></div>`
    : `<div class="small text-success mt-2"><i class="bi bi-check-circle me-1"></i>Everything was understood.</div>`;
  imp.preview.innerHTML = `
    <div class="ng-card p-3">
      <div class="fw-semibold mb-1">Found ${s.devices} devices (${escapeHtml(types)})</div>
      <div class="small text-muted-ng">${s.interfaces} interfaces · ${s.links} links · ${s.vlans} VLANs ·
        ${s.routes} static routes · ${s.acl_rules} ACL rules · ${s.flows} required flows</div>
      ${warn}
    </div>`;
  imp.preview.classList.remove("d-none");
  imp.preview.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function runImport(dryRun, button) {
  const body = importPayload(dryRun);
  if (!body.configs.trim()) {
    showFormError(imp.form, "Paste device output or add config files first.");
    return;
  }
  showFormError(imp.form, "");
  await withBusy(button, async () => {
    try {
      const res = await api.post("/networks/import", body);
      showPreview(res);
      if (!dryRun) {
        toast(`Imported ${res.summary.devices} devices`, "success");
        window.location.href = `/topology?network=${res.network_id}`;
      }
    } catch (error) {
      showFormError(imp.form, error.message);
    }
  });
}

const project = { files: [], previous: null };

function readBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
    reader.onerror = () => reject(new Error(`${file.name} could not be read`));
    reader.readAsDataURL(file);
  });
}

function renderProjectFiles() {
  document.getElementById("imp-project-list").innerHTML = project.files.length
    ? project.files.map((f, i) => `<span class="ng-type-badge me-1 mb-1 d-inline-block">${escapeHtml(f.name)} <button type="button" class="btn btn-link btn-sm p-0 ms-1" data-remove-file="${i}" aria-label="Remove ${escapeHtml(f.name)}">×</button></span>`).join("")
    : "";
  document.getElementById("imp-submit").disabled = !project.files.length;
}

async function addProjectFiles(list) {
  for (const file of list) {
    if (file.size > 60 * 1024 * 1024) { toast(`${file.name} is larger than 60 MB`, "error"); continue; }
    project.files = project.files.filter((f) => f.name !== file.name);
    project.files.push({ name: file.name, content: await readBase64(file) });
  }
  renderProjectFiles();
}

function singleDevicePrompt(res) {
  const box = document.getElementById("imp-single");
  box.innerHTML = `<div class="alert alert-info mb-0"><div class="fw-semibold mb-1"><i class="bi bi-info-circle me-1"></i>One device was imported</div>
    <p class="small mb-2">A single configuration has no neighbour tables, so its connections are unknown. Add the configurations of the neighbouring devices, or let NetGuard infer the connected subnets and neighbours from this configuration (marked Logical).</p>
    <div class="d-flex gap-2 flex-wrap"><label class="btn btn-sm btn-primary mb-0" for="imp-project"><i class="bi bi-plus-lg me-1"></i>Add Neighbour Configurations</label>
    <button type="button" class="btn btn-sm btn-outline-primary" id="imp-infer"><i class="bi bi-diagram-3 me-1"></i>Infer Connected Subnets</button>
    <a class="btn btn-sm btn-light border" href="/topology?network=${res.network_id}">Open as Imported</a></div></div>`;
  box.classList.remove("d-none");
  document.getElementById("imp-infer").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
    try {
      const result = await api.post(`/networks/${res.network_id}/infer-neighbours`);
      toast(`Inferred ${result.devices.length} neighbour(s) and ${result.links} logical connection(s)`, "success");
      window.location.href = `/topology?network=${res.network_id}`;
    } catch (error) { showFormError(imp.form, error.message); }
  }));
}

async function importProject(button) {
  showFormError(imp.form, "");
  await withBusy(button, async () => {
    try {
      const name = imp.form.name.value.trim() || null;
      const res = await api.post("/networks/import-project", { name, files: project.files });
      if (project.previous) {
        // The earlier single-device import is replaced by the combined import.
        try { await api.del(`/networks/${project.previous}`); } catch { /* keep it if it cannot be removed */ }
        project.previous = null;
      }
      if (res.single_device) {
        project.previous = res.network_id;
        singleDevicePrompt(res);
        return;
      }
      const flows = res.scenario_flows ? `${res.scenario_flows} scenario flow(s)` : `${res.inferred_flows || 0} inferred flow(s)`;
      toast(`Imported ${res.summary.devices} devices, ${res.summary.links} connections, ${flows}`, "success");
      window.location.href = `/topology?network=${res.network_id}`;
    } catch (error) { showFormError(imp.form, error.message); }
  });
}

function setupImport() {
  const modal = new bootstrap.Modal(imp.el);
  document.getElementById("btn-import").addEventListener("click", () => {
    imp.preview.classList.add("d-none");
    document.getElementById("imp-single").classList.add("d-none");
    project.files = []; project.previous = null;
    renderProjectFiles();
    showFormError(imp.form, "");
    modal.show();
  });
  document.getElementById("imp-sample").addEventListener("click", async (event) => {
    await withBusy(event.currentTarget, async () => {
      const sample = await api.get("/networks/import/sample");
      fillForm(imp.form, sample);
      imp.preview.classList.add("d-none");
    });
  });
  const input = document.getElementById("imp-project");
  input.addEventListener("change", async (event) => { await addProjectFiles([...event.target.files]); event.target.value = ""; });
  const drop = document.getElementById("imp-drop");
  ["dragenter", "dragover"].forEach((type) => drop.addEventListener(type, (event) => { event.preventDefault(); drop.classList.add("border-primary"); }));
  ["dragleave", "drop"].forEach((type) => drop.addEventListener(type, () => drop.classList.remove("border-primary")));
  drop.addEventListener("drop", (event) => { event.preventDefault(); addProjectFiles([...event.dataTransfer.files]); });
  document.getElementById("imp-project-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-file]");
    if (!button) return;
    project.files.splice(Number(button.dataset.removeFile), 1);
    renderProjectFiles();
  });
  document.getElementById("imp-check").addEventListener("click", (e) => runImport(true, e.currentTarget));
  document.getElementById("imp-paste-submit").addEventListener("click", (e) => runImport(false, e.currentTarget));
  imp.form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (project.files.length) importProject(document.getElementById("imp-submit"));
  });
}

function showTab(name) {
  bootstrap.Tab.getOrCreateInstance($(`${name}-tab`)).show();
}

async function loadScan(id) {
  try {
    await loadDiscovery(id);
    showTab("real");
  } catch (error) { toast(error.message, "error"); }
}

async function showDevice(result, id) {
  state.scan = result;
  const device = state.scan.devices.find((d) => d.id === id);
  const links = state.scan.links.filter((l) => l.source_device_id === id || l.destination_device_id === id);
  $("device-modal-title").textContent = device.name;
  const cls = device.classification;
  const evidence = device.provenance?.length
    ? device.provenance.map((p) => `<li><span class="badge ${p.access === "credential-free" ? "text-bg-light border" : "text-bg-primary"} me-1">${escapeHtml(p.access)}</span><strong>${escapeHtml(p.technique)}</strong>: ${escapeHtml(p.detail)}</li>`).join("")
    : device.evidence.map((e) => `<li>${escapeHtml(e)}</li>`).join("");
  $("device-details").innerHTML = `<dl class="row small"><dt class="col-4">IP address</dt><dd class="col-8 font-monospace">${escapeHtml(device.ip)}</dd><dt class="col-4">MAC address</dt><dd class="col-8 font-monospace">${escapeHtml(device.mac || "Unknown")}</dd><dt class="col-4">Vendor / model</dt><dd class="col-8">${escapeHtml([device.vendor, device.model].filter(Boolean).join(" · ") || "Unknown")}</dd><dt class="col-4">Identified as</dt><dd class="col-8">${escapeHtml(device.role || device.type)}</dd><dt class="col-4">Services</dt><dd class="col-8">${escapeHtml((device.open_services || []).join(", ") || "None detected")}</dd>${cls ? `<dt class="col-4">Discovery status</dt><dd class="col-8" data-device-status>${escapeHtml(cls.label)}${cls.missing.length ? ` · missing: ${escapeHtml(cls.missing.join(", "))}` : ""}</dd>` : ""}<dt class="col-4">Authentication</dt><dd class="col-8">${escapeHtml(device.auth_status)}</dd></dl>${(device.location_notes || []).map((n) => `<p class="small"><i class="bi bi-geo-alt me-1"></i>${escapeHtml(n)}</p>`).join("")}<h6>Discovery evidence</h6><ul class="small">${evidence}</ul><h6>Interface connections</h6>${links.length ? links.map((l) => `<div class="border rounded p-2 mb-2 small"><strong>${escapeHtml(l.source_device_name)} ${escapeHtml(l.source_interface_name || "Unknown")} ↔ ${escapeHtml(l.destination_device_name)} ${escapeHtml(l.destination_interface_name || "Unknown")}</strong><div>${escapeHtml(l.discovery_status)} · ${Math.round((l.confidence || 0) * 100)}% confidence · ${escapeHtml(l.state || "Unknown")} · ${l.speed_mbps ? l.speed_mbps + " Mb/s" : "Speed unknown"}</div><div class="text-muted-ng">${(l.evidence || []).map(escapeHtml).join(" ")}</div></div>`).join("") : '<p class="small text-muted-ng">No verified interface relationship is available.</p>'}<div class="d-flex gap-2 mt-3"><a class="btn btn-outline-primary" href="/topology?network=${state.scan.network_id}&device=${device.id}">Open in Topology</a></div>`;
  bootstrap.Modal.getOrCreateInstance($("device-modal")).show();
}

function setupWorkflows() {
  $("virtual-project").addEventListener("change", selectVirtualProject);
  $("virtual-open").addEventListener("click", () => {
    const network = state.networks.find((item) => String(item.id) === $("virtual-project").value && item.environment === "virtual");
    if (network) window.location.href = `/topology?network=${network.id}`;
  });
  $("provider-cancel").addEventListener("click", () => {
    $("provider-box").classList.add("d-none"); $("provider-password").value = ""; state.connection = null;
  });
  $("provider-form").addEventListener("input", (event) => {
    if (event.target.matches("input")) { state.connection = null; $("provider-labs").innerHTML = ""; }
  });
  document.querySelectorAll("[data-provider]").forEach((button) => button.addEventListener("click", () => {
    state.provider = button.dataset.provider;
    state.connection = null;
    $("provider-title").textContent = `${state.provider === "eve-ng" ? "EVE-NG" : "GNS3"} connection`;
    $("provider-server").value = localStorage.getItem(`netguard.lab.${state.provider}`) || "";
    $("provider-server").placeholder = state.provider === "eve-ng" ? "http://192.168.56.10" : "http://127.0.0.1:3080";
    $("provider-password").value = "";
    $("provider-labs").innerHTML = "";
    showFormError($("provider-form"), "");
    $("provider-box").classList.remove("d-none");
    $("provider-server").focus();
  }));
  $("provider-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    showFormError(event.currentTarget, "");
    await withBusy($("provider-connect"), async () => {
      try {
        const credentials = { provider: state.provider, server: $("provider-server").value.trim(), username: $("provider-user").value.trim(),
          password: $("provider-password").value };
        const response = await api.post("/labs/connect", credentials);
        if (!response.connected) throw new Error(response.message);
        state.connection = { ...response, credentials };
        localStorage.setItem(`netguard.lab.${state.provider}`, response.server);
        if (!response.labs.length) {
          $("provider-labs").innerHTML = `<div class="small text-muted-ng" role="status">${escapeHtml(response.message)} Create a lab on the server first.</div>`;
          return;
        }
        $("provider-labs").innerHTML = `<div class="small text-success mb-3" role="status">${escapeHtml(response.message)}</div><label class="form-label" for="provider-project">${state.provider === "eve-ng" ? "Lab" : "Project"}</label><select id="provider-project" class="form-select mb-2">${response.labs.map((lab) => `<option value="${escapeHtml(lab.id)}">${escapeHtml(lab.name)}${lab.folder ? ` · ${escapeHtml(lab.folder)}` : ""}${existingProviderProject(lab.id) ? ' · imported' : ''}</option>`).join("")}</select><p id="provider-project-note" class="small text-muted-ng"></p><div class="d-flex gap-2"><button type="button" class="btn btn-primary" id="provider-project-open">Import Lab</button><button type="button" class="btn btn-outline-secondary d-none" id="provider-project-reimport">Import Again</button></div>`;
        selectProviderProject();
      } catch (error) { showFormError($("provider-form"), error.message); }
    });
  });
  $("provider-labs").addEventListener("input", () => showFormError($("provider-form"), ""));
  $("provider-labs").addEventListener("change", (event) => {
    if (event.target.id === "provider-project") selectProviderProject();
  });
  $("provider-labs").addEventListener("click", (event) => {
    const button = event.target.closest("#provider-project-open, #provider-project-reimport");
    if (!button || !state.connection) return;
    withBusy(button, async () => {
      try {
        const id = $("provider-project").value;
        const existing = existingProviderProject(id);
        if (existing && button.id === "provider-project-open") { window.location.href = `/topology?network=${existing.id}`; return; }
        const result = await api.post("/labs/import", { ...state.connection.credentials, lab_id: id });
        $("provider-password").value = "";
        toast(`Imported ${result.network.device_count} devices and ${result.network.link_count} lab cables`, "success");
        window.location.href = `/topology?network=${result.network_id}`;
      } catch (error) { showFormError($("provider-form"), error.message); }
    });
  });
  $("btn-example").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
    try {
      const result = await api.post("/networks/samples", { scenario: $("example-scenario").value });
      window.location.href = `/topology?network=${result.network_id}`;
    } catch (error) { toast(error.message, "error"); }
  }));
  setupScanner({ showDevice, onComplete: () => loadNetworks() });
}

async function main() {
  await initShell({ active: "networks", title: "Networks", subtitle: "Laboratories, discovery and configuration imports" });
  modal = new bootstrap.Modal(modalEl);
  modalEl.addEventListener("shown.bs.modal", () => form.name.focus());
  document.getElementById("btn-new-network").addEventListener("click", () => openModal());
  setupImport();
  setupWorkflows();
  try {
    await loadNetworks();
  } catch (error) {
    toast(error.message, "error");
  }
  const params = new URLSearchParams(window.location.search);
  if (params.get("create")) openModal();
  const environment = params.get("environment");
  if (environment === "real" || environment === "saved") showTab(environment);
  if (params.get("network") && environment === "real") await loadScan(Number(params.get("network")));
}

main();
