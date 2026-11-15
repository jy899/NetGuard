import { api } from "../api.js";
import { initShell } from "../layout.js";
import { CATEGORY_LABELS, changeStatusBadge, recommendationBadge, riskBadge } from "../risk.js";
import { confirmDialog, escapeHtml, formatDate, toast } from "../ui.js";
import { initValidation, loadValidation } from "./validation.js";

const networkSelect = document.getElementById("filter-network");
const statusSelect = document.getElementById("filter-status");
const listEl = document.getElementById("change-list");
let changes = [];

const OPEN_STATES = { pending_approval: ["warn", "waiting"], approved: ["ok", "approved, not applied"], awaiting_confirm: ["warn", "to confirm"] };

/** Changes grouped under their network: one collapsible card per network, newest activity first. */
function render() {
  const summary = document.getElementById("change-summary");
  if (!changes.length) {
    summary.textContent = "";
    listEl.innerHTML = `<div class="ng-empty"><i class="bi bi-arrow-left-right"></i><h4>No changes yet</h4>
      <p>Open a network, press Analyze and choose a fix, or select a device and choose <strong>Propose Change</strong>.</p>
      <a class="btn btn-sm btn-primary" href="/topology">Open Topology Workspace</a></div>`;
    return;
  }
  const groups = new Map();
  for (const c of changes) {
    if (!groups.has(c.network_id)) groups.set(c.network_id, { id: c.network_id, name: c.network_name || `Network ${c.network_id}`, items: [] });
    groups.get(c.network_id).items.push(c);
  }
  summary.textContent = `${changes.length} change${changes.length === 1 ? "" : "s"} in ${groups.size} network${groups.size === 1 ? "" : "s"}`;
  listEl.innerHTML = [...groups.values()].map((g) => {
    const counts = Object.entries(OPEN_STATES).map(([status, [cls, label]]) => {
      const n = g.items.filter((c) => c.status === status).length;
      return n ? `<span class="ng-count ${cls}">${n} ${label}</span>` : "";
    }).join("");
    return `<details class="ng-group" open data-network-id="${g.id}">
      <summary><i class="bi bi-chevron-right ng-group-caret"></i><i class="bi bi-diagram-3 text-primary"></i>
        <span class="fw-semibold">${escapeHtml(g.name)}</span><span class="small text-muted-ng">${g.items.length} change${g.items.length === 1 ? "" : "s"}</span>
        <span class="d-flex gap-1 flex-wrap">${counts}</span>
        <a class="btn btn-sm btn-light border ms-auto" href="/topology?network=${g.id}"><i class="bi bi-box-arrow-up-right me-1"></i>Open map</a></summary>
      <div class="table-responsive"><table class="table ng-table ng-group-table">
        <colgroup><col style="width:22%"><col style="width:22%"><col style="width:13%"><col style="width:12%"><col style="width:13%"><col style="width:18%"></colgroup>
        <thead><tr><th>Change</th><th>Current → Proposed</th><th>Risk</th><th>Status</th><th>Updated</th><th></th></tr></thead>
        <tbody>${g.items.map(row).join("")}</tbody></table></div></details>`;
  }).join("");
}

function row(c) {
  const latest = c.latest_assessment;
  return `<tr data-change-id="${c.id}">
    <td><div class="fw-semibold">${escapeHtml(c.device_name)} <span class="text-muted-ng fw-normal small">#${c.id}</span></div>
      <div class="small">${escapeHtml(c.change_type_label)}${c.target_name ? ` · <span class="mono">${escapeHtml(c.target_name)}</span>` : ""}</div>
      <div class="small text-muted-ng">${escapeHtml(CATEGORY_LABELS[c.category] || c.category)}</div></td>
    <td class="mono small" style="max-width:300px"><span class="text-muted-ng">${escapeHtml(c.current_value)}</span><br>→ ${escapeHtml(c.proposed_value)}</td>
    <td>${latest ? `${riskBadge(latest.risk_level)} <span class="small text-muted-ng">${latest.total_risk_score}/100</span><div class="mt-1">${recommendationBadge(latest.recommendation, latest.risk_level)}</div>` : '<span class="small text-muted-ng">Not checked</span>'}</td>
    <td>${changeStatusBadge(c.status, c)}</td>
    <td class="text-muted-ng small">${formatDate(c.updated_at)}</td>
    <td class="actions">
      <a class="btn btn-sm btn-primary" href="/topology?network=${c.network_id}&change=${c.id}" data-action="open">${c.status === "approved" ? "Apply" : "Open"}</a>
      ${latest ? `<a class="btn btn-sm btn-light border" href="/reports?assessment=${latest.id}" title="Report" aria-label="Report"><i class="bi bi-file-earmark-text"></i></a>` : ""}
      <button class="btn btn-sm btn-light border text-danger" data-action="delete" title="Delete change" aria-label="Delete change ${c.id}"><i class="bi bi-trash"></i></button>
    </td></tr>`;
}

async function load() {
  const params = new URLSearchParams();
  if (networkSelect.value) params.set("network_id", networkSelect.value);
  if (statusSelect.value) params.set("status", statusSelect.value);
  try {
    changes = await api.get(`/changes?${params}`);
    render();
  } catch (error) {
    toast(error.message, "error");
  }
}

listEl.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action=delete]");
  if (!button) return;
  const id = Number(button.closest("tr").dataset.changeId);
  const ok = await confirmDialog({
    title: "Delete change",
    message: `<p class="mb-0">Delete change #${id} and all of its analysis results, including saved assessments?</p>`,
    confirmLabel: "Delete Change",
    danger: true,
  });
  if (!ok) return;
  try {
    await api.del(`/changes/${id}`);
    toast("Change deleted", "success");
    await load();
  } catch (error) {
    toast(error.message, "error");
  }
});

async function main() {
  await initShell({ active: "changes", title: "Validation & Changes", subtitle: "Baseline comparison and pre-deployment checks" });
  const networks = await api.get("/networks");
  networkSelect.innerHTML = `<option value="">All networks</option>` +
    networks.map((n) => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join("");
  const requestedNetwork = new URLSearchParams(location.search).get("network");
  if (requestedNetwork && networks.some((n) => String(n.id) === String(requestedNetwork))) {
    networkSelect.value = String(requestedNetwork);
  }
  networkSelect.addEventListener("change", () => { load(); loadValidation(networkSelect.value); });
  const requestedStatus = new URLSearchParams(location.search).get("status");
  if (requestedStatus && [...statusSelect.options].some((o) => o.value === requestedStatus)) statusSelect.value = requestedStatus;
  statusSelect.addEventListener("change", load);
  await Promise.all([load(), initValidation(networkSelect.value)]);
  const tab = new URLSearchParams(location.search).get("tab");
  if (tab === "validation" || tab === "rules") bootstrap.Tab.getOrCreateInstance(document.getElementById(`${tab}-tab`)).show();
}

main();
