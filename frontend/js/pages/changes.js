import { api } from "../api.js";
import { initShell } from "../layout.js";
import { CATEGORY_LABELS, changeStatusBadge, recommendationBadge, riskBadge } from "../risk.js";
import { confirmDialog, escapeHtml, formatDate, toast } from "../ui.js";
import { initValidation, loadValidation } from "./validation.js";

const networkSelect = document.getElementById("filter-network");
const statusSelect = document.getElementById("filter-status");
const listEl = document.getElementById("change-list");
let changes = [];

function render() {
  if (!changes.length) {
    listEl.innerHTML = `<div class="ng-empty"><i class="bi bi-arrow-left-right"></i><h4>No changes yet</h4>
      <p>Open the Topology Workspace, select a device and choose <strong>Propose Change</strong>.</p>
      <a class="btn btn-sm btn-primary" href="/topology">Open Topology Workspace</a></div>`;
    return;
  }
  listEl.innerHTML = `<div class="table-responsive"><table class="table ng-table">
    <thead><tr><th>#</th><th>Network / Device</th><th>Change</th><th>Current → Proposed</th><th>Latest Risk</th>
      <th>Recommendation</th><th>Status</th><th>Updated</th><th></th></tr></thead>
    <tbody>${changes
      .map((c) => {
        const latest = c.latest_assessment;
        return `<tr data-change-id="${c.id}">
          <td class="text-muted-ng">${c.id}</td>
          <td><div class="fw-semibold">${escapeHtml(c.device_name)}</div><div class="small text-muted-ng">${escapeHtml(c.network_name || "")}</div></td>
          <td><div>${escapeHtml(c.change_type_label)}${c.target_name ? ` · <span class="mono">${escapeHtml(c.target_name)}</span>` : ""}</div>
            <div class="small text-muted-ng">${escapeHtml(CATEGORY_LABELS[c.category] || c.category)}${c.reason ? ` · ${escapeHtml(c.reason)}` : ""}</div></td>
          <td class="mono small" style="max-width:280px"><span class="text-muted-ng">${escapeHtml(c.current_value)}</span><br>→ ${escapeHtml(c.proposed_value)}</td>
          <td>${latest ? `${riskBadge(latest.risk_level)} <span class="small text-muted-ng">${latest.total_risk_score}/100</span>` : "—"}</td>
          <td>${latest ? recommendationBadge(latest.recommendation, latest.risk_level) : "—"}</td>
          <td>${changeStatusBadge(c.status)}</td>
          <td class="text-muted-ng small">${formatDate(c.updated_at)}</td>
          <td class="actions">
            <a class="btn btn-sm btn-primary" href="/topology?network=${c.network_id}&change=${c.id}" data-action="open">
              <i class="bi bi-diagram-3 me-1"></i>Open</a>
            ${latest ? `<a class="btn btn-sm btn-light border" href="/reports?assessment=${latest.id}" title="Report" aria-label="Report"><i class="bi bi-file-earmark-text"></i></a>` : ""}
            <button class="btn btn-sm btn-light border text-danger" data-action="delete" title="Delete change" aria-label="Delete change ${c.id}"><i class="bi bi-trash"></i></button>
          </td></tr>`;
      })
      .join("")}</tbody></table></div>`;
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
  statusSelect.addEventListener("change", load);
  await Promise.all([load(), initValidation(networkSelect.value)]);
  const tab = new URLSearchParams(location.search).get("tab");
  if (tab === "validation" || tab === "rules") bootstrap.Tab.getOrCreateInstance(document.getElementById(`${tab}-tab`)).show();
}

main();
