import { api } from "../api.js";
import { changeBlock, checksBlock, findingsBlock, flowItem } from "../analysis-view.js";
import { riskBadge, severityBadge } from "../risk.js";
import { escapeHtml, formatDate, toast } from "../ui.js";

let runs = [];

function renderRules(rules) {
  document.getElementById("rule-list").innerHTML = `<div class="table-responsive"><table class="table ng-table">
    <thead><tr><th>Rule ID</th><th>Rule</th><th>Rule pack</th><th>Condition</th><th>Severity</th><th>Impact Type</th>
      <th>Severity factor S</th><th>Recommendation</th></tr></thead>
    <tbody>${rules
      .map((r) => `<tr>
        <td class="mono fw-semibold">${escapeHtml(r.id)}</td>
        <td class="fw-semibold">${escapeHtml(r.name)}</td>
        <td>${escapeHtml(r.pack_label || r.category_label)}</td>
        <td class="small">${escapeHtml(r.condition)}</td>
        <td>${severityBadge(r.severity)}</td>
        <td class="mono small">${escapeHtml(r.impact_type)}</td>
        <td class="mono small">${r.severity_factor}</td>
        <td class="small">${escapeHtml(r.recommendation)}</td></tr>`)
      .join("")}</tbody></table></div>`;
}

function renderRuns() {
  const el = document.getElementById("run-list");
  document.getElementById("run-count").textContent = `${runs.length} most recent`;
  if (!runs.length) {
    el.innerHTML = `<div class="ng-empty"><i class="bi bi-shield-check"></i><h4>No validation runs yet</h4>
      <p>Analyse a proposed change in the Topology Workspace to run the rule set.</p></div>`;
    return;
  }
  el.innerHTML = `<div class="table-responsive"><table class="table ng-table">
    <thead><tr><th>Run</th><th>Change</th><th>Result</th><th>Passed</th><th>Failed</th><th>Pre-existing</th><th>Risk</th></tr></thead>
    <tbody>${runs
      .map((a, index) => {
        const count = (status) => a.checks.filter((c) => c.status === status).length;
        return `<tr data-run-index="${index}" style="cursor:pointer">
          <td class="text-muted-ng">#${a.id}</td>
          <td><div class="fw-semibold">${escapeHtml(a.change.device)} · ${escapeHtml(a.change.change_type_label)}</div>
            <div class="small text-muted-ng mono text-truncate" style="max-width:320px" title="${escapeHtml(a.change.proposed_value)}">${escapeHtml(a.change.current_value)} → ${escapeHtml(a.change.proposed_value)}</div>
            <div class="small text-muted-ng">${formatDate(a.created_at)}</div></td>
          <td>${riskBadge(a.validation_result === "PASS" ? "LOW" : "CRITICAL", a.validation_result)}</td>
          <td>${count("passed")}</td><td>${count("failed")}</td><td>${count("warning")}</td>
          <td>${riskBadge(a.risk_level)}</td></tr>`;
      })
      .join("")}</tbody></table></div>`;
}

function showRun(index) {
  const a = runs[index];
  document.querySelectorAll("#run-list tr.table-active").forEach((tr) => tr.classList.remove("table-active"));
  document.querySelector(`#run-list tr[data-run-index="${index}"]`)?.classList.add("table-active");
  document.getElementById("run-badge").innerHTML = riskBadge(a.validation_result === "PASS" ? "LOW" : "CRITICAL", `Run #${a.id} ${a.validation_result}`);
  document.getElementById("run-checks").innerHTML = `${checksBlock(a.checks)}
    <details class="mt-3" open><summary class="small fw-semibold">Baseline and proposed configuration</summary><div class="mt-2">${changeBlock(a)}</div></details>
    <details class="mt-3"><summary class="small fw-semibold">Before-and-after flow results</summary><div class="mt-2">${a.impacts.map((item, n) => flowItem(item, n, false)).join("") || '<p class="small text-muted-ng">No evaluated flows.</p>'}</div></details>
    <details class="mt-3"><summary class="small fw-semibold">Recommended corrections</summary><div class="mt-2">${findingsBlock(a.findings)}<ul class="small">${a.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ul></div></details>
    <div class="mt-3 d-flex gap-2"><a class="btn btn-sm btn-outline-primary" href="/reports?assessment=${a.id}">Open Report</a>
    <a class="btn btn-sm btn-light border" href="/topology?network=${a.network_id}&change=${a.change_id}">Open in Workspace</a></div>`;
}

export async function loadValidation(networkId = "") {
  try {
    const params = new URLSearchParams({ limit: "100" });
    if (networkId) params.set("network_id", networkId);
    runs = await api.get(`/assessments?${params}`);
    renderRuns();
    if (runs.length) showRun(0);
    else {
      document.getElementById("run-badge").innerHTML = "";
      document.getElementById("run-checks").innerHTML = '<p class="small text-muted-ng mb-0">No validation results for this network.</p>';
    }
  } catch (error) {
    toast(error.message, "error");
  }
}

export async function initValidation(networkId = "") {
  document.getElementById("run-list").addEventListener("click", (event) => {
    const row = event.target.closest("tr[data-run-index]");
    if (row) showRun(Number(row.dataset.runIndex));
  });
  try { renderRules(await api.get("/rules")); } catch (error) { toast(error.message, "error"); }
  await loadValidation(networkId);
}
