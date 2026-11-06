import { api } from "../api.js";
import { DEVICE_TYPES, deviceIcon } from "../device-types.js";
import { RISK_COLORS, recommendationBadge, riskBadge } from "../risk.js";
import { initShell } from "../layout.js";
import { escapeHtml, formatDate, toast } from "../ui.js";

function statCard({ label, value, icon, tone = "", note }) {
  return `
    <div class="col-sm-6 col-xl-3">
      <div class="ng-card ng-stat">
        <div class="ng-stat-icon ${tone}"><i class="bi ${icon}"></i></div>
        <div>
          <div class="ng-stat-label">${label}</div>
          <div class="ng-stat-value" data-stat="${label}">${value}</div>
          <div class="ng-stat-note">${note}</div>
        </div>
      </div>
    </div>`;
}

function renderStats(summary) {
  document.getElementById("stat-cards").innerHTML = [
    statCard({ label: "Networks", value: summary.networks, icon: "bi-hdd-network", note: "Modelled networks" }),
    statCard({
      label: "Devices",
      value: summary.devices,
      icon: "bi-router",
      note: `${summary.interfaces} interfaces · ${summary.links} links`,
    }),
    statCard({
      label: "Detected Issues",
      value: summary.detected_issues ?? 0,
      icon: "bi-exclamation-triangle",
      tone: "warn",
      note: "Latest network analysis results",
    }),
    statCard({
      label: "Change Assessments",
      value: summary.saved_assessments,
      icon: "bi-shield-check",
      tone: "neutral",
      note: `${summary.high_critical_changes} high / critical · ${summary.pending_changes} pending`,
    }),
  ].join("");
}

function renderActivity(items) {
  const container = document.getElementById("recent-activity");
  if (!items.length) {
    container.innerHTML = `<div class="ng-card-body small text-muted-ng">No network scans or analyses yet. <a href="/networks">Open Networks</a> to begin.</div>`;
    return;
  }
  container.innerHTML = `<ul class="ng-activity-list">${items.slice(0, 6).map((item) => `<li>
    <span class="ng-activity-icon"><i class="bi ${item.kind === "scan" || item.kind === "discovery" ? "bi-radar" : item.kind === "report" ? "bi-file-earmark-text" : item.kind === "change" ? "bi-shield-check" : "bi-diagram-3"}"></i></span>
    <div class="flex-grow-1 min-w-0"><a class="fw-semibold text-decoration-none" href="/reports?${item.assessment_id ? `assessment=${item.assessment_id}` : `history=${item.id}`}">${escapeHtml(item.title)}</a>
      <div class="small text-muted-ng">${escapeHtml(item.network_name || "")} · ${escapeHtml(activitySummary(item.summary))}</div></div>
    <span class="small text-muted-ng">${formatDate(item.created_at)}</span></li>`).join("")}</ul>`;
}

const STATUS_LABELS = { healthy: "Healthy", issues: "Issues found", incomplete: "Incomplete coverage" };
const plural = (count, word) => `${count} ${word}${count === 1 ? "" : "s"}`;

function activitySummary(summary) {
  if (!summary || typeof summary !== "object") return summary || "";
  // "completed" only says the record was saved; analysis statuses are shown as words, not repeated counts.
  return [summary.device_count != null ? plural(summary.device_count, "device") : "",
    summary.issue_count != null ? plural(summary.issue_count, "issue") : "",
    summary.risk_level ? `${summary.risk_level} risk` : "",
    STATUS_LABELS[summary.status] || ""].filter(Boolean).join(" · ");
}

function renderRecent(networks) {
  const container = document.getElementById("recent-networks");
  if (!networks.length) {
    container.innerHTML = `
      <div class="ng-empty">
        <i class="bi bi-hdd-network"></i>
        <h4>No networks yet</h4>
        <p>Create your first network to start modelling its topology.</p>
        <a class="btn btn-primary btn-sm" href="/networks?create=1"><i class="bi bi-plus-lg me-1"></i>Create Network</a>
      </div>`;
    return;
  }
  const rows = networks
    .map(
      (n) => `
      <tr>
        <td><a href="/topology?network=${n.id}" class="fw-semibold text-decoration-none">${escapeHtml(n.name)}</a></td>
        <td><span class="ng-type-badge">${escapeHtml(n.network_type)}</span></td>
        <td>${n.device_count}</td>
        <td>${n.link_count}</td>
        <td class="text-muted-ng">${formatDate(n.updated_at)}</td>
        <td class="actions"><a class="btn btn-sm btn-outline-primary" href="/topology?network=${n.id}">Open</a></td>
      </tr>`
    )
    .join("");
  container.innerHTML = `
    <div class="table-responsive">
      <table class="table ng-table">
        <thead><tr><th>Name</th><th>Type</th><th>Devices</th><th>Links</th><th>Last updated</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderInventory(byType, total) {
  document.getElementById("inventory-total").textContent = `${total} total`;
  const max = Math.max(1, ...Object.values(byType));
  document.getElementById("device-inventory").innerHTML = Object.entries(DEVICE_TYPES)
    .map(([type, meta]) => {
      const count = byType[type] || 0;
      return `
        <div class="d-flex align-items-center gap-2 mb-2">
          <img src="${deviceIcon(type)}" width="22" height="22" alt="">
          <div class="flex-grow-1">
            <div class="d-flex justify-content-between small"><span>${meta.label}</span><span class="fw-semibold">${count}</span></div>
            <div class="ng-bar"><span style="width:${(count / max) * 100}%;background:${meta.color}"></span></div>
          </div>
        </div>`;
    })
    .join("");
}

function renderAssessments(items) {
  const el = document.getElementById("recent-assessments");
  if (!items.length) {
    el.innerHTML = `<div class="ng-empty py-4"><i class="bi bi-shield-check"></i><h4>No assessments yet</h4>
      <p>Select a device in the Topology Workspace and choose <strong>Propose Change</strong>.</p></div>`;
    return;
  }
  el.innerHTML = `<div class="table-responsive"><table class="table ng-table">
    <thead><tr><th>Change</th><th>Network</th><th>Score</th><th>Risk</th><th>Recommendation</th><th>Analysed</th><th></th></tr></thead>
    <tbody>${items
      .map((a) => `<tr>
        <td><div class="fw-semibold">${escapeHtml(a.device_name)}</div><div class="small text-muted-ng mono">${escapeHtml(a.change_label)}</div></td>
        <td>${escapeHtml(a.network_name)}</td>
        <td class="fw-semibold">${a.total_risk_score}</td>
        <td>${riskBadge(a.risk_level)}</td>
        <td>${recommendationBadge(a.recommendation, a.risk_level)}</td>
        <td class="small text-muted-ng">${formatDate(a.created_at)}${a.saved ? ' <i class="bi bi-check-circle-fill text-success" title="Saved"></i>' : ""}</td>
        <td class="actions"><a class="btn btn-sm btn-outline-primary" href="/topology?network=${a.network_id}&change=${a.change_id}">Open</a></td>
      </tr>`)
      .join("")}</tbody></table></div>`;
}

function renderDistribution(dist) {
  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  document.getElementById("risk-distribution").innerHTML = total
    ? Object.entries(dist)
        .map(([level, count]) => `<div class="d-flex align-items-center gap-2 mb-2">
          <span style="width:84px">${riskBadge(level)}</span>
          <div class="flex-grow-1"><div class="ng-bar"><span style="width:${(count / total) * 100}%;background:${RISK_COLORS[level]}"></span></div></div>
          <span class="fw-semibold" style="width:24px;text-align:right">${count}</span></div>`)
        .join("") + `<div class="small text-muted-ng">Latest analysis of each of ${total} change(s).</div>`
    : `<p class="small text-muted-ng mb-0">No changes analysed yet.</p>`;
}

async function main() {
  await initShell({ active: "dashboard", title: "Dashboard", subtitle: "NetGuard overview" });
  try {
    const summary = await api.get("/dashboard/summary");
    renderStats(summary);
    renderActivity(summary.recent_activity || []);
    renderRecent(summary.recent_networks);
    renderInventory(summary.devices_by_type, summary.devices);
    renderAssessments(summary.recent_assessments);
    renderDistribution(summary.risk_distribution);
  } catch (error) {
    toast(error.message, "error");
  }
}

main();
