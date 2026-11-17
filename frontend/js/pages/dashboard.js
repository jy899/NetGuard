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

// The issue count covers analysed networks only, so a network nobody has analysed is not shown as "0 issues".
function issuesCard(summary) {
  const networks = summary.networks ?? 0;
  const analysed = summary.analysed_networks ?? 0;
  const none = networks > 0 && analysed === 0;
  let note = "From the latest analyses";
  if (none) note = "Not analysed yet · press Analyze on the map";
  else if (analysed < networks) note = `From the latest analyses · ${analysed} of ${networks} networks analysed`;
  return statCard({
    label: "Detected Issues",
    value: none ? "—" : summary.detected_issues ?? 0,
    icon: "bi-exclamation-triangle",
    tone: "warn",
    note,
  });
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
    issuesCard(summary),
    statCard({
      label: "Changes",
      value: summary.total_changes ?? 0,
      icon: "bi-shield-check",
      tone: "neutral",
      note: `${summary.awaiting_approval} to approve · ${summary.approved_changes} to apply${summary.high_critical_changes ? ` · ${summary.high_critical_changes} high risk` : ""}`,
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
      <div class="small text-muted-ng">${escapeHtml([item.network_name, activitySummary(item.summary)].filter(Boolean).join(" · "))}</div></div>
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
        <p>Scan a network or import a lab to draw its map.</p>
        <a class="btn btn-primary btn-sm" href="/networks"><i class="bi bi-plus-lg me-1"></i>Add Network</a>
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

/** First-run steps; the card disappears once all three are done. */
async function renderGetStarted(summary) {
  let logins = null;
  try { logins = (await api.get("/credential-profiles")).length; } catch { /* not allowed for this group */ }
  const steps = [
    { done: summary.networks > 0, title: "Add a network", text: "Scan a range or import a GNS3, EVE-NG or Packet Tracer lab.", href: "/networks", action: "Add Network" },
    { done: logins === null || logins > 0, title: "Save a device login", text: "Read-only SSH or SNMPv3, so NetGuard can read configs and ports.", href: "/settings#credentials", action: "Add Login" },
    { done: summary.analysis_runs > 0, title: "Find problems", text: "Open the map and press Analyze.", href: "/topology", action: "Open Map" },
  ];
  const el = document.getElementById("get-started");
  if (steps.every((s) => s.done)) { el.innerHTML = ""; return; }
  el.innerHTML = `<div class="ng-card mb-3" data-get-started><div class="ng-card-header"><h3>Get started</h3><span class="small text-muted-ng">${steps.filter((s) => s.done).length} of 3 done</span></div>
    <div class="ng-card-body"><ol class="list-unstyled mb-0 d-grid gap-2">${steps.map((s, i) => `<li class="d-flex align-items-center gap-3">
      <span class="badge rounded-pill ${s.done ? "text-bg-success" : "text-bg-light border"}">${s.done ? '<i class="bi bi-check-lg"></i>' : i + 1}</span>
      <div class="flex-grow-1"><div class="fw-semibold ${s.done ? "text-decoration-line-through text-muted-ng" : ""}">${s.title}</div><div class="small text-muted-ng">${s.text}</div></div>
      ${s.done ? "" : `<a class="btn btn-sm btn-outline-primary" href="${s.href}">${s.action}</a>`}</li>`).join("")}</ol></div></div>`;
}

function renderChangeNotice(summary) {
  const el = document.getElementById("change-notice");
  const parts = [];
  if (summary.approved_changes) parts.push(`<a class="alert alert-success d-flex align-items-center gap-2 mb-2 text-decoration-none" href="/changes?status=approved" data-approved-notice>
    <i class="bi bi-patch-check"></i><span><strong>${summary.approved_changes} approved fix${summary.approved_changes === 1 ? "" : "es"}</strong> not applied yet.</span><span class="ms-auto small fw-semibold">Apply now <i class="bi bi-arrow-right"></i></span></a>`);
  if (summary.awaiting_approval) parts.push(`<a class="alert alert-light border d-flex align-items-center gap-2 mb-2 text-decoration-none" href="/changes?status=pending_approval">
    <i class="bi bi-hourglass-split"></i><span><strong>${summary.awaiting_approval}</strong> waiting for approval.</span><span class="ms-auto small fw-semibold">Review <i class="bi bi-arrow-right"></i></span></a>`);
  el.innerHTML = parts.length ? `<div class="mb-3">${parts.join("")}</div>` : "";
}

async function main() {
  await initShell({ active: "dashboard", title: "Dashboard", subtitle: "NetGuard overview" });
  try {
    const summary = await api.get("/dashboard/summary");
    renderGetStarted(summary);
    renderChangeNotice(summary);
    renderStats(summary);
    renderActivity(summary.recent_activity || []);
    renderRecent(summary.recent_networks);
    renderInventory(summary.devices_by_type, summary.devices);
    renderDistribution(summary.risk_distribution);
  } catch (error) {
    toast(error.message, "error");
  }
}

main();
