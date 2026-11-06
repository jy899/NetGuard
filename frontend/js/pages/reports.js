// Reports & History: saved assessments, and a printable report per assessment.
import { api } from "../api.js";
import {
  changeBlock,
  checksBlock,
  decisionBlock,
  aiBlock,
  dimensionsBlock,
  explanationBlock,
  findingsBlock,
  flowItem,
  scoreBlock,
} from "../analysis-view.js";
import { initShell, setPageTitle } from "../layout.js";
import { recommendationBadge, riskBadge, severityBadge } from "../risk.js";
import { escapeHtml, formatDate, toast, withBusy } from "../ui.js";
import { advisoriesBlock, diagnosticSections, environmentLabel, expectedActionBadge, flowResultBadge, scopeText } from "../evidence-view.js";
import { deviceLabel } from "../device-types.js";

const listView = document.getElementById("report-list-view");
const detailView = document.getElementById("report-detail-view");
const networkSelect = document.getElementById("filter-network");
const kindSelect = document.getElementById("filter-kind");

let listRequest = 0;

async function loadList() {
  // Filters can change while an earlier list request is still loading; only the latest request may render.
  const request = ++listRequest;
  const params = new URLSearchParams({ limit: "200" });
  if (networkSelect.value) params.set("network_id", networkSelect.value);
  if (document.querySelector("input[name=scope]:checked").value === "saved") params.set("saved", "true");
  const el = document.getElementById("report-list");
  try {
    const historyParams = new URLSearchParams({ limit: "200" });
    if (networkSelect.value) historyParams.set("network_id", networkSelect.value);
    if (kindSelect.value && kindSelect.value !== "assessment") historyParams.set("kind", kindSelect.value);
    const [assessments, history] = await Promise.all([
      !kindSelect.value || kindSelect.value === "assessment" ? api.get(`/assessments?${params}`) : [],
      kindSelect.value !== "assessment" ? api.get(`/history?${historyParams}`) : [],
    ]);
    if (request !== listRequest) return;
    const items = [
      ...assessments.map((item) => ({ item, kind: "assessment", created_at: item.created_at })),
      ...history.map((item) => ({ item, kind: item.kind, created_at: item.created_at })),
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    if (!items.length) {
      el.innerHTML = `<div class="ng-empty"><i class="bi bi-file-earmark-text"></i><h4>No matching records</h4>
        <p>Run a network scan or analysis, or save a change assessment.</p><a class="btn btn-sm btn-primary" href="/networks">Open Networks</a></div>`;
      return;
    }
    el.innerHTML = `<div class="table-responsive"><table class="table ng-table">
      <thead><tr><th>Record</th><th>Network</th><th>Summary</th><th>Result</th><th>Created</th><th></th></tr></thead>
      <tbody>${items
        .map(({ item: a, kind }) => kind === "assessment" ? `<tr>
          <td><span class="ng-type-badge">Change assessment</span><div class="small text-muted-ng mt-1">#${a.id}${a.saved ? " · Saved" : ""}</div></td>
          <td>${escapeHtml(a.network_name || "")}</td><td><div class="fw-semibold">${escapeHtml(a.change.device)} · ${escapeHtml(a.change.change_type_label)}</div><div class="small mono text-muted-ng">${escapeHtml(a.change.current_value)} → ${escapeHtml(a.change.proposed_value)}</div></td>
          <td>${riskBadge(a.risk_level)}<div class="small mt-1">Validation ${escapeHtml(a.validation_result)}</div></td><td class="small text-muted-ng">${formatDate(a.created_at)}</td>
          <td class="actions"><a class="btn btn-sm btn-primary" href="/reports?assessment=${a.id}">View Report</a></td></tr>`
          : `<tr><td><span class="ng-type-badge">${escapeHtml(recordLabel(kind))}</span><div class="small text-muted-ng mt-1">#${a.id} · Sample Data</div></td><td>${escapeHtml(a.network_name || "")}</td>
            <td><div class="fw-semibold">${escapeHtml(a.title)}</div><div class="small text-muted-ng">${escapeHtml(historySummary(a.summary))}</div></td><td><span class="ng-badge-plain">${escapeHtml(a.status || "Saved")}</span>${a.issue_count ? `<div class="small mt-1">${a.issue_count} issue(s)</div>` : ""}</td><td class="small text-muted-ng">${formatDate(a.created_at)}</td><td class="actions"><a class="btn btn-sm btn-primary" href="/reports?history=${a.id}">View Report</a></td></tr>`)
        .join("")}</tbody></table></div>`;
  } catch (error) {
    toast(error.message, "error");
  }
}

function renderReport(a) {
  const affected = a.impacts.filter((i) => i.affected);
  const unaffected = a.impacts.filter((i) => !i.affected);
  detailView.innerHTML = `
    <div class="ng-report">
      <div class="d-flex justify-content-between align-items-center mb-3 ng-no-print">
        <a href="/reports" class="btn btn-sm btn-light border"><i class="bi bi-arrow-left me-1"></i>All reports</a>
        <div class="d-flex gap-2">
          <a class="btn btn-sm btn-outline-primary" href="/topology?network=${a.network_id}&change=${a.change_id}"><i class="bi bi-diagram-3 me-1"></i>Open in Workspace</a>
          <div class="btn-group btn-group-sm" role="group" aria-label="Export report"><button class="btn btn-outline-primary" data-export="pdf"><i class="bi bi-file-earmark-pdf me-1"></i>PDF</button><button class="btn btn-outline-primary" data-export="html">HTML</button><button class="btn btn-outline-primary" data-export="json">JSON</button></div>
          <button class="btn btn-sm btn-light border" id="btn-print"><i class="bi bi-printer me-1"></i>Print</button>
        </div>
      </div>
      <div class="ng-card ng-card-body mb-3">
        <div class="d-flex justify-content-between flex-wrap gap-3">
          <div>
            <div class="small text-muted-ng text-uppercase fw-semibold">NetGuard Change Assessment Report</div>
            <h1 class="mb-1">Assessment #${a.id}: ${escapeHtml(a.change.device)} · ${escapeHtml(a.change.change_type_label)}</h1>
            <div class="small text-muted-ng">Network: ${escapeHtml(a.network_name || "")} · Analysed ${formatDate(a.created_at)}
              by ${escapeHtml(a.created_by_username || "—")} · ${a.saved ? `Saved ${formatDate(a.saved_at)}` : "Not saved"}</div>
          </div>
          <div>${recommendationBadge(a.recommendation, a.risk_level)}</div>
        </div>
      </div>
      <div class="row g-3">
        <div class="col-md-6"><div class="ng-card ng-card-body h-100"><h2 class="mt-0">Proposed Change</h2>${changeBlock(a)}</div></div>
        <div class="col-md-6"><div class="ng-card ng-card-body h-100"><h2 class="mt-0">Risk Assessment</h2>${scoreBlock(a)}<div class="mt-3">${dimensionsBlock(a)}</div></div></div>
      </div>
      <div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Recommendation</h2>${decisionBlock(a)}</div>
      ${a.ai?.available ? `<div class="ng-card ng-card-body mt-3"><h2 class="mt-0">AI Forecast</h2>${aiBlock(a)}</div>` : ""}
      <div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Explanation</h2>${explanationBlock(a)}</div>
      <div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Findings (${a.findings.length})</h2>${findingsBlock(a.findings)}
        ${a.existing_issues.length ? `<h2>Pre-existing issues (not caused by this change)</h2>${findingsBlock(a.existing_issues)}` : ""}</div>
      ${(a.advisories || []).length ? `<div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Security &amp; hygiene advisories</h2>${advisoriesBlock(a.advisories)}</div>` : ""}
      ${(a.coverage_notes || []).length ? `<div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Analysis coverage notes</h2><ul class="small ps-3 mb-0">${a.coverage_notes.map(note => `<li>${escapeHtml(note)}</li>`).join("")}</ul></div>` : ""}
      <div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Impact Analysis</h2>
        <div class="small text-muted-ng mb-2">Affected devices: ${escapeHtml(a.affected_devices.join(", ") || "none")}</div>
        <div class="row g-3"><div class="col-lg-6"><div class="small fw-semibold mb-2">Affected flows (${affected.length})</div>
          ${affected.map((i, n) => flowItem(i, n, false)).join("") || '<p class="small text-muted-ng">None.</p>'}</div>
          <div class="col-lg-6"><div class="small fw-semibold mb-2">Unaffected flows (${unaffected.length})</div>
          ${unaffected.map((i, n) => flowItem(i, n, false)).join("") || '<p class="small text-muted-ng">None.</p>'}</div></div>
      </div>
      <div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Validation Checks — ${escapeHtml(a.validation_result)}</h2>${checksBlock(a.checks)}</div>
      <p class="small text-muted-ng mt-3">${escapeHtml(scopeText(a.evidence_scope || "Stored-model assessment"))}. Risk = 100 × S × (1 + I + E) / 24 (severity, intent impact, exposure); it ranks risk and is not a failure probability. Analysis time ${a.analysis_ms} ms.</p>
    </div>`;
  document.getElementById("btn-print").addEventListener("click", () => window.print());
  bindExports(`/assessments/${a.id}/export`, `NetGuard-assessment-${a.id}`);
}

function bindExports(path, filename) {
  detailView.querySelectorAll("[data-export]").forEach((button) => button.addEventListener("click", () => withBusy(button, async () => {
    const format = button.dataset.export;
    try {
      await api.download(`${path}?format=${format}`, `${filename}.${format}`);
      toast(`Report exported as ${format.toUpperCase()}`, "success");
    } catch (error) { toast(error.message, "error"); }
  })));
}

function recordLabel(kind) {
  return { scan: "Network scan", analysis: "Network analysis", report: "Analysis report" }[kind] || "Network activity";
}

function historySummary(summary) {
  if (!summary || typeof summary !== "object") return summary || "";
  return Object.entries({ device_count: "devices", found: "devices", link_count: "connections", issue_count: "issues", authenticated: "authenticated", failing_flow_count: "failing flows" }).filter(([key]) => summary[key] != null).map(([key, label]) => `${summary[key]} ${label}`).join(" · ");
}

function description(value) {
  if (Array.isArray(value)) return value.map(description).filter(Boolean).join("; ");
  if (value && typeof value === "object") {
    if (value.device || value.interface) return [value.device, value.interface].filter(Boolean).join(" ");
    return [value.source, value.observation || value.detail || value.message || value.text].filter(Boolean).join(": ");
  }
  return value == null ? "" : String(value);
}

function diagnosticIssue(issue) {
  const row = (label, value) => value ? `<dt>${label}</dt><dd>${escapeHtml(description(value))}</dd>` : "";
  return `<article class="ng-report-issue"><div class="d-flex gap-2 align-items-center flex-wrap mb-2"><h3 class="h6 mb-0">${escapeHtml(issue.name || issue.title || issue.rule_id)}</h3>${severityBadge(issue.severity || "MEDIUM")}<span class="ng-badge-plain">${escapeHtml(issue.certainty || issue.finding_status || "Model finding")}</span></div>
    ${diagnosticSections(issue)}<dl class="ng-kv mt-2 mb-0">${row("Affected interfaces", issue.affected_interfaces)}${row("Correction", issue.corrective_action || issue.recommendation || issue.recommended_action)}${row("Expected outcome", issue.expected_outcome)}</dl></article>`;
}

function renderHistory(record) {
  const snapshot = record.snapshot || {};
  const topology = snapshot.topology || snapshot;
  const devices = topology.devices || snapshot.devices || [];
  const links = topology.links || snapshot.links || [];
  const analysis = snapshot.analysis || snapshot.health || {};
  const flowCount = analysis.flows?.length || 0;
  const passingFlows = analysis.flows?.filter((flow) => flow.ok === true).length || 0;
  const healthy = analysis.status === "healthy" && analysis.analysis_complete !== false;
  const analysisStatus = healthy ? "HEALTHY" : analysis.issue_count ? `${analysis.issue_count} ISSUE${analysis.issue_count === 1 ? "" : "S"} FOUND` : "ANALYSIS INCOMPLETE";
  const discovery = (snapshot.network?.metadata_json || topology.network?.metadata_json || {}).discovery || {};
  const deviceById = new Map(devices.map((device) => [device.id, device]));
  const endpoint = (link, source) => {
    const prefix = source ? "source" : "destination";
    const device = deviceById.get(link[`${prefix}_device_id`]);
    const iface = device?.interfaces?.find((item) => item.id === link[`${prefix}_interface_id`]);
    return [link[`${prefix}_device_name`] || device?.name || link[prefix] || "Unknown device", link[`${prefix}_interface_name`] || iface?.name || (source ? link.source_port : link.target_port) || "Unknown interface"].join(" ");
  };
  detailView.innerHTML = `<div class="ng-report">
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3 ng-no-print"><a class="btn btn-sm btn-light border" href="/reports">Back to history</a><div class="d-flex flex-wrap gap-2">${record.network_id ? `<a class="btn btn-sm btn-outline-primary" href="/topology?network=${record.network_id}">Open Topology</a>` : '<span class="small text-muted-ng align-self-center">Original network removed · saved snapshot available</span>'}<div class="btn-group btn-group-sm" role="group" aria-label="Export report"><button class="btn btn-outline-primary" data-export="pdf"><i class="bi bi-file-earmark-pdf me-1"></i>PDF</button><button class="btn btn-outline-primary" data-export="html">HTML</button><button class="btn btn-outline-primary" data-export="json">JSON</button></div><button class="btn btn-sm btn-light border" id="btn-print"><i class="bi bi-printer me-1"></i>Print</button></div></div>
    <div class="ng-card ng-card-body"><div class="d-flex justify-content-between gap-3 flex-wrap"><div><div class="small text-muted-ng mb-1">${escapeHtml(recordLabel(record.kind))} #${record.id}</div><h1>${escapeHtml(record.title)}</h1><div class="small text-muted-ng">${escapeHtml(record.network_name || snapshot.network?.name || "")} · ${formatDate(record.created_at)}${record.created_by_username ? ` · ${escapeHtml(record.created_by_username)}` : ""}</div></div>${snapshot.network?.is_simulated || record.simulated ? '<span class="ng-sample-indicator align-self-start">Offline example</span>' : ""}</div><p class="mb-0 mt-3">${escapeHtml(historySummary(record.summary))}</p></div>
    ${analysis.status ? `<div class="alert ${healthy ? 'alert-success' : 'alert-warning'} mt-3" role="status" data-report="health"><strong>${analysisStatus} · ${(analysis.advisories || []).length} security advisories</strong><div class="small mt-1">${flowCount ? `${passingFlows}/${flowCount} required flow checks passed.` : 'No required flow checks are available.'} ${escapeHtml(scopeText(analysis.evidence_scope || environmentLabel(snapshot.network || topology.network || {})))}. Analysis uses the saved model.</div></div>` : ''}
    ${analysis.analysis_complete === false ? '<div class="ng-card ng-card-body mt-3 border-warning" role="status"><strong>Analysis incomplete</strong><p class="small mb-0 mt-1">Some device, interface or connection evidence is unavailable. Unknown results do not establish successful connectivity.</p></div>' : ""}
    <div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Device Inventory (${devices.length})</h2><div class="table-responsive"><table class="table ng-table"><thead><tr><th>Hostname</th><th>IP Address</th><th>Type / Model</th><th>Authentication</th></tr></thead><tbody>${devices.map((device) => `<tr><td>${escapeHtml(device.name || device.hostname || "Unknown")}</td><td class="mono">${escapeHtml(device.management_ip || device.ip || "Unknown")}</td><td>${escapeHtml([deviceLabel(device.role || device.device_type || device.type), device.model].filter(Boolean).join(" · "))}</td><td>${escapeHtml(device.auth_status || device.authentication_status || discovery[device.id]?.auth_status || "Not recorded")}</td></tr>`).join("") || '<tr><td colspan="4">No device inventory in this snapshot.</td></tr>'}</tbody></table></div></div>
    ${links.length ? `<div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Interface Connections</h2><p class="small text-muted-ng">Discovery evidence records the captured snapshot. Reviewed configuration changes apply to the stored model evaluated in this report.</p><div class="table-responsive"><table class="table ng-table"><thead><tr><th>Source</th><th>Destination</th><th>Relationship</th><th>Captured evidence / Confidence</th></tr></thead><tbody>${links.map((link) => `<tr><td class="mono">${escapeHtml(endpoint(link, true))}</td><td class="mono">${escapeHtml(endpoint(link, false))}</td><td>${escapeHtml(link.connection_type || link.kind || "Unknown")} · ${escapeHtml(link.discovery_status || "Unknown")}${link.state || link.status ? ` · ${escapeHtml(link.state || link.status)}` : ""}</td><td>${escapeHtml(description(link.evidence || link.discovery_evidence) || "No discovery evidence recorded")}<div class="small text-muted-ng">${link.confidence == null ? "Unknown confidence" : `${Math.round(link.confidence * 100)}% confidence`}</div></td></tr>`).join("")}</tbody></table></div></div>` : ""}
    ${analysis.issues ? `<div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Analysis Findings (${analysis.issues.length})</h2>${analysis.issues.map(diagnosticIssue).join("") || `<p class="mb-0 small">${analysis.analysis_complete === false ? "Evaluated rules found no confirmed issue. The analysis remains incomplete because required evidence is missing." : "No issues detected by the evaluated rules."}</p>`}</div>` : ""}
    ${(analysis.advisories || []).length ? `<div class="ng-card ng-card-body mt-3" data-report="advisories"><h2 class="mt-0">Security &amp; hygiene advisories (${analysis.advisories.length})</h2><p class="small text-muted-ng">Advisories do not change connectivity status.</p>${advisoriesBlock(analysis.advisories)}</div>` : ""}
    ${(analysis.coverage_notes || []).length ? `<div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Analysis coverage notes</h2><ul class="small ps-3 mb-0">${analysis.coverage_notes.map(note => `<li>${escapeHtml(typeof note === "object" ? note.detail || note.message : note)}</li>`).join("")}</ul></div>` : ""}
    ${analysis.flows?.length ? `<div class="ng-card ng-card-body mt-3"><h2 class="mt-0">Required Flow Results</h2><div class="table-responsive"><table class="table ng-table"><thead><tr><th>Source</th><th>Destination</th><th>Expected</th><th>Result</th><th>Evidence</th></tr></thead><tbody>${analysis.flows.map((flow) => `<tr><td>${escapeHtml(flow.source)}</td><td>${escapeHtml(flow.destination)}</td><td>${expectedActionBadge(flow.expected)}</td><td>${flowResultBadge(flow.ok)}</td><td class="${flow.ok === false ? "text-danger" : ""}">${escapeHtml(flow.reason || (flow.ok == null ? "Result unavailable" : "Matched the required result"))}</td></tr>`).join("")}</tbody></table></div></div>` : ""}
    <p class="small text-muted-ng mt-3">This report is a saved snapshot of the collected or imported evidence at that time. It contains no passwords, SNMP passphrases or community strings.</p></div>`;
  setPageTitle("Report Preview", `${recordLabel(record.kind)} #${record.id}`);
  document.getElementById("btn-print").addEventListener("click", () => window.print());
  bindExports(`/history/${record.id}/export`, `NetGuard-${record.kind}-${record.id}`);
}

async function main() {
  await initShell({ active: "reports", title: "Reports & History", subtitle: "Network activity and saved results" });
  const query = new URLSearchParams(window.location.search);
  const historyId = Number(query.get("history") || query.get("record"));
  if (historyId) {
    listView.classList.add("d-none"); detailView.classList.remove("d-none");
    try { renderHistory(await api.get(`/history/${historyId}`)); }
    catch (error) { detailView.innerHTML = `<div class="ng-empty"><h4>${escapeHtml(error.message)}</h4><a class="btn btn-sm btn-primary" href="/reports">Back to history</a></div>`; }
    return;
  }
  const assessmentId = Number(new URLSearchParams(window.location.search).get("assessment"));
  if (assessmentId) {
    listView.classList.add("d-none");
    detailView.classList.remove("d-none");
    try {
      const assessment = await api.get(`/assessments/${assessmentId}`);
      setPageTitle("Assessment Report", `Assessment #${assessment.id}`);
      document.title = `Assessment #${assessment.id} · NetGuard`;
      renderReport(assessment);
    } catch (error) {
      detailView.innerHTML = `<div class="ng-empty"><i class="bi bi-exclamation-circle"></i><h4>${escapeHtml(error.message)}</h4>
        <a class="btn btn-sm btn-primary" href="/reports">Back to reports</a></div>`;
    }
    return;
  }
  const networks = await api.get("/networks");
  networkSelect.innerHTML = `<option value="">All networks</option>` +
    networks.map((n) => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join("");
  const requestedNetwork = query.get("network");
  if (requestedNetwork && networks.some((n) => String(n.id) === String(requestedNetwork))) {
    networkSelect.value = String(requestedNetwork);
  }
  if (query.get("scope") === "all") document.getElementById("scope-all").checked = true;
  networkSelect.addEventListener("change", loadList);
  kindSelect.addEventListener("change", loadList);
  document.querySelectorAll("input[name=scope]").forEach((el) => el.addEventListener("change", loadList));
  await loadList();
}

main();
