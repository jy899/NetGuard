// Renders the Network Health Check result in the topology side panel.
import { flowLabel, riskBadge, riskClass, severityBadge } from "./risk.js";
import { escapeHtml, formatDate } from "./ui.js";
import { advisoriesBlock, diagnosticSections, environmentLabel, expectedActionBadge, flowResultBadge, scopeText } from "./evidence-view.js";

const VERDICTS = {
  recommended: { level: "LOW", text: "Recommended" },
  partial: { level: "MEDIUM", text: "Partial" },
  unsafe: { level: "CRITICAL", text: "Not safe" },
};

export function commandsBlock(lines, id = "") {
  if (!lines || !lines.length) return "";
  return `<div class="ng-cli-wrap"><button type="button" class="btn btn-sm btn-light border ng-cli-copy" data-action="copy-commands"
      data-commands-id="${escapeHtml(id)}" title="Copy commands"><i class="bi bi-clipboard"></i></button>
    <pre class="ng-cli" data-commands="${escapeHtml(id)}">${lines.map(escapeHtml).join("\n")}</pre></div>`;
}

function verificationText(v) {
  const parts = [];
  parts.push(v.resolves ? "Resolves this issue" : "Does not fully resolve this issue");
  if (v.also_resolves.length) parts.push(`also resolves ${v.also_resolves.length} other issue(s)`);
  if (v.restored_flows.length) parts.push(`restores ${v.restored_flows.join(", ")}`);
  if (v.new_issues.length) parts.push(`introduces ${v.new_issues.map((n) => n.rule_id).join(", ")}`);
  if (v.reveals?.length) parts.push(`then shows the next issue on that path: ${v.reveals.map((n) => n.rule_id).join(", ")}`);
  if (v.broken_flows.length) parts.push(`breaks ${v.broken_flows.join(", ")}`);
  if (!v.new_issues.length && !v.broken_flows.length) parts.push("no additional modeled issues or broken required flows");
  return parts.join(" · ");
}

function fixHtml(issueIndex, fix, fixIndex, kind = "issue") {
  const v = fix.verification;
  const verdict = VERDICTS[v.verdict] || VERDICTS.partial;
  const primary = v.verdict === "recommended" && fixIndex === 0;
  return `<div class="ng-fix">
    <div class="d-flex justify-content-between align-items-start gap-2">
      <strong>${escapeHtml(fix.label)}</strong>${riskBadge(verdict.level, verdict.text)}
    </div>
    <div class="small text-muted-ng">${escapeHtml(fix.description)}</div>
    <div class="small mt-1"><span class="mono">${escapeHtml(v.current_value)}</span> → <span class="mono fw-semibold">${escapeHtml(v.proposed_value)}</span></div>
    <div class="small mt-1 ${v.verdict === "unsafe" ? "text-danger" : "text-success"}"><i class="bi bi-shield-check me-1"></i>${escapeHtml(verificationText(v))}
      · ${escapeHtml(v.risk_level)} risk</div>
    ${v.caution ? `<div class="small mt-1 text-warning-emphasis"><i class="bi bi-exclamation-triangle me-1"></i>Not recommended without review (see note above).</div>` : ""}
    ${v.work_order ? '<div class="small mt-1"><i class="bi bi-tools me-1"></i>Physical work order: a person carries it out; NetGuard verified its effect on the model.</div>' : ""}
    ${fix.ai ? `<div class="small mt-1 ng-ai-note" data-fix-ai="${fix.ai.band}"><i class="bi bi-stars me-1"></i>AI repair likelihood ${Math.round(fix.ai.repair_probability * 100)}% · ${escapeHtml(fix.ai.reason)}</div>` : ""}
    <details class="mt-1"><summary class="small">${v.work_order ? "Work order and commands" : "Suggested commands"}</summary>${commandsBlock(v.commands, `fix-${kind}-${issueIndex}-${fixIndex}`)}</details>
    <div class="d-flex gap-2 mt-2">
      <button class="btn btn-sm ${primary ? "btn-success" : "btn-outline-success"}" data-action="apply-fix" data-kind="${kind}"
        data-issue-index="${issueIndex}" data-fix-index="${fixIndex}" ${v.verdict === "unsafe" ? "disabled" : ""}>
        <i class="bi bi-send-check me-1"></i>Submit for Approval</button>
      <button class="btn btn-sm btn-outline-primary" data-action="review-fix" data-kind="${kind}" data-issue-index="${issueIndex}" data-fix-index="${fixIndex}">
        <i class="bi bi-search me-1"></i>Validate Correction</button>
    </div>
  </div>`;
}

/** Issues whose first fix option is verified as safe and resolving. */
export function fixableIssues(report, skipped) {
  return report.issues
    .map((issue, index) => ({ issue, index }))
    .filter(({ issue }) => !skipped.has(issue.key) && issue.fixes[0]?.verification.verdict === "recommended");
}

export const PACK_LABELS = { physical: "Physical", layer2: "Layer 2", layer3: "Layer 3", acl: "ACL and policy", security: "Security hygiene" };

const AI_KIND = { link: "bi-diagram-2", peer: "bi-people", syslog: "bi-journal-text" };

export function aiInsightsBlock(ai) {
  if (!ai?.available) return "";
  const causes = ai.root_causes || [];
  const anomalies = ai.anomalies || [];
  return `<div class="ng-panel-section" data-health="ai"><div class="ng-panel-title"><span><i class="bi bi-stars me-1"></i>AI insights</span> <span>v${ai.model_version}</span></div>
    <p class="small mb-2">${escapeHtml(ai.summary || "")}</p>
    ${causes.length ? `<div class="small fw-semibold mb-1">Likely root causes</div><ol class="small ps-3 mb-2">${causes.slice(0, 3).map((c) => `<li class="mb-1"><span class="mono">${escapeHtml(c.rule_id)}</span> ${escapeHtml(c.message)}
      <div class="ng-ai-meter mt-1"><span style="width:${Math.round(c.probability * 100)}%"></span></div><div class="text-muted-ng">${escapeHtml(c.summary)}</div></li>`).join("")}</ol>` : ""}
    ${anomalies.length ? `<div class="small fw-semibold mb-1">Anomalies and cross-device misconfigurations</div>${anomalies.slice(0, 8).map((a) => `<div class="border rounded p-2 mb-1 small">
      <i class="bi ${AI_KIND[a.kind] || "bi-exclamation-diamond"} me-1"></i><strong>${escapeHtml(a.title)}</strong>${a.probability != null ? ` · ${Math.round(a.probability * 100)}%` : ""}${a.also_reported_by_rules ? ' <span class="ng-type-badge">also reported by rules</span>' : ' <span class="ng-type-badge">new</span>'}
      <div class="text-muted-ng">${escapeHtml(a.summary)}</div>${a.example ? `<div class="mono text-muted-ng text-truncate" title="${escapeHtml(a.example)}">${escapeHtml(a.example)}</div>` : ""}</div>`).join("")}` : ""}
    <div class="small text-muted-ng mt-1">${escapeHtml(ai.advisory || "")}</div></div>`;
}

export function renderHealthPanel(report, skipped = new Set(), network = {}) {
  const healthy = report.status === "healthy";
  const incomplete = report.status === 'incomplete' || report.analysis_complete === false;
  const fixable = fixableIssues(report, skipped);
  const visible = report.issues.map((issue, index) => ({ issue, index })).filter(({ issue }) => !skipped.has(issue.key));
  const issues = visible
    .map(({ issue, index }) => `
      <div class="ng-issue ${riskClass(issue.severity)}" data-issue-card="${index}">
        <div class="ng-issue-header d-flex justify-content-between align-items-center gap-2">
          <button type="button" class="ng-section-toggle" data-action="focus-issue" data-issue-index="${index}">
            <span class="head"><span class="rule">${escapeHtml(issue.rule_id)}</span> <strong>${escapeHtml(issue.name)}</strong></span>
          </button>
          <span class="d-flex align-items-center gap-1">${severityBadge(issue.severity)}
            <button class="btn btn-sm btn-link p-0 text-muted-ng" data-action="skip-issue" data-issue-index="${index}"
              title="Skip this issue for now">Skip</button></span>
        </div>
        <div class="small mt-2"><span class="ng-type-badge">${issue.certainty === 'suspected' ? 'Suspected cause' : 'Confirmed in model'}</span>
          ${issue.pack ? `<span class="ng-type-badge ms-1">${escapeHtml(PACK_LABELS[issue.pack] || issue.pack)}</span>` : ''}
          ${issue.risk ? `<span class="ms-1 mono" title="Risk = 100 × S × (1 + I + E) / 24">Risk ${issue.risk.score} (S${issue.risk.S} · I${issue.risk.I} · E${issue.risk.E})</span>` : ''}
          ${issue.confidence == null ? '' : `<span class="text-muted-ng ms-1">Evidence confidence ${Math.round(issue.confidence * 100)}%</span>`}</div>
        ${diagnosticSections(issue)}
        <div class="small text-muted-ng mt-2"><strong>Affected devices / interfaces</strong><div>${(issue.affected_interfaces || []).length ? issue.affected_interfaces.map(item => `${escapeHtml(item.device || '')} <span class="mono">${escapeHtml(item.interface || 'Unknown Port')}</span>`).join(', ') : escapeHtml((issue.devices || []).join(', ') || 'See highlighted topology')}</div></div>
        <div class="small mt-2"><strong>Recommended correction</strong><div>${escapeHtml(issue.corrective_action || issue.recommendation)}</div></div>
        <div class="small mt-2"><strong>Expected outcome</strong><div>${escapeHtml(issue.expected_outcome || issue.consequence)}</div></div>
        ${issue.related_flows.length ? `<div class="small mt-1"><i class="bi bi-exclamation-circle me-1"></i>Breaks: ${escapeHtml(issue.related_flows.join(", "))}</div>` : ""}
        <div class="ng-panel-title mt-3 mb-2">Fix options</div>
        ${issue.fixes.length
          ? issue.fixes.map((fix, fixIndex) => fixHtml(index, fix, fixIndex)).join("")
          : `<p class="small text-muted-ng mb-0">No automatic fix. ${escapeHtml(issue.recommendation)}.</p>`}
      </div>`)
    .join("");
  const flows = report.flows.length
    ? `<ul class="ng-conn-list">${report.flows
        .map((f) => `<li><span><i class="bi ${f.ok === true ? "bi-check-circle-fill text-success" : f.ok === false ? "bi-x-circle-fill text-danger" : "bi-question-circle text-muted-ng"} me-1"></i>
          <strong>${escapeHtml(f.source)}</strong> → <strong>${escapeHtml(f.destination)}</strong>
          <span class="mono text-muted-ng">${escapeHtml(flowLabel(f.protocol, f.port))}</span>
          ${f.reason ? `<div class="small ${f.ok === false ? 'text-danger' : 'text-muted-ng'}">${escapeHtml(f.reason)}</div>` : ""}</span>
          <span class="d-flex flex-column align-items-end gap-1 flex-shrink-0">${flowResultBadge(f.ok)}${expectedActionBadge(f.expected)}</span></li>`)
        .join("")}</ul>`
    : `<p class="small text-muted-ng mb-0">No traffic tests are configured for this model. This analysis has not verified end-to-end service connectivity.</p>`;
  const implicit = report.flows.length && report.flows.every((f) => f.kind === "implicit");
  const flowTitle = implicit ? "Host Connectivity" : "Required Flows";
  const flowNote = implicit
    ? `<p class="small text-muted-ng mb-2">No required flows are defined, so every host pair is expected to work unless an ACL denies it.</p>`
    : "";
  return `
    <div class="ng-panel-section ng-analysis-head">
      <div class="ng-panel-title">Network Analysis
        <button class="btn btn-sm btn-link p-0" data-action="close-health" title="Close health check" aria-label="Close health check"><i class="bi bi-x-lg"></i></button></div>
      <div class="ng-decision ${riskClass(healthy ? "LOW" : incomplete && !report.issue_count ? "MEDIUM" : report.counts.CRITICAL ? "CRITICAL" : "HIGH")}">
        <div class="label" data-health="status">${incomplete && !report.issue_count && !report.failing_flow_count ? 'NO DETECTED ISSUES · LIMITED COVERAGE' : healthy ? "HEALTHY" : `${report.issue_count} ISSUE${report.issue_count === 1 ? "" : "S"} FOUND`}</div>
        <p>${healthy ? `No supported issues found. All modeled ${implicit ? "host-pair" : "required-flow"} checks passed.`
          : report.failing_flow_count ? `${report.failing_flow_count} modeled connection check(s) failed. Review the findings below.`
          : report.issue_count ? 'Review the detected configuration findings below. Service impact is limited to the available model.'
          : 'No fault was detected in the available data. Review the coverage gaps below before treating this network as healthy.'}</p>
        ${incomplete ? `<p class="small mb-0">Analysis coverage is partial.${report.unknown_flow_count ? ` ${report.unknown_flow_count} traffic check(s) could not be verified.` : ''} Missing evidence is not a confirmed fault or a passing test.</p>` : ''}
      </div>
      <div class="small text-muted-ng mt-2">${report.rules_checked} rules · ${report.devices_checked} devices · ${report.links_checked} links ·
        ${report.elapsed_ms} ms · ${formatDate(report.checked_at)}</div>
      <div class="small mt-2" data-health="summary">Connectivity ${escapeHtml(String(report.status || "").toUpperCase())} · ${(report.advisories || []).length} security advisories</div>
      <div class="small text-muted-ng mt-1" data-health="evidence-scope">${escapeHtml(scopeText(report.evidence_scope || environmentLabel(network)))}. Analysis uses stored model evidence.</div>
      <div class="d-flex gap-2 mt-2 flex-wrap">
        ${fixable.length ? `<button class="btn btn-sm btn-success" data-action="fix-all"><i class="bi bi-send-check me-1"></i>Submit All Fixes (${fixable.length})</button>` : ""}
        <button class="btn btn-sm btn-outline-primary" data-action="rerun-health"><i class="bi bi-arrow-repeat me-1"></i>Run again</button>
        <button class="btn btn-sm btn-outline-primary" data-action="save-network-report">Save Report</button>
        ${report.record_id ? `<a class="btn btn-sm btn-light border" href="/reports?record=${report.record_id}">View Saved Analysis</a>` : ''}
        <a class="btn btn-sm btn-light border" href="/changes${report.network_id ? `?network=${report.network_id}` : ''}">Validation &amp; Changes</a>
        ${skipped.size ? `<button class="btn btn-sm btn-link" data-action="unskip-all">Show ${skipped.size} skipped</button>` : ""}
      </div>
    </div>
    ${aiInsightsBlock(report.ai)}
    ${visible.length ? `<div class="ng-panel-section"><div class="ng-panel-title">Issues <span>${visible.length}</span></div>${issues}</div>` : ""}
    ${(report.advisories || []).length ? `<div class="ng-panel-section" data-health="advisories"><div class="ng-panel-title">Security &amp; hygiene advisories <span>${report.advisories.length}</span></div><p class="small text-muted-ng">Advisories do not change connectivity status.</p>${report.advisories.map((advisory, index) => advisoriesBlock([advisory]) + ((advisory.fixes || []).length ? `<div class="ms-2 mb-3">${advisory.fixes.map((fix, fixIndex) => fixHtml(index, fix, fixIndex, "advisory")).join("")}</div>` : "")).join("")}</div>` : ""}
    ${(report.coverage_notes || []).length ? `<div class="ng-panel-section"><div class="ng-panel-title">Analysis coverage notes</div><ul class="small ps-3 mb-0">${report.coverage_notes.map(note => `<li>${escapeHtml(typeof note === "object" ? note.detail || note.message : note)}</li>`).join("")}</ul></div>` : ""}
    ${(report.coverage_gaps || []).length ? `<div class="ng-panel-section" data-health="coverage"><div class="ng-panel-title">Coverage gaps</div>${report.coverage_gaps.map((gap) => `<div class="border rounded p-2 mb-2 small"><strong>${escapeHtml(gap.detail)}</strong><div class="text-muted-ng mt-1">${escapeHtml(gap.next_step)}</div>${gap.link_id ? `<button class="btn btn-sm btn-outline-primary mt-2" data-action="select-link" data-link-id="${gap.link_id}">Inspect connection</button>` : gap.code === 'configuration' && report.environment === 'real' ? '<button class="btn btn-sm btn-outline-primary mt-2" data-action="device-access">Device Access</button>' : ''}</div>`).join('')}</div>` : ''}
    <div class="ng-panel-section"><div class="ng-panel-title">${flowTitle} <span>${report.flows.length ? `${report.flows.filter((f) => f.ok).length}/${report.flows.length} passed` : 'Not configured'}</span></div>${flowNote}${flows}</div>
    <div class="ng-panel-section"><p class="small text-muted-ng mb-0">Issues are ordered by risk score. A fix is validated on a copy of the model and needs IT Manager approval; only approved changes to laboratory devices are sent, with backup, verification and rollback. Confidence describes the collected evidence, not a measured probability of correctness.</p></div>`;
}
