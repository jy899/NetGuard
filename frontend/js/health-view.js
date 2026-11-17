// Renders the Network Health Check result in the topology side panel.
import { flowLabel, riskBadge, riskClass, severityBadge } from "./risk.js";
import { escapeHtml, formatDate } from "./ui.js";
import { advisoriesBlock, diagnosticSections, environmentLabel, expectedActionBadge, flowResultBadge, scopeText } from "./evidence-view.js";
import { canAutoFix, canExecute } from "./topology/workflow.js";

let viewer = null;  // signed-in user of the current render (decides whether Fix Now is offered)
const CHANGE_STATE = {
  pending_approval: { icon: "bi-hourglass-split", text: "Submitted. Waiting for approval.", button: "Open" },
  approved: { icon: "bi-patch-check", text: "Approved. Not applied yet.", button: "Apply Now" },
  awaiting_confirm: { icon: "bi-stopwatch", text: "Applied. Confirm it to keep it.", button: "Open" },
};

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
    ${fixActions(issueIndex, fix, fixIndex, kind, primary, v.verdict === "unsafe")}
  </div>`;
}

/** The buttons under a fix: its submitted change if there is one, otherwise Fix Now (Auto-Fix) and Submit. */
function fixActions(issueIndex, fix, fixIndex, kind, primary, unsafe) {
  const at = `data-kind="${kind}" data-issue-index="${issueIndex}" data-fix-index="${fixIndex}"`;
  const open = CHANGE_STATE[fix.change?.status];
  if (open) {
    return `<div class="d-flex align-items-center gap-2 mt-2" data-fix-change="${fix.change.status}">
      <span class="small ${fix.change.status === "approved" ? "text-success fw-semibold" : "text-muted-ng"}"><i class="bi ${open.icon} me-1"></i>${open.text}</span>
      <button class="btn btn-sm ${fix.change.status === "approved" ? "btn-success" : "btn-outline-primary"} ms-auto" data-action="open-change" data-change-id="${fix.change.id}">${open.button}</button></div>`;
  }
  const direct = canAutoFix(viewer);
  return `<div class="d-flex gap-2 mt-2 flex-wrap">
      ${direct ? `<button class="btn btn-sm ${primary ? "btn-success" : "btn-outline-success"}" data-action="auto-fix" ${at} ${unsafe ? "disabled" : ""}
        title="Backup, apply, check, automatic undo"><i class="bi bi-lightning-charge-fill me-1"></i>Fix Now</button>` : ""}
      <button class="btn btn-sm ${primary && !direct ? "btn-success" : "btn-outline-success"}" data-action="apply-fix" ${at} ${unsafe ? "disabled" : ""}>
        <i class="bi bi-send-check me-1"></i>Submit for Approval</button>
      <button class="btn btn-sm btn-outline-primary" data-action="review-fix" ${at}>
        <i class="bi bi-search me-1"></i>Check First</button>
    </div>`;
}

/** Issues whose first fix option is verified as safe and resolving and not already submitted. */
export function fixableIssues(report, skipped) {
  return report.issues
    .map((issue, index) => ({ issue, index }))
    .filter(({ issue }) => !skipped.has(issue.key) && issue.fixes[0]?.verification.verdict === "recommended" && !issue.fixes[0]?.change);
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

/** Fixes applied on this network, newest first. Undo goes newest to oldest, so only the next one has the button. */
function appliedFixesBlock(fixes, user) {
  if (!fixes?.length) return "";
  const mayUndo = canExecute(user) || canAutoFix(user);
  return `<div class="ng-panel-section" data-health="applied-fixes">
    <details class="ng-applied" ${fixes.length <= 3 ? "open" : ""}><summary class="ng-panel-title mb-0">Applied fixes <span>${fixes.length}</span></summary>
      <ul class="ng-conn-list mt-2">${fixes.map((c) => `<li>
        <span class="min-w-0"><strong>${escapeHtml(c.device_name)}</strong> · ${escapeHtml(c.change_type_label)}
          <div class="small mono text-muted-ng text-truncate">${escapeHtml(c.current_value ?? "")} → ${escapeHtml(c.proposed_value ?? "")}</div>
          <div class="small text-muted-ng">${formatDate(c.applied_at || c.updated_at)}${c.applied_by ? ` · ${escapeHtml(c.applied_by)}` : ""}${c.undo_note ? ` · ${escapeHtml(c.undo_note)}` : ""}</div></span>
        ${c.undo_next && mayUndo ? `<button class="btn btn-sm btn-outline-danger flex-shrink-0" data-action="undo-fix" data-change-id="${c.id}"><i class="bi bi-arrow-counterclockwise me-1"></i>Undo</button>` : ""}
      </li>`).join("")}</ul>
      ${fixes.filter((c) => c.can_undo).length > 1 ? '<p class="small text-muted-ng mb-0">Fixes are undone newest first. <strong>Undo Fix</strong> on the toolbar does the same.</p>' : ""}
    </details></div>`;
}

export function renderHealthPanel(report, skipped = new Set(), network = {}, user = null, appliedFixes = []) {
  viewer = user;
  const healthy = report.status === "healthy";
  const incomplete = report.status === 'incomplete' || report.analysis_complete === false;
  // Failing flows are usually caused by the listed issues, so they are not added to the issue count.
  const problems = (report.issue_count || 0) + (report.cabling_count || 0);
  const failed = report.failing_flow_count || 0;
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
      <div class="ng-decision ${riskClass(healthy ? "LOW" : incomplete && !problems && !failed ? "MEDIUM" : report.counts.CRITICAL ? "CRITICAL" : "HIGH")}">
        <div class="label" data-health="status">${!problems && !failed && incomplete ? 'NO DETECTED ISSUES · LIMITED COVERAGE' : healthy ? "HEALTHY" : problems ? `${problems} ISSUE${problems === 1 ? "" : "S"} FOUND` : `${failed} CONNECTION CHECK${failed === 1 ? "" : "S"} FAILED`}</div>
        <p>${healthy ? `No supported issues found. All modeled ${implicit ? "host-pair" : "required-flow"} checks passed.`
          : report.cabling_count ? `${report.cabling_count} cable(s) from the imported file are missing${report.failing_flow_count ? ` and ${report.failing_flow_count} connection check(s) failed` : ""}. Review the findings below.`
          : report.failing_flow_count ? `${report.failing_flow_count} modeled connection check(s) failed. Review the findings below.`
          : report.issue_count ? 'Review the detected configuration findings below. Service impact is limited to the available model.'
          : 'No fault was detected in the available data. Review the coverage gaps below before treating this network as healthy.'}</p>
        ${incomplete ? `<p class="small mb-0">Analysis coverage is partial.${report.unknown_flow_count ? ` ${report.unknown_flow_count} traffic check(s) could not be verified.` : ''} Missing evidence is not a confirmed fault or a passing test.</p>` : ''}
      </div>
      <div class="small text-muted-ng mt-2">${report.rules_checked} rules · ${report.devices_checked} devices · ${report.links_checked} cabled links${report.logical_links ? ` · ${report.logical_links} logical (not analysed)` : ""} ·
        ${report.elapsed_ms} ms · ${formatDate(report.checked_at)}</div>
      <div class="small mt-2" data-health="summary">Connectivity ${escapeHtml(String(report.status || "").toUpperCase())} · ${(report.advisories || []).length} security advisories</div>
      <div class="small text-muted-ng mt-1" data-health="evidence-scope">${escapeHtml(scopeText(report.evidence_scope || environmentLabel(network)))}</div>
      ${fixable.length ? `<div class="d-flex gap-2 mt-3 flex-wrap">
        ${network?.is_simulated && canAutoFix(user) ? `<button class="btn btn-sm btn-success" data-action="fix-all-now"><i class="bi bi-lightning-charge-fill me-1"></i>Fix All Now (${fixable.length})</button>` : ""}
        <button class="btn btn-sm ${network?.is_simulated && canAutoFix(user) ? "btn-outline-success" : "btn-success"}" data-action="fix-all"><i class="bi bi-send-check me-1"></i>Submit All for Approval (${fixable.length})</button>
      </div>` : ""}
      <div class="ng-quick-links mt-2">
        <button class="btn btn-link" data-action="rerun-health"><i class="bi bi-arrow-repeat"></i>Run again</button>
        <button class="btn btn-link" data-action="save-network-report"><i class="bi bi-file-earmark-plus"></i>Save Report</button>
        ${report.record_id ? `<a class="btn btn-link" href="/reports?record=${report.record_id}"><i class="bi bi-clock-history"></i>View Saved Analysis</a>` : ""}
        <a class="btn btn-link" href="/changes${report.network_id ? `?network=${report.network_id}` : ""}"><i class="bi bi-shield-check"></i>Validation &amp; Changes</a>
        ${skipped.size ? `<button class="btn btn-link" data-action="unskip-all"><i class="bi bi-eye"></i>Show ${skipped.size} skipped</button>` : ""}
      </div>
    </div>
    ${appliedFixesBlock(appliedFixes, user)}
    ${aiInsightsBlock(report.ai)}
    ${(report.cabling_findings || []).length ? `<div class="ng-panel-section" data-health="cabling"><div class="ng-panel-title">Cabling <span>${report.cabling_findings.length}</span></div>${report.cabling_findings.map((f) => `<div class="border rounded p-2 mb-2 small"><span class="badge ${f.severity === "HIGH" ? "text-bg-danger" : "text-bg-warning"} me-1">${escapeHtml(f.severity)}</span><strong>${escapeHtml(f.detail)}</strong><div class="text-muted-ng mt-1">${escapeHtml(f.next_step)}</div></div>`).join("")}<button class="btn btn-sm btn-outline-secondary" data-action="accept-cabling"><i class="bi bi-check2-square me-1"></i>Accept current cabling</button></div>` : ""}
    ${visible.length ? `<div class="ng-panel-section"><div class="ng-panel-title">Issues <span>${visible.length}</span></div>${issues}</div>` : ""}
    ${(report.advisories || []).length ? `<div class="ng-panel-section" data-health="advisories"><div class="ng-panel-title">Security &amp; hygiene advisories <span>${report.advisories.length}</span></div><p class="small text-muted-ng">Advisories do not change connectivity status.</p>${report.advisories.map((advisory, index) => advisoriesBlock([advisory]) + ((advisory.fixes || []).length ? `<div class="ms-2 mb-3">${advisory.fixes.map((fix, fixIndex) => fixHtml(index, fix, fixIndex, "advisory")).join("")}</div>` : "")).join("")}</div>` : ""}
    ${(report.coverage_notes || []).length ? `<div class="ng-panel-section"><div class="ng-panel-title">Analysis coverage notes</div><ul class="small ps-3 mb-0">${report.coverage_notes.map(note => `<li>${escapeHtml(typeof note === "object" ? note.detail || note.message : note)}</li>`).join("")}</ul></div>` : ""}
    ${(report.coverage_gaps || []).length ? `<div class="ng-panel-section" data-health="coverage"><div class="ng-panel-title">Coverage gaps</div>${report.coverage_gaps.map((gap) => `<div class="border rounded p-2 mb-2 small"><strong>${escapeHtml(gap.detail)}</strong><div class="text-muted-ng mt-1">${escapeHtml(gap.next_step)}</div>${gap.link_id ? `<button class="btn btn-sm btn-outline-primary mt-2" data-action="select-link" data-link-id="${gap.link_id}">Inspect connection</button>` : gap.code === 'configuration' && report.environment === 'real' ? '<button class="btn btn-sm btn-outline-primary mt-2" data-action="device-access">Device Access</button>' : ''}</div>`).join('')}</div>` : ''}
    <div class="ng-panel-section"><div class="ng-panel-title">${flowTitle} <span>${report.flows.length ? `${report.flows.filter((f) => f.ok).length}/${report.flows.length} passed` : 'Not configured'}</span></div>${flowNote}${flows}</div>
    <div class="ng-panel-section"><p class="small text-muted-ng mb-0">Highest risk first. Every fix is checked on a copy of the network first, applied after approval (or at once with Fix Now) and undone automatically if the check after it fails.</p></div>`;
}
