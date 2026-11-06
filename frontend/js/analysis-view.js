// Renders an assessment (analysis result). Shared by the Topology Workspace
// panel and the Reports page so both show the same content.

import { flowLabel, recommendationBadge, riskBadge, riskClass, severityBadge } from "./risk.js";
import { commandsBlock } from "./health-view.js";
import { escapeHtml, formatDate } from "./ui.js";
import { advisoriesBlock, expectedActionBadge, flowResultBadge } from "./evidence-view.js";
import { canModify, workflowButtons } from "./topology/workflow.js";

export const FACTOR_LABELS = {
  S: ["Severity", "highest rule severity among the findings (1 low – 4 critical)", 4],
  I: ["Intent impact", "required traffic intents broken or rerouted (0 – 3)", 3],
  E: ["Exposure", "edge device, ACL policy or untrusted endpoint involved (0 – 2)", 2],
};
const CONFIDENCE_TEXT = { HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
export function scoreBlock(a) {
  return `
    <div class="ng-score ${riskClass(a.risk_level)}">
      <div class="ng-score-ring" style="--pct:${a.total_risk_score}"><div><strong data-analysis="score">${a.total_risk_score}</strong><span>/ 100</span></div></div>
      <div>
        <div class="ng-score-level" data-analysis="level">${escapeHtml(a.risk_level)} RISK</div>
        <div class="mt-1">${riskBadge(a.validation_result === "PASS" ? "LOW" : "CRITICAL", `Validation ${a.validation_result}`)}</div>
        <div class="small text-muted-ng mt-1">${a.counts.affected_count ?? 0} of ${a.counts.evaluated_count ?? 0} flows affected</div>
      </div>
    </div>`;
}

/** Transparent risk: Risk = 100 × S × (1 + I + E) / 24, with each factor shown. */
export function dimensionsBlock(a) {
  const f = a.risk_factors || {};
  if (f.S == null) return '<p class="small text-muted-ng mb-0">This assessment predates the factor-based score; re-analyse the change to see severity, intent impact and exposure.</p>';
  return `<div class="ng-dims ${riskClass(a.risk_level)}" data-analysis="factors">${Object.entries(FACTOR_LABELS)
    .map(([key, [label, help, max]]) => `<div class="ng-dim-row" title="${escapeHtml(help)}"><span>${label} <span class="mono">${key}</span></span><span class="val">${f[key]} / ${max}</span>
        <div class="ng-bar"><span style="width:${(f[key] / max) * 100}%"></span></div></div>`)
    .join("")}
    <div class="small mono mt-2" data-analysis="formula">100 × ${f.S} × (1 + ${f.I} + ${f.E}) / 24 = ${a.total_risk_score}</div>
    <div class="small text-muted-ng">Bands: Low &lt; 25 · Medium &lt; 50 · High &lt; 75 · Critical ≥ 75${a.evidence_confidence ? ` · Evidence confidence: <strong>${escapeHtml(CONFIDENCE_TEXT[a.evidence_confidence] || a.evidence_confidence)}</strong>` : ""}</div></div>`;
}

export function decisionBlock(a) {
  return `<div class="ng-decision ${riskClass(a.recommendation === "DEPLOY" ? "LOW" : a.recommendation === "DEPLOY_WITH_CAUTION" ? "MEDIUM" : a.risk_level)}">
    <div class="small text-muted-ng">Recommendation</div>
    <div class="label" data-analysis="recommendation">${escapeHtml(a.recommendation_label.toUpperCase())}</div>
    <p>${escapeHtml(a.recommendation_summary)}</p>
    ${a.actions.length ? `<ul>${a.actions.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
  </div>`;
}

const AI_BAND = { low: "LOW", medium: "MEDIUM", high: "HIGH" };
const AI_AGREEMENT = {
  agrees: "Agrees with the simulation of this network.",
  model_higher: "Higher than the simulation: check paths outside the modelled flows after the change.",
  model_lower: "Lower than the simulation: follow the simulation.",
};

export function aiBlock(a) {
  const ai = a.ai || {};
  if (!ai.available) return "";
  const pct = Math.round(ai.harm_probability * 100);
  return `<div class="ng-ai-card" data-analysis="ai">
    <div class="d-flex justify-content-between align-items-center gap-2">
      <div><i class="bi bi-stars me-1"></i><strong>AI change-risk forecast</strong></div>${riskBadge(AI_BAND[ai.band] || "MEDIUM", `${pct}% harm`)}</div>
    <div class="ng-ai-meter mt-2" role="img" aria-label="Predicted harm probability ${pct}%"><span style="width:${pct}%"></span></div>
    <div class="small mt-2">${ai.expected_endpoints != null ? `Expected blast radius: about <strong>${Math.round(ai.expected_endpoints)}</strong> endpoint(s), <strong>${Math.round(ai.expected_flows ?? 0)}</strong> flow(s).` : ""}
      ${ai.agreement ? ` ${escapeHtml(AI_AGREEMENT[ai.agreement] || "")}` : ""}</div>
    ${(ai.factors || []).length ? `<ul class="small mb-1 mt-2 ps-3">${ai.factors.map((f) => `<li><i class="bi ${f.direction === "raises" ? "bi-arrow-up-right text-danger" : "bi-arrow-down-right text-success"} me-1"></i>${escapeHtml(f.text)}</li>`).join("")}</ul>` : ""}
    <p class="small mb-1">${escapeHtml(ai.summary || "")}</p>
    ${a.hybrid?.score != null ? `<div class="small border-top pt-2 mt-2" data-analysis="hybrid"><strong>Hybrid risk ${a.hybrid.score}/100 (${escapeHtml(a.hybrid.level)})</strong> · ${escapeHtml(a.hybrid.basis)}${a.hybrid.second_review ? ' · <span class="text-danger">second review recommended</span>' : ""}</div>` : ""}
    <div class="small text-muted-ng">${escapeHtml(ai.advisory || "")} Model v${ai.model_version}.</div>
  </div>`;
}

export function explanationBlock(a) {
  return `<div class="ng-explanation" data-analysis="explanation">${a.explanation
    .split("\n\n")
    .map((p) => `<p>${escapeHtml(p)}</p>`)
    .join("")}</div>`;
}

export function findingsBlock(findings, emptyText = "No issues introduced by this change.") {
  if (!findings.length) return `<p class="small text-muted-ng mb-0">${emptyText}</p>`;
  return findings
    .map(
      (f) => `<div class="ng-finding ${riskClass(f.severity)}">
        <div class="head"><span class="rule">${escapeHtml(f.rule_id)}</span><strong>${escapeHtml(f.name)}</strong>${severityBadge(f.severity)}</div>
        <div>${escapeHtml(f.message)}</div>
        ${f.devices.length ? `<div class="small text-muted-ng mt-1">Devices: ${escapeHtml(f.devices.join(", "))}</div>` : ""}
      </div>`
    )
    .join("");
}

export function flowItem(impact, index, interactive = true) {
  const tag = interactive ? "button" : "div";
  const label = impact.kind === "gateway" ? "default gateway" : flowLabel(impact.protocol, impact.port);
  const result = impact.result === "passed" ? true : impact.result === "failed" ? false : undefined;
  return `<${tag} ${interactive ? 'type="button"' : ""} class="ng-flow" data-impact-index="${index}">
    <div class="d-flex justify-content-between align-items-start gap-2">
      <span><strong>${escapeHtml(impact.source_device)}</strong> → <strong>${escapeHtml(impact.destination_device)}</strong>
        <span class="mono text-muted-ng">${escapeHtml(label)}</span></span>
      <span class="d-flex flex-column align-items-end gap-1">${flowResultBadge(result)}${expectedActionBadge(impact.expected_action || impact.expected)}<span class="ng-status-pill ${escapeHtml(impact.status)}">${escapeHtml(impact.status)}</span></span>
    </div>
    <div class="small text-muted-ng">${escapeHtml(impact.service)}${impact.criticality && impact.kind !== "gateway" ? ` · ${escapeHtml(impact.criticality)}` : ""}</div>
    ${impact.reason || impact.failure_reason ? `<div class="reason">${escapeHtml(impact.reason || impact.failure_reason)}</div>` : ""}
    ${impact.path.length ? `<div class="route">${impact.path.map(escapeHtml).join(" → ")}</div>` : ""}
  </${tag}>`;
}

export function checksBlock(checks) {
  const icon = { passed: "bi-check-circle-fill", failed: "bi-x-circle-fill", warning: "bi-exclamation-triangle-fill" };
  return checks
    .map(
      (c) => `<div class="ng-check"><i class="bi ${icon[c.status]} ${c.status}"></i>
        <div class="flex-grow-1"><span class="mono">${escapeHtml(c.rule_id)}</span> ${escapeHtml(c.name)}
          ${c.messages.length ? `<div class="small text-muted-ng">${c.messages.map(escapeHtml).join("<br>")}</div>` : ""}</div>
        <span class="small text-muted-ng text-capitalize">${escapeHtml(c.status)}</span></div>`
    )
    .join("");
}

export function changeBlock(a) {
  const c = a.change;
  return `<div class="ng-change-box">
    <div><strong>${escapeHtml(c.device)}</strong> · ${escapeHtml(c.change_type_label)}${c.target ? ` · <span class="mono">${escapeHtml(c.target)}</span>` : ""}</div>
    <div class="values"><span class="from mono">${escapeHtml(c.current_value)}</span><i class="bi bi-arrow-right"></i>
      <span class="to mono" data-analysis="proposed">${escapeHtml(c.proposed_value)}</span></div>
    ${c.reason ? `<div class="small text-muted-ng mt-1">Reason: ${escapeHtml(c.reason)}</div>` : ""}
  </div>`;
}

/** Full analysis view for the topology side panel. */
export function renderAnalysisPanel(a, change = null, user = null) {
  const status = change?.status || a.change.status;
  const locked = ["applied", "rolled_back", "failed", "awaiting_confirm"].includes(status);
  const affected = a.impacts.map((impact, index) => ({ impact, index })).filter((x) => x.impact.affected);
  const unaffected = a.impacts.map((impact, index) => ({ impact, index })).filter((x) => !x.impact.affected);
  const counts = a.checks.reduce((acc, c) => ({ ...acc, [c.status]: (acc[c.status] || 0) + 1 }), {});
  return `
    <div class="ng-panel-section ng-analysis-head">
      <div class="ng-panel-title">NetGuard Analysis
        <button class="btn btn-sm btn-link p-0" data-action="close-analysis" title="Close analysis" aria-label="Close analysis"><i class="bi bi-x-lg"></i></button></div>
      ${changeBlock(a)}
      <div class="small text-muted-ng mt-2">Assessment #${a.id} · ${formatDate(a.created_at)} · ${a.analysis_ms} ms
        ${a.saved ? `· ${riskBadge("LOW", "Saved")}` : ""}</div>
      ${a.evidence_scope ? `<div class="small text-muted-ng mt-1">${escapeHtml(a.evidence_scope)}</div>` : ""}
    </div>
    <div class="ng-panel-section">${scoreBlock(a)}<div class="mt-3">${dimensionsBlock(a)}</div></div>
    <div class="ng-panel-section">${decisionBlock(a)}</div>
    ${a.ai?.available ? `<div class="ng-panel-section">${aiBlock(a)}</div>` : ""}
    <div class="ng-panel-section">
      <div class="ng-analysis-actions">
        ${locked || !canModify(user) ? "" : `<button class="btn btn-sm btn-outline-primary" data-action="modify-change"><i class="bi bi-pencil-square me-1"></i>Modify Change</button>
        <button class="btn btn-sm btn-outline-primary" data-action="reanalyze"><i class="bi bi-arrow-repeat me-1"></i>Re-analyze</button>`}
        <button class="btn btn-sm ${a.saved ? "btn-success" : "btn-primary"} full" data-action="save-assessment" ${a.saved ? "disabled" : ""}>
          <i class="bi ${a.saved ? "bi-check2-circle" : "bi-save"} me-1"></i>${a.saved ? "Assessment Saved" : "Save Assessment"}</button>
        ${workflowButtons(a, change, user)}
        <a class="btn btn-sm btn-light border full" href="/reports?assessment=${a.id}"><i class="bi bi-file-earmark-text me-1"></i>Open Report</a>
      </div>
    </div>
    ${(a.configuration_diff || []).length ? `<div class="ng-panel-section"><div class="ng-panel-title">Configuration Comparison</div>
      ${a.configuration_diff.map(item => `<div class="small mb-2"><strong>${escapeHtml(item.device)} · ${escapeHtml(item.target)}</strong>
        <div class="mono text-muted-ng">Baseline: ${escapeHtml(typeof item.current === 'object' ? JSON.stringify(item.current) : item.current)}</div>
        <div class="mono">Proposed: ${escapeHtml(typeof item.proposed === 'object' ? JSON.stringify(item.proposed) : item.proposed)}</div></div>`).join('')}
    </div>` : ''}
    ${a.change.commands && a.change.commands.length ? `<div class="ng-panel-section"><div class="ng-panel-title">Device Commands</div>${commandsBlock(a.change.commands, `chg-${a.change.id}`)}
      <p class="small text-muted-ng mt-2 mb-0">After IT Manager approval, NetGuard sends these commands only to a laboratory device, with a configuration backup, post-change verification and automatic rollback.</p></div>` : ""}
    <div class="ng-panel-section"><div class="ng-panel-title">Explanation</div>${explanationBlock(a)}</div>
    <div class="ng-panel-section"><div class="ng-panel-title">Findings <span>${a.findings.length}</span></div>${findingsBlock(a.findings)}</div>
    ${(a.advisories || []).length ? `<div class="ng-panel-section"><div class="ng-panel-title">Security &amp; hygiene advisories</div>${advisoriesBlock(a.advisories)}</div>` : ""}
    ${(a.coverage_notes || []).length ? `<div class="ng-panel-section"><div class="ng-panel-title">Analysis coverage notes</div><ul class="small ps-3 mb-0">${a.coverage_notes.map(note => `<li>${escapeHtml(note)}</li>`).join("")}</ul></div>` : ""}
    <div class="ng-panel-section">
      <div class="ng-panel-title">Impact Analysis <span>${affected.length} affected</span></div>
      ${affected.length ? affected.map((x) => flowItem(x.impact, x.index)).join("") : `<p class="small text-muted-ng">No evaluated flow is affected.</p>`}
      <details class="mt-2"><summary class="small fw-semibold">Unaffected flows (${unaffected.length})</summary>
        <div class="mt-2">${unaffected.map((x) => flowItem(x.impact, x.index)).join("")}</div></details>
    </div>
    <div class="ng-panel-section">
      <details><summary class="small fw-semibold">Validation checks · ${counts.passed || 0} passed · ${counts.failed || 0} failed · ${counts.warning || 0} pre-existing</summary>
        <div class="mt-2">${checksBlock(a.checks)}</div></details>
    </div>
    ${a.resolved_issues.length ? `<div class="ng-panel-section"><div class="ng-panel-title">Resolved by this change</div>${findingsBlock(a.resolved_issues)}</div>` : ""}`;
}

export { recommendationBadge };
