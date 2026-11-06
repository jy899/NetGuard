// Shared labels for stored-model evidence, traffic results and advisories.
import { escapeHtml } from "./ui.js";
import { severityBadge } from "./risk.js";

export function environmentLabel(network = {}) {
  if (network.source === "discovery") return "Live network · read-only discovery (authorised range)";
  if (["eve-ng", "gns3"].includes(network.source)) {
    return `Virtual lab · ${network.source === "eve-ng" ? "EVE-NG" : "GNS3"}${network.is_simulated ? " (sample data from an earlier version)" : ""}`;
  }
  if (network.source === "config-import") return "Configuration import · stored model";
  if (network.is_simulated || network.source === "demo" || network.source === "sample") return "Offline example network";
  if (network.environment === "virtual") return "Virtual lab";
  return "Manual model";
}

/** Scope text without a trailing full stop, so callers can append their own sentence. */
export function scopeText(text) {
  return String(text || "").trim().replace(/\.+$/, "");
}

export function flowResultBadge(ok) {
  const result = ok === true ? "PASS" : ok === false ? "FAIL" : "UNKNOWN";
  return `<span class="ng-flow-result ${result.toLowerCase()}">${result}</span>`;
}

export function expectedActionBadge(action) {
  // Older saved assessments and implicit flows carry no expected action; never imply ALLOW.
  if (!action) return `<span class="ng-badge-plain text-nowrap text-muted-ng" title="No expected action recorded">EXPECTED N/A</span>`;
  return `<span class="ng-badge-plain text-nowrap">${escapeHtml(action.toUpperCase())}</span>`;
}

export function evidenceText(item) {
  if (!item || typeof item !== "object") return String(item || "");
  return [item.source, item.detail || item.observation || item.description || ""].filter(Boolean).join(": ");
}

// Older snapshots can repeat a diagnostic message. Keep each fact visible once.
export function diagnosticSections(issue) {
  const seen = new Set();
  const section = (title, value) => {
    const values = [];
    for (const item of Array.isArray(value) ? value : [value]) {
      const text = evidenceText(item);
      const detail = typeof item === "object" && item ? item.detail || item.observation || item.description || text : text;
      const keys = [text, detail].map(part => part.trim().toLowerCase());
      if (!keys[0] || keys.some(key => seen.has(key))) continue;
      keys.forEach(key => seen.add(key));
      values.push(text);
    }
    if (!values.length) return "";
    return `<div class="small mt-2"><strong>${title}</strong>${Array.isArray(value)
      ? `<ul class="ps-3 mb-0">${values.map(text => `<li>${escapeHtml(text)}</li>`).join("")}</ul>`
      : `<div>${escapeHtml(values[0])}</div>`}</div>`;
  };
  return section("Symptom", issue.symptom || issue.message) +
    section(issue.certainty === "suspected" ? "Possible root cause" : "Root cause", issue.root_cause || issue.possible_root_cause || issue.message) +
    section("Supporting evidence", issue.evidence || issue.supporting_evidence || []);
}

export function advisoriesBlock(advisories = []) {
  return advisories.map(item => `<article class="ng-advisory">
    <div class="d-flex align-items-start gap-2"><strong class="flex-grow-1">${escapeHtml(item.rule_id || item.id)} · ${escapeHtml(item.title || item.name)}</strong>${severityBadge(item.severity)}</div>
    <ul class="small ps-3 mt-2 mb-1">${(item.evidence || []).map(fact => `<li>${escapeHtml(evidenceText(fact))}</li>`).join("")}</ul>
    ${(item.affected_devices || item.devices || []).length ? `<div class="small text-muted-ng">Devices: ${escapeHtml((item.affected_devices || item.devices).join(", "))}</div>` : ""}
    <div class="small mt-1">${escapeHtml(item.recommendation)}</div>
    ${item.reference ? `<div class="small text-muted-ng mt-1">${escapeHtml(item.reference)}</div>` : ""}
  </article>`).join("");
}
