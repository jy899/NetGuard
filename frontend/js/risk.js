// Risk level, recommendation and status presentation helpers (brief 8.4 colours).
import { escapeHtml } from "./ui.js";

export const RISK_COLORS = {
  LOW: "#2e8b57",
  MEDIUM: "#d4a106",
  HIGH: "#e07020",
  CRITICAL: "#c62f2f",
};

export function riskClass(level) {
  return `ng-risk-${(level || "neutral").toLowerCase()}`;
}

export function riskBadge(level, text) {
  return `<span class="ng-badge-risk ${riskClass(level)}">${escapeHtml(text || level)}</span>`;
}

export const RECOMMENDATION_LABELS = {
  DEPLOY: "Deploy",
  DEPLOY_WITH_CAUTION: "Deploy with caution",
  DO_NOT_DEPLOY: "Do not deploy",
};

export function recommendationBadge(code, level) {
  const tone = code === "DO_NOT_DEPLOY" ? (level === "CRITICAL" ? "CRITICAL" : "HIGH") : code === "DEPLOY" ? "LOW" : "MEDIUM";
  return riskBadge(tone, RECOMMENDATION_LABELS[code] || code);
}

export function severityBadge(severity) {
  const level = severity === "MEDIUM/HIGH" ? "HIGH" : severity;
  return riskBadge(level, severity);
}

export const CHANGE_STATUS_LABELS = {
  draft: "Draft", analyzed: "Validated", saved: "Saved", pending_approval: "Awaiting approval", approved: "Approved",
  rejected: "Rejected", applied: "Applied", rolled_back: "Rolled back", failed: "Rollback failed",
};
const STATUS_CLASS = {
  saved: "ng-risk-low", approved: "ng-risk-low", applied: "ng-risk-low", analyzed: "ng-risk-medium",
  pending_approval: "ng-risk-medium", rolled_back: "ng-risk-high", rejected: "ng-risk-high", failed: "ng-risk-critical",
};

export function changeStatusBadge(status) {
  const cls = STATUS_CLASS[status] || "ng-risk-neutral";
  return `<span class="ng-badge-risk ${cls}">${escapeHtml(CHANGE_STATUS_LABELS[status] || status)}</span>`;
}

export const CATEGORY_LABELS = { ip_interface: "IP / Interface", routing: "Routing", acl: "ACL", vlan: "VLAN", security: "Security hardening", physical: "Physical work order" };

export function flowLabel(protocol, port) {
  if (!protocol) return "gateway";
  return protocol.toUpperCase() + (port ? `/${port}` : "");
}
