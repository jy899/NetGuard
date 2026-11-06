// Change approval, approved laboratory execution and read-only configuration collection for the workspace.
// Secrets typed into these dialogs are sent once and cleared; nothing is written to browser storage.
import { api } from "../api.js";
import { escapeHtml, toast, withBusy } from "../ui.js";

const allowed = (user, permission) => Boolean(user && (user.permissions || []).includes(permission));
export const canModify = (user) => allowed(user, "change.propose");
export const canApprove = (user) => allowed(user, "change.approve");
export const canExecute = (user) => allowed(user, "change.execute");
export const canExecuteProduction = (user) => allowed(user, "change.execute_production");

function mount(html) {
  const wrapper = document.createElement("div");
  wrapper.innerHTML = html.trim();
  const element = wrapper.firstElementChild;
  document.body.appendChild(element);
  return element;
}

/** Workflow actions for the analysis panel, by change status and role. */
export function workflowButtons(a, change, user) {
  const status = change?.status || a.change.status;
  const approval = change?.approval || {};
  const who = (name) => (name ? ` by ${escapeHtml(name)}` : "");
  const note = (text, cls = "text-muted-ng") => `<div class="full small ${cls} text-center">${text}</div>`;
  if (status === "awaiting_confirm") {
    const by = change?.self_healing?.confirm_by;
    const time = by ? new Date(`${by}Z`).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "the deadline";
    return note(`<i class="bi bi-stopwatch me-1"></i>Applied and verified on the production device. Confirm by ${escapeHtml(time)} or NetGuard rolls it back automatically.`, "text-warning fw-semibold")
      + (canExecute(user) ? `<button class="btn btn-sm btn-success" data-action="confirm-change"><i class="bi bi-check2-circle me-1"></i>Confirm (keep)</button><button class="btn btn-sm btn-outline-danger" data-action="rollback-change"><i class="bi bi-arrow-counterclockwise me-1"></i>Roll back now</button>` : "")
      + `<button class="btn btn-sm btn-light border full" data-action="show-executions">Execution log</button>`;
  }
  if (status === "applied") return note(`<i class="bi bi-check2-all me-1"></i>Applied${change?.lab_device ? " to the laboratory device and verified" : " (recorded as deployed)"}`, "text-success fw-semibold");
  if (status === "rolled_back") return note('<i class="bi bi-arrow-counterclockwise me-1"></i>Verification failed; the device was restored from its backup.', "text-warning fw-semibold") + `<button class="btn btn-sm btn-light border full" data-action="show-executions">Execution log</button>`;
  if (status === "failed") return note('<i class="bi bi-exclamation-octagon me-1"></i>Rollback could not be verified; restore the device from the stored backup.', "text-danger fw-semibold") + `<button class="btn btn-sm btn-light border full" data-action="show-executions">Execution log</button>`;
  if (status === "pending_approval") {
    if (canApprove(user) && approval.submitted_by !== user.username) return `<button class="btn btn-sm btn-success" data-action="approve-change"><i class="bi bi-check2-circle me-1"></i>Approve</button><button class="btn btn-sm btn-outline-danger" data-action="reject-change"><i class="bi bi-x-circle me-1"></i>Reject</button>`;
    return note(`<i class="bi bi-hourglass-split me-1"></i>Waiting for IT Manager approval (submitted${who(approval.submitted_by)}).`);
  }
  if (status === "approved") {
    if (!canExecute(user)) return note(`Approved${who(approval.decided_by)}; waiting for execution by an engineer.`, "text-success");
    const header = note(`<i class="bi bi-patch-check me-1"></i>Approved${who(approval.decided_by)}${approval.note ? `: ${escapeHtml(approval.note)}` : ""}`, "text-success");
    if (change?.lab_device) return header + `<button class="btn btn-sm btn-success full" data-action="execute-change"><i class="bi bi-play-circle me-1"></i>Execute on Lab Device</button>`;
    const healing = change?.self_healing || {};
    const self = approval.decided_by && approval.decided_by === user?.username;
    const production = healing.enabled && canExecuteProduction(user) && !self
      ? `<button class="btn btn-sm btn-success full" data-action="execute-change"><i class="bi bi-shield-check me-1"></i>Execute with Self-Healing Safeguards</button>`
      : note(healing.enabled ? (self ? "Separation of duties: the approver cannot execute this production change." : "Your group may not execute production changes.") : "Production self-healing is off (Settings); apply the commands manually.");
    return header + production + `<button class="btn btn-sm btn-outline-success full" data-action="apply-change"><i class="bi bi-check2-square me-1"></i>Record as Deployed</button>`;
  }
  const rejected = status === "rejected" ? note(`<i class="bi bi-x-octagon me-1"></i>Rejected${who(approval.decided_by)}${approval.note ? `: ${escapeHtml(approval.note)}` : ""}. Modify and validate again to resubmit.`, "text-danger") : "";
  if (!canModify(user)) return rejected || note("Read-only: an engineer submits changes for your approval.");
  if (a.validation_result === "INCOMPLETE") return rejected + note("Submission is blocked: configuration evidence is incomplete. Collect the configuration and validate again.");
  if (a.recommendation === "DO_NOT_DEPLOY") return rejected + note("Submission is blocked: NetGuard recommends DO NOT DEPLOY.");
  return rejected + `<button class="btn btn-sm btn-success full" data-action="submit-change"><i class="bi bi-send-check me-1"></i>Submit for Approval</button>`;
}

function credentialRows(prefix) {
  return `<div class="row g-2 mt-1" data-cred-rows>
    <div class="col-md-6"><label class="form-label small" for="${prefix}-profile">SSH credential profile</label><select id="${prefix}-profile" class="form-select form-select-sm"><option value="">Enter credentials</option></select></div>
    <div class="col-md-6"><label class="form-label small" for="${prefix}-port">SSH port</label><input id="${prefix}-port" type="number" min="1" max="65535" value="22" class="form-control form-control-sm"></div>
    <div class="col-md-4"><label class="form-label small" for="${prefix}-user">Username</label><input id="${prefix}-user" class="form-control form-control-sm" maxlength="64" autocomplete="off"></div>
    <div class="col-md-4"><label class="form-label small" for="${prefix}-password">Password</label><input id="${prefix}-password" type="password" class="form-control form-control-sm" maxlength="128" autocomplete="new-password"></div>
    <div class="col-md-4"><label class="form-label small" for="${prefix}-secret">Enable secret (optional)</label><input id="${prefix}-secret" type="password" class="form-control form-control-sm" maxlength="128" autocomplete="new-password"></div>
  </div>`;
}

async function fillProfiles(select) {
  try {
    const profiles = (await api.get("/credential-profiles")).filter((p) => (p.method || "ssh") === "ssh");
    select.innerHTML = '<option value="">Enter credentials</option>' + profiles.map((p) => `<option value="${p.id}">${escapeHtml(p.name)} · ${escapeHtml(p.username)}</option>`).join("");
  } catch { /* profiles are optional */ }
}

function credentials(element, prefix) {
  const $ = (id) => element.querySelector(`#${prefix}-${id}`);
  const body = { profile_id: Number($("profile").value) || null, username: $("user").value.trim(), password: $("password").value,
    secret: $("secret").value, port: Number($("port").value) || 22 };
  ["password", "secret"].forEach((id) => { $(id).value = ""; });
  return body;
}

export function createWorkflow({ onChanged }) {
  // ------------------------------------------------------------ decision (approve / reject)
  const decision = mount(`<div class="modal fade" id="decision-modal" tabindex="-1" aria-labelledby="decision-title" aria-hidden="true"><div class="modal-dialog modal-dialog-centered"><div class="modal-content">
    <div class="modal-header"><h5 class="modal-title" id="decision-title">Approve change</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
    <div class="modal-body"><div class="alert alert-danger small py-2 d-none" id="decision-error" role="alert"></div><div id="decision-summary" class="small mb-2"></div>
      <label class="form-label small" for="decision-note" id="decision-note-label">Note (optional)</label><textarea id="decision-note" class="form-control" rows="2" maxlength="300"></textarea></div>
    <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal">Cancel</button><button type="button" class="btn btn-success" id="decision-submit">Approve</button></div></div></div></div>`);
  const decisionModal = bootstrap.Modal.getOrCreateInstance(decision);
  let decisionState = null;
  decision.querySelector("#decision-submit").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
    const error = decision.querySelector("#decision-error");
    try {
      const updated = await api.post(`/changes/${decisionState.change.id}/${decisionState.approve ? "approve" : "reject"}`, { note: decision.querySelector("#decision-note").value.trim() || null });
      decisionModal.hide();
      toast(decisionState.approve ? "Change approved" : "Change rejected", decisionState.approve ? "success" : "info");
      await onChanged(updated);
    } catch (err) { error.textContent = err.message; error.classList.remove("d-none"); }
  }));

  // ------------------------------------------------------------ execution on a laboratory device
  const execute = mount(`<div class="modal fade" id="execute-modal" tabindex="-1" aria-labelledby="execute-title" aria-hidden="true"><div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
    <div class="modal-header"><h5 class="modal-title" id="execute-title">Execute approved change on the laboratory device</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
    <div class="modal-body"><div class="alert alert-danger small py-2 d-none" id="execute-error" role="alert"></div>
      <div id="execute-summary" class="small mb-2"></div>
      <ol class="small mb-3" id="execute-steps"><li>Re-validate the change on a fresh copy of the model.</li><li>Back up the running configuration (stored encrypted).</li><li>Send the commands below.</li><li>Read the configuration again and verify the intended state, with no new finding and no newly broken flow.</li><li>On any failure, restore the changed sections from the backup and verify the restoration.</li></ol>
      <pre class="ng-cli" id="execute-commands"></pre>
      <label class="form-label small fw-semibold" for="execute-transport">Connection</label>
      <select id="execute-transport" class="form-select form-select-sm"><option value="console">Laboratory console (EVE-NG / GNS3)</option><option value="ssh">SSH to the management address</option><option value="auto">Automatic (SSH when credentials are given)</option></select>
      <div class="small text-muted-ng mt-1">Lab consoles normally need no login; enter credentials only when the console asks for them.</div>
      ${credentialRows("ex")}
      <div id="execute-result" class="mt-3" aria-live="polite"></div></div>
    <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal" id="execute-close">Cancel</button><button type="button" class="btn btn-success" id="execute-submit"><i class="bi bi-play-circle me-1"></i>Execute with Backup and Rollback</button></div></div></div></div>`);
  const executeModal = bootstrap.Modal.getOrCreateInstance(execute);
  let executeState = null;
  const renderExecution = (ex) => `<div class="border rounded p-3 ${ex.status === "applied" ? "border-success" : "border-warning"}">
      <div class="fw-semibold mb-1">${escapeHtml({ applied: "Applied and verified", awaiting_confirm: "Verified, waiting for confirmation", rolled_back: "Rolled back to the backup", rollback_failed: "Rollback not verified", failed: "Failed" }[ex.status] || ex.status)} · ${escapeHtml(ex.device_name)} via ${escapeHtml(ex.transport)}</div>
      ${(ex.verification?.lost_reachability || []).length ? `<div class="small text-danger">No longer reachable: ${escapeHtml(ex.verification.lost_reachability.join(", "))}</div>` : ""}
      <ul class="small mb-2">${(ex.log || []).map((l) => `<li>${escapeHtml(l.step)}</li>`).join("")}</ul>
      ${(ex.verification?.new_findings || []).length ? `<div class="small text-danger">New findings: ${escapeHtml(ex.verification.new_findings.join(", "))}</div>` : ""}
      ${(ex.verification?.broken_flows || []).length ? `<div class="small text-danger">Newly broken flows: ${escapeHtml(ex.verification.broken_flows.join(", "))}</div>` : ""}
      ${(ex.rollback_commands || []).length ? `<details class="small"><summary>Rollback commands sent</summary><pre class="ng-cli mt-1">${ex.rollback_commands.map(escapeHtml).join("\n")}</pre></details>` : ""}</div>`;
  execute.querySelector("#execute-submit").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
    const error = execute.querySelector("#execute-error");
    error.classList.add("d-none");
    try {
      const body = { confirm: true, transport: execute.querySelector("#execute-transport").value, ...credentials(execute, "ex") };
      const result = await api.post(`/changes/${executeState.change.id}/execute`, body);
      execute.querySelector("#execute-result").innerHTML = renderExecution(result.execution);
      execute.querySelector("#execute-submit").classList.add("d-none");
      execute.querySelector("#execute-close").textContent = "Close";
      const done = result.execution.status;
      toast(done === "applied" ? "Change applied and verified" : done === "awaiting_confirm" ? "Verified: confirm the change before the window closes" : "Change rolled back", done === "rolled_back" || done === "failed" ? "warning" : "success");
      await onChanged(result.change, { executed: true });
    } catch (err) { error.textContent = err.message; error.classList.remove("d-none"); }
  }));

  // ------------------------------------------------------------ configuration collection
  const collect = mount(`<div class="modal fade" id="collect-modal" tabindex="-1" aria-labelledby="collect-title" aria-hidden="true"><div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
    <div class="modal-header"><div><h5 class="modal-title" id="collect-title">Collect device configurations</h5><div class="small text-muted-ng">Read-only · show commands only · the configuration replaces the stored model of each device</div></div><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
    <div class="modal-body"><div class="alert alert-danger small py-2 d-none" id="collect-error" role="alert"></div>
      <fieldset><legend class="form-label small fw-semibold">Devices</legend><div id="collect-devices" class="d-flex flex-column gap-1"></div></fieldset>
      <label class="form-label small fw-semibold mt-3" for="collect-transport">Connection</label>
      <select id="collect-transport" class="form-select form-select-sm"><option value="auto">Automatic (lab console, or SSH when credentials are given)</option><option value="console">Laboratory console</option><option value="ssh">SSH to the management address</option></select>
      ${credentialRows("co")}
      <div id="collect-result" class="mt-3" aria-live="polite"></div></div>
    <div class="modal-footer"><button type="button" class="btn btn-light" data-bs-dismiss="modal">Close</button><button type="button" class="btn btn-primary" id="collect-submit"><i class="bi bi-download me-1"></i>Collect</button></div></div></div></div>`);
  const collectModal = bootstrap.Modal.getOrCreateInstance(collect);
  let collectState = null;
  collect.querySelector("#collect-submit").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
    const error = collect.querySelector("#collect-error");
    error.classList.add("d-none");
    const ids = [...collect.querySelectorAll("[data-collect-device]:checked")].map((input) => Number(input.dataset.collectDevice));
    if (!ids.length) { error.textContent = "Select at least one device."; error.classList.remove("d-none"); return; }
    try {
      const result = await api.post(`/networks/${collectState.network.id}/collect`, { device_ids: ids, transport: collect.querySelector("#collect-transport").value, ...credentials(collect, "co") });
      collect.querySelector("#collect-result").innerHTML = result.outcomes.map((o) => `<div class="border rounded p-2 mb-2 small ${o.ok ? "border-success" : "border-danger"}"><strong>${escapeHtml(o.name)}</strong> · ${escapeHtml(o.transport)} · ${o.ok ? `<span class="text-success">collected</span> <span class="mono text-muted-ng">SHA-256 ${escapeHtml(o.sha256.slice(0, 16))}…</span>` : `<span class="text-danger">${escapeHtml(o.detail)}</span>`}${(o.warnings || []).length ? `<details><summary>${o.warnings.length} note(s)</summary><ul class="mb-0">${o.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul></details>` : ""}</div>`).join("");
      if (result.outcomes.some((o) => o.ok)) await onChanged(null, { collected: true });
    } catch (err) { error.textContent = err.message; error.classList.remove("d-none"); }
  }));

  return {
    async submit(change, button) {
      await withBusy(button, async () => {
        try { const updated = await api.post(`/changes/${change.id}/submit`); toast("Submitted for IT Manager approval", "success"); await onChanged(updated); }
        catch (err) { toast(err.message, "error"); }
      });
    },
    decide(change, assessment, approve) {
      decisionState = { change, approve };
      decision.querySelector("#decision-title").textContent = approve ? "Approve change" : "Reject change";
      decision.querySelector("#decision-submit").textContent = approve ? "Approve" : "Reject";
      decision.querySelector("#decision-submit").className = `btn ${approve ? "btn-success" : "btn-danger"}`;
      decision.querySelector("#decision-note-label").textContent = approve ? "Note (optional)" : "Reason (required)";
      decision.querySelector("#decision-note").value = "";
      decision.querySelector("#decision-error").classList.add("d-none");
      decision.querySelector("#decision-summary").innerHTML = `<strong>${escapeHtml(assessment.change.device)}</strong> · ${escapeHtml(assessment.change.change_type_label)} <span class="mono">${escapeHtml(assessment.change.current_value)} → ${escapeHtml(assessment.change.proposed_value)}</span><div class="mt-1">${escapeHtml(assessment.recommendation_label)} · ${escapeHtml(assessment.risk_level)} risk ${assessment.total_risk_score}/100${assessment.evidence_confidence ? ` · evidence confidence ${escapeHtml(assessment.evidence_confidence.toLowerCase())}` : ""}</div>`;
      decisionModal.show();
    },
    async confirm(change, keep, button) {
      await withBusy(button, async () => {
        try {
          const result = await api.post(`/changes/${change.id}/${keep ? "confirm" : "rollback"}`, {});
          toast(keep ? "Change confirmed and saved" : `Rollback: ${result.execution.status.replace("_", " ")}`, keep ? "success" : "warning");
          await onChanged(result.change, { executed: true });
        } catch (err) { toast(err.message, "error"); }
      });
    },
    async execute(change, assessment) {
      executeState = { change };
      const production = change && change.lab_device === false;
      execute.querySelector("#execute-title").textContent = production ? "Execute approved change on the production device" : "Execute approved change on the laboratory device";
      execute.querySelector("#execute-steps").innerHTML = production
        ? "<li>Re-validate on a fresh model copy (digital twin) and check the hybrid rules + AI risk limit.</li><li>Back up the running configuration (encrypted, SHA-256).</li><li>Record live reachability and arm the device's own revert timer where the platform has one.</li><li>Send the commands, read the configuration back, verify the intended state, rules, required flows on the digital twin and live reachability.</li><li>Keep the change only when you confirm it within the window; otherwise NetGuard restores the backup.</li>"
        : "<li>Re-validate the change on a fresh copy of the model.</li><li>Back up the running configuration (stored encrypted).</li><li>Send the commands below.</li><li>Read the configuration again and verify the intended state, with no new finding and no newly broken flow.</li><li>On any failure, restore the changed sections from the backup and verify the restoration.</li>";
      execute.querySelector("#execute-transport").value = production ? "ssh" : "console";
      execute.querySelector("#execute-error").classList.add("d-none");
      execute.querySelector("#execute-result").innerHTML = "";
      execute.querySelector("#execute-submit").classList.remove("d-none");
      execute.querySelector("#execute-close").textContent = "Cancel";
      execute.querySelector("#execute-summary").innerHTML = `<strong>${escapeHtml(assessment.change.device)}</strong> · ${escapeHtml(assessment.change.change_type_label)} <span class="mono">${escapeHtml(assessment.change.current_value)} → ${escapeHtml(assessment.change.proposed_value)}</span>`;
      execute.querySelector("#execute-commands").textContent = (assessment.change.commands || []).filter((c) => !c.startsWith("!") && !c.startsWith("#")).join("\n");
      await fillProfiles(execute.querySelector("#ex-profile"));
      executeModal.show();
    },
    async showExecutions(change) {
      try {
        const rows = await api.get(`/changes/${change.id}/executions`);
        executeState = { change };
        execute.querySelector("#execute-summary").innerHTML = "";
        execute.querySelector("#execute-commands").textContent = rows[0]?.commands?.join("\n") || "";
        execute.querySelector("#execute-result").innerHTML = rows.map(renderExecution).join("") || '<p class="small text-muted-ng">No execution recorded.</p>';
        execute.querySelector("#execute-submit").classList.add("d-none");
        execute.querySelector("#execute-close").textContent = "Close";
        executeModal.show();
      } catch (err) { toast(err.message, "error"); }
    },
    async collect(network, devices) {
      collectState = { network };
      const eligible = devices.filter((d) => ["router", "switch", "firewall"].includes(d.device_type) && (d.access?.console || d.management_ip));
      collect.querySelector("#collect-error").classList.add("d-none");
      collect.querySelector("#collect-result").innerHTML = "";
      collect.querySelector("#collect-devices").innerHTML = eligible.length ? eligible.map((d) => `<div class="form-check"><input class="form-check-input" type="checkbox" id="co-dev-${d.id}" data-collect-device="${d.id}" checked><label class="form-check-label small" for="co-dev-${d.id}"><strong>${escapeHtml(d.name)}</strong> <span class="text-muted-ng">${escapeHtml([d.access?.console ? "lab console" : null, d.management_ip].filter(Boolean).join(" · "))}</span></label></div>`).join("") : '<p class="small text-muted-ng mb-0">No router or switch has a laboratory console or a management address.</p>';
      await fillProfiles(collect.querySelector("#co-profile"));
      collectModal.show();
    },
  };
}
