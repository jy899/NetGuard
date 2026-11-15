import { api, session } from "../api.js";
import { initShell } from "../layout.js";
import { confirmDialog, escapeHtml, fillForm, formatDate, readForm, showFormError, toast, withBusy } from "../ui.js";

/** Short names for the permission chips; the full description is in the chip's tooltip. */
const PERMISSION_SHORT = {
  "topology.view": "View", "network.edit": "Edit networks", "network.import_export": "Import & export",
  "discovery.run": "Discover", "analysis.run": "Analyze", "change.propose": "Propose changes",
  "change.approve": "Approve changes", "change.execute": "Apply fixes (lab)", "change.execute_production": "Apply fixes (real)",
  "change.auto_fix": "Fix without approval", "credentials.manage": "Device logins", "users.manage": "Users & groups",
  "device.terminal": "Terminal", "device.terminal_config": "Terminal config (real)",
};

const $ = (id) => document.getElementById(id);
const state = { user: null, accounts: [], groups: [], catalogue: [], profiles: [], accountId: null, profileId: null, groupId: null };

function renderProfile() {
  const user = state.user;
  $("account-info").innerHTML = `<dt>Username</dt><dd>${escapeHtml(user.username)}</dd><dt>User group</dt><dd>${escapeHtml(user.role)}</dd><dt>Created</dt><dd>${formatDate(user.created_at)}</dd>`;
  const labels = Object.fromEntries(state.catalogue.map((p) => [p.id, p.label]));
  $("account-permissions").innerHTML = (user.permissions || []).map((p) => `<li>${escapeHtml(labels[p] || p)}</li>`).join("") || "<li>None</li>";
}

function renderSession() {
  let expiry = "Not available";
  try {
    const parts = session.token.split(".");
    const encoded = parts[parts.length === 3 ? 1 : 0].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(encoded));
    if (payload.exp) expiry = formatDate(new Date(payload.exp * 1000).toISOString());
  } catch { /* retain the explicit unavailable state */ }
  $("session-info").innerHTML = `Signed in as <strong>${escapeHtml(state.user.username)}</strong> on this computer · session ends ${expiry}`;
}


async function loadAccounts() {
  [state.accounts, state.groups] = await Promise.all([api.get("/accounts"), api.get("/groups")]);
  $("account-list").innerHTML = `<div class="table-responsive"><table class="table ng-table"><thead><tr><th>Username</th><th>User group</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>${state.accounts.map((user) => {
    const protectedAccount = user.id === state.user.id || user.username === "admin";
    return `<tr data-account="${user.id}"><td class="fw-semibold">${escapeHtml(user.username)}</td><td>${escapeHtml(user.role)}</td><td><span class="ng-badge-plain ${user.is_active ? "text-success" : "text-muted-ng"}">${user.is_active ? "Active" : "Disabled"}</span></td><td class="small text-muted-ng">${formatDate(user.created_at)}</td><td class="actions"><button class="btn btn-sm btn-outline-primary" data-account-action="edit">Edit</button>${protectedAccount ? '<span class="small text-muted-ng ms-2">Protected account</span>' : `<button class="btn btn-sm btn-light border" data-account-action="toggle">${user.is_active ? "Disable" : "Enable"}</button><button class="btn btn-sm btn-outline-danger" data-account-action="delete">Delete</button>`}</td></tr>`;
  }).join("")}</tbody></table></div>`;
  const labels = Object.fromEntries(state.catalogue.map((p) => [p.id, p.label]));
  $("group-list").innerHTML = `<div class="table-responsive"><table class="table ng-table"><thead><tr><th>Group</th><th>Permissions</th><th>Members</th><th></th></tr></thead><tbody>${state.groups.map((group) => `<tr data-group="${group.id}"><td><div class="fw-semibold">${escapeHtml(group.name)}${group.builtin ? ' <span class="ng-badge-plain small">Built-in</span>' : ""}</div><div class="small text-muted-ng">${escapeHtml(group.description || "")}</div></td><td class="small">${group.permissions.map((p) => `<span class="ng-type-badge me-1 mb-1 d-inline-block" title="${escapeHtml(`${labels[p] || p} (${p})`)}">${escapeHtml(PERMISSION_SHORT[p] || p)}</span>`).join("") || '<span class="text-muted-ng">No permissions</span>'}</td><td>${group.members}</td><td class="actions"><button class="btn btn-sm btn-outline-primary" data-group-action="edit">Edit</button>${group.builtin ? "" : '<button class="btn btn-sm btn-outline-danger" data-group-action="delete">Delete</button>'}</td></tr>`).join("")}</tbody></table></div>`;
}

function openAccount(user = null) {
  state.accountId = user?.id ?? null;
  const form = $("account-form"); form.reset(); showFormError(form, "");
  $("account-group").innerHTML = state.groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  $("account-group").value = String(user?.group_id ?? state.groups.find((g) => g.name === "Network Engineers")?.id ?? state.groups[0]?.id);
  $("account-username").value = user?.username || "";
  $("account-modal-title").textContent = user ? "Edit User" : "Add User";
  $("account-username").disabled = !!user;
  $("account-password").value = "";
  $("account-password-label").textContent = user ? "New password (optional)" : "Password";
  bootstrap.Modal.getOrCreateInstance($("account-modal")).show();
}

function openGroup(group = null) {
  state.groupId = group?.id ?? null;
  const form = $("group-form"); form.reset(); showFormError(form, "");
  $("group-name").value = group?.name || "";
  $("group-name").disabled = !!group?.builtin;
  $("group-description").value = group?.description || "";
  const granted = new Set(group?.permissions || ["topology.view"]);
  $("group-permissions").innerHTML = state.catalogue.map((p) => `<div class="col-md-6"><div class="form-check"><input class="form-check-input" type="checkbox" id="perm-${p.id}" data-permission="${p.id}" ${granted.has(p.id) ? "checked" : ""}><label class="form-check-label small" for="perm-${p.id}"><span class="fw-semibold">${escapeHtml(p.label)}</span><br><span class="mono text-muted-ng">${escapeHtml(p.id)}</span></label></div></div>`).join("");
  $("group-modal-title").textContent = group ? `Edit ${group.name}` : "Add User Group";
  bootstrap.Modal.getOrCreateInstance($("group-modal")).show();
}

async function loadProfiles() {
  state.profiles = await api.get("/credential-profiles");
  $("credential-list").innerHTML = state.profiles.length ? `<div class="table-responsive"><table class="table ng-table"><thead><tr><th>Profile</th><th>Method</th><th>Device Username</th><th>Port</th><th>Priority</th><th>Assigned Devices</th><th></th></tr></thead><tbody>${state.profiles.map((profile) => `<tr data-profile="${profile.id}"><td><div class="fw-semibold">${escapeHtml(profile.name)}</div><div class="small text-muted-ng">${escapeHtml(profile.notes || "")}</div></td><td>${escapeHtml({ ssh: "SSH", snmpv3: "SNMPv3", snmpv2c: "SNMPv2c (read-only)" }[profile.method || "ssh"])}</td><td>${escapeHtml(profile.username)}<div class="small text-muted-ng">${profile.has_password ? "Encrypted secret saved" : "No secret saved"}</div></td><td>${profile.port}</td><td>${profile.priority}</td><td>${profile.used_by ?? 0}</td><td class="actions"><button class="btn btn-sm btn-outline-primary" data-profile-action="edit">Edit</button><button class="btn btn-sm btn-outline-danger" data-profile-action="delete">Delete</button></td></tr>`).join("")}</tbody></table></div>` : '<div class="ng-card-body small text-muted-ng">No device logins yet. Add one so NetGuard can read your devices (read-only SSH or SNMPv3).</div>';
}

function openCredential(profile = null) {
  state.profileId = profile?.id ?? null;
  const form = $("credential-form"); form.reset(); showFormError(form, "");
  fillForm(form, profile || { port: 22, priority: 100, method: "ssh" });
  $("credential-method").value = profile?.method || "ssh";
  $("credential-password").value = "";
  $("credential-priv").value = "";
  methodFields();
  $("credential-password-note").classList.toggle("d-none", !profile);
  $("credential-modal-title").textContent = profile ? "Edit Device Login" : "Add Device Login";
  bootstrap.Modal.getOrCreateInstance($("credential-modal")).show();
}

function bindProfile() {
  $("password-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const form = event.currentTarget; showFormError(form, ""); const data = readForm(form);
    data.current_password = $("pw-current").value; data.new_password = $("pw-new").value; data.confirm = $("pw-confirm").value;
    if (!data.current_password || !data.new_password) return showFormError(form, "Fill in all password fields.");
    if (!data.new_password) return showFormError(form, "Enter a new password.");
    if (data.new_password !== data.confirm) return showFormError(form, "The new passwords do not match.");
    await withBusy($("pw-submit"), async () => {
      try { const result = await api.put("/auth/password", { current_password: data.current_password, new_password: data.new_password }); session.save(result.access_token, result.user || state.user); form.reset(); renderSession(); toast("Password updated. Other sessions have been signed out.", "success"); }
      catch (error) { showFormError(form, error.message); }
    });
  });
  $("btn-revoke-sessions").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const confirmed = await confirmDialog({ title: "Sign out other sessions?", message: "Earlier sign-ins will need to authenticate again. This browser stays signed in.", confirmLabel: "Sign Out Other Sessions" });
    if (!confirmed) return;
    await withBusy(button, async () => {
      try { const result = await api.post("/auth/revoke-other-sessions"); session.save(result.access_token, result.user || state.user); renderSession(); toast("Other sessions signed out", "success"); }
      catch (error) { toast(error.message, "error"); }
    });
  });
}

function bindAccounts() {
  $("btn-add-account").addEventListener("click", () => openAccount());
  $("account-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const form = event.currentTarget; showFormError(form, "");
    const username = $("account-username").value.trim(); const password = $("account-password").value; const groupId = Number($("account-group").value);
    if (!groupId) return showFormError(form, "Choose a user group.");
    if (!state.accountId && (!username || !password)) return showFormError(form, "Enter a username and a password.");
    await withBusy($("account-submit"), async () => {
      try {
        if (state.accountId) await api.put(`/accounts/${state.accountId}`, password ? { group_id: groupId, password } : { group_id: groupId });
        else await api.post("/accounts", { username, password, group_id: groupId });
        $("account-password").value = ""; bootstrap.Modal.getInstance($("account-modal")).hide(); await loadAccounts(); toast("User account saved", "success");
      } catch (error) { showFormError(form, error.message); }
    });
  });
  $("btn-add-group").addEventListener("click", () => openGroup());
  $("group-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const form = event.currentTarget; showFormError(form, "");
    const body = { name: $("group-name").value.trim(), description: $("group-description").value.trim() || null,
      permissions: [...form.querySelectorAll("[data-permission]:checked")].map((input) => input.dataset.permission) };
    if (body.name.length < 2) return showFormError(form, "Enter a group name.");
    await withBusy($("group-submit"), async () => {
      try {
        if (state.groupId) await api.put(`/groups/${state.groupId}`, body); else await api.post("/groups", body);
        bootstrap.Modal.getInstance($("group-modal")).hide(); await loadAccounts(); toast("User group saved", "success");
      } catch (error) { showFormError(form, error.message); }
    });
  });
  $("group-list").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-group-action]"); if (!button) return;
    const group = state.groups.find((item) => item.id === Number(button.closest("[data-group]").dataset.group));
    if (button.dataset.groupAction === "edit") return openGroup(group);
    if (!await confirmDialog({ title: "Delete user group?", message: `<p class="mb-0">Delete <strong>${escapeHtml(group.name)}</strong>? A group with members cannot be deleted.</p>`, confirmLabel: "Delete Group", danger: true })) return;
    try { await api.del(`/groups/${group.id}`); await loadAccounts(); toast("User group deleted", "success"); }
    catch (error) { toast(error.message, "error"); }
  });
  $("account-list").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-account-action]"); if (!button) return;
    const user = state.accounts.find((item) => item.id === Number(button.closest("[data-account]").dataset.account));
    if (button.dataset.accountAction === "edit") return openAccount(user);
    const removing = button.dataset.accountAction === "delete";
    if (!await confirmDialog({ title: removing ? "Delete user?" : `${user.is_active ? "Disable" : "Enable"} user?`, message: `<p class="mb-0">${escapeHtml(user.username)}${removing ? " will be removed. Their historical network records remain available." : user.is_active ? " will be unable to sign in." : " will be able to sign in again."}</p>`, confirmLabel: removing ? "Delete User" : user.is_active ? "Disable User" : "Enable User", danger: removing || user.is_active })) return;
    try { if (removing) await api.del(`/accounts/${user.id}`); else await api.put(`/accounts/${user.id}`, { is_active: !user.is_active }); await loadAccounts(); toast("User account updated", "success"); }
    catch (error) { toast(error.message, "error"); }
  });
}

function methodFields() {
  const method = $("credential-method").value;
  $("credential-snmp").classList.toggle("d-none", method !== "snmpv3");
  $("credential-username-row").classList.toggle("d-none", method === "snmpv2c");
  if (method === "snmpv2c" && !$("credential-username").value) $("credential-username").value = "community";
  $("credential-password-label").textContent = { ssh: "Device password", snmpv3: "Authentication passphrase", snmpv2c: "Read-only community string" }[method];
  $("credential-port-label").textContent = method === "ssh" ? "SSH port" : "SNMP port";
  if (method !== "ssh" && $("credential-port").value === "22") $("credential-port").value = "161";
  if (method === "ssh" && $("credential-port").value === "161") $("credential-port").value = "22";
}

function bindCredentials() {
  $("btn-add-credential").addEventListener("click", () => openCredential());
  $("credential-method").addEventListener("change", methodFields);
  $("credential-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const form = event.currentTarget; showFormError(form, ""); const data = readForm(form); data.password = $("credential-password").value;
    if (!data.name?.trim() || !data.username?.trim() || (!state.profileId && !data.password)) return showFormError(form, $("credential-method").value === "snmpv2c" ? "Enter a profile name and the read-only community string." : "Enter a profile name, device username and password.");
    if (!$("credential-port").checkValidity() || !$("credential-priority").checkValidity() || !data.port || !data.priority) return showFormError(form, "Enter a valid port and priority.");
    const method = $("credential-method").value;
    const body = { name: data.name.trim(), username: data.username.trim(), password: data.password || "", port: Number(data.port), priority: Number(data.priority), notes: data.notes || "",
      method, snmp_auth_protocol: method === "snmpv3" ? $("credential-auth-protocol").value : "", snmp_priv_protocol: method === "snmpv3" ? $("credential-priv-protocol").value : "",
      priv_password: method === "snmpv3" ? $("credential-priv").value : "" };
    $("credential-priv").value = "";
    await withBusy($("credential-submit"), async () => {
      try { if (state.profileId) await api.put(`/credential-profiles/${state.profileId}`, body); else await api.post("/credential-profiles", body); $("credential-password").value = ""; bootstrap.Modal.getInstance($("credential-modal")).hide(); await loadProfiles(); toast("Device login saved", "success"); }
      catch (error) { showFormError(form, error.message); }
    });
  });
  $("credential-list").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-profile-action]"); if (!button) return;
    const profile = state.profiles.find((item) => item.id === Number(button.closest("[data-profile]").dataset.profile));
    if (button.dataset.profileAction === "edit") return openCredential(profile);
    if (!await confirmDialog({ title: "Delete credential profile?", message: `<p>Delete <strong>${escapeHtml(profile.name)}</strong>?</p><p class="mb-0 small text-muted-ng">Devices using this profile will need another credential assignment.</p>`, confirmLabel: "Delete Profile", danger: true })) return;
    try { await api.del(`/credential-profiles/${profile.id}`); await loadProfiles(); toast("Device login deleted", "success"); }
    catch (error) { toast(error.message, "error"); }
  });

  ["account-modal", "credential-modal"].forEach((id) => $(id).addEventListener("hidden.bs.modal", () => $(id).querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; })));
}

// Plain names for the advisory models; the technical method is shown on hover.
const AI_MODELS = {
  change_risk: ["Change risk", "Chance that a change breaks traffic or adds a serious problem", "Gradient-boosted trees"],
  blast_endpoints: ["Blast radius: devices", "How many endpoints a change touches", "Gradient-boosted regression"],
  blast_flows: ["Blast radius: traffic", "How many required flows a change breaks", "Gradient-boosted regression"],
  root_cause: ["Root cause", "Which finding is causing the outage", "Gradient-boosted trees"],
  fix_ranker: ["Best fix", "Which fix truly repairs the cause", "Gradient-boosted trees"],
  link_faults: ["Cable check", "Mismatches between the two ends of a cable (11 kinds)", "Naive Bayes"],
  syslog: ["Log reader", "Sorts device log messages into 10 fault types", "Naive Bayes"],
};
const TRIGGER = { shipped: "Installed", manual: "Retrained", auto: "Auto-learned" };
const STATUS = { active: ["In use", "text-bg-success"], previous: ["Earlier", "text-bg-light border"], rejected: ["Not used", "text-bg-light border text-muted"] };

function metricText(m) {
  if (!m) return "";
  if (m.auc != null) return `AUC ${m.auc} · Brier ${m.brier} (base rate ${m.brier_base_rate}) · ${m.test_rows} held-out rows${m.top1_accuracy != null ? ` · top-1 ${Math.round(m.top1_accuracy * 100)}%` : ""}`;
  if (m.mae != null) return `MAE ${m.mae} (mean baseline ${m.mae_mean_baseline}) · Spearman ${m.spearman} · ${m.test_rows} held-out rows`;
  if (m.macro_f1 != null) return `Accuracy ${m.accuracy} · macro-F1 ${m.macro_f1} (majority baseline ${m.majority_baseline_accuracy}) · ${m.test_rows} held-out rows`;
  return "";
}

/** One score per model (AUC, macro-F1 or rank correlation on networks never seen in training), shown as a grade. */
function grade(m) {
  const score = m?.auc ?? m?.macro_f1 ?? m?.spearman;
  if (score == null) return "";
  const [label, cls] = score >= 0.95 ? ["Excellent", "text-bg-success"] : score >= 0.85 ? ["Good", "text-bg-primary"] : ["Fair", "text-bg-warning"];
  return `<span class="badge ${cls}" title="${escapeHtml(metricText(m))}">${label} · ${Math.round(score * 100)}%</span>`;
}

const total = (counts) => Object.values(counts || {}).reduce((a, b) => a + b, 0);

async function loadAi(isAdmin) {
  const el = $("ai-info");
  let s;
  try { s = await api.get("/ai/status"); } catch (error) { el.textContent = error.message; return; }
  if (!s.available) {
    el.innerHTML = `<div class="ng-card ng-card-body small">The AI model files are not installed (data/models). NetGuard's rule-based analysis works without them.</div>`;
    return;
  }
  const ds = s.dataset || {};
  const current = (s.releases || []).find((r) => r.status === "active") || {};
  const mine = s.local_outcomes?.executed ?? 0;
  el.innerHTML = `
    <div class="ng-card mb-3"><div class="ng-card-body d-flex gap-3 align-items-start flex-wrap">
      <div class="ng-ai-mark"><i class="bi bi-stars"></i></div>
      <div class="flex-grow-1 min-w-0">
        <div class="d-flex align-items-center gap-2 flex-wrap"><h3 class="h5 mb-0">NetGuard AI</h3><span class="badge text-bg-success" data-ai-release>Release ${s.release ?? 1} in use</span>${s.training ? '<span class="badge text-bg-warning">Training…</span>' : ""}</div>
        <p class="small mb-1 mt-1">Learns from <strong>${total(ds.counts).toLocaleString()}</strong> practice examples (${ds.synthetic_campuses ?? "generated"} generated campus networks and ${ds.example_networks ?? 0} built-in networks) and <strong>${current.local_outcomes ?? 0}</strong> of your applied fixes.</p>
        <p class="small text-muted-ng mb-0">Advice only: NetGuard's rules make every decision. Trained ${escapeHtml(formatDate(current.trained_at || s.trained_at))} · ${escapeHtml(TRIGGER[current.trigger] || "Installed")}</p>
      </div>
      ${isAdmin ? '<button class="btn btn-sm btn-outline-primary" id="btn-retrain"><i class="bi bi-arrow-repeat me-1"></i>Retrain Now</button>' : ""}
    </div></div>

    <div class="row g-3">
      <div class="col-xl-7"><div class="ng-card h-100"><div class="ng-card-header"><h3>What it does</h3><span class="small text-muted-ng">Tested on networks it never saw</span></div>
        <table class="table ng-table mb-0"><tbody>${Object.entries(AI_MODELS).filter(([k]) => s.models.includes(k)).map(([k, [name, what, method]]) => `
          <tr title="${escapeHtml(method)}"><td><strong>${escapeHtml(name)}</strong><div class="small text-muted-ng">${escapeHtml(what)}</div></td><td class="text-end align-middle">${grade(s.metrics[k])}</td></tr>`).join("")}</tbody></table></div></div>
      <div class="col-xl-5"><div class="ng-card h-100"><div class="ng-card-header"><h3>Learning</h3></div><div class="ng-card-body">
        <form id="ai-learning-form" class="d-grid gap-3" novalidate>
          <div class="form-check form-switch"><input class="form-check-input" type="checkbox" role="switch" id="ai-auto" ${s.learning?.auto ? "checked" : ""} ${isAdmin ? "" : "disabled"}><label class="form-check-label" for="ai-auto">Learn automatically</label></div>
          <div class="d-flex align-items-center gap-2 small">after <input class="form-control form-control-sm" style="width:80px" id="ai-after" type="number" min="1" max="500" value="${s.learning?.after ?? 10}" ${isAdmin ? "" : "disabled"}> new applied fixes</div>
          <div class="small text-muted-ng"><strong>${s.new_outcomes ?? 0}</strong> new since release ${s.release ?? 1} · ${mine} in total. A new release is used only if it scores at least as well as the current one.</div>
          ${isAdmin ? '<div><button class="btn btn-sm btn-primary" type="submit">Save</button> <span class="small text-muted-ng" id="ai-learning-status"></span></div>' : ""}
        </form></div></div></div>
    </div>

    <div class="ng-card mt-3"><div class="ng-card-header"><h3>Versions</h3><span class="small text-muted-ng">Every training is kept. Restore any version.</span></div>
      <div class="table-responsive"><table class="table ng-table mb-0" id="ai-versions"><thead><tr><th>Release</th><th>Trained</th><th>How</th><th>Your fixes</th><th>Change risk</th><th>Status</th><th></th></tr></thead><tbody>
      ${(s.releases || []).map((r) => {
        const [label, cls] = STATUS[r.status] || STATUS.previous;
        const risk = r.quality?.change_risk;
        return `<tr data-release="${r.release}"><td class="fw-semibold">${r.release}</td><td class="small">${escapeHtml(formatDate(r.trained_at))}</td><td class="small">${escapeHtml(TRIGGER[r.trigger] || r.trigger)}</td>
          <td class="small">${r.local_outcomes ?? 0}</td><td class="small">${risk != null ? `${Math.round(risk * 1000) / 10}%` : "—"}</td>
          <td><span class="badge ${cls}" title="${escapeHtml(r.note || "")}">${label}</span></td>
          <td class="actions">${isAdmin && r.status !== "active" ? `<button class="btn btn-sm btn-light border" data-ai-restore="${r.release}">Restore</button>` : ""}</td></tr>`;
      }).join("")}</tbody></table></div></div>`;
  if (!isAdmin) return;
  $("btn-retrain").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
    if (!await confirmDialog({ title: "Retrain NetGuard AI?", message: "Takes about a minute. The new release is used only if it scores at least as well as the current one; otherwise it is kept as \"Not used\".", confirmLabel: "Retrain" })) return;
    try {
      const result = await api.post("/ai/retrain", { include_local: true });
      const r = result.release;
      toast(r.status === "active" ? `Release ${r.release} is now in use.` : `Release ${r.release} scored lower, so release ${result.status.release} stays in use.`, r.status === "active" ? "success" : "info", 6000);
      await loadAi(true);
    } catch (error) { toast(error.message, "error"); }
  }));
  $("ai-learning-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api.put("/ai/learning", { auto: $("ai-auto").checked, after: Number($("ai-after").value) });
      $("ai-learning-status").textContent = "Saved.";
    } catch (error) { $("ai-learning-status").textContent = error.message; }
  });
  el.querySelectorAll("[data-ai-restore]").forEach((button) => button.addEventListener("click", () => withBusy(button, async () => {
    const release = button.dataset.aiRestore;
    if (!await confirmDialog({ title: `Restore release ${release}?`, message: "NetGuard AI switches back to this version straight away. You can switch again at any time.", confirmLabel: "Restore" })) return;
    try { await api.post(`/ai/releases/${release}/restore`, {}); toast(`Release ${release} is now in use.`, "success"); await loadAi(true); }
    catch (error) { toast(error.message, "error"); }
  })));
}

async function main() {
  state.user = await initShell({ active: "settings", title: "Settings", subtitle: "Account, users, logins, AI and safety" });
  bindProfile(); bindAccounts(); bindCredentials(); renderProfile(); renderSession();
  const tab = { password: "profile", sessions: "profile" }[location.hash.slice(1)] || location.hash.slice(1);  // /settings#credentials
  if (tab && document.getElementById(`${tab}-tab`)) bootstrap.Tab.getOrCreateInstance(document.getElementById(`${tab}-tab`)).show();
  try {
    const [settings, catalogue] = await Promise.all([api.get("/account/settings"), api.get("/permissions")]);
    state.catalogue = catalogue; state.user = settings.profile; renderProfile();
    const security = settings.security;
    loadSelfHealing(settings.is_admin);
    const chip = (icon, text) => `<span class="ng-chip"><i class="bi ${icon} me-1"></i>${text}</span>`;
    $("security-info").innerHTML = [
      chip("bi-lock", `Device logins encrypted (${escapeHtml(security.vault || "AES")}, ${escapeHtml(security.key_protection || "key file")})`),
      security.login_throttling ? chip("bi-shield-lock", "Sign-in lockout after repeated failures") : "",
      chip("bi-clock", `Sessions last ${Math.round(security.token_expire_minutes / 60 * 10) / 10} hours`),
      chip("bi-display", security.web_access ? "Browser access on 127.0.0.1" : "Desktop window only"),
    ].join("");
    if (settings.is_admin) { $("accounts-nav").classList.remove("d-none"); await loadAccounts(); }
    await loadProfiles();
    await loadAi(settings.is_admin);
    let requested = new URLSearchParams(location.search).get("tab");
    if (requested === "password" || requested === "sessions") requested = "profile";  // now part of My Account
    if (["profile", "credentials", "ai", "security"].includes(requested) || requested === "accounts" && settings.is_admin) bootstrap.Tab.getOrCreateInstance($(`${requested}-tab`)).show();
  } catch (error) { toast(error.message, "error"); }
}

main();


async function loadSelfHealing(isAdmin) {
  const form = document.getElementById("self-healing-form");
  if (!form) return;
  let policy;
  try { policy = await api.get("/settings/self-healing"); } catch { return; }
  const fields = { device_timer: "sh-timer", reachability_check: "sh-reach" };
  for (const [key, id] of Object.entries(fields)) document.getElementById(id).checked = !!policy[key];
  document.getElementById("sh-minutes").value = policy.confirm_minutes;
  document.getElementById("sh-level").value = policy.max_hybrid_level;
  form.querySelectorAll("input, select, button").forEach((el) => { el.disabled = !isAdmin; });
  if (!isAdmin) document.getElementById("sh-status").textContent = "Only an administrator can change these.";
  if (form.dataset.bound) return;
  form.dataset.bound = "1";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api.put("/settings/self-healing", {
        device_timer: document.getElementById("sh-timer").checked, reachability_check: document.getElementById("sh-reach").checked,
        confirm_minutes: Number(document.getElementById("sh-minutes").value), max_hybrid_level: document.getElementById("sh-level").value });
      document.getElementById("sh-status").textContent = "Saved.";
    } catch (exc) { document.getElementById("sh-status").textContent = exc.message; }
  });
}
