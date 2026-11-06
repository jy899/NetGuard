import { api, session } from "../api.js";
import { initShell } from "../layout.js";
import { confirmDialog, escapeHtml, fillForm, formatDate, readForm, showFormError, toast, withBusy } from "../ui.js";

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
  $("session-info").innerHTML = `<dt>Account</dt><dd>${escapeHtml(state.user.username)}</dd><dt>Session</dt><dd>This browser</dd><dt>Expires</dt><dd>${expiry}</dd>`;
}


async function loadAccounts() {
  [state.accounts, state.groups] = await Promise.all([api.get("/accounts"), api.get("/groups")]);
  $("account-list").innerHTML = `<div class="table-responsive"><table class="table ng-table"><thead><tr><th>Username</th><th>User group</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>${state.accounts.map((user) => {
    const protectedAccount = user.id === state.user.id || user.username === "admin";
    return `<tr data-account="${user.id}"><td class="fw-semibold">${escapeHtml(user.username)}</td><td>${escapeHtml(user.role)}</td><td><span class="ng-badge-plain ${user.is_active ? "text-success" : "text-muted-ng"}">${user.is_active ? "Active" : "Disabled"}</span></td><td class="small text-muted-ng">${formatDate(user.created_at)}</td><td class="actions"><button class="btn btn-sm btn-outline-primary" data-account-action="edit">Edit</button>${protectedAccount ? '<span class="small text-muted-ng ms-2">Protected account</span>' : `<button class="btn btn-sm btn-light border" data-account-action="toggle">${user.is_active ? "Disable" : "Enable"}</button><button class="btn btn-sm btn-outline-danger" data-account-action="delete">Delete</button>`}</td></tr>`;
  }).join("")}</tbody></table></div>`;
  const labels = Object.fromEntries(state.catalogue.map((p) => [p.id, p.label]));
  $("group-list").innerHTML = `<div class="table-responsive"><table class="table ng-table"><thead><tr><th>Group</th><th>Permissions</th><th>Members</th><th></th></tr></thead><tbody>${state.groups.map((group) => `<tr data-group="${group.id}"><td><div class="fw-semibold">${escapeHtml(group.name)}${group.builtin ? ' <span class="ng-badge-plain small">Built-in</span>' : ""}</div><div class="small text-muted-ng">${escapeHtml(group.description || "")}</div></td><td class="small">${group.permissions.map((p) => `<span class="ng-type-badge me-1 mb-1 d-inline-block" title="${escapeHtml(labels[p] || p)}">${escapeHtml(p)}</span>`).join("") || '<span class="text-muted-ng">No permissions</span>'}</td><td>${group.members}</td><td class="actions"><button class="btn btn-sm btn-outline-primary" data-group-action="edit">Edit</button>${group.builtin ? "" : '<button class="btn btn-sm btn-outline-danger" data-group-action="delete">Delete</button>'}</td></tr>`).join("")}</tbody></table></div>`;
}

function openAccount(user = null) {
  state.accountId = user?.id ?? null;
  const form = $("account-form"); form.reset(); showFormError(form, "");
  $("account-group").innerHTML = state.groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  $("account-group").value = String(user?.group_id ?? state.groups.find((g) => g.name === "Network Engineers")?.id ?? state.groups[0]?.id);
  $("account-username").value = user?.username || "";
  $("account-modal-title").textContent = user ? "Edit User" : "Add User";
  $("account-username").disabled = !!user;
  $("account-password-wrap").classList.toggle("d-none", !!user);
  $("account-password").value = "";
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
  $("credential-list").innerHTML = state.profiles.length ? `<div class="table-responsive"><table class="table ng-table"><thead><tr><th>Profile</th><th>Method</th><th>Device Username</th><th>Port</th><th>Priority</th><th>Assigned Devices</th><th></th></tr></thead><tbody>${state.profiles.map((profile) => `<tr data-profile="${profile.id}"><td><div class="fw-semibold">${escapeHtml(profile.name)}</div><div class="small text-muted-ng">${escapeHtml(profile.notes || "")}</div></td><td>${escapeHtml({ ssh: "SSH", snmpv3: "SNMPv3", snmpv2c: "SNMPv2c (read-only)" }[profile.method || "ssh"])}</td><td>${escapeHtml(profile.username)}<div class="small text-muted-ng">${profile.has_password ? "Encrypted secret saved" : "No secret saved"}</div></td><td>${profile.port}</td><td>${profile.priority}</td><td>${profile.used_by ?? 0}</td><td class="actions"><button class="btn btn-sm btn-outline-primary" data-profile-action="edit">Edit</button><button class="btn btn-sm btn-outline-danger" data-profile-action="delete">Delete</button></td></tr>`).join("")}</tbody></table></div>` : '<div class="ng-card-body small text-muted-ng">No credential profiles. Add a profile to reuse it across selected network devices.</div>';
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
  $("credential-modal-title").textContent = profile ? "Edit Credential Profile" : "Add Credential Profile";
  bootstrap.Modal.getOrCreateInstance($("credential-modal")).show();
}

function bindProfile() {
  $("password-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const form = event.currentTarget; showFormError(form, ""); const data = readForm(form);
    data.current_password = $("pw-current").value; data.new_password = $("pw-new").value; data.confirm = $("pw-confirm").value;
    if (!data.current_password || !data.new_password) return showFormError(form, "Fill in all password fields.");
    if (data.new_password.length < 8) return showFormError(form, "The new password must be at least 8 characters.");
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
    if (!state.accountId && (!username || password.length < 8)) return showFormError(form, "Enter a username and an initial password of at least 8 characters.");
    await withBusy($("account-submit"), async () => {
      try {
        if (state.accountId) await api.put(`/accounts/${state.accountId}`, { group_id: groupId });
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
      try { if (state.profileId) await api.put(`/credential-profiles/${state.profileId}`, body); else await api.post("/credential-profiles", body); $("credential-password").value = ""; bootstrap.Modal.getInstance($("credential-modal")).hide(); await loadProfiles(); toast("Credential profile saved", "success"); }
      catch (error) { showFormError(form, error.message); }
    });
  });
  $("credential-list").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-profile-action]"); if (!button) return;
    const profile = state.profiles.find((item) => item.id === Number(button.closest("[data-profile]").dataset.profile));
    if (button.dataset.profileAction === "edit") return openCredential(profile);
    if (!await confirmDialog({ title: "Delete credential profile?", message: `<p>Delete <strong>${escapeHtml(profile.name)}</strong>?</p><p class="mb-0 small text-muted-ng">Devices using this profile will need another credential assignment.</p>`, confirmLabel: "Delete Profile", danger: true })) return;
    try { await api.del(`/credential-profiles/${profile.id}`); await loadProfiles(); toast("Credential profile deleted", "success"); }
    catch (error) { toast(error.message, "error"); }
  });

  ["account-modal", "credential-modal"].forEach((id) => $(id).addEventListener("hidden.bs.modal", () => $(id).querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; })));
}

const AI_MODELS = {
  change_risk: ["Change risk predictor", "Gradient-boosted trees: probability that a change breaks a flow or adds a high-severity finding"],
  blast_endpoints: ["Blast radius (endpoints)", "Gradient-boosted regression: endpoints a change affects"],
  blast_flows: ["Blast radius (flows)", "Gradient-boosted regression: flows a change breaks"],
  root_cause: ["Root-cause analyzer", "Gradient-boosted trees: probability that a finding causes the failing flows"],
  fix_ranker: ["Remediation ranker", "Gradient-boosted trees: probability that a fix is a true root-cause repair"],
  link_faults: ["Cross-device link classifier", "Naive Bayes over both ends of each cable: 11 misconfiguration classes"],
  syslog: ["Syslog classifier", "Naive Bayes over Cisco IOS syslog messages: 10 fault categories"],
};

function metricText(name, m) {
  if (!m) return "";
  if (m.auc != null) return `AUC ${m.auc} · Brier ${m.brier} (base rate ${m.brier_base_rate}) · ${m.test_rows} held-out rows${m.top1_accuracy != null ? ` · top-1 ${Math.round(m.top1_accuracy * 100)}%` : ""}`;
  if (m.mae != null) return `MAE ${m.mae} (mean baseline ${m.mae_mean_baseline}) · Spearman ${m.spearman} · ${m.test_rows} held-out rows`;
  if (m.macro_f1 != null) return `Accuracy ${m.accuracy} · macro-F1 ${m.macro_f1} (majority baseline ${m.majority_baseline_accuracy}) · ${m.test_rows} held-out rows`;
  return "";
}

async function loadAi(isAdmin) {
  try {
    const s = await api.get("/ai/status");
    const counts = s.dataset?.counts || {};
    $("ai-info").innerHTML = s.available ? `
      <p class="small">${escapeHtml(s.advisory)}</p>
      <dl class="ng-kv"><dt>Model version</dt><dd>${s.model_version} · trained ${escapeHtml(formatDate(s.trained_at))}</dd>
        <dt>Training data</dt><dd>${Object.entries(counts).map(([k, v]) => `${escapeHtml(k.replace(/_/g, " "))} ${v}`).join(" · ")}</dd>
        <dt>Local outcomes</dt><dd>${s.local_outcomes?.forecasts ?? 0} forecasts · ${s.local_outcomes?.executed ?? 0} executed laboratory changes</dd></dl>
      <table class="table table-sm ng-ai-metrics"><thead><tr><th>Model</th><th>Held-out evaluation</th></tr></thead><tbody>
        ${Object.entries(AI_MODELS).filter(([k]) => s.models.includes(k)).map(([k, [label, what]]) => `<tr><td><strong>${escapeHtml(label)}</strong><div class="small text-muted-ng">${escapeHtml(what)}</div></td><td class="small">${escapeHtml(metricText(k, s.metrics[k]))}</td></tr>`).join("")}
      </tbody></table>
      <p class="small text-muted-ng mb-0">${escapeHtml(s.evaluation || "")} ${escapeHtml(s.dataset?.provenance || "")}</p>`
      : `<p class="small mb-0">The model files are not installed (data/models). NetGuard's deterministic analysis works without them.</p>`;
    $("btn-retrain").classList.toggle("d-none", !isAdmin);
  } catch (error) { $("ai-info").textContent = error.message; }
}

async function main() {
  state.user = await initShell({ active: "settings", title: "Settings", subtitle: "Accounts, credentials and security" });
  bindProfile(); bindAccounts(); bindCredentials(); renderProfile(); renderSession();
  try {
    const [settings, catalogue] = await Promise.all([api.get("/account/settings"), api.get("/permissions")]);
    state.catalogue = catalogue; state.user = settings.profile; renderProfile();
    const security = settings.security;
    loadSelfHealing(settings.is_admin);
    $("security-info").innerHTML = `<dt>Minimum new password</dt><dd>${security.password_min_length} characters</dd><dt>Login throttling</dt><dd>${security.login_throttling ? "Enabled" : "Disabled"}</dd><dt>Device secrets</dt><dd>${escapeHtml(security.vault || "Encrypted")} · key protected by ${escapeHtml(security.key_protection || "a key file")}</dd><dt>Session duration</dt><dd>${security.token_expire_minutes} minutes</dd><dt>Browser access</dt><dd>${security.web_access ? "Enabled on 127.0.0.1" : "Desktop window only"}</dd><dt>Device changes</dt><dd>${escapeHtml(security.device_changes || "")}</dd>`;
    if (settings.is_admin) { $("accounts-nav").classList.remove("d-none"); await loadAccounts(); }
    await loadProfiles();
    await loadAi(settings.is_admin);
    $("btn-retrain").addEventListener("click", (event) => withBusy(event.currentTarget, async () => {
      if (!await confirmDialog({ title: "Retrain AI models", message: "Retrain from the bundled datasets and this installation's executed laboratory changes? This takes about a minute.", confirmLabel: "Retrain" })) return;
      try {
        const result = await api.post("/ai/retrain", { include_local: true });
        toast(`Models retrained (${result.local_outcomes} local outcome(s) included).`, "success");
        await loadAi(true);
      } catch (error) { toast(error.message, "error"); }
    }));
    const requested = new URLSearchParams(location.search).get("tab");
    if (["profile", "password", "sessions", "credentials", "ai", "security"].includes(requested) || requested === "accounts" && settings.is_admin) bootstrap.Tab.getOrCreateInstance($(`${requested}-tab`)).show();
  } catch (error) { toast(error.message, "error"); }
}

main();


async function loadSelfHealing(isAdmin) {
  const form = document.getElementById("self-healing-form");
  if (!form) return;
  let policy;
  try { policy = await api.get("/settings/self-healing"); } catch { return; }
  const fields = { enabled: "sh-enabled", device_timer: "sh-timer", reachability_check: "sh-reach" };
  for (const [key, id] of Object.entries(fields)) document.getElementById(id).checked = !!policy[key];
  document.getElementById("sh-minutes").value = policy.confirm_minutes;
  document.getElementById("sh-level").value = policy.max_hybrid_level;
  form.querySelectorAll("input, select, button").forEach((el) => { el.disabled = !isAdmin; });
  if (!isAdmin) document.getElementById("sh-status").textContent = "Only an administrator can change this policy.";
  if (form.dataset.bound) return;
  form.dataset.bound = "1";
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const saved = await api.put("/settings/self-healing", {
        enabled: document.getElementById("sh-enabled").checked, device_timer: document.getElementById("sh-timer").checked,
        reachability_check: document.getElementById("sh-reach").checked,
        confirm_minutes: Number(document.getElementById("sh-minutes").value), max_hybrid_level: document.getElementById("sh-level").value });
      document.getElementById("sh-status").textContent = saved.enabled ? "Saved: production self-healing is on." : "Saved: production self-healing is off.";
    } catch (exc) { document.getElementById("sh-status").textContent = exc.message; }
  });
}
