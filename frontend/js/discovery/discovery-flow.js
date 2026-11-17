// Credential-free discovery with optional authentication: progress timeline, credential request dialog,
// one consolidated confirmation, grouped authentication and the discovery report.
// Secrets typed here are sent once to the authenticate endpoint and cleared; nothing is written to browser storage.
import { api } from "../api.js";
import { escapeHtml, toast } from "../ui.js";

export const METHOD_LABELS = { ssh: "SSH (read-only)", "https-api": "HTTPS / API", snmpv3: "SNMPv3 (authPriv)", snmpv2c: "SNMPv2c (read-only community)" };
export const CATEGORY_CLASS = {
  full: "text-bg-success", partial: "text-bg-secondary", auth_required: "text-bg-warning",
  auth_failed: "text-bg-danger", unverified: "text-bg-light border", unreachable: "text-bg-dark",
};
const AUTH_LABELS = { not_offered: "Not offered", not_needed: "Not needed", required: "Would add detail", success: "Authenticated", failed: "Failed" };

export function isSmartDiscovery(network) {
  return network?.source === "discovery" && network?.metadata_json?.method === "smart";
}

function badge(primary, labels) {
  return `<span class="badge ${CATEGORY_CLASS[primary] || "text-bg-light"}" data-category="${escapeHtml(primary)}">${escapeHtml(labels?.[primary] || primary)}</span>`;
}

function mount(html) {
  const wrapper = document.createElement("div");
  wrapper.innerHTML = html.trim();
  const element = wrapper.firstElementChild;
  document.body.appendChild(element);
  return element;
}

function credentialFields(prefix, method) {
  return `<div class="row g-2">
    ${method === "ssh" ? `<div class="col-md-3"><label class="form-label small" for="${prefix}-port">SSH port</label>
      <input id="${prefix}-port" type="number" min="1" max="65535" class="form-control" placeholder="22" inputmode="numeric"></div>` : ""}
    <div class="${method === "ssh" ? "col-md-4" : "col-md-6"}${method === "snmpv2c" ? " d-none" : ""}"><label class="form-label small" for="${prefix}-user">${method === "snmpv3" ? "SNMPv3 user" : "Username"}</label>
      <input id="${prefix}-user" class="form-control" maxlength="64" autocomplete="off"${method === "snmpv2c" ? ' value="community"' : ""}></div>
    <div class="${method === "ssh" ? "col-md-5" : "col-md-6"}"><label class="form-label small" for="${prefix}-password">${method === "snmpv3" ? "Authentication passphrase" : method === "snmpv2c" ? "Read-only community string" : "Password"}</label>
      <input id="${prefix}-password" type="password" class="form-control" maxlength="128" autocomplete="new-password"></div>
    ${method === "snmpv3" ? `<div class="col-md-6"><label class="form-label small" for="${prefix}-priv">Privacy passphrase</label>
      <input id="${prefix}-priv" type="password" class="form-control" maxlength="128" autocomplete="new-password"></div>
      <div class="col-md-3"><label class="form-label small" for="${prefix}-auth-protocol">Authentication</label>
      <select id="${prefix}-auth-protocol" class="form-select"><option>SHA-256</option><option>SHA-512</option></select></div>
      <div class="col-md-3"><label class="form-label small" for="${prefix}-priv-protocol">Privacy</label>
      <select id="${prefix}-priv-protocol" class="form-select"><option>AES-128</option><option>AES-256</option></select></div>` : ""}
  </div>`;
}

async function profilesFor(method) {
  try {
    return (await api.get("/credential-profiles")).filter((p) => (p.method || "ssh") === method);
  } catch { return []; }
}

/** Ordered queue of saved profiles to try when the entered credentials fail (each once per device, first success wins). */
async function fallbackQueue(prefix, methods) {
  let profiles = [];
  try { profiles = (await api.get("/credential-profiles")).filter((p) => methods.includes(p.method || "ssh")); } catch { /* optional */ }
  if (!profiles.length) return "";
  return `<details class="small mt-2" data-fallback="${prefix}"><summary>Fallback: try saved profiles in order if these credentials fail (${profiles.length})</summary>
    <ol class="list-unstyled mb-1 mt-1" data-fallback-list="${prefix}">${profiles.map((p) => `<li class="d-flex align-items-center gap-2 py-1" data-fallback-id="${p.id}">
      <input class="form-check-input mt-0" type="checkbox" id="${prefix}-fb-${p.id}" data-fallback-pick checked>
      <label class="flex-grow-1" for="${prefix}-fb-${p.id}">${escapeHtml(p.name)} · ${escapeHtml(p.username)} · ${escapeHtml(METHOD_LABELS[p.method || "ssh"])}</label>
      <button type="button" class="btn btn-sm btn-light border py-0" data-fallback-up aria-label="Move ${escapeHtml(p.name)} up"><i class="bi bi-arrow-up"></i></button></li>`).join("")}</ol>
    <div class="text-muted-ng">Each profile is tried once per device, in this order; the first one accepted is used. Leave the credential fields empty to try only these.</div></details>`;
}

function fallbackIds(root, prefix) {
  return [...root.querySelectorAll(`[data-fallback-list="${prefix}"] [data-fallback-id]`)]
    .filter((li) => li.querySelector("[data-fallback-pick]").checked).map((li) => Number(li.dataset.fallbackId));
}

function bindFallbackOrder(root) {
  root.addEventListener("click", (event) => {
    const up = event.target.closest("[data-fallback-up]");
    if (!up) return;
    const item = up.closest("li");
    if (item.previousElementSibling) item.parentElement.insertBefore(item, item.previousElementSibling);
  });
}

function methodNote(request, method) {
  const note = request.method_notes?.[method];
  return note ? `<div class="small ${(request.detected || []).includes(method) ? "text-success" : "text-muted-ng"}">${escapeHtml(note)}</div>` : "";
}

// ------------------------------------------------------------ progress timeline
export function renderTimeline(container, timeline, { delay = 260 } = {}) {
  container.innerHTML = `<ol class="ng-scan-timeline list-unstyled mb-0">${timeline.map((stage) => `<li data-stage="${escapeHtml(stage.id)}" class="pending">
      <i class="bi bi-circle me-2" aria-hidden="true"></i><strong>${escapeHtml(stage.label)}</strong>
      <span class="small text-muted-ng ms-1">${escapeHtml(stage.detail)}</span></li>`).join("")}</ol>`;
  const items = [...container.querySelectorAll("li")];
  let index = 0;
  return {
    get done() { return index >= items.length; },
    progress: () => `${Math.min(index, items.length)}/${items.length}`,
    run: (onStage) => new Promise((resolve) => {
      const step = () => {
        if (index >= items.length) { resolve(); return; }
        const item = items[index];
        item.classList.replace("pending", "done");
        item.querySelector("i").className = "bi bi-check-circle-fill text-success me-2";
        index += 1;
        onStage?.(timeline[index - 1], index);
        setTimeout(step, delay);
      };
      step();
    }),
  };
}

// ------------------------------------------------------------ credential request dialog
function createCredentialDialog() {
  const element = mount(`<div class="modal" id="credential-request-modal" tabindex="-1" aria-labelledby="cr-title" aria-hidden="true" data-bs-backdrop="static" data-bs-keyboard="false">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><div><h5 class="modal-title" id="cr-title">Authentication can improve discovery</h5>
        <div class="small text-muted-ng">Optional · credentials are never guessed · saved profiles are tried once each · use a read-only account</div></div>
        <button type="button" class="btn-close" id="cr-close" aria-label="Skip for now"></button></div>
      <div class="modal-body">
        <div id="cr-device" class="d-flex flex-wrap gap-2 align-items-center mb-2"></div>
        <p class="small mb-2" id="cr-reason"></p>
        <h6 class="small fw-semibold mb-1">What becomes available after authentication</h6><ul class="small mb-2" id="cr-gains"></ul>
        <div class="small text-muted-ng mb-3" id="cr-progress" role="status" aria-live="polite"></div>
        <form id="cr-form" novalidate>
          <div class="alert alert-danger small py-2 d-none" id="cr-error" role="alert"></div>
          <fieldset class="mb-2"><legend class="form-label small fw-semibold mb-1">Authentication method</legend><div id="cr-methods" class="d-flex flex-wrap gap-3"></div></fieldset>
          <details class="small mb-2"><summary>Not offered for this device</summary><ul class="mb-0" id="cr-not-offered"></ul></details>
          <div class="row g-2 mb-2"><div class="col-md-6"><label class="form-label small" for="cr-profile">Saved credential profile</label>
            <select id="cr-profile" class="form-select"><option value="">Enter credentials</option></select></div>
            </div>
          <div id="cr-method-note" class="mb-2"></div>
          <div id="cr-fields"></div>
          <div id="cr-fallback"></div>
          <fieldset class="mt-3" id="cr-reuse-box"><legend class="form-label small fw-semibold mb-1">Use the same credentials for</legend><div id="cr-reuse" class="d-flex flex-column gap-1"></div></fieldset>
          <div class="form-check mt-3"><input class="form-check-input" type="checkbox" id="cr-remember">
            <label class="form-check-label small" for="cr-remember">Remember securely (encrypted on this NetGuard server as a credential profile)</label></div>
          <div class="mt-2 d-none" id="cr-profile-name-box"><label class="form-label small" for="cr-profile-name">Profile name (optional)</label>
            <input id="cr-profile-name" class="form-control" maxlength="60" autocomplete="off"></div>
          <p class="small text-muted-ng mt-2 mb-0">Without "Remember securely", credentials are used for this authentication only and then discarded. Passwords are never shown again, logged, exported or kept in the browser.</p>
        </form>
      </div>
      <div class="modal-footer" id="cr-footer">
        <button type="button" class="btn btn-outline-secondary me-auto" id="cr-skip-all">Skip All Credential Requests</button>
        <button type="button" class="btn btn-light border" id="cr-skip">Skip for Now</button>
        <button type="submit" form="cr-form" class="btn btn-primary" id="cr-submit"><i class="bi bi-shield-lock me-1"></i>Enter Credentials</button>
      </div></div></div></div>`);
  const modal = bootstrap.Modal.getOrCreateInstance(element);
  const $ = (id) => element.querySelector(`#${id}`);
  let state = null;

  function method() { return element.querySelector("input[name=cr-method]:checked")?.value; }
  function clearSecrets() { element.querySelectorAll("input[type=password]").forEach((input) => { input.value = ""; }); }
  function error(message) { $("cr-error").textContent = message || ""; $("cr-error").classList.toggle("d-none", !message); }

  async function methodChanged() {
    const chosen = method();
    $("cr-fields").innerHTML = credentialFields("cr", chosen);
    $("cr-method-note").innerHTML = state ? methodNote(state.request, chosen) : "";
    $("cr-fallback").innerHTML = state ? await fallbackQueue("cr", state.request.methods) : "";
    const profiles = await profilesFor(chosen);
    $("cr-profile").innerHTML = '<option value="">Enter credentials</option>' + profiles.map((p) =>
      `<option value="${p.id}">${escapeHtml(p.name)} · ${escapeHtml(p.username)} · ${escapeHtml(METHOD_LABELS[p.method || "ssh"])}</option>`).join("");
    $("cr-remember").disabled = false;
    $("cr-reuse").querySelectorAll("[data-reuse-device]").forEach((box) => {
      const supported = (box.dataset.methods || "").split(",").includes(chosen);
      box.disabled = !supported;
      if (!supported) box.checked = false;
    });
  }

  function render() {
    const { request, labels } = state;
    $("cr-device").innerHTML = `<strong class="fs-6" data-cr="name">${escapeHtml(request.name)}</strong>
      <span class="mono small">${escapeHtml(request.ip)}</span><span class="badge text-bg-light border">${escapeHtml(request.role || request.type)}${request.model ? ` · ${escapeHtml(request.model)}` : ""}</span>
      ${badge(request.auth === "failed" ? "auth_failed" : "auth_required", labels)}`;
    $("cr-reason").textContent = request.reason;
    $("cr-gains").innerHTML = request.gains.map((g) => `<li>${escapeHtml(g.text)}</li>`).join("");
    $("cr-methods").innerHTML = request.methods.map((m, i) => `<div class="form-check"><input class="form-check-input" type="radio" name="cr-method" id="cr-method-${m}" value="${m}" ${i === 0 ? "checked" : ""}><label class="form-check-label" for="cr-method-${m}">${escapeHtml(METHOD_LABELS[m])}${request.detected && !request.detected.includes(m) ? ' <span class="small text-muted-ng">(not seen in the scan)</span>' : ""}</label></div>`).join("");
    $("cr-not-offered").innerHTML = request.not_offered.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    $("cr-reuse").innerHTML = request.reuse_candidates.length ? request.reuse_candidates.map((c) => `<div class="form-check"><input class="form-check-input" type="checkbox" id="cr-reuse-${c.device_id}" data-reuse-device="${c.device_id}" data-methods="${c.methods.join(",")}" ${c.preselected ? "checked" : ""}>
        <label class="form-check-label small" for="cr-reuse-${c.device_id}">${escapeHtml(c.name)} <span class="mono text-muted-ng">${escapeHtml(c.ip)}</span></label></div>`).join("") : '<div class="small text-muted-ng">No other pending device supports these methods.</div>';
    $("cr-reuse-box").classList.toggle("d-none", !request.reuse_candidates.length);
    $("cr-remember").checked = false;
    $("cr-remember").disabled = false;
    $("cr-profile-name-box").classList.add("d-none");
    $("cr-profile-name").value = "";
    const manual = state.mode === "manual";
    $("cr-skip-all").classList.toggle("d-none", manual);
    $("cr-skip").textContent = manual ? "Cancel" : "Skip for Now";
    $("cr-submit").innerHTML = `<i class="bi bi-shield-lock me-1"></i>${manual ? "Authenticate" : "Enter Credentials"}`;
    error(request.last_error || "");
    methodChanged();
  }

  async function finish(answer) {
    clearSecrets();
    state.resolve(answer);
    state = null;
    await new Promise((resolve) => { element.addEventListener("hidden.bs.modal", resolve, { once: true }); modal.hide(); });
  }

  async function skip(all) {
    if (!state || state.busy) return;  // never dismiss while an authentication request is pending
    if (state.mode === "manual") { await finish({ action: "cancel", result: state.attempted ? state.result : null, attempted: !!state.attempted }); return; }
    const result = await api.post(`/discovery/${state.networkId}/skip`, all ? { all: true, device_ids: [] } : { device_ids: [state.request.device_id] });
    await finish({ action: all ? "skip-all" : "skip", result });
  }

  $("cr-close").addEventListener("click", () => skip(false));
  $("cr-skip").addEventListener("click", () => skip(false));
  $("cr-skip-all").addEventListener("click", () => skip(true));
  $("cr-methods").addEventListener("change", methodChanged);
  bindFallbackOrder(element);
  $("cr-remember").addEventListener("change", () => $("cr-profile-name-box").classList.toggle("d-none", !$("cr-remember").checked));
  $("cr-profile").addEventListener("change", () => {
    const usingProfile = !!$("cr-profile").value;
    element.querySelectorAll("#cr-fields input").forEach((input) => { input.disabled = usingProfile; if (usingProfile) input.value = ""; });
    $("cr-remember").disabled = usingProfile;
  });
  $("cr-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state || state.busy) return;
    const current = state;
    const chosen = method();
    const ids = [state.request.device_id, ...[...element.querySelectorAll("[data-reuse-device]:checked")].map((box) => Number(box.dataset.reuseDevice))];
    const body = { device_ids: ids, method: chosen, profile_id: Number($("cr-profile").value) || null,
      username: $("cr-user")?.value.trim() || "", password: $("cr-password")?.value || "", priv_password: $("cr-priv")?.value || "",
      ...($("cr-auth-protocol") ? { snmp_auth_protocol: $("cr-auth-protocol").value, snmp_priv_protocol: $("cr-priv-protocol").value } : {}),
      remember: $("cr-remember").checked, profile_name: $("cr-profile-name").value.trim() || null,
      ssh_port: Number($("cr-port")?.value) || null, fallback_profile_ids: fallbackIds(element, "cr") };
    clearSecrets();
    if (chosen === "snmpv2c") body.username = body.username || "community";
    if (!body.profile_id && (!body.username || !body.password) && !body.fallback_profile_ids.length) { error("Enter credentials, choose a saved profile, tick saved profiles to try in order, or skip this device."); return; }
    const locked = ["cr-submit", "cr-skip", "cr-skip-all", "cr-close"].map((id) => $(id));
    current.busy = true;
    locked.forEach((button) => { button.disabled = true; });
    try {
      const response = await api.post(`/discovery/${current.networkId}/authenticate`, body);
      const primary = response.outcomes.find((o) => o.device_id === current.request.device_id);
      const failed = response.outcomes.filter((o) => !o.ok);
      current.result = response.result;
      current.attempted = true;
      if (!primary?.ok) {
        error(`${primary?.detail || "Authentication failed."} Check the credentials (and the SSH port), choose another method, or skip.`);
        return;
      }
      if (response.profile_note) toast(response.profile_note, "warning");
      toast(`${response.outcomes.length - failed.length} device(s) authenticated${failed.length ? ` · ${failed.length} failed: ${failed.map((o) => o.name).join(", ")}` : ""}${response.profile ? ` · saved as profile "${response.profile.name}"` : ""}.`, failed.length ? "warning" : "success");
      current.busy = false;
      await finish({ action: "authenticated", result: response.result });
    } catch (err) { error(err.message); }
    finally {
      current.busy = false;
      locked.forEach((button) => { button.disabled = false; });
    }
  });

  return {
    ask(networkId, request, result, { mode = "request", progress = null } = {}) {
      return new Promise((resolve) => {
        state = { networkId, request, labels: result.report?.labels, resolve, mode, result };
        render();
        $("cr-progress").textContent = progress ? progress() : "";
        if (progress) {
          const timer = setInterval(() => {
            if (!state) { clearInterval(timer); return; }
            $("cr-progress").textContent = progress();
          }, 300);
        }
        modal.show();
      });
    },
  };
}

// ------------------------------------------------------------ consolidated confirmation
function createConfirmationDialog() {
  const element = mount(`<div class="modal" id="discovery-confirm-modal" tabindex="-1" aria-labelledby="dc-title" aria-hidden="true" data-bs-backdrop="static" data-bs-keyboard="false">
    <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><h5 class="modal-title" id="dc-title">Continue with the available results?</h5></div>
      <div class="modal-body">
        <p class="small">Some network devices require authentication to complete their analysis. NetGuard has discovered all available information without credentials, but certain device connections, interfaces, or routing details could not be verified.</p>
        <p class="small mb-2">Would you like to provide credentials for further analysis, or continue with the available results?</p>
        <div id="dc-devices" class="d-flex flex-column gap-2"></div>
      </div>
      <div class="modal-footer"><button type="button" class="btn btn-light border" id="dc-continue">Continue Without Credentials</button>
        <button type="button" class="btn btn-primary" id="dc-auth">Authenticate Selected Devices</button></div>
    </div></div></div>`);
  const modal = bootstrap.Modal.getOrCreateInstance(element);
  let resolver = null;
  async function done(answer) {
    const resolve = resolver; resolver = null;
    await new Promise((r) => { element.addEventListener("hidden.bs.modal", r, { once: true }); modal.hide(); });
    resolve(answer);
  }
  element.querySelector("#dc-continue").addEventListener("click", () => done({ action: "continue" }));
  element.querySelector("#dc-auth").addEventListener("click", () => {
    const ids = [...element.querySelectorAll("[data-confirm-device]:checked")].map((box) => Number(box.dataset.confirmDevice));
    if (!ids.length) { toast("Select at least one device, or continue without credentials.", "warning"); return; }
    done({ action: "authenticate", device_ids: ids });
  });
  return {
    ask(candidates) {
      element.querySelector("#dc-devices").innerHTML = candidates.map((c) => `<div class="border rounded p-2"><div class="form-check">
          <input class="form-check-input" type="checkbox" id="dc-${c.device_id}" data-confirm-device="${c.device_id}" checked>
          <label class="form-check-label" for="dc-${c.device_id}"><strong>${escapeHtml(c.name)}</strong> <span class="mono small text-muted-ng">${escapeHtml(c.ip)}</span>${c.auth === "failed" ? ' <span class="badge text-bg-danger">Authentication failed</span>' : ' <span class="badge text-bg-warning">Skipped</span>'}</label></div>
          <ul class="small mb-0 mt-1">${c.gains.filter((g) => g.important).map((g) => `<li>${escapeHtml(g.text)}</li>`).join("")}</ul></div>`).join("");
      return new Promise((resolve) => { resolver = resolve; modal.show(); });
    },
  };
}

// ------------------------------------------------------------ grouped authentication (confirmation / Device Access)
function createGroupDialog() {
  const element = mount(`<div class="modal" id="discovery-auth-modal" tabindex="-1" aria-labelledby="da-title" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable"><div class="modal-content">
      <div class="modal-header"><div><h5 class="modal-title" id="da-title">Authenticate devices</h5><div class="small text-muted-ng">Optional · each credential is tried once · read-only collection</div></div>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
      <div class="modal-body">
        <div class="alert alert-danger small py-2 d-none" id="da-error" role="alert"></div>
        <div id="da-devices" class="mb-3"></div>
        <div id="da-groups"></div>
        <div id="da-results" class="mt-3" aria-live="polite"></div>
        <div id="da-profiles" class="mt-3"></div>
      </div>
      <div class="modal-footer"><button type="button" class="btn btn-light border" data-bs-dismiss="modal" id="da-close">Close</button>
        <button type="button" class="btn btn-primary" id="da-submit"><i class="bi bi-shield-lock me-1"></i>Authenticate</button></div>
    </div></div></div>`);
  const modal = bootstrap.Modal.getOrCreateInstance(element);
  const $ = (id) => element.querySelector(`#${id}`);
  let state = null;

  function groups() {
    const chosen = new Map();
    element.querySelectorAll("[data-da-method]").forEach((select) => {
      if (!element.querySelector(`[data-da-include="${select.dataset.daMethod}"]`)?.checked) return;
      const list = chosen.get(select.value) || [];
      list.push(Number(select.dataset.daMethod));
      chosen.set(select.value, list);
    });
    return chosen;
  }

  async function renderGroups() {
    if (!state) return;
    const current = groups();
    const sections = [];
    for (const [method, ids] of current) {
      const members = ids.map((id) => state.devices.find((d) => d.device_id === id));
      const split = state.split.has(method) && ids.length > 1;
      const profiles = await profilesFor(method);
      const unseen = members.filter((d) => d.method_notes?.[method] && !(d.detected || []).includes(method));
      const sameNote = unseen.length > 1 && unseen.every((d) => d.method_notes[method] === unseen[0].method_notes[method]);
      const notes = sameNote
        ? `<li><strong>${escapeHtml(unseen.map((d) => d.name).join(", "))}</strong>: ${escapeHtml(unseen[0].method_notes[method])}</li>`
        : unseen.map((d) => `<li><strong>${escapeHtml(d.name)}</strong>: ${escapeHtml(d.method_notes[method])}</li>`).join("");
      const perDevice = members.map((d) => `<div class="border-top pt-2 mt-2"><div class="small fw-semibold mb-1">${escapeHtml(d.name)} <span class="mono text-muted-ng">${escapeHtml(d.ip)}</span></div>
          ${credentialFields(`da-${method}-d${d.device_id}`, method)}</div>`).join("");
      sections.push(`<section class="border rounded p-3 mb-2" data-da-group="${method}"><div class="d-flex justify-content-between flex-wrap gap-2 mb-2">
          <strong>${escapeHtml(METHOD_LABELS[method])}</strong><span class="small text-muted-ng">${escapeHtml(members.map((d) => d.name).join(", "))}</span></div>
        ${notes ? `<ul class="small text-muted-ng mb-2 ps-3">${notes}</ul>` : ""}
        ${ids.length > 1 ? `<div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" role="switch" id="da-${method}-split" data-da-split="${method}" ${split ? "checked" : ""}>
          <label class="form-check-label small" for="da-${method}-split">Different credentials for each device</label></div>` : ""}
        ${split ? perDevice : `<div class="row g-2 mb-2"><div class="col-md-6"><label class="form-label small" for="da-${method}-profile">Saved credential profile</label>
          <select id="da-${method}-profile" class="form-select"><option value="">Enter credentials</option>${profiles.map((p) => `<option value="${p.id}">${escapeHtml(p.name)} · ${escapeHtml(p.username)}</option>`).join("")}</select></div>
          </div>
        ${credentialFields(`da-${method}`, method)}`}
        ${await fallbackQueue(`da-${method}`, [method])}
        <div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="da-${method}-remember"><label class="form-check-label small" for="da-${method}-remember">Remember securely (encrypted credential profile)</label></div>
      </section>`);
    }
    $("da-groups").innerHTML = sections.join("") || '<p class="small text-muted-ng">Select at least one device.</p>';
  }

  async function renderProfiles() {
    if (!state?.manageProfiles) { $("da-profiles").innerHTML = ""; return; }
    const profiles = await api.get("/credential-profiles");
    $("da-profiles").innerHTML = `<h6 class="small fw-semibold">Saved credential profiles</h6>${profiles.length ? `<table class="table ng-table small"><thead><tr><th>Name</th><th>Method</th><th>Username</th><th>Secret</th><th></th></tr></thead><tbody>${profiles.map((p) => `<tr><td>${escapeHtml(p.name)}</td><td>${escapeHtml(METHOD_LABELS[p.method || "ssh"])}</td><td>${escapeHtml(p.username)}</td><td>${p.has_password ? "Saved · encrypted" : "—"}</td><td><button type="button" class="btn btn-sm btn-outline-danger" data-da-remove-profile="${p.id}">Remove</button></td></tr>`).join("")}</tbody></table>` : '<p class="small text-muted-ng mb-0">No credentials are remembered. Tick "Remember securely" when authenticating to save one.</p>'}`;
  }

  bindFallbackOrder(element);
  element.addEventListener("change", (event) => {
    if (event.target.matches("[data-da-split]")) {
      const method = event.target.dataset.daSplit;
      if (event.target.checked) state.split.add(method); else state.split.delete(method);
      renderGroups();
      return;
    }
    if (event.target.matches("[data-da-method], [data-da-include]")) renderGroups();
    if (event.target.matches("[id$='-profile']")) {
      const method = event.target.id.replace(/^da-/, "").replace(/-profile$/, "");
      element.querySelectorAll(`[data-da-group="${method}"] input[type=password], [data-da-group="${method}"] input[id$='-user']`).forEach((input) => { input.disabled = !!event.target.value; });
    }
  });
  element.addEventListener("click", async (event) => {
    const remove = event.target.closest("[data-da-remove-profile]");
    if (remove) {
      try { await api.del(`/credential-profiles/${remove.dataset.daRemoveProfile}`); toast("Saved credential profile removed. Discovery results are unchanged.", "info"); await renderProfiles(); await renderGroups(); }
      catch (err) { toast(err.message, "error"); }
    }
  });
  element.addEventListener("hide.bs.modal", (event) => {
    if (state?.busy) event.preventDefault();  // never dismiss while an authentication request is pending
  });
  element.addEventListener("hidden.bs.modal", () => {
    element.querySelectorAll("input[type=password]").forEach((input) => { input.value = ""; });
    if (state) { const { resolve, result, changed, attempted } = state; state = null; resolve({ result, changed, attempted }); }
  });
  $("da-submit").addEventListener("click", async () => {
    const current = state;
    if (!current || current.busy) return;
    $("da-error").classList.add("d-none");
    const work = [...groups()];
    if (!work.length) { $("da-error").textContent = "Select at least one device."; $("da-error").classList.remove("d-none"); return; }
    current.busy = true;
    $("da-submit").disabled = true;
    $("da-close").disabled = true;
    const lines = [];
    try {
      const read = (prefix, method) => ({
        username: $(`${prefix}-user`)?.value.trim() || (method === "snmpv2c" ? "community" : ""),
        password: $(`${prefix}-password`)?.value || "", priv_password: $(`${prefix}-priv`)?.value || "",
        ssh_port: Number($(`${prefix}-port`)?.value) || null,
        ...($(`${prefix}-auth-protocol`) ? { snmp_auth_protocol: $(`${prefix}-auth-protocol`).value, snmp_priv_protocol: $(`${prefix}-priv-protocol`).value } : {}),
      });
      for (const [method, ids] of work) {
        const split = current.split.has(method) && ids.length > 1;
        const profileId = split ? null : Number($(`da-${method}-profile`)?.value) || null;
        const fallback = fallbackIds(element, `da-${method}`);
        const remember = $(`da-${method}-remember`)?.checked || false;
        // One request per device when each has its own credentials; otherwise one request for the group.
        const batches = split ? ids.map((id) => ({ ids: [id], ...read(`da-${method}-d${id}`, method) })) : [{ ids, ...read(`da-${method}`, method) }];
        element.querySelectorAll(`[data-da-group="${method}"] input[type=password]`).forEach((input) => { input.value = ""; });
        for (const batch of batches) {
          const { ids: deviceIds, ...creds } = batch;
          const names = deviceIds.map((id) => current.devices.find((d) => d.device_id === id)?.name).join(", ");
          if (!profileId && (!creds.password) && !fallback.length) { lines.push(`${METHOD_LABELS[method]} · ${names}: enter credentials, choose a saved profile or tick profiles to try in order.`); continue; }
          const body = { device_ids: deviceIds, method, profile_id: profileId, ...creds, fallback_profile_ids: fallback, remember };
          try {
            const response = await api.post(`/discovery/${current.networkId}/authenticate`, body);
            current.result = response.result;
            current.attempted = true;
            if (response.outcomes.some((o) => o.ok)) current.changed = true;
            response.outcomes.forEach((o) => lines.push(`${o.ok ? "✓" : "✗"} ${o.name}: ${o.detail}`));
            // Successful devices leave the list; failed ones stay selectable for a corrected attempt.
            const pending = new Set((response.result.available_authentications || []).map((d) => d.device_id));
            element.querySelectorAll("[data-da-include]").forEach((box) => {
              if (!pending.has(Number(box.dataset.daInclude))) box.closest("tr").remove();
            });
            if (response.profile_note) lines.push(response.profile_note);
          } catch (err) { lines.push(`${METHOD_LABELS[method]} · ${names}: ${err.message}`); }
        }
      }
      $("da-results").innerHTML = `<ul class="small mb-0">${lines.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>`;
      await renderGroups();
      await renderProfiles();
    } finally {
      current.busy = false;
      $("da-submit").disabled = false;
      $("da-close").disabled = false;
    }
  });

  return {
    open(networkId, devices, { title = "Authenticate devices", manageProfiles = false, preselect = null } = {}) {
      return new Promise((resolve) => {
        state = { networkId, devices, resolve, result: null, manageProfiles, busy: false, changed: false, split: new Set() };
        $("da-title").textContent = title;
        $("da-results").innerHTML = "";
        $("da-devices").innerHTML = devices.length ? `<table class="table ng-table small mb-0"><thead><tr><th>Include</th><th>Device</th><th>Method</th></tr></thead><tbody>${devices.map((d) => `<tr>
            <td><input class="form-check-input" type="checkbox" data-da-include="${d.device_id}" aria-label="Include ${escapeHtml(d.name)}" ${!preselect || preselect.includes(d.device_id) ? "checked" : ""}></td>
            <td><strong>${escapeHtml(d.name)}</strong> <span class="mono text-muted-ng">${escapeHtml(d.ip)}</span>${d.auth === "failed" ? ' <span class="badge text-bg-danger">Failed</span>' : ""}</td>
            <td><select class="form-select form-select-sm" data-da-method="${d.device_id}" aria-label="Method for ${escapeHtml(d.name)}">${d.methods.map((m) => `<option value="${m}" title="${escapeHtml(d.method_notes?.[m] || "")}">${escapeHtml(METHOD_LABELS[m])}${d.detected && !d.detected.includes(m) ? " · not seen in scan" : ""}</option>`).join("")}</select></td></tr>`).join("")}</tbody></table>`
          : '<p class="small text-muted-ng">Every device that offers secure management has already been authenticated, or nothing more can be learned by authenticating it.</p>';
        $("da-submit").classList.toggle("d-none", !devices.length);
        renderGroups();
        renderProfiles();
        modal.show();
      });
    },
  };
}

let dialogs = null;
function getDialogs() {
  if (!dialogs) dialogs = { credential: createCredentialDialog(), confirm: createConfirmationDialog(), group: createGroupDialog() };
  return dialogs;
}

/** Ask for credentials one device at a time, then at most one consolidated confirmation. */
export async function runCredentialFlow(networkId, result, { progress = null } = {}) {
  const { credential, confirm, group } = getDialogs();
  for (let guard = 0; guard < 40 && result.session.state === "prompting"; guard += 1) {
    if (result.credential_requests.length) {
      const answer = await credential.ask(networkId, result.credential_requests[0], result, { progress });
      result = answer.result || await api.get(`/discovery/${networkId}`);
      continue;
    }
    if (result.session.confirmation === "pending") {
      const candidates = result.confirmation_candidates;
      await api.post(`/discovery/${networkId}/confirmation`, { action: "shown" });
      const choice = await confirm.ask(candidates);
      if (choice.action === "authenticate") {
        const devices = candidates.filter((c) => choice.device_ids.includes(c.device_id));
        await group.open(networkId, devices, { title: "Authenticate selected devices" });
      }
      result = await api.post(`/discovery/${networkId}/confirmation`, { action: "continue" });
    }
    break;
  }
  return result;
}

/** User-initiated authentication (Discovery Report / Device Access); never part of the automatic prompts.
 *  Resolves {changed, result}: changed is false when the user closed the dialog without authenticating. */
export async function openAuthentication(networkId, result, { deviceIds = null, manageProfiles = false } = {}) {
  const devices = (result.available_authentications || []).filter((d) => !deviceIds || deviceIds.includes(d.device_id));
  if (deviceIds && devices.length === 1 && !manageProfiles) {
    const answer = await getDialogs().credential.ask(networkId, devices[0], result, { mode: "manual" });
    return { changed: answer.action === "authenticated", attempted: answer.action === "authenticated" || !!answer.attempted, result: answer.result || result };
  }
  const answer = await getDialogs().group.open(networkId, devices, { title: manageProfiles ? "Device Access" : "Authenticate devices", manageProfiles });
  return { changed: !!answer.changed, attempted: !!answer.attempted, result: answer.result || result };
}

// ------------------------------------------------------------ discovery report
/** Routed segments (other VLANs): found inside the authorised scope, swept, or left out with the reason. */
function segmentsSection(result) {
  const seg = result.segments;
  const leftRouters = result.subnets_not_scanned || [];
  if (!seg && !leftRouters.length) return "";
  const swept = new Set(seg?.swept || []);
  const found = (seg?.answered || []).map((r) => `<li><span class="mono">${escapeHtml(r.cidr)}</span> — ${r.ip ? `gateway <span class="mono">${escapeHtml(r.ip)}</span> answered (${escapeHtml(r.via || "")})` : escapeHtml(r.via || "local interface")} · ${swept.has(r.cidr) ? '<span class="text-success">swept</span>' : '<span class="text-muted-ng">not swept</span>'}</li>`).join("");
  const left = [...(seg?.left_out || []), ...leftRouters].map((r) => `<li><span class="mono">${escapeHtml(r.cidr)}</span> — ${escapeHtml(r.reason)}</li>`).join("");
  return `<h6>Routed segments</h6><div class="small mb-3" data-report="segments">
    ${seg ? `<p class="mb-1">Authorised scope <span class="mono">${escapeHtml(seg.scope)}</span>: ${seg.probed} segment(s) checked on ${seg.gateways_checked} gateway address(es), ${(seg.answered || []).length} answered, ${swept.size} swept.${seg.note ? ` ${escapeHtml(seg.note)}` : ""}</p>` : ""}
    ${found ? `<ul class="mb-1">${found}</ul>` : ""}
    ${left ? `<div class="fw-semibold mt-1">Left out</div><ul class="mb-0">${left}</ul>` : ""}</div>`;
}

export function renderReport(result) {
  const report = result.report;
  const labels = report.labels;
  const order = ["full", "partial", "auth_required", "auth_failed", "unverified", "unreachable"];
  const cards = order.map((key) => `<div class="col-6 col-md-4 col-xl-2"><div class="ng-card p-3 h-100" data-report-count="${key}">
      <div class="fs-4 fw-semibold">${report.counts[key] ?? 0}</div><div class="small">${badge(key, labels)}</div></div></div>`).join("");
  const conn = report.connections;
  const rows = result.devices.map((d) => {
    const c = d.classification || {};
    return `<tr data-report-row="${d.id}"><td><strong>${escapeHtml(d.name)}</strong><div class="mono text-muted-ng">${escapeHtml(d.ip)}</div></td>
      <td>${escapeHtml(d.role || d.type)}<div class="text-muted-ng">${escapeHtml([d.vendor, d.model].filter(Boolean).join(" · ") || "Model unknown")}</div></td>
      <td>${badge(c.primary, labels)}${c.primary === "auth_required" ? ` <span class="badge text-bg-light border">${escapeHtml(labels[c.completeness === "full" ? "full" : "partial"])}</span>` : ""}</td>
      <td>${(c.missing || []).length ? `<ul class="ps-3 mb-0">${c.missing.map((m) => `<li>${escapeHtml(m)}</li>`).join("")}</ul>` : '<span class="text-success">Nothing missing</span>'}
        ${(d.location_notes || []).map((n) => `<div class="small text-muted-ng mt-1"><i class="bi bi-geo-alt me-1"></i>${escapeHtml(n)}</div>`).join("")}${c.note ? `<div class="small text-muted-ng mt-1">${escapeHtml(c.note)}</div>` : ""}</td>
      <td>${escapeHtml(AUTH_LABELS[c.auth] || "—")}${(d.methods || []).length ? `<div class="text-muted-ng">${d.methods.map((m) => escapeHtml(METHOD_LABELS[m])).join(", ")}</div>` : ""}</td>
      <td><button type="button" class="btn btn-sm btn-light border" data-device-details="${d.id}">Details</button></td></tr>`;
  }).join("");
  const pairs = report.port_pairs.map((p) => `<tr><td>${escapeHtml(p.source)} <span class="mono">${escapeHtml(p.source_port)}</span> → ${escapeHtml(p.destination)} <span class="mono">${escapeHtml(p.destination_port)}</span></td>
      <td><span class="badge ${{ confirmed: "text-bg-success", inferred: "ng-badge-inferred", logical: "text-bg-info", manual: "text-bg-light border" }[p.status] || "text-bg-secondary"}">${escapeHtml({ confirmed: "Confirmed (both neighbour tables)", inferred: "Inferred (one neighbour entry or MAC table)", logical: "Logical (shared routed subnet)", manual: "Added manually" }[p.status] || "Unknown (port reference missing)")}</span></td></tr>`).join("");
  const available = (result.available_authentications || []).length;
  const grades = report.grades || {};
  return `<div class="alert alert-info small" role="status"><strong>Live discovery.</strong>
      ${report.authorization ? ` Authorised range ${escapeHtml(report.authorization.range)} confirmed by ${escapeHtml(report.authorization.by)}.` : ""}
      ${report.scope?.excluded?.length ? ` Excluded: ${escapeHtml(report.scope.excluded.join(", "))}.` : ""}${report.scope?.untrusted?.length ? ` Untrusted: ${escapeHtml(report.scope.untrusted.join(", "))}.` : ""}</div>
    <div class="row g-2 mb-3">${cards}</div>
    <div class="d-flex flex-wrap gap-2 mb-3">
      <span class="badge text-bg-success">${grades.Confirmed ?? conn.confirmed} Confirmed</span>
      <span class="badge ng-badge-inferred">${grades.Inferred ?? conn.inferred} Inferred</span>
      <span class="badge text-bg-info">${grades.Logical ?? 0} Logical</span>
      <span class="badge text-bg-light border">${conn.unknown} Unknown (no port evidence)</span>
      <span class="ms-auto d-flex gap-2">${available ? `<button type="button" class="btn btn-sm btn-outline-primary" data-report-authenticate><i class="bi bi-shield-lock me-1"></i>Authenticate devices</button>` : ""}
      <a class="btn btn-sm btn-primary" data-report-open href="/topology?network=${result.network_id}">Open Topology</a></span></div>
    <div class="table-responsive mb-3"><table class="table ng-table small" data-report="devices"><thead><tr><th>Device</th><th>Identified as</th><th>Status</th><th>Missing / notes</th><th>Authentication</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    <h6>Connections</h6>${pairs ? `<div class="table-responsive mb-3"><table class="table ng-table small" data-report="connections"><tbody>${pairs}</tbody></table></div>` : '<p class="small text-muted-ng">No cable has been verified. ICMP, DNS, the gateway hop and DHCP facts never establish a cable; authenticate a switch to read its neighbour and MAC tables.</p>'}
    ${segmentsSection(result)}
    ${report.unreachable.length ? `<h6>Unreachable</h6><ul class="small" data-report="unreachable">${report.unreachable.map((u) => `<li><strong>${escapeHtml(u.name)}</strong> <span class="mono">${escapeHtml(u.ip)}</span> — ${escapeHtml(u.detail)}</li>`).join("")}</ul>` : ""}`;
}
