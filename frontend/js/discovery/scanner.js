// Real Network discovery: one range, one Scan button, live progress, a results table and an inline credential
// panel that appears only for devices whose deeper read needs a login.

import { openUrl } from "../topology/console.js";
import { api } from "../api.js";
import { escapeHtml, toast, withBusy } from "../ui.js";

const $ = (id) => document.getElementById(id);
const METHOD_LABELS = { ssh: "SSH", snmpv3: "SNMPv3", snmpv2c: "SNMPv2c (read-only)" };
const state = { result: null, polling: null, interfaces: [], hooks: {} };

function list(id) {
  return $(id).value.split(/[\s,;]+/).map((v) => v.trim()).filter(Boolean);
}

async function detect() {
  try {
    const local = await api.get("/discovery/local-networks");
    state.interfaces = local.interfaces || [];
    const select = $("scan-interface");
    select.innerHTML = state.interfaces.map((row, i) => `<option value="${i}">${escapeHtml(row.interface)} · ${escapeHtml(row.address)}/${row.prefix}${row.gateway ? ` · gateway ${escapeHtml(row.gateway)}` : ""}</option>`).join("")
      + '<option value="custom">Other range…</option>';
    if (state.interfaces.length && !$("scan-target").value) $("scan-target").value = state.interfaces[0].scan_target;
    if (!state.interfaces.length) select.value = "custom";
  } catch (error) { toast(error.message, "error"); }
}

function progressView(job) {
  const pct = job.phase === "sweep" ? Math.min(100, Math.round((job.done / job.total) * 100)) : job.state === "done" ? 100 : null;
  $("scan-progress").classList.remove("d-none");
  $("scan-progress-bar").style.width = `${pct ?? 100}%`;
  $("scan-progress-bar").classList.toggle("progress-bar-animated", job.state === "running");
  $("scan-progress-bar").classList.toggle("progress-bar-striped", pct === null || job.state === "running");
  $("scan-progress-label").textContent = job.state === "failed" ? `Discovery failed: ${job.error}` : job.phase_label;
  $("scan-progress-count").textContent = `${job.found} found · ${job.elapsed}s`;
}

async function startScan() {
  const button = $("scan-start");
  button.disabled = true;
  $("scan-error").classList.add("d-none");
  try {
    const job = await api.post("/discovery/jobs", {
      target: $("scan-target").value.trim(), authorized_scope: true, excluded: list("scan-excluded"),
      untrusted: list("scan-untrusted"), auto_credentials: $("scan-auto").checked, follow_neighbours: $("scan-follow").checked,
    });
    progressView(job);
    await new Promise((resolve) => {
      state.polling = setInterval(async () => {
        try {
          const status = await api.get(`/discovery/jobs/${job.id}`);
          progressView(status);
          if (status.state === "running") return;
          clearInterval(state.polling);
          if (status.state === "done") await load(status.network_id);
          else { $("scan-error").textContent = status.error; $("scan-error").classList.remove("d-none"); }
          resolve();
        } catch (error) { clearInterval(state.polling); $("scan-error").textContent = error.message; $("scan-error").classList.remove("d-none"); resolve(); }
      }, 700);
    });
    state.hooks.onComplete?.();
  } catch (error) {
    $("scan-error").textContent = error.message;
    $("scan-error").classList.remove("d-none");
  } finally { button.disabled = false; }
}

export async function load(networkId) {
  state.result = await api.get(`/discovery/${networkId}`);
  render();
}

function accessLabel(d) {
  if (d.auth === "success") return `<span class="text-success"><i class="bi bi-check-circle me-1"></i>Read (${escapeHtml(METHOD_LABELS[d.auth_method] || d.auth_method || "")})</span>`;
  if (d.auth === "failed") return `<span class="text-danger"><i class="bi bi-x-circle me-1"></i>Login failed</span>`;
  if (d.auth === "skipped") return '<span class="text-muted-ng">Skipped</span>';
  if ((d.methods || []).length) return `<span class="text-warning-emphasis"><i class="bi bi-key me-1"></i>${d.methods.map((m) => METHOD_LABELS[m]).join(" / ")}</span>`;
  return '<span class="text-muted-ng">Not needed</span>';
}

function identity(d) {
  const unknown = d.identity_unknown || d.type === "unknown";
  return `${unknown ? '<span class="badge text-bg-light border me-1">Unidentified</span>' : ""}${escapeHtml(d.role || d.type)}
    <div class="text-muted-ng small">${escapeHtml([d.vendor, d.model].filter(Boolean).join(" · ") || (unknown ? "Identity not determined from the evidence" : ""))}</div>`;
}

function render() {
  const r = state.result;
  if (!r) return;
  $("scan-result").classList.remove("d-none");
  const devices = r.devices;
  const identified = devices.filter((d) => !(d.identity_unknown || d.type === "unknown")).length;
  const read = devices.filter((d) => d.auth === "success").length;
  const grades = r.report?.grades || {};
  const unknownLinks = r.report?.connections?.unknown ?? 0;
  $("scan-result-title").textContent = r.network.name;
  $("scan-open-topology").href = `/topology?network=${r.network_id}`;
  $("scan-summary").innerHTML = [
    `<span><strong>${devices.length}</strong> devices</span>`, `<span><strong>${identified}</strong> identified</span>`,
    `<span><strong>${devices.length - identified}</strong> unidentified</span>`, `<span><strong>${read}</strong> read with credentials</span>`,
    `<span class="badge text-bg-success">${grades.Confirmed ?? 0} confirmed</span>`, `<span class="badge ng-badge-inferred">${grades.Inferred ?? 0} inferred</span>`,
    `<span class="badge text-bg-info">${grades.Logical ?? 0} logical</span>`, `<span class="badge text-bg-light border">${unknownLinks} without connection evidence</span>`,
  ].join("");
  $("scan-table").innerHTML = devices.length ? `<div class="table-responsive"><table class="table ng-table small align-middle mb-0" data-scan="devices">
    <thead><tr><th>IP address</th><th>Name</th><th>MAC / vendor</th><th>Identified as</th><th>Services</th><th>Access</th><th></th></tr></thead><tbody>
    ${devices.map((d) => `<tr data-scan-row="${d.id}"><td class="mono">${escapeHtml(d.ip || "")}${d.gateway ? ' <span class="badge text-bg-light border">gateway</span>' : ""}</td>
      <td><strong>${escapeHtml(d.name)}</strong><div class="text-muted-ng small">${escapeHtml(d.name_source || "")}</div></td>
      <td class="mono">${escapeHtml(d.mac || "—")}<div class="text-muted-ng small" style="font-family:inherit">${escapeHtml(d.vendor || "")}</div></td>
      <td>${identity(d)}</td>
      <td class="small">${escapeHtml((d.open_services || []).join(", ") || "—")}</td>
      <td class="small">${accessLabel(d)}</td>
      <td class="text-nowrap">${(d.portals || []).length ? `<button type="button" class="btn btn-sm btn-outline-dark me-1" data-portal-url="${escapeHtml(d.portals[0].url)}" title="${escapeHtml(d.portals.map((p) => p.url + (p.product ? ` (${p.product})` : "")).join("\n"))}"><i class="bi bi-window me-1"></i>Web GUI</button>` : ""}<button type="button" class="btn btn-sm btn-light border" data-device-details="${d.id}">Evidence</button></td></tr>`).join("")}
    </tbody></table></div>` : '<p class="small text-muted-ng mb-0">No device answered ICMP, TCP, ARP or SNMP in this range.</p>';
  renderCredentials();
}

function pendingLogins() {
  return (state.result?.available_authentications || []).filter((d) => !state.result.devices.find((x) => x.id === d.device_id && x.auth === "skipped"));
}

function renderCredentials() {
  const pending = pendingLogins();
  const box = $("scan-credentials");
  if (!pending.length) { box.classList.add("d-none"); box.innerHTML = ""; return; }
  const methods = [...new Set(pending.flatMap((d) => d.methods))];
  box.classList.remove("d-none");
  box.innerHTML = `<div class="d-flex justify-content-between align-items-start gap-2 mb-2"><div>
      <h5 class="h6 mb-1"><i class="bi bi-key me-1"></i>Deeper discovery needs a login on ${pending.length} device${pending.length === 1 ? "" : "s"}</h5>
      <div class="small text-muted-ng">A read-only login reads interfaces, neighbours (LLDP/CDP), MAC, ARP and routing tables; NetGuard then follows the neighbours it finds with the same credentials. Typed credentials are not stored unless you tick Remember.</div></div>
      <button type="button" class="btn btn-sm btn-link" data-cred-skip>Skip</button></div>
    <div class="d-flex flex-wrap gap-3 mb-2">${pending.map((d) => `<div class="form-check"><input class="form-check-input" type="checkbox" id="cred-dev-${d.device_id}" data-cred-device="${d.device_id}" data-methods="${d.methods.join(",")}" checked>
      <label class="form-check-label small" for="cred-dev-${d.device_id}">${escapeHtml(d.name)} <span class="mono text-muted-ng">${escapeHtml(d.ip)}</span></label></div>`).join("")}</div>
    <form id="cred-form" class="row g-2 align-items-end" novalidate>
      <div class="col-md-2"><label class="form-label small" for="cred-method">Method</label><select id="cred-method" class="form-select form-select-sm">${methods.map((m) => `<option value="${m}">${METHOD_LABELS[m]}</option>`).join("")}</select></div>
      <div class="col-md-3"><label class="form-label small" for="cred-profile">Saved profile</label><select id="cred-profile" class="form-select form-select-sm"><option value="">Enter credentials</option></select></div>
      <div class="col-md-2" data-cred-user><label class="form-label small" for="cred-user">Username</label><input id="cred-user" class="form-control form-control-sm" autocomplete="off" maxlength="64"></div>
      <div class="col-md-2"><label class="form-label small" for="cred-password" id="cred-password-label">Password</label><input id="cred-password" type="password" class="form-control form-control-sm" autocomplete="off" maxlength="128"></div>
      <div class="col-md-2 d-none" data-cred-priv><label class="form-label small" for="cred-priv">Privacy passphrase</label><input id="cred-priv" type="password" class="form-control form-control-sm" autocomplete="off" maxlength="128"></div>
      <div class="col-md-1"><button class="btn btn-sm btn-primary w-100" id="cred-submit">Read</button></div>
      <div class="col-12"><div class="form-check"><input class="form-check-input" type="checkbox" id="cred-remember"><label class="form-check-label small" for="cred-remember">Remember as an encrypted credential profile</label></div></div>
      <div class="col-12"><div class="alert alert-danger small py-2 mb-0 d-none" id="cred-error" role="alert"></div></div>
    </form>`;
  methodChanged();
}

async function methodChanged() {
  const method = $("cred-method").value;
  document.querySelector("[data-cred-priv]").classList.toggle("d-none", method !== "snmpv3");
  document.querySelector("[data-cred-user]").classList.toggle("d-none", method === "snmpv2c");
  $("cred-password-label").textContent = method === "snmpv2c" ? "Read-only community" : method === "snmpv3" ? "Auth passphrase" : "Password";
  document.querySelectorAll("[data-cred-device]").forEach((box) => {
    const ok = box.dataset.methods.split(",").includes(method);
    box.disabled = !ok;
    if (!ok) box.checked = false;
  });
  try {
    const profiles = (await api.get("/credential-profiles")).filter((p) => (p.method || "ssh") === method);
    $("cred-profile").innerHTML = '<option value="">Enter credentials</option>' + profiles.map((p) => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join("");
  } catch { /* profiles are optional */ }
}

async function submitCredentials(event) {
  event.preventDefault();
  const ids = [...document.querySelectorAll("[data-cred-device]:checked")].map((b) => Number(b.dataset.credDevice));
  const method = $("cred-method").value;
  const body = { device_ids: ids, method, profile_id: Number($("cred-profile").value) || null,
    username: method === "snmpv2c" ? "community" : $("cred-user").value.trim(), password: $("cred-password").value,
    priv_password: $("cred-priv").value, remember: $("cred-remember").checked, continue_discovery: true };
  $("cred-password").value = ""; $("cred-priv").value = "";
  const error = (text) => { $("cred-error").textContent = text; $("cred-error").classList.toggle("d-none", !text); };
  if (!ids.length) return error("Select at least one device that offers this method.");
  if (!body.profile_id && (!body.password || (method !== "snmpv2c" && !body.username))) return error("Enter the credentials or choose a saved profile.");
  await withBusy($("cred-submit"), async () => {
    try {
      $("scan-progress").classList.remove("d-none");
      $("scan-progress-label").textContent = "Reading devices and following their neighbours…";
      $("scan-progress-bar").style.width = "100%";
      const response = await api.post(`/discovery/${state.result.network_id}/authenticate`, body);
      const ok = response.outcomes.filter((o) => o.ok).length;
      const failed = response.outcomes.filter((o) => !o.ok);
      const crawl = response.crawl ? ` · ${response.crawl.read} more read, ${response.crawl.added} found through neighbours` : "";
      toast(`${ok} device(s) read${failed.length ? ` · ${failed.length} failed` : ""}${crawl}`, failed.length && !ok ? "error" : failed.length ? "warning" : "success");
      await load(state.result.network_id);
      if (failed.length) error(failed.map((o) => `${o.name}: ${o.detail}`).join(" "));
      state.hooks.onComplete?.();
    } catch (err) { error(err.message); }
    finally { $("scan-progress-label").textContent = "Discovery complete"; }
  });
}

async function skipAll() {
  const ids = pendingLogins().map((d) => d.device_id);
  try {
    await api.post(`/discovery/${state.result.network_id}/skip`, { all: true, device_ids: ids });
    await load(state.result.network_id);
  } catch (error) { toast(error.message, "error"); }
}

export function setupScanner(hooks = {}) {
  state.hooks = hooks;
  $("scan-interface").addEventListener("change", () => {
    const value = $("scan-interface").value;
    if (value === "custom") { $("scan-target").focus(); $("scan-target").select(); return; }
    $("scan-target").value = state.interfaces[Number(value)]?.scan_target || "";
  });
  $("scan-form").addEventListener("submit", (event) => { event.preventDefault(); startScan(); });
  $("scan-credentials").addEventListener("change", (event) => { if (event.target.id === "cred-method") methodChanged(); });
  $("scan-credentials").addEventListener("submit", submitCredentials);
  $("scan-credentials").addEventListener("click", (event) => { if (event.target.closest("[data-cred-skip]")) skipAll(); });
  $("scan-table").addEventListener("click", (event) => {
    const portal = event.target.closest("[data-portal-url]");
    if (portal) { openUrl(portal.dataset.portalUrl, "Device web management"); return; }
    const button = event.target.closest("[data-device-details]");
    if (button) hooks.showDevice?.(state.result, Number(button.dataset.deviceDetails));
  });
  document.getElementById("real-tab")?.addEventListener("shown.bs.tab", () => { if (!state.interfaces.length) detect(); }, { once: true });
  if (document.getElementById("real-panel")?.classList.contains("active")) detect();
}
