// EVE-NG-style device interaction in the Topology Workspace:
//  * Open CLI: an interactive terminal (SSH, Telnet or the laboratory console) in a floating, resizable window,
//    several at once; double-clicking a device opens it. Production devices open read-only unless the user's
//    group may configure them; every session is recorded in the history.
//  * Web GUI: the device's detected management portals (any port, vendor fingerprint, certificate), opened in a
//    NetGuard child window (desktop app) or a browser tab, plus on-demand port scans to find more.
import { api } from "../api.js";
import { escapeHtml, toast } from "../ui.js";

let windows = 0;
let z = 1080;

function modal(id, title, body, footer = "") {
  document.getElementById(id)?.remove();
  const wrapper = document.createElement("div");
  wrapper.innerHTML = `<div class="modal fade" id="${id}" tabindex="-1" aria-labelledby="${id}-title" aria-hidden="true"><div class="modal-dialog modal-dialog-centered modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="${id}-title">${title}</h5><button class="btn-close" type="button" data-bs-dismiss="modal" aria-label="Close"></button></div><div class="modal-body">${body}</div>${footer ? `<div class="modal-footer">${footer}</div>` : ""}</div></div></div>`;
  document.body.appendChild(wrapper.firstElementChild);
  const el = document.getElementById(id);
  const instance = bootstrap.Modal.getOrCreateInstance(el);
  el.addEventListener("hidden.bs.modal", () => el.remove(), { once: true });
  instance.show();
  return { el, instance };
}

// ------------------------------------------------------------------ CLI terminal
export async function openTerminal(device) {
  if (!device) return;
  const lab = !!device.is_lab;
  const consoleUrl = device.access?.console;
  let profiles = [];
  try { profiles = (await api.get("/credential-profiles")).filter((p) => (p.method || "ssh") === "ssh"); } catch { /* optional */ }
  const body = `<form id="term-form" novalidate>
    <div class="alert alert-danger py-2 small d-none" data-term-error></div>
    <p class="small text-muted-ng">${lab ? "Laboratory device: the session has full access." : "Production device: the session is <strong>read-only</strong> unless your user group may configure production devices. Changes belong in Validation &amp; Changes."} Every session is recorded in Reports &amp; History.</p>
    <div class="row g-2">
      <div class="col-sm-4"><label class="form-label" for="term-transport">Connection</label><select class="form-select" id="term-transport">
        <option value="auto">Automatic</option>${consoleUrl ? `<option value="console">Lab console (${escapeHtml(consoleUrl)})</option>` : ""}
        <option value="ssh">SSH</option><option value="telnet">Telnet</option></select></div>
      <div class="col-sm-3"><label class="form-label" for="term-port">Port</label><input class="form-control" id="term-port" type="number" min="1" max="65535" placeholder="default"></div>
      <div class="col-sm-5"><label class="form-label" for="term-profile">Saved SSH profile</label><select class="form-select" id="term-profile"><option value="">None (enter below or assigned)</option>${profiles.map((p) => `<option value="${p.id}">${escapeHtml(p.name)} (${escapeHtml(p.username)})</option>`).join("")}</select></div>
      <div class="col-sm-6"><label class="form-label" for="term-user">Username</label><input class="form-control" id="term-user" autocomplete="off"></div>
      <div class="col-sm-6"><label class="form-label" for="term-pass">Password</label><input class="form-control" id="term-pass" type="password" autocomplete="new-password"></div>
      <div class="col-12 form-check ms-1"><input class="form-check-input" type="checkbox" id="term-readonly" ${lab ? "" : "checked"}><label class="form-check-label small" for="term-readonly">Read-only session (block configuration commands)</label></div>
      <div class="col-12 form-check ms-1"><input class="form-check-input" type="checkbox" id="term-newkey"><label class="form-check-label small" for="term-newkey">Accept a changed SSH host key (only if you know why it changed)</label></div>
    </div></form>`;
  const { el, instance } = modal("term-modal", `Open CLI · ${escapeHtml(device.name)}`, body,
    `<button class="btn btn-light" type="button" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary" type="button" id="term-connect"><i class="bi bi-terminal me-1"></i>Connect</button>`);
  el.querySelector("#term-connect").addEventListener("click", async () => {
    const error = el.querySelector("[data-term-error]");
    error.classList.add("d-none");
    const payload = {
      transport: el.querySelector("#term-transport").value,
      port: Number(el.querySelector("#term-port").value) || null,
      profile_id: Number(el.querySelector("#term-profile").value) || null,
      username: el.querySelector("#term-user").value.trim() || null,
      password: el.querySelector("#term-pass").value || null,
      mode: el.querySelector("#term-readonly").checked ? "read-only" : null,
      accept_new_key: el.querySelector("#term-newkey").checked,
    };
    try {
      const session = await api.post(`/devices/${device.id}/terminal`, payload);
      instance.hide();
      terminalWindow(device, session);
    } catch (exc) {
      error.textContent = exc.message;
      error.classList.remove("d-none");
    }
  });
}

function terminalWindow(device, session) {
  if (typeof window.Terminal !== "function") {
    toast("The terminal component did not load.", "danger");
    return;
  }
  windows += 1;
  const id = `ng-term-${windows}`;
  const box = document.createElement("div");
  box.className = "ng-term-window";
  box.id = id;
  box.style.zIndex = String(++z);
  box.style.left = `${80 + (windows % 6) * 28}px`;
  box.style.top = `${90 + (windows % 6) * 28}px`;
  box.setAttribute("role", "dialog");
  box.setAttribute("aria-label", `Terminal ${device.name}`);
  box.innerHTML = `<div class="ng-term-head"><span class="ng-term-title"><i class="bi bi-terminal me-1"></i>${escapeHtml(device.name)} · ${escapeHtml(session.transport)} ${escapeHtml(session.host)}:${session.port}</span>
    <span class="ng-term-mode ${session.mode === "read-only" ? "ro" : "rw"}">${session.mode === "read-only" ? "READ-ONLY" : session.production ? "FULL · PRODUCTION" : "LAB"}</span>
    <span class="ms-auto d-flex gap-1"><button class="btn btn-sm btn-link text-white p-0 px-1" data-term-min title="Minimise" aria-label="Minimise"><i class="bi bi-dash-lg"></i></button><button class="btn btn-sm btn-link text-white p-0 px-1" data-term-close title="Close" aria-label="Close"><i class="bi bi-x-lg"></i></button></span></div>
    <div class="ng-term-notice">${escapeHtml(session.notice || "")}</div><div class="ng-term-body"></div>`;
  document.body.appendChild(box);
  const term = new window.Terminal({ cursorBlink: true, fontFamily: "Cascadia Mono, Consolas, Menlo, monospace", fontSize: 13,
    theme: { background: "#0f1720", foreground: "#d8e1ea" }, scrollback: 5000, convertEol: false });
  const fit = window.FitAddon ? new window.FitAddon.FitAddon() : null;
  if (fit) term.loadAddon(fit);
  term.open(box.querySelector(".ng-term-body"));
  fit?.fit();
  term.writeln(`\x1b[90mConnecting to ${session.host}:${session.port} (${session.platform})…\x1b[0m`);
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${scheme}://${location.host}/api/terminal/ws?ticket=${encodeURIComponent(session.ticket)}&cols=${term.cols}&rows=${term.rows}`);
  let open = false;
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "output") term.write(message.data);
    else if (message.type === "ready") { open = true; term.writeln(`\x1b[32mConnected (${message.mode}).${message.host_key ? ` Host key ${message.host_key}` : ""}\x1b[0m`); term.focus(); }
    else if (message.type === "notice") term.write(`\r\n\x1b[33m[NetGuard] ${message.message}\x1b[0m\r\n`);
    else if (message.type === "hostkey" || message.type === "error") term.writeln(`\r\n\x1b[31m${message.message}\x1b[0m`);
    else if (message.type === "closed") term.writeln(`\r\n\x1b[90m${message.message}\x1b[0m`);
  });
  socket.addEventListener("close", () => { open = false; term.writeln("\r\n\x1b[90m[session ended]\x1b[0m"); });
  const send = (message) => { if (open && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message)); };
  term.onData((data) => send({ type: "input", data }));
  const resize = () => {
    if (!box.isConnected) return;
    fit?.fit();
    send({ type: "resize", cols: term.cols, rows: term.rows });
  };
  const observer = new ResizeObserver(resize);
  observer.observe(box);
  box.addEventListener("mousedown", () => { box.style.zIndex = String(++z); });
  box.querySelector("[data-term-close]").addEventListener("click", () => { open = false; observer.disconnect(); socket.close(); term.dispose(); box.remove(); });
  box.querySelector("[data-term-min]").addEventListener("click", () => box.classList.toggle("min"));
  // Drag by the title bar.
  const head = box.querySelector(".ng-term-head");
  head.addEventListener("pointerdown", (event) => {
    if (event.target.closest("button")) return;
    const start = { x: event.clientX, y: event.clientY, left: box.offsetLeft, top: box.offsetTop };
    const move = (e) => { box.style.left = `${Math.max(0, start.left + e.clientX - start.x)}px`; box.style.top = `${Math.max(0, start.top + e.clientY - start.y)}px`; };
    const up = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  });
}

// ------------------------------------------------------------------ web management portals
export function openUrl(url, title) {
  const desktop = window.pywebview?.api?.open_portal;
  if (desktop) {
    window.pywebview.api.open_portal(url, title).catch(() => window.open(url, "_blank", "noopener"));
    return;
  }
  window.open(url, "_blank", "noopener");
}

function portalRows(data, device) {
  const rows = data.portals.map((p) => `<tr>
      <td><div class="fw-semibold">${escapeHtml(p.vendor ? `${p.vendor} · ${p.product}` : (p.title || "Web interface"))}</div>
        <div class="mono small">${escapeHtml(p.url)}</div>
        <div class="small text-muted-ng">${escapeHtml([p.title && p.vendor ? `“${p.title}”` : null, p.server ? `server ${p.server}` : null, p.login_page ? "login page" : null].filter(Boolean).join(" · "))}</div>
        ${p.certificate ? `<div class="small text-muted-ng">Certificate ${escapeHtml(p.certificate.subject || "?")}${p.self_signed ? " (self-signed)" : ""} · SHA-256 <span class="mono">${escapeHtml((p.certificate.sha256 || "").slice(0, 23))}…</span></div>` : ""}</td>
      <td class="text-end text-nowrap"><button class="btn btn-sm btn-primary" data-portal-open="${escapeHtml(p.url)}"><i class="bi bi-box-arrow-up-right me-1"></i>Open</button>
        <button class="btn btn-sm btn-light border" data-portal-copy="${escapeHtml(p.url)}" title="Copy URL" aria-label="Copy URL"><i class="bi bi-clipboard"></i></button></td></tr>`).join("");
  const suggested = (data.suggested || []).map((s) => `<tr><td><div class="mono small">${escapeHtml(s.url)}</div><div class="small text-muted-ng">Not verified: no web service was detected yet. Scan the ports first.</div></td><td class="text-end"><button class="btn btn-sm btn-light border" data-portal-open="${escapeHtml(s.url)}">Try</button></td></tr>`).join("");
  return rows || suggested
    ? `<table class="table table-sm align-middle mb-2"><tbody>${rows}${suggested}</tbody></table>`
    : `<p class="small text-muted-ng">No web management interface is known for ${escapeHtml(device.name)}.</p>`;
}

export async function openPortals(device) {
  if (!device) return;
  let data;
  try { data = await api.get(`/devices/${device.id}/portals`); } catch (exc) { toast(exc.message, "danger"); return; }
  const body = `<div data-portal-list>${portalRows(data, device)}</div>
    ${data.lab_console ? `<p class="small">Laboratory console: <span class="mono">${escapeHtml(data.lab_console)}</span> (use Open CLI).</p>` : ""}
    <div class="border rounded p-2 small"><div class="fw-semibold mb-1">Find more management interfaces</div>
      <p class="text-muted-ng mb-2">A read-only TCP connect scan of ${escapeHtml(data.ip || "the device")}; every open port is checked for HTTP and HTTPS (FortiGate 10443, UniFi 8443, appliances on 8080 and so on).${data.last_scan ? ` Last scan: ${escapeHtml(data.last_scan.range)} at ${escapeHtml(data.last_scan.at)}, open ports ${escapeHtml((data.last_scan.open_ports || []).join(", ") || "none")}.` : ""}</p>
      <div class="d-flex gap-2 flex-wrap"><button class="btn btn-sm btn-outline-primary" data-portal-scan="common">Common ports</button><button class="btn btn-sm btn-outline-primary" data-portal-scan="well-known">1–1024 and well-known</button><button class="btn btn-sm btn-outline-secondary" data-portal-scan="all">All 65,535 ports</button></div>
      <div class="progress mt-2 d-none" style="height:6px" data-portal-progress><div class="progress-bar" style="width:0%"></div></div><div class="small text-muted-ng mt-1" data-portal-status></div></div>`;
  const { el } = modal("portal-modal", `Web GUI · ${escapeHtml(device.name)}`, body);
  el.addEventListener("click", async (event) => {
    const openBtn = event.target.closest("[data-portal-open]");
    if (openBtn) { openUrl(openBtn.dataset.portalOpen, `${device.name} web management`); return; }
    const copy = event.target.closest("[data-portal-copy]");
    if (copy) { navigator.clipboard?.writeText(copy.dataset.portalCopy); toast("URL copied.", "info"); return; }
    const scanBtn = event.target.closest("[data-portal-scan]");
    if (!scanBtn) return;
    el.querySelectorAll("[data-portal-scan]").forEach((b) => { b.disabled = true; });
    const bar = el.querySelector("[data-portal-progress]");
    const status = el.querySelector("[data-portal-status]");
    bar.classList.remove("d-none");
    try {
      const job = await api.post(`/devices/${device.id}/portals/scan`, { range: scanBtn.dataset.portalScan });
      for (;;) {
        await new Promise((r) => setTimeout(r, 800));
        const row = await api.get(`/terminal/jobs/${job.job_id}`);
        bar.firstElementChild.style.width = `${Math.round((row.done / Math.max(row.total, 1)) * 100)}%`;
        status.textContent = row.state === "identifying" ? `Checking ${row.open_ports.length} open port(s) for web interfaces…` : `${row.done} of ${row.total} ports checked`;
        if (row.state === "done" || row.state === "failed") {
          status.textContent = row.state === "failed" ? `Scan failed: ${row.error}` : `Open ports: ${row.open_ports.join(", ") || "none"} · ${row.portals.length} web interface(s) found.`;
          const fresh = await api.get(`/devices/${device.id}/portals`);
          el.querySelector("[data-portal-list]").innerHTML = portalRows(fresh, device);
          break;
        }
      }
    } catch (exc) {
      status.textContent = exc.message;
    } finally {
      el.querySelectorAll("[data-portal-scan]").forEach((b) => { b.disabled = false; });
    }
  });
}
