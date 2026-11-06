// Small UI helpers shared by every page: escaping, dates, toasts,
// confirmation dialogs and form utilities. Requires bootstrap.bundle (global).

export function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Backend timestamps are naive UTC; display them in local time. */
export function formatDate(value, withTime = true) {
  if (!value) return "—";
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value}Z`;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return value;
  const options = { year: "numeric", month: "short", day: "2-digit" };
  if (withTime) Object.assign(options, { hour: "2-digit", minute: "2-digit" });
  return date.toLocaleString(undefined, options);
}

export function maskToPrefix(mask) {
  if (!mask) return null;
  return mask.split(".").reduce((bits, octet) => bits + (Number(octet) >>> 0).toString(2).split("1").length - 1, 0);
}

export function formatIp(ip, mask) {
  if (!ip) return "—";
  const prefix = maskToPrefix(mask);
  return prefix === null ? ip : `${ip}/${prefix}`;
}

function toastHost() {
  let host = document.querySelector(".ng-toast-host");
  if (!host) {
    host = document.createElement("div");
    host.className = "ng-toast-host";
    host.setAttribute("aria-live", "polite");
    document.body.appendChild(host);
  }
  return host;
}

const TOAST_ICONS = {
  success: "bi-check-circle-fill",
  error: "bi-exclamation-octagon-fill",
  warning: "bi-exclamation-triangle-fill",
  info: "bi-info-circle-fill",
};

export function toast(message, type = "info", timeout = 3500) {
  const el = document.createElement("div");
  el.className = `ng-toast ${type}`;
  el.setAttribute("role", type === "error" ? "alert" : "status");
  el.innerHTML = `<i class="bi ${TOAST_ICONS[type] || TOAST_ICONS.info}"></i><div>${escapeHtml(message)}</div>`;
  toastHost().appendChild(el);
  setTimeout(() => el.remove(), timeout);
}

/** Bootstrap modal based confirm dialog. Resolves to true/false. */
export function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    const wrapper = document.createElement("div");
    wrapper.innerHTML = `
      <div class="modal fade" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
          <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title">${escapeHtml(title)}</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
            <div class="modal-body">${message}</div>
            <div class="modal-footer">
              <button type="button" class="btn btn-light" data-bs-dismiss="modal">Cancel</button>
              <button type="button" class="btn ${danger ? "btn-danger" : "btn-primary"}" data-ng-confirm>${escapeHtml(confirmLabel)}</button>
            </div>
          </div>
        </div>
      </div>`;
    const modalEl = wrapper.firstElementChild;
    document.body.appendChild(modalEl);
    const modal = new bootstrap.Modal(modalEl);
    let confirmed = false;
    let shown = false;
    modalEl.addEventListener("shown.bs.modal", () => { shown = true; }, { once: true });
    modalEl.querySelector("[data-ng-confirm]").addEventListener("click", () => {
      confirmed = true;
      // Bootstrap ignores hide() while the modal is still fading in, which would lose a quick confirmation.
      if (shown) modal.hide();
      else modalEl.addEventListener("shown.bs.modal", () => modal.hide(), { once: true });
    });
    modalEl.addEventListener("hidden.bs.modal", () => {
      modal.dispose();
      modalEl.remove();
      resolve(confirmed);
    });
    modal.show();
  });
}

/** Read named form fields into an object; empty strings become null. */
export function readForm(form) {
  const data = {};
  for (const [key, value] of new FormData(form).entries()) {
    const trimmed = typeof value === "string" ? value.trim() : value;
    data[key] = trimmed === "" ? null : trimmed;
  }
  return data;
}

export function fillForm(form, values) {
  for (const element of form.elements) {
    if (!element.name) continue;
    const value = values?.[element.name];
    element.value = value === null || value === undefined ? "" : value;
  }
}

export function showFormError(form, message) {
  const box = form.querySelector("[data-form-error]");
  if (!box) return;
  box.textContent = message || "";
  box.classList.toggle("d-none", !message);
}

/** Disable a button and show a spinner while an async action runs. */
export async function withBusy(button, action) {
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = `<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>${button.textContent.trim()}`;
  try {
    return await action();
  } finally {
    button.disabled = false;
    button.innerHTML = original;
  }
}
