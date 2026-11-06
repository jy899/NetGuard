// Shared application shell: sidebar navigation, top bar and auth guard.
// Every authenticated page calls initShell() before rendering its content.

import { api, redirectToLogin, session } from "./api.js";
import { logoSvg } from "./device-types.js";
import { escapeHtml } from "./ui.js";
import { initNavigationPanel, initWorkspacePanels } from "./workspace-panels.js";

export const NAV_ITEMS = [
  { key: "dashboard", label: "Dashboard", href: "/dashboard", icon: "bi-speedometer2" },
  { key: "networks", label: "Networks", href: "/networks", icon: "bi-hdd-network" },
  { key: "topology", label: "Topology Workspace", href: "/topology", icon: "bi-diagram-3" },
  { key: "changes", label: "Validation & Changes", href: "/changes", icon: "bi-shield-check" },
  { key: "reports", label: "Reports & History", href: "/reports", icon: "bi-file-earmark-text" },
  { key: "settings", label: "Settings", href: "/settings", icon: "bi-gear" },
];

function navLinks(list, active) {
  return list.map(
    (item) => `
      <a href="${item.href}" class="${item.key === active ? "active" : ""}" title="${item.label}" aria-label="${item.label}"
         ${item.key === active ? 'aria-current="page"' : ""}>
        <i class="bi ${item.icon}"></i><span>${item.label}</span>
        ${item.soon ? '<span class="ng-soon">Soon</span>' : ""}
      </a>`
  ).join("");
}

function renderSidebar(active) {
  return `
    <a class="ng-brand" href="/dashboard" aria-label="NetGuard Dashboard" title="NetGuard Dashboard">
      ${logoSvg(30)}
      <div class="ng-brand-text">
        <div class="ng-brand-name">NETGUARD</div>
      </div>
    </a>
    <button class="ng-nav-toggle" type="button" id="ng-nav-toggle" aria-controls="ng-sidebar" aria-expanded="true" title="Collapse menu">
      <i class="bi bi-layout-sidebar-inset" aria-hidden="true"></i><span>Collapse menu</span>
    </button>
    <nav class="ng-nav" aria-label="Main navigation">
      ${navLinks(NAV_ITEMS, active)}
    </nav>
    <div class="ng-sidebar-footer"><i class="bi bi-shield-check me-1"></i>Network analysis</div>`;
}

function initials(name) {
  return (name || "?").slice(0, 2).toUpperCase();
}

function renderTopbar(title, subtitle, user) {
  return `
    <div class="min-w-0">
      <h1 class="ng-topbar-title text-truncate" id="ng-page-title">${escapeHtml(title)}</h1>
      <div class="ng-topbar-sub text-truncate" id="ng-page-subtitle">${escapeHtml(subtitle || "")}</div>
    </div>
    ${user && !(user.permissions || []).includes("network.edit") ? `<span class="ng-sample-indicator me-3" title="Your user group (${escapeHtml(user.role)}) cannot edit networks.">Read-only access</span>` : ""}
    <div class="dropdown">
      <button class="ng-user-btn" type="button" data-bs-toggle="dropdown" aria-expanded="false" id="ng-user-menu">
        <span class="ng-avatar">${escapeHtml(initials(user?.username))}</span>
        <span class="ng-user-meta"><span class="name d-block">${escapeHtml(user?.username)}</span>
          <span class="role d-block">${escapeHtml(user?.role)}</span></span>
        <i class="bi bi-chevron-down small text-muted"></i>
      </button>
      <ul class="dropdown-menu dropdown-menu-end shadow-sm">
        <li><span class="dropdown-item-text small text-muted">${escapeHtml(user?.email)}</span></li>
        <li><hr class="dropdown-divider"></li>
        <li><button class="dropdown-item" type="button" id="ng-logout"><i class="bi bi-box-arrow-right me-2"></i>Log out</button></li>
      </ul>
    </div>`;
}

export function setPageTitle(title, subtitle) {
  const titleEl = document.getElementById("ng-page-title");
  const subEl = document.getElementById("ng-page-subtitle");
  if (titleEl && title !== undefined) titleEl.textContent = title;
  if (subEl && subtitle !== undefined) subEl.textContent = subtitle;
}

async function logout() {
  try {
    await api.post("/auth/logout");
  } catch {
    /* token may already be invalid; logging out locally is enough */
  }
  session.clear();
  window.location.replace("/login");
}

/**
 * Verify the session, then render sidebar and top bar.
 * Returns the logged-in user, or never resolves if redirected to login.
 */
export async function initShell({ active, title, subtitle }) {
  if (!session.token) {
    redirectToLogin();
    return new Promise(() => {});
  }
  const user = await api.get("/auth/me"); // 401 redirects to login automatically
  document.getElementById("ng-sidebar").innerHTML = renderSidebar(active);
  document.getElementById("ng-topbar").innerHTML = renderTopbar(title, subtitle, user);
  document.getElementById("ng-logout").addEventListener("click", logout);
  initNavigationPanel();
  initWorkspacePanels();
  // Hide controls the service would refuse: one class per permission the user's group does not grant.
  const granted = new Set(user?.permissions || []);
  ["network.edit", "network.import_export", "discovery.run", "analysis.run", "change.propose", "change.execute",
    "credentials.manage"].forEach((p) => document.body.classList.toggle(`ng-lacks-${p.replace(".", "-")}`, !granted.has(p)));
  document.title = `${title} · NetGuard`;
  return user;
}
