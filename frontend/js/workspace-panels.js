// Reuse the application splitters for navigation and the common topology workspace.
import { flexPanel, navPanel } from "./panels.js";

let navigation;
let details;
let canvasObserver;

export function initNavigationPanel() {
  if (navigation) return navigation;
  navigation = navPanel(document.getElementById("ng-sidebar"));
  document.getElementById("ng-nav-toggle")?.addEventListener("click", () => navigation?.toggle());
  return navigation;
}

export function initWorkspacePanels() {
  const panel = document.getElementById("side-panel");
  const workspace = panel?.closest(".ng-workspace");
  if (!workspace || details) return details;
  const toggle = document.getElementById("btn-details-toggle");
  details = flexPanel(panel, "topology", "right", {
    min: 280,
    max: () => Math.min(720, workspace.getBoundingClientRect().width - 328),
    initial: Math.min(420, Math.max(320, workspace.getBoundingClientRect().width * 0.3)),
    label: "details panel",
    onChange(open) {
      if (toggle) {
        toggle.setAttribute("aria-expanded", String(open));
        toggle.title = open ? "Hide details panel" : "Show details panel";
        toggle.querySelector("span").textContent = open ? "Hide Details" : "Show Details";
      }
      panel.setAttribute("aria-hidden", String(!open));
    },
  });
  toggle?.addEventListener("click", () => details.toggle());
  document.addEventListener("netguard:panel-open", () => details.show());
  document.addEventListener("netguard:panel-close", () => {
    details.hide();
    // The close action may have already replaced its focused content.
    toggle?.focus({ preventScroll: true });
  });

  // Cytoscape follows the actual canvas container, including toolbar wrapping
  // and the smaller stacked layout, without changing device positions or zoom.
  let frame = 0;
  let lastWidth = -1;
  let lastHeight = -1;
  canvasObserver = new ResizeObserver(([entry]) => {
    const width = Math.round(entry.contentRect.width);
    const height = Math.round(entry.contentRect.height);
    if (width <= 0 || height <= 0 || (width === lastWidth && height === lastHeight)) return;
    lastWidth = width;
    lastHeight = height;
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      document.dispatchEvent(new CustomEvent("netguard:layout-changed"));
    });
  });
  // Observe the layout owner, not the element whose canvases Cytoscape redraws.
  canvasObserver.observe(document.querySelector(".ng-canvas-wrap"));
  return details;
}
