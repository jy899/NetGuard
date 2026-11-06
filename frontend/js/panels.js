// Collapsible, drag-resizable side panels: the navigation menu, the topology device panel and the Lab Studio
// side panels. Drag the bar to resize, click its arrow (or double-click the bar) to hide or show the panel.
// The width and open state are remembered in this browser.

const store = {
  get(key) {
    try {
      return JSON.parse(localStorage.getItem(`netguard.panel.${key}`) || "null");
    } catch {
      return null;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(`netguard.panel.${key}`, JSON.stringify(value));
    } catch {
      /* storage is optional */
    }
  },
};

/**
 * @param {object} o
 * @param {HTMLElement} o.panel   the panel element
 * @param {string} o.key          remembered under this name
 * @param {"left"|"right"} o.side which side of the window the panel is on
 * @param {number} o.min, o.max, o.initial  widths in px
 * @param {number} [o.collapsed]  width when hidden (0 = gone; the navigation keeps its icons at 64)
 * @param {(width:number, open:boolean) => void} o.apply  sets the width on the page
 * @param {() => void} o.reset   back to the page's own CSS (narrow screens, where the panels stack)
 */
export function makeSplitter({ panel, key, side, min, max, initial, collapsed = 0, apply, reset, label,
  breakpoint = 1024, initialOpen = true, onChange = () => {}, narrow = null }) {
  if (!panel || panel.dataset.splitter) return null;
  panel.dataset.splitter = key;
  const bar = document.createElement("div");
  bar.className = `ng-splitter ng-splitter-${side}`;
  bar.dataset.panelKey = key;
  bar.setAttribute("role", "separator");
  bar.setAttribute("aria-orientation", "vertical");
  bar.setAttribute("aria-label", `Resize ${label}`);
  bar.setAttribute("aria-controls", panel.id);
  bar.setAttribute("aria-valuemin", String(collapsed));
  bar.tabIndex = 0;
  bar.title = `Drag to resize the ${label}; double-click to hide or show it`;
  bar.innerHTML = `<button type="button" class="ng-splitter-btn" aria-label="Hide or show the ${label}"><i class="bi"></i></button>`;
  const btn = bar.querySelector("button");
  if (side === "left") panel.after(bar);
  else panel.before(bar);

  const saved = store.get(key) || {};
  const limit = () => Math.max(min, Number(typeof max === "function" ? max() : max));
  const savedWidth = Number(saved.width);
  let width = Number.isFinite(savedWidth) && savedWidth >= min ? savedWidth : initial;
  width = Math.min(limit(), Math.max(min, width));
  let open = typeof saved.open === "boolean" ? saved.open : initialOpen;

  const wide = window.matchMedia(`(min-width: ${breakpoint}px)`);
  let renderedState = "";
  function render() {
    const effectiveWidth = Math.round(Math.min(limit(), Math.max(min, width)));
    const effectiveOpen = wide.matches ? open : narrow ? narrow(open) : open;
    const signature = `${wide.matches}:${effectiveOpen}:${effectiveWidth}:${Math.round(limit())}`;
    if (signature === renderedState) return;
    renderedState = signature;
    bar.hidden = !wide.matches;
    if (wide.matches) apply(effectiveOpen ? effectiveWidth : collapsed, effectiveOpen);
    else reset(effectiveOpen);
    bar.classList.toggle("collapsed", !effectiveOpen);
    bar.setAttribute("aria-valuemax", String(Math.round(limit())));
    bar.setAttribute("aria-valuenow", String(effectiveOpen ? Math.round(effectiveWidth) : collapsed));
    bar.setAttribute("aria-valuetext", effectiveOpen ? `${Math.round(effectiveWidth)} pixels` : "Collapsed");
    const pointsLeft = (side === "left") === effectiveOpen;
    btn.querySelector("i").className = `bi ${pointsLeft ? "bi-chevron-left" : "bi-chevron-right"}`;
    btn.title = effectiveOpen ? `Hide the ${label}` : `Show the ${label}`;
    btn.setAttribute("aria-label", btn.title);
    btn.setAttribute("aria-expanded", String(effectiveOpen));
    onChange(effectiveOpen, effectiveWidth);
    document.dispatchEvent(new CustomEvent("netguard:layout-changed"));
  }
  const save = () => store.set(key, { width: Math.round(width), open });
  const setOpen = (next) => {
    open = next;
    render();
    save();
  };
  const toggle = () => setOpen(!open);

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    toggle();
  });
  bar.addEventListener("dblclick", (event) => {
    if (!event.target.closest("button")) toggle();
  });
  bar.addEventListener("keydown", (e) => {
    if (e.target !== bar) return;
    const step = e.shiftKey ? 48 : 16;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle();
    } else if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const grow = (e.key === "ArrowRight") === (side === "left");
      width = Math.min(limit(), Math.max(min, (open ? panel.getBoundingClientRect().width : min) + (grow ? step : -step)));
      open = true;
      render();
      save();
    } else if (e.key === "Home" || e.key === "End") {
      e.preventDefault();
      width = e.key === "Home" ? min : limit();
      open = true;
      render();
      save();
    }
  });
  bar.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button") || e.button !== 0) return;
    e.preventDefault();
    bar.setPointerCapture(e.pointerId);
    bar.classList.add("dragging");
    document.body.classList.add("ng-resizing");
    const startX = e.clientX;
    const startW = open ? panel.getBoundingClientRect().width : collapsed;
    const move = (ev) => {
      const dx = ev.clientX - startX;
      const w = side === "left" ? startW + dx : startW - dx;
      if (w < Math.max(collapsed, min * 0.55)) {
        open = false;
      } else {
        open = true;
        width = Math.min(limit(), Math.max(min, w));
      }
      render();
    };
    const up = () => {
      bar.classList.remove("dragging");
      document.body.classList.remove("ng-resizing");
      bar.removeEventListener("pointermove", move);
      bar.removeEventListener("pointerup", up);
      bar.removeEventListener("pointercancel", up);
      bar.removeEventListener("lostpointercapture", up);
      if (bar.hasPointerCapture(e.pointerId)) bar.releasePointerCapture(e.pointerId);
      save();
    };
    bar.addEventListener("pointermove", move);
    bar.addEventListener("pointerup", up);
    bar.addEventListener("pointercancel", up);
    bar.addEventListener("lostpointercapture", up);
  });
  wide.addEventListener("change", () => render());
  window.addEventListener("resize", render);
  render();
  return { toggle, bar, show: () => setOpen(true), hide: () => setOpen(false), refresh: render, isOpen: () => open };
}

/** A flex item panel (topology device panel). */
export function flexPanel(panel, key, side, { min = 280, max = 760, initial = 380, label = "panel", onChange = () => {} } = {}) {
  return makeSplitter({
    panel, key, side, min, max, initial, label, onChange,
    apply(width, open) {
      panel.style.flex = `0 0 ${width}px`;
      panel.style.width = `${width}px`;
      panel.style.display = open ? "" : "none";
    },
    reset(open) {
      panel.style.flex = panel.style.width = "";
      panel.style.display = open ? "" : "none";
    },
  });
}

/** The left navigation menu: narrower down to icons only, wider up to 360 px. */
export function navPanel(sidebar) {
  return makeSplitter({
    panel: sidebar, key: "nav", side: "left", min: 184,
    max: () => {
      const details = document.getElementById("side-panel");
      const rightWidth = window.innerWidth >= 1024 && details?.offsetParent ? details.getBoundingClientRect().width + 8 : 0;
      return Math.min(360, window.innerWidth - rightWidth - 360 - 8);
    },
    initial: 228, collapsed: 64, label: "menu", breakpoint: 768,
    initialOpen: window.innerWidth >= 1200,
    narrow: () => false,
    apply(width, open) {
      document.documentElement.style.setProperty("--ng-sidebar-width", `${width}px`);
      document.body.classList.toggle("ng-nav-compact", !open);
    },
    reset() {
      document.documentElement.style.setProperty("--ng-sidebar-width", "64px");
      document.body.classList.add("ng-nav-compact");
    },
    onChange(open) {
      const toggle = document.getElementById("ng-nav-toggle");
      if (!toggle) return;
      toggle.setAttribute("aria-expanded", String(open));
      toggle.title = open ? "Collapse menu" : "Expand menu";
      toggle.setAttribute("aria-label", toggle.title);
      toggle.querySelector("span").textContent = toggle.title;
      toggle.querySelector("i").className = `bi ${open ? "bi-chevron-left" : "bi-chevron-right"}`;
    },
  });
}
