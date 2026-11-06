// Device type catalogue: labels, colours and network-style SVG icons.
// Icons are generated as data URIs so Cytoscape and <img> tags share them.

const GLYPHS = {
  // Router: circle with four arrows (classic routing symbol)
  router: `
    <circle cx="32" cy="32" r="27" fill="COLOR"/>
    <ellipse cx="32" cy="32" rx="27" ry="27" fill="none" stroke="#ffffff" stroke-opacity=".25" stroke-width="2"/>
    <g fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M28 28L18 18M18 18h7M18 18v7"/>
      <path d="M36 36l10 10M46 46h-7M46 46v-7"/>
      <path d="M46 18L36 28M36 28h7M36 28v-7"/>
      <path d="M18 46l10-10M28 36h-7M28 36v7"/>
    </g>`,
  // Switch: rounded box with opposing arrows
  switch: `
    <rect x="6" y="14" width="52" height="36" rx="7" fill="COLOR"/>
    <g fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
      <path d="M16 25h26M36 20l6 5-6 5"/>
      <path d="M48 39H22M28 34l-6 5 6 5"/>
    </g>`,
  // Firewall: brick wall
  firewall: `
    <rect x="6" y="10" width="52" height="44" rx="6" fill="COLOR"/>
    <g stroke="#fff" stroke-width="2.4" stroke-opacity=".95" fill="none">
      <path d="M6 21h52M6 32h52M6 43h52"/>
      <path d="M24 10v11M42 10v11M15 21v11M33 21v11M51 21v11M24 32v11M42 32v11M15 43v11M33 43v11M51 43v11"/>
    </g>`,
  // PC: monitor and stand
  pc: `
    <rect x="8" y="10" width="48" height="33" rx="4" fill="COLOR"/>
    <rect x="13" y="15" width="38" height="23" rx="1.5" fill="#fff" fill-opacity=".92"/>
    <path d="M26 43h12l2 7H24z" fill="COLOR"/>
    <rect x="18" y="50" width="28" height="4" rx="2" fill="COLOR"/>`,
  // Server: stacked units with status lights
  server: `
    <rect x="12" y="6" width="40" height="52" rx="5" fill="COLOR"/>
    <g fill="#fff" fill-opacity=".9">
      <rect x="17" y="12" width="30" height="10" rx="2"/>
      <rect x="17" y="27" width="30" height="10" rx="2"/>
      <rect x="17" y="42" width="30" height="10" rx="2"/>
    </g>
    <g fill="COLOR"><circle cx="41" cy="17" r="2"/><circle cx="41" cy="32" r="2"/><circle cx="41" cy="47" r="2"/></g>`,
  // Internet / cloud
  internet: `
    <path d="M18 48h30a11 11 0 0 0 1.5-21.9A15 15 0 0 0 20.6 22 12.5 12.5 0 0 0 18 48z" fill="COLOR"/>
    <g fill="none" stroke="#fff" stroke-width="2.2" stroke-opacity=".95">
      <circle cx="34" cy="35" r="8"/>
      <path d="M26 35h16M34 27c-3 3-3 13 0 16M34 27c3 3 3 13 0 16"/>
    </g>`,
  // Role icons for devices found by a scan (the device type stays one of the six above)
  printer: `
    <rect x="18" y="8" width="28" height="14" rx="2" fill="#fff" stroke="COLOR" stroke-width="3"/>
    <rect x="6" y="20" width="52" height="24" rx="5" fill="COLOR"/>
    <rect x="16" y="36" width="32" height="20" rx="2" fill="#fff" stroke="COLOR" stroke-width="3"/>
    <path d="M22 44h20M22 50h14" stroke="COLOR" stroke-width="2.4"/><circle cx="49" cy="28" r="2.5" fill="#fff"/>`,
  camera: `
    <path d="M8 18l36-6 4 18-36 6z" fill="COLOR"/><circle cx="16" cy="28" r="4" fill="#fff"/>
    <path d="M44 22l10-3 2 10-10 3z" fill="COLOR" fill-opacity=".8"/>
    <path d="M30 34v10H18v8" fill="none" stroke="COLOR" stroke-width="4" stroke-linecap="round"/>`,
  phone: `
    <rect x="10" y="22" width="44" height="34" rx="6" fill="COLOR"/>
    <path d="M14 10c10-5 26-5 36 0l-3 9h-8l-1-4c-4-1-8-1-12 0l-1 4h-8z" fill="COLOR"/>
    <g fill="#fff"><circle cx="22" cy="32" r="2.6"/><circle cx="32" cy="32" r="2.6"/><circle cx="42" cy="32" r="2.6"/>
    <circle cx="22" cy="41" r="2.6"/><circle cx="32" cy="41" r="2.6"/><circle cx="42" cy="41" r="2.6"/>
    <circle cx="22" cy="50" r="2.6"/><circle cx="32" cy="50" r="2.6"/><circle cx="42" cy="50" r="2.6"/></g>`,
  ap: `
    <ellipse cx="32" cy="46" rx="24" ry="9" fill="COLOR"/>
    <g fill="none" stroke="COLOR" stroke-width="3.4" stroke-linecap="round">
      <path d="M22 30a14 14 0 0 1 20 0"/><path d="M15 23a24 24 0 0 1 34 0"/><path d="M8 16a34 34 0 0 1 48 0"/></g>
    <circle cx="32" cy="36" r="3" fill="COLOR"/><circle cx="44" cy="46" r="2" fill="#fff"/>`,
  nas: `
    <rect x="12" y="6" width="40" height="52" rx="5" fill="COLOR"/>
    <g fill="#fff" fill-opacity=".9"><rect x="18" y="12" width="12" height="40" rx="2"/><rect x="34" y="12" width="12" height="40" rx="2"/></g>
    <g fill="COLOR"><circle cx="24" cy="46" r="2"/><circle cx="40" cy="46" r="2"/></g>`,
  laptop: `
    <rect x="12" y="12" width="40" height="28" rx="3" fill="COLOR"/>
    <rect x="16" y="16" width="32" height="20" rx="1.5" fill="#fff" fill-opacity=".92"/>
    <path d="M4 44h56l-4 8H8z" fill="COLOR"/>`,
  unknown: `
    <rect x="8" y="8" width="48" height="48" rx="10" fill="COLOR"/>
    <path d="M25 25a7 7 0 1 1 10 6c-2 1-3 3-3 5v2" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round"/>
    <circle cx="32" cy="46" r="2.8" fill="#fff"/>`,
};

// Colours of the role icons (scan results), next to the six device types.
const ROLE_ICONS = {
  printer: "#6b5b95", camera: "#8a5a2b", phone: "#2f7d4f", ap: "#1d7fa8", nas: "#3d5a80", laptop: "#4a5a70",
  unknown: "#8792a2",
};

export const DEVICE_TYPES = {
  router: { label: "Router", color: "#1f6fb2", icon: "bi-router" },
  switch: { label: "Switch", color: "#12817f", icon: "bi-hdd-network" },
  firewall: { label: "Firewall", color: "#5a4bb0", icon: "bi-bricks" },
  pc: { label: "PC", color: "#4a5a70", icon: "bi-pc-display" },
  server: { label: "Server", color: "#2c4a72", icon: "bi-hdd-stack" },
  internet: { label: "Internet / Cloud", short: "Internet", color: "#3a8ad4", icon: "bi-cloud" },
};

export const DEVICE_TYPE_KEYS = Object.keys(DEVICE_TYPES);

const iconCache = new Map();

export function deviceIcon(type) {
  if (!iconCache.has(type)) {
    const color = DEVICE_TYPES[type]?.color || ROLE_ICONS[type] || DEVICE_TYPES.pc.color;
    const glyph = (GLYPHS[type] || GLYPHS.pc).replaceAll("COLOR", color);
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">${glyph}</svg>`;
    iconCache.set(type, `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`);
  }
  return iconCache.get(type);
}

export function deviceLabel(type) {
  return DEVICE_TYPES[type]?.label || ({ printer: "Printer", camera: "IP camera", phone: "IP phone", ap: "Access point", laptop: "Laptop", nas: "NAS", guest: "Guest workstation", unknown: "Unknown device" })[type] || type;
}

/** NetGuard logo (shield + nodes) as inline SVG markup. */
export function logoSvg(size = 30) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 32 32" aria-hidden="true">
    <path d="M16 2.5l11 4v8.2c0 7-4.6 12.4-11 14.8C9.6 27.1 5 21.7 5 14.7V6.5z" fill="#2f6fd0"/>
    <path d="M16 2.5l11 4v8.2c0 7-4.6 12.4-11 14.8z" fill="#1f5fbf"/>
    <g stroke="#fff" stroke-width="1.6" fill="none"><path d="M11 12.5l5 6 5-6M16 18.5v4"/></g>
    <g fill="#fff"><circle cx="11" cy="12.5" r="2.2"/><circle cx="21" cy="12.5" r="2.2"/><circle cx="16" cy="18.5" r="2.2"/><circle cx="16" cy="22.8" r="1.6"/></g>
  </svg>`;
}

/** The icon key for a device: its type, or for a device found by a scan the role the scan recognised. */
export function iconKey(device) {
  // "guest" has no glyph of its own; deviceIcon() draws it as a PC while deviceLabel() names it.
  if (device?.role) return device.role;
  const s = device?.scan;
  if (!s || s.segment || device.platform) return device?.device_type || "pc";
  const role = (s.role || "").toLowerCase();
  if (s.self) return "laptop";
  if (role.includes("printer")) return "printer";
  if (role.includes("camera")) return "camera";
  if (role.includes("phone")) return "phone";
  if (role.includes("access point")) return "ap";
  if (role.includes("nas")) return "nas";
  if (["router", "switch", "firewall", "internet"].includes(device.device_type)) return device.device_type;
  if (s.state !== "read" && (s.confidence || "low") === "low" && role === "host") return "unknown";
  return device.device_type;
}

export const deviceIconFor = (device) => deviceIcon(iconKey(device));
