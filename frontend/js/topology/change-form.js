// "Propose Network Change" modal (brief 6.2). Builds the form for the selected
// category / change type, shows the current value and submits the change for
// analysis. The same form is reused to modify a change and re-analyse it.

import { api } from "../api.js";
import { CATEGORY_LABELS } from "../risk.js";
import { escapeHtml, formatIp, showFormError, withBusy } from "../ui.js";
import { store } from "./store.js";

const L3 = ["router", "firewall"];
const ENDPOINTS = ["pc", "server", "internet"];
const INFRA = ["router", "firewall", "switch"];
const routing = (d) => L3.includes(d.device_type) || Boolean(d.config_facts?.ip_routing);

const TYPES = {
  ip_address: { category: "ip_interface", label: "IP Address", target: "interface", devices: [...L3, ...ENDPOINTS, "switch"],
    interfaces: (d) => d.interfaces.filter((i) => d.device_type !== "switch" || (routing(d) && (i.ip_address || /^vlan/i.test(i.name)))) },
  default_gateway: { category: "ip_interface", label: "Default Gateway", target: "device", devices: ["pc", "server"] },
  interface_status: { category: "ip_interface", label: "Interface Status", target: "interface",
    devices: [...L3, ...ENDPOINTS, "switch"], interfaces: (d) => d.interfaces },
  interface_settings: { category: "ip_interface", label: "Speed / Duplex / MTU / OSPF Timers", target: "interface",
    devices: INFRA, interfaces: (d) => d.interfaces },
  ospf_area: { category: "routing", label: "OSPF Area", target: "interface", devices: INFRA, when: routing,
    interfaces: (d) => d.interfaces.filter((i) => i.ip_address) },
  ospf_network: { category: "routing", label: "OSPF Network", target: "interface", devices: INFRA, when: routing,
    interfaces: (d) => d.interfaces.filter((i) => i.ip_address) },
  static_route: { category: "routing", label: "Static Route", target: "device", devices: INFRA, when: routing },
  acl_add: { category: "acl", label: "Add ACL Rule", target: "device", devices: INFRA, when: routing },
  acl_remove: { category: "acl", label: "Remove ACL Rule", target: "device", devices: INFRA, when: routing },
  access_vlan: { category: "vlan", label: "Access VLAN", target: "interface", devices: ["switch"],
    interfaces: (d) => d.interfaces.filter((i) => (i.mode || (i.vlan_id ? "access" : "trunk")) === "access") },
  vlan_database: { category: "vlan", label: "VLAN Database", target: "device", devices: ["switch"] },
  trunk_settings: { category: "vlan", label: "Trunk Settings", target: "interface", devices: ["switch"],
    interfaces: (d) => d.interfaces.filter((i) => (i.mode || (i.vlan_id ? "access" : "trunk")) === "trunk") },
  stp_root: { category: "vlan", label: "Spanning-Tree Root", target: "device", devices: ["switch"] },
  mgmt_hardening: { category: "security", label: "Management Hardening", target: "device", devices: INFRA },
};

const protoOptions = ["ip", "tcp", "udp", "icmp"].map((p) => [p, p.toUpperCase()]);

function input(name, label, { col = 4, type = "text", placeholder = "", mono = false, min, max } = {}) {
  return `<div class="col-md-${col}" data-chg-field="${name}"><label class="form-label" for="chg-${name}">${label}</label>
    <input class="form-control ${mono ? "mono" : ""}" id="chg-${name}" name="${name}" type="${type}"
      ${placeholder ? `placeholder="${escapeHtml(placeholder)}"` : ""} ${min !== undefined ? `min="${min}"` : ""} ${max !== undefined ? `max="${max}"` : ""}></div>`;
}

function select(name, label, options, { col = 4 } = {}) {
  return `<div class="col-md-${col}" data-chg-field="${name}"><label class="form-label" for="chg-${name}">${label}</label>
    <select class="form-select" id="chg-${name}" name="${name}">${options
      .map(([v, l]) => `<option value="${escapeHtml(v)}">${escapeHtml(l)}</option>`)
      .join("")}</select></div>`;
}

const routeText = (r) => `${r.destination} via ${r.next_hop}`;
const aclText = (r) => `${r.sequence} ${r.action} ${r.protocol} ${r.source} ${r.destination}${r.port ? ` eq ${r.port}` : ""}`;

/** Field markup, current value text and prefill values per change type. */
const FORMS = {
  ip_address: {
    fields: () => input("ip_address", "New IP Address", { mono: true, placeholder: "e.g. 192.168.40.1" }) +
      input("subnet_mask", "Subnet Mask", { mono: true, placeholder: "e.g. 255.255.255.0 or /24" }),
    current: (d, i) => (i?.ip_address ? formatIp(i.ip_address, i.subnet_mask) : "Not set"),
    prefill: (d, i) => ({ ip_address: i?.ip_address, subnet_mask: i?.subnet_mask }),
  },
  default_gateway: {
    fields: () => input("gateway", "New Default Gateway", { mono: true, placeholder: "e.g. 10.20.0.1" }),
    current: (d) => d.default_gateway || "None",
    prefill: (d) => ({ gateway: d.default_gateway }),
  },
  interface_status: {
    fields: () => select("status", "New Status", [["up", "Up"], ["down", "Down"], ["admin-down", "Admin down"]]),
    current: (d, i) => i?.status || "—",
    prefill: (d, i) => ({ status: i?.status === "up" ? "admin-down" : "up" }),
  },
  ospf_area: {
    fields: () => input("area", "Proposed OSPF Area", { type: "number", min: 0, max: 65535, placeholder: "e.g. 1" }),
    current: (d, i) => (i && i.ospf_area !== null && i.ospf_area !== undefined ? `Area ${i.ospf_area}` : "Not in OSPF"),
    prefill: () => ({}),
  },
  ospf_network: {
    fields: () => select("action", "Action", [["remove", "Remove network from OSPF"], ["advertise", "Advertise network in OSPF"]], { col: 6 }) +
      input("area", "Area", { type: "number", min: 0, max: 65535, col: 3, placeholder: "0" }),
    current: (d, i) => (i && i.ospf_area !== null && i.ospf_area !== undefined ? `Advertised in Area ${i.ospf_area}` : "Not advertised"),
    prefill: (d, i) => ({ action: i && i.ospf_area !== null && i.ospf_area !== undefined ? "remove" : "advertise", area: 0 }),
    visible: (v) => ({ area: v.action === "advertise" }),
  },
  static_route: {
    fields: (d) => select("action", "Action", [["add", "Add route"], ["modify", "Modify route"], ["remove", "Remove route"]], { col: 3 }) +
      select("route_id", "Existing Route", d.static_routes.map((r) => [String(r.id), routeText(r)]), { col: 5 }) +
      input("destination", "Destination", { mono: true, col: 4, placeholder: "e.g. 0.0.0.0/0" }) +
      input("next_hop", "Next Hop", { mono: true, col: 4, placeholder: "e.g. 10.0.12.2" }),
    current: (d, i, v) => {
      if (v.action === "add") return v.destination ? `No static route to ${v.destination}` : "—";
      const route = d.static_routes.find((r) => String(r.id) === String(v.route_id));
      return route ? routeText(route) : "No static routes";
    },
    prefill: (d) => {
      const route = d.static_routes[0];
      return route ? { action: "modify", route_id: route.id, destination: route.destination, next_hop: route.next_hop } : { action: "add" };
    },
    visible: (v) => ({ route_id: v.action !== "add", destination: v.action !== "remove", next_hop: v.action !== "remove" }),
    onChange: (d, v, set) => {
      const route = d.static_routes.find((r) => String(r.id) === String(v.route_id));
      if (route && v.action === "modify") set({ destination: route.destination, next_hop: route.next_hop });
    },
  },
  interface_settings: {
    fields: () => input("speed", "Speed (Mb/s)", { type: "number", min: 10, col: 3, placeholder: "unchanged" }) +
      select("duplex", "Duplex", [["", "Unchanged"], ["full", "Full"], ["half", "Half"], ["auto", "Auto"]], { col: 3 }) +
      input("mtu", "MTU", { type: "number", min: 576, max: 9216, col: 2, placeholder: "unchanged" }) +
      input("ospf_hello", "OSPF hello (s)", { type: "number", min: 1, col: 2, placeholder: "—" }) +
      input("ospf_dead", "OSPF dead (s)", { type: "number", min: 1, col: 2, placeholder: "—" }),
    current: (d, i) => (i ? `${i.speed_mbps ? `${i.speed_mbps} Mb/s` : "speed default"}, ${i.duplex || "duplex default"}, MTU ${i.mtu || "default"}${i.ospf_area !== null && i.ospf_area !== undefined ? `, OSPF ${i.ospf_hello || 10}/${i.ospf_dead || (i.ospf_hello || 10) * 4} s` : ""}` : "—"),
    prefill: () => ({}),
  },
  trunk_settings: {
    fields: () => input("native_vlan", "Native VLAN", { type: "number", min: 1, max: 4094, col: 3, placeholder: "unchanged" }) +
      input("allowed_vlans", "Allowed VLANs", { col: 9, mono: true, placeholder: "e.g. 10,20-30 or all (blank = unchanged)" }),
    current: (d, i) => (i ? `native VLAN ${i.native_vlan || 1}, allowed ${i.allowed_vlans ? i.allowed_vlans.join(",") : "all"}` : "—"),
    prefill: () => ({}),
  },
  stp_root: {
    fields: (d) => select("vlan", "VLAN", d.vlans.map((v) => [String(v.vlan_id), `VLAN ${v.vlan_id}${v.name ? ` (${v.name})` : ""}`]), { col: 6 }) +
      select("priority", "Bridge priority", [["4096", "4096 (root)"], ["0", "0"], ["8192", "8192 (secondary root)"]], { col: 6 }),
    current: (d) => `spanning-tree ${d.config_facts?.stp_mode || "default"}`,
    prefill: (d) => ({ vlan: d.vlans[0]?.vlan_id, priority: "4096" }),
  },
  mgmt_hardening: {
    fields: () => select("hardening", "Hardening", [["secure_management", "SSH only and no HTTP server"], ["restrict_vty", "Restrict VTY access-class"],
      ["remove_snmp_communities", "Remove SNMPv1/v2c communities"], ["secure_passwords", "Encrypt passwords (scrypt)"]], { col: 6 }) +
      input("permit", "Management subnet", { mono: true, col: 6, placeholder: "e.g. 10.0.99.0/24" }),
    current: (d) => (d.config_facts ? "Configuration collected" : "No configuration collected"),
    prefill: () => ({ hardening: "secure_management" }),
    visible: (v) => ({ permit: v.hardening === "restrict_vty" }),
  },
  acl_add: {
    fields: (d) => select("acl_name", "Access list", [["", "Device rule list (all routed traffic)"],
      ...[...new Set(d.acl_rules.map((r) => r.acl_name).filter(Boolean))].map((n) => [n, n])], { col: 4 }) +
      input("sequence", "Sequence", { type: "number", min: 1, max: 9999, col: 2 }) +
      select("acl_action", "Action", [["deny", "Deny"], ["permit", "Permit"]], { col: 2 }) +
      select("protocol", "Protocol", protoOptions, { col: 2 }) +
      input("port", "Port", { type: "number", min: 1, max: 65535, col: 2, placeholder: "any" }) +
      input("source", "Source", { mono: true, col: 6, placeholder: "any, host IP or 10.20.0.0/24" }) +
      input("destination", "Destination", { mono: true, col: 6, placeholder: "any, host IP or network" }),
    current: (d) => (d.acl_rules.length ? `${d.acl_rules.length} rule(s): ${d.acl_rules.map(aclText).join("; ")}` : "No ACL (all traffic permitted)"),
    prefill: (d) => {
      const name = d.acl_rules.find((r) => r.acl_name)?.acl_name || "";
      const used = new Set(d.acl_rules.filter((r) => (r.acl_name || "") === name).map((r) => r.sequence));
      let seq = 10;
      while (used.has(seq)) seq += 10;
      return { acl_name: name, sequence: seq, acl_action: "deny", protocol: "tcp", source: "any", destination: "any" };
    },
    visible: (v) => ({ port: v.protocol === "tcp" || v.protocol === "udp" }),
  },
  acl_remove: {
    fields: (d) => select("rule_id", "Rule to Remove", d.acl_rules.map((r) => [String(r.id), aclText(r)]), { col: 8 }),
    current: (d, i, v) => {
      const rule = d.acl_rules.find((r) => String(r.id) === String(v.rule_id));
      return rule ? aclText(rule) : "No ACL rules";
    },
    prefill: (d) => ({ rule_id: d.acl_rules[0]?.id }),
  },
  access_vlan: {
    fields: (d) => input("vlan_id", "Proposed Access VLAN", { type: "number", min: 1, max: 4094, placeholder: "e.g. 20" }) +
      `<div class="col-md-8 small text-muted-ng align-self-end pb-2">Defined on ${escapeHtml(d.name)}: ${
        d.vlans.map((v) => `VLAN ${v.vlan_id}${v.name ? ` (${escapeHtml(v.name)})` : ""}`).join(", ") || "none"}</div>`,
    current: (d, i) => (i?.vlan_id ? `VLAN ${i.vlan_id}` : "No VLAN"),
    prefill: () => ({}),
  },
  vlan_database: {
    fields: () => select("action", "Action", [["add", "Create VLAN"], ["remove", "Delete VLAN"]], { col: 3 }) +
      input("vlan_id", "VLAN ID", { type: "number", min: 1, max: 4094, col: 3 }) +
      input("name", "Name", { col: 6, placeholder: "e.g. GUEST" }),
    current: (d) => (d.vlans.length ? d.vlans.map((v) => `VLAN ${v.vlan_id}`).join(", ") : "No VLANs"),
    prefill: () => ({ action: "add" }),
    visible: (v) => ({ name: v.action === "add" }),
  },
};

/** Convert form values into the API parameters for a change type. */
function toParameters(type, v) {
  const num = (x) => (x === null || x === "" || x === undefined ? null : Number(x));
  switch (type) {
    case "ip_address": return { ip_address: v.ip_address, subnet_mask: v.subnet_mask };
    case "default_gateway": return { gateway: v.gateway };
    case "interface_status": return { status: v.status };
    case "ospf_area": return { area: v.area };
    case "ospf_network": return { action: v.action, area: num(v.area) ?? 0 };
    case "static_route": return { action: v.action, route_id: num(v.route_id), destination: v.destination, next_hop: v.next_hop };
    case "acl_add": return { acl_name: v.acl_name || null, sequence: num(v.sequence), action: v.acl_action, protocol: v.protocol,
      source: v.source || "any", destination: v.destination || "any", port: v.protocol === "tcp" || v.protocol === "udp" ? num(v.port) : null };
    case "interface_settings": {
      const out = {};
      ["speed", "mtu", "ospf_hello", "ospf_dead"].forEach((k) => { if (num(v[k]) !== null) out[k] = num(v[k]); });
      if (v.duplex) out.duplex = v.duplex;
      return out;
    }
    case "trunk_settings": {
      const out = {};
      if (num(v.native_vlan) !== null) out.native_vlan = num(v.native_vlan);
      const text = (v.allowed_vlans || "").trim();
      if (text === "all") out.allowed_vlans = "all";
      else if (text) out.allowed_vlans = text.split(",").flatMap((part) => {
        const [a, b] = part.split("-").map((x) => Number(x.trim()));
        return b ? Array.from({ length: Math.max(0, b - a + 1) }, (_, k) => a + k) : [a];
      }).filter((x) => Number.isInteger(x));
      return out;
    }
    case "stp_root": return { vlan: num(v.vlan), priority: num(v.priority) };
    case "mgmt_hardening": return v.hardening === "restrict_vty" ? { action: v.hardening, permit: v.permit } : { action: v.hardening };
    case "acl_remove": return { rule_id: num(v.rule_id) };
    case "access_vlan": return { vlan_id: num(v.vlan_id) };
    case "vlan_database": return { action: v.action, vlan_id: num(v.vlan_id), name: v.name };
    default: return {};
  }
}

/** Convert stored parameters back into form values (for "Modify Change"). */
function fromParameters(type, p) {
  if (type === "acl_add") return { ...p, acl_action: p.action, acl_name: p.acl_name || "" };
  if (type === "mgmt_hardening") return { ...p, hardening: p.action };
  if (type === "trunk_settings") return { ...p, allowed_vlans: Array.isArray(p.allowed_vlans) ? p.allowed_vlans.join(",") : p.allowed_vlans };
  return { ...p };
}

/**
 * @param {object} ctx
 * @param {(change, assessment) => void} ctx.onAnalyzed
 */
export function createChangeForm(ctx) {
  const modalEl = document.getElementById("change-modal");
  const form = document.getElementById("change-form");
  const modal = new bootstrap.Modal(modalEl);
  const categoryEl = document.getElementById("chg-category");
  const typeEl = document.getElementById("chg-type");
  const ifaceWrap = document.getElementById("chg-interface-wrap");
  const ifaceEl = document.getElementById("chg-interface");
  const fieldsEl = document.getElementById("chg-fields");
  const currentEl = document.getElementById("chg-current");
  const reasonEl = document.getElementById("chg-reason");
  let device = null;
  let editing = null; // change being modified

  const values = () => {
    const out = {};
    fieldsEl.querySelectorAll("input, select").forEach((el) => (out[el.name] = el.value.trim() === "" ? null : el.value.trim()));
    return out;
  };
  const setValues = (vals) => {
    Object.entries(vals || {}).forEach(([k, v]) => {
      const el = fieldsEl.querySelector(`[name="${k}"]`);
      if (el && v !== undefined && v !== null) el.value = v;
    });
  };
  const iface = () => device.interfaces.find((i) => String(i.id) === ifaceEl.value);

  function typesFor(category) {
    return Object.entries(TYPES).filter(([, t]) => t.category === category && t.devices.includes(device.device_type) && (!t.when || t.when(device)));
  }

  function refreshVisibility() {
    const spec = FORMS[typeEl.value];
    const visible = spec.visible ? spec.visible(values()) : {};
    fieldsEl.querySelectorAll("[data-chg-field]").forEach((el) => {
      el.classList.toggle("d-none", visible[el.dataset.chgField] === false);
    });
    currentEl.textContent = spec.current(device, iface(), values());
  }

  function renderType(prefill) {
    const type = typeEl.value;
    const meta = TYPES[type];
    const spec = FORMS[type];
    ifaceWrap.classList.toggle("d-none", meta.target !== "interface");
    if (meta.target === "interface") {
      const options = meta.interfaces(device);
      ifaceEl.innerHTML = options.length
        ? options.map((i) => `<option value="${i.id}">${escapeHtml(i.name)}${i.ip_address ? ` (${formatIp(i.ip_address, i.subnet_mask)})` : i.vlan_id ? ` (VLAN ${i.vlan_id})` : ""}</option>`).join("")
        : `<option value="">No suitable interface</option>`;
      if (prefill?.interface_id) ifaceEl.value = String(prefill.interface_id);
    }
    fieldsEl.innerHTML = spec.fields(device);
    setValues(prefill?.values ?? spec.prefill(device, iface()));
    fieldsEl.querySelectorAll("input, select").forEach((el) =>
      el.addEventListener("change", () => {
        if (spec.onChange) spec.onChange(device, values(), setValues);
        refreshVisibility();
      })
    );
    refreshVisibility();
  }

  function renderCategories(selectedCategory) {
    const categories = Object.keys(CATEGORY_LABELS).filter((c) => typesFor(c).length);
    categoryEl.innerHTML = categories.map((c) => `<option value="${c}">${CATEGORY_LABELS[c]}</option>`).join("");
    categoryEl.value = selectedCategory && categories.includes(selectedCategory) ? selectedCategory : categories[0];
  }

  function renderTypes(selectedType) {
    const types = typesFor(categoryEl.value);
    typeEl.innerHTML = types.map(([k, t]) => `<option value="${k}">${t.label}</option>`).join("");
    if (selectedType && types.some(([k]) => k === selectedType)) typeEl.value = selectedType;
  }

  categoryEl.addEventListener("change", () => {
    renderTypes();
    renderType();
  });
  typeEl.addEventListener("change", () => renderType());
  ifaceEl.addEventListener("change", () => {
    setValues(FORMS[typeEl.value].prefill(device, iface()));
    refreshVisibility();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showFormError(form, "");
    const type = typeEl.value;
    const meta = TYPES[type];
    if (meta.target === "interface" && !ifaceEl.value) return showFormError(form, "Select an interface.");
    const payload = {
      device_id: device.id,
      change_type: type,
      interface_id: meta.target === "interface" ? Number(ifaceEl.value) : null,
      parameters: toParameters(type, values()),
      reason: reasonEl.value.trim() || null,
    };
    await withBusy(document.getElementById("change-submit"), async () => {
      try {
        const change = editing ? await api.put(`/changes/${editing.id}`, payload) : await api.post("/changes", payload);
        const assessment = await api.post(`/changes/${change.id}/analyze`);
        modal.hide();
        ctx.onAnalyzed(change, assessment);
      } catch (error) {
        showFormError(form, error.message);
      }
    });
  });

  modalEl.addEventListener("shown.bs.modal", () => fieldsEl.querySelector("input, select")?.focus());

  return {
    open(targetDevice, options = {}) {
      device = targetDevice;
      editing = null;
      document.getElementById("change-modal-title").textContent = "Propose Network Change";
      document.getElementById("chg-device-name").textContent = device.name;
      reasonEl.value = "";
      const meta = options.changeType ? TYPES[options.changeType] : null;
      renderCategories(meta?.category);
      renderTypes(options.changeType);
      renderType(options.interfaceId ? { interface_id: options.interfaceId } : undefined);
      showFormError(form, "");
      modal.show();
    },
    openModify(change) {
      device = store.devices.get(change.device_id);
      if (!device) return false;
      editing = change;
      document.getElementById("change-modal-title").textContent = `Modify Change #${change.id}`;
      document.getElementById("chg-device-name").textContent = device.name;
      reasonEl.value = change.reason || "";
      renderCategories(TYPES[change.change_type].category);
      renderTypes(change.change_type);
      renderType({ interface_id: change.interface_id, values: fromParameters(change.change_type, change.parameters) });
      showFormError(form, "");
      modal.show();
      return true;
    },
  };
}
