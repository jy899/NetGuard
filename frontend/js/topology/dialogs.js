// Modal dialogs for the topology workspace: device add/edit, device
// configuration (interfaces, VLANs, static routes, ACL), required flows and
// link creation. Each dialog persists through the API and then asks the
// controller to refresh the store/graph.

import { api } from "../api.js";
import { createCrudSection } from "../crud.js";
import { DEVICE_TYPES } from "../device-types.js";
import { flowLabel } from "../risk.js";
import { escapeHtml, fillForm, readForm, showFormError, toast, withBusy } from "../ui.js";
import { interfaceNeighbours, sortedDevices, store, usedInterfaceIds } from "./store.js";

const L3 = ["router", "firewall"];
const HOSTS = ["pc", "server"];

/**
 * @param {object} ctx
 * @param {() => Promise<void>} ctx.refresh        reload store + graph (keeps unsaved positions)
 * @param {() => {x:number,y:number}} ctx.freePosition
 * @param {(deviceId:number) => void} ctx.selectDevice
 * @param {(linkId:number) => void} ctx.selectLink
 */
export function createDialogs(ctx) {
  return {
    device: deviceDialog(ctx),
    config: configDialog(ctx),
    intents: intentDialog(ctx),
    link: linkDialog(ctx),
  };
}

// ---------------------------------------------------------------- device
function deviceDialog(ctx) {
  const modalEl = document.getElementById("device-modal");
  const form = document.getElementById("device-form");
  const modal = new bootstrap.Modal(modalEl);
  const hostOnly = form.querySelector("[data-host-only]");
  let editing = null;

  form.device_type.innerHTML = Object.entries(DEVICE_TYPES)
    .map(([key, meta]) => `<option value="${key}">${meta.label}</option>`)
    .join("");
  const syncHostFields = () => hostOnly.classList.toggle("d-none", !HOSTS.includes(form.device_type.value));
  form.device_type.addEventListener("change", syncHostFields);
  modalEl.addEventListener("shown.bs.modal", () => form.name.focus());

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = readForm(form);
    if (!data.name) return showFormError(form, "Device name is required.");
    if (!HOSTS.includes(data.device_type)) data.default_gateway = null;
    await withBusy(document.getElementById("device-submit"), async () => {
      try {
        let device;
        if (editing) {
          device = await api.put(`/devices/${editing.id}`, data);
          toast(`Device ${device.name} updated`, "success");
        } else {
          const position = ctx.freePosition();
          device = await api.post(`/networks/${store.network.id}/devices`, {
            ...data,
            x_position: position.x,
            y_position: position.y,
          });
          toast(`Device ${device.name} added`, "success");
        }
        modal.hide();
        await ctx.refresh();
        ctx.selectDevice(device.id);
      } catch (error) {
        showFormError(form, error.message);
      }
    });
  });

  return {
    openCreate(type = "router") {
      editing = null;
      document.getElementById("device-modal-title").textContent = "Add Device";
      fillForm(form, { device_type: type });
      syncHostFields();
      showFormError(form, "");
      modal.show();
    },
    openEdit(device) {
      editing = device;
      document.getElementById("device-modal-title").textContent = `Edit Device — ${device.name}`;
      fillForm(form, device);
      syncHostFields();
      showFormError(form, "");
      modal.show();
    },
  };
}

// --------------------------------------------------------- configuration
function configDialog(ctx) {
  const modalEl = document.getElementById("config-modal");
  const modal = new bootstrap.Modal(modalEl);
  const tabsEl = document.getElementById("config-tabs");
  const panesEl = document.getElementById("config-panes");
  let deviceId = null;
  let sections = [];

  const device = () => store.devices.get(deviceId);
  const statusOptions = [
    { value: "up", label: "Up" },
    { value: "down", label: "Down" },
    { value: "admin-down", label: "Admin down" },
  ];

  /** "10,20-22" -> [10, 20, 21, 22]; an unreadable entry is reported instead of being dropped silently. */
  function parseVlanList(text) {
    const vlans = new Set();
    for (const token of String(text).split(",").map((x) => x.trim()).filter(Boolean)) {
      const match = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(token);
      const low = match ? Number(match[1]) : NaN;
      const high = match && match[2] !== undefined ? Number(match[2]) : low;
      if (!match || low < 1 || high > 4094 || low > high) throw new Error(`Allowed VLANs: "${token}" is not a VLAN ID or range within 1–4094.`);
      for (let vlan = low; vlan <= high; vlan += 1) vlans.add(vlan);
    }
    return [...vlans].sort((a, b) => a - b);
  }

  /** [10, 20, 21, 22] -> "10,20-22" (an empty list means no VLAN is allowed). */
  function compactVlans(list) {
    if (!list.length) return "none";
    const parts = [];
    let start = list[0], previous = list[0];
    for (const vlan of [...list.slice(1), null]) {
      if (vlan === previous + 1) { previous = vlan; continue; }
      parts.push(start === previous ? `${start}` : `${start}-${previous}`);
      start = previous = vlan;
    }
    return parts.join(",");
  }

  function interfaceSpec(dev) {
    const isSwitch = dev.device_type === "switch";
    const isL3 = L3.includes(dev.device_type);
    const neighbours = () => interfaceNeighbours(dev.id);
    const fields = [
      { name: "name", label: "Name", required: true, col: 2, placeholder: "e.g. Gi0/0/0" },
      { name: "description", label: "Description", col: 6, maxLength: 120, placeholder: "Adapter name or port role" },
      ...(isSwitch
        ? [
            { name: "mode", label: "Mode", type: "select", col: 2, options: [{ value: "access", label: "Access" }, { value: "trunk", label: "Trunk" }] },
            { name: "vlan_id", label: "Access VLAN", type: "number", min: 1, max: 4094, col: 2, placeholder: "1–4094",
              visible: (v) => v.mode !== "trunk" },
            { name: "native_vlan", label: "Native VLAN", type: "number", min: 1, max: 4094, col: 2, placeholder: "1",
              visible: (v) => v.mode === "trunk" },
            { name: "allowed_vlans", label: "Allowed VLANs", col: 3, mono: true, placeholder: "e.g. 10,20-30 (empty = all)",
              visible: (v) => v.mode === "trunk" },
            { name: "stp_state", label: "STP State", type: "select", col: 2,
              options: [
                { value: "", label: "—" },
                { value: "forwarding", label: "Forwarding" },
                { value: "blocking", label: "Blocking" },
                { value: "discarding", label: "Discarding" },
                { value: "learning", label: "Learning" },
                { value: "disabled", label: "Disabled" },
              ] },
          ]
        : [
            { name: "ip_address", label: "IP Address", col: 3, mono: true, placeholder: "e.g. 10.0.12.1" },
            { name: "subnet_mask", label: "Subnet Mask", col: 2, mono: true, placeholder: "e.g. /30" },
            { name: "vlan_id", label: isL3 ? "802.1Q VLAN" : "VLAN ID", type: "number", min: 1, max: 4094, col: isL3 ? 1 : 2, placeholder: "—" },
          ]),
      ...(isL3 ? [{ name: "ospf_area", label: "OSPF Area", type: "number", min: 0, max: 65535, col: 1, placeholder: "—" }] : []),
      { name: "speed_mbps", label: "Speed (Mbps)", type: "number", min: 10, max: 100000, col: 2, placeholder: "e.g. 1000" },
      { name: "status", type: "select", label: "Status", col: 2, options: statusOptions },
    ];
    const columns = [
      { label: "Name", render: (i) => `<strong>${escapeHtml(i.name)}</strong>${i.description ? `<div class="small text-muted-ng">${escapeHtml(i.description)}</div>` : ""}` },
      ...(isSwitch
        ? [
            { label: "Mode", render: (i) => escapeHtml(i.mode || (i.vlan_id ? "access" : "trunk")) },
            { label: "VLAN / Trunk", render: (i) => (i.mode === "trunk"
              ? `<span class="small">Native ${i.native_vlan ?? 1}${i.allowed_vlans ? ` · VLANs ${escapeHtml(compactVlans(i.allowed_vlans))}` : ""}${i.stp_state ? ` · STP ${escapeHtml(i.stp_state)}` : ""}</span>`
              : (i.vlan_id ?? "—") + (i.stp_state ? ` <span class="small text-muted-ng">(STP ${escapeHtml(i.stp_state)})</span>` : "")) },
          ]
        : [
            { label: "IP Address", render: (i) => `<span class="mono">${escapeHtml(i.ip_address || "—")}</span>` },
            { label: "Mask", render: (i) => `<span class="mono">${escapeHtml(i.subnet_mask || "—")}</span>` },
            { label: "VLAN", render: (i) => i.vlan_id ?? "—" },
          ]),
      ...(isL3 ? [{ label: "OSPF", render: (i) => (i.ospf_area !== null && i.ospf_area !== undefined ? `Area ${i.ospf_area}` : "—") }] : []),
      { label: "Status", render: (i) => `<span class="ng-status ${escapeHtml(i.status)}">${escapeHtml(i.status.replace("-", " "))}</span>` },
      { label: "Connected To", render: (i) => escapeHtml(neighbours().get(i.id) || "—") },
    ];
    return {
      key: "interfaces", title: "Interfaces", idPrefix: "if", noun: "Interface", columns, fields,
      help: isL3 ? "Mask accepts 255.255.255.0 or /24. Sub-interfaces (Gi0/0/1.10) need an 802.1Q VLAN." : isSwitch ? "Trunks carry every VLAN defined on the switch." : "Mask accepts 255.255.255.0 or /24.",
      items: () => device().interfaces,
      defaults: () => ({ status: "up", mode: "access" }),
      describe: (i) => i.name,
      createUrl: () => `/devices/${deviceId}/interfaces`,
      updateUrl: (i) => `/interfaces/${i.id}`,
      deleteUrl: (i) => `/interfaces/${i.id}`,
      toPayload: (v) => ({
        name: v.name, description: v.description ?? null, ip_address: v.ip_address ?? null, subnet_mask: v.subnet_mask ?? null,
        vlan_id: isSwitch && v.mode === "trunk" ? null : v.vlan_id ?? null, status: v.status || "up",
        ospf_area: v.ospf_area ?? null, mode: isSwitch ? v.mode : null,
        speed_mbps: v.speed_mbps ?? null,
        ...(isSwitch ? {
          native_vlan: v.mode === "trunk" ? (v.native_vlan ?? null) : null,
          allowed_vlans: v.mode === "trunk" && v.allowed_vlans ? parseVlanList(v.allowed_vlans) : null,
          stp_state: v.stp_state || null,
        } : {}),
      }),
      deleteMessage: (i) => {
        const linked = neighbours().get(i.id);
        return `<p>Delete interface <strong>${escapeHtml(i.name)}</strong> from ${escapeHtml(device().name)}?</p>${
          linked ? `<p class="small text-muted mb-0">It is connected to ${escapeHtml(linked)}. The link is kept but will no longer reference this interface.</p>` : ""}`;
      },
    };
  }

  const vlanSpec = () => ({
    key: "vlans", title: "VLANs", idPrefix: "vlan", noun: "VLAN",
    columns: [
      { label: "VLAN ID", render: (v) => `<strong>${v.vlan_id}</strong>` },
      { label: "Name", render: (v) => escapeHtml(v.name || "—") },
    ],
    fields: [
      { name: "vlan_id", label: "VLAN ID", type: "number", min: 1, max: 4094, required: true, col: 3 },
      { name: "name", label: "Name", col: 5, maxLength: 32, placeholder: "e.g. FINANCE" },
    ],
    help: "Access ports can only use VLANs defined here.",
    items: () => device().vlans, describe: (v) => `${v.vlan_id}`,
    createUrl: () => `/devices/${deviceId}/vlans`, updateUrl: (v) => `/vlans/${v.id}`, deleteUrl: (v) => `/vlans/${v.id}`,
  });

  const routeSpec = () => ({
    key: "routes", title: "Static Routes", idPrefix: "route", noun: "Static route", plural: "static routes",
    columns: [
      { label: "Destination", render: (r) => `<span class="mono">${escapeHtml(r.destination)}</span>` },
      { label: "Next Hop", render: (r) => `<span class="mono">${escapeHtml(r.next_hop)}</span>` },
    ],
    fields: [
      { name: "destination", label: "Destination", required: true, col: 4, mono: true, placeholder: "e.g. 0.0.0.0/0" },
      { name: "next_hop", label: "Next Hop", required: true, col: 4, mono: true, placeholder: "e.g. 10.0.1.1" },
    ],
    help: "Static routes win over OSPF on an equal prefix length.",
    items: () => device().static_routes, describe: (r) => r.destination,
    createUrl: () => `/devices/${deviceId}/static-routes`, updateUrl: (r) => `/static-routes/${r.id}`, deleteUrl: (r) => `/static-routes/${r.id}`,
  });

  const aclSpec = () => ({
    key: "acl", title: "ACL", idPrefix: "acl", noun: "ACL rule",
    columns: [
      { label: "Seq", render: (r) => `<strong>${r.sequence}</strong>` },
      { label: "Action", render: (r) => `<span class="${r.action === "deny" ? "text-danger" : "text-success"} fw-semibold">${escapeHtml(r.action)}</span>` },
      { label: "Protocol", render: (r) => escapeHtml(r.protocol) },
      { label: "Source", render: (r) => `<span class="mono">${escapeHtml(r.source)}</span>` },
      { label: "Destination", render: (r) => `<span class="mono">${escapeHtml(r.destination)}</span>` },
      { label: "Port", render: (r) => r.port ?? "any" },
    ],
    fields: [
      { name: "sequence", label: "Seq", type: "number", min: 1, max: 9999, required: true, col: 1 },
      { name: "action", label: "Action", type: "select", col: 2, options: [{ value: "permit", label: "Permit" }, { value: "deny", label: "Deny" }] },
      { name: "protocol", label: "Protocol", type: "select", col: 2,
        options: ["ip", "tcp", "udp", "icmp"].map((p) => ({ value: p, label: p.toUpperCase() })) },
      { name: "source", label: "Source", col: 2, mono: true, placeholder: "any" },
      { name: "destination", label: "Destination", col: 3, mono: true, placeholder: "any" },
      { name: "port", label: "Port", type: "number", min: 1, max: 65535, col: 2, placeholder: "any",
        visible: (v) => v.protocol === "tcp" || v.protocol === "udp" },
    ],
    help: "Applies to all traffic routed through the device. First match wins; an implicit deny follows the last rule.",
    items: () => device().acl_rules, describe: (r) => `seq ${r.sequence}`,
    defaults: () => ({ action: "deny", protocol: "ip", source: "any", destination: "any" }),
    createUrl: () => `/devices/${deviceId}/acl-rules`, updateUrl: (r) => `/acl-rules/${r.id}`, deleteUrl: (r) => `/acl-rules/${r.id}`,
    toPayload: (v) => ({ ...v, source: v.source || "any", destination: v.destination || "any",
      port: v.protocol === "tcp" || v.protocol === "udp" ? v.port : null }),
  });

  function build(tab) {
    const dev = device();
    const specs = [interfaceSpec(dev)];
    if (dev.device_type === "switch") specs.push(vlanSpec());
    if (L3.includes(dev.device_type)) specs.push(routeSpec(), aclSpec());
    tabsEl.innerHTML = specs
      .map((s, i) => `<li class="nav-item" role="presentation"><button class="nav-link ${s.key === tab || (!tab && i === 0) ? "active" : ""}"
        data-bs-toggle="tab" data-bs-target="#config-pane-${s.key}" type="button" role="tab" id="config-tab-${s.key}">${s.title}</button></li>`)
      .join("");
    panesEl.className = "tab-content";
    panesEl.innerHTML = specs
      .map((s, i) => `<div class="tab-pane fade ${s.key === tab || (!tab && i === 0) ? "show active" : ""}" id="config-pane-${s.key}" role="tabpanel"></div>`)
      .join("");
    sections = specs.map((spec) =>
      createCrudSection(document.getElementById(`config-pane-${spec.key}`), {
        ...spec,
        onSaved: async () => {
          await ctx.refresh();
          sections.forEach((s) => s.refresh());
        },
      })
    );
  }

  modalEl.addEventListener("shown.bs.modal", () => sections[0]?.focus());

  return {
    open(id, tab = null) {
      deviceId = id;
      document.getElementById("config-modal-title").textContent = `Configuration — ${device().name}`;
      build(tab);
      modal.show();
    },
  };
}

// ---------------------------------------------------------- required flows
function intentDialog(ctx) {
  const modalEl = document.getElementById("intent-modal");
  const modal = new bootstrap.Modal(modalEl);
  let section = null;
  const deviceOptions = () =>
    sortedDevices()
      .filter((d) => HOSTS.includes(d.device_type) || d.device_type === "internet")
      .map((d) => ({ value: d.id, label: d.name }));
  const name = (id) => escapeHtml(store.devices.get(id)?.name || "?");

  function build() {
    section = createCrudSection(document.getElementById("intent-section"), {
      idPrefix: "intent", noun: "Required flow", plural: "required flows",
      columns: [
        { label: "Name", render: (i) => `<strong>${escapeHtml(i.name)}</strong>` },
        { label: "Flow", render: (i) => `${name(i.source_device_id)} → ${name(i.destination_device_id)}` },
        { label: "Service", render: (i) => `<span class="mono">${escapeHtml(flowLabel(i.protocol, i.port))}</span>` },
        { label: "Expected", render: (i) => `<span class="${i.expected_action === "allow" ? "text-success" : "text-danger"} fw-semibold text-uppercase">${escapeHtml(i.expected_action)}</span>` },
        { label: "Criticality", render: (i) => escapeHtml(i.criticality) },
      ],
      fields: [
        { name: "name", label: "Name", required: true, col: 3, placeholder: "e.g. Finance ERP access" },
        { name: "source_device_id", label: "Source", type: "select", col: 2, options: deviceOptions },
        { name: "destination_device_id", label: "Destination", type: "select", col: 2, options: deviceOptions },
        { name: "protocol", label: "Protocol", type: "select", col: 1,
          options: ["ip", "tcp", "udp", "icmp"].map((p) => ({ value: p, label: p.toUpperCase() })) },
        { name: "port", label: "Port", type: "number", min: 1, max: 65535, col: 1, placeholder: "any",
          visible: (v) => v.protocol === "tcp" || v.protocol === "udp" },
        { name: "expected_action", label: "Expected", type: "select", col: 1, options: [{ value: "allow", label: "Allow" }, { value: "deny", label: "Deny" }] },
        { name: "criticality", label: "Criticality", type: "select", col: 2,
          options: ["critical", "high", "medium", "low"].map((c) => ({ value: c, label: c[0].toUpperCase() + c.slice(1) })) },
      ],
      items: () => store.intents,
      describe: (i) => i.name,
      defaults: () => ({ protocol: "tcp", expected_action: "allow", criticality: "medium" }),
      createUrl: () => `/networks/${store.network.id}/intents`,
      updateUrl: (i) => `/intents/${i.id}`,
      deleteUrl: (i) => `/intents/${i.id}`,
      toPayload: (v) => ({
        ...v,
        source_device_id: Number(v.source_device_id),
        destination_device_id: Number(v.destination_device_id),
        port: v.protocol === "tcp" || v.protocol === "udp" ? v.port : null,
      }),
      onSaved: async () => {
        await ctx.refresh();
        section.refresh();
      },
    });
  }

  return {
    open() {
      if (deviceOptions().length < 2) {
        toast("Add at least two PCs, servers or an Internet cloud before defining required flows.", "warning");
        return;
      }
      build();
      modal.show();
    },
  };
}

// ------------------------------------------------------------------ link
function linkDialog(ctx) {
  const modalEl = document.getElementById("link-modal");
  const form = document.getElementById("link-form");
  const modal = new bootstrap.Modal(modalEl);
  const srcDev = document.getElementById("link-src-dev");
  const dstDev = document.getElementById("link-dst-dev");
  const srcIf = document.getElementById("link-src-if");
  const dstIf = document.getElementById("link-dst-if");

  function deviceOptions(selected) {
    return (
      `<option value="">Select device…</option>` +
      sortedDevices()
        .map((d) => `<option value="${d.id}" ${d.id === selected ? "selected" : ""}>${escapeHtml(d.name)}</option>`)
        .join("")
    );
  }

  function interfaceOptions(select, deviceId) {
    const device = store.devices.get(Number(deviceId));
    const used = usedInterfaceIds();
    if (!device) {
      select.innerHTML = `<option value="">—</option>`;
      select.disabled = true;
      return;
    }
    select.disabled = false;
    // Sub-interfaces (Gi0/0/1.10) ride on their parent's link and cannot be cabled.
    const physical = device.interfaces.filter((i) => !i.name.includes("."));
    const free = physical.filter((i) => !used.has(i.id));
    select.innerHTML =
      `<option value="">No interface</option>` +
      physical
        .map((i) => {
          const inUse = used.has(i.id);
          const ip = i.ip_address ? ` (${i.ip_address})` : "";
          return `<option value="${i.id}" ${inUse ? "disabled" : ""}>${escapeHtml(i.name + ip)}${inUse ? " — in use" : ""}</option>`;
        })
        .join("");
    if (free.length) select.value = String(free[0].id);
  }

  function updateHint() {
    const missing = [srcDev.value, dstDev.value]
      .map((id) => store.devices.get(Number(id)))
      .filter((d) => d && d.interfaces.length === 0)
      .map((d) => d.name);
    document.getElementById("link-hint").textContent = missing.length
      ? `${missing.join(" and ")} ${missing.length > 1 ? "have" : "has"} no interfaces. Add them via Configuration, or connect without an interface.`
      : "Interfaces already connected to another link are not available.";
  }

  srcDev.addEventListener("change", () => {
    interfaceOptions(srcIf, srcDev.value);
    updateHint();
  });
  dstDev.addEventListener("change", () => {
    interfaceOptions(dstIf, dstDev.value);
    updateHint();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const toId = (v) => (v ? Number(v) : null);
    const payload = {
      source_device_id: toId(srcDev.value),
      source_interface_id: toId(srcIf.value),
      destination_device_id: toId(dstDev.value),
      destination_interface_id: toId(dstIf.value),
    };
    if (!payload.source_device_id || !payload.destination_device_id) {
      return showFormError(form, "Select both a source and a destination device.");
    }
    if (payload.source_device_id === payload.destination_device_id) {
      return showFormError(form, "Source and destination must be different devices.");
    }
    await withBusy(document.getElementById("link-submit"), async () => {
      try {
        const link = await api.post(`/networks/${store.network.id}/links`, payload);
        toast(`Linked ${link.source_device_name} ↔ ${link.destination_device_name}`, "success");
        modal.hide();
        await ctx.refresh();
        ctx.selectLink(link.id);
      } catch (error) {
        showFormError(form, error.message);
      }
    });
  });

  return {
    open({ sourceId = null, destinationId = null } = {}) {
      if (store.devices.size < 2) {
        toast("Add at least two devices before creating a link.", "warning");
        return;
      }
      showFormError(form, "");
      srcDev.innerHTML = deviceOptions(sourceId);
      dstDev.innerHTML = deviceOptions(destinationId);
      interfaceOptions(srcIf, sourceId);
      interfaceOptions(dstIf, destinationId);
      updateHint();
      modal.show();
    },
  };
}
