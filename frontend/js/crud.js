// Reusable "table + add/edit form" editor used for interfaces, VLANs, static
// routes, ACL rules and required flows. Each section is described by a spec;
// the component renders it, validates required fields and calls the API.

import { api } from "./api.js";
import { confirmDialog, escapeHtml, showFormError, toast, withBusy } from "./ui.js";

/**
 * @param {HTMLElement} container
 * @param {object} spec
 *   idPrefix, noun, columns: [{label, render(item)}], fields: [{name,label,type,options,placeholder,col,required,min,max,
 *   visible(values), help}], items(): array, createUrl(): string, updateUrl(item), deleteUrl(item),
 *   toPayload(values, item), deleteMessage(item), defaults(): object, describe(item), onSaved(): Promise
 */
export function createCrudSection(container, spec) {
  let editing = null;

  container.innerHTML = `
    <div data-crud-table class="mb-3"></div>
    <form class="ng-crud-form" novalidate>
      <div class="d-flex justify-content-between align-items-center mb-2">
        <strong class="small" data-crud-title>Add ${escapeHtml(spec.noun)}</strong>
        <button type="button" class="btn btn-sm btn-link p-0 d-none" data-crud-cancel>Cancel edit</button>
      </div>
      <div class="alert alert-danger py-2 small d-none" role="alert" data-form-error></div>
      <div class="row g-2 align-items-end" data-crud-fields></div>
      <div class="d-flex justify-content-between align-items-center mt-2">
        <span class="form-text m-0">${spec.help || ""}</span>
        <button type="submit" class="btn btn-sm btn-primary" id="${spec.idPrefix}-submit" data-crud-submit></button>
      </div>
    </form>`;

  const tableEl = container.querySelector("[data-crud-table]");
  const form = container.querySelector("form");
  const fieldsEl = container.querySelector("[data-crud-fields]");
  const submitBtn = container.querySelector("[data-crud-submit]");
  const cancelBtn = container.querySelector("[data-crud-cancel]");

  function fieldHtml(field) {
    const id = `${spec.idPrefix}-${field.name}`;
    const required = field.required ? ' <span class="text-danger">*</span>' : "";
    let control;
    if (field.type === "select") {
      const options = (typeof field.options === "function" ? field.options() : field.options)
        .map((o) => `<option value="${escapeHtml(o.value)}">${escapeHtml(o.label)}</option>`)
        .join("");
      control = `<select class="form-select form-select-sm" id="${id}" name="${field.name}">${options}</select>`;
    } else {
      const attrs = [
        field.min !== undefined ? `min="${field.min}"` : "",
        field.max !== undefined ? `max="${field.max}"` : "",
        field.maxLength !== undefined ? `maxlength="${field.maxLength}"` : "",
        field.placeholder ? `placeholder="${escapeHtml(field.placeholder)}"` : "",
      ].join(" ");
      control = `<input class="form-control form-control-sm ${field.mono ? "mono" : ""}" id="${id}" name="${field.name}"
        type="${field.type || "text"}" ${attrs}>`;
    }
    return `<div class="col-md-${field.col || 3}" data-field="${field.name}">
      <label class="form-label" for="${id}">${escapeHtml(field.label)}${required}</label>${control}</div>`;
  }

  function values() {
    const result = {};
    for (const field of spec.fields) {
      const el = form.elements[field.name];
      if (!el) continue;
      const raw = el.value.trim();
      if (raw === "") result[field.name] = null;
      else if (field.type === "number") result[field.name] = Number(raw);
      else result[field.name] = raw;
    }
    return result;
  }

  function updateVisibility() {
    const current = values();
    for (const field of spec.fields) {
      const wrapper = fieldsEl.querySelector(`[data-field="${field.name}"]`);
      if (wrapper) wrapper.classList.toggle("d-none", field.visible ? !field.visible(current) : false);
    }
  }

  function renderFields() {
    fieldsEl.innerHTML = spec.fields.map(fieldHtml).join("");
    fieldsEl.querySelectorAll("select, input").forEach((el) => el.addEventListener("change", updateVisibility));
  }

  function fill(item) {
    const source = item || (spec.defaults ? spec.defaults() : {});
    for (const field of spec.fields) {
      const el = form.elements[field.name];
      if (!el) continue;
      const value = source[field.name];
      el.value = value === null || value === undefined ? (field.type === "select" && el.options.length ? el.options[0].value : "") : value;
    }
    updateVisibility();
  }

  function reset() {
    editing = null;
    renderFields();
    fill(null);
    showFormError(form, "");
    container.querySelector("[data-crud-title]").textContent = `Add ${spec.noun}`;
    submitBtn.innerHTML = `<i class="bi bi-plus-lg me-1"></i>Add ${escapeHtml(spec.noun)}`;
    cancelBtn.classList.add("d-none");
  }

  function renderTable() {
    const items = spec.items();
    if (!items.length) {
      tableEl.innerHTML = `<div class="ng-empty py-3"><i class="bi bi-inbox"></i>No ${escapeHtml(spec.plural || spec.noun.toLowerCase() + "s")} yet.</div>`;
      return;
    }
    tableEl.innerHTML = `
      <div class="table-responsive border rounded">
        <table class="table ng-table">
          <thead><tr>${spec.columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join("")}<th></th></tr></thead>
          <tbody>${items
            .map(
              (item) => `<tr data-item-id="${item.id}" class="${editing && editing.id === item.id ? "table-active" : ""}">
                ${spec.columns.map((c) => `<td>${c.render(item)}</td>`).join("")}
                <td class="actions">
                  <button type="button" class="btn btn-sm btn-light border" data-crud-action="edit" title="Edit"
                    aria-label="Edit ${escapeHtml(spec.describe(item))}"><i class="bi bi-pencil"></i></button>
                  <button type="button" class="btn btn-sm btn-light border text-danger" data-crud-action="delete" title="Delete"
                    aria-label="Delete ${escapeHtml(spec.describe(item))}"><i class="bi bi-trash"></i></button>
                </td></tr>`
            )
            .join("")}</tbody>
        </table>
      </div>`;
  }

  tableEl.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-crud-action]");
    if (!button) return;
    const id = Number(button.closest("tr").dataset.itemId);
    const item = spec.items().find((i) => i.id === id);
    if (button.dataset.crudAction === "edit") {
      editing = item;
      renderFields();
      fill(item);
      showFormError(form, "");
      container.querySelector("[data-crud-title]").textContent = `Edit ${spec.noun} — ${spec.describe(item)}`;
      submitBtn.innerHTML = `<i class="bi bi-check-lg me-1"></i>Save ${escapeHtml(spec.noun)}`;
      cancelBtn.classList.remove("d-none");
      renderTable();
      return;
    }
    const ok = await confirmDialog({
      title: `Delete ${spec.noun.toLowerCase()}`,
      message: spec.deleteMessage ? spec.deleteMessage(item) : `<p class="mb-0">Delete <strong>${escapeHtml(spec.describe(item))}</strong>?</p>`,
      confirmLabel: `Delete ${spec.noun}`,
      danger: true,
    });
    if (!ok) return;
    try {
      await api.del(spec.deleteUrl(item));
      toast(`${spec.noun} ${spec.describe(item)} deleted`, "success");
      if (editing && editing.id === id) reset();
      await spec.onSaved();
      renderTable();
    } catch (error) {
      toast(error.message, "error");
    }
  });

  cancelBtn.addEventListener("click", () => {
    reset();
    renderTable();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = values();
    const missing = spec.fields.filter((f) => f.required && (!f.visible || f.visible(data)) && data[f.name] === null);
    if (missing.length) {
      showFormError(form, `${missing.map((f) => f.label).join(", ")} ${missing.length > 1 ? "are" : "is"} required.`);
      return;
    }
    let payload;
    try {
      payload = spec.toPayload ? spec.toPayload(data, editing) : data;
    } catch (error) {
      showFormError(form, error.message); // e.g. an unreadable VLAN list; nothing is sent
      return;
    }
    await withBusy(submitBtn, async () => {
      try {
        const saved = editing ? await api.put(spec.updateUrl(editing), payload) : await api.post(spec.createUrl(), payload);
        toast(`${spec.noun} ${spec.describe(saved)} ${editing ? "updated" : "added"}`, "success");
        reset();
        await spec.onSaved();
        renderTable();
        form.querySelector("input, select")?.focus();
      } catch (error) {
        showFormError(form, error.message);
      }
    });
  });

  reset();
  renderTable();
  return {
    refresh() {
      renderTable();
    },
    reset() {
      reset();
      renderTable();
    },
    focus() {
      form.querySelector("input, select")?.focus();
    },
  };
}
