"use strict";
const settingsEl = (id) => document.getElementById(id);
const settingsState = { session: null, accounts: null, keys: null, runtime: null, credentials: new Map(), editing: null, dirtyForms: new Set() };
const settingsRequest = (url, options = {}) => jsonRequest(url, { ...options, csrf: settingsState.session?.csrf || "" });

function settingsNode(tag, text, className = "") {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
}
function settingsText(key, tag = "span", className = "") {
  const item = settingsNode(tag, t(key), className);
  item.dataset.i18n = key;
  return item;
}
function settingsNotice(message, error = false) {
  const box = settingsEl("settingsNotice");
  box.textContent = message;
  box.classList.toggle("error", error);
  box.hidden = false;
  box.focus();
}
function settingsError(error) { settingsNotice(error.message, true); }
async function settingsBusy(target, action) {
  if (target.dataset.busy) return;
  target.dataset.busy = "1";
  const buttons = target.matches("button") ? [target] : [...target.querySelectorAll("button[type=submit]")];
  buttons.forEach((b) => { b.disabled = true; });
  try { await action(); }
  catch (error) { settingsError(error); }
  finally { buttons.forEach((b) => { b.disabled = false; }); delete target.dataset.busy; }
}
function settingsButton(key, action, className = "secondary") {
  const button = settingsText(key, "button", className);
  button.type = "button";
  button.addEventListener("click", () => settingsBusy(button, action));
  return button;
}
function clearSettingsToken() {
  settingsEl("issuedToken").value = "";
  settingsEl("issuedKey").hidden = true;
}
function settingsTab() {
  const selected = ["accounts", "keys", "runtime"].includes(location.hash.slice(1)) ? location.hash.slice(1) : "accounts";
  for (const item of document.querySelectorAll(".settings-panel")) item.hidden = item.id !== selected;
  for (const link of document.querySelectorAll(".settings-nav a")) {
    if (link.hash === `#${selected}`) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (selected !== "keys") clearSettingsToken();
}

async function loadSettingsCredentials() {
  try {
    const value = await settingsRequest("/oauth/credentials");
    settingsState.credentials = new Map(value.accounts.map((a) => [a.alias, a.credential_present]));
  } catch { settingsState.credentials = new Map(); }
}
function renderSettingsAccounts() {
  const list = settingsEl("mailboxList");
  list.replaceChildren();
  for (const account of settingsState.accounts?.accounts || []) {
    const card = settingsNode("article", undefined, "card mailbox-card");
    const top = settingsNode("div", undefined, "card-top");
    const name = settingsNode("div");
    name.append(settingsNode("h2", account.alias), settingsNode("p", account.address));
    top.append(name, settingsText(account.enabled ? "accounts.enabled" : "accounts.disabledState", "span", `badge${account.enabled ? "" : " disabled"}`));
    const credential = settingsState.credentials.get(account.alias);
    const controls = settingsNode("div", undefined, "actions");
    controls.append(settingsButton("settings.edit", () => openSettingsMailbox(account)));
    if (account.auth_kind === "password") {
      controls.append(settingsButton("settings.setPassword", () => openSettingsPassword(account)));
    } else {
      const link = settingsText(account.oauth_provider === "google" ? "accounts.connectGoogle" : "accounts.connectOauth", "a", "secondary");
      link.href = `/oauth?account=${encodeURIComponent(account.alias)}`;
      link.target = "_blank"; link.rel = "noopener";
      controls.append(link);
    }
    controls.append(settingsButton(account.enabled ? "accounts.disable" : "accounts.enable", async () => {
      const changed = await settingsRequest(`/api/admin/accounts/${encodeURIComponent(account.alias)}/state`, {
        method: "POST", body: { expected_revision: settingsState.accounts.revision, enabled: !account.enabled },
      });
      settingsState.accounts = changed; renderSettingsAccounts(); settingsNotice(t("settings.mailboxSaved"));
    }));
    controls.append(settingsButton("settings.remove", async () => {
      if (!await EG.confirm({ title: t("settings.removeTitle", { alias: account.alias }), message: t("settings.removeHelp"), confirmLabel: t("settings.remove"), danger: true })) return;
      const changed = await settingsRequest(`/api/admin/accounts/${encodeURIComponent(account.alias)}`, {
        method: "DELETE", body: { expected_revision: settingsState.accounts.revision, confirmation: account.alias },
      });
      settingsState.accounts = changed;
      if (settingsState.editing === account.alias) closeSettingsMailbox();
      renderSettingsAccounts(); settingsNotice(t("settings.mailboxRemoved"));
    }, "danger-ghost"));
    card.append(top, settingsNode("p", `${account.imap_host}:${account.imap_port} · ${account.smtp_host}:${account.smtp_port}`, "muted"),
      settingsText(credential === undefined ? "settings.credentialUnknown" : credential ? "settings.credentialReady" : "settings.credentialMissing", "p", "muted"), controls);
    list.append(card);
  }
  if (!settingsState.accounts?.accounts.length) list.append(settingsText("settings.noMailboxes", "p", "muted"));
}
async function openSettingsMailbox(account = null) {
  if (settingsState.dirtyForms.has("mailboxForm") && !await EG.confirm({ title: t("settings.discard"), message: t("settings.discardHelp") })) return;
  const form = settingsEl("mailboxForm");
  form.reset();
  settingsState.editing = account?.alias || null;
  for (const input of form.elements) {
    if (!input.name || !account || account[input.name] === undefined) continue;
    const value = account[input.name];
    if (input.type === "checkbox") input.checked = value;
    else input.value = Array.isArray(value) ? value.join(", ") : value;
  }
  form.elements.alias.disabled = Boolean(account);
  settingsEl("editorTitle").textContent = t(account ? "settings.editMailbox" : "accounts.add");
  settingsEl("editorTitle").dataset.i18n = account ? "settings.editMailbox" : "accounts.add";
  settingsEl("mailboxEditor").hidden = false;
  settingsEl("mailboxEditor").scrollIntoView({ block: "start", behavior: "smooth" });
  (account ? form.elements.address : form.elements.alias).focus();
  settingsState.dirtyForms.delete("mailboxForm");
}
function closeSettingsMailbox() {
  settingsEl("mailboxForm").reset(); settingsEl("mailboxEditor").hidden = true;
  settingsState.editing = null; settingsState.dirtyForms.delete("mailboxForm");
}
function settingsAccountPayload(form) {
  const text = (name) => form.elements[name].value.trim();
  const list = (name) => text(name).split(",").map((v) => v.trim()).filter(Boolean);
  return {
    alias: text("alias"), address: text("address"), send_from_addresses: list("send_from_addresses").length ? list("send_from_addresses") : [text("address")],
    auth_kind: text("auth_kind"), credential_record: text("credential_record"),
    imap_host: text("imap_host"), imap_port: Number(text("imap_port")),
    smtp_host: text("smtp_host"), smtp_port: Number(text("smtp_port")), smtp_mode: text("smtp_mode"),
    folders: list("folders"), archive_folder: text("archive_folder"), sent_folder: text("sent_folder"), trash_folder: text("trash_folder"),
    safe_move_folders: list("safe_move_folders"), copy_preserve_source_fallback: form.elements.copy_preserve_source_fallback.checked,
    provider: text("provider"), enabled: form.elements.enabled.checked,
  };
}
async function saveSettingsMailbox() {
  const account = settingsAccountPayload(settingsEl("mailboxForm"));
  const alias = settingsState.editing;
  const snapshot = await settingsRequest(alias ? `/api/admin/accounts/${encodeURIComponent(alias)}` : "/api/admin/accounts", {
    method: alias ? "PATCH" : "POST", body: { expected_revision: settingsState.accounts.revision, account },
  });
  settingsState.accounts = snapshot;
  closeSettingsMailbox(); await loadSettingsCredentials(); renderSettingsAccounts(); settingsNotice(t("settings.mailboxSaved"));
}
function suggestSettingsCredential() {
  if (settingsState.editing) return;
  const form = settingsEl("mailboxForm");
  const field = form.elements.credential_record;
  if (field.dataset.custom === "1") return;
  const kind = form.elements.auth_kind.value === "password" ? "password" : form.elements.imap_host.value.trim().toLowerCase() === "imap.gmail.com" ? "google" : "microsoft";
  const alias = form.elements.alias.value.trim();
  field.value = alias ? `${kind}:${alias}` : "";
}
function openSettingsPassword(account) {
  settingsEl("passwordForm").dataset.alias = account.alias;
  settingsEl("passwordAccount").textContent = `${account.alias} · ${account.address}`;
  settingsEl("mailboxPassword").value = "";
  settingsEl("passwordDialog").showModal(); settingsEl("mailboxPassword").focus();
}
async function saveSettingsPassword() {
  const alias = settingsEl("passwordForm").dataset.alias;
  try {
    await settingsRequest(`/oauth/credentials/${encodeURIComponent(alias)}/password`, {
      method: "POST", body: { expected_revision: settingsState.accounts.revision, password: settingsEl("mailboxPassword").value },
    });
    settingsEl("passwordDialog").close(); await loadSettingsCredentials(); renderSettingsAccounts(); settingsNotice(t("settings.passwordSaved"));
  } finally { settingsEl("mailboxPassword").value = ""; }
}

function settingsExpiryText(key) {
  if (key.expires_at === null) return t("mcp.keyNeverExpires", { summary: key.scopes.join(" · ") });
  return t(key.expired ? "mcp.keyExpired" : "mcp.keyExpires", { summary: key.scopes.join(" · "), date: key.expires_at.slice(0, 10) });
}
function renderSettingsKeys() {
  const list = settingsEl("settingsKeyList"); list.replaceChildren();
  for (const key of settingsState.keys?.keys || []) {
    const card = settingsNode("article", undefined, "card mailbox-card");
    card.append(settingsNode("h2", key.label), settingsNode("p", key.client_id, "muted"), settingsNode("p", settingsExpiryText(key), "muted"),
      settingsButton("mcp.revoke", async () => {
        if (!await EG.confirm({ title: t("mcp.revokeConfirm.title", { client: key.client_id }), message: t("mcp.revokeConfirm.body"), confirmLabel: t("mcp.revoke"), danger: true })) return;
        settingsState.keys = await settingsRequest(`/api/admin/api-keys/${encodeURIComponent(key.client_id)}/revoke`, {
          method: "POST", body: { expected_revision: settingsState.keys.revision },
        });
        clearSettingsToken(); renderSettingsKeys(); settingsNotice(t("mcp.revoked", { client: key.client_id }));
      }, "danger-ghost"));
    list.append(card);
  }
  if (!settingsState.keys?.keys.length) list.append(settingsText("mcp.noKeys", "p", "muted"));
}
function settingsKeyRisk() {
  const never = settingsEl("settingsKeyTtl").value === "never";
  settingsEl("settingsKeyRisk").hidden = !never;
  settingsEl("settingsKeyAck").required = never;
  settingsEl("settingsKeyAck").checked = false;
}
async function createSettingsKey() {
  if (!settingsState.keys) throw new Error(t("mcp.keysLoading"));
  const scopes = [...settingsEl("settingsScopes").querySelectorAll("input:checked")].map((i) => i.value);
  if (!scopes.length) throw new Error(t("mcp.needScope"));
  const never = settingsEl("settingsKeyTtl").value === "never";
  if (never && !settingsEl("settingsKeyAck").checked) throw new Error(t("mcp.noExpiryRequired"));
  const issued = await settingsRequest("/api/admin/api-keys", {
    method: "POST", body: { expected_revision: settingsState.keys.revision, label: settingsEl("settingsKeyForm").elements.label.value,
      scopes, ttl_days: never ? null : Number(settingsEl("settingsKeyTtl").value), acknowledge_no_expiry: never && settingsEl("settingsKeyAck").checked },
  });
  settingsState.keys = { revision: issued.revision, keys: issued.keys, max_keys: issued.max_keys };
  settingsEl("issuedToken").value = issued.token; settingsEl("issuedKey").hidden = false;
  settingsEl("settingsKeyForm").elements.label.value = "";
  settingsEl("settingsKeyAck").checked = false;
  renderSettingsKeys(); settingsEl("issuedKey").scrollIntoView({ block: "center" });
}

function renderRuntimeSettings() {
  const root = settingsEl("runtimeFields"); root.replaceChildren();
  const groups = new Map();
  for (const field of settingsState.runtime?.fields || []) {
    if (!groups.has(field.group)) {
      const card = settingsNode("section", undefined, "card"); card.append(settingsText(`settings.group.${field.group}`, "h2"));
      const grid = settingsNode("div", undefined, "form-grid"); card.append(grid); root.append(card); groups.set(field.group, grid);
    }
    const label = settingsNode("label");
    const input = document.createElement(field.type === "select" ? "select" : "input");
    input.name = field.name; input.id = `runtime-${field.name}`;
    if (field.type === "select") {
      for (const value of field.choices) { const option = settingsNode("option", value); option.value = value; input.append(option); }
    } else input.type = field.type;
    if (field.type === "checkbox") input.checked = field.value;
    else input.value = String(field.value);
    if (field.min !== undefined) input.min = field.min;
    if (field.max !== undefined) input.max = field.max;
    if (field.type !== "checkbox") {
      if (field.type === "number") { input.required = true; input.step = "1"; }
      else input.maxLength = 4096;
    }
    label.append(settingsText(`settings.field.${field.name}`), settingsNode("code", field.env), input,
      settingsText(`settings.help.${field.name}`, "small"));
    if (field.pending) label.append(settingsText("settings.pendingField", "small"));
    groups.get(field.group).append(label);
  }
  settingsEl("restartPending").hidden = !settingsState.runtime?.restart_required;
}
function runtimeChanges() {
  return Object.fromEntries((settingsState.runtime?.fields || []).map((field) => {
    const input = settingsEl(`runtime-${field.name}`);
    return [field.name, field.type === "checkbox" ? input.checked : field.type === "number" ? Number(input.value) : input.value];
  }).filter(([name, value]) => settingsState.runtime.fields.find((f) => f.name === name).value !== value));
}
async function saveRuntimeSettings() {
  const changes = runtimeChanges();
  if (!Object.keys(changes).length) { settingsState.dirtyForms.delete("runtimeForm"); settingsNotice(t("settings.noChanges")); return; }
  const risk = settingsState.runtime.fields.some((f) => f.risk && Object.hasOwn(changes, f.name));
  if (risk && !await EG.confirm({ title: t("settings.permissionTitle"), message: t("settings.permissionHelp"), confirmLabel: t("settings.saveRuntime"), danger: true })) return;
  settingsState.runtime = await settingsRequest("/api/admin/settings", {
    method: "PATCH", body: { expected_revision: settingsState.runtime.revision, changes, acknowledge_risk: risk },
  });
  renderRuntimeSettings(); settingsState.dirtyForms.delete("runtimeForm"); settingsNotice(t("settings.runtimeSaved"));
}
async function startSettings() {
  settingsEl("newMailbox").addEventListener("click", () => openSettingsMailbox());
  settingsEl("cancelMailbox").addEventListener("click", closeSettingsMailbox);
  settingsEl("cancelPassword").addEventListener("click", () => settingsEl("passwordDialog").close());
  settingsEl("passwordDialog").addEventListener("close", () => { settingsEl("mailboxPassword").value = ""; });
  settingsEl("settingsKeyTtl").addEventListener("change", settingsKeyRisk);
  settingsEl("dismissIssuedToken").addEventListener("click", clearSettingsToken);
  settingsEl("copyIssuedToken").addEventListener("click", () => settingsBusy(settingsEl("copyIssuedToken"), async () => {
    await navigator.clipboard.writeText(settingsEl("issuedToken").value); settingsNotice(t("common.copied"));
  }));
  for (const [id, action] of [["mailboxForm", saveSettingsMailbox], ["passwordForm", saveSettingsPassword], ["settingsKeyForm", createSettingsKey], ["runtimeForm", saveRuntimeSettings]]) {
    settingsEl(id).addEventListener("submit", (event) => { event.preventDefault(); void settingsBusy(event.currentTarget, action); });
  }
  settingsEl("mailboxForm").addEventListener("reset", () => { settingsEl("mailboxForm").elements.credential_record.dataset.custom = ""; });
  for (const name of ["alias", "auth_kind", "imap_host"]) settingsEl("mailboxForm").elements[name].addEventListener("input", suggestSettingsCredential);
  settingsEl("mailboxForm").elements.credential_record.addEventListener("input", (event) => { event.target.dataset.custom = event.target.value ? "1" : ""; if (!event.target.value) suggestSettingsCredential(); });
  for (const id of ["mailboxForm", "runtimeForm"]) settingsEl(id).addEventListener("input", () => { settingsState.dirtyForms.add(id); });
  settingsEl("reloadRuntime").addEventListener("click", () => settingsBusy(settingsEl("reloadRuntime"), async () => {
    if (settingsState.dirtyForms.has("runtimeForm") && !await EG.confirm({ title: t("settings.discard"), message: t("settings.discardHelp") })) return;
    settingsState.runtime = await settingsRequest("/api/admin/settings"); renderRuntimeSettings(); settingsState.dirtyForms.delete("runtimeForm");
  }));
  window.addEventListener("hashchange", settingsTab);
  window.addEventListener("pagehide", () => { clearSettingsToken(); settingsEl("mailboxPassword").value = ""; });
  window.addEventListener("beforeunload", (event) => { if (settingsState.dirtyForms.size) { event.preventDefault(); event.returnValue = ""; } });
  EG.onLocaleChange(() => { renderSettingsAccounts(); renderSettingsKeys(); });
  settingsTab();
  try {
    settingsState.session = await settingsRequest("/api/session");
    const admin = settingsState.session.account_admin_enabled;
    settingsEl("adminUnavailable").hidden = admin;
    settingsEl("newMailbox").disabled = true;
    settingsEl("runtimeForm").hidden = !admin;
    settingsEl("settingsResource").value = settingsState.session.mcp_resource;
    settingsEl("settingsKeyForm").hidden = !settingsState.session.api_keys_enabled;
    settingsEl("keysUnavailable").hidden = settingsState.session.api_keys_enabled;
    for (const scope of settingsState.session.mcp_scopes) {
      const label = settingsNode("label", undefined, "check-label");
      const check = document.createElement("input"); check.type = "checkbox"; check.value = scope;
      check.checked = ["mail:metadata", "mail:read"].includes(scope);
      label.append(check, settingsNode("span", scope)); settingsEl("settingsScopes").append(label);
    }
    const reads = [];
    if (admin) reads.push(
      settingsRequest("/api/admin/accounts").then((value) => { settingsState.accounts = value; settingsEl("newMailbox").disabled = false; renderSettingsAccounts(); }),
      settingsRequest("/api/admin/settings").then((value) => { settingsState.runtime = value; renderRuntimeSettings(); }),
      loadSettingsCredentials().then(renderSettingsAccounts),
    );
    if (settingsState.session.api_keys_enabled) reads.push(settingsRequest("/api/admin/api-keys").then((value) => { settingsState.keys = value; renderSettingsKeys(); }));
    const results = await Promise.allSettled(reads);
    for (const result of results) if (result.status === "rejected") settingsError(result.reason);
  } catch (error) { settingsError(error); }
  finally { settingsEl("loadState").hidden = true; }
}
document.addEventListener("DOMContentLoaded", startSettings);
