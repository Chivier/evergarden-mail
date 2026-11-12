"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

function element() {
  return { value: "", checked: false, hidden: false, required: false, dataset: {}, children: [],
    classList: { toggle() {} }, append(...items) { this.children.push(...items); },
    replaceChildren(...items) { this.children = items; }, addEventListener() {}, scrollIntoView() {}, focus() {},
  };
}
function load() {
  const items = new Map();
  const el = (id) => { if (!items.has(id)) items.set(id, element()); return items.get(id); };
  const calls = [];
  const context = { console, Intl, Map, Set, document: { addEventListener() {}, getElementById: el, createElement: element },
    jsonRequest: async (url, options) => { calls.push({ url, options }); return { revision: "new", token: "test-issued-token", keys: [], max_keys: 32 }; },
  };
  vm.createContext(context); loadI18n(context, "en");
  vm.runInContext(`${fs.readFileSync(path.resolve(__dirname, "../../apps/mail_ui/static/settings.js"), "utf8")}\n;globalThis.__settings = { settingsState, settingsKeyRisk, createSettingsKey, clearSettingsToken, settingsAccountPayload, settingsExpiryText, runtimeChanges };`, context);
  const api = context.__settings;
  api.settingsState.keys = { revision: "initial", keys: [] };
  api.settingsState.session = { csrf: "csrf-test" };
  el("settingsScopes").querySelectorAll = () => [{ value: "mail:read" }];
  el("settingsKeyForm").elements = { label: { value: "Laptop" } };
  el("settingsKeyTtl").value = "never";
  return { api, el, calls };
}

test("selecting no expiry exposes the risk, requires confirmation and resets an old acknowledgement", () => {
  const { api, el } = load();
  el("settingsKeyAck").checked = true; api.settingsKeyRisk();
  assert.equal(el("settingsKeyRisk").hidden, false);
  assert.equal(el("settingsKeyAck").required, true);
  assert.equal(el("settingsKeyAck").checked, false);
  el("settingsKeyTtl").value = "90"; api.settingsKeyRisk();
  assert.equal(el("settingsKeyRisk").hidden, true);
  assert.equal(el("settingsKeyAck").required, false);
});

test("non-expiring token creation is blocked before a request until acknowledged", async () => {
  const { api, el, calls } = load();
  await assert.rejects(api.createSettingsKey(), /risk/);
  assert.equal(calls.length, 0);
  el("settingsKeyAck").checked = true;
  await api.createSettingsKey();
  assert.equal(calls[0].options.body.ttl_days, null);
  assert.equal(calls[0].options.body.acknowledge_no_expiry, true);
  assert.equal(calls[0].options.csrf, "csrf-test");
  assert.equal(el("issuedToken").value, "test-issued-token");
  assert.equal(JSON.stringify(api.settingsState).includes("test-issued-token"), false);
  api.clearSettingsToken();
  assert.equal(el("issuedToken").value, "");
  assert.equal(el("issuedKey").hidden, true);
});

test("permanent and dated tokens have readable expiry labels", () => {
  const { api } = load();
  assert.equal(api.settingsExpiryText({ scopes: ["mail:read"], expires_at: null }), "mail:read · never expires");
  assert.match(api.settingsExpiryText({ scopes: ["mail:read"], expires_at: "2027-01-01T00:00:00Z", expired: false }), /2027-01-01/);
});

test("mailbox edits keep ports, folders, sender identities and disabled state", () => {
  const { api } = load();
  const values = { alias: "work", address: "login@example.test", send_from_addresses: "public@example.test, login@example.test", auth_kind: "password", credential_record: "password:work", imap_host: "imap.example.test", imap_port: "1993", smtp_host: "smtp.example.test", smtp_port: "465", smtp_mode: "ssl", folders: "INBOX, Projects", archive_folder: "Projects", sent_folder: "Sent", trash_folder: "Trash", safe_move_folders: "Projects", provider: "imap" };
  const elements = Object.fromEntries(Object.entries(values).map(([name, value]) => [name, { value }]));
  elements.copy_preserve_source_fallback = { checked: true }; elements.enabled = { checked: false };
  const payload = api.settingsAccountPayload({ elements });
  assert.equal(payload.enabled, false); assert.equal(payload.smtp_port, 465); assert.equal(payload.imap_port, 1993);
  assert.deepEqual(Array.from(payload.folders), ["INBOX", "Projects"]);
  assert.deepEqual(Array.from(payload.send_from_addresses), ["public@example.test", "login@example.test"]);
  assert.equal(payload.copy_preserve_source_fallback, true);
  assert.equal(Object.hasOwn(payload, "password"), false);
});

test("runtime saves send only changed values and preserve boolean and numeric types", () => {
  const { api, el } = load();
  api.settingsState.runtime = { fields: [
    { name: "admin_login_max_failures", type: "number", value: 15 },
    { name: "side_effects_enabled", type: "checkbox", value: false },
    { name: "schedule_timezone", type: "text", value: "UTC" },
  ] };
  el("runtime-admin_login_max_failures").value = "15";
  el("runtime-side_effects_enabled").checked = true;
  el("runtime-schedule_timezone").value = "Europe/Paris";
  assert.equal(JSON.stringify(api.runtimeChanges()), JSON.stringify({ side_effects_enabled: true, schedule_timezone: "Europe/Paris" }));
});
