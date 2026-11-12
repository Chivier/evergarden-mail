"use strict";

// A failed sync names each mailbox with a readable reason; the provider's raw
// wording stays available behind a disclosure.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

const FAILURES = [
  { account: "personal", reason: "dns", error_class: "gaierror", detail: "[Errno -2] Name or service not known", folders: [] },
  { account: "work", reason: "timeout", error_class: "TimeoutError", detail: "Archive: timed out", folders: ["Archive"] },
  { account: "odd", reason: "unexpected", error_class: "", detail: "", folders: [] },
];

function loadApp(locale, body) {
  const elements = new Map();
  const element = (tag = "div") => ({
    tag, textContent: "", hidden: true, disabled: false, children: [], dataset: {}, attributes: {}, listeners: {},
    classList: { names: new Set(), toggle(name, on) { if (on) this.names.add(name); else this.names.delete(name); } },
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(type, handler) { this.listeners[type] = handler; },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
  });
  const context = {
    console, Intl, AbortController, setTimeout, clearTimeout,
    document: {
      addEventListener() {}, createElement: element, querySelectorAll: () => [],
      getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    },
    window: { setTimeout, clearTimeout, location: { pathname: "/", search: "", assign() {} } },
    async fetch() {
      return { ok: false, status: 400, headers: { get: () => "application/json" }, async json() { return body; } };
    },
  };
  vm.createContext(context);
  loadI18n(context, locale);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../../apps/shared_static/http.js"), "utf8"), context);
  vm.runInContext(`${fs.readFileSync(path.resolve(__dirname, "../../apps/mail_ui/static/app.js"), "utf8")}
;globalThis.__app = { state, synchronize };`, context);
  context.__app.state.csrf = "c".repeat(32);
  return { app: context.__app, byId: (id) => context.document.getElementById(id) };
}

const text = (item) => (typeof item === "string" ? item : [item.textContent, ...item.children.map(text)].join(""));
const find = (item, tag) => (item.tag === tag ? [item] : item.children.flatMap((child) => find(child, tag)));

test("each failed mailbox gets a reason, folders and a secondary raw detail", async () => {
  const page = loadApp("en", {
    detail: "MAIL_SYNC_INCOMPLETE: 3 mailbox(es) did not sync",
    reason_code: "MAIL_SYNC_INCOMPLETE",
    sync_failures: FAILURES,
  });
  await page.app.synchronize();
  const notice = page.byId("notice");
  assert.equal(notice.hidden, false);
  assert.ok(notice.classList.names.has("error"));
  assert.equal(page.byId("syncState").textContent, "Sync did not finish");
  const items = find(notice, "li");
  assert.equal(items.length, 3);
  assert.match(text(items[0]), /^personal cannot resolve the server name\. Check the IMAP host\./);
  assert.match(text(items[1]), /^work the server did not answer in time\. Try again later\. Folders: Archive\./);
  assert.match(text(items[2]), /^odd the sync failed\./, "unknown reasons fall back to 'other'");
  const raw = find(items[0], "code");
  assert.equal(raw.length, 1);
  assert.equal(raw[0].textContent, "gaierror: [Errno -2] Name or service not known");
  assert.equal(find(items[0], "summary")[0].textContent, "Technical detail");
  assert.equal(find(items[2], "details").length, 0, "no empty disclosure");
  assert.doesNotMatch(text(notice), /mail_sync_incomplete|\{"error"/);
  find(notice, "button")[0].listeners.click();
  assert.equal(notice.hidden, true);
});

test("the readable reasons are translated", async () => {
  const page = loadApp("zh-CN", { detail: "x", reason_code: "MAIL_SYNC_INCOMPLETE", sync_failures: FAILURES.slice(0, 1) });
  await page.app.synchronize();
  const notice = page.byId("notice");
  assert.match(text(notice), /以下邮箱未能同步/);
  assert.match(text(notice), /personal 无法解析服务器地址/);
  assert.match(text(notice), /技术细节/);
});

test("other sync errors still show the server message", async () => {
  const page = loadApp("en", { detail: "MCP gateway is unavailable" });
  await page.app.synchronize();
  assert.equal(page.byId("notice").textContent, "MCP gateway is unavailable");
});
