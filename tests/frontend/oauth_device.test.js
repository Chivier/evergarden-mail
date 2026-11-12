"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

function loadPage(responses) {
  const nodes = new Map();
  const requests = [];
  const timers = [];
  const requestTimers = new Map();
  const navigations = [];
  let nextRequestTimer = 0;
  const context = {
    URL, Date, console, AbortController,
    setTimeout(callback, duration) { const id = ++nextRequestTimer; requestTimers.set(id, {callback, duration}); return id; },
    clearTimeout(id) { requestTimers.delete(id); },
    document: {
      addEventListener() {},
      getElementById(id) {
        if (!nodes.has(id)) nodes.set(id, {
          value: "work", hidden: true, textContent: "",
          addEventListener(_name, callback) { this.click = callback; },
        });
        return nodes.get(id);
      },
    },
    window: {
      clearTimeout() {},
      setTimeout(callback, milliseconds) { timers.push({ callback, milliseconds }); return timers.length; },
      location: { pathname: "/oauth", search: "", assign(url) { navigations.push(url); } },
    },
    async fetch(url, options) {
      requests.push({ url, options });
      const value = responses.shift();
      if (value instanceof Error) throw value;
      if (value?.httpStatus) {
        return { ok: false, status: value.httpStatus, headers: { get: () => "application/json" }, async json() { return value.body; } };
      }
      return { ok: true, status: 200, headers: { get: () => "application/json" }, async json() { return value; } };
    },
  };
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../../apps/shared_static/http.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../../apps/approval_ui/static/oauth.js"), "utf8"), context);
  vm.runInContext('csrf = "csrf-test"; globalThis.poll = pollDevice;', context);
  return { nodes, requests, timers, requestTimers, navigations, context };
}

function deviceStart(changes = {}) {
  return {
    flow: "device_code", flow_id: "test-flow", user_code: "ABCD-EFGH",
    verification_uri: "https://login.microsoft.com/device", interval: 5,
    expires_at: new Date(Date.now() + 900000).toISOString(), ...changes,
  };
}

test("device login retains the page, polls with CSRF, and shows success", async () => {
  const page = loadPage([deviceStart(), { status: "slow_down", interval: 10 }, { status: "authorized" }]);
  await page.nodes.get("start").click();
  assert.equal(page.nodes.get("device").hidden, false);
  assert.equal(page.nodes.get("device-code").textContent, "ABCD-EFGH");
  assert.equal(page.nodes.get("device-link").href, "https://login.microsoft.com/device");
  assert.equal(page.navigations.length, 0);
  assert.equal(page.timers[0].milliseconds, 5000);
  await page.context.poll();
  assert.equal(page.requests[1].options.headers["X-CSRF-Token"], "csrf-test");
  assert.deepEqual(JSON.parse(page.requests[1].options.body), { flow_id: "test-flow" });
  assert.equal(page.timers[1].milliseconds, 10000);
  await page.context.poll();
  assert.equal(page.nodes.get("device").hidden, true);
  assert.match(page.nodes.get("result").textContent, /授权成功/);
  await page.context.poll();
  assert.equal(page.requests.length, 3);
  assert.equal(page.requestTimers.size, 0);
});

test("a rejected device poll stops polling; a network failure keeps polling with backoff", async () => {
  const rejected = loadPage([deviceStart(), { httpStatus: 400, body: { detail: "OAuth device flow is unknown" } }]);
  await rejected.nodes.get("start").click();
  await rejected.context.poll();
  assert.equal(rejected.nodes.get("result").textContent, "OAuth device flow is unknown");
  assert.equal(rejected.timers.length, 1, "a 4xx response does not schedule another poll");

  const offline = loadPage([deviceStart(), new TypeError("Failed to fetch")]);
  await offline.nodes.get("start").click();
  await offline.context.poll();
  assert.equal(offline.nodes.get("result").textContent, "网络连接中断。请刷新核对状态。");
  assert.equal(offline.timers.length, 2);
  assert.equal(offline.timers[1].milliseconds, 15000);
  assert.equal(offline.requestTimers.size, 0);
});

test("device login rejects an unexpected verification origin", async () => {
  const page = loadPage([deviceStart({ verification_uri: "https://login.microsoft.com.attacker.test/device" })]);
  await page.nodes.get("start").click();
  assert.equal(page.nodes.get("device").hidden, true);
  assert.equal(page.timers.length, 0);
  assert.match(page.nodes.get("result").textContent, /安全策略/);
});

test("expired device codes stop polling and request a fresh start", async () => {
  const page = loadPage([deviceStart({ expires_at: new Date(Date.now() - 1000).toISOString() })]);
  await page.nodes.get("start").click();
  await page.context.poll();
  assert.equal(page.requests.length, 1);
  assert.equal(page.nodes.get("device").hidden, true);
  assert.match(page.nodes.get("result").textContent, /已过期/);
});

test("Google authorization opens the official endpoint for the selected Google mailbox", async () => {
  const url = "https://accounts.google.com/o/oauth2/v2/auth?state=test-state";
  const page = loadPage([{ authorization_url: url }]);
  page.nodes.get("account").value = "company";
  vm.runInContext('providers = {company: "google"};', page.context);
  await page.nodes.get("start").click();
  assert.deepEqual(page.navigations, [url]);
  assert.equal(page.requests[0].options.headers["X-CSRF-Token"], "csrf-test");
});

for (const url of [
  "https://accounts.google.com.attacker.test/o/oauth2/v2/auth",
  "http://accounts.google.com/o/oauth2/v2/auth",
  "https://accounts.google.com:8443/o/oauth2/v2/auth",
  "https://accounts.google.com/wrong-path",
  ["https://attacker", "accounts.google.com/o/oauth2/v2/auth"].join("@"),
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
]) {
  test(`Google authorization rejects an unexpected destination: ${url}`, async () => {
    const page = loadPage([{ authorization_url: url }]);
    page.nodes.get("account").value = "company";
    vm.runInContext('providers = {company: "google"};', page.context);
    await page.nodes.get("start").click();
    assert.equal(page.navigations.length, 0);
    assert.match(page.nodes.get("result").textContent, /安全策略/);
  });
}

test("unconfigured Google mailboxes explain the missing setup and disable authorization", () => {
  const page = loadPage([]);
  page.nodes.get("account").value = "company";
  vm.runInContext('providers = {company: "google"}; configured = {company: false}; updateProvider();', page.context);
  assert.equal(page.nodes.get("start").disabled, true);
  assert.match(page.nodes.get("result").textContent, /尚未配置/);
});

test("Google mailboxes reject a Microsoft device-code response", async () => {
  const page = loadPage([deviceStart()]);
  page.nodes.get("account").value = "company";
  vm.runInContext('providers = {company: "google"};', page.context);
  await page.nodes.get("start").click();
  assert.equal(page.timers.length, 0);
  assert.match(page.nodes.get("result").textContent, /安全策略/);
});

test("unconfigured Microsoft mailboxes ask for the operator's own app registration", () => {
  const page = loadPage([]);
  vm.runInContext('providers = { work: "microsoft" }; configured = { work: false }; updateProvider();', page.context);
  assert.equal(page.nodes.get("start").disabled, true);
  assert.match(page.nodes.get("result").textContent, /Entra/);
  assert.doesNotMatch(page.nodes.get("result").textContent, /Google/);
});

test("device login names the configured app registration only when one is set", async () => {
  const named = loadPage([deviceStart()]);
  vm.runInContext('providers = { work: "microsoft" }; appNames = { work: "Example Mail" };', named.context);
  await named.nodes.get("start").click();
  assert.equal(named.nodes.get("device-app").hidden, false);
  assert.match(named.nodes.get("device-app").textContent, /Example Mail/);

  const unnamed = loadPage([deviceStart()]);
  vm.runInContext('providers = { work: "microsoft" }; appNames = {};', unnamed.context);
  await unnamed.nodes.get("start").click();
  assert.equal(unnamed.nodes.get("device-app").hidden, true);
});
