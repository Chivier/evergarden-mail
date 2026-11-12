"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

const ORIGIN = "https://mail.example.test";

function loginPage(next, fetch = async () => { throw new Error("unexpected request"); }) {
  const nodes = new Map();
  const replaced = [];
  const assigned = [];
  const node = () => ({value: "", textContent: "", className: "", disabled: false, events: {},
    addEventListener(name, callback) { this.events[name] = callback; }, focus() {}});
  const search = next === undefined ? "" : `?next=${encodeURIComponent(next)}`;
  const context = {
    URL, URLSearchParams, AbortController, setTimeout, clearTimeout, fetch,
    document: {getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); }},
    window: {location: {origin: ORIGIN, pathname: "/login", search,
      replace(url) { replaced.push(url); }, assign(url) { assigned.push(url); }}},
  };
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../../apps/shared_static/http.js"), "utf8"), context);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../../apps/mail_ui/static/login.js"), "utf8"), context);
  const byId = (id) => context.document.getElementById(id);
  return {byId, replaced, assigned, safeNext: () => vm.runInContext("safeNext()", context),
    submit: () => byId("loginForm").events.submit({preventDefault() {}})};
}

const json = (value, status = 200) => ({status, ok: status >= 200 && status < 300,
  headers: {get: () => "application/json"}, async json() { return value; }});

test("safeNext keeps same-origin paths and rejects every foreign or scheme target", () => {
  for (const next of ["/\\evil.example", "//evil.example", "https://evil.example/x", "javascript:alert(1)",
    "\\\\evil.example/x", `${ORIGIN}.evil.example/x`]) {
    assert.equal(loginPage(next).safeNext(), "/", next);
  }
  assert.equal(loginPage("/review?x=1").safeNext(), "/review?x=1");
  assert.equal(loginPage("/feedback?issue_id=1#detail").safeNext(), "/feedback?issue_id=1#detail");
  assert.equal(loginPage(`${ORIGIN}/review?mode=single`).safeNext(), "/review?mode=single");
  assert.equal(loginPage(undefined).safeNext(), "/");
});

test("login posts credentials without a login redirect and maps rejections", async () => {
  const requests = [];
  let answer = json({detail: "invalid administrator credentials"}, 401);
  const page = loginPage("/review?x=1", async (url, options) => { requests.push({url, options}); return answer; });
  page.byId("username").value = "admin";
  page.byId("password").value = "secret";
  await page.submit();
  assert.deepEqual(JSON.parse(requests[0].options.body), {username: "admin", password: "secret"});
  assert.equal(requests[0].url, "/api/login");
  assert.equal(page.byId("loginResult").textContent, "用户名或密码不正确。");
  assert.equal(page.byId("password").value, "");
  assert.deepEqual(page.assigned, []);

  answer = json({detail: "too many attempts"}, 429);
  await page.submit();
  assert.equal(page.byId("loginResult").textContent, "尝试次数过多，请稍后再试。");

  answer = {status: 502, ok: false, headers: {get: () => "text/html"}, async json() { throw new SyntaxError("<"); }};
  await page.submit();
  assert.match(page.byId("loginResult").textContent, /服务暂时不可用（HTTP 502）/);

  answer = json({subject: "admin"});
  await page.submit();
  assert.deepEqual(page.replaced, ["/review?x=1"]);
});
