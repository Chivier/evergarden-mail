"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");
const test = require("node:test");

function page(fetch, search = "") {
  const nodes = new Map();
  const redirects = [];
  const timers = new Map();
  let timerId = 0;
  const node = () => ({textContent: "", value: "missing", checked: false, hidden: true,
    disabled: false, children: [], addEventListener() {}, scrollIntoView() {},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; }});
  const location = {pathname: "/feedback", search, assign(url) { redirects.push(url); }};
  const context = {URLSearchParams, Date, Intl, AbortController, console, fetch, location,
    setTimeout(callback, duration) { const id = ++timerId; timers.set(id, {callback, duration}); return id; },
    clearTimeout(id) { timers.delete(id); },
    document: {addEventListener() {}, createElement: node,
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); }},
    window: {location}, history: {replaceState() {}},
  };
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(fs.readFileSync("apps/shared_static/http.js", "utf8"), context);
  const source = fs.readFileSync("apps/mail_ui/static/feedback.js", "utf8")
    .replace(/\nstart\(\)\.catch\(report\);\s*$/, "\nglobalThis.initialLoad = start().catch(report);");
  vm.runInContext(source, context);
  return {nodes, redirects, timers, context};
}

function response(value, {status = 200, type = "application/json"} = {}) {
  return {status, ok: status >= 200 && status < 300, headers: {get() { return type; }},
    async json() { return value; }};
}

function feedbackResponse(url, issues = []) {
  if (url === "/api/session") return response({csrf: "test-csrf"});
  if (url.endsWith("diagnose_message")) return response({stable_message_id: "a".repeat(24), actionable: true});
  return response({items: issues, next_cursor: null, indexed_count: 0, actionable_count: 0});
}

test("feedback list HTML failure preserves direct diagnostics and refresh recovers all sections", async () => {
  let fail = true;
  const calls = [];
  const p = page(async (url, options) => {
    calls.push({url, options});
    if (fail && url.endsWith("list_mail_feedback")) return response(null, {status: 502, type: "text/html"});
    return feedbackResponse(url);
  }, `?message_id=${"a".repeat(24)}`);
  await p.context.initialLoad;
  assert.match(p.nodes.get("notice").textContent, /服务暂时不可用（HTTP 502）/);
  assert.equal(p.nodes.get("detail").hidden, false);
  assert.match(p.nodes.get("diagnostic").textContent, /"actionable": true/);
  const tool = calls.find((call) => call.url.endsWith("diagnose_message"));
  assert.equal(tool.options.headers["X-CSRF-Token"], "test-csrf");
  assert.deepEqual(JSON.parse(tool.options.body), {arguments: {stable_message_id: "a".repeat(24)}});
  fail = false;
  await p.nodes.get("refresh").onclick();
  assert.equal(p.nodes.get("notice").textContent, "");
  assert.equal(calls.filter((call) => call.url.endsWith("list_mail_feedback")).length, 2);
  assert.equal(calls.filter((call) => call.url.endsWith("diagnose_message")).length, 2);
  assert.equal(calls.some((call) => call.url.includes("submit") || call.url.includes("approved")), false);
  assert.equal(p.timers.size, 0);
});

test("feedback session timeout reports recovery guidance without starting mail calls", async () => {
  const calls = [];
  const p = page(async (url) => {
    calls.push(url);
    const error = new Error("aborted"); error.name = "AbortError"; throw error;
  });
  await p.context.initialLoad;
  assert.equal(p.nodes.get("notice").textContent, "请求超时，请稍后刷新重试。");
  assert.deepEqual(calls, ["/api/session"]);
  assert.equal(p.timers.size, 0);
});

test("feedback session expiry redirects to login", async () => {
  const p = page(async () => ({status: 401, ok: false, headers: {get: () => "text/html"},
    async json() { throw new Error("HTML"); }}));
  await p.context.initialLoad;
  assert.deepEqual(p.redirects, [`/login?next=${encodeURIComponent("/feedback")}`]);
  assert.match(p.nodes.get("notice").textContent, /登录已过期/);
});

test("feedback issues label a message that left the archive", async () => {
  const issue = {stable_message_id: "b".repeat(24), intended_action: "trash", user_decision: "pending",
    processing_status: "message_removed", execution_result: "NOT_EXECUTED", restored_actionable: false,
    feedback_url: "/feedback?issue_id=1"};
  const p = page(async (url) => feedbackResponse(url, url.endsWith("list_mail_feedback") ? [issue] : []));
  await p.context.initialLoad;
  const [item] = p.nodes.get("issues").children;
  assert.match(item.children[0].textContent, /处理状态 邮件已不在归档中/);
});
