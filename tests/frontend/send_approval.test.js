"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");
const test = require("node:test");

const id = "00000000-0000-0000-0000-000000000001";
const packet = {operation: "reply", subject: "<script>attack()</script>",
  account: "test", from: "from@example.test", to: ["to@example.test"], cc: [], bcc: ["hidden@example.test"],
  body: "Hello\n\n<img src=x onerror=attack()>\n> quoted reply", attachments: []};
const sendDraft = (kind, status, extra = {}) => ({draft_id: id, kind, status, payload_hash: "immutable-hash",
  expires_at: "2030-01-01T00:00:00Z", review_packet: packet, ...extra});

function page(kind = "send", status = "pending_approval", {extra = {}, later = []} = {}) {
  const nodes = new Map();
  const requests = [];
  const timers = new Map();
  let nextTimer = 0;
  const node = () => ({textContent: "", hidden: true, disabled: true, checked: false, children: [], events: {},
    addEventListener(event, fn) { this.events[event] = fn; },
    append(child) { this.children.push(child); }, replaceChildren() { this.children = []; }});
  const responses = [{csrf: "csrf", subject: "admin"}, sendDraft(kind, status, extra), {approval_id: "approved-id"}, ...later];
  const context = {URLSearchParams, Date, AbortController,
    setTimeout(callback, duration) { const timer = ++nextTimer; timers.set(timer, {callback, duration}); return timer; },
    clearTimeout(timer) { timers.delete(timer); },
    document: {getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); },
      createElement: node, addEventListener() {}},
    window: {location: {pathname: "/review/send", search: `?draft_id=${id}`, assign() {}}},
    async fetch(url, options) {
      requests.push({url, options});
      const value = responses.shift();
      return {ok: true, status: 200, headers: {get: () => "application/json"}, async json() { return value; }};
    }};
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(fs.readFileSync("apps/shared_static/http.js", "utf8"), context);
  vm.runInContext(fs.readFileSync("apps/approval_ui/static/send.js", "utf8"), context);
  return {nodes, requests, timers, start: () => vm.runInContext("start()", context)};
}

test("renders exact plain text and all recipients, then approves only the immutable hash", async () => {
  const p = page();
  await p.start();
  assert.equal(p.nodes.get("mailBody").textContent, "Hello\n\n<img src=x onerror=attack()>\n> quoted reply");
  assert.equal(p.nodes.get("subject").textContent, "<script>attack()</script>");
  assert.equal(p.nodes.get("bcc").textContent, "hidden@example.test");
  assert.equal(p.nodes.get("cc").textContent, "无");
  assert.equal(p.nodes.get("operation").textContent, "回复邮件");
  assert.equal(p.nodes.get("approve").disabled, true);
  p.nodes.get("confirm").checked = true;
  p.nodes.get("confirm").events.change();
  assert.equal(p.nodes.get("approve").disabled, false);
  await p.nodes.get("approve").events.click();
  assert.equal(p.requests.at(-1).url, "/approvals");
  assert.deepEqual(JSON.parse(p.requests.at(-1).options.body), {draft_id: id, payload_hash: "immutable-hash"});
  assert.equal(p.requests.at(-1).options.headers["X-CSRF-Token"], "csrf");
  assert.equal(p.nodes.get("approve").disabled, true);
  assert.match(p.nodes.get("result").textContent, /等待发送方执行。审批编号：approved-id/);
  assert.equal(p.timers.size, 0, "without the server dispatcher nothing polls");
  await p.nodes.get("approve").events.click();
  assert.equal(p.requests.length, 3);
});

test("with the server dispatcher the page follows the send until it is final", async () => {
  const dispatch = {approval_dispatch: {enabled: true, ready: true, kinds: ["send"]}};
  const p = page("send", "pending_approval", {extra: dispatch,
    later: [sendDraft("send", "attempting", dispatch), sendDraft("send", "confirmed", dispatch)]});
  await p.start();
  p.nodes.get("confirm").checked = true;
  await p.nodes.get("approve").events.click();
  assert.equal(p.nodes.get("result").textContent, "已批准，服务器将自动发送（关闭页面也会继续）。");
  assert.equal(p.nodes.get("executionState").textContent, "执行状态：已批准，排队等待服务器执行");
  for (const expected of ["正在执行", "执行成功"]) {
    assert.equal(p.timers.size, 1);
    const [[timerId, timer]] = [...p.timers.entries()];
    assert.equal(timer.duration, 5000);
    p.timers.delete(timerId);
    await timer.callback();
    assert.equal(p.requests.at(-1).url, `/drafts/${id}`);
    assert.equal(p.nodes.get("status").textContent, expected);
    assert.equal(p.nodes.get("executionState").textContent, `执行状态：${expected}`);
  }
  assert.equal(p.timers.size, 0, "a final status stops polling");
});

test("rejects other operation kinds and keeps completed drafts disabled", async () => {
  const wrong = page("trash");
  await wrong.start();
  assert.match(wrong.nodes.get("result").textContent, /仅用于发送/);
  assert.equal(wrong.nodes.get("approve").disabled, true);
  const approved = page("send", "approved");
  await approved.start();
  assert.equal(approved.nodes.get("confirm").disabled, true);
  assert.equal(approved.nodes.get("approve").disabled, true);
});
