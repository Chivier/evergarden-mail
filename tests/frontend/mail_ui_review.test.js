"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

function loadApp(answer) {
  const elements = new Map();
  const requests = [];
  const timers = new Map();
  let nextTimer = 0;
  const element = (tag = "div") => ({
    tag, textContent: "", value: "", hidden: false, disabled: false, open: false, children: [],
    dataset: {}, files: [], href: "",
    classList: { toggle() {} },
    setAttribute(name, value) { this[name] = value; },
    addEventListener() {}, append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    showModal() { this.open = true; }, close() { this.open = false; },
  });
  const setTimeout = (callback, duration) => { const id = ++nextTimer; timers.set(id, { callback, duration }); return id; };
  const clearTimeout = (id) => { timers.delete(id); };
  const context = {
    console, Intl, AbortController, setTimeout, clearTimeout,
    document: {
      addEventListener() {}, createElement: element,
      getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    },
    window: { setTimeout, clearTimeout, location: { pathname: "/", search: "", assign() {} } },
    async fetch(url, options) {
      requests.push({ url, options });
      return answer(url.replace("/api/mcp/", ""), JSON.parse(options.body || "null"), options);
    },
  };
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../../apps/shared_static/http.js"), "utf8"), context);
  vm.runInContext(`${fs.readFileSync(path.resolve(__dirname, "../../apps/mail_ui/static/app.js"), "utf8")}
;globalThis.__app = { openReview, checkApproval, executeApproved, mcp, stagedFileReferences, state };`, context);
  const app = context.__app;
  app.state.csrf = "c".repeat(32);
  app.state.approvalUrl = "https://approve.example.test";
  return { app, requests, timers, byId: (id) => context.document.getElementById(id) };
}

const json = (value, status = 200) => ({ status, ok: status >= 200 && status < 300,
  headers: { get: () => "application/json" }, async json() { return value; } });
const draft = (extra = {}) => ({
  draft_id: "d-1", kind: "archive", payload_hash: "h", requires_human_approval: true,
  execution_owner: "server", review_packet: { account: "icloud", stable_message_id: "m" }, ...extra,
});

test("server-executed drafts hide execution and explain the UIDPLUS move", () => {
  const page = loadApp(async () => json({}));
  page.app.openReview(draft({ review_packet: { account: "icloud", uidplus_move_fallback: true } }),
    "archive_approved", "Archive 是可恢复的文件夹移动。");
  assert.equal(page.byId("executeApprovedButton").hidden, true);
  assert.equal(page.byId("executeApprovedButton").disabled, true);
  assert.equal(page.byId("approvalLink").hidden, false);
  assert.equal(page.byId("approvalLink").href, "https://approve.example.test/review?mode=single&draft_id=d-1");
  assert.equal(page.byId("reviewStatus").textContent,
    "等待独立人工审批。批准后由服务器自动执行，可点击“检查审批状态”查看结果。");
  assert.match(page.byId("reviewWarning").textContent, /只删除这一封原件（UID EXPUNGE）/);
});

test("policy approvals are executable at once and need no approval page", () => {
  const page = loadApp(async () => json({}));
  page.app.openReview(draft({ execution_owner: "client", requires_human_approval: false, approval_id: "a-1" }),
    "archive_approved", "");
  assert.equal(page.app.state.draft.approvalId, "a-1");
  assert.equal(page.byId("executeApprovedButton").hidden, false);
  assert.equal(page.byId("executeApprovedButton").disabled, false);
  assert.equal(page.byId("approvalLink").hidden, true);
  assert.equal(page.byId("reviewStatus").textContent, "已自动批准。确认内容后点击“执行已批准操作”。");
});

test("an execution error keeps the button disabled until a status check allows a retry", async () => {
  const statuses = [
    { status: "retryable", approval: { approval_id: "a-1" }, review_packet: { account: "icloud" } },
    { status: "unknown", approval: { approval_id: "a-1" } },
  ];
  const page = loadApp(async (tool) => {
    if (tool === "archive_approved") {
      return { status: 504, ok: false, headers: { get: () => "text/html" }, async json() { throw new SyntaxError("<"); } };
    }
    if (tool === "get_draft_status") return json(statuses.shift());
    return json([]);
  });
  page.app.openReview(draft({ execution_owner: "client", requires_human_approval: false, approval_id: "a-1" }),
    "archive_approved", "");
  const running = page.app.executeApproved();
  assert.equal(page.byId("executeApprovedButton").disabled, true);
  await running;
  assert.match(page.byId("notice").textContent, /服务暂时不可用（HTTP 504）.*已提交的操作请先核实结果/);
  assert.equal(page.byId("reviewStatus").textContent, "状态：邮箱暂时不可用，可稍后再次执行");
  assert.equal(page.byId("executeApprovedButton").disabled, false);

  await page.app.executeApproved();
  assert.equal(page.byId("reviewStatus").textContent, "状态：正在核对执行结果");
  assert.equal(page.byId("executeApprovedButton").disabled, true);
  assert.equal(page.requests.filter((item) => item.url.endsWith("archive_approved")).length, 2);
});

test("server mode status checks never enable client execution and refresh mail when confirmed", async () => {
  const page = loadApp(async (tool) => (tool === "get_draft_status"
    ? json({ status: "confirmed", approval: { approval_id: "a-9" } })
    : json([])));
  page.app.openReview(draft(), "archive_approved", "");
  await page.app.checkApproval();
  assert.equal(page.byId("reviewStatus").textContent, "状态：执行成功");
  assert.equal(page.byId("executeApprovedButton").disabled, true);
  assert.equal(page.app.state.draft.approvalId, null);
  assert.ok(page.requests.some((item) => item.url.endsWith("list_recent")), "confirmed refreshes the list");
  await page.app.executeApproved();
  assert.equal(page.requests.some((item) => item.url.endsWith("archive_approved")), false);
});

test("UIDPLUS execution reports that the original was removed", async () => {
  const page = loadApp(async (tool) => (tool === "trash_approved"
    ? json({ state: "CONFIRMED", strategy: "uidplus_expunge", verified: true })
    : json([])));
  page.app.openReview(draft({ kind: "trash", execution_owner: "client", requires_human_approval: false, approval_id: "a-1" }),
    "trash_approved", "");
  await page.app.executeApproved();
  assert.equal(page.byId("notice").textContent, "已移动到目标文件夹并删除原件。");
  assert.equal(page.byId("reviewStatus").textContent, "执行状态：执行成功");
  assert.equal(page.byId("executeApprovedButton").disabled, true);
});

test("MCP calls get timeouts sized to the provider work they wait for", async () => {
  const page = loadApp(() => new Promise(() => {}));
  for (const [tool, expected] of [["archive_approved", 170000], ["sync_mail", 170000],
    ["preview_trash", 70000], ["prepare_send", 70000], ["get_draft_status", 25000], ["list_recent", 25000]]) {
    page.timers.clear();
    void page.app.mcp(tool, {});
    assert.deepEqual([...page.timers.values()].map((timer) => timer.duration), [expected], tool);
  }
  assert.equal(page.requests[0].options.headers["X-CSRF-Token"], "c".repeat(32));
});

test("attachments over 5 MiB are rejected before anything is staged", async () => {
  const page = loadApp(async () => json({ staged_attachment_id: "s" }));
  page.byId("composeFiles").files = [{ name: "small.txt", size: 10 }, { name: "big.pdf", size: 5 * 1024 * 1024 + 1 }];
  await assert.rejects(page.app.stagedFileReferences(), /附件超过 5 MiB 上限，请缩小后重试。（big\.pdf）/);
  assert.equal(page.requests.length, 0);
});
