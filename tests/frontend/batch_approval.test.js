"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

const json = (value, status = 200) => ({
  ok: status >= 200 && status < 300, status,
  headers: {get: () => "application/json"},
  async json() { return value; },
});

// The fake DOM only offers elements that exist in the real page, starting with
// the markup's `hidden` state, so script and markup cannot drift apart.
const markup = fs.readFileSync(path.resolve(__dirname, "../../apps/approval_ui/static/review.html"), "utf8");
const markupIds = new Map([...markup.matchAll(/<[a-z0-9]+\b[^>]*\bid="([^"]+)"[^>]*>/g)]
  .map(([tag, id]) => [id, /\shidden[\s>]/.test(tag)]));

// `responses` answers every non-execution request in order; the execution view
// polls independently and is answered from `execution` (an empty page by default).
function page(responses, {execution = [], messages = [], search = "?batch=trash", hash = "", confirm = true} = {}) {
  const nodes = new Map();
  const messageRequests = [];
  const requests = [];
  const executionRequests = [];
  const confirms = [];
  const replaced = [];
  const documentEvents = {};
  const timers = new Map();
  let nextTimer = 0;
  function node(tag = "div") {
    const element = {
      tag, children: [], events: {}, attributes: {}, parent: null, scrollTop: 0,
      checked: false, disabled: false, textContent: "", className: "", hidden: false,
      setAttribute(name, value) { this.attributes[name] = String(value); this[name] = value; },
      getAttribute(name) { return this.attributes[name] ?? null; },
      addEventListener(name, callback) { this.events[name] = callback; },
      append(...children) {
        for (const child of children) { child.parent = this; this.children.push(child); }
      },
      replaceChildren(...children) { this.children = []; this.append(...children); },
      remove() {
        if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this);
        this.parent = null;
      },
      focus() {},
      querySelectorAll(selector) {
        const inputs = [];
        const visit = (item) => {
          if (item.tag === "input" && (selector !== "input:checked" || item.checked)) inputs.push(item);
          item.children.forEach(visit);
        };
        this.children.forEach(visit);
        return inputs;
      },
    };
    const names = () => element.className.split(/\s+/).filter(Boolean);
    element.classList = {
      contains: (name) => names().includes(name),
      add: (name) => { if (!names().includes(name)) element.className = [...names(), name].join(" "); },
      remove: (name) => { element.className = names().filter((item) => item !== name).join(" "); },
      toggle(name, force = !names().includes(name)) {
        if (force) this.add(name); else this.remove(name);
        return force;
      },
    };
    return element;
  }
  const answer = async (value, url, options) => {
    if (typeof value === "function") return value(url, options);
    if (value instanceof Error) throw value;
    return json(value);
  };
  const context = {
    URLSearchParams, Date, AbortController,
    setTimeout(callback, duration) { const id = ++nextTimer; timers.set(id, {callback, duration}); return id; },
    clearTimeout(id) { timers.delete(id); },
    document: {
      createElement: node,
      addEventListener(name, callback) { documentEvents[name] = callback; },
      getElementById(id) {
        if (!markupIds.has(id)) throw new Error(`review.html has no #${id}`);
        if (!nodes.has(id)) nodes.set(id, Object.assign(node(), {hidden: markupIds.get(id)}));
        return nodes.get(id);
      },
    },
    window: {
      location: { search, hash, pathname: "/review", assign() {} },
      history: { replaceState(_state, _title, url) { replaced.push(url); } },
      addEventListener() {},
    },
    async fetch(url, options) {
      if (/^\/drafts\/[^/?]+\/message$/.test(url)) {
        messageRequests.push(url);
        return json(messages.length ? messages.shift() : {available: false, reason: "not_archived"});
      }
      if (url.startsWith("/drafts?view=execution")) {
        executionRequests.push({url, options});
        return answer(execution.length ? execution.shift() : {drafts: [], has_more: false}, url, options);
      }
      requests.push({url, options});
      return answer(responses.shift(), url, options);
    },
  };
  vm.createContext(context);
  loadI18n(context);
  // The styled confirm dialog (ui.js) is answered here: title + message is the
  // full question the reviewer sees.
  context.EG.confirm = async ({title, message}) => { confirms.push(`${title}${message}`); return confirm; };
  for (const file of ["../../apps/shared_static/http.js", "../../apps/approval_ui/static/review.js"]) {
    vm.runInContext(fs.readFileSync(path.resolve(__dirname, file), "utf8"), context);
  }
  vm.runInContext("globalThis.startPage = start", context);
  const toasts = () => nodes.get("toasts").children.map((item) => ({
    tone: item.className, text: item.children[0].textContent, close: item.children[1],
  }));
  const pollTimers = () => [...timers.values()].filter((timer) => timer.duration === 5000);
  const requestTimers = () => [...timers.values()].filter((timer) => timer.duration >= 25000);
  const elements = {get: (id) => context.document.getElementById(id)};
  return {context, nodes: elements, requests, executionRequests, messageRequests, confirms, replaced, documentEvents, timers,
    toasts, lastToast: () => toasts().at(-1), pollTimers, requestTimers};
}
const drafts = ["first", "second"].map((id) => ({
  draft_id: id, payload_hash: `${id}-hash`, status: "pending_approval",
  expires_at: "2030-01-01T00:00:00Z", review_packet: {account: "gmail", subject: "<img onerror=attack()>"},
}));
const ready = {enabled: true, ready: true, kinds: ["archive", "mark", "move", "send", "trash"],
  last_scan_at: "2030-01-01T00:00:00Z"};
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

test("returned archive and mark drafts appear in the todo tab for individual approval", async () => {
  const other = ["archive", "mark"].map((kind) => ({
    draft_id: `returned-${kind}`, kind, status: "pending_approval",
    summary: {account: "outlook", subject: "Needs another review", recovery_of: "old-failed"},
  }));
  const p = page([{csrf: "csrf", subject: "admin"},
    {drafts: [], total: 0, has_more: false, other_drafts: other, other_total: 2}]);
  await p.context.startPage();
  assert.equal(p.nodes.get("otherPending").hidden, false);
  assert.equal(p.nodes.get("otherPendingItems").children.length, 2);
  const row = p.nodes.get("otherPendingItems").children[0];
  assert.match(row.children[1].textContent, /归档.*再次审批/);
  assert.equal(row.children[3].children[0].href, "/review?mode=single&draft_id=returned-archive");
  assert.equal(p.nodes.get("otherPendingItems").querySelectorAll("input").length, 0);
  assert.equal(p.nodes.get("approveBatch").disabled, true);
  assert.match(p.nodes.get("pendingCount").textContent, /2/);
  assert.equal(p.requests.filter((request) => request.options?.method === "POST").length, 0);
});

test("HTML approval failure keeps selection and requires fresh confirmation after reconciliation", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false},
    () => ({ok: false, status: 502, headers: {get: () => "text/html"},
      async json() { throw new SyntaxError("Unexpected token '<'"); }}),
    {drafts: drafts.map(({draft_id, payload_hash}) => ({draft_id, payload_hash})), has_more: false},
    {drafts, has_more: false}]);
  await p.context.startPage();
  const input = p.nodes.get("batchItems").querySelectorAll("input")[0];
  input.checked = true; input.events.change();
  await p.nodes.get("approveBatch").events.click();
  assert.match(p.lastToast().text, /HTTP 502.*核实结果/);
  assert.equal(p.lastToast().tone, "toast toast-error");
  assert.equal(p.requests.at(-2).url, "/drafts?select_all=true");
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input")[0].checked, true);
  assert.equal(p.requests.filter((request) => request.url === "/approvals/batch").length, 1);
});

test("batch approval sends only reviewed selection with its hash and CSRF, then refreshes", async () => {
  const p = page([{csrf: "session-csrf", subject: "admin"}, {drafts, has_more: false},
    {results: [{draft_id: "first", status: "approved"}]}, {drafts: [drafts[1]], has_more: false}]);
  await p.context.startPage();
  assert.equal(p.nodes.get("single").hidden, true);
  assert.equal(p.nodes.get("tabs").hidden, false);
  const inputs = p.nodes.get("batchItems").querySelectorAll("input");
  inputs[0].checked = true;
  inputs[0].events.change();
  // Selecting is the review: no separate confirmation box.
  assert.equal(p.nodes.get("approveBatch").disabled, false);
  assert.equal(p.nodes.get("approveBatch").textContent, "批准移入已删除邮件（1）");
  const subject = p.nodes.get("batchItems").children[0].children[1].children[0];
  assert.equal(subject.textContent, "<img onerror=attack()>");
  assert.equal(subject.title, "<img onerror=attack()>");
  await p.nodes.get("approveBatch").events.click();
  const request = p.requests.find((r) => r.url === "/approvals/batch");
  assert.deepEqual(JSON.parse(request.options.body), {items: [{draft_id: "first", payload_hash: "first-hash"}]});
  assert.equal(request.options.headers["X-CSRF-Token"], "session-csrf");
  assert.match(p.lastToast().text, /^已批准 1 封，等待客户端执行。/);
  assert.equal(p.nodes.get("approveBatch").disabled, true);
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input").length, 1);
  assert.equal(p.executionRequests.length, 3, "approval re-reads the queue and refreshes the execution counts");
});

test("a retried batch counts already approved drafts as approved", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false},
    {results: [{draft_id: "first", status: "already_approved"}, {draft_id: "second", status: "approved"}]},
    {drafts: [], has_more: false}]);
  await p.context.startPage();
  const all = p.nodes.get("selectAll");
  all.checked = true;
  all.events.change({currentTarget: all});
  await p.nodes.get("approveBatch").events.click();
  assert.match(p.lastToast().text, /^已批准 2 封，/);
  assert.equal(p.lastToast().tone, "toast toast-success");
});

test("select all enables approval at once and partial failures are visible", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false},
    {results: [{draft_id: "first", status: "approved"}, {draft_id: "second", status: "failed", detail: "draft is expired"}]},
    {drafts: [], has_more: false}]);
  await p.context.startPage();
  p.nodes.get("selectAll").checked = true;
  p.nodes.get("selectAll").events.change({currentTarget: p.nodes.get("selectAll")});
  assert.equal(p.nodes.get("approveBatch").disabled, false);
  await p.nodes.get("approveBatch").events.click();
  assert.match(p.lastToast().text, /已批准 1 项，失败 1 项/);
  assert.match(p.lastToast().text, /「<img onerror=attack\(\)>」: draft is expired/);
  assert.equal(p.lastToast().tone, "toast toast-error");
});

test("pending tab shows the queue total in the tab and the pager", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: true, total: 325}],
    {execution: [{drafts: [], has_more: false, counts: {all: 250}}]});
  await p.context.startPage();
  assert.equal(p.nodes.get("pendingCount").textContent, "（325）");
  assert.equal(p.nodes.get("executionCount").textContent, "（250）");
  assert.equal(p.nodes.get("pageInfo").textContent, "1–2 / 325");
  assert.equal(p.nodes.get("pendingPanel").hidden, false);
  assert.equal(p.nodes.get("executionPanel").hidden, true);
  assert.equal(p.pollTimers().length, 1, "only the dispatcher activity polls; the hidden execution tab does not");
  p.pollTimers()[0].callback();
  await flush();
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=all&offset=0&limit=1");
  assert.equal(p.pollTimers().length, 1);
});

test("200 long packets select and deselect reliably and open details only in the drawer", async () => {
  const many = Array.from({length: 200}, (_, i) => ({...drafts[0], draft_id: `draft-${i}`,
    review_packet: {subject: "long subject".repeat(500), body: "mail body".repeat(10000)}}));
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts: many, has_more: true},
    {draft_id: "draft-0", kind: "trash", status: "pending_approval", expires_at: "2030-01-01T00:00:00Z",
      review_packet: {subject: "Full packet", account: "gmail", source_folder: "INBOX", source_uid: 7}}]);
  await p.context.startPage();
  const all = p.nodes.get("selectAll");
  all.checked = true;
  all.events.change({currentTarget: all});
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input:checked").length, 200);
  assert.match(p.nodes.get("approveBatch").textContent, /200/);
  const inputs = p.nodes.get("batchItems").querySelectorAll("input");
  inputs[100].checked = false;
  inputs[100].events.change();
  assert.equal(all.indeterminate, true);
  all.checked = true;
  all.events.change({currentTarget: all});
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input:checked").length, 200);
  const row = p.nodes.get("batchItems").children[0];
  assert.equal(row.children.length, 6);
  const details = row.children[5].children[0];
  assert.equal(details.textContent, "详情");
  assert.equal(p.nodes.get("drawer").hidden, true);
  await details.events.click();
  assert.equal(p.requests.at(-1).url, "/drafts/draft-0");
  assert.equal(p.nodes.get("drawer").hidden, false);
  assert.equal(p.nodes.get("drawerTitle").textContent, "Full packet");
  assert.match(p.nodes.get("drawerPacket").textContent, /"source_uid": 7/);
  assert.equal(row.classList.contains("is-open"), true);
  p.documentEvents.keydown({key: "Escape"});
  assert.equal(p.nodes.get("drawer").hidden, true);
  assert.equal(row.classList.contains("is-open"), false);
  all.checked = false;
  all.events.change({currentTarget: all});
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input:checked").length, 0);
});

test("paging keeps cross-page selection and clears only confirmation", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: true},
    {drafts: [drafts[1]], has_more: false}]);
  await p.context.startPage();
  const all = p.nodes.get("selectAll");
  all.checked = true;
  all.events.change({currentTarget: all});
  await p.nodes.get("nextPage").events.click();
  assert.equal(p.requests.at(-1).url, "/drafts?offset=50&limit=50");
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input:checked").length, 1);
  assert.match(p.nodes.get("approveBatch").textContent, /2/);
  assert.equal(p.nodes.get("nextPage").disabled, true);
});

test("select all requests every pending ID and hash in one lightweight call", async () => {
  const allDrafts = Array.from({length: 201}, (_, i) => ({
    draft_id: `all-${i}`, payload_hash: `hash-${i}`,
  }));
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts: [drafts[0]], has_more: true},
    {drafts: allDrafts, has_more: false}]);
  await p.context.startPage();
  await p.nodes.get("selectAllPages").events.click();
  assert.equal(p.requests.at(-1).url, "/drafts?select_all=true");
  assert.match(p.nodes.get("approveBatch").textContent, /201/);
  assert.equal(p.nodes.get("selectionCount").textContent, "已选 201 封");
});

test("select all replaces stale selections and requires fresh confirmation", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false},
    {drafts: [{draft_id: "second", payload_hash: "second-hash"}], has_more: false},
    {results: [{draft_id: "second", status: "approved"}, {draft_id: "first", status: "failed", detail: "draft is expired"}]},
    {drafts: [], has_more: false}]);
  await p.context.startPage();
  const all = p.nodes.get("selectAll");
  all.checked = true;
  all.events.change({currentTarget: all});
  await p.nodes.get("selectAllPages").events.click();
  assert.match(p.nodes.get("approveBatch").textContent, /（1）/);
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input")[0].checked, false);
  assert.equal(p.nodes.get("batchItems").querySelectorAll("input")[1].checked, true);
  // A still-visible row can be reselected even if the latest snapshot dropped it;
  // its immutable ID/hash must still be sent for server-side expiry validation.
  const input = p.nodes.get("batchItems").querySelectorAll("input")[0];
  input.checked = true;
  input.events.change();
  await p.nodes.get("approveBatch").events.click();
  const post = p.requests.find((item) => item.url === "/approvals/batch");
  assert.deepEqual(JSON.parse(post.options.body).items, [
    {draft_id: "second", payload_hash: "second-hash"}, {draft_id: "first", payload_hash: "first-hash"},
  ]);
});

function stalledRequest(_url, options) {
  return new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => {
      const error = new Error("aborted");
      error.name = "AbortError";
      reject(error);
    });
  });
}

test("select all times out, keeps the previous selection and unlocks controls", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: true}, stalledRequest]);
  await p.context.startPage();
  const input = p.nodes.get("batchItems").querySelectorAll("input")[0];
  input.checked = true;
  input.events.change();
  const selecting = p.nodes.get("selectAllPages").events.click();
  assert.equal(p.nodes.get("refreshBatch").disabled, true);
  const requestCount = p.requests.length;
  await p.nodes.get("nextPage").events.click();
  await p.nodes.get("refreshBatch").events.click();
  await p.nodes.get("approveBatch").events.click();
  assert.equal(p.requests.length, requestCount);
  const timer = p.requestTimers().find((item) => item.duration === 25000);
  assert.equal(timer.duration, 25000);
  timer.callback();
  await selecting;
  assert.match(p.lastToast().text, /全选失败：请求超时/);
  assert.match(p.nodes.get("approveBatch").textContent, /（1）/);
  assert.equal(p.nodes.get("refreshBatch").disabled, false);
  // The kept selection can be approved again straight away.
  assert.equal(p.nodes.get("approveBatch").disabled, false);
  assert.equal(p.requestTimers().length, 0);
});

test("526 selected drafts submit in three bounded batches with progress, then report the queue", async () => {
  const many = Array.from({length: 526}, (_, i) => ({draft_id: `draft-${i}`, payload_hash: `hash-${i}`}));
  const labels = [];
  const result = (items) => () => {
    labels.push(p.nodes.get("approveBatch").textContent);
    return json({results: items.map((item) => ({draft_id: item.draft_id, status: "approved"}))});
  };
  const busy = {...ready, queue: {ready: 540, limit: 2000},
    activity: {current: null, finished_recent: 60, window_minutes: 10, blocked: 0}};
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: true, approval_dispatch: ready},
    {drafts: many}, result(many.slice(0, 200)), result(many.slice(200, 400)), result(many.slice(400)),
    {drafts: [], has_more: false}],
  {execution: [{drafts: [], has_more: false}, {drafts: [], has_more: false, approval_dispatch: busy}]});
  await p.context.startPage();
  await p.nodes.get("selectAllPages").events.click();
  await p.nodes.get("approveBatch").events.click();
  const posts = p.requests.filter((item) => item.url === "/approvals/batch");
  assert.deepEqual(posts.map((item) => JSON.parse(item.options.body).items.length), [200, 200, 126]);
  assert.deepEqual(posts.flatMap((item) => JSON.parse(item.options.body).items), many);
  assert.deepEqual(labels, ["正在提交 1–200 / 526", "正在提交 201–400 / 526", "正在提交 401–526 / 526"]);
  assert.equal(p.executionRequests[1].url, "/drafts?view=execution&status=all&offset=0&limit=1",
    "fresh queue numbers are read after the submission");
  assert.equal(p.lastToast().text, "已批准 526 封，已排入执行队列。队列现有 540 项，"
    + "按近 10 分钟速度预计约 90 分钟全部完成。进度见“执行记录 · 执行中”。");
  assert.equal(p.lastToast().tone, "toast toast-success");
  assert.equal(p.requestTimers().length, 0);

  const action = p.nodes.get("toasts").children.at(-1).children[2];
  assert.equal(action.textContent, "查看进度");
  action.events.click();
  await flush();
  assert.equal(p.toasts().length, 0, "the action closes its toast");
  assert.equal(p.nodes.get("executionPanel").hidden, false);
  assert.equal(p.nodes.get("chip-running").getAttribute("aria-pressed"), "true");
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=running&offset=0&limit=50");
});

test("a stalled second batch keeps only the unapproved drafts selected and stops submission", async () => {
  const many = Array.from({length: 526}, (_, i) => ({draft_id: `draft-${i}`, payload_hash: `hash-${i}`}));
  // draft-200 was approved elsewhere meanwhile and disappears from the pending snapshot.
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: true}, {drafts: many},
    {results: many.slice(0, 200).map((item) => ({draft_id: item.draft_id, status: "approved"}))},
    stalledRequest, {drafts: [...many.slice(0, 200), ...many.slice(201)], has_more: false},
    {drafts, has_more: true}]);
  await p.context.startPage();
  await p.nodes.get("selectAllPages").events.click();
  const submitting = p.nodes.get("approveBatch").events.click();
  // Allow the first resolved batch and its JSON body to reach the second fetch.
  for (let i = 0; i < 10; i++) await Promise.resolve();
  assert.equal(p.nodes.get("approveBatch").textContent, "正在提交 201–400 / 526");
  const timer = p.requestTimers().find((item) => item.duration === 45000);
  assert.equal(timer.duration, 45000);
  timer.callback();
  await submitting;
  assert.equal(p.requests.filter((item) => item.url === "/approvals/batch").length, 2);
  assert.equal(p.requests.at(-2).url, "/drafts?select_all=true");
  assert.equal(p.requests.at(-1).url, "/drafts?offset=0&limit=50");
  assert.match(p.lastToast().text, /已确认批准 200 项/);
  assert.match(p.lastToast().text, /请求超时，结果未知/);
  assert.equal(p.lastToast().tone, "toast toast-error");
  // 526 selected - 200 approved - 1 no longer pending.
  assert.match(p.nodes.get("approveBatch").textContent, /（325）/);
  assert.equal(p.nodes.get("refreshBatch").disabled, false);
  assert.equal(p.nodes.get("approveBatch").disabled, false);
});

test("a dispatcher without a fresh heartbeat blocks batch approval until it is ready", async () => {
  const p = page([{csrf: "csrf", subject: "admin"},
    {drafts, has_more: false, approval_dispatch: {...ready, ready: false}},
    {drafts, has_more: false, approval_dispatch: ready}]);
  await p.context.startPage();
  assert.equal(p.nodes.get("dispatchPill").textContent, "自动执行未运行");
  assert.match(p.nodes.get("dispatchPill").className, /pill-bad/);
  assert.equal(p.nodes.get("batchBlocked").hidden, false);
  assert.equal(p.nodes.get("batchBlocked").textContent, "自动执行服务未运行，暂不接受批准。");
  const all = p.nodes.get("selectAll");
  all.checked = true;
  all.events.change({currentTarget: all});
  assert.equal(p.nodes.get("approveBatch").disabled, true);
  await p.nodes.get("approveBatch").events.click();
  assert.equal(p.requests.some((item) => item.url === "/approvals/batch"), false);
  await p.nodes.get("refreshBatch").events.click();
  assert.equal(p.nodes.get("dispatchPill").textContent, "自动执行运行中");
  assert.match(p.nodes.get("dispatchPill").title, /上次扫描/);
  assert.equal(p.nodes.get("batchBlocked").hidden, true);
  assert.equal(p.nodes.get("approveBatch").disabled, false);
});

test("a dispatcher that does not run Trash blocks batch approval; client execution does not", async () => {
  const p = page([{csrf: "csrf", subject: "admin"},
    {drafts, has_more: false, approval_dispatch: {...ready, kinds: ["archive"]}},
    {drafts, has_more: false, approval_dispatch: {enabled: false, ready: false, kinds: []}}]);
  await p.context.startPage();
  assert.equal(p.nodes.get("batchBlocked").textContent, "自动执行服务未启用此类操作，暂不接受批准。");
  await p.nodes.get("refreshBatch").events.click();
  assert.equal(p.nodes.get("dispatchPill").textContent, "客户端执行");
  assert.match(p.nodes.get("dispatchPill").className, /pill-muted/);
  assert.equal(p.nodes.get("batchBlocked").hidden, true);
});

test("the activity line says what runs now, how much is queued, how long it takes and what waits", async () => {
  const dispatch = (queued, activity = {}) => ({...ready, queue: {ready: queued},
    activity: {current: null, finished_recent: 0, window_minutes: 10, blocked: 0, ...activity}});
  const busy = dispatch(120, {finished_recent: 45, blocked: 2, current: {draft_id: "d", kind: "trash",
    subject: "A quarterly report whose subject is far too long to show whole", account: "gmail",
    started_at: "2030-01-01T00:00:00Z"}});
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false, approval_dispatch: busy}],
    {execution: [{drafts: [], has_more: false, approval_dispatch: busy},
      {drafts: [], approval_dispatch: dispatch(0, {finished_recent: 12})},
      {drafts: [], approval_dispatch: dispatch(750, {finished_recent: 50})},
      {drafts: [], approval_dispatch: dispatch(2000)},
      {drafts: [], approval_dispatch: {...busy, ready: false}},
      {drafts: [], approval_dispatch: {enabled: false, ready: false, kinds: []}}]});
  await p.context.startPage();
  const bar = p.nodes.get("activityBar");
  const poll = async () => {
    p.pollTimers()[0].callback();
    await flush();
  };
  assert.equal(bar.hidden, false);
  assert.equal(bar.textContent, "正在执行：移入废纸篓「A quarterly report whose subject is far …」（gmail）"
    + " · 队列 120 项 · 近 10 分钟完成 45 项 · 预计约 27 分钟 · 2 项等待同一邮件的上一操作结束");
  assert.equal(bar.className, "activity-bar activity-busy");
  await poll();
  assert.equal(bar.textContent, "自动执行空闲，队列为空 · 近 10 分钟完成 12 项");
  assert.equal(bar.className, "activity-bar");
  await poll();
  assert.equal(bar.textContent, "自动执行运行中 · 队列 750 项 · 近 10 分钟完成 50 项 · 预计约 2.5 小时");
  await poll();
  assert.equal(bar.textContent, "自动执行运行中 · 队列 2000 项", "no rate, no estimate");
  assert.equal(p.nodes.get("queueInfo").textContent, "待执行 2000");
  assert.equal(p.nodes.get("queueInfo").className, "queue-info");
  await poll();
  assert.equal(bar.textContent, "自动执行服务未运行，已批准的操作会在恢复后继续");
  assert.equal(bar.className, "activity-bar activity-bad");
  await poll();
  assert.equal(bar.hidden, true, "client execution has no server activity to show");
});

// Mirrors the server's folding of fine-grained statuses into four phases.
const PHASES = {pending_approval: "pending", approval_expired: "failed", revoked: "failed", approved: "running",
  blocked: "running", awaiting_client: "running", retryable: "running", attempting: "running", unknown: "running",
  confirmed: "confirmed", failed: "failed", client_expired: "failed", consumed: "failed"};
const execution = (status, extra = {}) => ({
  draft_id: status, payload_hash: `${status}-hash`, status, phase: PHASES[status], kind: "trash", attempt: 1,
  revocable: false, summary: {subject: "<img onerror=attack()>", account: "gmail", sender: "sender@example.test"},
  approval: {approved_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-01T01:00:00Z", source: "human"},
  error_class: null, ...extra,
});
const counts = {all: 250, pending: 40, running: 120, confirmed: 70, failed: 20};

test("execution records show one pill per phase with a plain note, attempts and counts", async () => {
  const items = [
    execution("approved", {revocable: true}), execution("confirmed"),
    execution("unknown", {error_class: "ProviderOutcomeUnknown"}),
    execution("failed", {error_class: "ProviderDefinitelyRejected"}),
    execution("revoked"), execution("retryable", {attempt: 3, error_class: "ProviderNotAttempted", revocable: true}),
    execution("blocked", {revocable: true}), execution("client_expired"),
    execution("failed", {draft_id: "gone", error_class: "ProviderSourceGone"}),
  ];
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts: [], has_more: false}],
    {hash: "#execution", execution: [{drafts: items, has_more: true, counts}, new Error("database offline")]});
  await p.context.startPage();
  assert.equal(p.executionRequests.length, 1, "the execution view loads immediately");
  assert.equal(p.nodes.get("executionPanel").hidden, false);
  assert.equal(p.nodes.get("pendingPanel").hidden, true);
  const rows = p.nodes.get("executionItems").children;
  assert.equal(rows.length, 9);
  const pill = (row) => row.children[4].children[0];
  const note = (row) => row.children[4].children[1]?.textContent;
  assert.deepEqual(rows.map((row) => pill(row).textContent),
    ["执行中", "成功", "执行中", "失败", "失败", "执行中", "执行中", "失败", "失败"]);
  assert.deepEqual(rows.map((row) => pill(row).className), ["pill pill-info", "pill pill-ok", "pill pill-info",
    "pill pill-bad", "pill pill-bad", "pill pill-info", "pill pill-info", "pill pill-bad", "pill pill-bad"]);
  assert.deepEqual(rows.map(note), ["排队等待执行", undefined, "正在自动核对结果", "服务商拒绝",
    "已撤销", "邮箱暂不可用，稍后自动重试 · 第 3 次", "等待同一邮件的上一操作结束",
    "自动批准已失效，客户端未执行", "邮件已不在原文件夹，无法执行"]);
  assert.equal(pill(rows[3]).title, "执行失败");
  assert.equal(rows[3].children[4].children[1].title, "服务商拒绝（ProviderDefinitelyRejected）");
  assert.equal(rows[0].children[0].children[0].textContent, "<img onerror=attack()>");
  assert.equal(rows[0].children[0].children[1].textContent, "sender@example.test");
  assert.match(rows[0].children[5].children[0].textContent, /^批准 /);
  assert.match(rows[0].children[5].children[1].textContent, /^期限 (剩|已过) /);
  const ops = (row) => row.children[6].children.map((child) => child.textContent);
  assert.deepEqual(ops(rows[0]), ["撤销", "详情"], "waiting rows can be revoked");
  assert.deepEqual(ops(rows[1]), ["详情"], "finished rows cannot");
  assert.equal(p.nodes.get("executionCount").textContent, "（250）");
  assert.deepEqual(["all", "pending", "running", "confirmed", "failed"].map((id) => p.nodes.get(`count-${id}`).textContent),
    ["250", "40", "120", "70", "20"]);
  assert.equal(p.nodes.get("executionPageInfo").textContent, "1–9 / 250");
  assert.equal(p.nodes.get("nextExecution").disabled, false);
  assert.equal(p.pollTimers().length, 1);
  await p.nodes.get("nextExecution").events.click();
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=all&offset=50&limit=50");
  assert.equal(p.nodes.get("executionError").hidden, false);
  assert.match(p.nodes.get("executionError").textContent, /记录可能已过时/);
  assert.equal(p.nodes.get("executionItems").children.length, 9, "a failed refresh keeps the last rows");
});

test("pending drafts in the execution view show their submission time and link to approval", async () => {
  const id = "00000000-0000-0000-0000-000000000077";
  const unapproved = {approval: null, created_at: "2030-01-01T08:00:00Z", expires_at: "2030-01-02T08:00:00Z"};
  const items = [execution("pending_approval", {draft_id: id, ...unapproved}),
    execution("pending_approval", {draft_id: "send-1", kind: "send", ...unapproved})];
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts: [], has_more: false, approval_dispatch: ready}],
    {hash: "#execution", execution: [{drafts: items, has_more: false, approval_dispatch: ready}]});
  await p.context.startPage();
  const rows = p.nodes.get("executionItems").children;
  assert.equal(rows[0].children[4].children[0].textContent, "待审批");
  assert.equal(rows[0].children[4].children[1].textContent, "等待审批");
  assert.equal(rows[0].children[3].textContent, "—");
  assert.match(rows[0].children[5].children[0].textContent, /^提交 \d/);
  assert.match(rows[0].children[5].children[1].textContent, /^有效期 (剩|已过) /);
  assert.match(rows[0].children[5].title, /^提交：.*\n审批单有效期至：/);
  const ops = rows[0].children[6].children;
  assert.deepEqual(ops.map((child) => child.textContent), ["去审批", "详情"]);
  assert.equal(ops[0].tag, "a");
  assert.equal(ops[0].href, `/review?mode=single&draft_id=${id}`);
  assert.equal(rows[1].children[6].children[0].href, "/review/send?draft_id=send-1");
});

test("execution view renders kind and approval source labels with revoke buttons", async () => {
  const items = [
    execution("approved", {revocable: true}),
    execution("client_expired", {kind: "archive", approval: {...execution("x").approval, source: "policy"}}),
    execution("retryable", {kind: "send", attempt: 2, error_class: "ProviderNotAttempted", revocable: true,
      summary: {subject: "Hello", account: "work", from: "me@work.test"}}),
    execution("failed", {draft_id: "policy-failed", kind: "mark",
      approval: {...execution("x").approval, source: "policy"}}),
  ];
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts: [], has_more: false, approval_dispatch: ready}],
    {hash: "#execution", execution: [{drafts: items, has_more: false, approval_dispatch: ready}]});
  await p.context.startPage();
  const rows = p.nodes.get("executionItems").children;
  const text = (row, index) => row.children[index].textContent;
  assert.deepEqual(rows.map((row) => text(row, 1)), ["移入废纸篓", "归档", "发送", "标记"]);
  assert.deepEqual(rows.map((row) => text(row, 3)), ["人工", "自动", "人工", "自动"]);
  assert.equal(rows[2].children[0].children[1].textContent, "me@work.test");
  const ops = (row) => row.children[6].children.map((child) => child.textContent);
  assert.deepEqual(ops(rows[0]), ["撤销", "详情"]);
  assert.deepEqual(ops(rows[1]), ["详情"]);
  assert.deepEqual(ops(rows[2]), ["撤销", "详情"]);
  assert.deepEqual(ops(rows[3]), ["详情"]);
  assert.equal(rows[0].children[6].children[0].disabled, false);
});

test("revoking a waiting row posts that item after confirmation, then refreshes", async () => {
  const items = [
    execution("approved", {draft_id: "a", payload_hash: "a-hash", revocable: true}),
    execution("confirmed", {draft_id: "b", payload_hash: "b-hash"}),
  ];
  const page_ = {drafts: items, has_more: false, approval_dispatch: ready};
  const after = {drafts: [execution("revoked", {draft_id: "a", payload_hash: "a-hash"}), items[1]],
    has_more: false, approval_dispatch: ready};
  const p = page([{csrf: "revoke-csrf", subject: "admin"}, {drafts: [], has_more: false},
    {results: [{draft_id: "a", status: "revoked"}]}],
  {hash: "#execution", execution: [page_, after]});
  await p.context.startPage();
  const button = p.nodes.get("executionItems").children[0].children[6].children[0];
  assert.equal(button.textContent, "撤销");
  await button.events.click();
  assert.deepEqual(p.confirms, ["撤销 1 项批准？撤销后服务器不再执行；已经开始执行的项无法撤销。"]);
  const revoke = p.requests.find((item) => item.url === "/approvals/revoke");
  assert.deepEqual(JSON.parse(revoke.options.body), {items: [{draft_id: "a", payload_hash: "a-hash"}]});
  assert.equal(revoke.options.headers["X-CSRF-Token"], "revoke-csrf");
  assert.equal(p.lastToast().text, "已撤销 1 项。");
  assert.equal(p.lastToast().tone, "toast toast-success");
  assert.equal(p.executionRequests.length, 2, "revoking refreshes the execution records");
  const rows = p.nodes.get("executionItems").children;
  assert.deepEqual(rows[0].children[6].children.map((child) => child.textContent), ["详情"]);
  assert.equal(rows[0].children[4].children[1].textContent, "已撤销");
});

test("a declined or failed revoke changes nothing and reports the cause", async () => {
  const row = execution("approved", {draft_id: "a", payload_hash: "a-hash", revocable: true});
  const declined = page([{csrf: "csrf", subject: "admin"}, {drafts: [], has_more: false}],
    {confirm: false, hash: "#execution",
      execution: [{drafts: [row], has_more: false, approval_dispatch: ready}]});
  await declined.context.startPage();
  await declined.nodes.get("executionItems").children[0].children[6].children[0].events.click();
  assert.equal(declined.confirms.length, 1);
  assert.equal(declined.requests.some((item) => item.url === "/approvals/revoke"), false);

  const failing = page([{csrf: "csrf", subject: "admin"}, {drafts: [], has_more: false},
    {results: [{draft_id: "a", status: "failed", detail: "NOT_REVOCABLE: not a revocable approval (only approvals that have not started executing)"}]}],
  {hash: "#execution", execution: [{drafts: [row], has_more: false, approval_dispatch: ready},
    {drafts: [row], has_more: false, approval_dispatch: ready}]});
  await failing.context.startPage();
  await failing.nodes.get("executionItems").children[0].children[6].children[0].events.click();
  assert.match(failing.lastToast().text, /已撤销 0 项，失败 1 项/);
  assert.match(failing.lastToast().text, /不是可撤销的批准/);
  assert.equal(failing.lastToast().tone, "toast toast-error");
});

test("execution chips map to the status query and restart from the first page", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts: [], has_more: false}],
    {hash: "#execution", execution: [{drafts: [execution("confirmed")], has_more: true, counts}]});
  await p.context.startPage();
  await p.nodes.get("nextExecution").events.click();
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=all&offset=50&limit=50");
  await p.nodes.get("chip-failed").events.click();
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=failed&offset=0&limit=50");
  assert.equal(p.nodes.get("chip-failed").getAttribute("aria-pressed"), "true");
  assert.equal(p.nodes.get("chip-all").getAttribute("aria-pressed"), "false");
  assert.equal(p.nodes.get("executionEmpty").hidden, false);
  assert.equal(p.nodes.get("executionEmpty").textContent, "当前筛选下没有记录。");
  await p.nodes.get("chip-pending").events.click();
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=pending&offset=0&limit=50");
  await p.nodes.get("chip-running").events.click();
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=running&offset=0&limit=50");
  assert.equal(p.nodes.get("chip-failed").getAttribute("aria-pressed"), "false");
});

test("execution polling runs only while its tab is open; the pending tab polls the dispatcher instead", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts: [], has_more: false}]);
  const polls = () => p.pollTimers().map((timer) => timer.callback.name);
  await p.context.startPage();
  assert.equal(p.executionRequests.length, 1, "counts load once for the tab label");
  assert.deepEqual(polls(), ["pollDispatch"]);
  p.nodes.get("tabExecution").events.click();
  await flush();
  assert.equal(p.executionRequests.length, 2);
  assert.deepEqual(polls(), ["refreshExecution"]);
  assert.deepEqual(p.replaced, ["#execution"]);
  assert.equal(p.nodes.get("tabExecution").getAttribute("aria-selected"), "true");
  assert.equal(p.nodes.get("executionPanel").hidden, false);
  p.nodes.get("tabPending").events.click();
  assert.deepEqual(polls(), ["pollDispatch"]);
  assert.deepEqual(p.replaced, ["#execution", "#pending"]);
  assert.equal(p.nodes.get("pendingPanel").hidden, false);
  // Background tabs pause polling and catch up when visible again.
  p.context.document.hidden = true;
  p.documentEvents.visibilitychange();
  assert.deepEqual(polls(), []);
  p.context.document.hidden = false;
  p.documentEvents.visibilitychange();
  await flush();
  assert.equal(p.executionRequests.at(-1).url, "/drafts?view=execution&status=all&offset=0&limit=1");
  assert.deepEqual(polls(), ["pollDispatch"]);
});

test("toasts: errors stay until closed, successes dismiss themselves", async () => {
  const p = page([new Error("offline")]);
  await p.context.startPage();
  assert.equal(p.lastToast().tone, "toast toast-error");
  assert.match(p.lastToast().text, /网络连接中断/);
  assert.equal([...p.timers.values()].filter((timer) => timer.duration === 6000).length, 0);
  p.lastToast().close.events.click();
  assert.equal(p.toasts().length, 0);

  const ok = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false},
    {results: [{draft_id: "first", status: "approved"}]}, {drafts: [], has_more: false}]);
  await ok.context.startPage();
  const input = ok.nodes.get("batchItems").querySelectorAll("input")[0];
  input.checked = true;
  input.events.change();
  await ok.nodes.get("approveBatch").events.click();
  assert.equal(ok.toasts().length, 1);
  [...ok.timers.values()].find((timer) => timer.duration === 6000).callback();
  assert.equal(ok.toasts().length, 0);
});

const draftId = "00000000-0000-0000-0000-000000000042";
const singleDraft = (status, extra = {}) => ({
  draft_id: draftId, kind: "archive", payload_hash: "single-hash", status, phase: PHASES[status], revocable: false,
  expires_at: "2030-01-01T00:00:00Z", approval_dispatch: ready, queue_position: null, error_class: null,
  review_packet: {account: "icloud", subject: "Hi", uidplus_move_fallback: true}, ...extra,
});

test("a deep link with a Trash draft opens the list with that draft in the drawer", async () => {
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false},
    singleDraft("pending_approval", {kind: "trash", review_packet: {subject: "Linked"}})],
  {search: `?batch=trash&draft_id=${draftId}`});
  await p.context.startPage();
  await flush();
  assert.equal(p.nodes.get("single").hidden, true);
  assert.equal(p.requests.at(-1).url, `/drafts/${draftId}`);
  assert.equal(p.nodes.get("drawer").hidden, false);
  assert.equal(p.nodes.get("drawerTitle").textContent, "Linked");
  assert.equal(p.nodes.get("drawerSingleLink").href, `/review?mode=single&draft_id=${draftId}`);
  p.nodes.get("drawerClose").events.click();
  assert.equal(p.nodes.get("drawer").hidden, true);
});

test("single review warns about UIDPLUS moves and reports queue place and progress after approval", async () => {
  const approval = {approval_id: "approval-1", source: "human"};
  const p = page([{csrf: "csrf", subject: "admin"}, singleDraft("pending_approval"),
    {approval_id: "approval-1", approval_source: "human"},
    singleDraft("approved", {approval, queue_position: 4}), singleDraft("attempting", {approval}),
    singleDraft("unknown", {approval}), singleDraft("confirmed", {approval})],
  {search: `?draft_id=${draftId}`});
  await p.context.startPage();
  assert.equal(p.nodes.get("single").hidden, false);
  assert.equal(p.nodes.get("tabs").hidden, true);
  assert.equal(p.nodes.get("activityBar").hidden, true, "the activity line belongs to the list view");
  assert.equal(p.executionRequests.length, 0);
  assert.match(p.nodes.get("warning").textContent, /只删除这一封原件（UID EXPUNGE）/);
  assert.equal(p.nodes.get("kind").textContent, "归档");
  assert.equal(p.nodes.get("revokeSingle").hidden, true);
  assert.equal(p.nodes.get("executionState").textContent, "");
  assert.equal(p.nodes.get("approve").disabled, false);
  await p.nodes.get("approve").events.click();
  const post = p.requests.find((item) => item.url === "/approvals");
  assert.deepEqual(JSON.parse(post.options.body), {draft_id: draftId, payload_hash: "single-hash"});
  assert.equal(p.requests.at(-1).url, `/drafts/${draftId}`, "a fresh read follows the approval");
  assert.equal(p.lastToast().text, "已批准，已加入执行队列（第 4 位），服务器会自动执行，关闭本页也会继续。");
  assert.equal(p.lastToast().tone, "toast toast-success");
  assert.equal(p.nodes.get("executionState").textContent, "已批准，排队中：前面还有 3 项");
  assert.equal(p.nodes.get("executionState").className, "execution-state tone-info");
  assert.equal(p.nodes.get("approve").disabled, true);
  for (const expected of ["正在执行…", "正在自动核对执行结果…", "执行成功"]) {
    assert.equal(p.pollTimers().length, 1);
    p.pollTimers()[0].callback();
    await flush();
    assert.equal(p.nodes.get("executionState").textContent, expected);
  }
  assert.equal(p.nodes.get("executionState").className, "execution-state tone-ok");
  assert.equal(p.pollTimers().length, 0);
});

test("single review names the head of the queue, a failure cause and a lapsed approval", async () => {
  const approval = {approval_id: "approval-1", source: "human"};
  const expectations = [
    [singleDraft("approved", {approval, queue_position: 1}), "已批准，排在队首，即将执行"],
    [singleDraft("failed", {approval, error_class: "ProviderSourceGone"}),
      "执行失败：邮件已不在原文件夹，无法执行"],
    [singleDraft("approval_expired", {approval}), "批准已失效（旧模式遗留），未执行"],
  ];
  for (const [value, expected] of expectations) {
    const p = page([{csrf: "csrf", subject: "admin"}, value], {search: `?mode=single&draft_id=${draftId}`});
    await p.context.startPage();
    assert.equal(p.nodes.get("executionState").textContent, expected);
  }
});

test("single review blocks approval while the dispatcher cannot run it", async () => {
  const p = page([{csrf: "csrf", subject: "admin"},
    singleDraft("pending_approval", {approval_dispatch: {...ready, ready: false}})],
  {search: `?mode=single&draft_id=${draftId}`});
  await p.context.startPage();
  assert.equal(p.nodes.get("approve").disabled, true);
  assert.equal(p.nodes.get("singleBlocked").hidden, false);
  assert.equal(p.nodes.get("singleBlocked").textContent, "自动执行服务未运行，暂不接受批准。");
  await p.nodes.get("approve").events.click();
  assert.equal(p.requests.some((item) => item.url === "/approvals"), false);
});

test("single review revokes a waiting human approval and polls the final state", async () => {
  const p = page([{csrf: "csrf", subject: "admin"},
    singleDraft("approved", {approval: {source: "human"}, revocable: true}),
    {results: [{draft_id: draftId, status: "revoked"}]},
    singleDraft("revoked", {approval: {source: "human"}})],
  {search: `?mode=single&draft_id=${draftId}`});
  await p.context.startPage();
  assert.equal(p.nodes.get("revokeSingle").hidden, false);
  assert.equal(p.nodes.get("approve").disabled, true);
  assert.equal(p.nodes.get("singleNote").textContent,
    "这项批准会一直等待服务器执行，不会过期；如不想执行可点击“撤销批准”。");
  await p.nodes.get("revokeSingle").events.click();
  assert.equal(p.confirms.at(-1), "撤销 1 项批准？撤销后服务器不再执行；已经开始执行的项无法撤销。");
  assert.deepEqual(JSON.parse(p.requests.find((item) => item.url === "/approvals/revoke").options.body),
    {items: [{draft_id: draftId, payload_hash: "single-hash"}]});
  assert.equal(p.nodes.get("revokeSingle").hidden, true);
  assert.equal(p.nodes.get("executionState").textContent, "批准已撤销，未执行");
  assert.equal(p.pollTimers().length, 0, "a revoked approval is final and needs no polling");

  const policy = page([{csrf: "csrf", subject: "admin"},
    singleDraft("client_expired", {approval: {source: "policy"}})],
  {search: `?mode=single&draft_id=${draftId}`});
  await policy.context.startPage();
  assert.equal(policy.nodes.get("revokeSingle").hidden, true);
  assert.match(policy.nodes.get("singleNote").textContent, /不可重复批准/);
});

test("the drawer shows the full archived mail and approves a pending draft in place", async () => {
  const trash = {draft_id: "first", kind: "trash", payload_hash: "first-hash", status: "pending_approval",
    expires_at: "2030-01-01T00:00:00Z", approval_dispatch: ready,
    review_packet: {account: "gmail", subject: "Lunch", stable_message_id: "a".repeat(24)}};
  const mail = {available: true, message: {subject: "Lunch", sender_name: "Alice",
    sender_email: "alice@example.test", recipients_to: "me@example.test", body_text: "Full body",
    body_fetched: true, hash_matches: true}};
  const approved = {...trash, status: "approved", phase: "running", queue_position: 1,
    approval: {source: "human"}};
  const p = page([{csrf: "csrf", subject: "admin"}, {drafts, has_more: false, approval_dispatch: ready},
    trash, {approval_id: "a-1", approval_source: "human"}, approved, {drafts: [drafts[1]], has_more: false}],
  {messages: [mail]});
  await p.context.startPage();
  await p.context.openDrawer("first");
  assert.deepEqual(p.messageRequests, ["/drafts/first/message"]);
  assert.equal(p.nodes.get("drawerMailBody").textContent, "Full body");
  assert.equal(p.nodes.get("drawerApprove").hidden, false);
  assert.equal(p.nodes.get("drawerApprove").textContent, "批准移入已删除邮件");
  await p.nodes.get("drawerApprove").events.click();
  const post = p.requests.find((item) => item.url === "/approvals");
  assert.deepEqual(JSON.parse(post.options.body), {draft_id: "first", payload_hash: "first-hash"});
  assert.match(p.lastToast().text, /已批准/);
  assert.equal(p.nodes.get("drawerApprove").hidden, true, "an approved draft has nothing left to approve");
});
