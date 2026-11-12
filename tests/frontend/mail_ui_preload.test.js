"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

function loadApp(fetch) {
  const appPath = path.resolve(__dirname, "../../apps/mail_ui/static/app.js");
  const httpPath = path.resolve(__dirname, "../../apps/shared_static/http.js");
  const source = fs.readFileSync(appPath, "utf8");
  const elements = new Map();
  const context = {
    console,
    AbortController,
    document: {
      addEventListener() {},
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, { textContent: "" });
        return elements.get(id);
      },
    },
    fetch,
    Intl,
    setTimeout,
    clearTimeout,
    window: {
      clearTimeout,
      setTimeout,
      location: { pathname: "/", search: "", assign() {} },
    },
  };
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(fs.readFileSync(httpPath, "utf8"), context);
  vm.runInContext(`${source}\n;globalThis.__preloadTest = {
    clearMessagePreloads,
    loadCounts,
    element: byId,
    messagePreloadSize: () => messagePreloads.size,
    preloadView,
    state,
    viewTarget,
  };`, context);
  context.__preloadTest.state.csrf = "test-csrf-token";
  return context.__preloadTest;
}

function response(value) {
  return {
    ok: true,
    status: 200,
    headers: { get: () => "application/json" },
    async json() { return value; },
  };
}

test("late counts from an older refresh cannot replace newer mailbox counts", async () => {
  const pending = [];
  const api = loadApp(() => new Promise((resolve) => pending.push(resolve)));
  const older = api.loadCounts();
  const newer = api.loadCounts();
  pending[2](response({ count: 2, indexed_count: 2, actionable_count: 2 }));
  pending[3](response({ count: 3, indexed_count: 3, actionable_count: 1 }));
  await newer;
  pending[0](response({ count: 99 }));
  pending[1](response({ count: 99 }));
  await older;
  assert.equal(api.element("todayCount").textContent, "2");
  assert.equal(api.element("unreadCount").textContent, "1");
  assert.match(api.element("unreadCount").title, /本地索引 3/);
});

test("today preload coalesces in-flight work and reuses the short-lived result", async () => {
  const calls = [];
  let finish;
  const api = loadApp((url, options) => {
    calls.push({ url, options });
    return new Promise((resolve) => { finish = resolve; });
  });

  const first = api.preloadView("today");
  const second = api.preloadView("today");
  assert.strictEqual(first, second);
  assert.equal(calls.length, 1);

  finish(response([{ id: "a".repeat(24) }]));
  assert.deepEqual(await first, [{ id: "a".repeat(24) }]);
  assert.deepEqual(await second, [{ id: "a".repeat(24) }]);
  assert.deepEqual(await api.preloadView("today"), [{ id: "a".repeat(24) }]);
  assert.equal(calls.length, 1);

  const requestBody = JSON.parse(calls[0].options.body);
  assert.equal(requestBody.arguments.limit, 100);
  assert.equal(requestBody.arguments.account, null);
  assert.match(requestBody.arguments.since, /^\d{4}-\d{2}-\d{2}T/);
});

test("refresh and invalidation never reuse stale preloaded mail", async () => {
  let calls = 0;
  const api = loadApp(async () => {
    calls += 1;
    return response([{ id: String(calls).repeat(24) }]);
  });

  await api.preloadView("today");
  await api.preloadView("today", null, { refresh: true });
  assert.equal(calls, 2);

  api.clearMessagePreloads();
  await api.preloadView("today");
  assert.equal(calls, 3);
});

test("unread view requests unread messages from Inbox only", async () => {
  const calls = [];
  const api = loadApp(async (url, options) => {
    calls.push({ url, options });
    return response([]);
  });

  await api.preloadView("unread");
  const requestBody = JSON.parse(calls[0].options.body);
  assert.equal(requestBody.arguments.unread_only, true);
  assert.equal(requestBody.arguments.inbox_only, true);
});

test("preload cache remains bounded and navigation wires pointer and keyboard intent", async () => {
  const api = loadApp(async () => response([]));
  for (let index = 0; index < 20; index += 1) {
    await api.preloadView("all", `account-${index}`);
  }
  assert.equal(api.messagePreloadSize(), 12);

  const source = fs.readFileSync(
    path.resolve(__dirname, "../../apps/mail_ui/static/app.js"),
    "utf8",
  );
  assert.match(source, /addEventListener\("pointerenter", preload\)/);
  assert.match(source, /addEventListener\("focus", preload\)/);
  assert.match(
    source,
    /const initialMessages = loadMessages\(\);\s+const accounts = loadAccounts\(\);/,
  );
  assert.doesNotMatch(source, /(?:local|session)Storage/);
});
