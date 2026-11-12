"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

const HTTP_JS = path.resolve(__dirname, "../../apps/shared_static/http.js");

function load(fetch) {
  const timers = new Map();
  const redirects = [];
  const calls = [];
  let nextTimer = 0;
  const context = {
    AbortController,
    setTimeout(callback, duration) { const id = ++nextTimer; timers.set(id, {callback, duration}); return id; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(url, options) { calls.push({url, options}); return fetch(url, options); },
    window: {location: {pathname: "/review", search: "?batch=trash", assign(url) { redirects.push(url); }}},
  };
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(fs.readFileSync(HTTP_JS, "utf8"), context);
  return {
    timers, redirects, calls,
    jsonRequest: vm.runInContext("jsonRequest", context),
    HttpError: vm.runInContext("HttpError", context),
  };
}

function response(value, {status = 200, type = "application/json", malformed = false} = {}) {
  const result = {
    status, ok: status >= 200 && status < 300, reads: 0,
    headers: {get: (name) => (name.toLowerCase() === "content-type" ? type : null)},
    async json() {
      result.reads += 1;
      if (malformed) throw new SyntaxError("Unexpected token '<', '<!DOCTYPE secret'");
      return value;
    },
  };
  return result;
}

function abortError() {
  const error = new Error("The operation was aborted.");
  error.name = "AbortError";
  return error;
}

// Resolves only when the request signal aborts, as a stalled network would.
function stalled(_url, options) {
  return new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => reject(abortError()));
  });
}

async function failure(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("request unexpectedly succeeded");
}

test("1: GET sends only Accept; writes add JSON body and CSRF when given", async () => {
  const h = load(async () => response({ok: true}));
  assert.deepEqual(await h.jsonRequest("/drafts"), {ok: true});
  const get = h.calls[0].options;
  assert.equal(get.method, "GET");
  assert.deepEqual({...get.headers}, {Accept: "application/json"});
  assert.equal(get.body, undefined);

  await h.jsonRequest("/approvals", {method: "POST", body: {draft_id: "d"}, csrf: "csrf-token"});
  const post = h.calls[1].options;
  assert.equal(post.method, "POST");
  assert.deepEqual({...post.headers}, {
    Accept: "application/json", "Content-Type": "application/json", "X-CSRF-Token": "csrf-token",
  });
  assert.equal(post.body, JSON.stringify({draft_id: "d"}));

  await h.jsonRequest("/oauth/start/work", {method: "POST", csrf: ""});
  const bare = h.calls[2].options;
  assert.deepEqual({...bare.headers}, {Accept: "application/json"});
  assert.equal(bare.body, undefined);
  assert.equal(h.timers.size, 0);
});

test("2: fetch is same-origin, refuses redirects and is bounded by the requested timeout", async () => {
  const h = load(stalled);
  const pending = h.jsonRequest("/drafts", {timeoutMs: 45000});
  const options = h.calls[0].options;
  assert.equal(options.credentials, "same-origin");
  assert.equal(options.redirect, "error");
  assert.equal(options.signal.aborted, false);
  assert.deepEqual([...h.timers.values()].map((timer) => timer.duration), [45000]);
  [...h.timers.values()][0].callback();
  assert.equal(options.signal.aborted, true);
  await failure(pending);
  assert.equal(h.timers.size, 0);
});

test("3: fetch rejections become HttpError with status 0 and method-specific guidance", async () => {
  for (const [method, expected] of [
    ["GET", "请求超时，请稍后刷新重试。"],
    ["POST", "请求超时，结果未知。请刷新核对状态，不要重复提交。"],
  ]) {
    const h = load(stalled);
    const pending = h.jsonRequest("/x", {method});
    [...h.timers.values()][0].callback();
    const error = await failure(pending);
    assert.ok(error instanceof h.HttpError);
    assert.equal(error.message, expected);
    assert.equal(error.status, 0);
    assert.equal(h.timers.size, 0);
  }
  for (const method of ["GET", "POST"]) {
    const h = load(async () => { throw new TypeError("Failed to fetch"); });
    const error = await failure(h.jsonRequest("/x", {method}));
    assert.ok(error instanceof h.HttpError);
    assert.equal(error.message, "网络连接中断。请刷新核对状态。");
    assert.equal(error.status, 0);
    assert.equal(h.timers.size, 0);
  }
});

test("4: 401 redirects to login without reading the body unless redirects are disabled", async () => {
  const html = response(null, {status: 401, type: "text/html", malformed: true});
  const h = load(async () => html);
  const error = await failure(h.jsonRequest("/drafts"));
  assert.equal(error.message, "登录已过期，请重新登录后继续");
  assert.equal(error.status, 401);
  assert.equal(html.reads, 0);
  assert.deepEqual(h.redirects, [`/login?next=${encodeURIComponent("/review?batch=trash")}`]);
  assert.equal(h.timers.size, 0);

  const login = load(async () => response({detail: "invalid administrator credentials"}, {status: 401}));
  const rejected = await failure(login.jsonRequest("/api/login", {method: "POST", body: {}, loginRedirect: false}));
  assert.equal(rejected.status, 401);
  assert.equal(rejected.message, "invalid administrator credentials");
  assert.deepEqual(login.redirects, []);
});

test("5: non-JSON responses map to unavailable or malformed messages, writes add a verification note", async () => {
  for (const status of [502, 503, 504]) {
    const page = response(null, {status, type: "text/html"});
    const h = load(async () => page);
    const read = await failure(h.jsonRequest("/drafts"));
    assert.equal(read.message, `服务暂时不可用（HTTP ${status}），请稍后刷新核对状态。`);
    assert.equal(read.status, status);
    const write = await failure(h.jsonRequest("/approvals", {method: "POST", body: {}}));
    assert.equal(write.message, `服务暂时不可用（HTTP ${status}），请稍后刷新核对状态。已提交的操作请先核实结果。`);
    assert.equal(page.reads, 0);
    assert.equal(h.timers.size, 0);
  }
  for (const [status, type] of [[200, "text/html"], [500, "text/plain; charset=utf-8"], [200, ""], [413, "text/html"]]) {
    const h = load(async () => response({ok: true}, {status, type}));
    const read = await failure(h.jsonRequest("/drafts"));
    assert.equal(read.message, `服务响应格式异常（HTTP ${status}），请刷新核对状态。`);
    assert.equal(read.status, status);
    const write = await failure(h.jsonRequest("/approvals", {method: "POST"}));
    assert.equal(write.message, `服务响应格式异常（HTTP ${status}），请刷新核对状态。已提交的操作请先核实结果。`);
  }
});

test("6: body read failures distinguish a timeout from malformed JSON", async () => {
  const malformed = load(async () => response(null, {malformed: true}));
  assert.equal((await failure(malformed.jsonRequest("/x"))).message, "服务响应格式异常（HTTP 200），请刷新核对状态。");
  assert.equal(malformed.timers.size, 0);
  for (const [method, expected] of [
    ["GET", "请求超时，请稍后刷新重试。"],
    ["POST", "请求超时，结果未知。请刷新核对状态，不要重复提交。"],
  ]) {
    const h = load(async (_url, options) => ({
      ...response(null),
      json: () => new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(abortError()));
      }),
    }));
    const pending = h.jsonRequest("/x", {method});
    for (let i = 0; i < 5; i++) await Promise.resolve();
    assert.equal(h.timers.size, 1, "the timeout still covers the body read");
    [...h.timers.values()][0].callback();
    const error = await failure(pending);
    assert.equal(error.message, expected);
    assert.equal(error.status, 0);
    assert.equal(h.timers.size, 0);
  }
});

test("7: null and non-object JSON values are malformed; arrays and +json types are accepted", async () => {
  for (const value of [null, "text", 42, true]) {
    const h = load(async () => response(value));
    assert.equal((await failure(h.jsonRequest("/x"))).message, "服务响应格式异常（HTTP 200），请刷新核对状态。");
  }
  assert.deepEqual(await load(async () => response([1, 2])).jsonRequest("/api/mcp/list_accounts"), [1, 2]);
  const problem = load(async () => response({ok: 1}, {type: "application/problem+json; charset=utf-8"}));
  assert.deepEqual(await problem.jsonRequest("/x"), {ok: 1});
});

test("8: non-OK JSON keeps detail, reason code and request id; CSRF rejection asks for a reload", async () => {
  const h = load(async () => response(
    {detail: "APPROVAL_QUEUE_FULL: 已满", reason_code: "QUEUE_FULL", request_id: "rid-1"}, {status: 409}));
  const error = await failure(h.jsonRequest("/approvals", {method: "POST", body: {}}));
  assert.ok(error instanceof h.HttpError);
  assert.equal(error.name, "HttpError");
  assert.equal(error.message, "APPROVAL_QUEUE_FULL: 已满");
  assert.equal(error.status, 409);
  assert.equal(error.reasonCode, "QUEUE_FULL");
  assert.equal(error.requestId, "rid-1");

  const bare = await failure(load(async () => response({}, {status: 500})).jsonRequest("/x"));
  assert.equal(bare.message, "请求未完成（HTTP 500）");
  assert.equal(bare.reasonCode, null);
  const validation = await failure(load(async () => response({detail: [{msg: "field required"}]}, {status: 422}))
    .jsonRequest("/x", {method: "POST", body: {}}));
  assert.equal(validation.message, "请求未完成（HTTP 422）");

  const csrf = await failure(load(async () => response({detail: "valid CSRF token is required"}, {status: 403}))
    .jsonRequest("/approvals", {method: "POST", body: {}}));
  assert.equal(csrf.message, "页面会话已更新，请刷新页面后重试。");
  assert.equal(csrf.status, 403);
  const forbidden = await failure(load(async () => response({detail: "approval UI is fenced off"}, {status: 403}))
    .jsonRequest("/x"));
  assert.equal(forbidden.message, "approval UI is fenced off");
});

test("9: success returns the parsed value and clears the timer", async () => {
  const h = load(async () => response({drafts: [], has_more: false}, {type: "application/json; charset=utf-8"}));
  assert.deepEqual(await h.jsonRequest("/drafts", {timeoutMs: 1000}), {drafts: [], has_more: false});
  assert.equal(h.timers.size, 0);
});

test("10: Cloudflare edge JSON errors are replaced; origin 503 detail survives", async () => {
  const edge = await failure(load(async () => response({
    title: "Error 502: Bad gateway", status: 502, ray_id: "a4e2b7b7689614fb",
    detail: "The origin web server returned an invalid or incomplete response to Cloudflare.",
  }, {status: 502})).jsonRequest("/api/mcp/list_recent", {method: "POST", body: {}}));
  assert.equal(edge.message, "服务暂时不可用（HTTP 502，边缘网关 Ray a4e2b7b7689614fb），请稍后刷新核对状态。已提交的操作请先核实结果。");
  assert.equal(edge.status, 502);

  const origin = await failure(load(async () => response({detail: "MCP did not respond in time"}, {status: 503}))
    .jsonRequest("/api/mcp/list_recent", {method: "POST", body: {}}));
  assert.equal(origin.message, "MCP did not respond in time");
});
