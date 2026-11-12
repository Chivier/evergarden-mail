const { test } = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");
const fs = require("node:fs");

test("workbench catches all notification pages and announces only subsequent arrivals", async () => {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { textContent: "", hidden: true, listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; }, replaceChildren() {}, append() {}, showModal() {}, close() {} });
    return elements.get(id);
  };
  let ready, timer, fresh = false, notices = [], cursors = [];
  const context = vm.createContext({
    document: { getElementById: element, addEventListener: (_name, fn) => { ready = fn; }, createElement: () => element(`new-${Math.random()}`) },
    fetch: async url => {
      let body;
      if (url === "/api/session") body = { csrf: "csrf", bridge_accounts: ["work"] };
      else if (url === "/bridge/status") body = { accounts: [{ address: "user@work.test", paired: true, online: true, pending: 0, state: "connected" }] };
      else {
        const after = Number(url.split("=")[1]); cursors.push(after);
        const seqs = after === 0 ? Array.from({ length: 50 }, (_, i) => i + 1) : after === 50 ? [51] : fresh && after === 51 ? [52] : [];
        body = { items: seqs.map(seq => ({ seq, subject: `<script>${seq}`, sender: "Sender", message_id: String(seq) })), cursor: seqs.at(-1) || after, has_more: after === 0, unread_count: fresh ? 52 : 51 };
      }
      return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => body };
    },
    setInterval: fn => { timer = fn; }, setTimeout: () => {}, clearTimeout: () => {}, AbortController,
    showNotice: text => notices.push(text), messagePreloads: new Map(), loadMessages: async () => {}, openMessage: async () => {},
    window: { location: { pathname: "/", search: "", assign() { throw new Error("bridge must not redirect"); } } },
    Date, Map, String, URL, Blob,
  });
  loadI18n(context);
  vm.runInContext(fs.readFileSync("apps/shared_static/http.js", "utf8"), context);
  vm.runInContext(fs.readFileSync("apps/mail_ui/static/bridge.js", "utf8"), context);
  await ready();
  for (let i = 0; i < 8; i++) await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(cursors, [0, 50]);
  assert.equal(element("bridgeUnread").textContent, "51");
  assert.equal(notices.length, 0);
  fresh = true;
  await timer();
  assert.equal(notices.length, 1);
  await timer();
  assert.equal(notices.length, 1, "same notification is not repeated");
  assert.equal(element("bridgeUnread").textContent, "52");
});

function bridgePage(fetch) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { textContent: "", hidden: true, listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; }, replaceChildren() {}, append() {}, showModal() {}, close() {}, click() {}, remove() {} });
    return elements.get(id);
  };
  const redirects = [], notices = [];
  let ready;
  const context = vm.createContext({
    document: { getElementById: element, addEventListener: (_name, fn) => { ready = fn; }, createElement: () => element(`new-${Math.random()}`), body: { append() {} } },
    fetch, setInterval: () => {}, setTimeout: () => {}, clearTimeout: () => {}, AbortController,
    showNotice: (text, error) => notices.push({ text, error }), messagePreloads: new Map(), loadMessages: async () => {}, openMessage: async () => {},
    window: { location: { pathname: "/", search: "", assign(url) { redirects.push(url); } } },
    URL: { createObjectURL: () => "blob:test", revokeObjectURL() {} }, Blob, Date, Map, String,
  });
  loadI18n(context);
  vm.runInContext(fs.readFileSync("apps/shared_static/http.js", "utf8"), context);
  vm.runInContext(fs.readFileSync("apps/mail_ui/static/bridge.js", "utf8"), context);
  return { element, redirects, notices, start: () => ready() };
}

test("an expired session leaves the bridge hidden and the login redirect to the workbench", async () => {
  const page = bridgePage(async () => ({ ok: false, status: 401, headers: { get: () => "application/json" }, json: async () => ({ detail: "expired" }) }));
  await page.start();
  assert.equal(page.element("bridgeButton").hidden, true);
  assert.deepEqual(page.redirects, []);
});

test("pairing posts JSON with CSRF and reports HTML gateway failures readably", async () => {
  const requests = [];
  const page = bridgePage(async (url, options) => {
    requests.push({ url, options });
    if (url === "/api/session") return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => ({ csrf: "bridge-csrf", bridge_accounts: ["work"] }) };
    if (url === "/bridge/pair") return { ok: false, status: 502, headers: { get: () => "text/html" }, json: async () => { throw new SyntaxError("<"); } };
    return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => ({ accounts: [], items: [], cursor: 0, has_more: false, unread_count: 0 }) };
  });
  await page.start();
  assert.equal(page.element("bridgeButton").hidden, false);
  await page.element("bridgePair").listeners.click();
  const pair = requests.find(item => item.url === "/bridge/pair");
  assert.equal(pair.options.method, "POST");
  assert.equal(pair.options.headers["X-CSRF-Token"], "bridge-csrf");
  assert.deepEqual(JSON.parse(pair.options.body), { account: "work" });
  assert.deepEqual(page.notices.at(-1), { text: "服务暂时不可用（HTTP 502），请稍后刷新核对状态。已提交的操作请先核实结果。", error: true });
});
