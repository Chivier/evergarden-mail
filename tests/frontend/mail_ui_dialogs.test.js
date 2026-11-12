"use strict";

// Move, mark and trash use in-page dialogs with fixed choices instead of
// window.prompt / window.confirm.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

function loadApp({ confirmAnswer = true } = {}) {
  const elements = new Map();
  const requests = [];
  const confirms = [];
  const element = (tag = "div") => ({
    tag, textContent: "", value: "", hidden: false, disabled: false, open: false, children: [],
    dataset: {}, className: "", files: [], href: "", attributes: {},
    classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } },
    setAttribute(name, value) { this.attributes[name] = value; this[name] = value; },
    addEventListener() {}, focus() {},
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    querySelectorAll() { return []; },
    querySelector() { return null; },
    showModal() { this.open = true; }, close() { this.open = false; },
  });
  const context = {
    console, Intl, AbortController, setTimeout, clearTimeout,
    document: {
      addEventListener() {}, createElement: element, querySelectorAll: () => [],
      getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    },
    window: { setTimeout, clearTimeout, location: { pathname: "/", search: "", assign() {} } },
    async fetch(url, options) {
      requests.push({ tool: url.replace("/api/mcp/", ""), body: JSON.parse(options.body || "null") });
      return { ok: true, status: 200, headers: { get: () => "application/json" },
        async json() { return { draft_id: "d-1", kind: "move", execution_owner: "server", review_packet: {} }; } };
    },
  };
  vm.createContext(context);
  loadI18n(context, "en");
  context.EG.confirm = async (options) => { confirms.push(options); return confirmAnswer; };
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../../apps/shared_static/http.js"), "utf8"), context);
  vm.runInContext(`${fs.readFileSync(path.resolve(__dirname, "../../apps/mail_ui/static/app.js"), "utf8")}
;globalThis.__app = { state, openMove, submitMove, confirmTrash };`, context);
  const app = context.__app;
  app.state.csrf = "c".repeat(32);
  app.state.accounts = [{ alias: "work", email: "me@example.test", archive_folder: "Archive", safe_move_folders: ["Projects", "Archive"] }];
  app.state.current = { id: "m-1", account: "work", folder: "INBOX", flags: [] };
  return { app, requests, confirms, byId: (id) => context.document.getElementById(id) };
}

test("move offers only the mailbox's allowlisted folders and prepares the chosen one", async () => {
  const page = loadApp();
  page.app.openMove();
  const select = page.byId("moveDestination");
  assert.deepEqual(select.children.map((option) => option.value), ["Projects", "Archive"]);
  assert.equal(select.value, "Archive", "the archive folder is preselected when allowed");
  assert.equal(page.byId("moveDialog").open, true);
  assert.equal(page.byId("moveSubmit").disabled, false);
  select.value = "Projects";
  page.app.submitMove({ preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(page.byId("moveDialog").open, false);
  assert.equal(page.requests[0].tool, "preview_move");
  assert.equal(page.requests[0].body.arguments.destination, "Projects");
  assert.equal(page.requests[0].body.arguments.stable_message_id, "m-1");
});

test("a mailbox without move destinations cannot submit a move", () => {
  const page = loadApp();
  page.app.state.accounts[0].safe_move_folders = [];
  page.app.openMove();
  assert.equal(page.byId("moveSubmit").disabled, true);
  assert.equal(page.byId("moveEmpty").hidden, false);
});

test("trash asks through the styled confirm dialog and does nothing when declined", async () => {
  const declined = loadApp({ confirmAnswer: false });
  await declined.app.confirmTrash();
  assert.equal(declined.requests.length, 0);
  assert.equal(declined.confirms[0].danger, true);
  assert.match(declined.confirms[0].message, /nothing is deleted permanently/);

  const accepted = loadApp();
  await accepted.app.confirmTrash();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(accepted.requests[0].tool, "preview_trash");
});

test("no page script uses native prompt or confirm dialogs", () => {
  for (const file of ["mail_ui/static/app.js", "mail_ui/static/bridge.js", "approval_ui/static/review.js", "approval_ui/static/send.js"]) {
    const source = fs.readFileSync(path.resolve(__dirname, "../../apps", file), "utf8");
    assert.doesNotMatch(source, /window\.(prompt|confirm|alert)\(/, file);
  }
  const html = fs.readFileSync(path.resolve(__dirname, "../../apps/mail_ui/static/index.html"), "utf8");
  for (const action of ["seen", "unseen", "flag", "unflag"]) assert.match(html, new RegExp(`data-mark="${action}"`));
});
