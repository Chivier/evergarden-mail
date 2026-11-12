"use strict";

// Script-owned text survives a language switch, and EG.confirm settles each
// request exactly once even when a second request replaces an open one.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n, SHARED } = require("./i18n_env");

function fakeElement(tag = "div") {
  const listeners = {};
  return {
    tag, textContent: "", children: [], attributes: {}, open: false, returnValue: "", className: "",
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; },
    removeAttribute(name) { delete this.attributes[name]; },
    append(...children) { this.children.push(...children); },
    addEventListener(name, callback) { (listeners[name] ||= []).push(callback); },
    fire(name) { for (const callback of listeners[name] || []) callback(); },
    focus() {},
    querySelector(selector) {
      const all = [];
      const walk = (node) => { for (const child of node.children) { all.push(child); walk(child); } };
      walk(this);
      if (selector.startsWith("#")) return all.find((node) => node.id === selector.slice(1)) || null;
      return all.find((node) => String(node.className).split(" ").includes(selector.slice(1))) || null;
    },
    // Like the browser: close() is synchronous, the close event is queued.
    showModal() { this.open = true; },
    close(value) {
      if (!this.open) return;
      this.open = false;
      if (value !== undefined) this.returnValue = value;
      setImmediate(() => this.fire("close"));
    },
  };
}

function documentWith(elements) {
  return {
    body: fakeElement("body"),
    documentElement: {},
    createElement: fakeElement,
    querySelectorAll(selector) {
      const match = /^\[([\w-]+)\]$/.exec(selector);
      if (!match) return [];
      return elements.filter((element) => element.getAttribute(match[1]) !== null);
    },
  };
}

test("EG.setText re-translates script-owned text on a language switch", () => {
  const sync = fakeElement();
  const error = fakeElement();
  const context = vm.createContext({});
  loadI18n(context, "zh-CN");
  context.document = documentWith([sync, error]);
  context.EG.setText(sync, "mail.sync.done", { n: 3 });
  const chinese = sync.textContent;
  context.EG.setText(error, null, null, "literal server text");
  context.EG.setLocale("en", { persist: false });
  assert.notEqual(sync.textContent, chinese);
  assert.equal(sync.textContent, context.EG.t("mail.sync.done", { n: 3 }));
  assert.equal(error.textContent, "literal server text", "literal text is left alone");
  assert.equal(error.getAttribute("data-i18n-live"), null);
});

test("a replaced confirm request resolves false and the new one waits for its own answer", async () => {
  const context = vm.createContext({ setImmediate });
  loadI18n(context, "en");
  context.document = documentWith([]);
  vm.runInContext(fs.readFileSync(path.join(SHARED, "ui.js"), "utf8"), context);
  const first = context.EG.confirm({ message: "first" });
  const second = context.EG.confirm({ message: "second" });
  assert.equal(await first, false);
  await new Promise((resolve) => setImmediate(resolve));
  const dialog = context.document.body.children[0];
  assert.equal(dialog.open, true, "the second prompt is still showing");
  let settled = false;
  second.then(() => { settled = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false, "the stale close event did not answer the second prompt");
  dialog.close("confirm");
  assert.equal(await second, true);
});
