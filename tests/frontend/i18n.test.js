"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n, SHARED } = require("./i18n_env");

const APPS = path.resolve(__dirname, "../../apps");
const CJK = /[　-〿㐀-鿿＀-￯]/;

function catalogue(locale) {
  const context = vm.createContext({});
  return loadI18n(context, locale);
}

function entries(locale) {
  // Read the registered dictionary straight from the catalogue file.
  const captured = {};
  const context = vm.createContext({ EG: { register(name, values) { captured[name] = values; } } });
  vm.runInContext(fs.readFileSync(path.join(SHARED, "locales", `${locale}.js`), "utf8"), context);
  return captured[locale];
}

const placeholders = (text) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();

function staticSources() {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "locales") walk(full);
      } else if (/\.(html|js)$/.test(entry.name) && /(?:^|\/)(static|shared_static)(?:\/|$)/.test(path.relative(APPS, dir))) {
        files.push(full);
      }
    }
  };
  walk(APPS);
  return files;
}

test("en and zh-CN catalogues have identical keys and matching placeholders", () => {
  const en = entries("en");
  const zh = entries("zh-CN");
  assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
  for (const key of Object.keys(en)) {
    assert.deepEqual(placeholders(zh[key]), placeholders(en[key]), key);
    assert.ok(en[key].length && zh[key].length, `${key} is empty`);
  }
  // English text stays English apart from the endonym on the switcher.
  for (const [key, value] of Object.entries(en)) {
    if (!key.startsWith("lang.zh")) assert.doesNotMatch(value, CJK, key);
  }
});

test("no CJK text remains in static HTML or JS outside the catalogues", () => {
  const files = staticSources();
  assert.ok(files.some((file) => file.endsWith("app.js")) && files.some((file) => file.endsWith("i18n.js")));
  for (const file of files) {
    const lines = fs.readFileSync(file, "utf8").split("\n");
    lines.forEach((line, index) => {
      assert.doesNotMatch(line, CJK, `${path.relative(APPS, file)}:${index + 1}`);
    });
  }
});

test("every catalogue key a page or script names exists", () => {
  const en = entries("en");
  const namespaces = "lang|common|units|time|http|server|reason|reasonShort|status|statusNote|phase|error|kind|source|envelope|mail|compose|review|move|mark|trash|prefs|codes|mcp|accounts|bridge|login|feedback|approvals|send|oauth";
  const pattern = new RegExp(`["'\`]((?:${namespaces})\\.[A-Za-z0-9_.]+)["'\`]`, "g");
  // Prefixes completed at run time (labelOr / EG.has with a template).
  const prefixes = new Set(["approvals.mail.unavailable"]);
  const missing = [];
  for (const file of staticSources()) {
    for (const [, key] of fs.readFileSync(file, "utf8").matchAll(pattern)) {
      if (!(key in en) && !prefixes.has(key)) missing.push(`${path.basename(file)}: ${key}`);
    }
  }
  assert.deepEqual(missing, []);
});

test("locale resolution prefers the saved choice, then the browser, then English", () => {
  const resolve = (storage, languages) => {
    const store = new Map(storage ? [["evergarden.locale", storage]] : []);
    const context = vm.createContext({
      localStorage: { getItem: (key) => store.get(key) ?? null, setItem: (key, value) => store.set(key, value) },
      navigator: { languages, language: languages[0] },
    });
    for (const file of ["i18n.js", "locales/en.js", "locales/zh-CN.js"]) {
      vm.runInContext(fs.readFileSync(path.join(SHARED, file), "utf8"), context);
    }
    return { EG: context.EG, store };
  };
  assert.equal(resolve(null, ["zh-TW", "en"]).EG.locale(), "zh-CN");
  assert.equal(resolve(null, ["fr-FR", "zh-Hans-CN"]).EG.locale(), "zh-CN");
  assert.equal(resolve(null, ["en-GB", "zh-CN"]).EG.locale(), "en");
  assert.equal(resolve(null, ["fr-FR", "de"]).EG.locale(), "en");
  assert.equal(resolve("en", ["zh-CN"]).EG.locale(), "en");
  const chosen = resolve("zh-CN", ["en-US"]);
  assert.equal(chosen.EG.locale(), "zh-CN");
  chosen.EG.setLocale("en");
  assert.equal(chosen.store.get("evergarden.locale"), "en");
});

test("t() fills placeholders, falls back to English and then to the key", () => {
  const EG = catalogue("zh-CN");
  assert.equal(EG.t("mail.list.count", { n: 3 }), "3 封");
  assert.equal(EG.t("mail.heading.search.title", { query: "{n}" }), "搜索“{n}”");
  EG.register("en", { "test.onlyEnglish": "Only {what}" });
  assert.equal(EG.t("test.onlyEnglish", { what: "English" }), "Only English");
  assert.equal(EG.t("test.missing"), "test.missing");
  EG.setLocale("en", { persist: false });
  assert.equal(EG.t("mail.list.count", { n: 3 }), "3 messages");
});

test("server reason codes and location reasons become readable text in both languages", () => {
  const EG = catalogue("zh-CN");
  assert.equal(EG.serverMessage("APPROVAL_DISPATCHER_UNAVAILABLE: the approval dispatcher is not running"),
    "自动执行服务未运行或未启用此类操作，暂不接受批准。请稍后刷新重试。");
  assert.equal(EG.serverMessage("Service down", "SERVICE_UNAVAILABLE"), "服务暂时不可用。请刷新核对状态");
  assert.equal(EG.serverMessage("PROVIDER_NOT_ATTEMPTED: timeout. No mailbox change was made"),
    "未能连接邮箱，邮箱没有任何变化；已有批准仍然保留。请稍后重试。（timeout. No mailbox change was made）");
  assert.equal(EG.serverMessage("UNMAPPED_CODE: kept as sent"), "UNMAPPED_CODE: kept as sent");
  assert.equal(EG.serverMessage("plain detail"), "plain detail");
  assert.equal(EG.reasonText("NO_ACTIVE_PROVIDER_LOCATION").startsWith("索引仍有此邮件"), true);
  assert.equal(EG.reasonText("SOMETHING_NEW"), "SOMETHING_NEW");
  EG.setLocale("en", { persist: false });
  assert.match(EG.serverMessage("x", "DATABASE_UNAVAILABLE"), /^The database is temporarily unavailable/);
  assert.match(EG.reasonText("UIDVALIDITY_CHANGED"), /UIDVALIDITY changed/);
});

// A small DOM: enough for applyI18n's attribute selectors and the switcher.
function fakeDocument() {
  const all = [];
  const listeners = {};
  function element(tag, attributes = {}, text = "") {
    const node = {
      tag, textContent: text, attributes: { ...attributes }, children: [], dataset: {}, events: {},
      get childElementCount() { return this.children.length; },
      setAttribute(name, value) { this.attributes[name] = String(value); },
      getAttribute(name) { return this.attributes[name] ?? null; },
      removeAttribute(name) { delete this.attributes[name]; },
      addEventListener(name, callback) { this.events[name] = callback; },
      append(...nodes) { for (const child of nodes) { this.children.push(child); all.push(child); } },
      querySelectorAll(selector) { return query(this.children, selector); },
    };
    return node;
  }
  function matches(node, selector) {
    const match = /^([a-z]*)\[([\w-]+)\]$/.exec(selector);
    if (!match) throw new Error(`unsupported selector ${selector}`);
    const [, tag, attribute] = match;
    if (tag && node.tag !== tag) return false;
    if (attribute.startsWith("data-") && attribute !== "data-lang-switch" && node.dataset) {
      const key = attribute.slice(5).replace(/-([a-z])/g, (_m, letter) => letter.toUpperCase());
      if (key in node.dataset) return true;
    }
    return attribute in node.attributes;
  }
  function query(nodes, selector) {
    const found = [];
    const visit = (node) => { if (matches(node, selector)) found.push(node); node.children.forEach(visit); };
    nodes.forEach(visit);
    return found;
  }
  const doc = {
    documentElement: { lang: "en" },
    title: element("title", { "data-i18n": "mail.pageTitle" }, "Mail · Evergarden"),
    heading: element("h1", { "data-i18n": "login.title" }, "Welcome back to Evergarden"),
    search: element("input", { "data-i18n-placeholder": "mail.search.placeholder", "data-i18n-aria-label": "mail.search.label" }),
    close: element("button", { "data-i18n-title": "common.close" }),
    live: element("p", { "data-i18n-once": "mail.identity.checking" }, "Checking your session…"),
    switcher: element("div", { "data-lang-switch": "" }),
    createElement: (tag) => element(tag),
    addEventListener(name, callback) { listeners[name] = callback; },
    querySelectorAll: (selector) => query(all, selector),
    listeners,
  };
  all.push(doc.title, doc.heading, doc.search, doc.close, doc.live, doc.switcher);
  return doc;
}

test("switching language updates text, attributes, the lang attribute and the switcher", () => {
  const document = fakeDocument();
  const context = vm.createContext({ document, navigator: { languages: ["en-US"] } });
  for (const file of ["i18n.js", "locales/en.js", "locales/zh-CN.js"]) {
    vm.runInContext(fs.readFileSync(path.join(SHARED, file), "utf8"), context);
  }
  const { EG } = context;
  document.listeners.DOMContentLoaded();
  assert.equal(document.documentElement.lang, "en");
  assert.equal(document.title.textContent, "Mail · Evergarden");
  assert.equal(document.search.getAttribute("placeholder"), "Search subject, sender or body");
  assert.equal(document.live.textContent, "Checking your session…");
  const buttons = document.switcher.children;
  assert.deepEqual(buttons.map((button) => button.textContent), ["EN", "中文"]);
  assert.deepEqual(buttons.map((button) => button.getAttribute("aria-pressed")), ["true", "false"]);

  // The page script now owns the live element; a switch must not reset it.
  document.live.textContent = "Administrator: admin";
  const seen = [];
  EG.onLocaleChange((locale) => seen.push(locale));
  buttons[1].events.click();
  assert.equal(EG.locale(), "zh-CN");
  assert.deepEqual(seen, ["zh-CN"]);
  assert.equal(document.documentElement.lang, "zh-CN");
  assert.equal(document.title.textContent, "邮件 · Evergarden");
  assert.equal(document.heading.textContent, "欢迎回到 Evergarden");
  assert.equal(document.search.getAttribute("placeholder"), "搜索主题、发件人或正文");
  assert.equal(document.search.getAttribute("aria-label"), "搜索邮件");
  assert.equal(document.close.getAttribute("title"), "关闭");
  assert.equal(document.live.textContent, "Administrator: admin");
  assert.deepEqual(buttons.map((button) => button.getAttribute("aria-pressed")), ["false", "true"]);
  assert.equal(document.switcher.children.length, 2, "the switcher is built once");

  buttons[0].events.click();
  assert.equal(document.documentElement.lang, "en");
  assert.equal(document.heading.textContent, "Welcome back to Evergarden");
  assert.deepEqual(seen, ["zh-CN", "en"]);
});

test("relative spans and byte sizes follow the active language", () => {
  const EG = catalogue("zh-CN");
  assert.equal(EG.formatSpan(30 * 1000), "不到 1 分钟");
  assert.equal(EG.formatSpan(-5 * 60000), "5 分钟");
  assert.equal(EG.formatSpan(3 * 3600000), "3 小时");
  assert.equal(EG.formatBytes(48213), "48 KiB");
  EG.setLocale("en", { persist: false });
  assert.equal(EG.formatSpan(3 * 86400000), "3 days");
  assert.equal(EG.formatBytes(512), "512 bytes");
  assert.equal(EG.formatBytes(5 * 1024 * 1024), "5 MiB");
});

test("pages render English when the browser asks for English", () => {
  // The mail list date marker and login errors switch with the locale.
  const context = vm.createContext({
    console, Intl, setTimeout, clearTimeout, window: { clearTimeout, setTimeout },
    document: { addEventListener() {}, getElementById: () => ({ textContent: "" }) },
  });
  loadI18n(context, "en");
  const source = fs.readFileSync(path.join(APPS, "mail_ui/static/app.js"), "utf8");
  vm.runInContext(`${source}\n;globalThis.__app = { formatDate };`, context);
  const now = new Date(2026, 7, 31, 14, 30);
  assert.match(context.__app.formatDate(new Date(2026, 7, 31, 9, 5), false, now), /^Today /);
  assert.equal(context.__app.formatDate("nope", false, now), "Unknown date");
});

test("session and approval wording matches the server behaviour in both languages", () => {
  const en = entries("en");
  const zh = entries("zh-CN");
  // Human approvals never expire; a not-attempted provider call keeps them.
  assert.doesNotMatch(en["server.PROVIDER_NOT_ATTEMPTED"], /expire/i);
  assert.doesNotMatch(zh["server.PROVIDER_NOT_ATTEMPTED"], /过期/);
  // Logout revokes server-side on every device; sessions default to 7 days.
  assert.match(en["login.footnote"], /7 days/);
  assert.match(en["login.footnote"], /all devices/);
  assert.match(zh["login.footnote"], /7 天/);
  assert.match(zh["login.footnote"], /所有设备/);
  assert.match(en["mail.logoutTitle"], /all devices/);
  assert.match(zh["mail.logoutTitle"], /所有设备/);
  const index = fs.readFileSync(path.join(APPS, "mail_ui/static/index.html"), "utf8");
  assert.match(index, /id="logoutButton"[^>]*data-i18n-title="mail\.logoutTitle"/);
  const login = fs.readFileSync(path.join(APPS, "mail_ui/static/login.html"), "utf8");
  assert.ok(login.includes(en["login.footnote"]), "login.html fallback text matches the catalogue");
});
