"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

function loadApp() {
  const appPath = path.resolve(__dirname, "../../apps/mail_ui/static/app.js");
  const source = fs.readFileSync(appPath, "utf8");
  const context = {
    console,
    document: { addEventListener() {}, getElementById: () => ({ textContent: "" }) },
    Intl,
    setTimeout,
    clearTimeout,
    window: { clearTimeout, setTimeout },
  };
  vm.createContext(context);
  loadI18n(context);
  vm.runInContext(
    `${source}\n;globalThis.__app = { formatDate, mcpClientGuides, state, TOKEN_PLACEHOLDER: tokenPlaceholder() };`,
    context,
  );
  return context.__app;
}

function loadFormatter() {
  return loadApp().formatDate;
}

const NOW = new Date(2026, 7, 31, 14, 30);

test("list rows keep a date unless the message arrived today", () => {
  const formatDate = loadFormatter();

  const today = formatDate(new Date(2026, 7, 31, 9, 5), false, NOW);
  assert.match(today, /^今天 /, `expected a today marker, got ${today}`);
  assert.match(today, /09:05/);

  const earlierThisYear = formatDate(new Date(2026, 2, 4, 21, 42), false, NOW);
  assert.match(earlierThisYear, /03/);
  assert.match(earlierThisYear, /04/);
  assert.match(earlierThisYear, /21:42/);
  assert.doesNotMatch(earlierThisYear, /今天/);

  const lastYear = formatDate(new Date(2025, 10, 2, 8, 15), false, NOW);
  assert.match(lastYear, /2025/);
  assert.match(lastYear, /08:15/);

  // Yesterday must not collapse to a bare time just because the clock is close.
  const yesterday = formatDate(new Date(2026, 7, 30, 14, 30), false, NOW);
  assert.doesNotMatch(yesterday, /今天/);
  assert.match(yesterday, /30/);
});

test("detailed reader dates and unparseable values stay explicit", () => {
  const formatDate = loadFormatter();

  const detailed = formatDate(new Date(2026, 7, 31, 9, 5), true, NOW);
  assert.match(detailed, /2026/);
  assert.match(detailed, /9:05|09:05/);

  assert.equal(formatDate("not-a-date", false, NOW), "日期未知");
  assert.equal(formatDate("not-a-date", true, NOW), "日期未知");
});
