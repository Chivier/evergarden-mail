"use strict";

// Loads the shared i18n runtime and both catalogues into a node:vm context,
// the same three classic scripts every page loads before http.js.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SHARED = path.resolve(__dirname, "../../apps/shared_static");
const FILES = ["i18n.js", "locales/en.js", "locales/zh-CN.js"].map((name) => path.join(SHARED, name));

// Most page tests assert the original Simplified Chinese wording, so they run
// with zh-CN unless a test asks for another locale.
function loadI18n(context, locale = "zh-CN") {
  for (const file of FILES) vm.runInContext(fs.readFileSync(file, "utf8"), context, { filename: file });
  vm.runInContext(`EG.setLocale(${JSON.stringify(locale)}, { persist: false });`, context);
  return context.EG;
}

module.exports = { loadI18n, SHARED };
