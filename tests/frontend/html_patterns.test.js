"use strict";

// Browsers compile an input's pattern attribute with the RegExp "v" flag and
// silently ignore a pattern that is invalid there (e.g. an unescaped "-" in a
// character class), so every pattern in the static pages must compile under "v".
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const STATIC_ROOT = path.resolve(__dirname, "../../apps");

function htmlFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return htmlFiles(full);
    return entry.name.endsWith(".html") ? [full] : [];
  });
}

function decode(value) {
  return value.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&amp;/g, "&");
}

test("every pattern attribute compiles with the v flag browsers use", () => {
  const patterns = [];
  for (const file of htmlFiles(STATIC_ROOT)) {
    for (const match of fs.readFileSync(file, "utf8").matchAll(/\spattern="([^"]*)"/g)) {
      patterns.push({ file: path.relative(STATIC_ROOT, file), pattern: decode(match[1]) });
    }
  }
  assert.ok(patterns.length >= 2, "expected the add-mailbox form patterns");
  for (const { file, pattern } of patterns) {
    assert.doesNotThrow(() => new RegExp(`^(?:${pattern})$`, "v"), `${file}: ${pattern}`);
  }
});

test("the add-mailbox patterns accept suggested values and reject bad ones", () => {
  const html = fs.readFileSync(path.join(STATIC_ROOT, "mail_ui/static/index.html"), "utf8");
  const pick = (name) => {
    const match = html.match(new RegExp(`name="${name}"[^>]*\\spattern="([^"]*)"`));
    assert.ok(match, name);
    return new RegExp(`^(?:${decode(match[1])})$`, "v");
  };
  const alias = pick("alias");
  assert.ok(alias.test("work-mail_2"));
  assert.ok(!alias.test("Work"));
  assert.ok(!alias.test("-work"));
  const record = pick("credential_record");
  assert.ok(record.test("microsoft:work-mail"));
  assert.ok(record.test("password:a_b"));
  assert.ok(!record.test("bad value!"));
  assert.ok(!record.test(":work"));
});
