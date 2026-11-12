"use strict";

// Renders the Evergarden web UIs against the fictional-data preview server
// (mock.py) and saves screenshots.
//
//   node tools/ui-preview/shots.js matrix /tmp/evergarden-shots   # en+zh, light+dark, 1440+390
//   node tools/ui-preview/shots.js readme docs/assets/screenshots  # the README set
//
// Needs playwright-core and a Chromium build. Set PLAYWRIGHT_CORE to the
// package directory and CHROMIUM_EXECUTABLE to the browser binary when they
// are not resolvable from this checkout. The mock servers bind to 127.0.0.1
// on high ports (PREVIEW_PORT, default 48711, and the next port).
const { execFileSync, spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const { chromium } = require(process.env.PLAYWRIGHT_CORE || "playwright-core");

const ROOT = path.resolve(__dirname, "../..");
const BASE_PORT = Number(process.env.PREVIEW_PORT || 48711);
const MAIL = `http://127.0.0.1:${BASE_PORT}`;
const APPROVAL = `http://127.0.0.1:${BASE_PORT + 1}`;
const SEND_DRAFT = "00000000-0000-4000-8000-000000000077";
const SINGLE_DRAFT = "00000000-0000-4000-8000-000000000003";

function startMocks() {
  const python = process.env.PYTHON || "python3";
  const script = path.join(__dirname, "mock.py");
  const mail = spawn(python, ["-I", script, "mail", String(BASE_PORT), "--approval-url", APPROVAL], { stdio: "inherit" });
  const approval = spawn(python, ["-I", script, "approval", String(BASE_PORT + 1)], { stdio: "inherit" });
  return () => { mail.kill(); approval.kill(); };
}

async function waitFor(url) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch (_error) {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`preview server did not start: ${url}`);
}

const openMessage = async (page) => {
  await page.click(".message-card");
  await page.waitForSelector("#readerContent:not([hidden])");
};

const SCENES = {
  login: { url: `${MAIL}/login` },
  workbench: { url: `${MAIL}/` },
  reader: { url: `${MAIL}/`, act: openMessage },
  compose: { url: `${MAIL}/`, act: (page) => page.click("#composeButton:visible, #composeFab:visible") },
  "mcp-setup": { url: `${MAIL}/`, act: (page) => page.click("#mcpGuideButton"), desktopOnly: true },
  move: { url: `${MAIL}/`, act: async (page) => { await openMessage(page); await page.click("#moveButton"); } },
  "mobile-menu": { url: `${MAIL}/`, act: (page) => page.click("#menuButton"), mobileOnly: true },
  feedback: { url: `${MAIL}/feedback`, full: true },
  "approval-queue": { url: `${APPROVAL}/review` },
  "detail-drawer": { url: `${APPROVAL}/review`, act: (page) => page.click("#batchItems .link-button") },
  "execution-log": { url: `${APPROVAL}/review#execution` },
  "single-review": { url: `${APPROVAL}/review?mode=single&draft_id=${SINGLE_DRAFT}` },
  "send-approval": { url: `${APPROVAL}/review/send?draft_id=${SEND_DRAFT}`, full: true },
  oauth: { url: `${APPROVAL}/oauth`, act: (page) => page.click("#start") },
  "revoke-confirm": { url: `${APPROVAL}/review#execution`, act: (page) => page.click("#executionItems .secondary.small") },
};

const README = [
  ["workbench", "workbench", { width: 1440, height: 900 }],
  ["reader", "reader", { width: 1440, height: 900 }],
  ["workbench-dark", "reader", { width: 1440, height: 900, dark: true }],
  ["approval-queue", "approval-queue", { width: 1440, height: 900 }],
  ["detail-drawer", "detail-drawer", { width: 1440, height: 900 }],
  ["send-approval", "send-approval", { width: 1440, height: 900 }],
  ["mcp-setup", "mcp-setup", { width: 1440, height: 1000 }],
  ["login", "login", { width: 1440, height: 900 }],
  ["mobile-mail", "reader", { width: 390, height: 844 }],
  ["mobile-approvals", "approval-queue", { width: 390, height: 844 }],
];

// Without a CJK font the switcher's "中文" label renders as empty boxes; the
// README set then leaves the switcher out rather than publish tofu.
function hasCjkFont() {
  try {
    return execFileSync("fc-list", [":lang=zh"], { encoding: "utf8" }).trim().length > 0;
  } catch (_error) {
    return false;
  }
}

async function shoot(browser, scene, file, { width, height, dark = false, locale = "en", hideSwitcher = false }, problems) {
  const context = await browser.newContext({
    viewport: { width, height }, deviceScaleFactor: width < 600 ? 2 : 1,
    colorScheme: dark ? "dark" : "light", locale: locale === "en" ? "en-US" : "zh-CN",
  });
  const page = await context.newPage();
  const name = path.basename(file);
  page.on("console", (message) => { if (message.type() === "error") problems.push(`${name}: console ${message.text()}`); });
  page.on("pageerror", (error) => problems.push(`${name}: ${error.message}`));
  try {
    await page.goto(scene.url, { waitUntil: "networkidle" });
    if (scene.act) await scene.act(page).catch((error) => problems.push(`${name}: ${error.message.split("\n")[0]}`));
    await page.waitForTimeout(350);
    // The pages' CSP forbids injected style; the hidden attribute is enough.
    if (hideSwitcher) await page.evaluate(() => { for (const node of document.querySelectorAll("[data-lang-switch]")) node.hidden = true; });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    if (overflow > 0) problems.push(`${name}: horizontal overflow of ${overflow}px`);
    const lang = await page.evaluate(() => document.documentElement.lang);
    if (lang !== locale) problems.push(`${name}: html lang is ${lang}, expected ${locale}`);
    await page.screenshot({ path: file, fullPage: Boolean(scene.full) });
  } finally {
    await context.close();
  }
}

async function main() {
  const [set = "matrix", output = "/tmp/evergarden-shots"] = process.argv.slice(2);
  fs.mkdirSync(output, { recursive: true });
  const stop = startMocks();
  const problems = [];
  let browser;
  try {
    await waitFor(`${MAIL}/login`);
    await waitFor(`${APPROVAL}/review`);
    browser = await chromium.launch(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {});
    if (set === "readme") {
      const hideSwitcher = !hasCjkFont();
      if (hideSwitcher) console.log("no CJK font found: hiding the language switcher in the README set");
      for (const [file, scene, options] of README) {
        await shoot(browser, SCENES[scene], path.join(output, `${file}.png`), { ...options, hideSwitcher }, problems);
      }
    } else {
      for (const locale of ["en", "zh-CN"]) {
        for (const dark of [false, true]) {
          for (const width of [1440, 390]) {
            for (const [name, scene] of Object.entries(SCENES)) {
              if ((scene.desktopOnly && width < 600) || (scene.mobileOnly && width >= 600)) continue;
              const file = path.join(output, `${locale}-${dark ? "dark" : "light"}-${width}-${name}.png`);
              await shoot(browser, scene, file, { width, height: width < 600 ? 844 : 900, dark, locale }, problems);
            }
          }
        }
      }
    }
  } finally {
    await browser?.close();
    stop();
  }
  console.log(problems.length ? problems.join("\n") : "no console errors, overflow or lang problems");
  process.exitCode = problems.length ? 1 : 0;
}

main().catch((error) => { console.error(error); process.exitCode = 2; });
