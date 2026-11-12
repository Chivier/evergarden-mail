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
    `${source}\n;globalThis.__app = { mcpClientGuides, state, TOKEN_PLACEHOLDER: tokenPlaceholder() };`,
    context,
  );
  context.__app.state.mcp = {
    resource: "https://mail.test/mcp",
    discoveryUrl: "https://mail.test/.well-known/oauth-protected-resource/mcp",
    issuer: "https://auth.test",
    scopes: ["mail:metadata", "mail:read"],
  };
  return context.__app;
}

function allSnippets(app) {
  return app.mcpClientGuides().flatMap((guide) => guide.steps.map((step) => step.code)).join("\n");
}

test("snippets carry a placeholder until a key is issued in this session", () => {
  const app = loadApp();
  const snippets = allSnippets(app);

  assert.ok(snippets.includes(app.TOKEN_PLACEHOLDER));
  // Every client tab points at the deployment's own resource, not the sample.
  assert.ok(!snippets.includes("example.test"));
  assert.ok(snippets.includes("https://mail.test/mcp"));
});

test("a freshly issued key replaces the placeholder everywhere it appears", () => {
  const app = loadApp();
  app.state.mcpToken = "issued-token-value-not-a-real-secret";
  const snippets = allSnippets(app);

  assert.ok(!snippets.includes(app.TOKEN_PLACEHOLDER));
  // Claude Code writes it to a file, Codex to an env file, JSON to a header.
  assert.ok(snippets.includes("printf '%s' 'issued-token-value-not-a-real-secret'"));
  assert.ok(snippets.includes("EVERGARDEN_MCP_TOKEN=%s"));
  assert.ok(snippets.includes('"Authorization": "Bearer issued-token-value-not-a-real-secret"'));

  // Clearing it on dialog close puts the placeholder back.
  app.state.mcpToken = "";
  assert.ok(allSnippets(app).includes(app.TOKEN_PLACEHOLDER));
});

test("the OAuth tab appears only when the server can verify OAuth tokens", () => {
  const app = loadApp();
  // API-key-only install: no JWKS or introspection, so no OAuth option.
  assert.deepEqual([...app.mcpClientGuides().map((guide) => guide.id)], ["claude-code", "codex", "json"]);
  assert.ok(!allSnippets(app).includes('auth = "oauth"'));

  app.state.mcp.oauthEnabled = true;
  const ids = [...app.mcpClientGuides().map((guide) => guide.id)];
  assert.deepEqual(ids, ["claude-code", "codex", "json", "oauth"]);
  assert.ok(allSnippets(app).includes('auth = "oauth"'));
});
