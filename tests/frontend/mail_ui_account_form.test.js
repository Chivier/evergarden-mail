"use strict";

// The add-mailbox form suggests a credential record from alias, authentication
// and IMAP host, following the documented "<kind>:<alias>" convention.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadI18n } = require("./i18n_env");

function loadApp() {
  const context = {
    console, Intl, setTimeout, clearTimeout,
    document: { addEventListener() {}, getElementById: () => ({ textContent: "" }) },
    window: { setTimeout, clearTimeout },
  };
  vm.createContext(context);
  loadI18n(context, "en");
  vm.runInContext(`${fs.readFileSync(path.resolve(__dirname, "../../apps/mail_ui/static/app.js"), "utf8")}
;globalThis.__app = { suggestedCredentialRecord, refreshCredentialSuggestion, bindCredentialSuggestion };`, context);
  return context.__app;
}

function fakeForm() {
  const listeners = {};
  const input = (value = "") => {
    const own = {};
    return {
      value, placeholder: "", dataset: {}, own,
      addEventListener(type, handler) { (own[type] ||= []).push(handler); },
      fire(type) { for (const handler of own[type] || []) handler(); },
    };
  };
  return {
    elements: {
      alias: input(), auth_kind: input("oauth2"), imap_host: input(), credential_record: input(),
    },
    listeners,
    addEventListener(type, handler) { (listeners[type] ||= []).push(handler); },
  };
}

test("the suggestion follows the backend's provider choice", () => {
  const { suggestedCredentialRecord: suggest } = loadApp();
  assert.equal(suggest("personal", "password", "imap.example.com"), "password:personal");
  assert.equal(suggest("work", "oauth2", "outlook.office365.com"), "microsoft:work");
  assert.equal(suggest("gmail", "oauth2", " IMAP.Gmail.com "), "google:gmail");
  assert.equal(suggest("gmail", "password", "imap.gmail.com"), "password:gmail");
  assert.equal(suggest(" Work Box ", "password", ""), "password:work-box");
  assert.equal(suggest("", "password", "imap.example.com"), "");
  for (const value of ["password:personal", "microsoft:work", "password:work-box"]) {
    assert.match(value, /^[a-z0-9][a-z0-9:_-]{0,199}$/i, "accepted by the account config");
  }
});

test("the field is pre-filled, stays editable and returns to the suggestion when cleared", async () => {
  const app = loadApp();
  const form = fakeForm();
  const { alias, auth_kind: auth, imap_host: host, credential_record: record } = form.elements;
  app.bindCredentialSuggestion(form);
  assert.equal(record.value, "");
  assert.equal(record.placeholder, "microsoft:<alias>");

  alias.value = "personal";
  alias.fire("input");
  assert.equal(record.value, "microsoft:personal");
  auth.value = "password";
  auth.fire("change");
  assert.equal(record.value, "password:personal");
  assert.equal(record.placeholder, "password:<alias>");

  record.value = "password:legacy-record";
  record.fire("input");
  alias.value = "home";
  alias.fire("input");
  assert.equal(record.value, "password:legacy-record", "a typed value is never overwritten");

  record.value = "";
  record.fire("input");
  host.value = "imap.gmail.com";
  auth.value = "oauth2";
  host.fire("input");
  assert.equal(record.value, "google:home");

  record.value = "password:keep";
  record.fire("input");
  for (const handler of form.listeners.reset) handler();
  await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(record.dataset.custom, "", "a reset form suggests again");
  assert.equal(record.value, "google:home");
});
