"use strict";

const byId = (id) => document.getElementById(id);
let csrf = "";
let deviceFlow = null;
let pollTimer = null;
let providers = {};
let configured = {};
let appNames = {};

function updateProvider() {
  const account = byId("account").value;
  const label = providers[account] === "google" ? "Google" : "Microsoft";
  EG.setText(byId("start"), "oauth.start", { provider: label });
  byId("start").disabled = !account || configured[account] === false;
  if (configured[account] === false) {
    EG.setText(
      byId("result"),
      providers[account] === "google" ? "oauth.googleNotConfigured" : "oauth.microsoftNotConfigured",
    );
    byId("result").className = "result";
  } else {
    EG.setText(byId("result"), null);
  }
}

async function start() {
  try {
    const session = await jsonRequest("/session?surface=oauth");
    csrf = session.csrf;
    EG.setText(byId("identity"), "mail.identity.admin", { subject: session.subject });
    const value = await jsonRequest("/oauth/accounts");
    providers = value.providers || {};
    configured = value.configured || {};
    appNames = value.app_names || {};
    const select = byId("account");
    select.replaceChildren(...value.accounts.map((account) => {
      const option = document.createElement("option");
      option.value = account;
      option.textContent = `${account} · ${providers[account] === "google" ? "Google" : "Microsoft"}`;
      return option;
    }));
    const requested = new URLSearchParams(window.location.search).get("account");
    if (requested && value.accounts.includes(requested)) select.value = requested;
    updateProvider();
    const status = new URLSearchParams(window.location.search).get("status");
    if (status === "authorized") {
      EG.setText(byId("result"), "oauth.authorized");
      byId("result").className = "result success";
    }
  } catch (error) {
    EG.setText(byId("result"), null, null, error.message);
    byId("result").className = "result error";
  }
}

function scheduleDevicePoll(seconds) {
  window.clearTimeout(pollTimer);
  pollTimer = window.setTimeout(pollDevice, seconds * 1000);
}

async function pollDevice() {
  const flow = deviceFlow;
  if (!flow) return;
  if (Date.now() >= Date.parse(flow.expires_at)) {
    deviceFlow = null;
    byId("device").hidden = true;
    EG.setText(byId("result"), "oauth.codeExpired");
    byId("result").className = "result error";
    return;
  }
  try {
    const value = await jsonRequest("/oauth/device/poll", {
      method: "POST",
      body: { flow_id: flow.flow_id },
      csrf,
    });
    if (deviceFlow !== flow) return;
    if (value.status === "authorized") {
      deviceFlow = null;
      byId("device").hidden = true;
      EG.setText(byId("result"), "oauth.success");
      byId("result").className = "result success";
      return;
    }
    if (["authorization_declined", "expired_token"].includes(value.status)) {
      deviceFlow = null;
      byId("device").hidden = true;
      throw new Error(t("oauth.declined"));
    }
    EG.setText(byId("result"), "oauth.waiting");
    byId("result").className = "result";
    scheduleDevicePoll(value.interval || flow.interval || 5);
  } catch (error) {
    if (deviceFlow && deviceFlow !== flow) return;
    EG.setText(byId("result"), null, null, error.message);
    byId("result").className = "result error";
    if (error.status >= 400 && error.status < 500) deviceFlow = null;
    if (deviceFlow) scheduleDevicePoll(Math.max(flow.interval || 5, 15));
  }
}

byId("start").addEventListener("click", async () => {
  window.clearTimeout(pollTimer);
  deviceFlow = null;
  byId("device").hidden = true;
  byId("start").disabled = true;
  const account = byId("account").value;
  const provider = providers[account] || "microsoft";
  try {
    const value = await jsonRequest(`/oauth/start/${encodeURIComponent(account)}`, {
      method: "POST",
      csrf,
    });
    if (value.flow === "device_code") {
      if (provider !== "microsoft") throw new Error(t("oauth.badProvider"));
      const verification = new URL(value.verification_uri);
      if (!["https://login.microsoft.com/device", "https://microsoft.com/devicelogin", "https://www.microsoft.com/devicelogin"].includes(verification.href)) {
        throw new Error(t("oauth.badMicrosoft"));
      }
      deviceFlow = value;
      byId("device-code").textContent = value.user_code;
      const appName = appNames[account];
      byId("device-app").hidden = !appName;
      EG.setText(byId("device-app"), appName ? "oauth.deviceApp" : null, { app: appName || "" });
      byId("device-link").href = verification.href;
      byId("device").hidden = false;
      EG.setText(byId("result"), "oauth.enterCode");
      byId("result").className = "result";
      EG.setText(byId("start"), "oauth.regenerate");
      byId("start").disabled = false;
      scheduleDevicePoll(value.interval || 5);
      return;
    }
    const url = new URL(value.authorization_url);
    const allowed = provider === "google"
      ? url.origin === "https://accounts.google.com" && url.pathname === "/o/oauth2/v2/auth"
      : url.origin === "https://login.microsoftonline.com" && /^\/[a-zA-Z0-9._-]+\/oauth2\/v2\.0\/authorize$/.test(url.pathname);
    if (!allowed || url.username || url.password || url.hash) {
      throw new Error(t("oauth.badProvider"));
    }
    window.location.assign(url.href);
  } catch (error) {
    EG.setText(byId("result"), null, null, error.message);
    byId("result").className = "result error";
    byId("start").disabled = false;
  }
});

document.addEventListener("DOMContentLoaded", start);
byId("account").addEventListener("change", updateProvider);
// The identity, start button and result line are set with EG.setText, so a
// language switch re-translates them in place, including mid device flow.
