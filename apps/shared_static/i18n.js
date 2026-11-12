"use strict";

// Shared i18n runtime for every Evergarden page. Classic script (CSP
// script-src 'self'): it defines the globals EG and t(), and must load before
// the locale catalogues (locale-en.js, locale-zh-CN.js) and the page scripts.
//
// Markup opts in with data-i18n (text, re-applied on every switch),
// data-i18n-once (initial placeholder text the page script later owns) and
// data-i18n-placeholder / -title / -aria-label (attributes).
//
// Locale resolution: an explicit choice saved in localStorage, then the
// browser's navigator.languages (any zh* becomes zh-CN), then English.
(function install(root) {
  const SUPPORTED = ["en", "zh-CN"];
  const FALLBACK = "en";
  const STORAGE_KEY = "evergarden.locale";
  const catalogues = Object.create(null);
  const listeners = [];
  let current = null;

  function storage() {
    try {
      return root.localStorage || null;
    } catch (_error) {
      // Storage can throw in privacy modes; the choice then lasts one page.
      return null;
    }
  }

  function normalize(value) {
    const text = String(value || "").trim().toLowerCase();
    if (text.startsWith("zh")) return "zh-CN";
    if (text.startsWith("en")) return "en";
    return null;
  }

  function detect() {
    const stored = normalize(storage()?.getItem?.(STORAGE_KEY));
    if (stored) return stored;
    const nav = root.navigator;
    const preferred = nav
      ? (Array.isArray(nav.languages) && nav.languages.length ? nav.languages : [nav.language])
      : [];
    for (const item of preferred) {
      const match = normalize(item);
      if (match) return match;
    }
    return FALLBACK;
  }

  function locale() {
    if (!current) current = detect();
    return current;
  }

  function register(name, entries) {
    catalogues[name] = Object.assign(catalogues[name] || Object.create(null), entries);
  }

  function lookup(key) {
    const active = catalogues[locale()];
    if (active && Object.prototype.hasOwnProperty.call(active, key)) return active[key];
    const fallback = catalogues[FALLBACK];
    if (fallback && Object.prototype.hasOwnProperty.call(fallback, key)) return fallback[key];
    return undefined;
  }

  function has(key) {
    return lookup(key) !== undefined;
  }

  // "{name}" placeholders are replaced from params; unknown ones stay visible.
  function t(key, params) {
    const text = lookup(key);
    if (text === undefined) return key;
    if (!params) return text;
    return text.replace(/\{(\w+)\}/g, (match, name) => (
      Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match));
  }

  const ATTRIBUTES = [
    ["data-i18n-placeholder", "placeholder"],
    ["data-i18n-title", "title"],
    ["data-i18n-aria-label", "aria-label"],
  ];

  function applyI18n(scope) {
    const doc = root.document;
    const base = scope || doc;
    if (!base?.querySelectorAll) return;
    for (const element of base.querySelectorAll("[data-i18n]")) {
      element.textContent = t(element.getAttribute("data-i18n"));
    }
    // Placeholder text the page script later replaces: translated once, then
    // left to the script so a language switch never resets live content.
    for (const element of base.querySelectorAll("[data-i18n-once]")) {
      element.textContent = t(element.getAttribute("data-i18n-once"));
      element.removeAttribute("data-i18n-once");
    }
    // Script-owned text set through EG.setText keeps its key and arguments so
    // a language switch re-translates it in place.
    for (const element of base.querySelectorAll("[data-i18n-live]")) {
      let args = {};
      try {
        args = JSON.parse(element.getAttribute("data-i18n-args") || "{}");
      } catch (_error) {
        args = {};
      }
      element.textContent = t(element.getAttribute("data-i18n-live"), args);
    }
    for (const [attribute, target] of ATTRIBUTES) {
      for (const element of base.querySelectorAll(`[${attribute}]`)) {
        element.setAttribute(target, t(element.getAttribute(attribute)));
      }
    }
    if (doc?.documentElement) doc.documentElement.lang = locale();
    renderSwitchers();
  }

  // Set an element's text from a catalogue key and remember the key, so the
  // next applyI18n (every language switch) re-translates it. Passing a null
  // key sets literal text (for example a server error) and forgets any key.
  function setText(element, key, params, literal = "") {
    if (!element) return;
    element.removeAttribute?.("data-i18n-once");
    if (key) {
      element.setAttribute?.("data-i18n-live", key);
      if (params && Object.keys(params).length) element.setAttribute?.("data-i18n-args", JSON.stringify(params));
      else element.removeAttribute?.("data-i18n-args");
      element.textContent = t(key, params);
    } else {
      element.removeAttribute?.("data-i18n-live");
      element.removeAttribute?.("data-i18n-args");
      element.textContent = literal;
    }
  }

  function renderSwitchers() {
    const doc = root.document;
    if (!doc?.querySelectorAll) return;
    for (const container of doc.querySelectorAll("[data-lang-switch]")) {
      if (!container.childElementCount) {
        container.setAttribute("role", "group");
        for (const name of SUPPORTED) {
          const button = doc.createElement("button");
          button.type = "button";
          button.className = "lang-option";
          button.dataset.locale = name;
          button.lang = name;
          button.addEventListener("click", () => setLocale(name));
          container.append(button);
        }
      }
      container.setAttribute("aria-label", t("lang.switch"));
      for (const button of container.querySelectorAll("button[data-locale]")) {
        const name = button.dataset.locale;
        button.textContent = t(name === "en" ? "lang.en.short" : "lang.zh.short");
        button.title = t(name === "en" ? "lang.en.name" : "lang.zh.name");
        button.setAttribute("aria-pressed", String(name === locale()));
      }
    }
  }

  function setLocale(name, { persist = true } = {}) {
    const next = normalize(name) || FALLBACK;
    if (persist) {
      try {
        storage()?.setItem?.(STORAGE_KEY, next);
      } catch (_error) {
        // Keep the choice for this page only.
      }
    }
    const changed = next !== current;
    current = next;
    applyI18n();
    if (changed) {
      for (const listener of [...listeners]) {
        try {
          listener(next);
        } catch (_error) {
          // One failing re-render must not stop the others.
        }
      }
    }
    return next;
  }

  function onLocaleChange(listener) {
    listeners.push(listener);
  }

  // ---- Locale-aware formatting ----

  function toDate(value) {
    if (value === null || value === undefined || value === "") return null;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value, options = { dateStyle: "medium", timeStyle: "short" }) {
    const date = toDate(value);
    if (!date) return "";
    return new Intl.DateTimeFormat(locale(), options).format(date);
  }

  // Coarse "in 5 minutes" / "3 hours ago" wording from the catalogue.
  function formatSpan(milliseconds) {
    const minutes = Math.floor(Math.abs(milliseconds) / 60000);
    if (minutes < 1) return t("time.span.lessThanMinute");
    if (minutes < 60) return t("time.span.minutes", { n: minutes });
    if (minutes < 48 * 60) return t("time.span.hours", { n: Math.floor(minutes / 60) });
    return t("time.span.days", { n: Math.floor(minutes / 1440) });
  }

  function formatNumber(value) {
    return new Intl.NumberFormat(locale()).format(value);
  }

  function formatBytes(size) {
    const bytes = Number(size);
    if (!Number.isFinite(bytes) || bytes < 0) return t("common.unknownSize");
    if (bytes < 1024) return t("units.bytes", { n: formatNumber(bytes) });
    if (bytes < 1024 * 1024) return t("units.kib", { n: formatNumber(Math.ceil(bytes / 1024)) });
    return t("units.mib", { n: formatNumber(Number((bytes / (1024 * 1024)).toFixed(1))) });
  }

  // Server errors carry an English `detail` and, where the UI can explain it,
  // a stable reason code (a `reason_code` field or a "CODE: text" prefix).
  function reasonCodeOf(detail, reasonCode) {
    if (typeof reasonCode === "string" && reasonCode) return reasonCode;
    const match = /^([A-Z][A-Z0-9_]{3,}):\s/.exec(String(detail || ""));
    return match ? match[1] : null;
  }

  // A catalogue entry may embed the server's specific wording via {detail}
  // (the text after the "CODE: " prefix).
  function serverMessage(detail, reasonCode) {
    const text = typeof detail === "string" ? detail : "";
    const code = reasonCodeOf(text, reasonCode);
    if (code && has(`server.${code}`)) {
      const rest = text.startsWith(`${code}: `) ? text.slice(code.length + 2) : text;
      return t(`server.${code}`, { detail: rest });
    }
    return text;
  }

  // Location / readiness reason codes shown next to a message.
  function reasonText(code) {
    if (!code) return "";
    return has(`reason.${code}`) ? t(`reason.${code}`) : code;
  }

  const EG = {
    SUPPORTED,
    STORAGE_KEY,
    t,
    has,
    locale,
    register,
    setLocale,
    onLocaleChange,
    applyI18n,
    setText,
    formatDate,
    formatSpan,
    formatNumber,
    formatBytes,
    reasonCodeOf,
    serverMessage,
    reasonText,
  };
  root.EG = EG;
  root.t = t;

  const doc = root.document;
  if (doc?.addEventListener) {
    doc.addEventListener("DOMContentLoaded", () => applyI18n());
  }
})(globalThis);
