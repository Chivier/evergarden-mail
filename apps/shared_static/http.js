"use strict";

// Shared JSON transport for every Evergarden page. Classic script (CSP
// script-src 'self'): it defines the globals HttpError and jsonRequest and
// must load after i18n.js and its catalogues and before the page script.

class HttpError extends Error {
  constructor(message, { status = 0, reasonCode = null, requestId = null, payload = null } = {}) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.reasonCode = reasonCode ?? null;
    this.requestId = requestId ?? null;
    // The parsed error body, for callers that render structured details.
    this.payload = payload ?? null;
  }
}

async function jsonRequest(url, {
  method = "GET", body, csrf = "", timeoutMs = 25000, loginRedirect = true,
} = {}) {
  const reading = method === "GET";
  // A write whose response is lost may still have been applied.
  const writeNote = reading ? "" : t("http.writeNote");
  const interrupted = (error) => new HttpError(error?.name === "AbortError"
    ? (reading ? t("http.timeoutRead") : t("http.timeoutWrite"))
    : t("http.network"), { status: 0 });
  const malformed = (status) => new HttpError(
    t("http.malformed", { status, note: writeNote }), { status });
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "same-origin",
        redirect: "error",
        signal: controller.signal,
      });
    } catch (error) {
      throw interrupted(error);
    }
    const { status } = response;
    if (status === 401 && loginRedirect) {
      const { pathname, search } = window.location;
      window.location.assign(`/login?next=${encodeURIComponent(`${pathname}${search}`)}`);
      throw new HttpError(t("http.sessionExpired"), { status: 401 });
    }
    const type = String(response.headers?.get?.("content-type") || "").trim();
    if (!/^application\/(?:[\w.-]+\+)?json(?:\s*;|$)/i.test(type)) {
      if (status === 502 || status === 503 || status === 504) {
        throw new HttpError(t("http.unavailable", { status, note: writeNote }), { status });
      }
      throw malformed(status);
    }
    let value;
    try {
      value = await response.json();
    } catch (error) {
      if (error?.name === "AbortError") throw interrupted(error);
      throw malformed(status);
    }
    if (value === null || typeof value !== "object") throw malformed(status);
    // Cloudflare answers origin 502/504 and unreachable origins with its own
    // JSON error; its English detail says nothing about this service.
    if (status >= 500 && /cloudflare/i.test(JSON.stringify(value))) {
      const ray = typeof value.ray_id === "string" ? ` Ray ${value.ray_id.slice(0, 32)}` : "";
      throw new HttpError(t("http.gateway", { status, ray, note: writeNote }), { status });
    }
    if (!response.ok) {
      if (status === 403 && value.detail === "valid CSRF token is required") {
        throw new HttpError(t("http.csrf"), { status });
      }
      // FastAPI validation errors carry a list in `detail`; never render "[object Object]".
      const raw = typeof value.detail === "string" && value.detail ? value.detail : "";
      const reasonCode = EG.reasonCodeOf(raw, value.reason_code);
      const detail = EG.serverMessage(raw, reasonCode) || t("http.incomplete", { status });
      throw new HttpError(detail, {
        status, reasonCode, requestId: value.request_id, payload: value,
      });
    }
    return value;
  } finally {
    clearTimeout(timer);
  }
}
