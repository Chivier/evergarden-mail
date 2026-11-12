"use strict";

const form = document.getElementById("loginForm");
const button = document.getElementById("loginButton");
const result = document.getElementById("loginResult");

// Only same-origin targets; URL parsing normalizes "/\host" and "//host" to foreign origins.
function safeNext() {
  const raw = new URLSearchParams(window.location.search).get("next") || "/";
  let url;
  try { url = new URL(raw, window.location.origin); } catch (_error) { return "/"; }
  if (url.origin !== window.location.origin) return "/";
  return url.pathname + url.search + url.hash;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  result.textContent = t("login.checking");
  result.className = "login-result";
  try {
    await jsonRequest("/api/login", {
      method: "POST",
      body: {
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      },
      loginRedirect: false,
    });
    window.location.replace(safeNext());
  } catch (error) {
    result.textContent = error.status === 429
      ? t("login.tooMany")
      : (error.status === 401 ? t("login.invalid") : error.message);
    result.className = "login-result error";
    button.disabled = false;
    document.getElementById("password").value = "";
    document.getElementById("password").focus();
  }
});
