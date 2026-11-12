"use strict";

// No mail content or bridge credential is persisted in browser storage.
(() => {
  let csrf = "", accounts = [], cursor = 0, primed = false, busy = false;
  const items = new Map();
  const el = id => document.getElementById(id);
  function call(path, value) {
    return jsonRequest(`/bridge/${path}`, value === undefined ? {} : { method: "POST", body: value, csrf });
  }
  function render() {
    const container = el("bridgeNotifications");
    container.replaceChildren();
    for (const item of [...items.values()].sort((a, b) => b.seq - a.seq).slice(0, 100)) {
      const button = document.createElement("button");
      button.className = "message-card";
      button.type = "button";
      button.textContent = `${item.read_at ? "" : "● "}${item.subject || t("mail.noSubject")} · ${item.sender}`;
      button.addEventListener("click", () => { el("bridgeDialog").close(); void openMessage(item.message_id); });
      container.append(button);
    }
    if (!items.size) container.textContent = t("bridge.empty");
  }
  async function poll() {
    if (busy) return;
    busy = true;
    try {
      const status = await call("status");
      el("bridgeStatus").textContent = status.accounts.map(item => [
        t("bridge.statusLine", {
          address: item.address,
          state: t(!item.paired ? "bridge.unpaired" : item.online ? "bridge.online" : "bridge.offline"),
          pending: item.pending,
        }),
        item.state !== "connected" ? item.state : "",
        item.last_seen ? t("bridge.lastSeen", { time: EG.formatDate(item.last_seen) }) : "",
      ].filter(Boolean).join(" · ")).join("\n");
      let count = 0, result;
      for (let page = 0; page < 10; page++) {
        result = await call(`notifications?after=${cursor}`);
        for (const item of result.items) { items.set(item.seq, item); if (primed) count++; }
        cursor = result.cursor;
        if (!result.has_more) break;
      }
      el("bridgeUnread").textContent = String(result.unread_count);
      if (!result.has_more) primed = true;
      while (items.size > 100) items.delete(items.keys().next().value);
      render();
      if (count) {
        showNotice(t("bridge.arrived", { n: count }));
        messagePreloads.clear();
        void loadMessages({ refresh: true });
        if (typeof Notification !== "undefined" && Notification.permission === "granted") {
          const notification = new Notification(t("bridge.notificationTitle"), { body: t("bridge.notificationBody", { n: count }), tag: "evergarden-company-mail" });
          notification.onclick = () => { window.focus(); el("bridgeDialog").showModal(); };
        }
      }
    } catch (_error) { el("bridgeStatus").textContent = t("bridge.statusUnavailable"); }
    finally { busy = false; }
  }
  document.addEventListener("DOMContentLoaded", async () => {
    const button = el("bridgeButton");
    if (!button) return;
    try {
      // The workbench owns the login redirect for an expired session.
      const session = await jsonRequest("/api/session", { loginRedirect: false });
      accounts = session.bridge_accounts || [];
      if (!accounts.length) return;
      csrf = session.csrf;
      button.hidden = false;
      button.addEventListener("click", () => { el("bridgeDialog").showModal(); void poll(); });
      el("bridgeClose").addEventListener("click", () => el("bridgeDialog").close());
      el("bridgePair").addEventListener("click", async () => {
        try {
          const config = await call("pair", { account: accounts[0] });
          const url = URL.createObjectURL(new Blob([JSON.stringify(config)], { type: "application/json" }));
          const link = document.createElement("a"); link.href = url; link.download = "evergarden-bridge.json";
          document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
          showNotice(t("bridge.pairingDownloaded"));
        } catch (error) { showNotice(error.message, true); }
      });
      el("bridgeRead").addEventListener("click", async () => {
        try {
          await call("notifications/read", { through: cursor });
          for (const item of items.values()) item.read_at = new Date().toISOString();
          await poll();
        } catch (error) { showNotice(error.message, true); }
      });
      el("bridgeRevoke").addEventListener("click", async () => {
        const confirmed = await EG.confirm({
          title: t("bridge.disconnectConfirm.title"),
          message: t("bridge.disconnectConfirm.body"),
          confirmLabel: t("bridge.disconnect"),
          danger: true,
        });
        if (!confirmed) return;
        try { await call("revoke", { account: accounts[0] }); await poll(); showNotice(t("bridge.revoked")); }
        catch (error) { showNotice(error.message, true); }
      });
      el("bridgeDesktop").addEventListener("click", async () => {
        if (typeof Notification === "undefined") return showNotice(t("bridge.desktopUnsupported"), true);
        const permission = await Notification.requestPermission();
        showNotice(permission === "granted" ? t("bridge.desktopOn") : t("bridge.desktopOff"));
      });
      void poll(); setInterval(poll, 30000);
    } catch (_error) { /* The workbench handles session errors independently. */ }
  });
})();
