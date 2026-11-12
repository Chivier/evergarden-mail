"use strict";

const ORIGIN = "https://evergarden.example.invalid";
const MAX_RAW = 16 * 1024 * 1024;
const MAX_QUEUE = 32 * 1024 * 1024;
// Status texts follow Thunderbird's UI language: Simplified Chinese for any
// zh* locale, English otherwise. The options page reads them from storage.
const MESSAGES = {
  en: {
    invalidConfig: "This is not a valid Evergarden pairing file",
    pairingExpired: "The pairing is no longer valid; import a new pairing file",
    uploadFailed: "Upload failed (HTTP {status})",
    notAcknowledged: "The server did not confirm receipt",
    oversized: "Some messages are over 16 MiB; read them in Thunderbird",
    accountMissing: "Sign in to the paired company IMAP mailbox in Thunderbird first",
    queueFull: "The upload queue is full; the inbox is scanned again once the connection recovers",
    oversizedContinuing: "Some messages are over 16 MiB; read them in Thunderbird. Other mail is still received",
    queueSpace: "Not enough queue space; missing mail is fetched once the connection recovers",
    scanLimit: "The scan reached the 20000-message limit; shrink the inbox and try again",
    inboxMissing: "No company inbox found; make sure Thunderbird has finished syncing",
    receiveFailed: "Receiving failed for now; the next scan retries",
    switchBlocked: "The old mailbox still has mail waiting to upload, so the mailbox cannot be switched",
  },
  "zh-CN": {
    invalidConfig: "不是有效的 Evergarden 配对文件",
    pairingExpired: "配对已失效，请重新导入配对文件",
    uploadFailed: "上传失败（HTTP {status}）",
    notAcknowledged: "服务器未确认接收",
    oversized: "存在超过 16 MiB 的邮件，请在 Thunderbird 查看",
    accountMissing: "请先在 Thunderbird 中登录配对的公司 IMAP 邮箱",
    queueFull: "待上传队列已满，恢复连接后将重新扫描补收",
    oversizedContinuing: "存在超过 16 MiB 的邮件，请在 Thunderbird 查看；其余邮件继续接收",
    queueSpace: "队列空间不足，连接恢复后自动补收",
    scanLimit: "扫描达到 20000 封上限，请缩小收件箱后重试",
    inboxMissing: "未找到公司邮箱收件箱，请确认 Thunderbird 已完成同步",
    receiveFailed: "收信暂时失败，下次扫描将重试",
    switchBlocked: "旧邮箱仍有待上传邮件，不能切换邮箱",
  },
};
function msg(key, params = {}) {
  const language = String(globalThis.navigator?.language || "").toLowerCase();
  const table = language.startsWith("zh") ? MESSAGES["zh-CN"] : MESSAGES.en;
  return (table[key] || MESSAGES.en[key] || key).replace(/\{(\w+)\}/g, (match, name) => (name in params ? String(params[name]) : match));
}
function validateConfig(value) {
  if (!value || value.version !== 1 || value.endpoint !== `${ORIGIN}/bridge/ingest`
      || typeof value.account !== "string" || !/^[a-z0-9_-]{1,64}$/.test(value.account)
      || typeof value.address !== "string" || !value.address.includes("@")
      || typeof value.token !== "string" || !/^[A-Za-z0-9_-]{32,256}$/.test(value.token)
      || !Number.isFinite(Date.parse(value.paired_at))) throw new Error(msg("invalidConfig"));
  return value;
}

class Bridge {
  constructor(api, send = fetch) { this.api = api; this.send = send; this.running = Promise.resolve(); }
  serial(fn) {
    const task = this.running.then(fn);
    this.running = task.catch(() => {});
    return task;
  }
  async data() {
    const value = await this.api.storage.local.get(["config", "queue", "seen", "status"]);
    return { config: value.config, queue: value.queue || [], seen: value.seen || [], status: value.status || {} };
  }
  async save(value) { await this.api.storage.local.set(value); }
  async status(state, pending, error = "") {
    await this.save({ status: { state, pending, error, updated: new Date().toISOString() } });
  }
  async post(config, path, value) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await this.send(`${ORIGIN}/bridge/${path}`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${config.token}` },
        body: JSON.stringify(value), signal: controller.signal, credentials: "omit", redirect: "error",
      });
      if (!response.ok) throw new Error(response.status === 401 ? msg("pairingExpired") : msg("uploadFailed", { status: response.status }));
      return await response.json();
    } finally { clearTimeout(timeout); }
  }
  async flush(data) {
    while (data.queue.length) {
      try {
        const ack = await this.post(data.config, "ingest", data.queue[0].payload);
        if (ack.accepted !== true) throw new Error(msg("notAcknowledged"));
      } catch (error) {
        await this.status("retrying", data.queue.length, error.message);
        return false;
      }
      // Save the queue after each confirmed receipt. Lost acknowledgements are
      // retried; the server deduplicates using the RFC message identity.
      data.queue.shift();
      await this.save({ queue: data.queue });
    }
    await this.status(data.warning || "connected", 0, data.warning ? msg("oversized") : "");
    return true;
  }
  async matchingAccount(config) {
    const accounts = await this.api.accounts.list(true);
    const matches = accounts.filter(a => (a.identities || []).some(i => i.email.toLowerCase() === config.address.toLowerCase()));
    if (matches.length !== 1 || matches[0].type !== "imap") throw new Error(msg("accountMissing"));
    return matches[0];
  }
  key(message, config) {
    return `${config.account}:${message.headerMessageId || `${message.author}|${message.subject}|${new Date(message.date).toISOString()}|${message.size}`}`;
  }
  async capture(data, message, notify) {
    const key = this.key(message, data.config);
    if (data.seen.includes(key)) return true;
    const queued = data.queue.reduce((n, item) => n + item.payload.raw_base64.length, 0);
    if (data.queue.length >= 100 || queued >= MAX_QUEUE) {
      await this.status("queue_full", data.queue.length, msg("queueFull"));
      return false;
    }
    const file = await this.api.messages.getRaw(message.id, { data_format: "File", decrypt: false });
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.length > MAX_RAW) {
      data.warning = "oversized";
      await this.status("oversized", data.queue.length, msg("oversizedContinuing"));
      return true; // Never mark it seen: later scans keep reporting the limit.
    }
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    const encoded = btoa(binary);
    if (queued + encoded.length > MAX_QUEUE) {
      await this.status("queue_full", data.queue.length, msg("queueSpace"));
      return false;
    }
    data.queue.push({ key, payload: { account: data.config.account, address: data.config.address,
      raw_base64: encoded, notify, read: Boolean(message.read) } });
    data.seen.push(key);
    data.seen = data.seen.slice(-20000);
    // Both are committed together before a network request. Thunderbird IDs
    // are transient; queued raw bytes survive client restarts.
    await this.save({ queue: data.queue, seen: data.seen });
    return true;
  }
  async pages(list, callback) {
    let count = 0;
    try {
    while (list) {
      for (const message of list.messages) {
        if (await callback(message) === false) return;
        if (++count >= 20000) throw new Error(msg("scanLimit"));
      }
      list = list.id ? await this.api.messages.continueList(list.id) : null;
    }
    } finally { if (list && list.id && this.api.messages.abortList) await this.api.messages.abortList(list.id); }
  }
  async newMail(folder, list) {
    return this.serial(async () => {
      const data = await this.data();
      if (!data.config) return;
      validateConfig(data.config);
      const account = await this.matchingAccount(data.config);
      if (folder.accountId !== account.id || !(folder.type === "inbox" || (folder.specialUse || []).includes("inbox"))) return;
      await this.pages(list, message => this.capture(data, message, true));
      await this.flush(data);
    });
  }
  async tick() {
    return this.serial(async () => {
      const data = await this.data();
      if (!data.config) return;
      try {
        validateConfig(data.config);
        const account = await this.matchingAccount(data.config);
        if (await this.flush(data)) {
          const inboxes = [];
          function visit(folders) { for (const f of folders || []) { if (f.type === "inbox" || (f.specialUse || []).includes("inbox")) inboxes.push(f); visit(f.subFolders); } }
          visit(account.rootFolder ? account.rootFolder.subFolders : account.folders);
          if (!inboxes.length) throw new Error(msg("inboxMissing"));
          let captured = 0;
          const deadline = Date.now() + 20000;
          for (const folder of inboxes) {
            const list = await this.api.messages.query({ folderId: folder.id, fromDate: new Date(Date.now() - 7 * 86400000) });
            await this.pages(list, async message => {
              if (data.seen.includes(this.key(message, data.config))) return true;
              if (++captured > 100 || Date.now() > deadline) return false;
              const result = await this.capture(data, message, new Date(message.date).getTime() >= Date.parse(data.config.paired_at));
              if (!result) return false;
              return this.flush(data);
            });
          }
        }
        const latest = await this.data();
        await this.post(data.config, "heartbeat", { pending: latest.queue.length, state: latest.status.state || "connected" });
      } catch (error) { await this.status("retrying", (await this.data()).queue.length, error.message); }
    });
  }
}

if (typeof module !== "undefined") module.exports = { Bridge, validateConfig };
if (typeof browser !== "undefined") {
  const bridge = new Bridge(browser);
  browser.messages.onNewMailReceived.addListener((folder, list) => {
    bridge.newMail(folder, list).catch(() => bridge.status("retrying", 0, msg("receiveFailed")));
  });
  browser.alarms.onAlarm.addListener(alarm => { if (alarm.name === "evergarden-bridge") void bridge.tick(); });
  browser.runtime.onMessage.addListener(message => {
    if (message.type === "bridge-config") return bridge.serial(async () => {
      const config = validateConfig(message.config);
      const old = await bridge.data();
      if (old.queue.length && old.config && (old.config.account !== config.account || old.config.address !== config.address)) throw new Error(msg("switchBlocked"));
      await bridge.matchingAccount(config);
      await bridge.save({ config });
      return { ok: true };
    }).then(() => bridge.tick()).then(() => ({ ok: true }));
    if (message.type === "bridge-sync") return bridge.tick().then(() => ({ ok: true }));
  });
  browser.alarms.create("evergarden-bridge", { periodInMinutes: 1 });
  void bridge.tick();
}
